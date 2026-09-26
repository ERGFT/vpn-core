//! Вход `socks`: локальный SOCKS5 (CONNECT и UDP ASSOCIATE) с
//! маршрутизацией каждого соединения и каждой датаграммы.
//!
//! Защиты (перенесены из клиента): список разрешённых адресов, блокировка
//! адреса после серии неверных паролей, потолок одновременных соединений,
//! таймаут приветствия, закрепление UDP-ассоциации за владельцем.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::access::{self, AuthGuard, IpNet};
use super::outbound::UdpSession;
use super::router::Router;
use super::{Metadata, Network};
use crate::error::{Error, Result};
use crate::relay;
use crate::socks5::udp::{encode_datagram, parse_datagram, recv_result, ClientFilter};
use crate::socks5::{self, Credentials, ReplyCode, Socks5Command, TargetAddr};
use crate::vless::Address;

/// Потолок на приветствие и запрос SOCKS5: без него молчащий клиент
/// держал сокет и задачу вечно.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct SocksInbound {
    pub tag: Arc<str>,
    pub auth: Option<Credentials>,
    pub allow_ip: Vec<IpNet>,
    pub max_conns: usize,
}

pub fn to_address(a: &TargetAddr) -> Address {
    match a {
        TargetAddr::Ip(IpAddr::V4(v4)) => Address::Ipv4(*v4),
        TargetAddr::Ip(IpAddr::V6(v6)) => Address::Ipv6(*v6),
        TargetAddr::Domain(d) => Address::Domain(d.clone()),
    }
}

pub fn from_address(a: Address) -> TargetAddr {
    match a {
        Address::Ipv4(v4) => TargetAddr::Ip(IpAddr::V4(v4)),
        Address::Ipv6(v6) => TargetAddr::Ip(IpAddr::V6(v6)),
        Address::Domain(d) => TargetAddr::Domain(d),
    }
}

impl SocksInbound {
    /// Принимать соединения, пока не упадёт сам слушающий сокет.
    pub async fn serve(self: Arc<Self>, listener: TcpListener, router: Arc<Router>) -> Result<()> {
        let slots = Arc::new(tokio::sync::Semaphore::new(self.max_conns.max(1)));
        let guard = Arc::new(AuthGuard::default());
        let mut last_full_warn: Option<Instant> = None;
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    // Например, кончились дескрипторы: не падать целиком.
                    tracing::warn!(error = %e, "accept не удался");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Чужие адреса и адреса, заблокированные за подбор пароля, —
            // закрываем сразу, до всякого разбора.
            if !access::allowed(&self.allow_ip, peer.ip()) {
                tracing::debug!(%peer, "адрес не входит в allow_ip — соединение закрыто");
                continue;
            }
            if guard.is_blocked(peer.ip(), Instant::now()) {
                tracing::debug!(%peer, "адрес временно заблокирован за подбор пароля");
                continue;
            }
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                if last_full_warn.is_none_or(|t| t.elapsed().as_secs() >= 10) {
                    tracing::warn!(
                        max = self.max_conns,
                        "достигнут предел одновременных соединений (max_conns)"
                    );
                    last_full_warn = Some(Instant::now());
                }
                continue;
            };
            socket.set_nodelay(true).ok();
            let this = self.clone();
            let router = router.clone();
            let guard = guard.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = this.handle(socket, peer, router, guard).await {
                    tracing::warn!(%peer, error = %e, "соединение завершилось с ошибкой");
                }
            });
        }
    }

    async fn handle(
        &self,
        mut socket: TcpStream,
        peer: SocketAddr,
        router: Arc<Router>,
        guard: Arc<AuthGuard>,
    ) -> Result<()> {
        // Ошибки приветствия — только в debug: иначе перебор паролей или
        // сканер портов заваливали бы журнал.
        let req = match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            socks5::handshake_with_auth(&mut socket, self.auth.as_ref()),
        )
        .await
        {
            Ok(Ok(r)) => {
                if self.auth.is_some() {
                    guard.success(peer.ip());
                }
                r
            }
            Ok(Err(Error::Socks5AuthFailed)) => {
                if let access::Verdict::Blocked(d) = guard.failure(peer.ip(), Instant::now()) {
                    tracing::warn!(
                        ip = %peer.ip(),
                        secs = d.as_secs(),
                        "SOCKS5: подряд несколько неверных паролей — адрес временно заблокирован"
                    );
                }
                return Ok(());
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "SOCKS5: приветствие отклонено");
                return Ok(());
            }
            Err(_) => {
                tracing::debug!("SOCKS5: клиент не прислал запрос вовремя");
                return Ok(());
            }
        };

        if req.command == Socks5Command::UdpAssociate {
            return udp_associate(socket, peer, req.port, self.tag.clone(), router).await;
        }

        let meta = Metadata {
            inbound: self.tag.clone(),
            source: peer,
            network: Network::Tcp,
            target: to_address(&req.addr),
            port: req.port,
        };
        let outbound = router.select(&meta);
        let remote = match outbound.connect(&meta).await {
            Ok(s) => s,
            Err(e) => {
                let code = if matches!(e, Error::Blocked) {
                    ReplyCode::NotAllowedByRuleset
                } else {
                    ReplyCode::GeneralFailure
                };
                socks5::reply_error(&mut socket, code).await.ok();
                if matches!(e, Error::Blocked) {
                    tracing::debug!(target = %meta.target, "заблокировано правилом");
                    return Ok(());
                }
                return Err(e);
            }
        };
        let bind_addr = socket.local_addr()?;
        socks5::reply_success(&mut socket, bind_addr).await?;
        // Адреса сайтов — только в debug: иначе журнал — история посещений.
        tracing::debug!(
            target = %meta.target,
            port = meta.port,
            outbound = outbound.tag(),
            "проксирую"
        );
        let stats = relay::copy_bidirectional(socket, remote).await?;
        tracing::debug!(
            sent = stats.client_to_remote,
            received = stats.remote_to_client,
            idle_closed = stats.idle_closed,
            "соединение закрыто"
        );
        Ok(())
    }
}

/// UDP-ассоциация: датаграммы приложения маршрутизируются по одной, на
/// каждый выбранный выход — своя UDP-сессия (у VLESS — XUDP-поток, у
/// direct — свои сокеты). Ответы всех сессий уходят владельцу ассоциации.
async fn udp_associate(
    mut control: TcpStream,
    peer: SocketAddr,
    requested_port: u16,
    inbound: Arc<str>,
    router: Arc<Router>,
) -> Result<()> {
    let local_ip = control.local_addr()?.ip();
    let udp = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    socks5::reply_success(&mut control, udp.local_addr()?).await?;
    tracing::info!(udp = %udp.local_addr()?, "SOCKS5 UDP: ассоциация открыта");

    let mut filter = ClientFilter::new(peer.ip(), requested_port);
    // tag выхода → (номер сессии, сессия). Номер отличает пересозданную
    // сессию от старой, о закрытии которой пришло уведомление.
    let mut sessions: HashMap<String, (u64, Arc<dyn UdpSession>)> = HashMap::new();
    let mut next_id = 0u64;
    let (closed_tx, mut closed_rx) = mpsc::unbounded_channel::<(String, u64)>();
    let mut readers = JoinSet::new();
    let mut buf = vec![0u8; 65536];
    let mut ctl = [0u8; 64];

    loop {
        tokio::select! {
            r = control.read(&mut ctl) => {
                if matches!(r, Ok(0) | Err(_)) {
                    break;
                }
            }
            Some((tag, id)) = closed_rx.recv() => {
                if sessions.get(&tag).is_some_and(|(sid, _)| *sid == id) {
                    sessions.remove(&tag);
                }
            }
            r = udp.recv_from(&mut buf) => {
                let Some((n, from)) = recv_result(r)? else { continue };
                if !filter.accept(from) {
                    tracing::debug!(%from, "SOCKS5 UDP: датаграмма не от владельца ассоциации — отброшена");
                    continue;
                }
                let (addr, port, off) = match parse_datagram(&buf[..n]) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, "SOCKS5 UDP: датаграмма отброшена");
                        continue;
                    }
                };
                let meta = Metadata {
                    inbound: inbound.clone(),
                    source: from,
                    network: Network::Udp,
                    target: to_address(&addr),
                    port,
                };
                let outbound = router.select(&meta);
                let tag = outbound.tag().to_string();
                let session = match sessions.get(&tag) {
                    Some((_, s)) => s.clone(),
                    None => {
                        let s = match outbound.udp(&meta).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(error = %e, outbound = %tag, "SOCKS5 UDP: не удалось открыть UDP-сессию");
                                continue;
                            }
                        };
                        next_id += 1;
                        let id = next_id;
                        sessions.insert(tag.clone(), (id, s.clone()));
                        let (reader_s, udp, closed_tx, tag) =
                            (s.clone(), udp.clone(), closed_tx.clone(), tag.clone());
                        readers.spawn(async move {
                            while let Ok(Some((src, sport, data))) = reader_s.recv().await {
                                let dg = encode_datagram(&from_address(src), sport, &data);
                                // Ошибка отправки одной датаграммы — не повод
                                // закрывать сессию.
                                let _ = udp.send_to(&dg, from).await;
                            }
                            let _ = closed_tx.send((tag, id));
                        });
                        s
                    }
                };
                if let Err(e) = session.send(meta.target, port, buf[off..n].to_vec()).await {
                    tracing::debug!(error = %e, "SOCKS5 UDP: сессия закрыта, откроется заново");
                    sessions.remove(&tag);
                }
            }
            Some(_) = readers.join_next(), if !readers.is_empty() => {}
        }
    }
    readers.abort_all();
    tracing::info!("SOCKS5 UDP: ассоциация закрыта");
    Ok(())
}

/// Адрес «на этом компьютере» для слушающего сокета.
pub fn is_loopback_listen(addr: &SocketAddr) -> bool {
    match addr.ip().to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() && v4 != Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST,
    }
}
