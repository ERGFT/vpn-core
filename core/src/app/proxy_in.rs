//! Входы `socks`, `http` и `mixed` (SOCKS5 и HTTP на одном порту — вид
//! определяется по первому байту: 0x05 — SOCKS5, иначе HTTP).
//!
//! Защиты: список разрешённых адресов, блокировка адреса после серии
//! неверных паролей, потолок одновременных соединений, таймаут
//! приветствия, закрепление UDP-ассоциации за владельцем.
//!
//! Sniffing (`sniff = true`): если приложение прислало IP, а не домен,
//! прокси сразу отвечает «соединено», читает первые байты (TLS SNI или
//! HTTP Host) и выбирает маршрут уже с доменом.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::access::{self, AuthGuard, IpNet};
use super::config::InboundKind;
use super::http_in;
use super::outbound::UdpSession;
use super::router::Router;
use super::sniff;
use super::{Metadata, Network};
use crate::error::{Error, Result};
use crate::relay;
use crate::socks5::udp::{encode_datagram, parse_datagram, recv_result, ClientFilter};
use crate::socks5::{self, Credentials, ReplyCode, Socks5Command, TargetAddr};
use crate::vless::Address;

/// Потолок на приветствие и запрос: без него молчащий клиент держал
/// сокет и задачу вечно.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Потолок UDP-сессий на одну ассоциацию (у адресов fake-IP — своя
/// сессия на каждый адрес).
const MAX_UDP_SESSIONS: usize = 256;

pub struct ProxyInbound {
    pub tag: Arc<str>,
    pub kind: InboundKind,
    pub auth: Option<Credentials>,
    pub allow_ip: Vec<IpNet>,
    pub max_conns: usize,
    pub sniff: bool,
    /// Подставить найденный домен вместо IP: имя разрешит сервер, а не
    /// этот компьютер.
    pub sniff_override: bool,
}

impl ProxyInbound {
    /// Как вход называется в журнале.
    pub fn proto_name(&self) -> &'static str {
        match self.kind {
            InboundKind::Socks => "SOCKS5",
            InboundKind::Http => "HTTP",
            InboundKind::Mixed => "SOCKS5+HTTP",
            InboundKind::Dns => "DNS",
            InboundKind::Tun => "TUN",
        }
    }
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

/// Как ответить приложению после открытия соединения.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplyKind {
    Socks,
    HttpConnect,
    /// Обычный HTTP-запрос: ответа от прокси нет, отвечает сам сайт.
    HttpForward,
}

/// Итог приветствия.
enum Accepted {
    Connect {
        target: Address,
        port: u16,
        reply: ReplyKind,
        /// Что отправить сайту первым (заголовок HTTP-запроса, байты,
        /// пришедшие вслед за заголовком).
        initial: Vec<u8>,
    },
    UdpAssociate {
        port: u16,
    },
    /// Приветствие не удалось (ответ уже отправлен или не нужен).
    Done,
}

async fn send_reply(
    socket: &mut TcpStream,
    reply: ReplyKind,
    result: std::result::Result<(), &Error>,
) -> Result<()> {
    match (reply, result) {
        (ReplyKind::Socks, Ok(())) => {
            let bind = socket.local_addr()?;
            socks5::reply_success(socket, bind).await
        }
        (ReplyKind::Socks, Err(e)) => {
            let code = if matches!(e, Error::Blocked) {
                ReplyCode::NotAllowedByRuleset
            } else {
                ReplyCode::GeneralFailure
            };
            socks5::reply_error(socket, code).await
        }
        (ReplyKind::HttpConnect, Ok(())) => Ok(socket.write_all(http_in::RESP_ESTABLISHED).await?),
        (ReplyKind::HttpForward, Ok(())) => Ok(()),
        (_, Err(e)) => {
            let r = if matches!(e, Error::Blocked) {
                http_in::RESP_FORBIDDEN
            } else {
                http_in::RESP_BAD_GATEWAY
            };
            Ok(socket.write_all(r).await?)
        }
    }
}

impl ProxyInbound {
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

    fn auth_failed(&self, guard: &AuthGuard, peer: SocketAddr) {
        if let access::Verdict::Blocked(d) = guard.failure(peer.ip(), Instant::now()) {
            tracing::warn!(
                ip = %peer.ip(),
                secs = d.as_secs(),
                "подряд несколько неверных паролей — адрес временно заблокирован"
            );
        }
    }

    async fn greet_socks(
        &self,
        socket: &mut TcpStream,
        peer: SocketAddr,
        guard: &AuthGuard,
    ) -> Result<Accepted> {
        match socks5::handshake_with_auth(socket, self.auth.as_ref()).await {
            Ok(req) => {
                if self.auth.is_some() {
                    guard.success(peer.ip());
                }
                Ok(if req.command == Socks5Command::UdpAssociate {
                    Accepted::UdpAssociate { port: req.port }
                } else {
                    Accepted::Connect {
                        target: to_address(&req.addr),
                        port: req.port,
                        reply: ReplyKind::Socks,
                        initial: Vec::new(),
                    }
                })
            }
            Err(Error::Socks5AuthFailed) => {
                self.auth_failed(guard, peer);
                Ok(Accepted::Done)
            }
            Err(e) => Err(e),
        }
    }

    async fn greet_http(
        &self,
        socket: &mut TcpStream,
        peer: SocketAddr,
        guard: &AuthGuard,
    ) -> Result<Accepted> {
        let (head, rest) = match http_in::read_head(socket).await {
            Ok(v) => v,
            Err(e) => {
                socket.write_all(http_in::RESP_BAD_REQUEST).await.ok();
                return Err(e);
            }
        };
        let req = match http_in::parse_request(&head) {
            Ok(r) => r,
            Err(e) => {
                socket.write_all(http_in::RESP_BAD_REQUEST).await.ok();
                return Err(e);
            }
        };
        if let Some(creds) = &self.auth {
            // Без заголовка — не ошибка: браузер сначала спрашивает без
            // пароля и повторяет запрос после ответа 407.
            if req.auth.is_some() && !http_in::check_auth(&req, creds) {
                self.auth_failed(guard, peer);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            if !http_in::check_auth(&req, creds) {
                socket.write_all(http_in::RESP_AUTH).await.ok();
                return Ok(Accepted::Done);
            }
            guard.success(peer.ip());
        }
        let (reply, initial) = if req.connect {
            (ReplyKind::HttpConnect, rest)
        } else {
            let mut v = req.forward_head;
            v.extend_from_slice(&rest);
            (ReplyKind::HttpForward, v)
        };
        Ok(Accepted::Connect {
            target: req.target,
            port: req.port,
            reply,
            initial,
        })
    }

    async fn greet(
        &self,
        socket: &mut TcpStream,
        peer: SocketAddr,
        guard: &AuthGuard,
    ) -> Result<Accepted> {
        let socks = match self.kind {
            InboundKind::Socks => true,
            InboundKind::Http | InboundKind::Dns | InboundKind::Tun => false,
            InboundKind::Mixed => {
                let mut b = [0u8; 1];
                if socket.peek(&mut b).await? == 0 {
                    return Ok(Accepted::Done);
                }
                b[0] == 5
            }
        };
        if socks {
            self.greet_socks(socket, peer, guard).await
        } else {
            self.greet_http(socket, peer, guard).await
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
        let accepted =
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, self.greet(&mut socket, peer, &guard))
                .await
            {
                Ok(Ok(a)) => a,
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "приветствие отклонено");
                    return Ok(());
                }
                Err(_) => {
                    tracing::debug!("клиент не прислал запрос вовремя");
                    return Ok(());
                }
            };
        let (target, port, reply, mut initial) = match accepted {
            Accepted::Done => return Ok(()),
            Accepted::UdpAssociate { port } => {
                return udp_associate(socket, peer, port, self.tag.clone(), router).await;
            }
            Accepted::Connect {
                target,
                port,
                reply,
                initial,
            } => (target, port, reply, initial),
        };

        let mut meta = Metadata {
            inbound: self.tag.clone(),
            source: peer,
            network: Network::Tcp,
            target,
            port,
            sniffed: None,
        };
        // Sniffing нужен, только когда домена нет. Ответ «соединено»
        // уходит раньше, чем соединение с сайтом открыто, — иначе
        // приложение не пришлёт первых байт; ошибку потом можно сообщить
        // только закрытием соединения.
        let target_is_ip = !matches!(meta.target, Address::Domain(_));
        let replied_early = self.sniff && target_is_ip && reply != ReplyKind::HttpForward;
        if replied_early {
            send_reply(&mut socket, reply, Ok(())).await?;
            meta.sniffed = sniff::read_and_sniff(&mut socket, &mut initial).await?;
            if let Some(d) = &meta.sniffed {
                tracing::debug!(ip = %meta.target, domain = %d, "sniffing: найден домен");
                if self.sniff_override {
                    meta.target = Address::Domain(d.clone());
                }
            }
        }

        let outbound = match router.route(&mut meta).await {
            Ok(o) => o,
            Err(e) => {
                if !replied_early {
                    send_reply(&mut socket, reply, Err(&e)).await.ok();
                }
                tracing::debug!(error = %e, "маршрут не выбран");
                return Ok(());
            }
        };
        let mut remote = match outbound.connect(&meta).await {
            Ok(s) => s,
            Err(e) => {
                if !replied_early {
                    send_reply(&mut socket, reply, Err(&e)).await.ok();
                }
                if matches!(e, Error::Blocked) {
                    tracing::debug!(target = %meta.target, "заблокировано правилом");
                    return Ok(());
                }
                return Err(e);
            }
        };
        if !replied_early {
            send_reply(&mut socket, reply, Ok(())).await?;
        }
        if !initial.is_empty() {
            remote.write_all(&initial).await?;
        }
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
    // Ключ сессии: tag выхода, а для адресов fake-IP — ещё и сам адрес:
    // у такой сессии ответы подписываются этим адресом (приложение ждёт
    // ответ оттуда, куда отправляло). Номер отличает пересозданную сессию
    // от старой, о закрытии которой пришло уведомление.
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
                let mut meta = Metadata {
                    inbound: inbound.clone(),
                    source: from,
                    network: Network::Udp,
                    target: to_address(&addr),
                    port,
                    sniffed: None,
                };
                let original = meta.target.clone();
                let outbound = match router.route(&mut meta).await {
                    Ok(o) => o,
                    Err(e) => {
                        tracing::debug!(error = %e, "SOCKS5 UDP: датаграмма отброшена");
                        continue;
                    }
                };
                // Адрес был fake-IP (маршрутизатор подставил имя).
                let reply_as = (meta.target != original).then_some(original);
                let tag = match &reply_as {
                    Some(a) => format!("{}|{a}:{port}", outbound.tag()),
                    None => outbound.tag().to_string(),
                };
                if !sessions.contains_key(&tag) && sessions.len() >= MAX_UDP_SESSIONS {
                    tracing::debug!("SOCKS5 UDP: слишком много сессий в ассоциации — датаграмма отброшена");
                    continue;
                }
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
                                let src = match &reply_as {
                                    Some(fake) => fake.clone(),
                                    None => src,
                                };
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
