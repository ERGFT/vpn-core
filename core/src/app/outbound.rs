//! Выходы: куда уходит соединение, выбранное маршрутизатором.
//!
//! - `vless` — VLESS-сервер (`super::vless_out`);
//! - `direct` — напрямую, без сервера;
//! - `block` — сразу отказать.
//!
//! Каждый выход умеет TCP (`connect`) и UDP (`udp` → [`UdpSession`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::AsyncStream;
use crate::vless::Address;

/// Датаграмма: адрес, порт, данные.
pub type Packet = (Address, u16, Vec<u8>);

/// UDP-сессия выхода: датаграммы к любым назначениям и ответы от них.
/// Одна сессия — одна UDP-ассоциация приложения.
pub trait UdpSession: Send + Sync {
    /// Отправить датаграмму. Переполнение очереди — не ошибка (UDP может
    /// терять пакеты); ошибка — сессия больше не работает.
    fn send(&self, dst: Address, port: u16, data: Vec<u8>) -> BoxFuture<'_, Result<()>>;
    /// Следующий ответ: источник и данные. `Ok(None)` — сессия закрыта
    /// (ошибка на стороне сервера или долгое молчание).
    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>>;
}

pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    /// TCP-соединение с `meta.target:meta.port`.
    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>>;
    /// UDP-сессия для ассоциации, которую открыл `meta.source`.
    fn udp<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>>;
}

/// UDP-сессия закрывается после стольких секунд без пакетов.
pub const UDP_IDLE: Duration = Duration::from_secs(120);

/// Адрес этого компьютера (loopback или «любой»). Выход `direct` не
/// соединяет с ним клиентов с других машин: иначе прокси, открытый в сеть,
/// давал бы соседям доступ к службам, слушающим только 127.0.0.1.
fn is_local_host(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback() || ip.is_unspecified()
}

fn check_local_access(meta: &Metadata, ip: IpAddr) -> Result<()> {
    if is_local_host(ip) && !is_local_host(meta.source.ip()) {
        return Err(Error::Protocol(format!(
            "direct: клиенту {} из сети нельзя соединяться с адресами этого компьютера ({ip})",
            meta.source.ip()
        )));
    }
    Ok(())
}

fn host_string(a: &Address) -> String {
    a.to_string()
}

/// Напрямую, без сервера.
pub struct DirectOutbound {
    tag: String,
}

impl DirectOutbound {
    pub fn new(tag: impl Into<String>) -> Self {
        DirectOutbound { tag: tag.into() }
    }
}

/// Полный потолок на открытие прямого соединения (внутри — свои таймауты
/// на DNS и на каждый адрес).
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            if let Address::Domain(d) = &meta.target {
                if d.eq_ignore_ascii_case("localhost") {
                    check_local_access(meta, IpAddr::V4(Ipv4Addr::LOCALHOST))?;
                }
            }
            let s = tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, async {
                let s =
                    crate::transport::tcp_tls::connect_host(&host_string(&meta.target), meta.port)
                        .await?;
                // Проверка по фактическому адресу: домен мог указывать на
                // 127.0.0.1.
                check_local_access(meta, s.peer_addr()?.ip())?;
                Ok::<_, Error>(s)
            })
            .await
            .map_err(|_| Error::Protocol("direct: соединение не установилось вовремя".into()))??;
            Ok(Box::new(s) as Box<dyn AsyncStream>)
        })
    }

    fn udp<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let v4 = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
            // IPv6 может отсутствовать — тогда только IPv4.
            let v6 = UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
                .await
                .ok();
            Ok(Arc::new(DirectUdp {
                v4,
                v6,
                source: meta.source,
                last: std::sync::Mutex::new(tokio::time::Instant::now()),
                resolved: Mutex::new(std::collections::HashMap::new()),
            }) as Arc<dyn UdpSession>)
        })
    }
}

struct DirectUdp {
    v4: UdpSocket,
    v6: Option<UdpSocket>,
    source: SocketAddr,
    last: std::sync::Mutex<tokio::time::Instant>,
    /// Кэш разрешённых имён на время сессии (DNS-запрос на каждую
    /// датаграмму был бы слишком дорог).
    resolved: Mutex<std::collections::HashMap<String, IpAddr>>,
}

impl DirectUdp {
    fn touch(&self) {
        *self.last.lock().unwrap() = tokio::time::Instant::now();
    }

    async fn resolve(&self, dst: &Address) -> Result<IpAddr> {
        match dst {
            Address::Ipv4(ip) => Ok(IpAddr::V4(*ip)),
            Address::Ipv6(ip) => Ok(IpAddr::V6(*ip)),
            Address::Domain(d) => {
                if let Some(ip) = self.resolved.lock().await.get(d) {
                    return Ok(*ip);
                }
                let ip = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::lookup_host((d.as_str(), 0)),
                )
                .await
                .map_err(|_| Error::Protocol(format!("direct: имя {d} не разрешилось вовремя")))??
                .map(|a| a.ip())
                .next()
                .ok_or_else(|| Error::Protocol(format!("direct: имя {d} не разрешилось")))?;
                let mut cache = self.resolved.lock().await;
                if cache.len() < 1024 {
                    cache.insert(d.clone(), ip);
                }
                Ok(ip)
            }
        }
    }
}

fn ip_to_address(ip: IpAddr) -> Address {
    match ip.to_canonical() {
        IpAddr::V4(v4) => Address::Ipv4(v4),
        IpAddr::V6(v6) => Address::Ipv6(v6),
    }
}

impl UdpSession for DirectUdp {
    fn send(&self, dst: Address, port: u16, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let ip = match self.resolve(&dst).await {
                Ok(ip) => ip,
                Err(e) => {
                    tracing::debug!(error = %e, "direct UDP: датаграмма отброшена");
                    return Ok(());
                }
            };
            if is_local_host(ip) && !is_local_host(self.source.ip()) {
                tracing::debug!(%ip, "direct UDP: адрес этого компьютера недоступен клиентам из сети");
                return Ok(());
            }
            self.touch();
            let sock = match ip {
                IpAddr::V4(_) => Some(&self.v4),
                IpAddr::V6(_) => self.v6.as_ref(),
            };
            if let Some(sock) = sock {
                let _ = sock.send_to(&data, SocketAddr::new(ip, port)).await;
            }
            Ok(())
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move {
            let mut b4 = vec![0u8; 65536];
            let mut b6 = vec![0u8; 65536];
            loop {
                let deadline = *self.last.lock().unwrap() + UDP_IDLE;
                let got = tokio::select! {
                    r = self.v4.recv_from(&mut b4) => r.map(|(n, a)| (b4[..n].to_vec(), a)),
                    r = async {
                        match &self.v6 {
                            Some(s) => s.recv_from(&mut b6).await,
                            None => std::future::pending().await,
                        }
                    } => r.map(|(n, a)| (b6[..n].to_vec(), a)),
                    _ = tokio::time::sleep_until(deadline) => {
                        if tokio::time::Instant::now() >= *self.last.lock().unwrap() + UDP_IDLE {
                            return Ok(None);
                        }
                        continue;
                    }
                };
                match got {
                    Ok((data, from)) => {
                        self.touch();
                        return Ok(Some((ip_to_address(from.ip()), from.port(), data)));
                    }
                    // Ошибки отдельных датаграмм (ICMP «порт недоступен»)
                    // не закрывают сессию.
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        continue
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        })
    }
}

/// Сразу отказать (реклама, трекеры, запрещённые назначения).
pub struct BlockOutbound {
    tag: String,
}

impl BlockOutbound {
    pub fn new(tag: impl Into<String>) -> Self {
        BlockOutbound { tag: tag.into() }
    }
}

impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn connect<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move { Err(Error::Blocked) })
    }

    fn udp<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move { Ok(Arc::new(BlockUdp) as Arc<dyn UdpSession>) })
    }
}

struct BlockUdp;

impl UdpSession for BlockUdp {
    fn send(&self, _dst: Address, _port: u16, _data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async {
            tokio::time::sleep(UDP_IDLE).await;
            Ok(None)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Network;

    fn meta(source: &str, target: Address, port: u16, network: Network) -> Metadata {
        Metadata {
            inbound: "socks".into(),
            source: source.parse().unwrap(),
            network,
            target,
            port,
            sniffed: None,
        }
    }

    /// Клиент из сети не должен через direct попадать на службы, которые
    /// слушают только 127.0.0.1 этого компьютера.
    #[tokio::test]
    async fn direct_denies_this_host_to_lan_clients() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let d = DirectOutbound::new("direct");

        for target in [
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            Address::Domain("localhost".into()),
            Address::Domain("LocalHost".into()),
        ] {
            let m = meta("192.168.1.50:5000", target.clone(), port, Network::Tcp);
            let e = d.connect(&m).await.err().expect("должен быть отказ");
            assert!(e.to_string().contains("нельзя"), "{target}: {e}");
        }
        // Самому компьютеру — можно.
        let m = meta(
            "127.0.0.1:5000",
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            port,
            Network::Tcp,
        );
        d.connect(&m).await.expect("локальному клиенту разрешено");
    }

    #[tokio::test]
    async fn direct_udp_drops_this_host_for_lan_clients() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let d = DirectOutbound::new("direct");
        let m = meta(
            "192.168.1.50:5000",
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            port,
            Network::Udp,
        );
        let s = d.udp(&m).await.unwrap();
        s.send(Address::Ipv4(Ipv4Addr::LOCALHOST), port, b"x".to_vec())
            .await
            .unwrap();
        let mut b = [0u8; 8];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), target.recv_from(&mut b))
                .await
                .is_err(),
            "датаграмма не должна дойти"
        );
    }
}
