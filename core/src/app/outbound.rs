// SPDX-License-Identifier: GPL-3.0-or-later
//! Выходы: куда уходит соединение, выбранное маршрутизатором.
//!
//! - `vless` — VLESS-сервер (`super::vless_out`);
//! - `direct` — напрямую, без сервера;
//! - `block` — сразу отказать;
//! - `dns` — ответить самому (перехват DNS-запросов, см. `super::dns`).
//!
//! Каждый выход умеет TCP (`connect`) и UDP (`udp` → [`UdpSession`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::dns::{self, Dns, DnsSlot, DNS_INTERNAL};
use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::fragment::{Fragment, FragmentStream};
use crate::transport::noise::Noise;
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
    /// Тип выхода, как его называет Clash API: `Direct`, `Reject`, `VLESS`…
    fn clash_type(&self) -> &'static str;
    /// TCP-соединение с `meta.target:meta.port`.
    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>>;
    /// UDP-сессия для ассоциации, которую открыл `meta.source`.
    fn udp<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>>;
    /// Выход `dns` (перехват DNS) — через него нельзя ходить к DNS-серверам.
    fn is_dns(&self) -> bool {
        false
    }
    /// Адрес VLESS-сервера (у выхода `vless`).
    fn server(&self) -> Option<(String, u16)> {
        None
    }
    /// Группа серверов (selector/urltest/fallback).
    fn as_group(&self) -> Option<&super::group::Group> {
        None
    }
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

/// Адреса, которые клиентам из сети недоступны через `direct`: сам
/// компьютер и link-local (в том числе облачный metadata 169.254.169.254).
/// Отдельно от [`is_local_host`]: та решает, «свой» ли источник, и
/// link-local сосед не должен становиться своим.
fn is_host_only_target(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback()
        || ip.is_unspecified()
        || match ip {
            IpAddr::V4(v) => v.is_link_local(),
            IpAddr::V6(v) => (v.segments()[0] & 0xffc0) == 0xfe80,
        }
}

fn check_local_access(meta: &Metadata, ip: IpAddr) -> Result<()> {
    if is_host_only_target(ip) && !is_local_host(meta.source.ip()) {
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
    /// Если в настройках есть раздел `dns` — имена разрешаются им (с его
    /// правилами), иначе системным резолвером.
    dns: Option<DnsSlot>,
    /// Дробление начала TCP-соединений (ClientHello сайта).
    fragment: Option<Arc<Fragment>>,
    /// Шум перед первой UDP-датаграммой к адресу.
    noises: Arc<Vec<Noise>>,
}

impl DirectOutbound {
    pub fn new(tag: impl Into<String>) -> Self {
        DirectOutbound {
            tag: tag.into(),
            dns: None,
            fragment: None,
            noises: Arc::new(Vec::new()),
        }
    }

    pub fn with_dns(tag: impl Into<String>, dns: DnsSlot) -> Self {
        DirectOutbound {
            dns: Some(dns),
            ..Self::new(tag)
        }
    }

    pub fn with_fragment(mut self, f: Option<Arc<Fragment>>) -> Self {
        self.fragment = f;
        self
    }

    pub fn with_noises(mut self, n: Vec<Noise>) -> Self {
        self.noises = Arc::new(n);
        self
    }
}

/// DNS-модуль для разрешения имени, если он есть и это не запрос самого
/// DNS-модуля (иначе имя DNS-сервера разрешалось бы через него же).
fn dns_for<'a>(slot: &'a Option<DnsSlot>, meta: &Metadata) -> Option<&'a Arc<Dns>> {
    if &*meta.inbound == DNS_INTERNAL {
        return None;
    }
    slot.as_ref()?.get()
}

/// Адреса для `host:port` — через DNS-модуль или системным резолвером.
async fn resolve(dns: Option<&Arc<Dns>>, target: &Address, port: u16) -> Result<Vec<SocketAddr>> {
    match (target, dns) {
        (Address::Ipv4(v4), _) => Ok(vec![SocketAddr::new(IpAddr::V4(*v4), port)]),
        (Address::Ipv6(v6), _) => Ok(vec![SocketAddr::new(IpAddr::V6(*v6), port)]),
        (Address::Domain(d), Some(dns)) => Ok(dns
            .lookup(d)
            .await?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()),
        // Имя DNS-сервера (запрос самого DNS-модуля) — с кешем, как имя
        // VLESS-сервера: с TUN системный DNS идёт через клиент.
        (Address::Domain(d), None) if crate::net_protect::tun_active() => {
            crate::transport::tcp_tls::resolve_server(d, port).await
        }
        (Address::Domain(d), None) => crate::transport::tcp_tls::resolve_host(d, port).await,
    }
}

/// Полный потолок на открытие прямого соединения (внутри — свои таймауты
/// на DNS и на каждый адрес).
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn clash_type(&self) -> &'static str {
        "Direct"
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            if let Address::Domain(d) = &meta.target {
                if d.eq_ignore_ascii_case("localhost") {
                    check_local_access(meta, IpAddr::V4(Ipv4Addr::LOCALHOST))?;
                }
            }
            let s = tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, async {
                let mut addrs =
                    resolve(dns_for(&self.dns, meta), &meta.target, meta.port).await?;
                // Запрещённые адреса — до подключения: иначе соединение
                // успевало бы установиться (оракул для сканирования портов).
                if !is_local_host(meta.source.ip()) {
                    addrs.retain(|a| !is_host_only_target(a.ip()));
                    if addrs.is_empty() {
                        return Err(Error::Protocol(format!(
                            "direct: клиенту {} из сети нельзя соединяться с адресами этого компьютера",
                            meta.source.ip()
                        )));
                    }
                }
                let s =
                    crate::transport::tcp_tls::connect_addrs(&addrs, &host_string(&meta.target))
                        .await?;
                // Страховка: проверка по фактическому адресу.
                check_local_access(meta, s.peer_addr()?.ip())?;
                Ok::<_, Error>(s)
            })
            .await
            .map_err(|_| Error::Protocol("direct: соединение не установилось вовремя".into()))??;
            if self.fragment.is_some() {
                return Ok(
                    Box::new(FragmentStream::new(s, self.fragment.clone())) as Box<dyn AsyncStream>
                );
            }
            Ok(Box::new(s) as Box<dyn AsyncStream>)
        })
    }

    fn udp<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let v4 = crate::net_protect::udp_bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
            // IPv6 может отсутствовать — тогда только IPv4.
            let v6 =
                crate::net_protect::udp_bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).ok();
            Ok(Arc::new(DirectUdp {
                v4,
                v6,
                source: meta.source,
                last: std::sync::Mutex::new(tokio::time::Instant::now()),
                resolved: Mutex::new(std::collections::HashMap::new()),
                dns: dns_for(&self.dns, meta).cloned(),
                noises: self.noises.clone(),
                noised: Mutex::new(std::collections::HashSet::new()),
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
    dns: Option<Arc<Dns>>,
    noises: Arc<Vec<Noise>>,
    /// Адреса, к которым шум уже отправлен.
    noised: Mutex<std::collections::HashSet<SocketAddr>>,
}

impl DirectUdp {
    fn touch(&self) {
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = tokio::time::Instant::now();
    }

    async fn resolve(&self, dst: &Address) -> Result<IpAddr> {
        match dst {
            Address::Ipv4(ip) => Ok(IpAddr::V4(*ip)),
            Address::Ipv6(ip) => Ok(IpAddr::V6(*ip)),
            Address::Domain(d) => {
                if let Some(ip) = self.resolved.lock().await.get(d) {
                    return Ok(*ip);
                }
                let ips: Vec<IpAddr> = match &self.dns {
                    Some(dns) => dns.lookup(d).await?,
                    None => tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::lookup_host((d.as_str(), 0)),
                    )
                    .await
                    .map_err(|_| {
                        Error::Protocol(format!("direct: имя {d} не разрешилось вовремя"))
                    })??
                    .map(|a| a.ip())
                    .collect(),
                };
                // Без IPv6-сокета — первый IPv4.
                let ip = ips
                    .iter()
                    .find(|ip| ip.is_ipv4() || self.v6.is_some())
                    .copied()
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
            if is_host_only_target(ip) && !is_local_host(self.source.ip()) {
                tracing::debug!(%ip, "direct UDP: адрес этого компьютера недоступен клиентам из сети");
                return Ok(());
            }
            self.touch();
            let sock = match ip {
                IpAddr::V4(_) => Some(&self.v4),
                IpAddr::V6(_) => self.v6.as_ref(),
            };
            if let Some(sock) = sock {
                let to = SocketAddr::new(ip, port);
                if !self.noises.is_empty() {
                    let first = {
                        let mut n = self.noised.lock().await;
                        n.len() < 4096 && n.insert(to)
                    };
                    if first {
                        for noise in self.noises.iter().filter(|n| n.applies(ip, port)) {
                            let _ = sock.send_to(&noise.packet(), to).await;
                            let d = noise.delay();
                            if !d.is_zero() {
                                tokio::time::sleep(d).await;
                            }
                        }
                    }
                }
                let _ = sock.send_to(&data, to).await;
            }
            Ok(())
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move {
            let mut b4 = vec![0u8; 65536];
            let mut b6 = vec![0u8; 65536];
            loop {
                let deadline = *self
                    .last
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    + UDP_IDLE;
                let got = tokio::select! {
                    r = self.v4.recv_from(&mut b4) => r.map(|(n, a)| (b4[..n].to_vec(), a)),
                    r = async {
                        match &self.v6 {
                            Some(s) => s.recv_from(&mut b6).await,
                            None => std::future::pending().await,
                        }
                    } => r.map(|(n, a)| (b6[..n].to_vec(), a)),
                    _ = tokio::time::sleep_until(deadline) => {
                        if tokio::time::Instant::now() >= *self.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) + UDP_IDLE {
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

    fn clash_type(&self) -> &'static str {
        "Reject"
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

/// Перехват DNS: TCP-соединения и UDP-датаграммы к этому выходу — DNS-
/// запросы, на них отвечает DNS-модуль (правило `hijack-dns`
/// или `"port": [53]` → выход `dns`).
pub struct DnsOutbound {
    tag: String,
    dns: DnsSlot,
}

impl DnsOutbound {
    pub fn new(tag: impl Into<String>, dns: DnsSlot) -> Self {
        DnsOutbound {
            tag: tag.into(),
            dns,
        }
    }

    fn get(&self) -> Result<Arc<Dns>> {
        self.dns
            .get()
            .cloned()
            .ok_or_else(|| Error::Protocol("dns: модуль DNS не настроен".into()))
    }
}

/// Сколько DNS-запросов одна UDP-сессия обрабатывает одновременно.
const DNS_OUT_CONCURRENCY: usize = 64;

impl Outbound for DnsOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn clash_type(&self) -> &'static str {
        "DNS"
    }

    fn is_dns(&self) -> bool {
        true
    }

    fn connect<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            let dns = self.get()?;
            // DNS поверх TCP: запросы с длиной впереди, ответы так же.
            let (ours, theirs) = tokio::io::duplex(128 * 1024);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut s = ours;
                loop {
                    let mut len = [0u8; 2];
                    let read = tokio::time::timeout(UDP_IDLE, s.read_exact(&mut len)).await;
                    if !matches!(read, Ok(Ok(_))) {
                        break;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        break;
                    }
                    let Some(a) = dns::answer_bytes(&dns, &q, true).await else {
                        break;
                    };
                    let mut out = (a.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&a);
                    if s.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(theirs) as Box<dyn AsyncStream>)
        })
    }

    fn udp<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let (tx, rx) = tokio::sync::mpsc::channel(DNS_OUT_CONCURRENCY);
            Ok(Arc::new(DnsUdp {
                dns: self.get()?,
                tx,
                rx: Mutex::new(rx),
                slots: Arc::new(tokio::sync::Semaphore::new(DNS_OUT_CONCURRENCY)),
            }) as Arc<dyn UdpSession>)
        })
    }
}

struct DnsUdp {
    dns: Arc<Dns>,
    tx: tokio::sync::mpsc::Sender<Packet>,
    rx: Mutex<tokio::sync::mpsc::Receiver<Packet>>,
    slots: Arc<tokio::sync::Semaphore>,
}

impl UdpSession for DnsUdp {
    fn send(&self, dst: Address, port: u16, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            // Слишком много запросов сразу — лишние теряются, как в UDP.
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                return Ok(());
            };
            let (dns, tx) = (self.dns.clone(), self.tx.clone());
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(a) = dns::answer_bytes(&dns, &data, true).await {
                    // Ответ — «от» того адреса, куда спрашивали.
                    let _ = tx.send((dst, port, a)).await;
                }
            });
            Ok(())
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move {
            let mut rx = self.rx.lock().await;
            match tokio::time::timeout(UDP_IDLE, rx.recv()).await {
                Ok(p) => Ok(p),
                Err(_) => Ok(None),
            }
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
            inbound_type: "socks",
            rule: None,
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

    #[test]
    fn host_only_targets() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "169.254.169.254",
            "fe80::1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_host_only_target(s.parse().unwrap()), "{s}");
        }
        assert!(!is_host_only_target("8.8.8.8".parse().unwrap()));
        assert!(!is_host_only_target("192.168.1.5".parse().unwrap()));
        // Источник: link-local сосед — не «свой».
        assert!(!is_local_host("169.254.10.10".parse().unwrap()));
    }

    /// Облачный metadata (link-local) клиентам из сети недоступен — отказ
    /// сразу, без попытки соединения.
    #[tokio::test]
    async fn direct_denies_link_local_to_lan_clients() {
        let d = DirectOutbound::new("direct");
        for (source, target) in [
            ("192.168.1.50:5000", "169.254.169.254"),
            ("169.254.10.10:5000", "169.254.169.254"),
            ("[2001:db8::5]:5000", "fe80::1"),
        ] {
            let target = match target.parse::<IpAddr>().unwrap() {
                IpAddr::V4(v) => Address::Ipv4(v),
                IpAddr::V6(v) => Address::Ipv6(v),
            };
            let m = meta(source, target.clone(), 80, Network::Tcp);
            let e = tokio::time::timeout(Duration::from_secs(2), d.connect(&m))
                .await
                .expect("отказ до подключения, а не таймаут")
                .err()
                .expect("должен быть отказ");
            assert!(e.to_string().contains("нельзя"), "{source} → {target}: {e}");
        }
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
