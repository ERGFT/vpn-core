// SPDX-License-Identifier: GPL-3.0-or-later
//! Вход `tun`: виртуальный сетевой интерфейс, как у VPN. Весь трафик
//! компьютера (при `auto_route`) попадает в интерфейс, свой TCP/IP-стек
//! (smoltcp через `netstack-smoltcp`) превращает пакеты в соединения, и
//! дальше они идут тем же путём, что и соединения из SOCKS5:
//! маршрутизатор → выход.
//!
//! - TCP: соединение с приложением принимается сразу, выход открывается
//!   следом; не открылся — соединение с приложением закрывается.
//! - UDP: поток на каждую пару (приложение, назначение), см. [`udp`];
//!   ответы идут от того адреса, куда приложение отправляло (в том числе
//!   от fake-IP).
//! - DNS (порт 53 на любой адрес, UDP и TCP) при `dns_hijack` отвечает
//!   свой DNS-модуль — что бы ни было записано в настройках системы.
//! - Широковещательные и групповые пакеты, ICMP — отбрасываются.
//!
//! Собственные соединения клиента в TUN не попадают: см.
//! [`crate::net_protect`] и [`route`].

pub mod route;
mod udp;
#[cfg(windows)]
pub mod wfp;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::access::IpNet;
use super::dns::{answer_bytes, Dns};
use super::outbound::UDP_IDLE;
use super::router::{Router, RouterHandle};
use super::sniff;
use super::sniff_quic;
use super::{Metadata, Network};
use crate::error::{Error, Result};
use crate::relay;
use crate::vless::Address;

/// Настройки входа `tun` (уже проверенные).
#[derive(Debug, Clone)]
pub struct TunSettings {
    pub name: String,
    pub inet4: IpNet,
    pub inet6: Option<IpNet>,
    /// IPv6 задан в настройках явно (иначе — по умолчанию, и без IPv6 в
    /// системе его можно тихо не включать).
    pub inet6_explicit: bool,
    pub mtu: u16,
    pub auto_route: bool,
    pub route_exclude: Vec<IpNet>,
    /// Kill switch (Linux): без живого TUN трафик не идёт мимо туннеля.
    pub strict_route: bool,
    pub dns_hijack: bool,
    pub sniff: bool,
    pub sniff_override: bool,
    pub max_conns: usize,
    /// Готовый дескриптор TUN от системы (режим библиотеки, Android/iOS).
    pub fd: Option<i32>,
}

pub struct TunInbound {
    pub tag: Arc<str>,
    pub settings: TunSettings,
}

/// Окно TCP к приложению (буферы приёма и отправки стека, байт).
const TCP_WINDOW: u32 = 256 * 1024;
/// Очереди пакетов между устройством и стеком.
const PACKET_QUEUE: usize = 4096;

/// Перекачка пакетов между устройством и стеком в обе стороны.
async fn pump(dev: tun_rs::AsyncDevice, stack: netstack_smoltcp::Stack, mtu: u16) -> Result<()> {
    let dev = Arc::new(dev);
    let (mut to_stack, mut from_stack) = stack.split();
    let rx_dev = dev.clone();
    let inbound = async move {
        // С запасом над MTU: устройство может отдать пакет чуть длиннее.
        let mut buf = vec![0u8; mtu as usize + 256];
        loop {
            let n = rx_dev.recv(&mut buf).await?;
            if n == 0 {
                continue;
            }
            // Битый пакет стек отвергает ошибкой — это не повод
            // останавливать весь TUN.
            if let Err(e) = to_stack.send(buf[..n].to_vec()).await {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    return Err::<(), std::io::Error>(e);
                }
                tracing::trace!(error = %e, "tun: пакет отброшен стеком");
            }
        }
    };
    let outbound = async move {
        while let Some(p) = from_stack.next().await {
            dev.send(&p?).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        r = inbound => r,
        r = outbound => r,
    }
    .map_err(|e| Error::Protocol(format!("tun: устройство: {e}")))
}

fn ip_address(ip: IpAddr) -> Address {
    match ip.to_canonical() {
        IpAddr::V4(v4) => Address::Ipv4(v4),
        IpAddr::V6(v6) => Address::Ipv6(v6),
    }
}

/// Не для прокси: широковещание, групповые адреса, «никуда».
fn is_local_only(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
    }
}

/// Созданный интерфейс: адреса, имя; маршруты держит [`route::RouteGuard`].
pub struct TunDevice {
    pub name: String,
    /// Включён ли IPv6 на интерфейсе.
    pub has_v6: bool,
    /// Номер интерфейса (Windows: для маршрутов).
    pub if_index: Option<u32>,
    dev: tun_rs::AsyncDevice,
}

impl TunInbound {
    /// Создать интерфейс (нужны права администратора / root).
    pub fn create_device(&self) -> Result<TunDevice> {
        let s = &self.settings;
        if let Some(fd) = s.fd {
            return self.device_from_fd(fd);
        }
        let err = |e: std::io::Error| {
            Error::Config(format!(
                "tun: не удалось создать интерфейс {}: {e}{}",
                s.name,
                if cfg!(windows) {
                    " (нужны права администратора и wintun.dll рядом с программой)"
                } else {
                    " (нужны права root или CAP_NET_ADMIN)"
                }
            ))
        };
        let mut b = tun_rs::DeviceBuilder::new()
            .name(s.name.clone())
            .ipv4(
                match s.inet4.addr() {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => unreachable!("проверено при сборке"),
                },
                s.inet4.prefix(),
                None,
            )
            .mtu(s.mtu);
        // В системе без IPv6 адрес IPv6 не назначить; раз его нет, то и
        // утекать мимо TUN нечему.
        let v6_ok = std::net::UdpSocket::bind("[::1]:0").is_ok();
        let use_v6 = match (&s.inet6, v6_ok) {
            (Some(_), true) => true,
            (Some(_), false) if s.inet6_explicit => {
                return Err(Error::Config(
                    "tun: inet6_address задан, но IPv6 в системе выключен".into(),
                ))
            }
            (Some(_), false) => {
                tracing::info!("tun: IPv6 в системе нет — интерфейс только IPv4");
                false
            }
            (None, _) => false,
        };
        if let (Some(v6), true) = (&s.inet6, use_v6) {
            if let IpAddr::V6(a) = v6.addr() {
                b = b.ipv6(a, v6.prefix());
            }
        }
        #[cfg(windows)]
        {
            // Меньшая метрика — Windows предпочитает этот интерфейс (в том
            // числе для DNS).
            b = b.metric(1);
        }
        let dev = b.build_async().map_err(err)?;
        let name = dev.name().unwrap_or_else(|_| s.name.clone());
        #[cfg(windows)]
        if s.dns_hijack {
            // DNS интерфейса — соседний адрес в подсети TUN: запрос к нему
            // уйдёт в TUN и будет перехвачен.
            if let IpAddr::V4(a) = s.inet4.addr() {
                let peer = IpAddr::V4(std::net::Ipv4Addr::from(u32::from(a) + 1));
                if let Err(e) = dev.set_dns_servers(&[peer]) {
                    tracing::warn!(error = %e, "tun: не удалось задать DNS интерфейса");
                }
            }
        }
        #[cfg(windows)]
        let if_index = dev.if_index().ok();
        #[cfg(not(windows))]
        let if_index = None;
        Ok(TunDevice {
            name,
            has_v6: use_v6,
            if_index,
            dev,
        })
    }

    /// Устройство из готового дескриптора (режим библиотеки).
    #[cfg(unix)]
    fn device_from_fd(&self, fd: i32) -> Result<TunDevice> {
        // SAFETY: дескриптор передан владельцем (приложение отдало его
        // ядру) и дальше закрывается только устройством.
        let dev = unsafe { tun_rs::AsyncDevice::from_fd(fd) }
            .map_err(|e| Error::Config(format!("tun: дескриптор {fd}: {e}")))?;
        tracing::info!(fd, "tun: устройство из готового дескриптора");
        Ok(TunDevice {
            name: self.settings.name.clone(),
            has_v6: self.settings.inet6.is_some(),
            if_index: None,
            dev,
        })
    }

    #[cfg(not(unix))]
    fn device_from_fd(&self, _fd: i32) -> Result<TunDevice> {
        Err(Error::Config(
            "tun: готовый дескриптор — только на Unix (Android, iOS, Linux)".into(),
        ))
    }

    /// Принимать соединения из интерфейса.
    pub async fn serve(
        self: Arc<Self>,
        device: TunDevice,
        routers: Arc<RouterHandle>,
    ) -> Result<()> {
        let stack_err = |e: std::io::Error| Error::Protocol(format!("tun: стек: {e}"));
        let (stack, runner, udp, tcp) = netstack_smoltcp::StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .mtu(self.settings.mtu as usize)
            // Окно TCP к приложению: пропускная способность одного
            // соединения — окно ÷ RTT. Память буферов выделяется сразу, но
            // страницы, в которые ещё не писали, система не заводит.
            .tcp_recv_buffer_size(TCP_WINDOW)
            .tcp_send_buffer_size(TCP_WINDOW)
            // Очереди пакетов между устройством и стеком (в пакетах).
            .stack_buffer_size(PACKET_QUEUE)
            .tcp_buffer_size(PACKET_QUEUE)
            .udp_buffer_size(PACKET_QUEUE)
            .build()
            .map_err(stack_err)?;
        let (Some(runner), Some(udp), Some(mut tcp)) = (runner, udp, tcp) else {
            return Err(Error::Protocol("tun: стек собран без TCP/UDP".into()));
        };
        let slots = Arc::new(tokio::sync::Semaphore::new(self.settings.max_conns.max(1)));
        let (udp_read, udp_write) = udp.split();
        let (udp_tx, mut udp_rx) = tokio::sync::mpsc::channel(PACKET_QUEUE);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move { runner.await.map_err(stack_err) });
        tasks.spawn(pump(device.dev, stack, self.settings.mtu));
        let udp_slots = slots.clone();
        tasks.spawn(async move {
            udp::dispatch(udp_read, udp_write, udp_slots, UDP_IDLE, udp_tx).await;
            Ok(())
        });
        loop {
            tokio::select! {
                s = tcp.next() => {
                    let Some((t, _, _)) = s else {
                        return Err(Error::Protocol("tun: стек остановился".into()));
                    };
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        // Переполнено: соединение закрывается сразу.
                        tracing::debug!("tun: предел соединений — новое отброшено");
                        continue;
                    };
                    let (this, router) = (self.clone(), routers.get());
                    tokio::spawn(async move {
                        let _permit = permit;
                        let (src, dst) = (*t.local_addr(), *t.remote_addr());
                        if let Err(e) = this.tcp(t, &router).await {
                            tracing::debug!(%src, %dst, error = %e, "tun: TCP-соединение завершилось с ошибкой");
                        }
                    });
                }
                Some(u) = udp_rx.recv() => {
                    let (this, router) = (self.clone(), routers.get());
                    tokio::spawn(async move {
                        let (src, dst) = (u.local_addr(), u.peer_addr());
                        if let Err(e) = this.udp(u, &router).await {
                            tracing::debug!(%src, %dst, error = %e, "tun: UDP-поток завершился с ошибкой");
                        }
                    });
                }
                Some(r) = tasks.join_next() => {
                    return match r {
                        Ok(Ok(())) => Err(Error::Protocol("tun: стек остановился".into())),
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(Error::Protocol(format!("tun: стек: {e}"))),
                    };
                }
            }
        }
    }

    async fn tcp(&self, mut t: netstack_smoltcp::TcpStream, router: &Router) -> Result<()> {
        let (src, dst) = (*t.local_addr(), *t.remote_addr());
        if is_local_only(dst.ip()) {
            return Ok(());
        }
        if self.settings.dns_hijack && dst.port() == 53 {
            if let Some(dns) = router.dns() {
                return dns_over_tcp(dns, &mut t).await;
            }
        }
        if in_tun_net(&self.settings, dst) {
            return Ok(());
        }
        let mut meta = Metadata {
            inbound: self.tag.clone(),
            source: src,
            network: Network::Tcp,
            target: ip_address(dst.ip()),
            port: dst.port(),
            sniffed: None,
            inbound_type: "tun",
            rule: None,
        };
        let mut initial = Vec::new();
        if self.settings.sniff {
            meta.sniffed = sniff::read_and_sniff(&mut t, &mut initial).await?;
        }
        let outbound = router.route(&mut meta).await?;
        if self.settings.sniff_override && !matches!(meta.target, Address::Domain(_)) {
            if let Some(d) = &meta.sniffed {
                meta.target = Address::Domain(d.clone());
            }
        }
        let (mut remote, conn) = match router.dial(&outbound, &meta).await {
            Ok(r) => r,
            Err(Error::Blocked) => return Ok(()),
            Err(e) => return Err(e),
        };
        if !initial.is_empty() {
            remote.write_all(&initial).await?;
        }
        tracing::debug!(target = %meta.target, port = meta.port, outbound = outbound.tag(), "tun: проксирую");
        tokio::select! {
            r = relay::copy_bidirectional(t, remote) => { r?; }
            _ = conn.cancelled() => {}
        }
        Ok(())
    }

    async fn udp(&self, mut u: udp::UdpFlow, router: &Router) -> Result<()> {
        let (src, dst) = (u.local_addr(), u.peer_addr());
        if is_local_only(dst.ip()) {
            return Ok(());
        }
        let mut buf = vec![0u8; 65535];
        if self.settings.dns_hijack && dst.port() == 53 {
            if let Some(dns) = router.dns().cloned() {
                loop {
                    let n = u.read(&mut buf).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    if let Some(a) = answer_bytes(&dns, &buf[..n], true).await {
                        u.write_all(&a).await?;
                    }
                }
            }
        }
        if in_tun_net(&self.settings, dst) {
            return Ok(());
        }
        let mut meta = Metadata {
            inbound: self.tag.clone(),
            source: src,
            network: Network::Udp,
            target: ip_address(dst.ip()),
            port: dst.port(),
            sniffed: None,
            inbound_type: "tun",
            rule: None,
        };
        // QUIC (HTTP/3): домен из ClientHello в первых Initial-пакетах.
        let mut pending = Vec::new();
        if self.settings.sniff {
            meta.sniffed = sniff_quic::read_and_sniff(&mut u, &mut pending).await?;
            if pending.is_empty() {
                return Ok(());
            }
            if let Some(d) = &meta.sniffed {
                tracing::debug!(ip = %meta.target, domain = %d, "sniffing QUIC: найден домен");
            }
        }
        let outbound = router.route(&mut meta).await?;
        if self.settings.sniff_override && !matches!(meta.target, Address::Domain(_)) {
            if let Some(d) = &meta.sniffed {
                meta.target = Address::Domain(d.clone());
            }
        }
        let session = outbound.udp(&meta).await?;
        let member = outbound.as_group().and_then(|g| g.current());
        let conn = router.tracker().open(&meta, outbound.tag(), member);
        for d in pending {
            conn.add_up(d.len() as u64);
            session.send(meta.target.clone(), meta.port, d).await?;
        }
        loop {
            tokio::select! {
                r = u.read(&mut buf) => {
                    let n = r?;
                    if n == 0 {
                        return Ok(());
                    }
                    conn.add_up(n as u64);
                    session.send(meta.target.clone(), meta.port, buf[..n].to_vec()).await?;
                }
                r = session.recv() => {
                    match r? {
                        // Ответ пишется «от» адреса, куда отправляло
                        // приложение (так устроен [`udp::UdpFlow`]).
                        Some((_, _, data)) => {
                            conn.add_down(data.len() as u64);
                            u.write_all(&data).await?
                        }
                        None => return Ok(()),
                    }
                }
                _ = conn.info.cancelled() => return Ok(()),
            }
        }
    }
}

/// DNS поверх TCP: запросы с длиной впереди.
async fn dns_over_tcp<S: AsyncRead + AsyncWrite + Unpin>(dns: &Dns, t: &mut S) -> Result<()> {
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(Duration::from_secs(30), t.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }
        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
        t.read_exact(&mut q).await?;
        let Some(a) = answer_bytes(dns, &q, true).await else {
            return Ok(());
        };
        let mut out = (a.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&a);
        t.write_all(&out).await?;
    }
}

/// Проверить и дополнить настройки по умолчанию.
pub fn settings(i: &super::config::InboundConfig) -> Result<TunSettings> {
    let inet4 = i
        .inet4_address
        .unwrap_or_else(|| "172.19.0.1/30".parse().unwrap());
    if !inet4.addr().is_ipv4() || inet4.prefix() > 30 {
        return Err(Error::Config(
            "tun: inet4_address — IPv4-адрес с подсетью не меньше /30".into(),
        ));
    }
    let inet6 = match i.inet6_address {
        Some(a) if !a.addr().is_ipv6() => {
            return Err(Error::Config("tun: inet6_address — IPv6-адрес".into()))
        }
        Some(a) => Some(a),
        None => Some("fdfe:dcba:9876::1/126".parse().unwrap()),
    };
    let mtu = i.mtu.unwrap_or(1500);
    if !(1280..=65535).contains(&mtu) {
        return Err(Error::Config("tun: mtu — от 1280 до 65535".into()));
    }
    Ok(TunSettings {
        name: i
            .interface_name
            .clone()
            .unwrap_or_else(|| "reality-tun".into()),
        inet4,
        inet6,
        inet6_explicit: i.inet6_address.is_some(),
        mtu,
        // С готовым дескриптором маршруты и kill switch — забота системы
        // (у Android — VpnService).
        auto_route: i.wants_auto_route(),
        route_exclude: i.route_exclude.clone(),
        strict_route: i.tun_fd.is_none() && i.strict_route.unwrap_or(false),
        dns_hijack: i.dns_hijack.unwrap_or(true),
        sniff: i.sniff,
        sniff_override: i.sniff_override_destination,
        max_conns: i.max_conns.unwrap_or(4096),
        fd: i.tun_fd,
    })
}

/// Назначение — в подсети самого TUN (кроме DNS там никого нет).
pub fn in_tun_net(s: &TunSettings, ip: SocketAddr) -> bool {
    s.inet4.contains(ip.ip()) || s.inet6.is_some_and(|n| n.contains(ip.ip()))
}
