// SPDX-License-Identifier: GPL-3.0-or-later
//! Вход `tun`: виртуальный сетевой интерфейс, как у VPN. Весь трафик
//! компьютера (при `auto_route`) попадает в интерфейс, свой TCP/IP-стек
//! (`ipstack`) превращает пакеты в соединения, и дальше они идут тем же
//! путём, что и соединения из SOCKS5: маршрутизатор → выход.
//!
//! - TCP: соединение с приложением принимается сразу, выход открывается
//!   следом; не открылся — приложению уходит сброс.
//! - UDP: поток на каждую пару (приложение, назначение); ответы идут от
//!   того адреса, куда приложение отправляло (в том числе от fake-IP).
//! - DNS (порт 53 на любой адрес, UDP и TCP) при `dns_hijack` отвечает
//!   свой DNS-модуль — что бы ни было записано в настройках системы.
//! - Широковещательные и групповые пакеты, ICMP — отбрасываются.
//!
//! Собственные соединения клиента в TUN не попадают: см.
//! [`crate::net_protect`] и [`route`].

pub mod route;

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ipstack::{
    IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream, TcpConfig,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

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
}

pub struct TunInbound {
    pub tag: Arc<str>,
    pub settings: TunSettings,
}

/// Пакетный ввод-вывод устройства как поток для `ipstack`: одно чтение —
/// один пакет, одна запись — один пакет.
struct TunIo(tun_rs::AsyncDevice);

impl AsyncRead for TunIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let dst = buf.initialize_unfilled();
        match self.0.poll_recv(cx, dst) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TunIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
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

    /// Принимать соединения из интерфейса.
    pub async fn serve(
        self: Arc<Self>,
        device: TunDevice,
        routers: Arc<RouterHandle>,
    ) -> Result<()> {
        let mut cfg = IpStackConfig::default();
        cfg.mtu(self.settings.mtu)
            .map_err(|e| Error::Config(format!("tun: mtu: {e}")))?;
        cfg.udp_timeout(UDP_IDLE);
        let mut tcp = TcpConfig::default();
        // По умолчанию у ipstack окно 16 КиБ и простой 60 с: для
        // скачиваний мало, а долгие тихие соединения (SSH) рвались бы
        // (простой и так ограничивает релей). Опцию MSS в SYN-ACK не
        // ставим: с ней ipstack 1.0 на проверке терял соединения
        // (scripts/tun_netns.sh, 4 из 4), без неё — ни разу, ~85 МиБ/с.
        tcp.max_unacked_bytes = 512 * 1024;
        tcp.read_buffer_size = 256 * 1024;
        tcp.timeout = Duration::from_secs(3600);
        tcp.max_retransmit_count = 8;
        cfg.with_tcp_config(tcp);
        let mut stack = IpStack::new(cfg, TunIo(device.dev));
        let slots = Arc::new(tokio::sync::Semaphore::new(self.settings.max_conns.max(1)));
        loop {
            let stream = stack
                .accept()
                .await
                .map_err(|e| Error::Protocol(format!("tun: стек остановился: {e}")))?;
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                // Переполнено: соединение сбрасывается (стрим уничтожается).
                tracing::debug!("tun: предел соединений — новое отброшено");
                continue;
            };
            let (this, router) = (self.clone(), routers.get());
            match stream {
                IpStackStream::Tcp(t) => {
                    tokio::spawn(async move {
                        let _permit = permit;
                        let (src, dst) = (t.local_addr(), t.peer_addr());
                        if let Err(e) = this.tcp(t, &router).await {
                            tracing::debug!(%src, %dst, error = %e, "tun: TCP-соединение завершилось с ошибкой");
                        }
                    });
                }
                IpStackStream::Udp(u) => {
                    tokio::spawn(async move {
                        let _permit = permit;
                        let (src, dst) = (u.local_addr(), u.peer_addr());
                        if let Err(e) = this.udp(u, &router).await {
                            tracing::debug!(%src, %dst, error = %e, "tun: UDP-поток завершился с ошибкой");
                        }
                    });
                }
                IpStackStream::UnknownTransport(u) => {
                    tracing::trace!(proto = ?u.ip_protocol(), dst = %u.dst_addr(), "tun: пакет не TCP/UDP — отброшен");
                }
                IpStackStream::UnknownNetwork(_) => {}
            }
        }
    }

    async fn tcp(&self, mut t: IpStackTcpStream, router: &Router) -> Result<()> {
        let (src, dst) = (t.local_addr(), t.peer_addr());
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

    async fn udp(&self, mut u: IpStackUdpStream, router: &Router) -> Result<()> {
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
                        // приложение (так устроен поток ipstack).
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
async fn dns_over_tcp(dns: &Dns, t: &mut IpStackTcpStream) -> Result<()> {
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
        auto_route: i.auto_route.unwrap_or(true),
        route_exclude: i.route_exclude.clone(),
        strict_route: i.strict_route.unwrap_or(false),
        dns_hijack: i.dns_hijack.unwrap_or(true),
        sniff: i.sniff,
        sniff_override: i.sniff_override_destination,
        max_conns: i.max_conns.unwrap_or(4096),
    })
}

/// Назначение — в подсети самого TUN (кроме DNS там никого нет).
pub fn in_tun_net(s: &TunSettings, ip: SocketAddr) -> bool {
    s.inet4.contains(ip.ip()) || s.inet6.is_some_and(|n| n.contains(ip.ip()))
}
