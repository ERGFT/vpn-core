// SPDX-License-Identifier: GPL-3.0-or-later
//! Защита собственных сокетов клиента от петли через TUN.
//!
//! Когда TUN перехватывает весь трафик компьютера, соединения самого
//! клиента (к VLESS-серверу, выход `direct`, DNS-серверы) тоже попали бы в
//! TUN — и снова в клиент. Поэтому каждый исходящий сокет помечается:
//! - Linux: метка `SO_MARK`; правило `ip rule fwmark … lookup main`
//!   отправляет такие пакеты мимо таблицы с TUN;
//! - Windows: `IP_UNICAST_IF` — сокет привязан к физическому интерфейсу.
//!
//! - Android (`VpnService`), iOS — обратный вызов приложения
//!   ([`set_callback`]): оно само «защищает» сокет системным вызовом
//!   (`VpnService.protect(fd)`).
//!
//! Без TUN защита не включена и сокеты создаются как обычно.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use tokio::net::{TcpSocket, UdpSocket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protect {
    /// Метка `SO_MARK` (Linux).
    Mark(u32),
    /// Индексы физического интерфейса для IPv4 и IPv6 (Windows).
    Interface { v4: u32, v6: Option<u32> },
}

/// Обратный вызов защиты: получает дескриптор (Unix) или сокет (Windows);
/// `false` — защитить не удалось.
pub type ProtectFn = dyn Fn(i64) -> bool + Send + Sync;

static PROTECT: RwLock<Option<Protect>> = RwLock::new(None);
static PROTECT_FN: RwLock<Option<Arc<ProtectFn>>> = RwLock::new(None);
static TUN_ACTIVE: AtomicBool = AtomicBool::new(false);

fn update_active() {
    let on = PROTECT
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
        || PROTECT_FN
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some();
    TUN_ACTIVE.store(on, Ordering::SeqCst);
}

/// Включить (или выключить — `None`) защиту для всех новых сокетов.
pub fn set(p: Option<Protect>) {
    *PROTECT
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = p;
    update_active();
}

/// Защищать новые сокеты обратным вызовом приложения (Android
/// `VpnService.protect`); `None` — перестать.
pub fn set_callback(f: Option<Arc<ProtectFn>>) {
    *PROTECT_FN
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = f;
    update_active();
}

pub fn current() -> Option<Protect> {
    *PROTECT
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Работает ли TUN с перехватом маршрутов (тогда системный DNS тоже идёт
/// через клиент — см. `transport::tcp_tls::resolve_server`).
pub fn tun_active() -> bool {
    TUN_ACTIVE.load(Ordering::SeqCst)
}

fn apply(sock: socket2::SockRef<'_>, v6: bool) -> io::Result<()> {
    let cb = PROTECT_FN
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(f) = cb {
        #[cfg(unix)]
        let raw = std::os::fd::AsRawFd::as_raw_fd(&*sock) as i64;
        #[cfg(windows)]
        let raw = std::os::windows::io::AsRawSocket::as_raw_socket(&*sock) as i64;
        if !f(raw) {
            return Err(io::Error::other("приложение не защитило сокет (protect)"));
        }
    }
    match current() {
        None => Ok(()),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Some(Protect::Mark(m)) => sock.set_mark(m),
        #[cfg(windows)]
        Some(Protect::Interface { v4, v6: idx6 }) => windows::unicast_if(&sock, v6, v4, idx6),
        #[allow(unreachable_patterns)]
        Some(p) => {
            let _ = (sock, v6);
            Err(io::Error::other(format!(
                "защита сокета {p:?} на этой платформе не поддерживается"
            )))
        }
    }
}

/// TCP-сокет для исходящего соединения к `addr`.
pub fn tcp_socket(addr: &SocketAddr) -> io::Result<TcpSocket> {
    let s = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    apply(socket2::SockRef::from(&s), addr.is_ipv6())?;
    Ok(s)
}

/// UDP-сокет на `bind` (обычно `0.0.0.0:0` или `[::]:0`).
pub fn udp_bind(bind: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if bind.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if bind.is_ipv6() {
        // Только IPv6: IPv4 обслуживает отдельный сокет.
        s.set_only_v6(true)?;
    }
    apply(socket2::SockRef::from(&s), bind.is_ipv6())?;
    s.set_nonblocking(true)?;
    s.bind(&bind.into())?;
    UdpSocket::from_std(s.into())
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET,
    };

    pub fn unicast_if(
        sock: &socket2::SockRef<'_>,
        is_v6: bool,
        v4: u32,
        v6: Option<u32>,
    ) -> io::Result<()> {
        let raw = sock.as_raw_socket() as SOCKET;
        let (level, opt, val) = if is_v6 {
            match v6 {
                // Для IPv6 индекс — в обычном порядке байт.
                Some(i) => (IPPROTO_IPV6, IPV6_UNICAST_IF, i),
                // У компьютера нет выхода в IPv6: сокет без привязки ушёл
                // бы по маршруту через TUN обратно в клиент — петля,
                // съедающая все соединения. Лучше сразу «сеть недоступна».
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "нет IPv6 мимо TUN (у физического интерфейса нет IPv6)",
                    ))
                }
            }
        } else {
            // Для IPv4 — в сетевом порядке байт (так требует Windows).
            (IPPROTO_IP, IP_UNICAST_IF, v4.to_be())
        };
        // SAFETY: значение — u32, длина передаётся явно.
        let r = unsafe {
            setsockopt(
                raw,
                level,
                opt,
                (&val as *const u32).cast(),
                std::mem::size_of::<u32>() as i32,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
