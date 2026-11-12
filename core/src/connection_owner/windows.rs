// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows flow ownership via IP Helper and the owning process image.

use std::ffi::c_void;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::app::Network;

fn unique_pid<T: Copy>(
    api: impl Fn(*mut c_void, &mut u32) -> u32,
    matching_pid: impl Fn(T) -> Option<u32>,
) -> Option<u32> {
    let mut size = 0;
    if api(std::ptr::null_mut(), &mut size) != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    for _ in 0..3 {
        if !(4..=16 * 1024 * 1024).contains(&size) {
            return None;
        }
        // DWORD alignment for IP Helper. Every byte is initialized before reading.
        let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
        let status = api(buffer.as_mut_ptr().cast(), &mut size);
        if status == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if status != NO_ERROR || size as usize > buffer.len() * 4 || size < 4 {
            return None;
        }
        let rows = buffer[0] as usize;
        if rows > (size as usize - 4) / size_of::<T>() {
            return None;
        }
        let mut owner = None;
        for index in 0..rows {
            // The table starts with a DWORD count followed by its documented row type.
            let row = unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(4 + index * size_of::<T>())
                    .cast::<T>()
                    .read_unaligned()
            };
            if let Some(pid) = matching_pid(row) {
                if pid == 0 || owner.is_some_and(|previous| previous != pid) {
                    return None;
                }
                owner = Some(pid);
            }
        }
        return owner;
    }
    None
}

fn port(value: u32) -> u16 {
    u16::from_be(value as u16)
}

fn scope_matches(expected: u32, found: u32) -> bool {
    expected == 0 || expected == found
}

fn owner_pid(network: Network, source: SocketAddr, destination: SocketAddr) -> Option<u32> {
    let tcp = |family| {
        move |table, size: &mut u32| unsafe {
            GetExtendedTcpTable(
                table,
                size,
                0,
                u32::from(family),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }
    };
    let udp = |family| {
        move |table, size: &mut u32| unsafe {
            GetExtendedUdpTable(table, size, 0, u32::from(family), UDP_TABLE_OWNER_PID, 0)
        }
    };
    match (network, source, destination) {
        (Network::Tcp, SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            unique_pid(tcp(AF_INET), |r: MIB_TCPROW_OWNER_PID| {
                (Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()) == *src.ip()
                    && Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes()) == *dst.ip()
                    && port(r.dwLocalPort) == src.port()
                    && port(r.dwRemotePort) == dst.port())
                .then_some(r.dwOwningPid)
            })
        }
        (Network::Tcp, SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            unique_pid(tcp(AF_INET6), |r: MIB_TCP6ROW_OWNER_PID| {
                (Ipv6Addr::from(r.ucLocalAddr) == *src.ip()
                    && Ipv6Addr::from(r.ucRemoteAddr) == *dst.ip()
                    && scope_matches(src.scope_id(), r.dwLocalScopeId)
                    && scope_matches(dst.scope_id(), r.dwRemoteScopeId)
                    && port(r.dwLocalPort) == src.port()
                    && port(r.dwRemotePort) == dst.port())
                .then_some(r.dwOwningPid)
            })
        }
        (Network::Udp, SocketAddr::V4(src), SocketAddr::V4(_)) => {
            unique_pid(udp(AF_INET), |r: MIB_UDPROW_OWNER_PID| {
                let ip = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
                (port(r.dwLocalPort) == src.port() && (ip == *src.ip() || ip.is_unspecified()))
                    .then_some(r.dwOwningPid)
            })
        }
        (Network::Udp, SocketAddr::V6(src), SocketAddr::V6(_)) => {
            unique_pid(udp(AF_INET6), |r: MIB_UDP6ROW_OWNER_PID| {
                let ip = Ipv6Addr::from(r.ucLocalAddr);
                (port(r.dwLocalPort) == src.port()
                    && (ip.is_unspecified()
                        || (ip == *src.ip() && scope_matches(src.scope_id(), r.dwLocalScopeId))))
                .then_some(r.dwOwningPid)
            })
        }
        _ => None,
    }
}

pub(super) fn image(network: Network, src: SocketAddr, dst: SocketAddr) -> Option<Arc<str>> {
    let pid = owner_pid(network, src, dst)?;
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut path = vec![0u16; 32768];
    let mut size = path.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut size) };
    // Hold the process handle while confirming the flow still has the same PID.
    let unchanged = ok != 0 && owner_pid(network, src, dst) == Some(pid);
    unsafe { CloseHandle(handle) };
    if !unchanged {
        return None;
    }
    let path = String::from_utf16(path.get(..size as usize)?).ok()?;
    (!path.is_empty()).then(|| Arc::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn identifies_loopback_tcp_and_udp_images() {
        for host in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(host).unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            assert_eq!(
                owner_pid(
                    Network::Tcp,
                    client.local_addr().unwrap(),
                    accepted.local_addr().unwrap()
                ),
                Some(std::process::id())
            );
            let actual = image(
                Network::Tcp,
                client.local_addr().unwrap(),
                accepted.local_addr().unwrap(),
            )
            .unwrap();
            assert!(
                actual.eq_ignore_ascii_case(&std::env::current_exe().unwrap().to_string_lossy())
            );
            let udp = UdpSocket::bind(host).unwrap();
            assert_eq!(
                owner_pid(
                    Network::Udp,
                    udp.local_addr().unwrap(),
                    accepted.local_addr().unwrap()
                ),
                Some(std::process::id())
            );
        }
    }
}
