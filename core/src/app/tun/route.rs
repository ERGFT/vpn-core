// SPDX-License-Identifier: GPL-3.0-or-later
//! `auto_route`: направить трафик компьютера в TUN и вернуть как было.
//!
//! Linux (как у sing-box): своя таблица маршрутов с маршрутом по
//! умолчанию через TUN и два правила —
//! `fwmark 0x7e2 → main` (соединения самого клиента, помеченные
//! [`crate::net_protect`], идут обычным путём) и `всё остальное → таблица
//! TUN`. Подсети из `route_exclude` — правила `to … lookup main`. Если
//! клиент убит, интерфейс исчезает вместе со своими маршрутами, таблица
//! пустеет, и трафик снова идёт по main: сеть не «зависает». С
//! `strict_route` (kill switch) после таблицы TUN стоит запрет
//! `unreachable`: убитый клиент оставляет сеть закрытой (кроме
//! `route_exclude`), пока его не запустят снова или не выполнят
//! `reality-client --tun-cleanup`.
//!
//! Windows: маршруты `0.0.0.0/1` и `128.0.0.0/1` (и `::/1`, `8000::/1`)
//! через TUN — они точнее маршрута по умолчанию; соединения клиента
//! привязаны к физическому интерфейсу (`IP_UNICAST_IF`). Маршруты живут,
//! пока жив интерфейс.

use crate::app::access::IpNet;
use crate::error::{Error, Result};
use crate::net_protect;

/// Метка сокетов клиента и номер таблицы маршрутов (Linux).
pub const MARK: u32 = 0x7e2;
pub const TABLE: u32 = 2022;
#[cfg(target_os = "linux")]
const PREF_MARK: u32 = 9000;
#[cfg(target_os = "linux")]
const PREF_TUN: u32 = 9001;
#[cfg(target_os = "linux")]
const PREF_BLOCK: u32 = 9002;

/// Пока жив — трафик идёт в TUN; при уничтожении маршруты снимаются.
pub struct RouteGuard {
    down: Vec<Vec<String>>,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for cmd in &self.down {
            let _ = run(cmd, true);
        }
        net_protect::set(None);
        tracing::info!("tun: маршруты возвращены");
    }
}

fn run(cmd: &[String], quiet: bool) -> Result<()> {
    let out = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .output()
        .map_err(|e| Error::Config(format!("tun: не удалось запустить {}: {e}", cmd[0])))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if !quiet {
            return Err(Error::Config(format!(
                "tun: команда «{}» не удалась: {msg}",
                cmd.join(" ")
            )));
        }
    }
    Ok(())
}

fn args(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

/// Включить маршруты. `ifname` — имя TUN, `if_index` — его номер
/// (нужен на Windows).
pub fn setup(
    ifname: &str,
    if_index: Option<u32>,
    v6: bool,
    exclude: &[IpNet],
    strict: bool,
) -> Result<RouteGuard> {
    #[cfg(target_os = "linux")]
    {
        let _ = if_index;
        linux(ifname, v6, exclude, strict)
    }
    #[cfg(windows)]
    {
        if strict {
            return Err(Error::Config(
                "tun: strict_route (kill switch) пока есть только на Linux".into(),
            ));
        }
        windows(ifname, if_index, v6, exclude)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (ifname, if_index, v6, exclude, strict);
        Err(Error::Config(
            "tun: auto_route есть только для Linux и Windows".into(),
        ))
    }
}

/// Снять правила и таблицу TUN, оставшиеся после аварийного завершения
/// (в том числе блокировку `strict_route`). Linux.
pub fn cleanup() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        for cmd in linux_down() {
            let _ = run(&cmd, true);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::Config(
            "--tun-cleanup нужен только на Linux: на Windows маршруты исчезают вместе с интерфейсом".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_down() -> Vec<Vec<String>> {
    let mut down = Vec::new();
    for f in ["-4", "-6"] {
        // Правил с одним приоритетом может быть несколько — по одному за раз.
        for pref in [PREF_MARK, PREF_TUN, PREF_BLOCK] {
            for _ in 0..16 {
                down.push(args(&format!("ip {f} rule del pref {pref}")));
            }
        }
        down.push(args(&format!("ip {f} route flush table {TABLE}")));
    }
    down
}

#[cfg(target_os = "linux")]
fn linux(ifname: &str, v6: bool, exclude: &[IpNet], strict: bool) -> Result<RouteGuard> {
    let fams: Vec<&str> = if v6 { vec!["-4", "-6"] } else { vec!["-4"] };
    let down = linux_down();
    // Остатки прошлого запуска (если его убили) — убрать.
    for cmd in &down {
        let _ = run(cmd, true);
    }
    // Метка — раньше правил: иначе первые же соединения клиента ушли бы в TUN.
    net_protect::set(Some(net_protect::Protect::Mark(MARK)));
    let guard = RouteGuard { down };
    let mut up = Vec::new();
    for f in &fams {
        up.push(args(&format!(
            "ip {f} route replace default dev {ifname} table {TABLE}"
        )));
        up.push(args(&format!(
            "ip {f} rule add pref {PREF_MARK} fwmark {MARK:#x} lookup main"
        )));
    }
    // Исключения — правилом в main (а не throw в таблице TUN): так они
    // работают и при strict_route.
    for n in exclude {
        let f = if n.addr().is_ipv4() { "-4" } else { "-6" };
        if f == "-6" && !v6 {
            continue;
        }
        up.push(args(&format!(
            "ip {f} rule add pref {PREF_MARK} to {}/{} lookup main",
            n.addr(),
            n.prefix()
        )));
    }
    for f in &fams {
        up.push(args(&format!(
            "ip {f} rule add pref {PREF_TUN} lookup {TABLE}"
        )));
        if strict {
            // Kill switch: если TUN пропал (клиент убит), таблица пуста —
            // и этот запрет не пускает трафик мимо туннеля.
            up.push(args(&format!(
                "ip {f} rule add pref {PREF_BLOCK} unreachable"
            )));
        }
    }
    for cmd in &up {
        // Ошибка — guard при выходе снимет то, что успели добавить.
        run(cmd, false)?;
    }
    tracing::info!(
        interface = ifname,
        strict,
        "tun: весь трафик направлен в TUN"
    );
    Ok(guard)
}

#[cfg(windows)]
fn windows(ifname: &str, if_index: Option<u32>, v6: bool, exclude: &[IpNet]) -> Result<RouteGuard> {
    use std::net::IpAddr;
    let idx = if_index.ok_or_else(|| Error::Config("tun: не известен номер интерфейса".into()))?;
    let phys4 = winapi::best_interface(IpAddr::from([1, 1, 1, 1])).ok_or_else(|| {
        Error::Config("tun: не найден физический интерфейс с выходом в интернет".into())
    })?;
    let phys6 = winapi::best_interface("2606:4700:4700::1111".parse().unwrap());
    net_protect::set(Some(net_protect::Protect::Interface {
        v4: phys4,
        v6: phys6,
    }));
    // Без IPv6 у физического интерфейса IPv6 в TUN не направляется: иначе
    // система считала бы IPv6 рабочим, программы шли бы на AAAA-адреса, а
    // выход `direct` их никуда не донёс бы. Без маршрута программа сразу
    // получает «сеть недоступна» и переходит на IPv4.
    let v6 = v6 && phys6.is_some();
    if !v6 {
        tracing::info!("tun: у компьютера нет IPv6 — IPv6 в TUN не направляется");
    }
    let mut prefixes = vec![("ipv4", "0.0.0.0/1"), ("ipv4", "128.0.0.0/1")];
    if v6 {
        prefixes.push(("ipv6", "::/1"));
        prefixes.push(("ipv6", "8000::/1"));
    }
    let mut down = Vec::new();
    let mut up = Vec::new();
    for (fam, p) in &prefixes {
        up.push(args(&format!(
            "netsh interface {fam} add route prefix={p} interface={idx} metric=1 store=active"
        )));
        down.push(args(&format!(
            "netsh interface {fam} delete route prefix={p} interface={idx} store=active"
        )));
    }
    // Исключения — через шлюз физического интерфейса.
    if let Some(gw) = winapi::gateway_v4(phys4) {
        for n in exclude.iter().filter(|n| n.addr().is_ipv4()) {
            let p = format!("{}/{}", n.addr(), n.prefix());
            up.push(args(&format!(
                "netsh interface ipv4 add route prefix={p} interface={phys4} nexthop={gw} store=active"
            )));
            down.push(args(&format!(
                "netsh interface ipv4 delete route prefix={p} interface={phys4} nexthop={gw} store=active"
            )));
        }
    } else if !exclude.is_empty() {
        tracing::warn!("tun: шлюз не найден — route_exclude не применён");
    }
    if exclude.iter().any(|n| n.addr().is_ipv6()) {
        tracing::warn!("tun: route_exclude для IPv6 на Windows пока не поддерживается");
    }
    let guard = RouteGuard { down };
    for cmd in &up {
        run(cmd, false)?;
    }
    tracing::info!(interface = ifname, "tun: весь трафик направлен в TUN");
    Ok(guard)
}

#[cfg(windows)]
mod winapi {
    use std::net::{IpAddr, Ipv4Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetBestInterfaceEx, GetBestRoute, MIB_IPFORWARDROW,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    /// Интерфейс, через который система пошла бы к `ip`.
    pub fn best_interface(ip: IpAddr) -> Option<u32> {
        let mut idx = 0u32;
        // SAFETY: структура адреса нужного размера, idx — место для ответа.
        let r = unsafe {
            match ip {
                IpAddr::V4(v4) => {
                    let mut sa: SOCKADDR_IN = std::mem::zeroed();
                    sa.sin_family = AF_INET;
                    sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
                    GetBestInterfaceEx(&sa as *const _ as *const SOCKADDR, &mut idx)
                }
                IpAddr::V6(v6) => {
                    let mut sa: SOCKADDR_IN6 = std::mem::zeroed();
                    sa.sin6_family = AF_INET6;
                    sa.sin6_addr.u.Byte = v6.octets();
                    GetBestInterfaceEx(&sa as *const _ as *const SOCKADDR, &mut idx)
                }
            }
        };
        (r == 0).then_some(idx)
    }

    /// Шлюз по умолчанию интерфейса `idx` (IPv4).
    pub fn gateway_v4(idx: u32) -> Option<Ipv4Addr> {
        let mut row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
        let dst = u32::from_ne_bytes([1, 1, 1, 1]);
        // SAFETY: row — место для ответа.
        let r = unsafe { GetBestRoute(dst, 0, &mut row) };
        if r != 0 || row.dwForwardIfIndex != idx {
            return None;
        }
        let gw = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
        (!gw.is_unspecified()).then_some(gw)
    }
}
