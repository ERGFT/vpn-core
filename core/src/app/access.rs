// SPDX-License-Identifier: GPL-3.0-or-later
//! Кто может пользоваться локальным прокси, когда он открыт в сеть
//! (`--listen 0.0.0.0:…`): список разрешённых адресов (`--allow-ip`) и
//! временная блокировка адреса после нескольких неверных паролей.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Адрес или подсеть: `192.168.1.10`, `192.168.1.0/24`, `fd00::/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl std::str::FromStr for IpNet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .trim()
            .parse()
            .map_err(|_| format!("«{s}» — не IP-адрес и не подсеть"))?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|&n| n <= max)
                .ok_or_else(|| format!("«{s}»: длина префикса должна быть 0..={max}"))?,
            None => max,
        };
        Ok(IpNet { addr, prefix })
    }
}

impl<'de> serde::Deserialize<'de> for IpNet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl IpNet {
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(IpNet { addr, prefix })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// Разрешён ли адрес. Пустой список — разрешены все (но без пароля
/// прокси в сеть и так не откроется). Свой компьютер (loopback) разрешён
/// всегда.
pub fn allowed(list: &[IpNet], ip: IpAddr) -> bool {
    list.is_empty() || ip.to_canonical().is_loopback() || list.iter().any(|n| n.contains(ip))
}

/// Сколько неверных паролей подряд допускается до блокировки адреса.
const MAX_FAILURES: u32 = 5;
/// Первая блокировка; каждая следующая вдвое длиннее, до `MAX_BLOCK`.
const FIRST_BLOCK: Duration = Duration::from_secs(60);
const MAX_BLOCK: Duration = Duration::from_secs(60 * 60);
/// Сколько адресов помнить (защита от переполнения памяти при атаке с
/// множества адресов).
const MAX_TRACKED: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    strikes: u32,
    blocked_until: Option<Instant>,
    last: Instant,
}

/// Подсеть из строковой константы в коде (не из настроек): ошибка в ней —
/// ошибка программы, которую ловят тесты.
#[allow(clippy::expect_used, reason = "константа в коде, проверяется тестами")]
pub(crate) fn const_net(s: &'static str) -> IpNet {
    s.parse().expect("подсеть-константа")
}

/// Учёт неверных паролей по адресам.
#[derive(Default)]
pub struct AuthGuard {
    map: Mutex<HashMap<IpAddr, Entry>>,
}

/// Итог неудачной попытки.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Ещё можно пробовать.
    Counted,
    /// Адрес только что заблокирован на указанное время.
    Blocked(Duration),
}

/// Ключ учёта: IPv4 — как есть; IPv6 — префикс /64 (подсеть клиента:
/// сменой адреса внутри своей /64 блокировку не обойти).
fn key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(o))
        }
        v4 => v4,
    }
}

impl AuthGuard {
    /// Заблокирован ли адрес сейчас.
    pub fn is_blocked(&self, ip: IpAddr, now: Instant) -> bool {
        let map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(&key(ip))
            .and_then(|e| e.blocked_until)
            .is_some_and(|t| now < t)
    }

    /// Неверный пароль с адреса `ip`.
    pub fn failure(&self, ip: IpAddr, now: Instant) -> Verdict {
        let mut map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= MAX_TRACKED && !map.contains_key(&key(ip)) {
            // Чистим записи без действующей блокировки, давно не
            // обновлявшиеся; если и после этого места нет — вытесняем
            // самую старую.
            map.retain(|_, e| {
                e.blocked_until.is_some_and(|t| now < t)
                    || now.duration_since(e.last) < Duration::from_secs(600)
            });
            if map.len() >= MAX_TRACKED {
                if let Some(oldest) = map.iter().min_by_key(|(_, e)| e.last).map(|(k, _)| *k) {
                    map.remove(&oldest);
                }
            }
        }
        let e = map.entry(key(ip)).or_insert(Entry {
            failures: 0,
            strikes: 0,
            blocked_until: None,
            last: now,
        });
        // Счёт неудач сбрасывается после 10 минут без попыток.
        if now.duration_since(e.last) > Duration::from_secs(600) {
            e.failures = 0;
        }
        e.last = now;
        e.failures += 1;
        if e.failures >= MAX_FAILURES {
            let block = FIRST_BLOCK
                .saturating_mul(1u32 << e.strikes.min(10))
                .min(MAX_BLOCK);
            e.strikes += 1;
            e.failures = 0;
            e.blocked_until = Some(now + block);
            Verdict::Blocked(block)
        } else {
            Verdict::Counted
        }
    }

    /// Верный пароль — счёт неудач адреса обнуляется.
    pub fn success(&self, ip: IpAddr) {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key(ip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets_and_single_addresses() {
        let lan: IpNet = "192.168.1.0/24".parse().unwrap();
        assert!(lan.contains("192.168.1.77".parse().unwrap()));
        assert!(!lan.contains("192.168.2.1".parse().unwrap()));
        assert!(lan.contains("::ffff:192.168.1.5".parse().unwrap()));
        let one: IpNet = "10.0.0.5".parse().unwrap();
        assert!(one.contains("10.0.0.5".parse().unwrap()));
        assert!(!one.contains("10.0.0.6".parse().unwrap()));
        let v6: IpNet = "fd00::/8".parse().unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("fe80::1".parse().unwrap()));
        let any: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(any.contains("8.8.8.8".parse().unwrap()));
        assert!("192.168.1.0/33".parse::<IpNet>().is_err());
        assert!("телефон".parse::<IpNet>().is_err());
    }

    #[test]
    fn allowlist_always_lets_own_machine_in() {
        let list = vec!["192.168.1.10".parse().unwrap()];
        assert!(allowed(&list, "192.168.1.10".parse().unwrap()));
        assert!(!allowed(&list, "192.168.1.11".parse().unwrap()));
        assert!(allowed(&list, "127.0.0.1".parse().unwrap()));
        assert!(allowed(&[], "192.168.1.11".parse().unwrap()));
    }

    /// Подсети-константы из кода (const_net) разбираются.
    #[test]
    fn code_constant_nets_parse() {
        for s in [
            "198.18.0.0/15",
            "fc00::/18",
            "172.19.0.1/30",
            "fdfe:dcba:9876::1/126",
        ]
        .iter()
        .chain(crate::app::rules::PRIVATE_NETS)
        {
            assert!(s.parse::<IpNet>().is_ok(), "{s}");
        }
    }

    #[test]
    fn ipv6_same_64_shares_counter() {
        let g = AuthGuard::default();
        let t = Instant::now();
        for i in 0..5u16 {
            g.failure(format!("2001:db8:1:2::{i:x}").parse().unwrap(), t);
        }
        assert!(g.is_blocked("2001:db8:1:2::ffff".parse().unwrap(), t));
        assert!(!g.is_blocked("2001:db8:1:3::1".parse().unwrap(), t));
        // IPv4 — по-прежнему по адресу.
        for _ in 0..5 {
            g.failure("192.0.2.1".parse().unwrap(), t);
        }
        assert!(g.is_blocked("192.0.2.1".parse().unwrap(), t));
        assert!(!g.is_blocked("192.0.2.2".parse().unwrap(), t));
    }

    #[test]
    fn blocks_after_five_failures_and_escalates() {
        let g = AuthGuard::default();
        let ip: IpAddr = "192.168.1.66".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..4 {
            assert_eq!(g.failure(ip, t0), Verdict::Counted);
        }
        assert!(!g.is_blocked(ip, t0));
        assert_eq!(g.failure(ip, t0), Verdict::Blocked(Duration::from_secs(60)));
        assert!(g.is_blocked(ip, t0 + Duration::from_secs(59)));
        assert!(!g.is_blocked(ip, t0 + Duration::from_secs(61)));
        // Вторая серия — блокировка вдвое длиннее.
        let t1 = t0 + Duration::from_secs(61);
        for _ in 0..4 {
            g.failure(ip, t1);
        }
        assert_eq!(
            g.failure(ip, t1),
            Verdict::Blocked(Duration::from_secs(120))
        );
        // Другой адрес не затронут.
        assert!(!g.is_blocked("192.168.1.67".parse().unwrap(), t1));
    }

    #[test]
    fn success_resets_counter() {
        let g = AuthGuard::default();
        let ip: IpAddr = "10.1.1.1".parse().unwrap();
        let t = Instant::now();
        for _ in 0..4 {
            g.failure(ip, t);
        }
        g.success(ip);
        assert_eq!(g.failure(ip, t), Verdict::Counted);
    }

    #[test]
    fn memory_is_bounded_under_many_addresses() {
        let g = AuthGuard::default();
        let t = Instant::now();
        for i in 0..(MAX_TRACKED as u32 + 500) {
            g.failure(IpAddr::from(i.to_be_bytes()), t);
        }
        assert!(
            g.map
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
                <= MAX_TRACKED
        );
    }
}
