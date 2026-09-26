//! Fake-IP: на запрос A/AAAA приложение сразу получает адрес из
//! зарезервированного диапазона (по умолчанию `198.18.0.0/15` и
//! `fc00::/18`), а когда оно соединяется с этим адресом, прокси
//! подставляет исходное имя — и имя разрешает уже сервер. Нет ни задержки
//! на DNS, ни DNS-запросов о сайтах мимо туннеля.
//!
//! Одно имя — один номер в диапазоне; IPv4- и IPv6-адрес имени — это база
//! диапазона плюс тот же номер. Номера выдаются по кругу: когда диапазон
//! исчерпан, номер самой давно выданной записи переходит к новому имени.
//! Таблицу можно сохранять в файл, чтобы после перезапуска адреса, уже
//! запомненные программами, продолжали работать.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::app::access::IpNet;
use crate::error::{Error, Result};

/// Что за адрес пришёл в соединении.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reverse {
    /// Адрес не из диапазона fake-IP.
    NotFake,
    /// Адрес из диапазона, но такого имени мы не выдавали (или оно
    /// вытеснено): соединяться некуда.
    Unknown,
    Name(String),
}

struct Inner {
    by_name: HashMap<String, u32>,
    by_off: HashMap<u32, String>,
    next: u32,
    dirty: bool,
}

pub struct FakeIp {
    v4_base: u32,
    v4_prefix: u8,
    v6_base: Option<(u128, u8)>,
    /// Первый и последний выдаваемые номера.
    first: u32,
    last: u32,
    file: Option<PathBuf>,
    inner: Mutex<Inner>,
}

fn net_bounds4(n: &IpNet) -> Option<u32> {
    match n.addr() {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - n.prefix() as u32).unwrap_or(0);
            Some(u32::from(a) & mask)
        }
        _ => None,
    }
}

fn net_bounds6(n: &IpNet) -> Option<u128> {
    match n.addr() {
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - n.prefix() as u32).unwrap_or(0);
            Some(u128::from(a) & mask)
        }
        _ => None,
    }
}

impl FakeIp {
    pub fn new(v4: IpNet, v6: Option<IpNet>, file: Option<PathBuf>) -> Result<Self> {
        let v4_base = net_bounds4(&v4)
            .ok_or_else(|| Error::Config("dns.fakeip.inet4_range: нужна IPv4-подсеть".into()))?;
        if v4.prefix() > 24 {
            return Err(Error::Config(
                "dns.fakeip.inet4_range: подсеть меньше /24 — адресов не хватит".into(),
            ));
        }
        let v6_base = match &v6 {
            Some(n) => {
                let b = net_bounds6(n).ok_or_else(|| {
                    Error::Config("dns.fakeip.inet6_range: нужна IPv6-подсеть".into())
                })?;
                if n.prefix() > 120 {
                    return Err(Error::Config(
                        "dns.fakeip.inet6_range: подсеть меньше /120".into(),
                    ));
                }
                Some((b, n.prefix()))
            }
            None => None,
        };
        // Сколько номеров: размер IPv4-подсети (IPv6-подсеть не меньше
        // её — иначе берём меньшее).
        let mut size: u64 = 1u64 << (32 - v4.prefix() as u32);
        if let Some((_, p6)) = v6_base {
            let bits = 128 - p6 as u32;
            if bits < 32 {
                size = size.min(1u64 << bits);
            }
        }
        // Номер 0 — адрес сети, 1 — оставлен под шлюз (TUN), последний —
        // широковещательный.
        let first = 2u32;
        let last = (size - 2) as u32;
        let fake = FakeIp {
            v4_base,
            v4_prefix: v4.prefix(),
            v6_base,
            first,
            last,
            file,
            inner: Mutex::new(Inner {
                by_name: HashMap::new(),
                by_off: HashMap::new(),
                next: first,
                dirty: false,
            }),
        };
        if let Some(f) = &fake.file {
            if f.exists() {
                match fake.load(f) {
                    Ok(n) => {
                        tracing::info!(entries = n, file = %f.display(), "fake-IP: таблица загружена")
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, file = %f.display(), "fake-IP: таблица не прочитана, начинаю с пустой")
                    }
                }
            }
        }
        Ok(fake)
    }

    pub fn capacity(&self) -> u32 {
        self.last - self.first + 1
    }

    fn v4(&self, off: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.v4_base + off)
    }

    fn v6(&self, off: u32) -> Option<Ipv6Addr> {
        self.v6_base.map(|(b, _)| Ipv6Addr::from(b + off as u128))
    }

    /// Номер для имени (новый или прежний).
    fn allocate(&self, name: &str) -> u32 {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut g = self.inner.lock().unwrap();
        if let Some(&off) = g.by_name.get(&name) {
            return off;
        }
        let off = g.next;
        g.next = if off >= self.last {
            self.first
        } else {
            off + 1
        };
        if let Some(old) = g.by_off.remove(&off) {
            g.by_name.remove(&old);
        }
        g.by_off.insert(off, name.clone());
        g.by_name.insert(name, off);
        g.dirty = true;
        off
    }

    pub fn ipv4_for(&self, name: &str) -> Ipv4Addr {
        self.v4(self.allocate(name))
    }

    pub fn ipv6_for(&self, name: &str) -> Option<Ipv6Addr> {
        self.v6_base?;
        self.v6(self.allocate(name))
    }

    pub fn has_ipv6(&self) -> bool {
        self.v6_base.is_some()
    }

    /// Имя по адресу.
    pub fn reverse(&self, ip: IpAddr) -> Reverse {
        let off = match ip.to_canonical() {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                let mask = u32::MAX
                    .checked_shl(32 - self.v4_prefix as u32)
                    .unwrap_or(0);
                if a & mask != self.v4_base {
                    return Reverse::NotFake;
                }
                a - self.v4_base
            }
            IpAddr::V6(a) => {
                let Some((base, p)) = self.v6_base else {
                    return Reverse::NotFake;
                };
                let a = u128::from(a);
                let mask = u128::MAX.checked_shl(128 - p as u32).unwrap_or(0);
                if a & mask != base {
                    return Reverse::NotFake;
                }
                match u32::try_from(a - base) {
                    Ok(o) => o,
                    Err(_) => return Reverse::Unknown,
                }
            }
        };
        match self.inner.lock().unwrap().by_off.get(&off) {
            Some(n) => Reverse::Name(n.clone()),
            None => Reverse::Unknown,
        }
    }

    /// Сохранить таблицу, если она менялась.
    pub fn save(&self) -> Result<()> {
        let Some(f) = &self.file else { return Ok(()) };
        let text = {
            let mut g = self.inner.lock().unwrap();
            if !g.dirty {
                return Ok(());
            }
            g.dirty = false;
            let mut entries: Vec<(&u32, &String)> = g.by_off.iter().collect();
            entries.sort();
            let mut t = format!("next {}\n", g.next);
            for (off, name) in entries {
                t.push_str(&format!("{off} {name}\n"));
            }
            t
        };
        // Сначала во временный файл, потом переименование: оборванная
        // запись не портит прежнюю таблицу.
        let tmp = f.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, f)?;
        Ok(())
    }

    fn load(&self, f: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(f)?;
        let mut g = self.inner.lock().unwrap();
        for line in text.lines() {
            let Some((a, b)) = line.split_once(' ') else {
                continue;
            };
            if a == "next" {
                if let Ok(n) = b.parse::<u32>() {
                    if (self.first..=self.last).contains(&n) {
                        g.next = n;
                    }
                }
                continue;
            }
            let Ok(off) = a.parse::<u32>() else { continue };
            let name = b.trim().to_ascii_lowercase();
            let valid = !name.is_empty()
                && name.len() <= 253
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'));
            if !valid || !(self.first..=self.last).contains(&off) || g.by_name.contains_key(&name) {
                continue;
            }
            g.by_off.insert(off, name.clone());
            g.by_name.insert(name, off);
        }
        Ok(g.by_off.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(v4: &str, v6: Option<&str>, file: Option<PathBuf>) -> FakeIp {
        FakeIp::new(v4.parse().unwrap(), v6.map(|s| s.parse().unwrap()), file).unwrap()
    }

    #[test]
    fn stable_names_and_reverse() {
        let f = fake("198.18.0.0/15", Some("fc00::/18"), None);
        let a = f.ipv4_for("Example.COM.");
        assert_eq!(a, Ipv4Addr::new(198, 18, 0, 2), "номера 0 и 1 не выдаются");
        assert_eq!(f.ipv4_for("example.com"), a, "одно имя — один адрес");
        let a6 = f.ipv6_for("example.com").unwrap();
        assert_eq!(a6, "fc00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            f.reverse(IpAddr::V4(a)),
            Reverse::Name("example.com".into())
        );
        assert_eq!(
            f.reverse(IpAddr::V6(a6)),
            Reverse::Name("example.com".into())
        );
        assert_eq!(f.reverse("198.19.1.1".parse().unwrap()), Reverse::Unknown);
        assert_eq!(f.reverse("8.8.8.8".parse().unwrap()), Reverse::NotFake);
        assert_eq!(f.reverse("2001:db8::1".parse().unwrap()), Reverse::NotFake);
        assert_ne!(f.ipv4_for("other.com"), a);
        assert_eq!(f.capacity(), (1 << 17) - 3);
    }

    #[test]
    fn wraps_and_evicts_oldest() {
        let f = fake("10.0.0.0/24", None, None);
        assert_eq!(f.capacity(), 253);
        let first = f.ipv4_for("n0.test");
        for i in 1..253 {
            f.ipv4_for(&format!("n{i}.test"));
        }
        assert_eq!(
            f.reverse(IpAddr::V4(first)),
            Reverse::Name("n0.test".into())
        );
        // 254-е имя занимает номер самого первого.
        assert_eq!(f.ipv4_for("new.test"), first);
        assert_eq!(
            f.reverse(IpAddr::V4(first)),
            Reverse::Name("new.test".into())
        );
        assert_ne!(
            f.ipv4_for("n0.test"),
            first,
            "вытесненное имя получает новый адрес"
        );
        assert!(f.ipv6_for("x.test").is_none());
    }

    #[test]
    fn persists_between_restarts() {
        let dir = std::env::temp_dir().join(format!("vpn-core-fakeip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("fakeip.txt");
        let _ = std::fs::remove_file(&file);
        let a = {
            let f = fake("198.18.0.0/15", None, Some(file.clone()));
            let a = f.ipv4_for("kept.test");
            f.ipv4_for("second.test");
            f.save().unwrap();
            a
        };
        let f = fake("198.18.0.0/15", None, Some(file.clone()));
        assert_eq!(f.reverse(IpAddr::V4(a)), Reverse::Name("kept.test".into()));
        let third = f.ipv4_for("third.test");
        assert_eq!(
            third,
            Ipv4Addr::new(198, 18, 0, 4),
            "выдача продолжается, а не с начала"
        );
        // Мусор в файле не мешает.
        std::fs::write(
            &file,
            "next zzz\n5 ok.test\n99999999 far.test\n6 bad name\nxx\n",
        )
        .unwrap();
        let f = fake("198.18.0.0/15", None, Some(file.clone()));
        assert_eq!(
            f.reverse("198.18.0.5".parse().unwrap()),
            Reverse::Name("ok.test".into())
        );
        assert_eq!(f.reverse("198.18.0.6".parse().unwrap()), Reverse::Unknown);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_bad_ranges() {
        assert!(FakeIp::new("10.0.0.0/25".parse().unwrap(), None, None).is_err());
        assert!(FakeIp::new("fc00::/18".parse().unwrap(), None, None).is_err());
        assert!(FakeIp::new(
            "10.0.0.0/16".parse().unwrap(),
            Some("10.1.0.0/16".parse().unwrap()),
            None
        )
        .is_err());
    }
}
