//! Правила маршрутизации: условия и их быстрая проверка.
//!
//! Условия одного правила (как у sing-box):
//! `(домен ИЛИ адрес) И порт И сеть И вход`. Внутри группы — «или»:
//! `domain_suffix = ["ru", "su"]` значит «.ru или .su», а
//! `geosite = ["category-ru"]` вместе с `geoip = ["ru"]` — «российский
//! сайт или российский адрес». Незаданная группа не проверяется.
//!
//! Правила перебираются по порядку, срабатывает первое подошедшее.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;

use super::access::IpNet;
use super::geo::{self, SiteEntry};
use super::outbound::Outbound;
use super::{Metadata, Network};
use crate::error::{Error, Result};
use crate::vless::Address;

/// Порт или диапазон: `443`, `"443"`, `"1000-2000"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Num(u16),
    Str(String),
}

impl PortSpec {
    fn range(&self) -> Result<RangeInclusive<u16>> {
        match self {
            PortSpec::Num(n) => Ok(*n..=*n),
            PortSpec::Str(s) => {
                let bad = || Error::Config(format!("порт «{s}»: ожидается 443 или 1000-2000"));
                let (a, b) = s.split_once('-').unwrap_or((s, s));
                let a: u16 = a.trim().parse().map_err(|_| bad())?;
                let b: u16 = b.trim().parse().map_err(|_| bad())?;
                if a > b {
                    return Err(bad());
                }
                Ok(a..=b)
            }
        }
    }
}

/// Правило в файле настроек (`[[route.rules]]`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Домен целиком: `example.com` (без поддоменов).
    #[serde(default)]
    pub domain: Vec<String>,
    /// Домен и его поддомены: `example.com`; с точкой впереди
    /// (`.example.com`) — только поддомены.
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// Подстрока в домене.
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    /// Регулярное выражение для домена.
    #[serde(default)]
    pub domain_regex: Vec<String>,
    /// Категории из geosite.dat: `category-ads-all`, `google@cn`.
    #[serde(default)]
    pub geosite: Vec<String>,
    /// Адреса и подсети назначения.
    #[serde(default)]
    pub ip_cidr: Vec<IpNet>,
    /// Локальные адреса: 10/8, 192.168/16, 127/8, fc00::/7 и т.п.
    #[serde(default)]
    pub ip_is_private: bool,
    /// Страны из geoip.dat: `ru`, `private`.
    #[serde(default)]
    pub geoip: Vec<String>,
    #[serde(default)]
    pub port: Vec<PortSpec>,
    pub network: Option<Network>,
    /// tag входов, к которым относится правило.
    #[serde(default)]
    pub inbound: Vec<String>,
    /// Куда: tag выхода.
    pub outbound: String,
}

/// Домен для сравнения: нижний регистр, без точки в конце.
pub fn normalize_domain(d: &str) -> String {
    d.trim_end_matches('.').to_ascii_lowercase()
}

/// Набор доменных условий.
#[derive(Default)]
pub struct DomainSet {
    full: HashSet<String>,
    /// Домен и поддомены.
    suffix: HashSet<String>,
    /// Только поддомены.
    sub_only: HashSet<String>,
    keywords: Vec<String>,
    regex: Vec<String>,
    regex_set: Option<regex::RegexSet>,
}

impl DomainSet {
    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
            && self.suffix.is_empty()
            && self.sub_only.is_empty()
            && self.keywords.is_empty()
            && self.regex_set.is_none()
    }

    fn add_suffix(&mut self, s: &str) {
        let s = normalize_domain(s);
        match s.strip_prefix('.') {
            Some(sub) if !sub.is_empty() => {
                self.sub_only.insert(sub.to_string());
            }
            Some(_) => {}
            None if !s.is_empty() => {
                self.suffix.insert(s);
            }
            None => {}
        }
    }

    fn finish(&mut self) -> Result<()> {
        if !self.regex.is_empty() {
            let set = regex::RegexSetBuilder::new(&self.regex)
                .case_insensitive(true)
                .size_limit(64 << 20)
                .build()
                .map_err(|e| Error::Config(format!("domain_regex: {e}")))?;
            self.regex_set = Some(set);
        }
        Ok(())
    }

    pub fn matches(&self, domain: &str) -> bool {
        let d = normalize_domain(domain);
        if self.full.contains(&d) || self.suffix.contains(&d) {
            return true;
        }
        // Родительские домены: a.b.example.com → b.example.com → example.com → com.
        let mut rest = d.as_str();
        while let Some((_, parent)) = rest.split_once('.') {
            if self.suffix.contains(parent) || self.sub_only.contains(parent) {
                return true;
            }
            rest = parent;
        }
        if self.keywords.iter().any(|k| d.contains(k.as_str())) {
            return true;
        }
        self.regex_set.as_ref().is_some_and(|r| r.is_match(&d))
    }
}

/// Доменные условия из настроек (правила маршрутизации и DNS).
pub struct DomainLists<'a> {
    pub domain: &'a [String],
    pub domain_suffix: &'a [String],
    pub domain_keyword: &'a [String],
    pub domain_regex: &'a [String],
    pub geosite: &'a [String],
}

impl DomainSet {
    /// Собрать набор из списков и категорий geosite.
    pub fn build(l: &DomainLists<'_>, geo: &GeoFiles) -> Result<Self> {
        let mut domains = DomainSet::default();
        for d in l.domain {
            domains.full.insert(normalize_domain(d));
        }
        for d in l.domain_suffix {
            domains.add_suffix(d);
        }
        for k in l.domain_keyword {
            domains.keywords.push(k.to_ascii_lowercase());
        }
        for r in l.domain_regex {
            regex::Regex::new(r).map_err(|e| Error::Config(format!("domain_regex «{r}»: {e}")))?;
            domains.regex.push(r.clone());
        }
        for code in l.geosite {
            for e in geo.site(code) {
                match e {
                    SiteEntry::Full(d) => {
                        domains.full.insert(d.clone());
                    }
                    SiteEntry::Suffix(d) => domains.add_suffix(d),
                    SiteEntry::Keyword(k) => domains.keywords.push(k.clone()),
                    // Выражения из базы пишутся под Go (RE2); если какое-то
                    // не разбирается здесь — пропускаем его, а не всю категорию.
                    SiteEntry::Regex(r) => match regex::Regex::new(r) {
                        Ok(_) => domains.regex.push(r.clone()),
                        Err(_) => tracing::debug!(regex = %r, "geosite: выражение пропущено"),
                    },
                }
            }
        }
        domains.keywords.sort();
        domains.keywords.dedup();
        domains.finish()?;
        Ok(domains)
    }
}

/// Набор подсетей: отсортированные непересекающиеся диапазоны, поиск —
/// двоичный (в geoip у страны бывают тысячи подсетей).
#[derive(Default)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Ord + Copy>(mut v: Vec<(T, T)>, next: impl Fn(T) -> Option<T>) -> Vec<(T, T)> {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for (a, b) in v {
        if let Some(last) = out.last_mut() {
            // Пересекаются или идут встык.
            if a <= last.1 || next(last.1) == Some(a) {
                if b > last.1 {
                    last.1 = b;
                }
                continue;
            }
        }
        out.push((a, b));
    }
    out
}

fn find<T: Ord + Copy>(v: &[(T, T)], x: T) -> bool {
    let i = v.partition_point(|&(a, _)| a <= x);
    i > 0 && x <= v[i - 1].1
}

impl IpSet {
    pub fn from_nets(nets: impl IntoIterator<Item = IpNet>) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for n in nets {
            match n.addr() {
                IpAddr::V4(a) => {
                    let mask = u32::MAX.checked_shl(32 - n.prefix() as u32).unwrap_or(0);
                    let start = u32::from(a) & mask;
                    v4.push((start, start | !mask));
                }
                IpAddr::V6(a) => {
                    let mask = u128::MAX.checked_shl(128 - n.prefix() as u32).unwrap_or(0);
                    let start = u128::from(a) & mask;
                    v6.push((start, start | !mask));
                }
            }
        }
        IpSet {
            v4: merge(v4, |x: u32| x.checked_add(1)),
            v6: merge(v6, |x: u128| x.checked_add(1)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => find(&self.v6, u128::from(a)),
        }
    }
}

/// Частные и служебные адреса (`ip_is_private`).
pub const PRIVATE_NETS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

pub struct Rule {
    pub index: usize,
    domains: DomainSet,
    ips: IpSet,
    has_dest: bool,
    ports: Vec<RangeInclusive<u16>>,
    network: Option<Network>,
    inbounds: Vec<String>,
    pub outbound: Arc<dyn Outbound>,
}

/// Адрес назначения как IP, если это IP (в том числе IP, записанный
/// строкой в поле домена).
fn target_ip(a: &Address) -> Option<IpAddr> {
    match a {
        Address::Ipv4(v4) => Some(IpAddr::V4(*v4)),
        Address::Ipv6(v6) => Some(IpAddr::V6(*v6)),
        Address::Domain(d) => d.trim_matches(|c| c == '[' || c == ']').parse().ok(),
    }
}

impl Rule {
    /// Есть ли в правиле условия по IP.
    pub fn has_ip(&self) -> bool {
        !self.ips.is_empty()
    }

    pub fn matches(&self, meta: &Metadata) -> bool {
        if let Some(n) = self.network {
            if n != meta.network {
                return false;
            }
        }
        if !self.inbounds.is_empty() && !self.inbounds.iter().any(|t| **t == *meta.inbound) {
            return false;
        }
        if !self.ports.is_empty() && !self.ports.iter().any(|r| r.contains(&meta.port)) {
            return false;
        }
        if self.has_dest {
            let ip = target_ip(&meta.target);
            let domain_hit = !self.domains.is_empty()
                && (matches!(&meta.target, Address::Domain(d) if ip.is_none() && self.domains.matches(d))
                    || meta
                        .sniffed
                        .as_deref()
                        .is_some_and(|d| self.domains.matches(d)));
            let ip_hit = !self.ips.is_empty() && ip.is_some_and(|ip| self.ips.contains(ip));
            if !domain_hit && !ip_hit {
                return false;
            }
        }
        true
    }
}

/// Откуда брать базы geosite/geoip и что уже прочитано (одна база на
/// все правила).
pub struct GeoFiles {
    pub geosite: PathBuf,
    pub geoip: PathBuf,
    sites: HashMap<String, Vec<SiteEntry>>,
    ips: HashMap<String, Vec<IpNet>>,
}

impl GeoFiles {
    /// Прочитать из баз нужные категории (geosite и geoip).
    pub fn load(
        mut site_codes: Vec<String>,
        mut ip_codes: Vec<String>,
        geosite: &Path,
        geoip: &Path,
    ) -> Result<Self> {
        site_codes.sort();
        site_codes.dedup();
        ip_codes.sort();
        ip_codes.dedup();
        let sites = if site_codes.is_empty() {
            HashMap::new()
        } else {
            geo::load_sites(geosite, &site_codes)?
        };
        let ips = if ip_codes.is_empty() {
            HashMap::new()
        } else {
            geo::load_ips(geoip, &ip_codes)?
        };
        Ok(GeoFiles {
            geosite: geosite.into(),
            geoip: geoip.into(),
            sites,
            ips,
        })
    }

    fn site(&self, code: &str) -> &[SiteEntry] {
        let key = code.to_ascii_lowercase();
        self.sites.get(&key).map(Vec::as_slice).unwrap_or(&[])
    }

    fn ip(&self, code: &str) -> &[IpNet] {
        self.ips
            .get(&code.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

pub fn compile(
    index: usize,
    c: &RuleConfig,
    outbound: Arc<dyn Outbound>,
    geo: &GeoFiles,
) -> Result<Rule> {
    let n = index + 1;
    let domains = DomainSet::build(
        &DomainLists {
            domain: &c.domain,
            domain_suffix: &c.domain_suffix,
            domain_keyword: &c.domain_keyword,
            domain_regex: &c.domain_regex,
            geosite: &c.geosite,
        },
        geo,
    )
    .map_err(|e| Error::Config(format!("правило {n}: {e}")))?;

    let mut nets: Vec<IpNet> = c.ip_cidr.clone();
    if c.ip_is_private {
        nets.extend(PRIVATE_NETS.iter().map(|s| s.parse::<IpNet>().unwrap()));
    }
    for code in &c.geoip {
        nets.extend_from_slice(geo.ip(code));
    }
    let ips = IpSet::from_nets(nets);

    let has_dest = !c.domain.is_empty()
        || !c.domain_suffix.is_empty()
        || !c.domain_keyword.is_empty()
        || !c.domain_regex.is_empty()
        || !c.geosite.is_empty()
        || !c.ip_cidr.is_empty()
        || c.ip_is_private
        || !c.geoip.is_empty();
    let ports = c
        .port
        .iter()
        .map(PortSpec::range)
        .collect::<Result<Vec<_>>>()
        .map_err(|e| Error::Config(format!("правило {n}: {e}")))?;
    if !has_dest && ports.is_empty() && c.network.is_none() && c.inbound.is_empty() {
        return Err(Error::Config(format!(
            "правило {n} без условий подошло бы ко всему — для этого есть route.final"
        )));
    }
    Ok(Rule {
        index,
        domains,
        ips,
        has_dest,
        ports,
        network: c.network,
        inbounds: c.inbound.clone(),
        outbound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_set_semantics() {
        let mut s = DomainSet::default();
        s.full.insert("exact.com".into());
        s.add_suffix("Example.COM");
        s.add_suffix(".sub.org");
        s.keywords.push("ads".into());
        s.regex.push(r"^cdn\d+\.".into());
        s.finish().unwrap();

        assert!(s.matches("exact.com"));
        assert!(!s.matches("www.exact.com"), "domain — без поддоменов");
        assert!(s.matches("example.com"));
        assert!(s.matches("a.b.EXAMPLE.com."));
        assert!(!s.matches("notexample.com"), "суффикс — по границе метки");
        assert!(!s.matches("sub.org"), ".sub.org — только поддомены");
        assert!(s.matches("x.sub.org"));
        assert!(s.matches("myads.net"));
        assert!(s.matches("cdn42.host.io"));
        assert!(!s.matches("cdn.host.io"));
    }

    #[test]
    fn ip_set_ranges() {
        let s = IpSet::from_nets(
            [
                "10.0.0.0/8",
                "10.1.0.0/16",
                "11.0.0.0/8",
                "192.168.1.7",
                "2001:db8::/32",
            ]
            .iter()
            .map(|n| n.parse().unwrap()),
        );
        assert_eq!(s.v4.len(), 2, "пересекающиеся и смежные подсети сливаются");
        for ip in [
            "10.0.0.0",
            "10.255.255.255",
            "11.2.3.4",
            "192.168.1.7",
            "2001:db8::1",
            "::ffff:10.1.2.3",
        ] {
            assert!(s.contains(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["9.255.255.255", "12.0.0.0", "192.168.1.8", "2001:db9::1"] {
            assert!(!s.contains(ip.parse().unwrap()), "{ip}");
        }
        let all = IpSet::from_nets(["0.0.0.0/0".parse().unwrap()]);
        assert!(all.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ports() {
        assert_eq!(
            PortSpec::Str("1000-2000".into()).range().unwrap(),
            1000..=2000
        );
        assert_eq!(PortSpec::Num(443).range().unwrap(), 443..=443);
        assert!(PortSpec::Str("2000-1000".into()).range().is_err());
        assert!(PortSpec::Str("http".into()).range().is_err());
    }
}
