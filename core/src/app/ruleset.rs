//! Наборы правил sing-box (`rule_set`): бинарный `.srs` и исходный JSON.
//!
//! ```toml
//! [[route.rule_set]]
//! tag = "geosite-ru"
//! path = "geosite-ru.srs"          # формат — по расширению (.srs / .json)
//!
//! [[route.rules]]
//! rule_set = ["geosite-ru"]
//! outbound = "direct"
//! ```
//!
//! Поддерживаются наборы из доменов (точно, суффикс, подстрока, regex) и
//! адресов — как у наборов geosite/geoip от SagerNet и MetaCubeX. Их
//! содержимое добавляется к доменам и адресам правила. Наборы с другими
//! условиями (порт, процесс, логические правила, `invert`) отвергаются с
//! понятной ошибкой: молча упростить их — значит маршрутизировать иначе,
//! чем задумано.
//!
//! Формат `.srs` — по исходникам sing-box (`common/srs/binary.go`,
//! `sing/common/domain/matcher.go`, `set.go`): «SRS», версия, дальше
//! zlib; домены — в сжатом префиксном дереве (перевёрнутые строки),
//! адреса — диапазоны «от–до».

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::access::IpNet;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleSetConfig {
    pub tag: String,
    pub path: PathBuf,
    /// `binary` (.srs) или `source` (.json); по умолчанию — по расширению.
    pub format: Option<String>,
}

/// Содержимое набора.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleSet {
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub ip_cidr: Vec<IpNet>,
}

/// Потолок распакованного `.srs` (наборы geosite — единицы МиБ).
const MAX_UNPACKED: usize = 256 * 1024 * 1024;
const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

pub fn load(cfg: &RuleSetConfig) -> Result<RuleSet> {
    let bad = |e: String| Error::Config(format!("rule_set {}: {e}", cfg.tag));
    let data = std::fs::read(&cfg.path)
        .map_err(|e| bad(format!("не удалось прочитать {}: {e}", cfg.path.display())))?;
    let binary = match cfg.format.as_deref() {
        Some("binary") => true,
        Some("source") => false,
        Some(other) => return Err(bad(format!("format = «{other}» — binary или source"))),
        None => is_binary_path(&cfg.path, &data),
    };
    if binary {
        parse_srs(&data).map_err(bad)
    } else {
        parse_source(&data).map_err(bad)
    }
}

/// Загрузить наборы из `route.rule_set` и дописать их содержимое к
/// правилам маршрутизации и DNS, которые на них ссылаются.
pub fn expand(
    route: &mut super::config::RouteConfig,
    dns: Option<&mut super::dns::DnsConfig>,
) -> Result<()> {
    let mut sets: HashMap<&str, Option<RuleSet>> = HashMap::new();
    for rs in &route.rule_set {
        if rs.tag.is_empty() {
            return Err(Error::Config("route.rule_set: пустой tag".into()));
        }
        if sets.insert(&rs.tag, None).is_some() {
            return Err(Error::Config(format!(
                "route.rule_set: tag «{}» повторяется",
                rs.tag
            )));
        }
    }
    let used = route.rules.iter().flat_map(|r| r.rule_set.iter()).chain(
        dns.iter()
            .flat_map(|d| d.rules.iter().flat_map(|r| r.rule_set.iter())),
    );
    let mut wanted: Vec<&str> = Vec::new();
    for t in used {
        if !sets.contains_key(t.as_str()) {
            return Err(Error::Config(format!(
                "rule_set = [\"{t}\"]: нет такого набора в [[route.rule_set]]"
            )));
        }
        if !wanted.contains(&t.as_str()) {
            wanted.push(t);
        }
    }
    // Загружаем только используемые наборы.
    for rs in &route.rule_set {
        if wanted.contains(&rs.tag.as_str()) {
            let set = load(rs)?;
            sets.insert(&rs.tag, Some(set));
        }
    }
    let get = |t: &str| sets.get(t).and_then(Option::as_ref).expect("загружен выше");

    let mut out_rules = std::mem::take(&mut route.rules);
    for (i, r) in out_rules.iter_mut().enumerate() {
        for t in std::mem::take(&mut r.rule_set) {
            let s = get(&t);
            if s.is_empty() {
                return Err(Error::Config(format!(
                    "правило {}: набор «{t}» пуст — правило подошло бы не к тем адресам",
                    i + 1
                )));
            }
            r.domain.extend(s.domain.iter().cloned());
            r.domain_suffix.extend(s.domain_suffix.iter().cloned());
            r.domain_keyword.extend(s.domain_keyword.iter().cloned());
            r.domain_regex.extend(s.domain_regex.iter().cloned());
            r.ip_cidr.extend(s.ip_cidr.iter().cloned());
        }
    }
    if let Some(d) = dns {
        for (i, r) in d.rules.iter_mut().enumerate() {
            for t in std::mem::take(&mut r.rule_set) {
                let s = get(&t);
                if !s.has_domains() {
                    return Err(Error::Config(format!(
                        "dns.rules, правило {}: в наборе «{t}» нет доменов (DNS-правила — только по доменам)",
                        i + 1
                    )));
                }
                r.domain.extend(s.domain.iter().cloned());
                r.domain_suffix.extend(s.domain_suffix.iter().cloned());
                r.domain_keyword.extend(s.domain_keyword.iter().cloned());
                r.domain_regex.extend(s.domain_regex.iter().cloned());
            }
        }
    }
    route.rules = out_rules;
    Ok(())
}

impl RuleSet {
    pub fn has_domains(&self) -> bool {
        !(self.domain.is_empty()
            && self.domain_suffix.is_empty()
            && self.domain_keyword.is_empty()
            && self.domain_regex.is_empty())
    }

    pub fn is_empty(&self) -> bool {
        !self.has_domains() && self.ip_cidr.is_empty()
    }
}

fn is_binary_path(p: &Path, data: &[u8]) -> bool {
    p.extension().is_some_and(|e| e.eq_ignore_ascii_case("srs")) || data.starts_with(b"SRS")
}

// ── исходный JSON ──

#[derive(Deserialize)]
struct Source {
    #[allow(dead_code)]
    version: Option<u32>,
    rules: Vec<serde_json::Value>,
}

fn list(v: &serde_json::Value, key: &str) -> std::result::Result<Vec<String>, String> {
    match v.get(key) {
        None => Ok(Vec::new()),
        Some(serde_json::Value::String(s)) => Ok(vec![s.clone()]),
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{key}: ожидались строки"))
            })
            .collect(),
        Some(_) => Err(format!("{key}: ожидалась строка или список")),
    }
}

fn parse_source(data: &[u8]) -> std::result::Result<RuleSet, String> {
    let src: Source = serde_json::from_slice(data).map_err(|e| format!("JSON: {e}"))?;
    let mut out = RuleSet::default();
    const KNOWN: [&str; 5] = [
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
    ];
    for (i, r) in src.rules.iter().enumerate() {
        let obj = r
            .as_object()
            .ok_or_else(|| format!("правило {}: ожидался объект", i + 1))?;
        if let Some(k) = obj.keys().find(|k| !KNOWN.contains(&k.as_str())) {
            return Err(format!(
                "правило {}: условие «{k}» не поддерживается (только домены и ip_cidr)",
                i + 1
            ));
        }
        out.domain.extend(list(r, "domain")?);
        out.domain_suffix.extend(list(r, "domain_suffix")?);
        out.domain_keyword.extend(list(r, "domain_keyword")?);
        out.domain_regex.extend(list(r, "domain_regex")?);
        for c in list(r, "ip_cidr")? {
            out.ip_cidr.push(parse_cidr(&c)?);
        }
    }
    Ok(out)
}

fn parse_cidr(s: &str) -> std::result::Result<IpNet, String> {
    if s.contains('/') {
        s.parse().map_err(|_| format!("ip_cidr «{s}»"))
    } else {
        let ip: IpAddr = s.parse().map_err(|_| format!("ip_cidr «{s}»"))?;
        Ok(IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).expect("полный префикс"))
    }
}

// ── бинарный .srs ──

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> std::result::Result<u8, String> {
        let v = *self.b.get(self.pos).ok_or("файл оборван")?;
        self.pos += 1;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("файл оборван")?;
        let s = self.b.get(self.pos..end).ok_or("файл оборван")?;
        self.pos = end;
        Ok(s)
    }

    fn uvarint(&mut self) -> std::result::Result<u64, String> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("битое число".into())
    }

    /// Длина списка — не больше, чем осталось байт (защита от огромных
    /// выделений памяти по битому файлу).
    fn len(&mut self, elem: usize) -> std::result::Result<usize, String> {
        let n = self.uvarint()? as usize;
        if n.saturating_mul(elem.max(1)) > self.b.len() - self.pos {
            return Err("длина списка больше файла".into());
        }
        Ok(n)
    }

    fn u64s(&mut self) -> std::result::Result<Vec<u64>, String> {
        let n = self.len(8)?;
        (0..n)
            .map(|_| Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())))
            .collect()
    }

    fn bytes(&mut self) -> std::result::Result<&'a [u8], String> {
        let n = self.len(1)?;
        self.take(n)
    }

    fn strings(&mut self) -> std::result::Result<Vec<String>, String> {
        let n = self.len(1)?;
        (0..n)
            .map(|_| Ok(String::from_utf8_lossy(self.bytes()?).into_owned()))
            .collect()
    }

    fn u16s(&mut self) -> std::result::Result<Vec<u16>, String> {
        let n = self.len(2)?;
        (0..n)
            .map(|_| Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())))
            .collect()
    }
}

fn parse_srs(data: &[u8]) -> std::result::Result<RuleSet, String> {
    if data.len() < 4 || &data[..3] != b"SRS" {
        return Err("не файл набора правил sing-box (нет «SRS» в начале)".into());
    }
    let version = data[3];
    if version == 0 || version > 4 {
        return Err(format!("версия {version} не поддерживается"));
    }
    let unpacked =
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&data[4..], MAX_UNPACKED)
            .map_err(|e| format!("zlib: {e:?}"))?;
    let mut r = Reader {
        b: &unpacked,
        pos: 0,
    };
    let n = r.len(1)?;
    let mut out = RuleSet::default();
    for i in 0..n {
        read_rule(&mut r, &mut out).map_err(|e| format!("правило {}: {e}", i + 1))?;
    }
    Ok(out)
}

fn read_rule(r: &mut Reader, out: &mut RuleSet) -> std::result::Result<(), String> {
    match r.byte()? {
        0 => {}
        1 => return Err("логические правила (and/or) не поддерживаются".into()),
        t => return Err(format!("тип правила {t}")),
    }
    loop {
        let item = r.byte()?;
        match item {
            2 => {
                let (d, s) = read_domain_matcher(r)?;
                out.domain.extend(d);
                out.domain_suffix.extend(s);
            }
            3 => out.domain_keyword.extend(r.strings()?),
            4 => out.domain_regex.extend(r.strings()?),
            6 => out.ip_cidr.extend(read_ip_set(r)?),
            0xff => {
                if r.byte()? != 0 {
                    return Err("invert не поддерживается".into());
                }
                return Ok(());
            }
            // Условия, которые меняют смысл набора, — не упрощаем.
            0 | 7 | 9 => {
                let _ = r.u16s()?;
                return Err(format!(
                    "условие {} (порт, тип запроса) не поддерживается",
                    item_name(item)
                ));
            }
            _ => {
                return Err(format!(
                    "условие {} не поддерживается (только домены и ip_cidr)",
                    item_name(item)
                ))
            }
        }
    }
}

fn item_name(t: u8) -> String {
    let n = match t {
        0 => "query_type",
        1 => "network",
        5 => "source_ip_cidr",
        7 => "source_port",
        8 => "source_port_range",
        9 => "port",
        10 => "port_range",
        11 => "process_name",
        12 => "process_path",
        13 => "package_name",
        14 => "wifi_ssid",
        15 => "wifi_bssid",
        16 => "adguard_domain",
        _ => "",
    };
    if n.is_empty() {
        format!("#{t}")
    } else {
        n.to_string()
    }
}

fn get_bit(bm: &[u64], i: usize) -> bool {
    bm.get(i >> 6).is_some_and(|w| w & (1u64 << (i & 63)) != 0)
}

/// Все ключи сжатого дерева (LOUDS: у каждого узла — нули по числу детей
/// и единица; метки — по нулям).
fn trie_keys(
    leaves: &[u64],
    bitmap: &[u64],
    labels: &[u8],
) -> std::result::Result<Vec<Vec<u8>>, String> {
    let total_bits = bitmap.len() * 64;
    let mut prefixes: Vec<Vec<u8>> = vec![Vec::new()];
    let mut keys = Vec::new();
    let mut bm = 0usize;
    let mut node = 0usize;
    while node < prefixes.len() {
        if get_bit(leaves, node) {
            keys.push(prefixes[node].clone());
        }
        loop {
            if bm >= total_bits {
                return Err("дерево доменов оборвано".into());
            }
            if get_bit(bitmap, bm) {
                bm += 1;
                break;
            }
            let label = *labels
                .get(bm - node)
                .ok_or("дерево доменов: метка вне списка")?;
            let mut p = prefixes[node].clone();
            p.push(label);
            prefixes.push(p);
            if prefixes.len() > labels.len() + 1 {
                return Err("дерево доменов битое".into());
            }
            bm += 1;
        }
        node += 1;
    }
    Ok(keys)
}

/// Домены и суффиксы из дерева (как `Matcher.Dump` в sing).
fn read_domain_matcher(r: &mut Reader) -> std::result::Result<(Vec<String>, Vec<String>), String> {
    let _version = r.byte()?;
    let leaves = r.u64s()?;
    let bitmap = r.u64s()?;
    let labels = r.bytes()?.to_vec();
    let mut domains = std::collections::BTreeSet::new();
    let mut prefixes = std::collections::BTreeSet::new();
    let mut suffixes = Vec::new();
    for key in trie_keys(&leaves, &bitmap, &labels)? {
        // Строки перевёрнуты по символам (не байтам), как reverseDomain в sing.
        let s: String = String::from_utf8_lossy(&key).chars().rev().collect();
        match s.as_bytes().first() {
            Some(&PREFIX_LABEL) => {
                prefixes.insert(s[1..].to_string());
            }
            Some(&ROOT_LABEL) => suffixes.push(s[1..].to_string()),
            Some(_) => {
                domains.insert(s);
            }
            None => {}
        }
    }
    for p in prefixes {
        // «.example.com» и точный «example.com» — это суффикс example.com.
        if let Some(root) = p.strip_prefix('.') {
            if domains.remove(root) {
                suffixes.push(root.to_string());
                continue;
            }
        }
        suffixes.push(p);
    }
    Ok((domains.into_iter().collect(), suffixes))
}

fn read_ip_set(r: &mut Reader) -> std::result::Result<Vec<IpNet>, String> {
    if r.byte()? != 1 {
        return Err("набор адресов: версия не 1".into());
    }
    let n = u64::from_be_bytes(r.take(8)?.try_into().unwrap()) as usize;
    if n.saturating_mul(10) > r.b.len() - r.pos {
        return Err("набор адресов длиннее файла".into());
    }
    let mut out = Vec::new();
    for _ in 0..n {
        let from = read_addr(r)?;
        let to = read_addr(r)?;
        out.extend(range_to_cidrs(from, to)?);
    }
    Ok(out)
}

fn read_addr(r: &mut Reader) -> std::result::Result<IpAddr, String> {
    let n = r.uvarint()? as usize;
    let b = r.take(n)?;
    match n {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(b).unwrap())),
        16 => {
            let v6 = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap());
            // sing-box хранит IPv4 как «IPv4 в IPv6» не всегда — приводим.
            Ok(IpAddr::V6(v6).to_canonical())
        }
        _ => Err(format!("адрес длиной {n} байт")),
    }
}

/// Диапазон адресов → наименьший набор подсетей.
fn range_to_cidrs(from: IpAddr, to: IpAddr) -> std::result::Result<Vec<IpNet>, String> {
    let (lo, hi, bits, v4) = match (from, to) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128, 32u32, true),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128u32, false),
        _ => return Err("диапазон из адресов разных семейств".into()),
    };
    if lo > hi {
        return Err("диапазон «от» больше «до»".into());
    }
    let mut out = Vec::new();
    let mut cur = lo;
    loop {
        // Самый большой блок, выровненный по cur и не выходящий за hi.
        let mut size_bits = if cur == 0 {
            bits
        } else {
            cur.trailing_zeros().min(bits)
        };
        while size_bits > 0 {
            let span = if size_bits >= 128 {
                u128::MAX
            } else {
                (1u128 << size_bits) - 1
            };
            if cur.checked_add(span).is_some_and(|end| end <= hi) {
                break;
            }
            size_bits -= 1;
        }
        let ip = if v4 {
            IpAddr::V4(std::net::Ipv4Addr::from(cur as u32))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::from(cur))
        };
        out.push(IpNet::new(ip, (bits - size_bits) as u8).expect("префикс в пределах"));
        let span = if size_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << size_bits) - 1
        };
        match cur.checked_add(span) {
            Some(end) if end < hi => cur = end + 1,
            _ => break,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Построить `.srs` так же, как sing-box (`NewMatcher` + LOUDS).
    fn build_trie(mut keys: Vec<Vec<u8>>) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
        keys.sort();
        keys.dedup();
        let mut leaves = vec![0u64; 64];
        let mut bitmap = vec![0u64; 64];
        let mut labels = Vec::new();
        let set = |bm: &mut Vec<u64>, i: usize| {
            if bm.len() <= i >> 6 {
                bm.resize((i >> 6) + 1, 0);
            }
            bm[i >> 6] |= 1 << (i & 63);
        };
        // BFS по группам ключей с общим префиксом.
        let mut queue: std::collections::VecDeque<(usize, usize, usize)> =
            std::collections::VecDeque::from([(0, keys.len(), 0)]);
        let (mut bm, mut node) = (0usize, 0usize);
        while let Some((lo, hi, depth)) = queue.pop_front() {
            let mut i = lo;
            while i < hi {
                if keys[i].len() == depth {
                    set(&mut leaves, node);
                    i += 1;
                    continue;
                }
                let c = keys[i][depth];
                let mut j = i;
                while j < hi && keys[j].len() > depth && keys[j][depth] == c {
                    j += 1;
                }
                labels.push(c);
                bm += 1;
                queue.push_back((i, j, depth + 1));
                i = j;
            }
            set(&mut bitmap, bm);
            bm += 1;
            node += 1;
        }
        let words = bm.div_ceil(64);
        bitmap.truncate(words);
        (leaves, bitmap, labels)
    }

    fn uvarint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn srs(body: Vec<u8>) -> Vec<u8> {
        let mut f = b"SRS\x03".to_vec();
        f.extend(miniz_oxide::deflate::compress_to_vec_zlib(&body, 6));
        f
    }

    fn rev(s: &str) -> Vec<u8> {
        s.chars().rev().collect::<String>().into_bytes()
    }

    #[test]
    fn reads_domains_ips_and_keywords() {
        // domain: exact.example; suffix (v2+): root.example (\n); «.sub.example» (\r).
        let keys = vec![
            rev("exact.example"),
            rev("\nroot.example"),
            rev("\r.sub.example"),
            rev("\r.legacy.example"),
            rev("legacy.example"),
        ];
        let (leaves, bitmap, labels) = build_trie(keys);
        let mut body = Vec::new();
        uvarint(&mut body, 2); // два правила
        body.push(0); // обычное правило
        body.push(2); // домены
        body.push(1);
        for v in [&leaves, &bitmap] {
            uvarint(&mut body, v.len() as u64);
            for w in v.iter() {
                body.extend(w.to_be_bytes());
            }
        }
        uvarint(&mut body, labels.len() as u64);
        body.extend(&labels);
        body.push(3); // keyword
        uvarint(&mut body, 1);
        uvarint(&mut body, 3);
        body.extend(b"ads");
        body.extend([0xff, 0]);
        body.push(0);
        body.push(6); // ip_cidr: 10.0.0.0–10.0.0.255, 1.0.0.1–1.0.0.2
        body.push(1);
        body.extend(2u64.to_be_bytes());
        for (a, b) in [
            ([10, 0, 0, 0], [10, 0, 0, 255]),
            ([1, 0, 0, 1], [1, 0, 0, 2]),
        ] {
            body.push(4);
            body.extend(a);
            body.push(4);
            body.extend(b);
        }
        body.extend([0xff, 0]);
        let rs = parse_srs(&srs(body)).unwrap();
        assert_eq!(rs.domain, ["exact.example"]);
        let mut s = rs.domain_suffix.clone();
        s.sort();
        assert_eq!(s, [".sub.example", "legacy.example", "root.example"]);
        assert_eq!(rs.domain_keyword, ["ads"]);
        let ips: Vec<String> = rs
            .ip_cidr
            .iter()
            .map(|n| format!("{}/{}", n.addr(), n.prefix()))
            .collect();
        assert_eq!(ips, ["10.0.0.0/24", "1.0.0.1/32", "1.0.0.2/32"]);
    }

    #[test]
    fn rejects_unsupported_and_garbage() {
        let mut body = Vec::new();
        uvarint(&mut body, 1);
        body.push(0);
        body.push(9); // port
        uvarint(&mut body, 1);
        body.extend(443u16.to_be_bytes());
        body.extend([0xff, 0]);
        assert!(parse_srs(&srs(body)).unwrap_err().contains("port"));
        let mut body = Vec::new();
        uvarint(&mut body, 1);
        body.push(1);
        assert!(parse_srs(&srs(body)).unwrap_err().contains("логические"));
        assert!(parse_srs(b"SRS\x03garbage").is_err());
        assert!(parse_srs(b"XYZ").is_err());
        // Огромная длина — ошибка, не выделение памяти.
        let mut body = Vec::new();
        uvarint(&mut body, u64::MAX / 2);
        assert!(parse_srs(&srs(body)).is_err());
    }

    #[test]
    fn source_json() {
        let j = br#"{"version":2,"rules":[{"domain_suffix":["ru","su"],"domain":"x.com"},{"ip_cidr":["1.2.3.0/24","5.6.7.8"]}]}"#;
        let rs = parse_source(j).unwrap();
        assert_eq!(rs.domain_suffix, ["ru", "su"]);
        assert_eq!(rs.domain, ["x.com"]);
        assert_eq!(rs.ip_cidr.len(), 2);
        assert!(parse_source(br#"{"rules":[{"port":443}]}"#)
            .unwrap_err()
            .contains("port"));
    }

    #[test]
    fn ranges_to_cidrs() {
        let r = |a: &str, b: &str| -> Vec<String> {
            range_to_cidrs(a.parse().unwrap(), b.parse().unwrap())
                .unwrap()
                .iter()
                .map(|n| format!("{}/{}", n.addr(), n.prefix()))
                .collect()
        };
        assert_eq!(r("0.0.0.0", "255.255.255.255"), ["0.0.0.0/0"]);
        assert_eq!(
            r("10.0.0.1", "10.0.0.6"),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]
        );
        assert_eq!(r("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), ["::/0"]);
        assert_eq!(r("2001:db8::", "2001:db8::ffff"), ["2001:db8::/112"]);
    }
}
