// SPDX-License-Identifier: GPL-3.0-or-later
//! Базы `geosite.dat` и `geoip.dat` в формате V2Ray/Xray (protobuf):
//! списки доменов и подсетей по категориям и странам
//! (`geosite:category-ads-all`, `geoip:ru`).
//!
//! Разбор — свой, минимальный: из protobuf нужны только varint и
//! поля с длиной. Из файла берутся лишь запрошенные категории, остальное
//! сразу отбрасывается — вся база в памяти не держится.
//!
//! Схема (v2fly `app/router/routercommon/common.proto`):
//! ```text
//! GeoSiteList { repeated GeoSite entry = 1; }
//! GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//! Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
//!   Type: Plain = 0 (подстрока), Regex = 1, RootDomain = 2 (домен и поддомены), Full = 3
//! Attribute   { string key = 1; ... }
//! GeoIPList   { repeated GeoIP entry = 1; }
//! GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
//! CIDR        { bytes ip = 1; uint32 prefix = 2; }
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use super::access::IpNet;
use crate::error::{Error, Result};

/// Одна запись geosite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteEntry {
    Keyword(String),
    Regex(String),
    Suffix(String),
    Full(String),
}

enum Wire<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Skip,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

fn bad(what: &str) -> Error {
    Error::Config(format!("{what}: файл повреждён или не того формата"))
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.b.get(self.pos)?;
            self.pos += 1;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Следующее поле: номер и значение. `Ok(None)` — конец сообщения.
    fn field(&mut self) -> Option<Option<(u64, Wire<'a>)>> {
        if self.pos == self.b.len() {
            return Some(None);
        }
        let key = self.varint()?;
        let (num, ty) = (key >> 3, key & 7);
        let w = match ty {
            0 => Wire::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Wire::Skip
            }
            2 => {
                let n = usize::try_from(self.varint()?).ok()?;
                Wire::Bytes(self.take(n)?)
            }
            5 => {
                self.take(4)?;
                Wire::Skip
            }
            _ => return None,
        };
        Some(Some((num, w)))
    }
}

/// Перебрать поля сообщения; `f` получает номер и значение.
fn each_field<'a>(
    b: &'a [u8],
    what: &str,
    mut f: impl FnMut(u64, Wire<'a>) -> Result<()>,
) -> Result<()> {
    let mut r = Reader::new(b);
    loop {
        match r.field() {
            Some(Some((n, w))) => f(n, w)?,
            Some(None) => return Ok(()),
            None => return Err(bad(what)),
        }
    }
}

fn utf8<'a>(b: &'a [u8], what: &str) -> Result<&'a str> {
    std::str::from_utf8(b).map_err(|_| bad(what))
}

/// Имя категории без атрибута и сам атрибут: `google@cn` → (`google`, `cn`).
fn split_attr(code: &str) -> (String, Option<String>) {
    match code.split_once('@') {
        Some((c, a)) => (c.to_ascii_lowercase(), Some(a.to_ascii_lowercase())),
        None => (code.to_ascii_lowercase(), None),
    }
}

/// Прочитать из geosite нужные категории (`cn`, `category-ads-all`,
/// `google@cn`). Нет какой-то категории в файле — ошибка с её именем.
pub fn load_sites(path: &Path, codes: &[String]) -> Result<HashMap<String, Vec<SiteEntry>>> {
    let data = std::fs::read(path).map_err(|e| {
        Error::Config(format!(
            "не удалось прочитать {}: {e} (geosite.dat — например, из \
             github.com/v2fly/domain-list-community/releases)",
            path.display()
        ))
    })?;
    parse_sites(&data, codes).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

pub fn parse_sites(data: &[u8], codes: &[String]) -> Result<HashMap<String, Vec<SiteEntry>>> {
    const W: &str = "geosite";
    // Имя категории → нужные атрибуты (None — вся категория).
    let mut wanted: HashMap<String, Vec<Option<String>>> = HashMap::new();
    for c in codes {
        let (name, attr) = split_attr(c);
        wanted.entry(name).or_default().push(attr);
    }
    let mut out: HashMap<String, Vec<SiteEntry>> = HashMap::new();
    each_field(data, W, |n, w| {
        let (1, Wire::Bytes(site)) = (n, w) else {
            return Ok(());
        };
        // Сначала имя категории: ненужные пропускаем, не разбирая домены.
        let mut code = None;
        each_field(site, W, |n, w| {
            if let (1, Wire::Bytes(c)) = (n, w) {
                code = Some(utf8(c, W)?.to_ascii_lowercase());
            }
            Ok(())
        })?;
        let Some(code) = code else { return Ok(()) };
        let Some(attrs) = wanted.get(&code) else {
            return Ok(());
        };
        each_field(site, W, |n, w| {
            let (2, Wire::Bytes(dom)) = (n, w) else {
                return Ok(());
            };
            let (mut ty, mut value, mut dom_attrs) = (0u64, None, Vec::new());
            each_field(dom, W, |n, w| {
                match (n, w) {
                    (1, Wire::Varint(v)) => ty = v,
                    (2, Wire::Bytes(v)) => value = Some(utf8(v, W)?.to_ascii_lowercase()),
                    (3, Wire::Bytes(a)) => each_field(a, W, |n, w| {
                        if let (1, Wire::Bytes(k)) = (n, w) {
                            dom_attrs.push(utf8(k, W)?.to_ascii_lowercase());
                        }
                        Ok(())
                    })?,
                    _ => {}
                }
                Ok(())
            })?;
            let Some(value) = value else { return Ok(()) };
            let entry = match ty {
                0 => SiteEntry::Keyword(value),
                1 => SiteEntry::Regex(value),
                2 => SiteEntry::Suffix(value),
                3 => SiteEntry::Full(value),
                _ => return Ok(()),
            };
            for attr in attrs {
                let key = match attr {
                    None => code.clone(),
                    Some(a) if dom_attrs.contains(a) => format!("{code}@{a}"),
                    Some(_) => continue,
                };
                out.entry(key).or_default().push(entry.clone());
            }
            Ok(())
        })
    })?;
    for c in codes {
        let (name, attr) = split_attr(c);
        let key = match attr {
            Some(a) => format!("{name}@{a}"),
            None => name,
        };
        if !out.contains_key(&key) {
            return Err(Error::Config(format!("в geosite нет категории «{c}»")));
        }
    }
    Ok(out)
}

/// Прочитать из geoip нужные страны (`ru`, `private`).
pub fn load_ips(path: &Path, codes: &[String]) -> Result<HashMap<String, Vec<IpNet>>> {
    let data = std::fs::read(path).map_err(|e| {
        Error::Config(format!(
            "не удалось прочитать {}: {e} (geoip.dat — например, из \
             github.com/v2fly/geoip/releases)",
            path.display()
        ))
    })?;
    parse_ips(&data, codes).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

pub fn parse_ips(data: &[u8], codes: &[String]) -> Result<HashMap<String, Vec<IpNet>>> {
    const W: &str = "geoip";
    let wanted: Vec<String> = codes.iter().map(|c| c.to_ascii_lowercase()).collect();
    let mut out: HashMap<String, Vec<IpNet>> = HashMap::new();
    each_field(data, W, |n, w| {
        let (1, Wire::Bytes(geo)) = (n, w) else {
            return Ok(());
        };
        let mut code = None;
        let mut reverse = false;
        each_field(geo, W, |n, w| {
            match (n, w) {
                (1, Wire::Bytes(c)) => code = Some(utf8(c, W)?.to_ascii_lowercase()),
                (3, Wire::Varint(v)) => reverse = v != 0,
                _ => {}
            }
            Ok(())
        })?;
        let Some(code) = code.filter(|c| wanted.contains(c)) else {
            return Ok(());
        };
        if reverse {
            return Err(Error::Config(format!(
                "geoip: категория «{code}» с reverse_match не поддерживается"
            )));
        }
        let list = out.entry(code).or_default();
        each_field(geo, W, |n, w| {
            let (2, Wire::Bytes(cidr)) = (n, w) else {
                return Ok(());
            };
            let (mut ip, mut prefix) = (None, 0u64);
            each_field(cidr, W, |n, w| {
                match (n, w) {
                    (1, Wire::Bytes(b)) => {
                        ip = match b.len() {
                            4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).unwrap())),
                            16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).unwrap())),
                            _ => return Err(bad(W)),
                        }
                    }
                    (2, Wire::Varint(p)) => prefix = p,
                    _ => {}
                }
                Ok(())
            })?;
            let ip = ip.ok_or_else(|| bad(W))?;
            let net = u8::try_from(prefix)
                .ok()
                .and_then(|p| IpNet::new(ip, p))
                .ok_or_else(|| bad(W))?;
            list.push(net);
            Ok(())
        })
    })?;
    for c in &wanted {
        if !out.contains_key(c) {
            return Err(Error::Config(format!("в geoip нет категории «{c}»")));
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn varint(mut v: u64, out: &mut Vec<u8>) {
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
    fn bytes_field(n: u64, b: &[u8], out: &mut Vec<u8>) {
        varint(n << 3 | 2, out);
        varint(b.len() as u64, out);
        out.extend_from_slice(b);
    }
    fn varint_field(n: u64, v: u64, out: &mut Vec<u8>) {
        varint(n << 3, out);
        varint(v, out);
    }

    type Cat<'a> = (&'a str, &'a [(u64, &'a str, &'a [&'a str])]);

    /// Маленький geosite.dat для тестов: (категория, [(тип, значение, атрибуты)]).
    pub fn build_sites(cats: &[Cat<'_>]) -> Vec<u8> {
        let mut file = Vec::new();
        for (code, doms) in cats {
            let mut site = Vec::new();
            bytes_field(1, code.to_uppercase().as_bytes(), &mut site);
            for (ty, v, attrs) in doms.iter() {
                let mut d = Vec::new();
                varint_field(1, *ty, &mut d);
                bytes_field(2, v.as_bytes(), &mut d);
                for a in attrs.iter() {
                    let mut at = Vec::new();
                    bytes_field(1, a.as_bytes(), &mut at);
                    varint_field(2, 1, &mut at);
                    bytes_field(3, &at, &mut d);
                }
                bytes_field(2, &d, &mut site);
            }
            bytes_field(1, &site, &mut file);
        }
        file
    }

    /// Маленький geoip.dat: (страна, [подсети]).
    pub fn build_ips(cats: &[(&str, &[&str])]) -> Vec<u8> {
        let mut file = Vec::new();
        for (code, nets) in cats {
            let mut geo = Vec::new();
            bytes_field(1, code.to_uppercase().as_bytes(), &mut geo);
            for n in nets.iter() {
                let net: IpNet = n.parse().unwrap();
                let mut c = Vec::new();
                match net.addr() {
                    IpAddr::V4(v4) => bytes_field(1, &v4.octets(), &mut c),
                    IpAddr::V6(v6) => bytes_field(1, &v6.octets(), &mut c),
                }
                varint_field(2, net.prefix() as u64, &mut c);
                bytes_field(2, &c, &mut geo);
            }
            bytes_field(1, &geo, &mut file);
        }
        file
    }

    #[test]
    fn sites_by_category_and_attribute() {
        let f = build_sites(&[
            (
                "google",
                &[
                    (2, "google.com", &["cn"]),
                    (3, "www.google.com", &[]),
                    (0, "gstatic", &[]),
                ],
            ),
            ("ads", &[(1, "^ad[0-9]+\\.", &[])]),
            ("unused", &[(2, "example.org", &[])]),
        ]);
        let m = parse_sites(&f, &["GOOGLE".into(), "google@cn".into(), "ads".into()]).unwrap();
        assert_eq!(m["google"].len(), 3);
        assert_eq!(m["google@cn"], vec![SiteEntry::Suffix("google.com".into())]);
        assert_eq!(m["ads"], vec![SiteEntry::Regex("^ad[0-9]+\\.".into())]);
        assert!(!m.contains_key("unused"));
        let e = parse_sites(&f, &["nope".into()]).unwrap_err();
        assert!(e.to_string().contains("nope"), "{e}");
    }

    #[test]
    fn ips_by_country() {
        let f = build_ips(&[
            ("ru", &["5.8.0.0/16", "2a00:1450::/32"]),
            ("us", &["8.8.8.0/24"]),
        ]);
        let m = parse_ips(&f, &["RU".into()]).unwrap();
        assert_eq!(m["ru"].len(), 2);
        assert!(m["ru"][0].contains("5.8.1.2".parse().unwrap()));
        assert!(!m.contains_key("us"));
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for bad in [
            &[0x0a, 0xff][..],
            &[0x0a, 0x05, 1, 2][..],
            &[0xff; 12][..],
            &[0x0f][..],
        ] {
            assert!(parse_sites(bad, &["x".into()]).is_err());
            assert!(parse_ips(bad, &["x".into()]).is_err());
        }
    }
}
