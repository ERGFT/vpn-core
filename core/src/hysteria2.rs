// SPDX-License-Identifier: GPL-3.0-or-later
//! Hysteria 2 client configuration primitives.
//!
//! This module parses and validates sharing URIs used by the Hysteria 2
//! transport and production outbound. Protocol and interoperability status is
//! tracked in `docs/HYSTERIA2_IMPLEMENTATION_PLAN.md`.

use std::fmt;

use crate::error::{Error, Result};

/// Bound the number of port groups accepted from a URI or subscription.
const MAX_PORT_RANGES: usize = 128;
const SALAMANDER_MIN_PSK_LEN: usize = 4;

/// One port or an inclusive range from a Hysteria port-hopping address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

/// Obfuscation modes named in Hysteria 2 sharing URIs.
#[derive(Clone, PartialEq, Eq)]
pub enum Obfuscation {
    Salamander { password: String },
    Gecko { password: String },
}

impl fmt::Debug for Obfuscation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Salamander { .. } => "Salamander",
            Self::Gecko { .. } => "Gecko",
        };
        f.debug_struct("Obfuscation")
            .field("kind", &kind)
            .field("password", &crate::redact::Redacted)
            .finish()
    }
}

/// Validated, typed representation of a `hysteria2://` or `hy2://` URI.
///
/// Credentials and obfuscation secrets are redacted by `Debug`. Parsing a
/// URI does not imply that the Hysteria 2 outbound is available yet.
#[derive(Clone)]
pub struct Hysteria2Config {
    pub server: String,
    pub ports: Vec<PortRange>,
    pub auth: Option<String>,
    pub sni: Option<String>,
    pub insecure: bool,
    pub obfuscation: Option<Obfuscation>,
    pub pin_sha256: Option<String>,
    pub ech: Option<String>,
    pub name: Option<String>,
}

impl fmt::Debug for Hysteria2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2Config")
            .field("server", &self.server)
            .field("ports", &self.ports)
            .field("auth", &self.auth.as_ref().map(|_| crate::redact::Redacted))
            .field("sni", &self.sni)
            .field("insecure", &self.insecure)
            .field("obfuscation", &self.obfuscation)
            .field("pin_sha256", &self.pin_sha256)
            .field("ech", &self.ech.as_ref().map(|_| crate::redact::Redacted))
            .field("name", &self.name)
            .finish()
    }
}

impl Hysteria2Config {
    /// Parse the official Hysteria 2 sharing URI shape.
    pub fn parse(uri: &str) -> Result<Self> {
        let invalid = |message: String| Error::InvalidUri(format!("Hysteria 2: {message}"));
        let (scheme, rest) = uri
            .split_once("://")
            .ok_or_else(|| invalid("ожидалась ссылка hysteria2:// или hy2://".into()))?;
        if !matches!(scheme.to_ascii_lowercase().as_str(), "hysteria2" | "hy2") {
            return Err(invalid(format!(
                "ожидалась схема hysteria2 или hy2, получена {scheme}"
            )));
        }

        let (without_fragment, raw_name) = match rest.split_once('#') {
            Some((left, right)) => (left, Some(right)),
            None => (rest, None),
        };
        let (authority_path, raw_query) = match without_fragment.split_once('?') {
            Some((left, right)) => (left, Some(right)),
            None => (without_fragment, None),
        };
        let (authority, path) = authority_path
            .split_once('/')
            .map_or((authority_path, ""), |(a, p)| (a, p));
        if !path.is_empty() {
            return Err(invalid("путь в URI должен быть пустым или '/'".into()));
        }
        if authority.is_empty() {
            return Err(invalid("не задан адрес сервера".into()));
        }

        let (raw_auth, host_port) = match authority.rsplit_once('@') {
            Some((auth, host)) => (Some(auth), host),
            None => (None, authority),
        };
        let auth = raw_auth.map(decode_percent).transpose().map_err(invalid)?;
        if auth.as_deref().is_some_and(str::is_empty) {
            return Err(invalid("перед '@' задана пустая учётная запись".into()));
        }
        if auth
            .as_deref()
            .is_some_and(|value| value.chars().any(char::is_control))
        {
            return Err(invalid(
                "учётная запись содержит управляющие символы".into(),
            ));
        }

        let (raw_server, raw_ports) = parse_host_port(host_port).map_err(invalid)?;
        let server = normalize_host(raw_server).map_err(invalid)?;
        let ports = parse_ports(raw_ports.unwrap_or("443")).map_err(invalid)?;

        let mut sni = None;
        let mut insecure = false;
        let mut obfs = None;
        let mut obfs_password = None;
        let mut pin_sha256 = None;
        let mut ech = None;
        let mut seen = std::collections::HashSet::new();
        if let Some(query) = raw_query {
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                let key = key.into_owned();
                if !seen.insert(key.clone()) {
                    return Err(invalid(format!(
                        "параметр '{key}' задан больше одного раза"
                    )));
                }
                match key.as_str() {
                    "sni" => {
                        let value = validate_text("sni", value.into_owned()).map_err(invalid)?;
                        if value
                            .chars()
                            .any(|c| c.is_whitespace() || matches!(c, '/' | '@' | ':'))
                        {
                            return Err(invalid("sni содержит недопустимые символы".into()));
                        }
                        sni = Some(value);
                    }
                    "insecure" => {
                        insecure = match value.as_ref() {
                            "1" => true,
                            "0" => false,
                            other => {
                                return Err(invalid(format!(
                                    "insecure должен быть 0 или 1, получено '{other}'"
                                )))
                            }
                        }
                    }
                    "obfs" => obfs = Some(value.into_owned()),
                    "obfs-password" => obfs_password = Some(value.into_owned()),
                    "pinSHA256" => {
                        pin_sha256 =
                            Some(validate_text("pinSHA256", value.into_owned()).map_err(invalid)?)
                    }
                    "ech" => {
                        let encoded = value.into_owned();
                        use base64::Engine as _;
                        let valid = base64::engine::general_purpose::STANDARD
                            .decode(&encoded)
                            .or_else(|_| {
                                base64::engine::general_purpose::STANDARD_NO_PAD.decode(&encoded)
                            })
                            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&encoded))
                            .or_else(|_| {
                                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&encoded)
                            })
                            .is_ok();
                        if encoded.is_empty() || !valid {
                            return Err(invalid(
                                "ech должен содержать корректный base64 config list".into(),
                            ));
                        }
                        ech = Some(encoded);
                    }
                    other => return Err(invalid(format!("параметр '{other}' не поддерживается"))),
                }
            }
        }
        let obfuscation = match (obfs.as_deref(), obfs_password) {
            (None, None) => None,
            (None, Some(_)) => return Err(invalid("obfs-password требует параметр obfs".into())),
            (Some(_), None) => return Err(invalid("для obfs требуется obfs-password".into())),
            (Some(_), Some(password)) if password.is_empty() => {
                return Err(invalid("obfs-password не может быть пустым".into()))
            }
            (Some("salamander"), Some(password))
                if password.len() < SALAMANDER_MIN_PSK_LEN =>
            {
                return Err(invalid(format!(
                    "Salamander obfs-password должен содержать не менее {SALAMANDER_MIN_PSK_LEN} байт"
                )))
            }
            (Some(_), Some(password)) if password.chars().any(char::is_control) => {
                return Err(invalid("obfs-password содержит управляющие символы".into()))
            }
            (Some("salamander"), Some(password)) => Some(Obfuscation::Salamander { password }),
            (Some("gecko"), Some(password)) => Some(Obfuscation::Gecko { password }),
            (Some(kind), Some(_)) => {
                return Err(invalid(format!(
                    "неподдерживаемый obfs '{kind}' (доступны salamander и gecko)"
                )))
            }
        };
        let name = raw_name
            .map(decode_percent)
            .transpose()
            .map_err(invalid)?
            .map(|mut n| {
                n.retain(|c| !c.is_control());
                n
            })
            .filter(|n| !n.is_empty());

        Ok(Self {
            server,
            ports,
            auth,
            sni,
            insecure,
            obfuscation,
            pin_sha256,
            ech,
            name,
        })
    }
}

fn parse_host_port(authority: &str) -> std::result::Result<(&str, Option<&str>), String> {
    if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, tail) = ipv6
            .split_once(']')
            .ok_or_else(|| "IPv6-адрес должен быть заключён в квадратные скобки".to_string())?;
        if tail.is_empty() {
            return Ok((host, None));
        }
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| "ожидался ':' перед портом после IPv6-адреса".to_string())?;
        if port.is_empty() {
            return Err("порт пуст".into());
        }
        return Ok((host, Some(port)));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if host.is_empty() || port.is_empty() => {
            Err("неверный host:port".into())
        }
        Some((host, port)) => Ok((host, Some(port))),
        None => Ok((authority, None)),
    }
}

fn normalize_host(host: &str) -> std::result::Result<String, String> {
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '/')
    {
        return Err("адрес сервера пуст или содержит недопустимые символы".into());
    }
    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(ipv6.to_string());
    }
    let parsed = url::Url::parse(&format!("https://{host}/"))
        .map_err(|_| format!("некорректный адрес сервера '{host}'"))?;
    parsed
        .host_str()
        .map(str::to_owned)
        .ok_or_else(|| "не задан адрес сервера".into())
}

fn parse_ports(input: &str) -> std::result::Result<Vec<PortRange>, String> {
    if input.is_empty() {
        return Err("порт пуст".into());
    }
    let mut ports = Vec::new();
    for item in input.split(',') {
        if ports.len() == MAX_PORT_RANGES {
            return Err(format!(
                "разрешено не больше {MAX_PORT_RANGES} диапазонов портов"
            ));
        }
        if item.is_empty() || item.trim() != item {
            return Err(format!("неверный элемент диапазона портов '{item}'"));
        }
        let (first, last) = match item.split_once('-') {
            Some((first, last)) if !last.contains('-') => (first, last),
            Some(_) => return Err(format!("неверный диапазон портов '{item}'")),
            None => (item, item),
        };
        let parse_one = |s: &str| -> std::result::Result<u16, String> {
            s.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("порт должен быть числом от 1 до 65535: '{s}'"))
        };
        let first = parse_one(first)?;
        let last = parse_one(last)?;
        if first > last {
            return Err(format!("начало диапазона больше конца: '{item}'"));
        }
        ports.push(PortRange { first, last });
    }
    Ok(ports)
}

fn validate_text(field: &str, value: String) -> std::result::Result<String, String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(format!("{field} пуст или содержит управляющие символы"));
    }
    Ok(value)
}

/// Decode percent escapes without converting literal '+' to a space. Hysteria
/// authentication strings are userinfo, not form-urlencoded data.
fn decode_percent(value: &str) -> std::result::Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("неполная percent-последовательность".into());
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| "некорректная percent-последовательность".to_string())?;
            decoded.push(
                u8::from_str_radix(hex, 16)
                    .map_err(|_| "некорректная percent-последовательность".to_string())?,
            );
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "URI содержит не-UTF-8 текст".into())
}

#[cfg(test)]
mod tests {
    use super::{Hysteria2Config, Obfuscation, PortRange};

    #[test]
    fn parses_default_port_and_literal_plus_in_auth() {
        let cfg = Hysteria2Config::parse("hysteria2://user+tag@example.com").unwrap();
        assert_eq!(cfg.server, "example.com");
        assert_eq!(
            cfg.ports,
            [PortRange {
                first: 443,
                last: 443
            }]
        );
        assert_eq!(cfg.auth.as_deref(), Some("user+tag"));
    }

    #[test]
    fn parses_hy2_ipv6_port_hopping_and_supported_query_values() {
        let cfg = Hysteria2Config::parse(
            "hy2://user%3Apass@[2001:db8::1]:443,5000-5010/?sni=front.example&insecure=0&obfs=salamander&obfs-password=secret#home%20node",
        )
        .unwrap();
        assert_eq!(cfg.server, "2001:db8::1");
        assert_eq!(cfg.auth.as_deref(), Some("user:pass"));
        assert_eq!(cfg.ports.len(), 2);
        assert_eq!(
            cfg.ports[1],
            PortRange {
                first: 5000,
                last: 5010
            }
        );
        assert_eq!(cfg.sni.as_deref(), Some("front.example"));
        assert!(matches!(
            cfg.obfuscation,
            Some(Obfuscation::Salamander { .. })
        ));
        assert_eq!(cfg.name.as_deref(), Some("home node"));
    }

    #[test]
    fn debug_redacts_credentials_and_obfuscation_password() {
        let cfg = Hysteria2Config::parse(
            "hy2://very-secret@example.com?obfs=salamander&obfs-password=also-secret",
        )
        .unwrap();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("very-secret"));
        assert!(!debug.contains("also-secret"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_uri_fields() {
        for uri in [
            "hy2://pass@host?unknown=1",
            "hy2://pass@host?insecure=true",
            "hy2://pass@host?sni=a&sni=b",
            "hy2://pass@host?obfs-password=x",
            "hy2://pass@host?obfs=salamander",
            "hy2://pass@host:0",
            "hy2://pass@host:9-2",
            "hy2://pass@host:65536",
            "hy2://pass@host/a",
            "hy2://bad%0D%0Aauth@host",
            "hy2://bad%ZZ@host",
            "hy2://pass@host?ech=not-base64",
        ] {
            assert!(Hysteria2Config::parse(uri).is_err(), "{uri}");
        }
    }

    #[test]
    fn enforces_reference_salamander_minimum_psk_length_in_bytes() {
        for password in ["a", "abc"] {
            let uri = format!("hy2://pass@host?obfs=salamander&obfs-password={password}");
            assert!(Hysteria2Config::parse(&uri).is_err(), "{uri}");
        }

        let ascii =
            Hysteria2Config::parse("hy2://pass@host?obfs=salamander&obfs-password=abcd").unwrap();
        assert!(matches!(
            ascii.obfuscation,
            Some(Obfuscation::Salamander { .. })
        ));

        // The reference Go implementation measures the UTF-8 byte slice.
        let unicode =
            Hysteria2Config::parse("hy2://pass@host?obfs=salamander&obfs-password=%C3%A9%C3%A9")
                .unwrap();
        assert!(matches!(
            unicode.obfuscation,
            Some(Obfuscation::Salamander { .. })
        ));
    }
}
