// SPDX-License-Identifier: GPL-3.0-or-later
//! Format decoders and the normalized subscription server model.

use std::collections::HashMap;

use super::super::config::link::LinkBuilder;
use crate::error::{Error, Result};
use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NormalizedProtocol {
    Vless,
    Trojan,
    Hysteria2,
    Shadowsocks,
}

impl NormalizedProtocol {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria2 => "hysteria2",
            Self::Shadowsocks => "shadowsocks",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct NormalizedServer {
    pub(super) protocol: NormalizedProtocol,
    pub(super) name: String,
    pub(super) link: String,
}

impl std::fmt::Debug for NormalizedServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NormalizedServer")
            .field("protocol", &self.protocol)
            .field("name", &self.name)
            .field("link", &crate::redact::Redacted)
            .finish()
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct NormalizedSubscription {
    pub(super) servers: Vec<NormalizedServer>,
    pub(super) skipped: HashMap<String, usize>,
    pub(super) invalid: usize,
}

impl NormalizedSubscription {
    fn push_server(&mut self, scheme: &str, name: String, link: String) {
        let protocol = match scheme {
            "vless" => NormalizedProtocol::Vless,
            "trojan" => NormalizedProtocol::Trojan,
            "hysteria2" | "hy2" => NormalizedProtocol::Hysteria2,
            "ss" => NormalizedProtocol::Shadowsocks,
            _ => return,
        };
        self.servers.push(NormalizedServer {
            protocol,
            name,
            link,
        });
    }
}

/// Что нашлось в ответе панели.
#[derive(Default, PartialEq, Eq)]
pub struct Parsed {
    /// Имя сервера и vless://-ссылка.
    pub servers: Vec<(String, String)>,
    /// Пропущенные протоколы: схема → сколько.
    pub skipped: HashMap<String, usize>,
    /// Серверы с неверными полями (порт вне 1–65535).
    pub invalid: usize,
}

impl std::fmt::Debug for Parsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parsed")
            .field(
                "servers",
                &self
                    .servers
                    .iter()
                    .map(|(name, _)| (name, "[REDACTED]"))
                    .collect::<Vec<_>>(),
            )
            .field("skipped", &self.skipped)
            .field("invalid", &self.invalid)
            .finish()
    }
}

/// Порт сервера: по умолчанию 443; число вне `u16` или 0 — `None`
/// (раньше `as u16` молча превращал 70000 в 4464).
fn port_of(v: Option<&serde_json::Value>) -> Option<u16> {
    let Some(v) = v else { return Some(443) };
    let n = v
        .as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))?;
    u16::try_from(n).ok().filter(|&p| p != 0)
}

fn pct_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_string())
}

fn decode_base64(text: &str) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(b) = engine.decode(&compact) {
            if let Ok(s) = String::from_utf8(b) {
                return Some(s);
            }
        }
    }
    None
}

fn parse_lines(text: &str, out: &mut NormalizedSubscription) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((scheme, rest)) = line.split_once("://") else {
            continue;
        };
        let scheme = scheme.to_ascii_lowercase();
        if scheme == "hysteria2" || scheme == "hy2" {
            match crate::hysteria2::Hysteria2Config::parse(line) {
                Ok(config) => out.servers.push(NormalizedServer {
                    protocol: NormalizedProtocol::Hysteria2,
                    name: config.name.unwrap_or_else(|| config.server.clone()),
                    link: line.to_string(),
                }),
                Err(_) => out.invalid += 1,
            }
            continue;
        }
        if scheme == "ss" {
            match shadowsocks::config::ServerConfig::from_url(line) {
                Ok(config) if crate::shadowsocks_protocol::validate_classic(&config).is_ok() => {
                    let name = config
                        .remarks()
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| config.addr().to_string());
                    out.servers.push(NormalizedServer {
                        protocol: NormalizedProtocol::Shadowsocks,
                        name,
                        link: line.to_string(),
                    });
                }
                _ => out.invalid += 1,
            }
            continue;
        }
        if scheme != "vless" && scheme != "trojan" {
            *out.skipped.entry(scheme).or_default() += 1;
            continue;
        }
        let name = match rest.split_once('#') {
            Some((_, frag)) if !frag.is_empty() => pct_decode(frag),
            _ => rest
                .split(['?', '#'])
                .next()
                .and_then(|a| a.rsplit_once('@'))
                .map(|(_, hp)| hp.to_string())
                .unwrap_or_else(|| "server".into()),
        };
        out.push_server(&scheme, name, line.to_string());
    }
}

/// Convert the Shadowsocks profile representable by a standard sing-box
/// outbound. Plugins and transport extensions are rejected until implemented.
pub(crate) fn singbox_shadowsocks_uri(o: &serde_json::Value) -> Result<Option<String>> {
    let configured = |v: &serde_json::Value| {
        !v.is_null()
            && v.as_bool() != Some(false)
            && v.as_str() != Some("")
            && !v.as_array().is_some_and(Vec::is_empty)
            && !v.as_object().is_some_and(serde_json::Map::is_empty)
    };
    let allowed = ["type", "tag", "server", "server_port", "method", "password"];
    if o.as_object().is_some_and(|map| {
        map.iter()
            .any(|(k, v)| !allowed.contains(&k.as_str()) && configured(v))
    }) {
        return Ok(None);
    }
    for field in ["server", "method", "password"] {
        if o.get(field).is_some_and(|v| !v.is_string()) {
            return Err(Error::Config(format!(
                "Shadowsocks sing-box: {field} has the wrong type"
            )));
        }
    }
    let server = o
        .get("server")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Config("Shadowsocks sing-box: missing server".into()))?;
    let method = o
        .get("method")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Config("Shadowsocks sing-box: missing method".into()))?;
    let password = o
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Config("Shadowsocks sing-box: missing password".into()))?;
    let port = port_of(o.get("server_port")).ok_or_else(|| {
        Error::Config("Shadowsocks sing-box: missing or invalid server_port".into())
    })?;
    crate::shadowsocks_protocol::uri_from_fields(server, port, method, password).map(Some)
}

fn js<'a>(v: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    Some(cur)
}

fn js_str(v: &serde_json::Value, path: &[&str]) -> String {
    js(v, path)
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Преобразовать URI-представимое подмножество sing-box Hysteria2 в каноническую
/// модель URI. Опции, которые нельзя сохранить, пропускаются явно.
pub(crate) fn singbox_hysteria2_uri(o: &serde_json::Value) -> Result<Option<String>> {
    let invalid =
        |field: &str| Error::Config(format!("Hysteria 2 sing-box: {field} has the wrong type"));
    let configured = |v: &serde_json::Value| {
        !v.is_null()
            && v.as_bool() != Some(false)
            && v.as_str() != Some("")
            && !v.as_array().is_some_and(Vec::is_empty)
            && !v.as_object().is_some_and(serde_json::Map::is_empty)
    };
    let unsupported = [
        "hop_interval",
        "hop_interval_max",
        "up_mbps",
        "down_mbps",
        "network",
        "bbr_profile",
        "brutal_debug",
        "disable_chrome_parrot",
        "realm",
        "domain_resolver",
        "detour",
        "bind_interface",
        "bind_address",
        "bind_address_no_port",
        "routing_mark",
        "reuse_addr",
        "connect_timeout",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "udp_fragment_default",
        "udp_fragment_size",
    ];
    if unsupported
        .iter()
        .any(|key| o.get(key).is_some_and(configured))
    {
        return Ok(None);
    }
    let has_extra = |object: &serde_json::Value, allowed: &[&str]| {
        object.as_object().is_some_and(|map| {
            map.iter()
                .any(|(key, value)| !allowed.contains(&key.as_str()) && configured(value))
        })
    };
    if has_extra(
        o,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "server_ports",
            "password",
            "obfs",
            "tls",
        ],
    ) || has_extra(
        js(o, &["obfs"]).unwrap_or(&serde_json::Value::Null),
        &["type", "password"],
    ) || has_extra(
        js(o, &["tls"]).unwrap_or(&serde_json::Value::Null),
        &["enabled", "server_name", "insecure"],
    ) {
        return Ok(None);
    }
    for field in ["tls", "obfs"] {
        if o.get(field).is_some_and(|v| !v.is_object()) {
            return Err(invalid(field));
        }
    }
    for (path, label) in [
        (&["server"][..], "server"),
        (&["password"][..], "password"),
        (&["tag"][..], "tag"),
        (&["tls", "server_name"][..], "tls.server_name"),
        (&["obfs", "type"][..], "obfs.type"),
        (&["obfs", "password"][..], "obfs.password"),
    ] {
        if js(o, path).is_some_and(|v| !v.is_string()) {
            return Err(invalid(label));
        }
    }
    for (path, label) in [
        (&["tls", "enabled"][..], "tls.enabled"),
        (&["tls", "insecure"][..], "tls.insecure"),
    ] {
        if js(o, path).is_some_and(|v| !v.is_boolean()) {
            return Err(invalid(label));
        }
    }
    if js(o, &["tls", "enabled"]).and_then(|v| v.as_bool()) == Some(false) {
        return Ok(None);
    }
    let server = js(o, &["server"])
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Config("Hysteria 2 sing-box: missing server".into()))?;
    let port = port_of(js(o, &["server_port"]));
    let ports = js(o, &["server_ports"]).and_then(|v| v.as_array());
    if port.is_none() && ports.is_none() {
        return Err(Error::Config(
            "Hysteria 2 sing-box: missing or invalid server_port/server_ports".into(),
        ));
    }
    let port_text = if let Some(values) = ports {
        if values.is_empty() {
            return Err(Error::Config(
                "Hysteria 2 sing-box: server_ports is empty".into(),
            ));
        }
        let mut normalized = Vec::with_capacity(values.len());
        for item in values {
            let Some(item) = item.as_str() else {
                return Err(Error::Config(
                    "Hysteria 2 sing-box: server_ports entries must be strings".into(),
                ));
            };
            // В sing-box диапазон записывается `first:last`, в URI — `first-last`.
            normalized.push(item.replace(':', "-"));
        }
        normalized.join(",")
    } else {
        match port {
            Some(port) => port.to_string(),
            None => {
                return Err(Error::Config(
                    "Hysteria 2 sing-box: missing or invalid server_port/server_ports".into(),
                ));
            }
        }
    };
    if port_text.is_empty() {
        return Err(Error::Config(
            "Hysteria 2 sing-box: server port is empty".into(),
        ));
    }
    let host = if server.contains(':') {
        format!("[{server}]")
    } else {
        server.to_string()
    };
    let password = js_str(o, &["password"]);
    if password.is_empty() {
        return Err(Error::Config(
            "Hysteria 2 sing-box: password is missing or empty".into(),
        ));
    }
    let user: String = url::form_urlencoded::byte_serialize(password.as_bytes())
        .collect::<String>()
        .replace('+', "%20");
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    if let Some(sni) = js(o, &["tls", "server_name"]).and_then(|v| v.as_str()) {
        q.append_pair("sni", sni);
    }
    if js(o, &["tls", "insecure"]).and_then(|v| v.as_bool()) == Some(true) {
        q.append_pair("insecure", "1");
    }
    let obfs_type = js_str(o, &["obfs", "type"]);
    if obfs_type.is_empty() && js(o, &["obfs", "password"]).is_some() {
        return Err(Error::Config(
            "Hysteria 2 sing-box: obfs.password requires obfs.type".into(),
        ));
    }
    if !obfs_type.is_empty() {
        if obfs_type != "salamander" && obfs_type != "gecko" {
            return Ok(None);
        }
        q.append_pair("obfs", &obfs_type);
        let obfs_password = js_str(o, &["obfs", "password"]);
        if obfs_password.is_empty() {
            return Err(Error::Config(
                "Hysteria 2 sing-box: obfs.password is missing or empty".into(),
            ));
        }
        q.append_pair("obfs-password", &obfs_password);
    }
    let name = js_str(o, &["tag"]);
    let name = url::form_urlencoded::byte_serialize(name.as_bytes())
        .collect::<String>()
        .replace('+', "%20");
    let query = q.finish();
    let uri = format!(
        "hysteria2://{user}@{host}:{port_text}/{}{}",
        if query.is_empty() { "" } else { "?" },
        query
    );
    let uri = if name.is_empty() {
        uri
    } else {
        format!("{uri}#{name}")
    };
    if crate::hysteria2::Hysteria2Config::parse(&uri).is_err() {
        return Ok(None);
    }
    Ok(Some(uri))
}

/// JSON sing-box: supported proxy outbounds, including the URI-only Hysteria2 adapter.
fn parse_singbox(text: &str, out: &mut NormalizedSubscription) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| Error::Config(format!("подписка: JSON sing-box: {e}")))?;
    let list = v
        .get("outbounds")
        .and_then(|o| o.as_array())
        .cloned()
        .unwrap_or_default();
    for o in list {
        let ty = js_str(&o, &["type"]);
        let scheme = match ty.as_str() {
            "vless" => "vless",
            "trojan" => "trojan",
            "hysteria2" => {
                match singbox_hysteria2_uri(&o) {
                    Ok(Some(link)) => {
                        let name = js_str(&o, &["tag"]);
                        let name = if name.is_empty() {
                            js_str(&o, &["server"])
                        } else {
                            name
                        };
                        out.servers.push(NormalizedServer {
                            protocol: NormalizedProtocol::Hysteria2,
                            name,
                            link,
                        });
                    }
                    Ok(None) => {
                        *out.skipped
                            .entry("hysteria2 (unsupported sing-box options)".into())
                            .or_default() += 1
                    }
                    Err(_) => out.invalid += 1,
                }
                continue;
            }
            "shadowsocks" => {
                match singbox_shadowsocks_uri(&o) {
                    Ok(Some(link)) => {
                        let name = js_str(&o, &["tag"]);
                        let name = if name.is_empty() {
                            js_str(&o, &["server"])
                        } else {
                            name
                        };
                        out.servers.push(NormalizedServer {
                            protocol: NormalizedProtocol::Shadowsocks,
                            name,
                            link,
                        });
                    }
                    Ok(None) => {
                        *out.skipped
                            .entry("shadowsocks (unsupported sing-box options)".into())
                            .or_default() += 1;
                    }
                    Err(_) => out.invalid += 1,
                }
                continue;
            }
            // Служебные выходы sing-box — не серверы.
            "direct" | "block" | "dns" | "selector" | "urltest" | "" => continue,
            other => {
                *out.skipped.entry(other.to_string()).or_default() += 1;
                continue;
            }
        };
        let Some(port) = port_of(js(&o, &["server_port"])) else {
            out.invalid += 1;
            continue;
        };
        let mut b = LinkBuilder {
            scheme,
            uuid: if scheme == "trojan" {
                js_str(&o, &["password"])
            } else {
                js_str(&o, &["uuid"])
            },
            host: js_str(&o, &["server"]),
            port,
            params: Vec::new(),
            name: js_str(&o, &["tag"]),
        };
        b.param("flow", js_str(&o, &["flow"]));
        let tls = js(&o, &["tls", "enabled"]).and_then(|x| x.as_bool()) == Some(true);
        let reality =
            js(&o, &["tls", "reality", "enabled"]).and_then(|x| x.as_bool()) == Some(true);
        b.param(
            "security",
            if reality {
                "reality"
            } else if tls {
                "tls"
            } else {
                "none"
            },
        );
        b.param("sni", js_str(&o, &["tls", "server_name"]));
        b.param("fp", js_str(&o, &["tls", "utls", "fingerprint"]));
        b.param("pbk", js_str(&o, &["tls", "reality", "public_key"]));
        b.param("sid", js_str(&o, &["tls", "reality", "short_id"]));
        if let Some(alpn) = js(&o, &["tls", "alpn"]).and_then(|a| a.as_array()) {
            let a: Vec<&str> = alpn.iter().filter_map(|x| x.as_str()).collect();
            b.param("alpn", a.join(","));
        }
        let transport = js_str(&o, &["transport", "type"]);
        match transport.as_str() {
            "" => b.param("type", "tcp"),
            "ws" | "httpupgrade" => {
                b.param("type", transport.as_str());
                b.param("path", js_str(&o, &["transport", "path"]));
                let host = js_str(&o, &["transport", "headers", "Host"]);
                let host = if host.is_empty() {
                    js_str(&o, &["transport", "host"])
                } else {
                    host
                };
                b.param("host", host);
            }
            "grpc" => {
                b.param("type", "grpc");
                b.param("serviceName", js_str(&o, &["transport", "service_name"]));
            }
            other => {
                *out.skipped.entry(format!("vless+{other}")).or_default() += 1;
                continue;
            }
        }
        if b.name.is_empty() {
            b.name = format!("{}:{}", b.host, b.port);
        }
        let name = b.name.clone();
        out.push_server(scheme, name, b.build());
    }
    Ok(())
}

/// YAML Clash: supported `proxies` records.
fn parse_clash(text: &str, out: &mut NormalizedSubscription) -> Result<()> {
    let v: serde_json::Value = yaml_serde::from_str(text)
        .map_err(|e| Error::Config(format!("подписка: YAML Clash: {e}")))?;
    let list = v
        .get("proxies")
        .and_then(|o| o.as_array())
        .cloned()
        .unwrap_or_default();
    for p in list {
        let ty = js_str(&p, &["type"]);
        if ty == "ss" || ty == "shadowsocks" {
            let unsupported = ["plugin", "plugin-opts", "udp-over-tcp"];
            if unsupported.iter().any(|key| {
                p.get(*key).is_some_and(|v| {
                    !v.is_null() && v.as_bool() != Some(false) && v.as_str() != Some("")
                })
            }) || p.get("udp").and_then(|v| v.as_bool()) == Some(false)
            {
                *out.skipped
                    .entry("shadowsocks (unsupported Clash options)".into())
                    .or_default() += 1;
                continue;
            }
            let server = js_str(&p, &["server"]);
            let port = port_of(js(&p, &["port"]));
            let method = js_str(&p, &["cipher"]);
            let password = js_str(&p, &["password"]);
            let Some(port) = port else {
                out.invalid += 1;
                continue;
            };
            match crate::shadowsocks_protocol::uri_from_fields(&server, port, &method, &password) {
                Ok(link) => {
                    let name = js_str(&p, &["name"]);
                    out.servers.push(NormalizedServer {
                        protocol: NormalizedProtocol::Shadowsocks,
                        name: if name.is_empty() {
                            format!("{server}:{port}")
                        } else {
                            name
                        },
                        link,
                    });
                }
                Err(_) => out.invalid += 1,
            }
            continue;
        }
        let scheme = match ty.as_str() {
            "vless" => "vless",
            "trojan" => "trojan",
            _ => {
                *out.skipped.entry(ty).or_default() += 1;
                continue;
            }
        };
        let Some(port) = port_of(js(&p, &["port"])) else {
            out.invalid += 1;
            continue;
        };
        let mut b = LinkBuilder {
            scheme,
            uuid: if scheme == "trojan" {
                js_str(&p, &["password"])
            } else {
                js_str(&p, &["uuid"])
            },
            host: js_str(&p, &["server"]),
            port,
            params: Vec::new(),
            name: js_str(&p, &["name"]),
        };
        b.param("flow", js_str(&p, &["flow"]));
        // У trojan в Clash TLS включён всегда; имя — `sni`.
        let tls = scheme == "trojan" || js(&p, &["tls"]).and_then(|x| x.as_bool()) == Some(true);
        b.param("sni", js_str(&p, &["sni"]));
        let reality = js(&p, &["reality-opts"]).is_some();
        b.param(
            "security",
            if reality {
                "reality"
            } else if tls {
                "tls"
            } else {
                "none"
            },
        );
        b.param("sni", js_str(&p, &["servername"]));
        b.param("fp", js_str(&p, &["client-fingerprint"]));
        b.param("pbk", js_str(&p, &["reality-opts", "public-key"]));
        b.param("sid", js_str(&p, &["reality-opts", "short-id"]));
        let network = js_str(&p, &["network"]);
        match network.as_str() {
            "" | "tcp" => b.param("type", "tcp"),
            "ws" => {
                b.param("type", "ws");
                b.param("path", js_str(&p, &["ws-opts", "path"]));
                b.param("host", js_str(&p, &["ws-opts", "headers", "Host"]));
            }
            "grpc" => {
                b.param("type", "grpc");
                b.param(
                    "serviceName",
                    js_str(&p, &["grpc-opts", "grpc-service-name"]),
                );
            }
            other => {
                *out.skipped.entry(format!("vless+{other}")).or_default() += 1;
                continue;
            }
        }
        if b.name.is_empty() {
            b.name = format!("{}:{}", b.host, b.port);
        }
        let name = b.name.clone();
        out.push_server(scheme, name, b.build());
    }
    Ok(())
}

/// Разобрать ответ панели в любом из форматов.
pub(super) fn parse_typed(body: &[u8]) -> Result<NormalizedSubscription> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim().trim_start_matches('\u{feff}');
    let mut out = NormalizedSubscription::default();
    if text.starts_with('{') {
        parse_singbox(text, &mut out)?;
    } else if text.contains("proxies:") {
        parse_clash(text, &mut out)?;
    } else if text.contains("://") {
        parse_lines(text, &mut out);
    } else if let Some(decoded) = decode_base64(text) {
        parse_lines(&decoded, &mut out);
    } else {
        return Err(Error::Config(
            "подписка: ответ не похож ни на список ссылок, ни на base64, ни на JSON/YAML".into(),
        ));
    }
    // Имя задаёт панель, и оно попадает в tag выхода, а с ним — в журнал и
    // API: без управляющих символов (`\n` подделывал бы строки журнала).
    // Одинаковые имена — с номером, чтобы tag серверов были разными.
    let mut seen: HashMap<String, usize> = HashMap::new();
    for server in &mut out.servers {
        server.name.retain(|c| !c.is_control());
        if server.name.is_empty() {
            server.name = "server".into();
        }
        let n = seen.entry(server.name.clone()).or_default();
        *n += 1;
        if *n > 1 {
            server.name = format!("{} ({n})", server.name);
        }
    }
    Ok(out)
}

/// Public compatibility view; subscription application uses the typed model.
pub fn parse(body: &[u8]) -> Result<Parsed> {
    let parsed = parse_typed(body)?;
    Ok(Parsed {
        servers: parsed
            .servers
            .into_iter()
            .map(|server| (server.name, server.link))
            .collect(),
        skipped: parsed.skipped,
        invalid: parsed.invalid,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_typed, NormalizedProtocol};

    #[test]
    fn normalizes_supported_protocols_to_typed_servers() {
        let body = b"vless://uuid@vless.example:443#VLESS\ntrojan://pass@trojan.example:443#Trojan";
        let parsed = parse_typed(body).unwrap();

        assert_eq!(parsed.servers.len(), 2);
        assert_eq!(parsed.servers[0].protocol, NormalizedProtocol::Vless);
        assert_eq!(parsed.servers[0].name, "VLESS");
        assert_eq!(parsed.servers[1].protocol, NormalizedProtocol::Trojan);
        assert_eq!(parsed.servers[1].name, "Trojan");
    }

    #[test]
    fn imports_classic_shadowsocks_from_sip002_singbox_and_clash() {
        let sip002 = b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@ss.example:8388#node";
        let parsed = parse_typed(sip002).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].protocol, NormalizedProtocol::Shadowsocks);
        let config = shadowsocks::config::ServerConfig::from_url(&parsed.servers[0].link).unwrap();
        assert_eq!(config.method().to_string(), "aes-256-gcm");

        let singbox = br#"{"outbounds":[{"type":"shadowsocks","tag":"ss","server":"ss.example","server_port":8388,"method":"chacha20-ietf-poly1305","password":"password"}]}"#;
        let parsed = parse_typed(singbox).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].protocol, NormalizedProtocol::Shadowsocks);

        let clash = br#"proxies:
  - {name: ss, type: ss, server: ss.example, port: 8388, cipher: aes-128-gcm, password: password}
"#;
        let parsed = parse_typed(clash).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].protocol, NormalizedProtocol::Shadowsocks);
    }

    #[test]
    fn skips_classic_shadowsocks_records_with_unimplemented_extensions() {
        let singbox = br#"{"outbounds":[{"type":"shadowsocks","tag":"ss","server":"ss.example","server_port":8388,"method":"aes-256-gcm","password":"password","plugin":"v2ray-plugin"}]}"#;
        let parsed = parse_typed(singbox).unwrap();
        assert!(parsed.servers.is_empty());
        assert_eq!(
            parsed.skipped["shadowsocks (unsupported sing-box options)"],
            1
        );
    }

    #[test]
    fn parses_hysteria2_uri_lists_and_singbox_subset_without_losing_secrets() {
        let uri = b"hy2://user%2Btag%3Asecret@[2001:db8::1]:2080,3000-3010/?sni=edge.example&obfs=salamander&obfs-password=cloak#node";
        let parsed = parse_typed(uri).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].protocol, NormalizedProtocol::Hysteria2);
        let config = crate::hysteria2::Hysteria2Config::parse(&parsed.servers[0].link).unwrap();
        assert_eq!(config.server, "2001:db8::1");
        assert_eq!(config.auth.as_deref(), Some("user+tag:secret"));
        assert_eq!(config.ports.len(), 2);
        assert_eq!(config.name.as_deref(), Some("node"));

        let json = br#"{"outbounds":[{"type":"hysteria2","tag":"hy2","server":"2001:db8::1","server_ports":["2080","3000:3010"],"password":"p+ass","obfs":{"type":"salamander","password":"cloak"},"tls":{"server_name":"edge.example","insecure":true}}]}"#;
        let parsed = parse_typed(json).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].protocol, NormalizedProtocol::Hysteria2);
        let config = crate::hysteria2::Hysteria2Config::parse(&parsed.servers[0].link).unwrap();
        assert_eq!(config.server, "2001:db8::1");
        assert_eq!(config.auth.as_deref(), Some("p+ass"));
        assert!(config.insecure);
        assert_eq!(config.ports.len(), 2);
    }

    #[test]
    fn rejects_unrepresentable_hysteria2_options_and_preserves_uri_boundary() {
        let json = br#"{"outbounds":[{"type":"hysteria2","tag":"hy2","server":"example.com","server_port":443,"password":"secret","up_mbps":100}]}"#;
        let parsed = parse_typed(json).unwrap();
        assert!(parsed.servers.is_empty());
        assert_eq!(
            parsed
                .skipped
                .get("hysteria2 (unsupported sing-box options)"),
            Some(&1)
        );

        let body = b"hy2://secret@example.com:443#node";
        let parsed = parse_typed(body).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].protocol.as_str(), "hysteria2");

        let invalid = parse_typed(b"hy2://secret@example.com:bad#node").unwrap();
        assert!(invalid.servers.is_empty());
        assert_eq!(invalid.invalid, 1);

        let custom_ca = parse_typed(
            br#"{"outbounds":[{"type":"hysteria2","tag":"hy2","server":"example.com","server_port":443,"password":"secret","tls":{},"ca_file":"root.pem"}]}"#,
        )
        .unwrap();
        assert!(custom_ca.servers.is_empty());
        assert_eq!(
            custom_ca
                .skipped
                .get("hysteria2 (unsupported sing-box options)"),
            Some(&1)
        );
    }

    #[test]
    fn subscription_debug_output_redacts_hysteria2_credentials() {
        let parsed = parse_typed(
            b"hy2://uri-secret@example.com:443?obfs=salamander&obfs-password=obfs-secret#node",
        )
        .unwrap();
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("uri-secret"), "{debug}");
        assert!(!debug.contains("obfs-secret"), "{debug}");
        assert!(debug.contains("***"), "{debug}");

        let public = super::parse(
            b"hy2://uri-secret@example.com:443?obfs=salamander&obfs-password=obfs-secret#node",
        )
        .unwrap();
        let debug = format!("{public:?}");
        assert!(!debug.contains("uri-secret"), "{debug}");
        assert!(!debug.contains("obfs-secret"), "{debug}");
    }
}
