// SPDX-License-Identifier: GPL-3.0-or-later
//! VMess client configuration primitives.
//!
//! This module currently validates modern VMess share links and converts
//! their transport fields into the shared transport configuration. It does
//! not by itself provide a VMess outbound; protocol framing is tracked in
//! `docs/VMESS_IMPLEMENTATION_PLAN.md`.

use std::fmt;

use base64::Engine as _;
use serde_json::Value;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::transport::TransportConfig;

/// Data protection used by modern VMess AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
}

impl Cipher {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            other => Err(Error::InvalidUri(format!(
                "VMess: защита данных '{other}' не поддерживается современным AEAD"
            ))),
        }
    }
}

/// Validated modern `vmess://` link. Credentials are redacted in `Debug`.
#[derive(Clone)]
pub struct VmessConfig {
    pub id: Uuid,
    pub alter_id: u16,
    pub cipher: Cipher,
    pub transport: TransportConfig,
    pub name: Option<String>,
}

impl fmt::Debug for VmessConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmessConfig")
            .field("id", &crate::redact::Redacted)
            .field("alter_id", &self.alter_id)
            .field("cipher", &self.cipher)
            .field("transport", &self.transport)
            .field("name", &self.name)
            .finish()
    }
}

impl VmessConfig {
    /// Parse the base64-encoded JSON form used by Xray/V2Ray share links.
    /// Legacy `alterId` accounts and non-AEAD ciphers are rejected explicitly.
    pub fn parse(link: &str) -> Result<Self> {
        let invalid = |message: String| Error::InvalidUri(format!("VMess: {message}"));
        let encoded = link
            .trim()
            .strip_prefix("vmess://")
            .ok_or_else(|| invalid("ожидалась ссылка vmess://".into()))?;
        if encoded.is_empty() || encoded.chars().any(|ch| matches!(ch, '?' | '#' | '@')) {
            return Err(invalid("ожидались только base64-данные JSON ссылки".into()));
        }
        if encoded.len() > 64 * 1024 {
            return Err(invalid(
                "base64-данные ссылки превышают лимит 64 КиБ".into(),
            ));
        }

        let json = decode_link(encoded).map_err(invalid)?;
        if json.len() > 48 * 1024 {
            return Err(invalid(
                "декодированные данные ссылки превышают лимит 48 КиБ".into(),
            ));
        }
        let value: Value = serde_json::from_slice(&json)
            .map_err(|e| invalid(format!("некорректный JSON в ссылке: {e}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| invalid("корень JSON должен быть объектом".into()))?;

        let field =
            |names: &[&str]| -> Option<&Value> { names.iter().find_map(|name| object.get(*name)) };
        let text = |names: &[&str], default: &str| -> Result<String> {
            match field(names) {
                None | Some(Value::Null) => Ok(default.to_owned()),
                Some(Value::String(value)) => Ok(value.trim().to_owned()),
                Some(Value::Number(value)) => Ok(value.to_string()),
                Some(_) => Err(invalid(format!("поле '{}' должно быть строкой", names[0]))),
            }
        };

        if let Some(version) = object.get("v") {
            let supported = version.as_str() == Some("2") || version.as_u64() == Some(2);
            if !supported {
                let version = version.to_string();
                return Err(invalid(format!(
                    "формат share link версии '{version}' не поддерживается (ожидается v=2)"
                )));
            }
        }

        let id = Uuid::parse_str(&text(&["id"], "")?)
            .map_err(|_| invalid("поле 'id' должно содержать UUID".into()))?;
        let server = text(&["add", "address"], "")?;
        if server.is_empty() || server.len() > 255 || server.chars().any(char::is_control) {
            return Err(invalid("не задан корректный адрес сервера 'add'".into()));
        }
        let port = text(&["port"], "")?
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| invalid("поле 'port' должно быть числом от 1 до 65535".into()))?;
        let alter_id = text(&["aid", "alterId"], "0")?
            .parse::<u16>()
            .map_err(|_| invalid("поле 'aid' должно быть числом от 0 до 65535".into()))?;
        if alter_id != 0 {
            return Err(invalid(format!(
                "aid={alter_id} относится к устаревшим alterId-учётным данным; требуется aid=0"
            )));
        }
        let cipher = Cipher::parse(&text(&["scy"], "auto")?)?;

        let network = normalize_network(&text(&["net"], "tcp")?).map_err(invalid)?;
        let path = text(&["path"], "")?;
        let service_name = text(&["serviceName"], "")?;
        if network == "grpc" && !path.is_empty() && !service_name.is_empty() && path != service_name
        {
            return Err(invalid(
                "поля path и serviceName для gRPC противоречат друг другу".into(),
            ));
        }
        if let Some(extra) = field(&["extra"]) {
            if network != "xhttp"
                && !extra.is_null()
                && extra.as_object().is_none_or(|v| !v.is_empty())
            {
                return Err(invalid(
                    "поле extra поддерживается только для транспорта xhttp".into(),
                ));
            }
        }
        let header_type = text(&["type", "headerType"], "none")?;
        if !header_type.is_empty() && !header_type.eq_ignore_ascii_case("none") {
            return Err(invalid(format!(
                "TCP header type '{header_type}' не поддерживается"
            )));
        }
        let tls = text(&["tls"], "")?;
        let security = match tls.to_ascii_lowercase().as_str() {
            "" | "none" => "none",
            "tls" => "tls",
            "reality" => "reality",
            other => {
                return Err(invalid(format!(
                    "неподдерживаемая защита транспорта '{other}'"
                )))
            }
        };

        // Reuse the common transport parser and its validation rather than
        // maintaining a second interpretation of TLS/REALITY and transports.
        // Use the protocol's own non-special URL scheme so `url` does not
        // normalize the default HTTPS port 443 away before shared parsing.
        let url_text = format!("vmess://{}:{}", bracket_host(&server), port);
        let mut url = url::Url::parse(&url_text)
            .map_err(|e| invalid(format!("некорректный адрес сервера: {e}")))?;
        if url
            .host_str()
            .is_none_or(|host| !host.eq_ignore_ascii_case(&server))
            || url.port() != Some(port)
            || !(url.path().is_empty() || url.path() == "/")
        {
            return Err(invalid("некорректный адрес или порт сервера".into()));
        }
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("security", security);
            query.append_pair("type", network);
            for (source, target) in [
                ("sni", "sni"),
                ("fp", "fp"),
                ("host", "host"),
                ("serviceName", "serviceName"),
                ("mode", "mode"),
                ("alpn", "alpn"),
                ("pbk", "pbk"),
                ("sid", "sid"),
                ("pqv", "pqv"),
            ] {
                let value = if source == "host" {
                    field(&["host", "hostHeader"])
                } else if source == "path" {
                    field(&["path"])
                } else {
                    field(&[source])
                };
                if let Some(value) = value {
                    let value = value
                        .as_str()
                        .map(str::trim)
                        .ok_or_else(|| invalid(format!("поле '{source}' должно быть строкой")))?;
                    if !value.is_empty() {
                        query.append_pair(target, value);
                    }
                }
            }
            if !path.is_empty() {
                // Xray VMess share links store gRPC's service name in
                // `path`; the shared transport uses an explicit key.
                let target = if network == "grpc" {
                    "serviceName"
                } else {
                    "path"
                };
                query.append_pair(target, &path);
            }
            if let Some(extra) = field(&["extra"]) {
                let extra = serde_json::to_string(extra)
                    .map_err(|e| invalid(format!("некорректное поле extra: {e}")))?;
                query.append_pair("extra", &extra);
            }
        }
        let transport = TransportConfig::from_url(&url)?;
        transport.validate()?;

        let name = text(&["ps", "name"], "")?;
        if name.chars().any(char::is_control) {
            return Err(invalid("имя узла содержит управляющие символы".into()));
        }
        Ok(Self {
            id,
            alter_id,
            cipher,
            transport,
            name: (!name.is_empty()).then_some(name),
        })
    }
}

fn decode_link(encoded: &str) -> std::result::Result<Vec<u8>, String> {
    let encoded = encoded.trim();
    let mut failures = Vec::new();
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        match engine.decode(encoded) {
            Ok(bytes) => return Ok(bytes),
            Err(error) => failures.push(error.to_string()),
        }
    }
    Err(format!(
        "не удалось декодировать base64: {}",
        failures.join("; ")
    ))
}

fn normalize_network(value: &str) -> std::result::Result<&'static str, String> {
    match value.to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => Ok("tcp"),
        "ws" => Ok("ws"),
        "grpc" | "gun" => Ok("grpc"),
        "httpupgrade" => Ok("httpupgrade"),
        "xhttp" | "splithttp" => Ok("xhttp"),
        "kcp" | "mkcp" => Err("транспорт mKCP/UDP не поддерживается клиентом".into()),
        other => Err(format!("транспорт '{other}' не поддерживается клиентом")),
    }
}

fn bracket_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(value: Value) -> String {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&value).expect("fixture JSON is serializable"));
        format!("vmess://{encoded}")
    }

    fn valid() -> Value {
        serde_json::json!({
            "v": "2", "ps": "example", "add": "proxy.example", "port": "443",
            "id": "a8098c1a-f86e-11da-bd1a-00112444be1e", "aid": "0", "scy": "auto",
            "net": "ws", "host": "cdn.example", "path": "/vmess", "tls": "tls",
            "sni": "edge.example", "fp": "chrome"
        })
    }

    #[test]
    fn parses_modern_vmess_ws_tls_link() {
        let config = VmessConfig::parse(&link(valid())).expect("modern link parses");
        assert_eq!(config.cipher, Cipher::Auto);
        assert_eq!(config.alter_id, 0);
        assert_eq!(config.transport.host, "proxy.example");
        assert_eq!(config.transport.network, NetworkType::Ws);
        assert_eq!(config.transport.security, crate::transport::Security::Tls);
        assert_eq!(
            config.transport.raw_params.get("host").map(String::as_str),
            Some("cdn.example")
        );
        assert_eq!(
            config.transport.raw_params.get("path").map(String::as_str),
            Some("/vmess")
        );
        assert_eq!(config.transport.sni.as_deref(), Some("edge.example"));
        assert_eq!(config.name.as_deref(), Some("example"));
    }

    #[test]
    fn rejects_legacy_alter_ids_and_ciphers() {
        let mut value = valid();
        value["aid"] = Value::String("16".into());
        assert!(VmessConfig::parse(&link(value))
            .unwrap_err()
            .to_string()
            .contains("aid=16"));

        let mut value = valid();
        value["scy"] = Value::String("aes-128-cfb".into());
        assert!(VmessConfig::parse(&link(value))
            .unwrap_err()
            .to_string()
            .contains("AEAD"));
    }

    #[test]
    fn rejects_unsupported_transport_and_bad_server_data() {
        let mut value = valid();
        value["net"] = Value::String("kcp".into());
        assert!(VmessConfig::parse(&link(value)).is_err());

        let mut value = valid();
        value["port"] = Value::String("0".into());
        assert!(VmessConfig::parse(&link(value)).is_err());
    }

    #[test]
    fn maps_grpc_path_to_shared_service_name() {
        let mut value = valid();
        value["net"] = Value::String("grpc".into());
        value["path"] = Value::String("service".into());
        let config = VmessConfig::parse(&link(value)).expect("gRPC link parses");
        assert_eq!(config.transport.network, NetworkType::Grpc);
        assert_eq!(config.transport.service_name(), "service");
    }

    #[test]
    fn accepts_unpadded_url_safe_base64() {
        let json = serde_json::to_vec(&valid()).expect("fixture JSON is serializable");
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let config = VmessConfig::parse(&format!("vmess://{encoded}"))
            .expect("URL-safe unpadded link parses");
        assert_eq!(config.transport.network, NetworkType::Ws);
    }
}
