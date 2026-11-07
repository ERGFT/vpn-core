// SPDX-License-Identifier: GPL-3.0-or-later
//! Параметры общих нижележащих транспортов. Здесь нет UUID, credentials
//! или других типизированных полей, принадлежащих отдельному протоколу.

use std::collections::HashMap;

use crate::error::{Error, Result};
use base64::Engine as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Tcp,
    Ws,
    Grpc,
    HttpUpgrade,
    Xhttp,
}

impl NetworkType {
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s {
            "" | "tcp" | "raw" => Ok(Self::Tcp),
            "ws" => Ok(Self::Ws),
            "grpc" | "gun" => Ok(Self::Grpc),
            "httpupgrade" => Ok(Self::HttpUpgrade),
            "xhttp" | "splithttp" => Ok(Self::Xhttp),
            "quic" | "h2" | "http" | "h3" => Err(Error::InvalidUri(format!(
                "транспорт type={s} удалён из Xray-core; его заменяет type=xhttp"
            ))),
            "kcp" | "mkcp" => Err(Error::InvalidUri(
                "транспорт type=kcp (mKCP, UDP) не поддерживается этим клиентом".into(),
            )),
            other => Err(Error::InvalidUri(format!(
                "транспорт type={other} не поддерживается (поддерживаются: tcp, ws, grpc, httpupgrade, xhttp)"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    None,
    Tls,
    Reality,
}

impl Security {
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s {
            "" | "none" => Ok(Self::None),
            "tls" => Ok(Self::Tls),
            "reality" => Ok(Self::Reality),
            other => Err(Error::InvalidUri(format!(
                "security={other} не поддерживается (поддерживаются: none, tls, reality)"
            ))),
        }
    }
}

/// Настройки соединения с сервером, общие для VLESS, Trojan и других
/// протоколов, которым подходят уже реализованные транспорты.
#[derive(Clone)]
pub struct TransportConfig {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    pub network: NetworkType,
    pub raw_params: HashMap<String, String>,
    pub ca_roots: Option<std::sync::Arc<rustls::RootCertStore>>,
    pub fragment: Option<std::sync::Arc<crate::transport::fragment::Fragment>>,
    pub browser: crate::fingerprint::Browser,
}

impl std::fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut params: Vec<&String> = self.raw_params.keys().collect();
        params.sort();
        f.debug_struct("TransportConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("security", &self.security)
            .field("sni", &self.sni)
            .field("fingerprint", &self.fingerprint)
            .field("network", &self.network)
            .field("raw_params", &params)
            .field("ca_roots", &self.ca_roots.as_ref().map(|r| r.len()))
            .field("fragment", &self.fragment)
            .field("browser", &self.browser)
            .finish()
    }
}

impl TransportConfig {
    /// Разобрать общие параметры сервера из URL любого протокола.
    pub(crate) fn from_url(url: &url::Url) -> Result<Self> {
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidUri("отсутствует host".into()))?
            .to_string();
        let port = url
            .port()
            .ok_or_else(|| Error::InvalidUri("отсутствует port".into()))?;
        let mut raw_params = HashMap::new();
        for (key, value) in url.query_pairs() {
            let key = key.into_owned();
            if matches!(key.as_str(), "flow" | "encryption") {
                continue;
            }
            raw_params.insert(key, value.into_owned());
        }
        if let Some(header_type) = raw_params.get("headerType") {
            if !header_type.is_empty() && header_type != "none" {
                return Err(Error::InvalidUri(format!(
                    "headerType={header_type} не поддерживается (только none)"
                )));
            }
        }
        let security = match raw_params.get("security") {
            Some(value) => Security::parse(value)?,
            None => Security::None,
        };
        let network = match raw_params.get("type") {
            Some(value) => NetworkType::parse(value)?,
            None => NetworkType::Tcp,
        };
        let sni = raw_params.get("sni").cloned();
        let fingerprint = raw_params.get("fp").cloned();
        let browser = crate::fingerprint::Browser::from_fp(fingerprint.as_deref()).0;
        Ok(Self {
            host,
            port,
            security,
            sni,
            fingerprint,
            network,
            raw_params,
            ca_roots: None,
            fragment: None,
            browser,
        })
    }

    pub fn pool_key(&self) -> String {
        let mut params: Vec<(&String, &String)> = self.raw_params.iter().collect();
        params.sort();
        format!(
            "{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            self.host,
            self.port,
            self.security,
            self.network,
            self.sni,
            params,
            self.ca_roots.as_ref().map(std::sync::Arc::as_ptr),
            self.fragment,
            self.browser,
        )
    }

    pub fn alpn(&self) -> Option<Vec<Vec<u8>>> {
        let value = self.raw_params.get("alpn")?;
        let list: Vec<Vec<u8>> = value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes().to_vec())
            .collect();
        (!list.is_empty()).then_some(list)
    }

    pub fn http_path(&self) -> String {
        let raw = self.path();
        let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
        let mut path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let rest: Vec<&str> = query
            .split('&')
            .filter(|kv| !kv.is_empty() && kv.split('=').next() != Some("ed"))
            .collect();
        if !rest.is_empty() {
            path.push('?');
            path.push_str(&rest.join("&"));
        }
        path
    }

    pub fn ws_host(&self) -> &str {
        match self.raw_params.get("host") {
            Some(host) if !host.is_empty() => host,
            _ => self.effective_sni(),
        }
    }

    pub fn effective_sni(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
    }

    pub fn tls_server_name(&self) -> &str {
        let name = self.effective_sni();
        name.strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(name)
    }

    pub fn path(&self) -> &str {
        self.raw_params
            .get("path")
            .map(String::as_str)
            .unwrap_or("/")
    }

    pub fn service_name(&self) -> &str {
        self.raw_params
            .get("serviceName")
            .map(String::as_str)
            .unwrap_or("")
    }

    pub fn reality_params(&self) -> Result<RealityParams> {
        Self::reality_params_from(&self.raw_params)
    }

    pub(crate) fn reality_params_from(
        raw_params: &HashMap<String, String>,
    ) -> Result<RealityParams> {
        let pbk_str = raw_params
            .get("pbk")
            .ok_or_else(|| Error::InvalidUri("security=reality, но в ссылке нет pbk=".into()))?;
        let pbk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(pbk_str.trim_end_matches('='))
            .map_err(|e| Error::InvalidUri(format!("pbk= не является base64url: {e}")))?;
        if pbk_bytes.len() != 32 {
            return Err(Error::InvalidUri(format!(
                "pbk= должен декодироваться в 32 байта (X25519-ключ), получено {}",
                pbk_bytes.len()
            )));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&pbk_bytes);
        let probe = x25519_dalek::StaticSecret::random_from_rng(&mut rand::rand_core::UnwrapErr(
            rand::rngs::SysRng,
        ))
        .diffie_hellman(&x25519_dalek::PublicKey::from(public_key));
        if !probe.was_contributory() {
            return Err(Error::InvalidUri(
                "pbk= — вырожденный ключ X25519 (точка малого порядка), такой ключ небезопасен"
                    .into(),
            ));
        }
        let short_id = match raw_params.get("sid") {
            Some(value) if !value.is_empty() => hex::decode(value)
                .map_err(|e| Error::InvalidUri(format!("sid= не является hex: {e}")))?,
            _ => Vec::new(),
        };
        if short_id.len() > crate::reality::SHORT_ID_LEN {
            return Err(Error::InvalidUri(format!(
                "sid= длиннее {} байт: {}",
                crate::reality::SHORT_ID_LEN,
                short_id.len()
            )));
        }
        let mldsa65_verify = match raw_params.get("pqv") {
            Some(value) if !value.is_empty() => {
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(value.trim_end_matches('='))
                    .map_err(|e| Error::InvalidUri(format!("pqv= не является base64url: {e}")))?;
                if bytes.len() != crate::reality::MLDSA65_PUBLIC_KEY_LEN {
                    return Err(Error::InvalidUri(format!(
                        "pqv= должен декодироваться в {} байт (ключ ML-DSA-65), получено {}",
                        crate::reality::MLDSA65_PUBLIC_KEY_LEN,
                        bytes.len()
                    )));
                }
                Some(bytes)
            }
            _ => None,
        };
        Ok(RealityParams {
            public_key,
            short_id,
            mldsa65_verify,
        })
    }
}

#[derive(Clone)]
pub struct RealityParams {
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub mldsa65_verify: Option<Vec<u8>>,
}

impl std::fmt::Debug for RealityParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityParams")
            .field("public_key", &crate::redact::Redacted)
            .field("short_id", &crate::redact::Redacted)
            .field("mldsa65_verify", &crate::redact::opt(&self.mldsa65_verify))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_shared_transport_settings_without_protocol_fields() {
        let url = url::Url::parse(
            "trojan://credential@edge.example:443?security=tls&type=grpc&sni=front.example&flow=none&encryption=none",
        )
        .unwrap();
        let cfg = TransportConfig::from_url(&url).unwrap();

        assert_eq!(cfg.host, "edge.example");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.security, Security::Tls);
        assert_eq!(cfg.network, NetworkType::Grpc);
        assert_eq!(cfg.effective_sni(), "front.example");
        assert!(!cfg.raw_params.contains_key("flow"));
        assert!(!cfg.raw_params.contains_key("encryption"));
        assert!(!format!("{cfg:?}").contains("credential"));
    }
}
