// SPDX-License-Identifier: GPL-3.0-or-later
//! Strict helpers for the classic Shadowsocks AEAD profile.
//!
//! SIP022 / AEAD-2022 is intentionally excluded here and is implemented as a
//! separate protocol mode so key encoding and replay protection cannot be
//! accidentally mixed with the classic password-derived keys.

use std::str::FromStr;

use crate::error::{Error, Result};

/// Enforce the classic protocol's modern AEAD-only profile and reject
/// optional plugin layers until their process and UDP semantics are wired in.
pub(crate) fn validate_classic(config: &shadowsocks::config::ServerConfig) -> Result<()> {
    if config.plugin().is_some() {
        return Err(Error::Config(
            "shadowsocks: SIP003 plugins are not implemented".into(),
        ));
    }
    let method = config.method().to_string();
    if !matches!(
        method.as_str(),
        "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
    ) {
        return Err(Error::Config(format!(
            "shadowsocks: method «{method}» is deprecated or belongs to Shadowsocks 2022"
        )));
    }
    Ok(())
}

/// Build the canonical SIP002 URI for a sing-box/Xray server record.
pub(crate) fn uri_from_fields(
    server: &str,
    port: u16,
    method: &str,
    password: &str,
) -> Result<String> {
    if server.trim().is_empty() || server.trim() != server || server.chars().any(char::is_control) {
        return Err(Error::Config("shadowsocks: некорректный server".into()));
    }
    if port == 0 {
        return Err(Error::Config(
            "shadowsocks: server_port должен быть от 1 до 65535".into(),
        ));
    }
    if password.is_empty() || password.chars().any(char::is_control) {
        return Err(Error::Config(
            "shadowsocks: password пуст или содержит управляющие символы".into(),
        ));
    }

    let method = match method {
        "chacha20-poly1305" => "chacha20-ietf-poly1305",
        other => other,
    };
    let cipher = shadowsocks::crypto::CipherKind::from_str(method).map_err(|_| {
        Error::Config(format!(
            "shadowsocks: неподдерживаемый метод шифрования «{method}»"
        ))
    })?;
    let canonical_method = cipher.to_string();
    if !matches!(
        canonical_method.as_str(),
        "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
    ) {
        return Err(Error::Config(format!(
            "shadowsocks: метод «{canonical_method}» устарел или относится к Shadowsocks 2022; поддерживаются только aes-128-gcm, aes-256-gcm и chacha20-ietf-poly1305"
        )));
    }

    let config =
        shadowsocks::config::ServerConfig::new((server.to_owned(), port), password, cipher)
            .map_err(|error| {
                Error::Config(format!("shadowsocks: неверный ключ или пароль: {error}"))
            })?;
    Ok(config.to_url())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singbox_fields_create_classic_aeAD_uri() {
        let uri = uri_from_fields("ss.example", 8388, "chacha20-ietf-poly1305", "p@ss").unwrap();
        let parsed = shadowsocks::config::ServerConfig::from_url(&uri).unwrap();
        assert_eq!(parsed.addr().to_string(), "ss.example:8388");
        assert_eq!(parsed.password(), "p@ss");
        assert_eq!(parsed.method().to_string(), "chacha20-ietf-poly1305");
    }

    #[test]
    fn classic_shadowsocks_rejects_legacy_and_2022_methods() {
        for method in ["aes-256-cfb", "2022-blake3-aes-128-gcm", "none"] {
            assert!(
                uri_from_fields("ss.example", 8388, method, "secret").is_err(),
                "{method}"
            );
        }
    }
}
