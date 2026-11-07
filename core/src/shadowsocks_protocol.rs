// SPDX-License-Identifier: GPL-3.0-or-later
//! Strict helpers for the classic and SIP022 Shadowsocks AEAD profiles.
//!
//! SIP022 / AEAD-2022 has a separate method allowlist; its base64 PSKs are
//! validated by the reference crate and never treated as classic passwords.

use std::str::FromStr;

use crate::error::{Error, Result};

pub(crate) fn validate_supported(config: &shadowsocks::config::ServerConfig) -> Result<()> {
    validate_plugin(config)?;
    let method = config.method().to_string();
    if matches!(
        method.as_str(),
        "aes-128-gcm"
            | "aes-256-gcm"
            | "chacha20-ietf-poly1305"
            | "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
    ) {
        return Ok(());
    }
    Err(Error::Config(format!(
        "shadowsocks: unsupported or deprecated cipher method «{method}»"
    )))
}

fn validate_plugin(config: &shadowsocks::config::ServerConfig) -> Result<()> {
    if config.plugin().is_some() {
        return Err(Error::Config(
            "shadowsocks: SIP003 plugins are not implemented".into(),
        ));
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
        "aes-128-gcm"
            | "aes-256-gcm"
            | "chacha20-ietf-poly1305"
            | "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
    ) {
        return Err(Error::Config(format!(
            "shadowsocks: неподдерживаемый или устаревший метод шифрования «{canonical_method}»"
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
    fn singbox_fields_create_classic_aead_uri() {
        let uri = uri_from_fields("ss.example", 8388, "chacha20-ietf-poly1305", "p@ss").unwrap();
        let parsed = shadowsocks::config::ServerConfig::from_url(&uri).unwrap();
        assert_eq!(parsed.addr().to_string(), "ss.example:8388");
        assert_eq!(parsed.password(), "p@ss");
        assert_eq!(parsed.method().to_string(), "chacha20-ietf-poly1305");
    }

    #[test]
    fn supported_shadowsocks_rejects_legacy_methods() {
        for method in ["aes-256-cfb", "none"] {
            assert!(
                uri_from_fields("ss.example", 8388, method, "secret").is_err(),
                "{method}"
            );
        }
    }

    #[test]
    fn sip022_accepts_valid_psks_and_rejects_wrong_key_lengths() {
        for (method, psk) in [
            ("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA=="),
            (
                "2022-blake3-aes-256-gcm",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
        ] {
            let uri = uri_from_fields("ss.example", 8388, method, psk).unwrap();
            let parsed = shadowsocks::config::ServerConfig::from_url(&uri).unwrap();
            assert_eq!(parsed.method().to_string(), method);
            validate_supported(&parsed).unwrap();
        }
        assert!(
            uri_from_fields("ss.example", 8388, "2022-blake3-aes-128-gcm", "c2hvcnQ=").is_err()
        );
        assert!(uri_from_fields(
            "ss.example",
            8388,
            "2022-blake3-aes-256-gcm",
            "AAAAAAAAAAAAAAAAAAAAAA=="
        )
        .is_err());
    }
}
