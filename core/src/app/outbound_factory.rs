// SPDX-License-Identifier: GPL-3.0-or-later
//! Static construction boundary for server-backed proxy outbounds.
//!
//! Application composition, DNS, groups, detour slots, and routing remain in
//! `build_core`; this module owns validation and construction of proxy types.

use std::collections::HashMap;
use std::sync::Arc;

use super::config::{self, OutboundKind};
use super::outbound::{self, Outbound};
use super::{http_connect_out, hysteria2_out, socks_out, trojan_out};
use crate::error::{Error, Result};

/// Build one server-backed proxy outbound from its validated typed config.
#[allow(
    clippy::expect_used,
    reason = "invariant: proxy settings are selected by the same outbound kind"
)]
pub(super) fn build_proxy(
    config: &config::OutboundConfig,
    detour_slots: &HashMap<String, outbound::OutboundSlot>,
) -> Result<Arc<dyn Outbound>> {
    let proxy: Arc<dyn Outbound> = match config.kind() {
        OutboundKind::Vless => Arc::new(build_vless(config)?),
        OutboundKind::Trojan => Arc::new(build_trojan(config)?),
        OutboundKind::Hysteria2 => Arc::new(build_hysteria2(config)?),
        OutboundKind::Socks5 => {
            let settings = config
                .socks5()
                .expect("SOCKS5 settings match outbound kind");
            let (username, password) = settings.credentials()?;
            Arc::new(
                socks_out::Socks5Outbound::new(
                    config.tag.clone(),
                    settings.server.clone(),
                    settings.port,
                    username,
                    password,
                )?
                .with_detour(detour_slots.get(&config.tag).cloned()),
            )
        }
        OutboundKind::HttpConnect => {
            let settings = config
                .http_connect()
                .expect("HTTP CONNECT settings match outbound kind");
            let (username, password) = settings.proxy.credentials()?;
            let roots = settings
                .ca_file
                .as_deref()
                .map(config::load_ca)
                .transpose()?;
            Arc::new(
                http_connect_out::HttpConnectOutbound::new(
                    config.tag.clone(),
                    settings.proxy.server.clone(),
                    settings.proxy.port,
                    username,
                    password,
                    settings.tls,
                    settings.tls_server_name.clone(),
                )?
                .with_roots(roots)
                .with_detour(detour_slots.get(&config.tag).cloned()),
            )
        }
        _ => {
            return Err(Error::Config(format!(
                "выход «{}»: фабрика собирает только VLESS, Trojan, Hysteria 2, SOCKS5 и HTTP CONNECT",
                config.tag
            )));
        }
    };
    Ok(proxy)
}

#[allow(
    clippy::expect_used,
    reason = "invariant: called only for an outbound of type Hysteria 2"
)]
fn build_hysteria2(config: &config::OutboundConfig) -> Result<hysteria2_out::Hysteria2Outbound> {
    let link = config
        .hysteria2_link()
        .expect("Hysteria 2 settings match outbound kind")
        .read()?;
    let hysteria = crate::hysteria2::Hysteria2Config::parse(&link)?;
    crate::hysteria2_transport::validate_supported_options(&hysteria)?;
    let roots = config
        .hysteria2_ca_file()
        .map(|path| config::load_ca(path))
        .transpose()?;
    Ok(hysteria2_out::Hysteria2Outbound::new(config.tag.clone(), hysteria).with_roots(roots))
}

#[allow(
    clippy::expect_used,
    reason = "invariant: called only for an outbound of type VLESS"
)]
fn build_vless(config: &config::OutboundConfig) -> Result<super::vless_out::VlessOutbound> {
    let settings = config
        .as_vless()
        .expect("VLESS settings match outbound kind");
    let link = settings.link.read()?;
    let roots = settings
        .ca_file
        .as_deref()
        .map(config::load_ca)
        .transpose()?
        .map(Arc::new);
    let fragment = super::build_fragment(&config.tag, settings.fragment.as_ref())?;
    let vless = super::vless_from_link(
        &config.tag,
        &link,
        settings.xudp,
        settings.allow_insecure,
        roots,
        false,
        fragment,
    )?;
    match settings.mux {
        Some(concurrency) => vless.with_mux(concurrency),
        None => Ok(vless),
    }
}

#[allow(
    clippy::expect_used,
    reason = "invariant: called only for an outbound of type Trojan"
)]
fn build_trojan(config: &config::OutboundConfig) -> Result<trojan_out::TrojanOutbound> {
    let settings = config
        .trojan()
        .expect("Trojan settings match outbound kind");
    let link = settings.link.read()?;
    let roots = settings
        .ca_file
        .as_deref()
        .map(config::load_ca)
        .transpose()?
        .map(Arc::new);
    super::trojan_from_link(
        &config.tag,
        &link,
        settings.allow_insecure,
        roots,
        false,
        super::build_fragment(&config.tag, settings.fragment.as_ref())?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_builds_socks5_and_http_connect_proxies() {
        let config = config::Config::parse(
            r#"{
              "outbounds": [
                {"type":"socks","tag":"socks","server":"127.0.0.1","server_port":1080,"network":"tcp"},
                {"type":"http","tag":"http","server":"proxy.example","server_port":8080}
              ]
            }"#,
        )
        .unwrap();
        let detour_slots = HashMap::new();

        let socks = build_proxy(&config.outbounds[0], &detour_slots).unwrap();
        assert_eq!(socks.tag(), "socks");
        assert_eq!(socks.server(), Some(("127.0.0.1".into(), 1080)));
        assert_eq!(socks.capabilities(), outbound::OutboundCapabilities::TCP);

        let http = build_proxy(&config.outbounds[1], &detour_slots).unwrap();
        assert_eq!(http.tag(), "http");
        assert_eq!(http.server(), Some(("proxy.example".into(), 8080)));
        assert_eq!(http.capabilities(), outbound::OutboundCapabilities::TCP);
    }

    #[test]
    fn factory_rejects_non_proxy_outbounds() {
        let config =
            config::Config::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#).unwrap();

        assert!(build_proxy(&config.outbounds[0], &HashMap::new()).is_err());
    }

    #[test]
    fn factory_builds_hysteria2_from_singbox_config() {
        let config = config::Config::parse(
            r#"{"outbounds":[{"type":"hysteria2","tag":"hy2","server":"example.com","server_port":443,"password":"secret","tls":{"server_name":"edge.example"}}]}"#,
        )
        .unwrap();

        let outbound = build_proxy(&config.outbounds[0], &HashMap::new()).unwrap();
        assert_eq!(outbound.tag(), "hy2");
        assert_eq!(outbound.clash_type(), "Hysteria2");
        assert_eq!(outbound.server(), Some(("example.com".into(), 443)));
        assert_eq!(
            outbound.capabilities(),
            outbound::OutboundCapabilities::TCP_UDP_TERMINAL
        );
    }

    #[test]
    fn factory_rejects_unreadable_hysteria2_ca_file() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let ca_path =
            std::env::temp_dir().join(format!("vpn-core-hysteria2-missing-ca-{nonce}.pem"));
        let config = config::Config::parse(&format!(
            r#"{{"outbounds":[{{"type":"hysteria2","tag":"hy2","server":"example.com","server_port":443,"password":"secret","tls":{{}},"ca_file":{}}}]}}"#,
            serde_json::to_string(&ca_path).unwrap()
        ))
        .unwrap();

        let error = build_proxy(&config.outbounds[0], &HashMap::new())
            .err()
            .expect("invalid CA path must fail outbound construction");
        assert!(
            error.to_string().contains("hysteria2-missing-ca"),
            "{error}"
        );
    }

    #[test]
    fn factory_loads_custom_hysteria2_ca_file() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["test-ca.local".into()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let ca_path = std::env::temp_dir().join(format!("vpn-core-hysteria2-ca-{nonce}.pem"));
        std::fs::write(&ca_path, cert.pem()).unwrap();
        let config = config::Config::parse(&format!(
            r#"{{"outbounds":[{{"type":"hysteria2","tag":"hy2","server":"example.com","server_port":443,"password":"secret","tls":{{}},"ca_file":{}}}]}}"#,
            serde_json::to_string(&ca_path).unwrap()
        ))
        .unwrap();

        let outbound = build_proxy(&config.outbounds[0], &HashMap::new()).unwrap();
        assert_eq!(outbound.clash_type(), "Hysteria2");
        std::fs::remove_file(ca_path).unwrap();
    }
}
