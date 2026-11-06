// SPDX-License-Identifier: GPL-3.0-or-later
//! Type-checked outbound settings. External formats are first decoded into a
//! private staging value, validated, and then normalized into one of these
//! protocol-specific variants.

use std::path::PathBuf;

use crate::error::{Error, Result};

use super::OutboundKind;

#[derive(Clone)]
pub struct OutboundConfig {
    pub tag: String,
    pub(crate) settings: OutboundSettings,
}

#[derive(Clone)]
pub(crate) enum OutboundSettings {
    Vless(VlessConfig),
    Trojan(TrojanConfig),
    Socks5(ProxyConfig),
    HttpConnect(HttpConnectConfig),
    Direct(DirectConfig),
    Block,
    Dns,
    Selector(SelectorConfig),
    Urltest(UrltestConfig),
    Fallback(FallbackConfig),
}

#[derive(Clone)]
pub(crate) enum SecretSource {
    Inline(String),
    File(PathBuf),
}

#[derive(Clone)]
pub(crate) struct ProxyAuth {
    pub username: String,
    pub password: SecretSource,
}

impl SecretSource {
    pub(crate) fn read(&self) -> Result<String> {
        match self {
            Self::Inline(value) => Ok(value.trim().to_owned()),
            Self::File(path) => super::read_secret_file(path),
        }
    }
}

#[derive(Clone)]
pub(crate) struct VlessConfig {
    pub link: SecretSource,
    pub ca_file: Option<PathBuf>,
    pub xudp: bool,
    pub allow_insecure: bool,
    pub mux: Option<u16>,
    pub fragment: Option<crate::transport::fragment::FragmentConfig>,
}

#[derive(Clone)]
pub(crate) struct TrojanConfig {
    pub link: SecretSource,
    pub ca_file: Option<PathBuf>,
    pub allow_insecure: bool,
    pub fragment: Option<crate::transport::fragment::FragmentConfig>,
}

#[derive(Clone)]
pub(crate) struct ProxyConfig {
    pub server: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
    pub detour: Option<String>,
}

impl ProxyConfig {
    pub(crate) fn credentials(&self) -> Result<(Option<String>, Option<String>)> {
        match &self.auth {
            Some(auth) => Ok((Some(auth.username.clone()), Some(auth.password.read()?))),
            None => Ok((None, None)),
        }
    }
}

#[derive(Clone)]
pub(crate) struct HttpConnectConfig {
    pub proxy: ProxyConfig,
    pub tls: bool,
    pub tls_server_name: Option<String>,
    pub ca_file: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct DirectConfig {
    pub fragment: Option<crate::transport::fragment::FragmentConfig>,
    pub noises: Vec<crate::transport::noise::NoiseConfig>,
}

#[derive(Clone)]
pub(crate) struct SelectorConfig {
    pub outbounds: Vec<String>,
    pub subscriptions: Vec<String>,
    pub default: Option<String>,
}

#[derive(Clone)]
pub(crate) struct UrltestConfig {
    pub outbounds: Vec<String>,
    pub subscriptions: Vec<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct FallbackConfig {
    pub outbounds: Vec<String>,
    pub subscriptions: Vec<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
}

impl OutboundConfig {
    /// Construct the VLESS configuration used by the command-line client.
    pub fn vless(
        tag: impl Into<String>,
        link: Option<String>,
        link_file: Option<PathBuf>,
        ca_file: Option<PathBuf>,
        xudp: bool,
        allow_insecure: bool,
    ) -> Result<Self> {
        let tag = tag.into();
        let link = match (link, link_file) {
            (Some(link), None) => SecretSource::Inline(link),
            (None, Some(path)) => SecretSource::File(path),
            _ => {
                return Err(Error::Config(format!(
                    "выход {tag}: задайте ровно одно из link и link_file"
                )))
            }
        };
        Ok(Self {
            tag,
            settings: OutboundSettings::Vless(VlessConfig {
                link,
                ca_file,
                xudp,
                allow_insecure,
                mux: None,
                fragment: None,
            }),
        })
    }

    pub(crate) fn global_selector() -> Self {
        Self {
            tag: "GLOBAL".into(),
            settings: OutboundSettings::Selector(SelectorConfig {
                outbounds: Vec::new(),
                subscriptions: Vec::new(),
                default: None,
            }),
        }
    }

    pub fn kind(&self) -> OutboundKind {
        match &self.settings {
            OutboundSettings::Vless(_) => OutboundKind::Vless,
            OutboundSettings::Trojan(_) => OutboundKind::Trojan,
            OutboundSettings::Socks5(_) => OutboundKind::Socks5,
            OutboundSettings::HttpConnect(_) => OutboundKind::HttpConnect,
            OutboundSettings::Direct(_) => OutboundKind::Direct,
            OutboundSettings::Block => OutboundKind::Block,
            OutboundSettings::Dns => OutboundKind::Dns,
            OutboundSettings::Selector(_) => OutboundKind::Selector,
            OutboundSettings::Urltest(_) => OutboundKind::Urltest,
            OutboundSettings::Fallback(_) => OutboundKind::Fallback,
        }
    }

    pub(crate) fn as_vless(&self) -> Option<&VlessConfig> {
        match &self.settings {
            OutboundSettings::Vless(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn trojan(&self) -> Option<&TrojanConfig> {
        match &self.settings {
            OutboundSettings::Trojan(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn socks5(&self) -> Option<&ProxyConfig> {
        match &self.settings {
            OutboundSettings::Socks5(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn http_connect(&self) -> Option<&HttpConnectConfig> {
        match &self.settings {
            OutboundSettings::HttpConnect(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn direct(&self) -> Option<&DirectConfig> {
        match &self.settings {
            OutboundSettings::Direct(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn group_members(&self) -> Option<(&[String], &[String])> {
        match &self.settings {
            OutboundSettings::Selector(v) => Some((&v.outbounds, &v.subscriptions)),
            OutboundSettings::Urltest(v) => Some((&v.outbounds, &v.subscriptions)),
            OutboundSettings::Fallback(v) => Some((&v.outbounds, &v.subscriptions)),
            _ => None,
        }
    }

    pub(crate) fn selector(&self) -> Option<&SelectorConfig> {
        match &self.settings {
            OutboundSettings::Selector(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn group_default(&self) -> Option<&str> {
        self.selector().and_then(|v| v.default.as_deref())
    }

    pub(crate) fn urltest(&self) -> Option<&UrltestConfig> {
        match &self.settings {
            OutboundSettings::Urltest(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn detour(&self) -> Option<&str> {
        match &self.settings {
            OutboundSettings::Socks5(v) => v.detour.as_deref(),
            OutboundSettings::HttpConnect(v) => v.proxy.detour.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn referenced_paths(&self) -> Vec<&PathBuf> {
        match &self.settings {
            OutboundSettings::Vless(v) => secret_path(&v.link)
                .into_iter()
                .chain(v.ca_file.iter())
                .collect(),
            OutboundSettings::Trojan(v) => secret_path(&v.link)
                .into_iter()
                .chain(v.ca_file.iter())
                .collect(),
            OutboundSettings::Socks5(v) => proxy_auth_path(v.auth.as_ref()),
            OutboundSettings::HttpConnect(v) => v
                .proxy
                .auth
                .as_ref()
                .and_then(|auth| secret_path(&auth.password))
                .into_iter()
                .chain(v.ca_file.iter())
                .collect(),
            _ => Vec::new(),
        }
    }

    pub(crate) fn for_each_path(&mut self, f: &mut dyn FnMut(&mut PathBuf)) {
        match &mut self.settings {
            OutboundSettings::Vless(v) => {
                visit_secret_path(&mut v.link, f);
                visit_optional_path(&mut v.ca_file, f);
            }
            OutboundSettings::Trojan(v) => {
                visit_secret_path(&mut v.link, f);
                visit_optional_path(&mut v.ca_file, f);
            }
            OutboundSettings::Socks5(v) => visit_proxy_auth_path(v.auth.as_mut(), f),
            OutboundSettings::HttpConnect(v) => {
                visit_proxy_auth_path(v.proxy.auth.as_mut(), f);
                visit_optional_path(&mut v.ca_file, f);
            }
            _ => {}
        }
    }
}

fn visit_optional_path(path: &mut Option<PathBuf>, f: &mut dyn FnMut(&mut PathBuf)) {
    if let Some(path) = path {
        f(path);
    }
}

fn secret_path(secret: &SecretSource) -> Option<&PathBuf> {
    match secret {
        SecretSource::Inline(_) => None,
        SecretSource::File(path) => Some(path),
    }
}

fn proxy_auth_path(auth: Option<&ProxyAuth>) -> Vec<&PathBuf> {
    auth.and_then(|auth| secret_path(&auth.password))
        .into_iter()
        .collect()
}

fn visit_secret_path(secret: &mut SecretSource, f: &mut dyn FnMut(&mut PathBuf)) {
    if let SecretSource::File(path) = secret {
        f(path);
    }
}

fn visit_proxy_auth_path(auth: Option<&mut ProxyAuth>, f: &mut dyn FnMut(&mut PathBuf)) {
    if let Some(auth) = auth {
        visit_secret_path(&mut auth.password, f);
    }
}

impl std::fmt::Debug for OutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundConfig")
            .field("tag", &self.tag)
            .field("kind", &self.kind())
            .field("settings", &RedactedSettings(&self.settings))
            .finish()
    }
}

struct RedactedSettings<'a>(&'a OutboundSettings);

impl std::fmt::Debug for SecretSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline(_) => f.write_str("Inline(***)"),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
        }
    }
}

impl std::fmt::Debug for RedactedSettings<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            OutboundSettings::Vless(v) => f
                .debug_struct("Vless")
                .field("link", &v.link)
                .field("ca_file", &v.ca_file)
                .field("xudp", &v.xudp)
                .field("allow_insecure", &v.allow_insecure)
                .field("mux", &v.mux)
                .field("fragment", &v.fragment)
                .finish(),
            OutboundSettings::Trojan(v) => f
                .debug_struct("Trojan")
                .field("link", &v.link)
                .field("ca_file", &v.ca_file)
                .field("allow_insecure", &v.allow_insecure)
                .field("fragment", &v.fragment)
                .finish(),
            OutboundSettings::Socks5(v) => proxy_debug(f, "Socks5", v),
            OutboundSettings::HttpConnect(v) => f
                .debug_struct("HttpConnect")
                .field("proxy", &ProxyDebug(&v.proxy))
                .field("tls", &v.tls)
                .field("tls_server_name", &v.tls_server_name)
                .field("ca_file", &v.ca_file)
                .finish(),
            OutboundSettings::Direct(v) => f
                .debug_struct("Direct")
                .field("fragment", &v.fragment)
                .field("noises", &v.noises)
                .finish(),
            OutboundSettings::Block => f.write_str("Block"),
            OutboundSettings::Dns => f.write_str("Dns"),
            OutboundSettings::Selector(v) => f
                .debug_struct("Selector")
                .field("outbounds", &v.outbounds)
                .field("subscriptions", &v.subscriptions)
                .field("default", &v.default)
                .finish(),
            OutboundSettings::Urltest(v) => f
                .debug_struct("Urltest")
                .field("outbounds", &v.outbounds)
                .field("subscriptions", &v.subscriptions)
                .field("url", &v.url)
                .field("interval", &v.interval)
                .field("tolerance", &v.tolerance)
                .finish(),
            OutboundSettings::Fallback(v) => f
                .debug_struct("Fallback")
                .field("outbounds", &v.outbounds)
                .field("subscriptions", &v.subscriptions)
                .field("url", &v.url)
                .field("interval", &v.interval)
                .finish(),
        }
    }
}

struct ProxyDebug<'a>(&'a ProxyConfig);

impl std::fmt::Debug for ProxyDebug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        proxy_debug(f, "Proxy", self.0)
    }
}

fn proxy_debug(f: &mut std::fmt::Formatter<'_>, name: &str, v: &ProxyConfig) -> std::fmt::Result {
    f.debug_struct(name)
        .field("server", &v.server)
        .field("port", &v.port)
        .field("auth", &v.auth.as_ref().map(ProxyAuthDebug))
        .field("detour", &v.detour)
        .finish()
}

struct ProxyAuthDebug<'a>(&'a ProxyAuth);

impl std::fmt::Debug for ProxyAuthDebug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyAuth")
            .field("username", &crate::redact::opt(&Some(&self.0.username)))
            .field("password", &self.0.password)
            .finish()
    }
}

/// Parser-only staging model. It intentionally mirrors the old flat input
/// shape so parsers can collect fields, but it never escapes normalization.
#[derive(Clone)]
pub(super) struct RawOutboundConfig {
    pub tag: String,
    pub kind: OutboundKind,
    pub link: Option<String>,
    pub link_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
    pub xudp: bool,
    pub allow_insecure: bool,
    pub mux: Option<u16>,
    pub fragment: Option<crate::transport::fragment::FragmentConfig>,
    pub noises: Vec<crate::transport::noise::NoiseConfig>,
    pub proxy_server: Option<String>,
    pub proxy_port: Option<u16>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
    pub proxy_password_file: Option<PathBuf>,
    pub proxy_tls: bool,
    pub proxy_tls_server_name: Option<String>,
    pub detour: Option<String>,
    pub outbounds: Vec<String>,
    pub subscriptions: Vec<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u64>,
    pub default: Option<String>,
}

impl RawOutboundConfig {
    pub(super) fn new(tag: &str, kind: OutboundKind) -> Self {
        Self {
            tag: tag.to_owned(),
            kind,
            link: None,
            link_file: None,
            ca_file: None,
            xudp: true,
            allow_insecure: false,
            mux: None,
            fragment: None,
            noises: Vec::new(),
            proxy_server: None,
            proxy_port: None,
            proxy_username: None,
            proxy_password: None,
            proxy_password_file: None,
            proxy_tls: false,
            proxy_tls_server_name: None,
            detour: None,
            outbounds: Vec::new(),
            subscriptions: Vec::new(),
            url: None,
            interval: None,
            tolerance: None,
            default: None,
        }
    }

    pub(super) fn check_fields(&self) -> Result<()> {
        let tag = &self.tag;
        let group = self.kind.is_group();
        let group_fields = !self.outbounds.is_empty()
            || !self.subscriptions.is_empty()
            || self.url.is_some()
            || self.interval.is_some()
            || self.tolerance.is_some()
            || self.default.is_some();
        if self.fragment.is_some()
            && !matches!(
                self.kind,
                OutboundKind::Vless | OutboundKind::Trojan | OutboundKind::Direct
            )
        {
            return Err(Error::Config(format!(
                "выход {tag}: fragment — только у vless, trojan и direct"
            )));
        }
        if !self.noises.is_empty() && self.kind != OutboundKind::Direct {
            return Err(Error::Config(format!(
                "выход {tag}: noises — только у direct"
            )));
        }
        if self.detour.as_ref().is_some_and(|t| {
            t.trim().is_empty() || t.trim() != t || t.chars().any(char::is_control) || t == tag
        }) {
            return Err(Error::Config(format!(
                "выход {tag}: detour должен содержать корректный tag другого выхода"
            )));
        }
        if self.detour.is_some()
            && !matches!(self.kind, OutboundKind::Socks5 | OutboundKind::HttpConnect)
        {
            return Err(Error::Config(format!(
                "выход {tag}: detour пока поддерживается только у SOCKS5 и HTTP CONNECT"
            )));
        }
        if !group && group_fields {
            return Err(Error::Config(format!("выход {tag}: outbounds, subscriptions, url, interval, tolerance, default — только у групп (selector, urltest, fallback)")));
        }
        let server_fields = self.link.is_some() || self.link_file.is_some() || self.allow_insecure;
        let server = matches!(self.kind, OutboundKind::Vless | OutboundKind::Trojan);
        if server {
            match (self.link.is_some(), self.link_file.is_some()) {
                (true, true) => {
                    return Err(Error::Config(format!(
                        "выход {tag}: задано и значение, и файл — оставьте одно"
                    )))
                }
                (false, false) => {
                    return Err(Error::Config(format!("выход {tag}: не задан сервер")))
                }
                _ => {}
            }
        }
        let ca_file_allowed = server || (self.kind == OutboundKind::HttpConnect && self.proxy_tls);
        if (!server && server_fields) || (self.ca_file.is_some() && !ca_file_allowed) {
            return Err(Error::Config(format!("выход {tag}: link, link_file и allow_insecure — только у vless и trojan; ca_file допустим также у HTTP CONNECT с TLS")));
        }
        let proxy_fields = self.proxy_server.is_some()
            || self.proxy_port.is_some()
            || self.proxy_username.is_some()
            || self.proxy_password.is_some()
            || self.proxy_password_file.is_some();
        if !matches!(self.kind, OutboundKind::Socks5 | OutboundKind::HttpConnect)
            && (proxy_fields || self.proxy_tls || self.proxy_tls_server_name.is_some())
        {
            return Err(Error::Config(format!("выход {tag}: параметры proxy допустимы только у type = \"socks\" или type = \"http\"")));
        }
        if matches!(self.kind, OutboundKind::Socks5 | OutboundKind::HttpConnect) {
            let protocol = if self.kind == OutboundKind::Socks5 {
                "SOCKS5"
            } else {
                "HTTP CONNECT"
            };
            let server = self.proxy_server.as_ref().filter(|s| {
                !s.trim().is_empty() && s.trim() == s.as_str() && !s.chars().any(char::is_control)
            });
            let port = self.proxy_port.filter(|p| *p != 0);
            if server.is_none() || port.is_none() {
                return Err(Error::Config(format!(
                    "выход {tag}: {protocol} требует server и server_port от 1 до 65535"
                )));
            }
            if self.proxy_password.is_some() && self.proxy_password_file.is_some() {
                return Err(Error::Config(format!(
                    "выход {tag}: {protocol} password и password_file взаимоисключающие"
                )));
            }
            let has_password = self.proxy_password.is_some() || self.proxy_password_file.is_some();
            if self.proxy_username.is_some() != has_password {
                return Err(Error::Config(format!(
                    "выход {tag}: {protocol} username и password должны быть заданы вместе"
                )));
            }
            if self.kind == OutboundKind::Socks5 {
                if self
                    .proxy_password
                    .as_ref()
                    .is_some_and(|p| p.is_empty() || p.len() > 255)
                    || self
                        .proxy_username
                        .as_ref()
                        .is_some_and(|u| u.is_empty() || u.len() > 255)
                {
                    if self
                        .proxy_password
                        .as_ref()
                        .is_some_and(|p| p.is_empty() || p.len() > 255)
                    {
                        return Err(Error::Config(format!(
                            "выход {tag}: SOCKS5 password должен занимать 1–255 байт"
                        )));
                    }
                    return Err(Error::Config(format!(
                        "выход {tag}: SOCKS5 username должен занимать 1–255 байт"
                    )));
                }
            } else {
                if self.proxy_username.as_ref().is_some_and(|u| {
                    u.is_empty()
                        || u.len() > 4096
                        || u.contains(':')
                        || u.chars().any(char::is_control)
                }) || self.proxy_password.as_ref().is_some_and(|p| {
                    p.is_empty() || p.len() > 4096 || p.chars().any(char::is_control)
                }) {
                    return Err(Error::Config(format!("выход {tag}: HTTP CONNECT учётные данные пусты, слишком длинные или некорректны для Basic auth")));
                }
                if self.proxy_tls_server_name.is_some() && !self.proxy_tls {
                    return Err(Error::Config(format!(
                        "выход {tag}: tls.server_name можно задавать только при tls.enabled = true"
                    )));
                }
                if self.proxy_tls_server_name.as_ref().is_some_and(|s| {
                    s.trim().is_empty() || s.trim() != s.as_str() || s.chars().any(char::is_control)
                }) {
                    return Err(Error::Config(format!(
                        "выход {tag}: некорректное имя tls.server_name"
                    )));
                }
            }
        }
        if self.kind != OutboundKind::Vless && self.mux.is_some() {
            return Err(Error::Config(format!(
                "выход {tag}: mux — только у type = \"vless\""
            )));
        }
        if group {
            if self.outbounds.is_empty() && self.subscriptions.is_empty() {
                return Err(Error::Config(format!(
                    "выход {tag}: в группе нет участников (outbounds или subscriptions)"
                )));
            }
            if self.default.is_some() && self.kind != OutboundKind::Selector {
                return Err(Error::Config(format!(
                    "выход {tag}: default бывает только у selector"
                )));
            }
            if self.tolerance.is_some() && self.kind != OutboundKind::Urltest {
                return Err(Error::Config(format!(
                    "выход {tag}: tolerance бывает только у urltest"
                )));
            }
            if self.kind == OutboundKind::Selector
                && (self.url.is_some() || self.interval.is_some())
            {
                return Err(Error::Config(format!(
                    "выход {tag}: selector не проверяет участников — url и interval не нужны"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<OutboundConfig> {
        self.check_fields()?;
        let settings = match self.kind {
            OutboundKind::Vless => OutboundSettings::Vless(VlessConfig {
                link: self.take_link()?,
                ca_file: self.ca_file,
                xudp: self.xudp,
                allow_insecure: self.allow_insecure,
                mux: self.mux,
                fragment: self.fragment,
            }),
            OutboundKind::Trojan => OutboundSettings::Trojan(TrojanConfig {
                link: self.take_link()?,
                ca_file: self.ca_file,
                allow_insecure: self.allow_insecure,
                fragment: self.fragment,
            }),
            OutboundKind::Socks5 => OutboundSettings::Socks5(self.proxy()?),
            OutboundKind::HttpConnect => {
                let tls = self.proxy_tls;
                let tls_server_name = self.proxy_tls_server_name.take();
                let ca_file = self.ca_file.take();
                OutboundSettings::HttpConnect(HttpConnectConfig {
                    proxy: self.proxy()?,
                    tls,
                    tls_server_name,
                    ca_file,
                })
            }
            OutboundKind::Direct => OutboundSettings::Direct(DirectConfig {
                fragment: self.fragment,
                noises: self.noises,
            }),
            OutboundKind::Block => OutboundSettings::Block,
            OutboundKind::Dns => OutboundSettings::Dns,
            OutboundKind::Selector => OutboundSettings::Selector(SelectorConfig {
                outbounds: self.outbounds,
                subscriptions: self.subscriptions,
                default: self.default,
            }),
            OutboundKind::Urltest => OutboundSettings::Urltest(UrltestConfig {
                outbounds: self.outbounds,
                subscriptions: self.subscriptions,
                url: self.url,
                interval: self.interval,
                tolerance: self.tolerance,
            }),
            OutboundKind::Fallback => OutboundSettings::Fallback(FallbackConfig {
                outbounds: self.outbounds,
                subscriptions: self.subscriptions,
                url: self.url,
                interval: self.interval,
            }),
        };
        Ok(OutboundConfig {
            tag: self.tag,
            settings,
        })
    }

    fn take_link(&mut self) -> Result<SecretSource> {
        match (self.link.take(), self.link_file.take()) {
            (Some(link), None) => Ok(SecretSource::Inline(link)),
            (None, Some(path)) => Ok(SecretSource::File(path)),
            _ => Err(Error::Config(format!(
                "выход {}: не задан сервер",
                self.tag
            ))),
        }
    }

    fn proxy(&mut self) -> Result<ProxyConfig> {
        let server = self
            .proxy_server
            .take()
            .ok_or_else(|| Error::Config("proxy server отсутствует после проверки".into()))?;
        let port = self
            .proxy_port
            .take()
            .ok_or_else(|| Error::Config("proxy port отсутствует после проверки".into()))?;
        let auth = match (
            self.proxy_username.take(),
            self.proxy_password.take(),
            self.proxy_password_file.take(),
        ) {
            (None, None, None) => None,
            (Some(username), Some(password), None) => Some(ProxyAuth {
                username,
                password: SecretSource::Inline(password),
            }),
            (Some(username), None, Some(path)) => Some(ProxyAuth {
                username,
                password: SecretSource::File(path),
            }),
            _ => unreachable!("proxy credentials were validated before normalization"),
        };
        Ok(ProxyConfig {
            server,
            port,
            auth,
            detour: self.detour.take(),
        })
    }
}

impl std::fmt::Debug for RawOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawOutboundConfig")
            .field("tag", &self.tag)
            .field("kind", &self.kind)
            .field("link", &crate::redact::opt(&self.link))
            .field("proxy_username", &crate::redact::opt(&self.proxy_username))
            .field("proxy_password", &crate::redact::opt(&self.proxy_password))
            .finish_non_exhaustive()
    }
}
