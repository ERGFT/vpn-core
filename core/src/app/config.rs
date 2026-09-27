//! Файл настроек (TOML).
//!
//! ```toml
//! [[inbounds]]
//! type = "socks"
//! listen = "127.0.0.1:1080"
//! # auth_file = "auth.txt"          # логин:пароль в первой строке
//! # allow_ip = ["192.168.1.23"]
//!
//! [[outbounds]]
//! tag = "proxy"
//! type = "vless"
//! link_file = "server.txt"          # или link = "vless://…"
//!
//! [[outbounds]]
//! tag = "direct"
//! type = "direct"
//!
//! [route]
//! final = "proxy"                   # выход по умолчанию
//! ```
//!
//! Относительные пути — от папки файла настроек. Секреты (ссылку, пароль)
//! лучше держать в отдельных файлах: сам файл настроек тогда можно
//! показывать и хранить без опаски.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::access::IpNet;
pub use super::rules::{PortSpec, RuleConfig};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub route: RouteConfig,
    /// Свой DNS (см. `super::dns`); не задан — имена разрешает система
    /// (для `direct`) или сервер VLESS.
    pub dns: Option<super::dns::DnsConfig>,
    /// Подписки: списки серверов с панели (см. `super::subscription`).
    #[serde(default)]
    pub subscriptions: Vec<super::subscription::SubscriptionConfig>,
    /// Локальное API (см. `super::api`).
    pub api: Option<super::api::ApiConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InboundKind {
    /// SOCKS5 (CONNECT, UDP ASSOCIATE).
    Socks,
    /// HTTP-прокси (CONNECT и обычные запросы).
    Http,
    /// SOCKS5 и HTTP на одном порту.
    Mixed,
    /// DNS-сервер (UDP и TCP) для системы и программ.
    Dns,
    /// Виртуальный сетевой интерфейс: весь трафик компьютера (как VPN).
    Tun,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundConfig {
    #[serde(rename = "type")]
    pub kind: InboundKind,
    pub tag: Option<String>,
    /// Адрес входа (у `tun` не бывает).
    pub listen: Option<SocketAddr>,
    /// `логин:пароль` прямо в файле (лучше — `auth_file`).
    pub auth: Option<String>,
    pub auth_file: Option<PathBuf>,
    #[serde(default)]
    pub allow_ip: Vec<IpNet>,
    pub max_conns: Option<usize>,
    /// Узнавать домен по первым байтам (TLS SNI, HTTP Host), когда
    /// приложение прислало IP, — для правил по доменам.
    #[serde(default)]
    pub sniff: bool,
    /// Подставлять найденный домен вместо IP (имя разрешит сервер).
    #[serde(default)]
    pub sniff_override_destination: bool,

    // ── только для type = "tun" ──
    /// Имя интерфейса (по умолчанию `reality-tun`).
    pub interface_name: Option<String>,
    /// Адрес интерфейса (по умолчанию `172.19.0.1/30`).
    pub inet4_address: Option<IpNet>,
    /// IPv6-адрес интерфейса (по умолчанию `fdfe:dcba:9876::1/126`;
    /// без IPv6 его трафик шёл бы мимо TUN).
    pub inet6_address: Option<IpNet>,
    pub mtu: Option<u16>,
    /// Направить весь трафик компьютера в TUN (по умолчанию да).
    pub auto_route: Option<bool>,
    /// Подсети, которые остаются мимо TUN.
    #[serde(default)]
    pub route_exclude: Vec<IpNet>,
    /// Kill switch (Linux): если клиент упал, трафик не идёт мимо туннеля,
    /// пока клиент не запущен снова (или `--tun-cleanup`).
    pub strict_route: Option<bool>,
    /// Отвечать на DNS-запросы (порт 53 на любой адрес) своим DNS
    /// (по умолчанию да; нужен раздел [dns]).
    pub dns_hijack: Option<bool>,
}

impl InboundConfig {
    /// Адрес входа; у всех, кроме `tun`, обязателен.
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listen.ok_or_else(|| {
            Error::Config(format!(
                "вход {}: не задан listen",
                self.tag.as_deref().unwrap_or("без tag")
            ))
        })
    }

    fn has_tun_fields(&self) -> bool {
        self.interface_name.is_some()
            || self.inet4_address.is_some()
            || self.inet6_address.is_some()
            || self.mtu.is_some()
            || self.auto_route.is_some()
            || !self.route_exclude.is_empty()
            || self.strict_route.is_some()
            || self.dns_hijack.is_some()
    }

    /// Поля, которые бывают только у одного вида входа.
    pub fn check_fields(&self) -> Result<()> {
        let tag = self.tag.as_deref().unwrap_or("без tag");
        match self.kind {
            InboundKind::Tun => {
                if self.listen.is_some() || self.auth.is_some() || self.auth_file.is_some() {
                    return Err(Error::Config(format!(
                        "вход {tag}: у tun не бывает listen и пароля"
                    )));
                }
            }
            _ => {
                if self.has_tun_fields() {
                    return Err(Error::Config(format!(
                        "вход {tag}: interface_name, inet4_address, auto_route и т.п. — только у type = \"tun\""
                    )));
                }
                self.listen_addr()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundKind {
    Vless,
    Direct,
    Block,
    /// Ответить самому DNS-модулем (перехват DNS-запросов).
    Dns,
    /// Группа: участник, выбранный вручную (по умолчанию первый).
    Selector,
    /// Группа: самый быстрый по проверке.
    Urltest,
    /// Группа: первый работающий по порядку.
    Fallback,
}

impl OutboundKind {
    pub fn is_group(self) -> bool {
        matches!(self, Self::Selector | Self::Urltest | Self::Fallback)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConfig {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: OutboundKind,
    /// vless: ссылка прямо в файле (лучше — `link_file`).
    pub link: Option<String>,
    pub link_file: Option<PathBuf>,
    /// vless: свои корневые сертификаты для `security=tls`.
    pub ca_file: Option<PathBuf>,
    /// vless: UDP через XUDP (по умолчанию) или поток на назначение.
    #[serde(default = "yes")]
    pub xudp: bool,
    /// vless: разрешить `security=none` (без шифрования).
    #[serde(default)]
    pub allow_insecure: bool,
    /// vless: Mux.Cool — до стольких TCP-соединений в одном потоке
    /// (как `mux.concurrency` у Xray; не вместе с Vision).
    pub mux: Option<u16>,
    /// vless, direct: дробить начало соединения (ClientHello) против DPI.
    pub fragment: Option<crate::transport::fragment::FragmentConfig>,
    /// direct: пакеты-пустышки перед первой UDP-датаграммой к адресу.
    #[serde(default)]
    pub noises: Vec<crate::transport::noise::NoiseConfig>,

    // ── только для групп (selector, urltest, fallback) ──
    /// Участники — tag других выходов (в том числе групп).
    #[serde(default)]
    pub outbounds: Vec<String>,
    /// Подписки, серверы которых входят в группу.
    #[serde(default)]
    pub subscriptions: Vec<String>,
    /// Адрес проверки (по умолчанию `https://www.gstatic.com/generate_204`).
    pub url: Option<String>,
    /// Как часто проверять, секунд (по умолчанию 180).
    pub interval: Option<u64>,
    /// urltest: не переключаться, пока текущий хуже лучшего не больше
    /// чем на столько миллисекунд (по умолчанию 50).
    pub tolerance: Option<u64>,
    /// selector: участник по умолчанию.
    pub default: Option<String>,
}

impl OutboundConfig {
    /// Поля, которые бывают только у одного вида выхода.
    pub fn check_fields(&self) -> Result<()> {
        let tag = &self.tag;
        let group = self.kind.is_group();
        let group_fields = !self.outbounds.is_empty()
            || !self.subscriptions.is_empty()
            || self.url.is_some()
            || self.interval.is_some()
            || self.tolerance.is_some()
            || self.default.is_some();
        if self.fragment.is_some()
            && !matches!(self.kind, OutboundKind::Vless | OutboundKind::Direct)
        {
            return Err(Error::Config(format!(
                "выход {tag}: fragment — только у vless и direct"
            )));
        }
        if !self.noises.is_empty() && self.kind != OutboundKind::Direct {
            return Err(Error::Config(format!(
                "выход {tag}: noises — только у direct"
            )));
        }
        if !group && group_fields {
            return Err(Error::Config(format!(
                "выход {tag}: outbounds, subscriptions, url, interval, tolerance, default — только у групп (selector, urltest, fallback)"
            )));
        }
        let vless_fields = self.link.is_some()
            || self.link_file.is_some()
            || self.ca_file.is_some()
            || self.allow_insecure
            || self.mux.is_some();
        if self.kind != OutboundKind::Vless && vless_fields {
            return Err(Error::Config(format!(
                "выход {tag}: link, link_file, ca_file, allow_insecure, mux — только у type = \"vless\""
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
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Правила по порядку; срабатывает первое подошедшее.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    /// Выход по умолчанию; не задан — первый из `outbounds`.
    #[serde(rename = "final")]
    pub final_: Option<String>,
    /// База доменов для `geosite = [...]` (по умолчанию `geosite.dat`
    /// рядом с файлом настроек).
    pub geosite_file: Option<PathBuf>,
    /// База адресов для `geoip = [...]` (по умолчанию `geoip.dat`).
    pub geoip_file: Option<PathBuf>,
    /// `ip_if_non_match` — если ни одно правило не подошло к имени,
    /// разрешить его (DNS-модулем) и проверить правила по адресу.
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    /// Готовые наборы правил: `block-ads`, `private-direct`, `ru-direct`,
    /// `cn-direct`, `ir-direct` — после своих правил.
    #[serde(default)]
    pub presets: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| {
            let mut msg = e.to_string();
            // Частая ошибка на Windows: путь в двойных кавычках, где «\U»,
            // «\s» и т.п. читаются как спецсимволы.
            if msg.contains("escape") || msg.contains("unicode") {
                msg.push_str(
                    "\nподсказка: пути Windows пишите в одинарных кавычках: 'C:\\Users\\me\\server.txt'",
                );
            }
            Error::Config(msg)
        })
    }

    /// Прочитать файл настроек; относительные пути внутри него
    /// становятся путями от его папки.
    pub fn load(path: &Path) -> Result<Self> {
        warn_if_readable_by_others(path);
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("не удалось прочитать {}: {e}", path.display())))?;
        let mut cfg = Self::parse(&text)?;
        let base = path.parent().unwrap_or(Path::new("."));
        let fix = |p: &mut Option<PathBuf>| {
            if let Some(v) = p {
                if v.is_relative() {
                    *v = base.join(&*v);
                }
            }
        };
        for i in &mut cfg.inbounds {
            fix(&mut i.auth_file);
        }
        for o in &mut cfg.outbounds {
            fix(&mut o.link_file);
            fix(&mut o.ca_file);
        }
        for sub in &mut cfg.subscriptions {
            fix(&mut sub.url_file);
            fix(&mut sub.ca_file);
            let tag = sub.tag.clone();
            sub.cache_file
                .get_or_insert_with(|| format!("{tag}.subscription").into());
            fix(&mut sub.cache_file);
        }
        if let Some(a) = &mut cfg.api {
            fix(&mut a.token_file);
        }
        let r = &mut cfg.route;
        r.geosite_file.get_or_insert_with(|| "geosite.dat".into());
        r.geoip_file.get_or_insert_with(|| "geoip.dat".into());
        fix(&mut r.geosite_file);
        fix(&mut r.geoip_file);
        if let Some(d) = &mut cfg.dns {
            for s in &mut d.servers {
                fix(&mut s.ca_file);
            }
            if let Some(f) = &mut d.fakeip {
                fix(&mut f.cache_file);
            }
        }
        Ok(cfg)
    }
}

/// На Unix: файл с секретами не должен читаться другими пользователями.
pub fn warn_if_readable_by_others(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                tracing::warn!(
                    file = %path.display(),
                    "файл с секретом доступен другим пользователям; выполните chmod 600"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Прочитать секрет (ссылку или логин:пароль) из файла: первая непустая
/// строка без пробелов по краям.
pub fn read_secret_file(path: &Path) -> Result<String> {
    warn_if_readable_by_others(path);
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("не удалось прочитать {}: {e}", path.display())))?;
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::Config(format!("файл {} пуст", path.display())))
}

/// PEM-файл с корневыми сертификатами.
pub fn load_ca(path: &Path) -> Result<rustls::RootCertStore> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let mut roots = rustls::RootCertStore::empty();
    let iter = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::Config(format!("не удалось прочитать {}: {e}", path.display())))?;
    for cert in iter {
        let cert =
            cert.map_err(|e| Error::Config(format!("битый сертификат в {}: {e}", path.display())))?;
        roots.add(cert).map_err(|e| {
            Error::Config(format!(
                "сертификат из {} не подходит как корневой: {e}",
                path.display()
            ))
        })?;
    }
    if roots.is_empty() {
        return Err(Error::Config(format!(
            "в {} нет ни одного сертификата",
            path.display()
        )));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_and_rejects_typos() {
        let c = Config::parse(
            r#"
[[inbounds]]
type = "socks"
listen = "127.0.0.1:1080"
allow_ip = ["192.168.1.0/24"]

[[outbounds]]
tag = "proxy"
type = "vless"
link = "vless://u@h:1"
xudp = false

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"
"#,
        )
        .unwrap();
        assert_eq!(c.inbounds[0].kind, InboundKind::Socks);
        assert_eq!(c.inbounds[0].allow_ip.len(), 1);
        assert_eq!(c.outbounds.len(), 2);
        assert!(!c.outbounds[0].xudp);
        assert!(c.outbounds[1].xudp, "xudp по умолчанию включён");
        assert_eq!(c.route.final_.as_deref(), Some("direct"));

        // Опечатка в имени поля — ошибка, а не молчаливое «не задано».
        let e = Config::parse("[[outbounds]]\ntag='a'\ntype='direct'\nxudpp=true\n").unwrap_err();
        assert!(e.to_string().contains("xudpp"), "{e}");
        assert!(
            Config::parse("[[inbounds]]\ntype='carrier-pigeon'\nlisten='127.0.0.1:1'\n").is_err()
        );
        assert!(Config::parse(
            "[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:1'\nallow_ip=['x']\n"
        )
        .is_err());

        // Windows-путь в двойных кавычках — ошибка с подсказкой.
        let e = Config::parse(
            "[[outbounds]]\ntag='a'\ntype='vless'\nlink_file=\"C:\\Users\\me\\s.txt\"\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("одинарных"), "{e}");
        let ok = Config::parse(
            "[[outbounds]]\ntag='a'\ntype='vless'\nlink_file='C:\\Users\\me\\s.txt'\n",
        )
        .unwrap();
        assert_eq!(
            ok.outbounds[0].link_file.as_deref(),
            Some(Path::new("C:\\Users\\me\\s.txt"))
        );

        // Пример из репозитория разбирается.
        let ex = Config::parse(include_str!("../../../examples/client.toml")).unwrap();
        assert_eq!(ex.outbounds.len(), 3);
        assert_eq!(ex.route.rules.len(), 3);
        assert_eq!(ex.inbounds[0].kind, InboundKind::Mixed);
        let dns = ex.dns.expect("в примере есть [dns]");
        assert_eq!(dns.servers.len(), 2);
        assert_eq!(dns.rules.len(), 1);
        assert_eq!(ex.route.final_.as_deref(), Some("proxy"));
    }
}
