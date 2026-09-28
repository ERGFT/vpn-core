// SPDX-License-Identifier: GPL-3.0-or-later
//! Файл настроек: формат sing-box или Xray-core (JSON, можно с
//! комментариями) — определяется сам, см. [`Config::parse`].
//!
//! Оба формата разбираются в одну внутреннюю модель ([`Config`]): её
//! заполняют [`singbox`] и [`xray`], ею пользуется всё остальное ядро.
//! Неизвестный или неподдерживаемый ключ — ошибка с путём до него.
//!
//! Относительные пути — от папки файла настроек.

pub mod link;
mod obj;
mod singbox;
mod xray;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::access::IpNet;
pub use super::rules::{PortSpec, RuleConfig};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub route: RouteConfig,
    /// Свой DNS (см. `super::dns`); не задан — имена разрешает система
    /// (для `direct`) или сервер VLESS.
    pub dns: Option<super::dns::DnsConfig>,
    /// Подписки: списки серверов с панели (см. `super::subscription`).
    pub subscriptions: Vec<super::subscription::SubscriptionConfig>,
    /// Локальное API (см. `super::api`).
    pub api: Option<super::api::ApiConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct InboundConfig {
    pub kind: InboundKind,
    pub tag: Option<String>,
    /// Адрес входа (у `tun` не бывает).
    pub listen: Option<SocketAddr>,
    /// `логин:пароль` прямо в файле (лучше — `auth_file`).
    pub auth: Option<String>,
    pub auth_file: Option<PathBuf>,
    pub allow_ip: Vec<IpNet>,
    pub max_conns: Option<usize>,
    /// Узнавать домен по первым байтам (TLS SNI, HTTP Host), когда
    /// приложение прислало IP, — для правил по доменам.
    pub sniff: bool,
    /// Подставлять найденный домен вместо IP (имя разрешит сервер).
    pub sniff_override_destination: bool,

    // ── только для входа tun ──
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
    pub route_exclude: Vec<IpNet>,
    /// Kill switch (Linux): если клиент упал, трафик не идёт мимо туннеля,
    /// пока клиент не запущен снова (или `--tun-cleanup`).
    pub strict_route: Option<bool>,
    /// Отвечать на DNS-запросы (порт 53 на любой адрес) своим DNS
    /// (по умолчанию да; нужен раздел `dns`).
    pub dns_hijack: Option<bool>,
}

impl InboundConfig {
    pub fn new(kind: InboundKind) -> Self {
        InboundConfig {
            kind,
            tag: None,
            listen: None,
            auth: None,
            auth_file: None,
            allow_ip: Vec::new(),
            max_conns: None,
            sniff: false,
            sniff_override_destination: false,
            interface_name: None,
            inet4_address: None,
            inet6_address: None,
            mtu: None,
            auto_route: None,
            route_exclude: Vec::new(),
            strict_route: None,
            dns_hijack: None,
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    Vless,
    /// Сервер Trojan (ссылка trojan://).
    Trojan,
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

#[derive(Debug, Clone)]
pub struct OutboundConfig {
    pub tag: String,
    pub kind: OutboundKind,
    /// vless: ссылка прямо в файле (лучше — `link_file`).
    pub link: Option<String>,
    pub link_file: Option<PathBuf>,
    /// vless: свои корневые сертификаты для `security=tls`.
    pub ca_file: Option<PathBuf>,
    /// vless: UDP через XUDP (по умолчанию) или поток на назначение.
    pub xudp: bool,
    /// vless: разрешить `security=none` (без шифрования).
    pub allow_insecure: bool,
    /// vless: Mux.Cool — до стольких TCP-соединений в одном потоке
    /// (как `mux.concurrency` у Xray; не вместе с Vision).
    pub mux: Option<u16>,
    /// vless, direct: дробить начало соединения (ClientHello) против DPI.
    pub fragment: Option<crate::transport::fragment::FragmentConfig>,
    /// direct: пакеты-пустышки перед первой UDP-датаграммой к адресу.
    pub noises: Vec<crate::transport::noise::NoiseConfig>,

    // ── только для групп (selector, urltest, fallback) ──
    /// Участники — tag других выходов (в том числе групп).
    pub outbounds: Vec<String>,
    /// Подписки, серверы которых входят в группу.
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
    pub fn new(tag: &str, kind: OutboundKind) -> Self {
        OutboundConfig {
            tag: tag.to_string(),
            kind,
            link: None,
            link_file: None,
            ca_file: None,
            xudp: true,
            allow_insecure: false,
            mux: None,
            fragment: None,
            noises: Vec::new(),
            outbounds: Vec::new(),
            subscriptions: Vec::new(),
            url: None,
            interval: None,
            tolerance: None,
            default: None,
        }
    }

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
        if !group && group_fields {
            return Err(Error::Config(format!(
                "выход {tag}: outbounds, subscriptions, url, interval, tolerance, default — только у групп (selector, urltest, fallback)"
            )));
        }
        let server_fields = self.link.is_some()
            || self.link_file.is_some()
            || self.ca_file.is_some()
            || self.allow_insecure;
        let server = matches!(self.kind, OutboundKind::Vless | OutboundKind::Trojan);
        if !server && server_fields {
            return Err(Error::Config(format!(
                "выход {tag}: link, link_file, ca_file, allow_insecure — только у vless и trojan"
            )));
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
}

#[derive(Debug, Clone, Default)]
pub struct RouteConfig {
    /// Правила по порядку; срабатывает первое подошедшее.
    pub rules: Vec<RuleConfig>,
    /// Выход по умолчанию; не задан — первый из `outbounds`.
    pub final_: Option<String>,
    /// База доменов для `"geosite": [...]` (по умолчанию `geosite.dat`
    /// рядом с файлом настроек).
    pub geosite_file: Option<PathBuf>,
    /// База адресов для `"geoip": [...]` (по умолчанию `geoip.dat`).
    pub geoip_file: Option<PathBuf>,
    /// `ip_if_non_match` — если ни одно правило не подошло к имени,
    /// разрешить его (DNS-модулем) и проверить правила по адресу.
    pub domain_strategy: DomainStrategy,
    /// Готовые наборы правил: `block-ads`, `private-direct`, `ru-direct`,
    /// `cn-direct`, `ir-direct` — после своих правил.
    pub presets: Vec<String>,
    /// Наборы правил sing-box: `route.rule_set` (tag, path) — для
    /// `"rule_set": [...]` в правилах маршрутизации и DNS.
    pub rule_set: Vec<super::ruleset::RuleSetConfig>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
}

impl Config {
    /// Разобрать текст настроек: формат sing-box или Xray-core
    /// определяется по содержимому.
    pub fn parse(text: &str) -> Result<Self> {
        let json = obj::strip_jsonc(text.trim_start_matches('\u{feff}'));
        if !json.trim_start().starts_with('{') {
            return Err(Error::Config(
                "ожидался JSON в формате sing-box или Xray-core (свой формат TOML больше не \
                 поддерживается — пример: examples/sing-box.json, examples/xray.json)"
                    .into(),
            ));
        }
        let v: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| Error::Config(format!("JSON: {e}")))?;
        let root = obj::Obj::new("", &v)?;
        let cfg = match detect(&v) {
            Format::SingBox => singbox::parse(&root)?,
            Format::Xray => xray::parse(&root)?,
        };
        root.ignore(&["subscriptions", "experimental"]);
        root.finish()?;
        Ok(cfg)
    }

    /// Файлы, на которые ссылаются настройки (после [`Config::load`] —
    /// с полными путями), и которые уже есть на диске: ссылки на серверы,
    /// пароли, сертификаты, базы и наборы правил, кеши подписок и fake-IP.
    /// Нужен, чтобы перенести настройки целиком (служба Windows).
    pub fn input_files(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = Vec::new();
        let mut add = |p: &Option<PathBuf>| {
            if let Some(p) = p {
                v.push(p.clone());
            }
        };
        for i in &self.inbounds {
            add(&i.auth_file);
        }
        for o in &self.outbounds {
            add(&o.link_file);
            add(&o.ca_file);
        }
        for s in &self.subscriptions {
            add(&s.url_file);
            add(&s.ca_file);
            add(&s.cache_file);
        }
        if let Some(a) = &self.api {
            add(&a.token_file);
        }
        add(&self.route.geosite_file);
        add(&self.route.geoip_file);
        if let Some(d) = &self.dns {
            for s in &d.servers {
                add(&s.ca_file);
            }
            if let Some(f) = &d.fakeip {
                add(&f.cache_file);
            }
        }
        v.extend(self.route.rule_set.iter().map(|r| r.path.clone()));
        v.retain(|p| p.is_file());
        v.sort();
        v.dedup();
        v
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
        for rs in &mut r.rule_set {
            if rs.path.is_relative() {
                rs.path = base.join(&rs.path);
            }
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    SingBox,
    Xray,
}

/// sing-box или Xray: у Xray входы и выходы с `protocol`, разделы
/// `routing`/`fakedns`/`observatory`; у sing-box — `type`, `route`.
fn detect(v: &serde_json::Value) -> Format {
    let has = |k: &str| v.get(k).is_some();
    let entries_have = |k: &str| {
        ["inbounds", "outbounds"].iter().any(|list| {
            v.get(list)
                .and_then(|l| l.as_array())
                .is_some_and(|a| a.iter().any(|e| e.get(k).is_some()))
        })
    };
    if entries_have("protocol")
        || has("routing")
        || has("fakedns")
        || has("observatory")
        || has("burstObservatory")
        || has("policy")
    {
        Format::Xray
    } else {
        Format::SingBox
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
    fn singbox_example() {
        let c = Config::parse(include_str!("../../../../examples/sing-box.json")).unwrap();
        assert_eq!(c.inbounds.len(), 1);
        let i = &c.inbounds[0];
        assert_eq!(i.kind, InboundKind::Mixed);
        assert_eq!(i.listen, Some("127.0.0.1:1080".parse().unwrap()));
        assert!(i.sniff, "action: sniff без inbound — у всех входов");
        // proxy, direct, block + скрытый выход для hijack-dns.
        let tags: Vec<&str> = c.outbounds.iter().map(|o| o.tag.as_str()).collect();
        assert_eq!(tags, ["proxy", "direct", "block", "__hijack_dns"]);
        let link = c.outbounds[0].link.as_deref().unwrap();
        let v = crate::vless::VlessConfig::parse(link).unwrap();
        assert_eq!(v.host, "server.example.com");
        assert_eq!(v.security, crate::vless::Security::Reality);
        assert!(v.flow.is_vision());
        assert_eq!(v.sni.as_deref(), Some("www.example.com"));
        assert_eq!(c.route.final_.as_deref(), Some("proxy"));
        // sniff — не правило; hijack-dns — правило порта 53.
        assert_eq!(c.route.rules.len(), 4);
        assert_eq!(c.route.rules[0].outbound, "__hijack_dns");
        let dns = c.dns.unwrap();
        assert_eq!(dns.servers[0].address, "https://1.1.1.1:443/dns-query");
        assert_eq!(dns.servers[1].detour.as_deref(), Some("direct"));
        assert_eq!(dns.rules.len(), 1);
    }

    #[test]
    fn xray_example() {
        let c = Config::parse(include_str!("../../../../examples/xray.json")).unwrap();
        assert_eq!(c.inbounds[0].kind, InboundKind::Socks);
        assert!(c.inbounds[0].sniff);
        assert!(
            !c.inbounds[0].sniff_override_destination,
            "routeOnly — домен только для правил"
        );
        let tags: Vec<&str> = c.outbounds.iter().map(|o| o.tag.as_str()).collect();
        assert_eq!(tags, ["proxy", "direct", "block"]);
        let v = crate::vless::VlessConfig::parse(c.outbounds[0].link.as_deref().unwrap()).unwrap();
        assert_eq!(v.port, 443);
        assert_eq!(v.security, crate::vless::Security::Reality);
        assert_eq!(c.route.rules.len(), 4);
        assert_eq!(c.route.rules[0].geosite, ["category-ads-all"]);
        assert_eq!(c.route.rules[1].geoip, ["private"]);
        let dns = c.dns.unwrap();
        assert_eq!(dns.servers.len(), 2);
        assert_eq!(
            dns.servers[1].detour.as_deref(),
            Some("direct"),
            "+local — напрямую"
        );
        assert_eq!(dns.rules[0].geosite, ["category-ru"]);
        assert_eq!(dns.final_.as_deref(), Some("dns-0"));
    }

    #[test]
    fn errors_name_the_key() {
        let e = Config::parse(r#"{"outbounds":[{"type":"direct","tag":"d","typo":1}]}"#)
            .unwrap_err()
            .to_string();
        assert!(e.contains("outbounds[0]") && e.contains("typo"), "{e}");
        let e = Config::parse(r#"{"outbounds":[{"type":"shadowsocks","tag":"s"}]}"#)
            .unwrap_err()
            .to_string();
        assert!(e.contains("shadowsocks"), "{e}");
        let e = Config::parse(r#"{"outbounds":[{"protocol":"vmess"}]}"#)
            .unwrap_err()
            .to_string();
        assert!(e.contains("vmess"), "{e}");
        let e = Config::parse("[[inbounds]]\ntype = 'socks'\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("TOML"), "{e}");
    }

    #[test]
    fn xray_balancer_becomes_urltest() {
        let c = Config::parse(
            r#"{
              "outbounds": [
                {"tag": "de", "protocol": "trojan", "settings": {"servers": [{"address": "de.example", "port": 443, "password": "p"}]}},
                {"tag": "fi", "protocol": "trojan", "settings": {"servers": [{"address": "fi.example", "port": 443, "password": "p"}]}},
                {"tag": "direct", "protocol": "freedom"}
              ],
              "routing": {
                "rules": [{"type": "field", "port": "0-65535", "balancerTag": "auto"}],
                "balancers": [{"tag": "auto", "selector": ["de", "fi"], "strategy": {"type": "leastPing"}}]
              },
              "observatory": {"subjectSelector": ["de", "fi"], "probeURL": "https://cp.example/204", "probeInterval": "1m"}
            }"#,
        )
        .unwrap();
        let g = c.outbounds.iter().find(|o| o.tag == "auto").unwrap();
        assert_eq!(g.kind, OutboundKind::Urltest);
        assert_eq!(g.outbounds, ["de", "fi"]);
        assert_eq!(g.url.as_deref(), Some("https://cp.example/204"));
        assert_eq!(g.interval, Some(60));
        assert_eq!(
            c.outbounds[0].tag, "de",
            "первый выход — как у Xray, по умолчанию"
        );
    }
}
