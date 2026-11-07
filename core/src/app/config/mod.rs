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
mod outbound;
mod singbox;
mod xray;

pub use outbound::OutboundConfig;
pub(crate) use outbound::OutboundSettings;
use outbound::RawOutboundConfig;

use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;

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
    /// Виртуальный сетевой интерфейс для системного трафика; ядро обрабатывает
    /// TCP/UDP, а остальные IP-пакеты отбрасывает.
    Tun,
}

impl InboundKind {
    /// Имя вида, как в настройках: `socks`, `http`, `mixed`, `dns`, `tun`.
    pub fn name(self) -> &'static str {
        match self {
            InboundKind::Socks => "socks",
            InboundKind::Http => "http",
            InboundKind::Mixed => "mixed",
            InboundKind::Dns => "dns",
            InboundKind::Tun => "tun",
        }
    }
}

#[derive(Clone)]
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
    /// Для TUN без внешнего дескриптора направить системные IP-маршруты через
    /// интерфейс (по умолчанию да); ядро обрабатывает TCP/UDP, прочие IP-пакеты
    /// отбрасывает.
    pub auto_route: Option<bool>,
    /// Подсети, которые остаются мимо TUN.
    pub route_exclude: Vec<IpNet>,
    /// Kill switch для TUN с маршрутами ядра: правило `unreachable` на Linux,
    /// фильтры WFP на Windows. При внешнем FD им управляет система; поведение
    /// при сбое и очистка различаются по платформам, см. руководство TUN.
    pub strict_route: Option<bool>,
    /// Отвечать на DNS-запросы (порт 53 на любой адрес) своим DNS
    /// (по умолчанию да; нужен раздел `dns`).
    pub dns_hijack: Option<bool>,
    /// Готовый совместимый дескриптор TUN от host-приложения — только в
    /// режиме библиотеки; маршруты тогда ставит система. Android `VpnService`
    /// предоставляет такой FD. iOS `NEPacketTunnelFlow` не является FD, и
    /// текущий C ABI не содержит адаптера для packet-flow API.
    pub tun_fd: Option<i32>,
    /// Владелец системного дескриптора TUN: держит его открытым при разборе
    /// настроек и запуске, чтобы при ошибке он не остался незакрытым.
    #[cfg(unix)]
    pub tun_fd_owner: Option<Arc<OwnedFd>>,
}

impl std::fmt::Debug for InboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundConfig")
            .field("kind", &self.kind)
            .field("tag", &self.tag)
            .field("listen", &self.listen)
            .field("auth", &crate::redact::opt(&self.auth))
            .field("auth_file", &self.auth_file)
            .field("allow_ip", &self.allow_ip)
            .field("max_conns", &self.max_conns)
            .field("sniff", &self.sniff)
            .field(
                "sniff_override_destination",
                &self.sniff_override_destination,
            )
            .field("interface_name", &self.interface_name)
            .field("inet4_address", &self.inet4_address)
            .field("inet6_address", &self.inet6_address)
            .field("mtu", &self.mtu)
            .field("auto_route", &self.auto_route)
            .field("route_exclude", &self.route_exclude)
            .field("strict_route", &self.strict_route)
            .field("dns_hijack", &self.dns_hijack)
            .field("tun_fd", &self.tun_fd)
            .finish()
    }
}

impl InboundConfig {
    /// Вход TUN, который сам ставит маршруты (`auto_route`): не с готовым
    /// дескриптором и не выключен явно.
    pub fn wants_auto_route(&self) -> bool {
        self.kind == InboundKind::Tun && self.tun_fd.is_none() && self.auto_route.unwrap_or(true)
    }
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
            tun_fd: None,
            #[cfg(unix)]
            tun_fd_owner: None,
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
    /// Hysteria 2 over QUIC (sharing link in `link` or `link_file`).
    Hysteria2,
    /// Shadowsocks classic AEAD proxy (sharing link in `link` or `link_file`).
    Shadowsocks,
    /// SOCKS5 proxy для исходящих TCP CONNECT-соединений.
    Socks5,
    /// HTTP CONNECT proxy для исходящих TCP-соединений.
    HttpConnect,
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
        let outbound_paths: Vec<PathBuf> = self
            .outbounds
            .iter()
            .flat_map(|outbound| outbound.referenced_paths())
            .filter(|path| path.is_file())
            .cloned()
            .collect();
        let mut v: Vec<PathBuf> = outbound_paths;
        let mut add = |p: &Option<PathBuf>| {
            if let Some(p) = p {
                v.push(p.clone());
            }
        };
        for i in &self.inbounds {
            add(&i.auth_file);
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
        Self::parse_at(&text, path.parent().unwrap_or(Path::new(".")))
    }

    /// Разобрать текст настроек так, будто файл лежит в папке `base`:
    /// относительные пути — от неё.
    pub fn parse_at(text: &str, base: &Path) -> Result<Self> {
        let mut cfg = Self::parse(text)?;
        for sub in &mut cfg.subscriptions {
            let tag = sub.tag.clone();
            sub.cache_file
                .get_or_insert_with(|| format!("{tag}.subscription").into());
        }
        let r = &mut cfg.route;
        r.geosite_file.get_or_insert_with(|| "geosite.dat".into());
        r.geoip_file.get_or_insert_with(|| "geoip.dat".into());
        cfg.for_each_path(&mut |p| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        });
        Ok(cfg)
    }

    /// Все пути к файлам и папкам, упомянутые в настройках.
    pub fn for_each_path(&mut self, f: &mut dyn FnMut(&mut PathBuf)) {
        let opt = |p: &mut Option<PathBuf>, f: &mut dyn FnMut(&mut PathBuf)| {
            if let Some(v) = p {
                f(v);
            }
        };
        for i in &mut self.inbounds {
            opt(&mut i.auth_file, f);
        }
        for o in &mut self.outbounds {
            o.for_each_path(f);
        }
        for sub in &mut self.subscriptions {
            opt(&mut sub.url_file, f);
            opt(&mut sub.ca_file, f);
            opt(&mut sub.cache_file, f);
        }
        if let Some(a) = &mut self.api {
            opt(&mut a.token_file, f);
            opt(&mut a.external_ui, f);
        }
        let r = &mut self.route;
        opt(&mut r.geosite_file, f);
        opt(&mut r.geoip_file, f);
        for rs in &mut r.rule_set {
            f(&mut rs.path);
        }
        if let Some(d) = &mut self.dns {
            for s in &mut d.servers {
                opt(&mut s.ca_file, f);
            }
            if let Some(fk) = &mut d.fakeip {
                opt(&mut fk.cache_file, f);
            }
        }
    }

    /// Настройки, присланные через API: файлы — только из папки настроек
    /// (относительные пути без `..`). Иначе тот, у кого есть токен API,
    /// мог бы заставить клиент (служба Windows — от SYSTEM) читать и
    /// писать любые файлы компьютера.
    pub fn check_paths_confined(&mut self) -> Result<()> {
        let mut bad = None;
        self.for_each_path(&mut |p| {
            let ok = p.components().all(|c| {
                matches!(
                    c,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            });
            if !ok && bad.is_none() {
                bad = Some(p.display().to_string());
            }
        });
        match bad {
            Some(p) => Err(Error::Config(format!(
                "«{p}»: в настройках через API — только файлы из папки настроек \
                 (относительный путь без ..)"
            ))),
            None => Ok(()),
        }
    }

    /// Вторая ступень [`Self::check_paths_confined`] — для настроек после
    /// [`Self::parse_at`] (пути уже от `base`, подставлены пути по
    /// умолчанию): каждый файл после разрешения символических ссылок лежит
    /// внутри `base`. Ссылка в папке настроек, ведущая наружу, иначе
    /// обошла бы проверку по компонентам пути. Для ещё не созданного файла
    /// проверяется ближайшая существующая папка над ним.
    pub fn check_paths_inside(&mut self, base: &Path) -> Result<()> {
        let root = base
            .canonicalize()
            .map_err(|e| Error::Config(format!("папка настроек {}: {e}", base.display())))?;
        let mut bad = None;
        self.for_each_path(&mut |p| {
            if bad.is_none() && !resolves_inside(p, &root) {
                bad = Some(p.display().to_string());
            }
        });
        match bad {
            Some(p) => Err(Error::Config(format!(
                "«{p}»: в настройках через API — только файлы из папки настроек \
                 (путь ведёт за её пределы, в том числе через символическую ссылку)"
            ))),
            None => Ok(()),
        }
    }

    /// Формат текста настроек: `sing-box` или `xray`.
    pub fn format_name(text: &str) -> &'static str {
        let json = obj::strip_jsonc(text.trim_start_matches('\u{feff}'));
        match serde_json::from_str::<serde_json::Value>(&json).map(|v| detect(&v)) {
            Ok(Format::Xray) => "xray",
            _ => "sing-box",
        }
    }
}

/// `p` после разрешения символических ссылок — внутри `root` (уже
/// канонического). Несуществующий хвост пути — только обычные имена.
fn resolves_inside(p: &Path, root: &Path) -> bool {
    let mut cur = p.to_path_buf();
    let mut tail = Vec::new();
    let real = loop {
        match cur.canonicalize() {
            Ok(c) => break c,
            Err(_) => {
                // Нет имени (`..`, корень) — не проверить, значит нельзя.
                let Some(name) = cur.file_name() else {
                    return false;
                };
                tail.push(name.to_owned());
                if !cur.pop() {
                    return false;
                }
            }
        }
    };
    real.starts_with(root) && tail.iter().all(|n| n != "..")
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
        let link = c.outbounds[0].as_vless().unwrap().link.read().unwrap();
        let v = crate::vless::VlessConfig::parse(link.as_str()).unwrap();
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
        let v = crate::vless::VlessConfig::parse(
            &c.outbounds[0].as_vless().unwrap().link.read().unwrap(),
        )
        .unwrap();
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
        assert!(e.to_lowercase().contains("shadowsocks"), "{e}");
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
    fn xray_shadowsocks_outbound_normalizes_one_aead_server() {
        let config = Config::parse(
            r#"{"outbounds":[{"protocol":"shadowsocks","tag":"ss","settings":{"servers":[{"address":"ss.example","port":8388,"method":"chacha20-poly1305","password":"secret","level":0}]}}]}"#,
        )
        .unwrap();
        assert_eq!(config.outbounds[0].kind(), OutboundKind::Shadowsocks);
        assert!(!format!("{:?}", config.outbounds[0]).contains("secret"));
    }

    #[test]
    fn xray_shadowsocks_2022_accepts_psk_and_rejects_invalid_key_length() {
        let valid = Config::parse(
            r#"{"outbounds":[{"protocol":"shadowsocks","tag":"ss22","settings":{"servers":[{"address":"ss.example","port":8388,"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA=="}]}}]}"#,
        )
        .unwrap();
        assert_eq!(valid.outbounds[0].kind(), OutboundKind::Shadowsocks);
        assert!(!format!("{:?}", valid.outbounds[0]).contains("AAAAAAAA"));

        let invalid = Config::parse(
            r#"{"outbounds":[{"protocol":"shadowsocks","tag":"ss22","settings":{"servers":[{"address":"ss.example","port":8388,"method":"2022-blake3-aes-128-gcm","password":"c2hvcnQ="}]}}]}"#,
        );
        assert!(invalid.is_err());
    }

    #[test]
    fn singbox_socks_outbound_is_tcp_only_and_redacts_credentials() {
        let c = Config::parse(
            r#"{"outbounds":[{"type":"socks","tag":"proxy","server":"proxy.example","server_port":1080,"network":"tcp","username":"private-user","password":"private-pass"}]}"#,
        )
        .unwrap();
        let out = &c.outbounds[0];
        assert_eq!(out.kind(), OutboundKind::Socks5);
        assert!(out.as_vless().is_none());
        let socks = out.socks5().unwrap();
        assert_eq!(socks.server, "proxy.example");
        assert_eq!(socks.port, 1080);
        let debug = format!("{out:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-pass"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn singbox_socks_supports_password_file_extension() {
        let c = Config::parse(
            r#"{"outbounds":[{"type":"socks","tag":"proxy","server":"proxy.example","server_port":1080,"network":"tcp","username":"user","password_file":"proxy.pass"}]}"#,
        )
        .unwrap();
        let socks = c.outbounds[0].socks5().unwrap();
        let auth = socks.auth.as_ref().unwrap();
        assert_eq!(auth.username, "user");
        assert!(matches!(
            &auth.password,
            super::outbound::SecretSource::File(path)
                if path == std::path::Path::new("proxy.pass")
        ));
    }

    #[test]
    fn outbound_file_secrets_are_confined_and_listed_as_inputs() {
        let filename = format!(
            "vpn-core-proxy-password-{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(&filename);
        std::fs::write(&path, "not-a-real-password").unwrap();
        let config = format!(
            r#"{{"outbounds":[{{"type":"socks","tag":"proxy","server":"proxy.example","server_port":1080,"network":"tcp","username":"user","password_file":"{filename}"}}]}}"#
        );
        let parsed = Config::parse_at(&config, &temp_dir).unwrap();
        assert!(parsed.input_files().contains(&path));
        std::fs::remove_file(&path).unwrap();

        let unsafe_config = r#"{"outbounds":[{"type":"socks","tag":"proxy","server":"proxy.example","server_port":1080,"network":"tcp","username":"user","password_file":"../outside.txt"}]}"#;
        let mut parsed = Config::parse(unsafe_config).unwrap();
        assert!(parsed.check_paths_confined().is_err());
    }

    #[test]
    fn singbox_http_and_socks_outbounds_parse_detour_tags() {
        let c = Config::parse(
            r#"{"outbounds":[{"type":"socks","tag":"first","server":"socks.example","server_port":1080,"network":"tcp"},{"type":"http","tag":"second","server":"http.example","server_port":8080,"detour":"first"}]}"#,
        )
        .unwrap();
        assert_eq!(c.outbounds[0].detour(), None);
        assert_eq!(c.outbounds[1].detour(), Some("first"));
    }

    #[test]
    fn singbox_rejects_detour_on_unsupported_outbound_types() {
        let error =
            Config::parse(r#"{"outbounds":[{"type":"direct","tag":"direct","detour":"other"}]}"#)
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("цепочки доступны только у SOCKS5 и HTTP CONNECT"),
            "{error}"
        );
    }

    #[test]
    fn singbox_hysteria2_outbound_parses_with_redacted_secret() {
        let config = Config::parse(
            r#"{"outbounds":[{"type":"hysteria2","tag":"hy2","server":"example.com","server_port":443,"password":"secret","tls":{},"ca_file":"certs/hy2-root.pem"}]}"#,
        )
        .unwrap();
        assert_eq!(config.outbounds[0].kind(), OutboundKind::Hysteria2);
        assert_eq!(
            config.outbounds[0]
                .hysteria2_ca_file()
                .map(std::path::PathBuf::as_path),
            Some(std::path::Path::new("certs/hy2-root.pem"))
        );
        let debug = format!("{:?}", config.outbounds[0]);
        assert!(!debug.contains("secret"), "{debug}");
    }

    #[test]
    fn singbox_socks_rejects_unsupported_or_incomplete_settings() {
        for (config, expected) in [
            (
                r#"{"outbounds":[{"type":"socks","tag":"p","server":"proxy.example","network":"tcp"}]}"#,
                "server_port",
            ),
            (
                r#"{"outbounds":[{"type":"socks","tag":"p","server":"proxy.example","server_port":1080,"network":"tcp","username":"user"}]}"#,
                "username и password",
            ),
            (
                r#"{"outbounds":[{"type":"socks","tag":"p","server":"proxy.example","server_port":1080,"network":"tcp","version":"4"}]}"#,
                "version",
            ),
            (
                r#"{"outbounds":[{"type":"socks","tag":"p","server":"proxy.example","server_port":1080,"network":"tcp","tls":{"enabled":true}}]}"#,
                "TLS",
            ),
            (
                r#"{"outbounds":[{"type":"socks","tag":"p","server":"proxy.example","server_port":1080,"network":"tcp","udp_over_tcp":true}]}"#,
                "UDP-over-TCP",
            ),
            (
                r#"{"outbounds":[{"type":"socks","tag":"p","server":"proxy.example","server_port":1080}]}"#,
                "network",
            ),
            (
                r#"{"outbounds":[{"type":"socks","tag":"p","server":"proxy.example","server_port":1080,"network":"udp"}]}"#,
                "UDP",
            ),
        ] {
            let error = Config::parse(config).unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }

    #[test]
    fn singbox_http_connect_outbound_supports_basic_auth_and_verified_tls() {
        let c = Config::parse(
            r#"{"outbounds":[{"type":"http","tag":"proxy","server":"proxy.example","server_port":8443,"username":"private-user","password":"private-pass","tls":{"enabled":true,"server_name":"tls.example"},"ca_file":"proxy-ca.pem"}]}"#,
        )
        .unwrap();
        let out = &c.outbounds[0];
        assert_eq!(out.kind(), OutboundKind::HttpConnect);
        let http = out.http_connect().unwrap();
        assert_eq!(http.proxy.server, "proxy.example");
        assert_eq!(http.proxy.port, 8443);
        assert!(http.tls);
        assert_eq!(http.tls_server_name.as_deref(), Some("tls.example"));
        assert_eq!(
            http.ca_file.as_deref(),
            Some(std::path::Path::new("proxy-ca.pem"))
        );
        let debug = format!("{out:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-pass"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn singbox_http_connect_rejects_incomplete_or_unsafe_options() {
        for (config, expected) in [
            (
                r#"{"outbounds":[{"type":"http","tag":"p","server":"proxy.example"}]}"#,
                "server_port",
            ),
            (
                r#"{"outbounds":[{"type":"http","tag":"p","server":"proxy.example","server_port":8080,"username":"user"}]}"#,
                "username и password",
            ),
            (
                r#"{"outbounds":[{"type":"http","tag":"p","server":"proxy.example","server_port":8080,"username":"user:bad","password":"pass"}]}"#,
                "Basic auth",
            ),
            (
                r#"{"outbounds":[{"type":"http","tag":"p","server":"proxy.example","server_port":8080,"version":2}]}"#,
                "HTTP/1.1",
            ),
            (
                r#"{"outbounds":[{"type":"http","tag":"p","server":"proxy.example","server_port":8080,"tls":{"enabled":true,"insecure":true}}]}"#,
                "отключение проверки сертификата",
            ),
        ] {
            let error = Config::parse(config).unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
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
        assert_eq!(g.kind(), OutboundKind::Urltest);
        let OutboundSettings::Urltest(urltest) = &g.settings else {
            panic!("Xray balancer must normalize to urltest");
        };
        assert_eq!(urltest.outbounds, ["de", "fi"]);
        assert_eq!(urltest.url.as_deref(), Some("https://cp.example/204"));
        assert_eq!(urltest.interval, Some(60));
        assert_eq!(
            c.outbounds[0].tag, "de",
            "первый выход — как у Xray, по умолчанию"
        );
    }
}
