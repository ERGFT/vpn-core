// SPDX-License-Identifier: GPL-3.0-or-later
//! Маршрутизатор: по данным соединения выбирает выход — по правилам
//! (`route.rules`, первое подошедшее), иначе выход по умолчанию
//! (`route.final`).
//!
//! Перед правилами адрес fake-IP заменяется исходным именем. Если ни одно
//! правило не подошло, а `domain_strategy` — `ip_if_non_match`, имя
//! разрешается DNS-модулем и правила проверяются ещё раз — по адресу
//! (например, `"geoip": ["ru"]` для сайта, которого нет в geosite).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::config::{DomainStrategy, RouteConfig};
use super::dns::fakeip::Reverse;
use super::dns::Dns;
use super::outbound::Outbound;
use super::rules::{self, GeoFiles, Rule};
use super::stats::{ConnInfo, Counted, Mode, Tracker};
use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::AsyncStream;
use crate::vless::Address;

/// Потолок длины имени: поле длины в заголовках выходов — один байт.
const MAX_DOMAIN_LEN: usize = 255;

pub struct Router {
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    rules: Vec<Rule>,
    final_: Arc<dyn Outbound>,
    dns: Option<Arc<Dns>>,
    domain_strategy: DomainStrategy,
    /// Учёт соединений (переживает перечитывание настроек).
    tracker: Arc<Tracker>,
    /// Группа `GLOBAL` — выход в режиме global.
    global: Option<Arc<dyn Outbound>>,
    /// Выход в режиме direct.
    direct: Option<Arc<dyn Outbound>>,
}

/// Текущий маршрутизатор. Перечитывание настроек подменяет его целиком;
/// открытые соединения живут со старыми выходами, новые идут по новым
/// правилам.
pub struct RouterHandle(RwLock<Arc<Router>>);

impl RouterHandle {
    pub fn new(r: Router) -> Arc<Self> {
        Arc::new(RouterHandle(RwLock::new(Arc::new(r))))
    }

    pub fn get(&self) -> Arc<Router> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn set(&self, r: Arc<Router>) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = r;
    }
}

impl Router {
    /// `inbound_tags` — чтобы правило с опечаткой в имени входа было
    /// ошибкой, а не правилом, которое никогда не срабатывает.
    pub fn new(
        outbounds: Vec<Arc<dyn Outbound>>,
        route: &RouteConfig,
        inbound_tags: &[String],
        geo: &GeoFiles,
    ) -> Result<Self> {
        let first = outbounds
            .first()
            .cloned()
            .ok_or_else(|| Error::Config("не задан ни один выход (outbound)".into()))?;
        let mut map = HashMap::new();
        for o in outbounds {
            if map.insert(o.tag().to_string(), o.clone()).is_some() {
                return Err(Error::Config(format!(
                    "два выхода с одинаковым tag = \"{}\"",
                    o.tag()
                )));
            }
        }
        let final_ = match route.final_.as_deref() {
            Some(t) => map
                .get(t)
                .cloned()
                .ok_or_else(|| Error::Config(format!("route.final: нет выхода «{t}»")))?,
            None => first,
        };
        let mut rules = Vec::with_capacity(route.rules.len());
        for (i, r) in route.rules.iter().enumerate() {
            let out = map.get(&r.outbound).cloned().ok_or_else(|| {
                Error::Config(format!(
                    "правило {}: нет выхода с tag = \"{}\"",
                    i + 1,
                    r.outbound
                ))
            })?;
            if let Some(t) = r.inbound.iter().find(|t| !inbound_tags.contains(t)) {
                return Err(Error::Config(format!(
                    "правило {}: нет входа с tag = \"{t}\"",
                    i + 1
                )));
            }
            rules.push(rules::compile(i, r, out, geo)?);
        }
        if !rules.is_empty() {
            tracing::info!(rules = rules.len(), "правила маршрутизации загружены");
        }
        Ok(Router {
            outbounds: map,
            rules,
            final_,
            dns: None,
            domain_strategy: route.domain_strategy,
            tracker: Tracker::new(),
            global: None,
            direct: None,
        })
    }

    /// Выходы режимов global и direct.
    pub fn set_modes(&mut self, global: Option<Arc<dyn Outbound>>, direct: Arc<dyn Outbound>) {
        self.global = global;
        self.direct = Some(direct);
    }

    /// Правила с их выходами — для API (`GET /rules`).
    pub fn rules(&self) -> impl Iterator<Item = (&str, &str)> {
        self.rules.iter().map(|r| (&*r.label, r.outbound.tag()))
    }

    /// Все выходы (для API), без скрытых служебных.
    pub fn outbounds(&self) -> Vec<Arc<dyn Outbound>> {
        self.outbounds
            .values()
            .filter(|o| !o.tag().starts_with("__"))
            .cloned()
            .collect()
    }

    pub fn final_tag(&self) -> &str {
        self.final_.tag()
    }

    pub fn set_tracker(&mut self, t: Arc<Tracker>) {
        self.tracker = t;
    }

    pub fn tracker(&self) -> &Arc<Tracker> {
        &self.tracker
    }

    pub fn dns(&self) -> Option<&Arc<Dns>> {
        self.dns.as_ref()
    }

    /// Группы серверов (выходы selector/urltest/fallback).
    pub fn groups(&self) -> Vec<Arc<dyn Outbound>> {
        let mut v: Vec<Arc<dyn Outbound>> = self
            .outbounds
            .values()
            .filter(|o| o.as_group().is_some())
            .cloned()
            .collect();
        v.sort_by(|a, b| a.tag().cmp(b.tag()));
        v
    }

    /// Открыть TCP-соединение через выход и начать его учёт (трафик,
    /// список соединений, закрытие через API).
    pub async fn dial(
        &self,
        outbound: &Arc<dyn Outbound>,
        meta: &Metadata,
    ) -> Result<(Box<dyn AsyncStream>, Arc<ConnInfo>)> {
        let s = outbound.connect(meta).await?;
        let member = outbound.as_group().and_then(|g| g.current());
        let guard = self.tracker.open(meta, outbound.tag(), member);
        let info = guard.info.clone();
        Ok((Box::new(Counted::new(s, guard)), info))
    }

    /// Подключить DNS-модуль (fake-IP и `ip_if_non_match`).
    pub fn set_dns(&mut self, dns: Arc<Dns>) {
        self.dns = Some(dns);
    }

    /// Выход для соединения с учётом fake-IP и `domain_strategy`.
    /// `meta.target` с fake-IP заменяется именем. Ошибка — адрес из
    /// диапазона fake-IP, для которого имя неизвестно.
    pub async fn route(&self, meta: &mut Metadata) -> Result<Arc<dyn Outbound>> {
        if let Some(dns) = &self.dns {
            let ip = match &meta.target {
                Address::Ipv4(v4) => Some(std::net::IpAddr::V4(*v4)),
                Address::Ipv6(v6) => Some(std::net::IpAddr::V6(*v6)),
                Address::Domain(_) => None,
            };
            if let Some(ip) = ip {
                match dns.reverse(ip) {
                    Reverse::NotFake => {}
                    Reverse::Name(n) => meta.target = Address::Domain(n),
                    Reverse::Unknown => {
                        return Err(Error::Protocol(format!(
                            "адрес {ip} из диапазона fake-IP, но имя для него неизвестно (устарел после перезапуска?)"
                        )))
                    }
                }
            }
        }
        // Длина имени в заголовках VLESS, Mux.Cool, XUDP и Trojan — один
        // байт: длиннее 255 закодировалось бы с обрезанной длиной (битый
        // заголовок) или обрезанным именем. Такое имя бывает из fake-IP:
        // текст имени DNS-запроса с экранированными байтами (`\.`)
        // длиннее его 255 байт на проводе.
        if let Address::Domain(d) = &meta.target {
            if d.len() > MAX_DOMAIN_LEN {
                return Err(Error::Protocol(format!(
                    "имя длиннее {MAX_DOMAIN_LEN} байт ({}) — его нельзя передать серверу",
                    d.len()
                )));
            }
        }
        let mode = self.tracker.mode();
        if mode != Mode::Rule {
            // Перехват DNS — в любом режиме: иначе DNS-запросы программ
            // ушли бы на сервер как обычный трафик.
            if let Some(r) = self
                .rules
                .iter()
                .find(|r| r.outbound.is_dns() && r.matches(meta))
            {
                meta.rule = Some(r.label.clone());
                return Ok(r.outbound.clone());
            }
            let out = match mode {
                Mode::Global => self.global.clone(),
                _ => self.direct.clone(),
            };
            if let Some(o) = out {
                meta.rule = Some(format!("mode={}", mode.clash_name().to_ascii_lowercase()).into());
                return Ok(o);
            }
        }
        if let Some(o) = self.match_rules(meta) {
            return Ok(o);
        }
        if self.domain_strategy == DomainStrategy::IpIfNonMatch
            && self.rules.iter().any(Rule::has_ip)
        {
            if let (Address::Domain(d), Some(dns)) = (&meta.target, &self.dns) {
                match dns.lookup(d).await {
                    Ok(ips) => {
                        for ip in ips {
                            let mut m = meta.clone();
                            m.target = match ip {
                                std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
                                std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
                            };
                            if let Some(o) = self.match_rules(&mut m) {
                                meta.rule = m.rule;
                                return Ok(o);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(domain = %d, error = %e, "ip_if_non_match: имя не разрешилось")
                    }
                }
            }
        }
        Ok(self.final_.clone())
    }

    /// Выход для соединения только по правилам (без DNS).
    pub fn select(&self, meta: &Metadata) -> Arc<dyn Outbound> {
        let mut m = meta.clone();
        self.match_rules(&mut m)
            .unwrap_or_else(|| self.final_.clone())
    }

    fn match_rules(&self, meta: &mut Metadata) -> Option<Arc<dyn Outbound>> {
        for r in &self.rules {
            if r.matches(meta) {
                meta.rule = Some(r.label.clone());
                tracing::debug!(
                    rule = r.index + 1,
                    outbound = r.outbound.tag(),
                    target = %meta.target,
                    sniffed = ?meta.sniffed,
                    "маршрут по правилу"
                );
                return Some(r.outbound.clone());
            }
        }
        None
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(tag).cloned()
    }

    /// Нужны ли правилам домены (тогда имеет смысл sniffing).
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::config::Config;
    use crate::app::geo::tests::{build_ips, build_sites};
    use crate::app::outbound::{BlockOutbound, DirectOutbound};
    use crate::app::Network;
    use crate::vless::Address;
    use std::path::Path;

    fn outs() -> Vec<Arc<dyn Outbound>> {
        vec![
            Arc::new(DirectOutbound::new("direct")),
            Arc::new(BlockOutbound::new("block")),
            Arc::new(DirectOutbound::new("proxy")),
        ]
    }

    fn meta(target: Address, sniffed: Option<&str>) -> Metadata {
        Metadata {
            inbound: "in".into(),
            source: "127.0.0.1:1".parse().unwrap(),
            network: Network::Tcp,
            target,
            port: 443,
            sniffed: sniffed.map(str::to_string),
            inbound_type: "socks",
            rule: None,
        }
    }

    fn dom(d: &str) -> Address {
        Address::Domain(d.into())
    }

    fn router(dir: &Path, rules: &str) -> Router {
        // Пути — строкой JSON: в Windows-путях есть «\».
        let q = |f: &str| serde_json::to_string(&dir.join(f).display().to_string()).unwrap();
        let cfg = Config::parse(&format!(
            r#"{{"route": {{"rules": [{rules}], "final": "proxy",
                           "geosite_file": {}, "geoip_file": {}}}}}"#,
            q("geosite.dat"),
            q("geoip.dat")
        ))
        .unwrap();
        let geo = GeoFiles::load(
            cfg.route
                .rules
                .iter()
                .flat_map(|r| r.geosite.clone())
                .collect(),
            cfg.route
                .rules
                .iter()
                .flat_map(|r| r.geoip.clone())
                .collect(),
            cfg.route.geosite_file.as_deref().unwrap(),
            cfg.route.geoip_file.as_deref().unwrap(),
        )
        .unwrap();
        Router::new(outs(), &cfg.route, &["in".into()], &geo).unwrap()
    }

    #[test]
    fn geosite_and_geoip_rules() {
        let dir = std::env::temp_dir().join(format!("vpn-core-geo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("geosite.dat"),
            build_sites(&[
                (
                    "category-ads",
                    &[(2, "adnet.test", &[]), (0, "tracker", &[])],
                ),
                ("ru", &[(2, "ru", &[]), (3, "vk.com", &[])]),
            ]),
        )
        .unwrap();
        std::fs::write(dir.join("geoip.dat"), build_ips(&[("ru", &["5.8.0.0/16"])])).unwrap();
        let r = router(
            &dir,
            r#"{"geosite": ["category-ads"], "outbound": "block"},
               {"geosite": ["ru"], "geoip": ["RU"], "outbound": "direct"}"#,
        );
        let pick = |m: Metadata| r.select(&m).tag().to_string();
        assert_eq!(pick(meta(dom("x.adnet.test"), None)), "block");
        assert_eq!(pick(meta(dom("mytracker.io"), None)), "block");
        assert_eq!(pick(meta(dom("yandex.ru"), None)), "direct");
        assert_eq!(pick(meta(dom("vk.com"), None)), "direct");
        assert_eq!(
            pick(meta(dom("m.vk.com"), None)),
            "proxy",
            "Full — без поддоменов"
        );
        assert_eq!(
            pick(meta(Address::Ipv4("5.8.9.9".parse().unwrap()), None)),
            "direct"
        );
        assert_eq!(
            pick(meta(dom("5.8.9.9"), None)),
            "direct",
            "IP строкой в поле домена"
        );
        assert_eq!(
            pick(meta(Address::Ipv4("1.1.1.1".parse().unwrap()), None)),
            "proxy"
        );
        assert_eq!(
            pick(meta(
                Address::Ipv4("1.1.1.1".parse().unwrap()),
                Some("mail.ru")
            )),
            "direct",
            "домен из sniffing"
        );
        assert_eq!(pick(meta(dom("example.com"), None)), "proxy");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn name_longer_than_255_bytes_is_rejected() {
        let dir = std::env::temp_dir().join(format!("vpn-core-long-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("geosite.dat"), build_sites(&[])).unwrap();
        std::fs::write(dir.join("geoip.dat"), build_ips(&[])).unwrap();
        let r = router(&dir, "");
        let mut ok = meta(dom(&"a".repeat(255)), None);
        assert_eq!(r.route(&mut ok).await.unwrap().tag(), "proxy");
        let mut long = meta(dom(&"a".repeat(256)), None);
        assert!(r.route(&mut long).await.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Настоящие базы v2fly: GEO_DIR=папка с geosite.dat и geoip.dat.
    #[test]
    #[ignore = "нужны настоящие geosite.dat и geoip.dat: GEO_DIR=…"]
    fn real_geo_matching() {
        let dir = std::path::PathBuf::from(std::env::var("GEO_DIR").unwrap());
        let r = router(
            &dir,
            r#"{"geosite": ["category-ads-all"], "outbound": "block"},
               {"geosite": ["category-ru"], "geoip": ["ru", "private"], "outbound": "direct"}"#,
        );
        let pick = |m: Metadata| r.select(&m).tag().to_string();
        assert_eq!(pick(meta(dom("doubleclick.net"), None)), "block");
        assert_eq!(pick(meta(dom("www.yandex.ru"), None)), "direct");
        assert_eq!(pick(meta(dom("gosuslugi.ru"), None)), "direct");
        assert_eq!(
            pick(meta(Address::Ipv4("192.168.1.1".parse().unwrap()), None)),
            "direct"
        );
        assert_eq!(
            pick(meta(Address::Ipv4("77.88.8.8".parse().unwrap()), None)),
            "direct"
        );
        assert_eq!(pick(meta(dom("github.com"), None)), "proxy");
        assert_eq!(
            pick(meta(Address::Ipv4("8.8.8.8".parse().unwrap()), None)),
            "proxy"
        );
        // Скорость: сотня тысяч проверок.
        let t = std::time::Instant::now();
        for i in 0..100_000 {
            let _ = r.select(&meta(dom(&format!("host{i}.example.org")), None));
        }
        eprintln!("100000 проверок: {:?}", t.elapsed());
    }
}
