//! Маршрутизатор: по данным соединения выбирает выход — по правилам
//! (`route.rules`, первое подошедшее), иначе выход по умолчанию
//! (`route.final`).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use super::config::RouteConfig;
use super::outbound::Outbound;
use super::rules::{self, GeoFiles, Rule};
use super::Metadata;
use crate::error::{Error, Result};

pub struct Router {
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    rules: Vec<Rule>,
    final_: Arc<dyn Outbound>,
}

impl Router {
    /// `inbound_tags` — чтобы правило с опечаткой в имени входа было
    /// ошибкой, а не правилом, которое никогда не срабатывает.
    pub fn new(
        outbounds: Vec<Arc<dyn Outbound>>,
        route: &RouteConfig,
        inbound_tags: &[String],
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
                .ok_or_else(|| Error::Config(format!("route.final: нет выхода с tag = \"{t}\"")))?,
            None => first,
        };
        let geo = GeoFiles::load(
            &route.rules,
            route
                .geosite_file
                .as_deref()
                .unwrap_or(Path::new("geosite.dat")),
            route
                .geoip_file
                .as_deref()
                .unwrap_or(Path::new("geoip.dat")),
        )?;
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
            rules.push(rules::compile(i, r, out, &geo)?);
        }
        if !rules.is_empty() {
            tracing::info!(rules = rules.len(), "правила маршрутизации загружены");
        }
        Ok(Router {
            outbounds: map,
            rules,
            final_,
        })
    }

    /// Выход для соединения.
    pub fn select(&self, meta: &Metadata) -> Arc<dyn Outbound> {
        for r in &self.rules {
            if r.matches(meta) {
                tracing::debug!(
                    rule = r.index + 1,
                    outbound = r.outbound.tag(),
                    target = %meta.target,
                    sniffed = ?meta.sniffed,
                    "маршрут по правилу"
                );
                return r.outbound.clone();
            }
        }
        self.final_.clone()
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
        }
    }

    fn dom(d: &str) -> Address {
        Address::Domain(d.into())
    }

    fn router(dir: &Path, rules: &str) -> Router {
        let cfg = Config::parse(&format!(
            // Пути — в одинарных кавычках: в Windows-путях есть «\».
            "{rules}\n[route]\nfinal = \"proxy\"\ngeosite_file = '{}'\ngeoip_file = '{}'\n",
            dir.join("geosite.dat").display(),
            dir.join("geoip.dat").display()
        ))
        .unwrap();
        Router::new(outs(), &cfg.route, &["in".into()]).unwrap()
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
            r#"
[[route.rules]]
geosite = ["category-ads"]
outbound = "block"

[[route.rules]]
geosite = ["ru"]
geoip = ["RU"]
outbound = "direct"
"#,
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

    /// Настоящие базы v2fly: GEO_DIR=папка с geosite.dat и geoip.dat.
    #[test]
    #[ignore = "нужны настоящие geosite.dat и geoip.dat: GEO_DIR=…"]
    fn real_geo_matching() {
        let dir = std::path::PathBuf::from(std::env::var("GEO_DIR").unwrap());
        let r = router(
            &dir,
            r#"
[[route.rules]]
geosite = ["category-ads-all"]
outbound = "block"

[[route.rules]]
geosite = ["category-ru"]
geoip = ["ru", "private"]
outbound = "direct"
"#,
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
