// SPDX-License-Identifier: GPL-3.0-or-later
//! Свой DNS: несколько серверов (UDP, TCP, DoT, DoH, системный), выбор
//! сервера по имени (те же доменные условия и geosite, что у
//! маршрутизатора), кеш, fake-IP.
//!
//! ```json
//! "dns": {
//!   "servers": [
//!     { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },  // DoH через сервер
//!     { "type": "udp", "tag": "local", "server": "77.88.8.8", "detour": "direct" }   // местный DNS напрямую
//!   ],
//!   "rules": [{ "geosite": ["category-ru"], "server": "local" }],
//!   "final": "remote"
//! }
//! ```
//!
//! Где используется:
//! - DNS-вход (sing-box: `direct` + правило `hijack-dns`; Xray:
//!   `dokodemo-door` → выход `dns`) — DNS-сервер для системы и программ;
//! - выход `dns` (правило `hijack-dns`) — перехват DNS-запросов из прокси;
//! - выход `direct` — разрешает имена через этот модуль;
//! - маршрутизатор — `domain_strategy`: `ip_if_non_match` и обратное
//!   преобразование fake-IP в имя.

pub mod cache;
pub mod fakeip;
pub mod upstream;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;

use super::access::IpNet;
use super::outbound::Outbound;
use super::rules::{DomainLists, DomainSet, GeoFiles};
use crate::error::{Error, Result};
use cache::Cache;
use fakeip::{FakeIp, Reverse};
use upstream::Upstream;

pub use upstream::DNS_INTERNAL;

/// Потолок на ответ модуля целиком (выбор сервера, запрос, повторы).
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// TTL ответов fake-IP: программа не должна надолго запоминать адрес.
const FAKE_TTL: u32 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[default]
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServerConfig {
    pub tag: String,
    /// `1.1.1.1`, `udp://…`, `tcp://…`, `tls://…`, `https://…/dns-query`,
    /// `local` (системный), `fakeip`.
    pub address: String,
    /// Через какой выход ходить к серверу (по умолчанию — `route.final`,
    /// обычно сервер VLESS: так запросы не видны в локальной сети).
    pub detour: Option<String>,
    /// Свои корневые сертификаты для tls:// и https://.
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRuleConfig {
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub exclude_domain: Vec<String>,
    #[serde(default)]
    pub exclude_domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub domain_regex: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    /// tag наборов из `route.rule_set` (берутся только домены).
    #[serde(default)]
    pub rule_set: Vec<String>,
    /// DNS record type codes. An empty list matches any question type.
    #[serde(default)]
    pub query_type: Vec<u16>,
    #[serde(default)]
    pub user_id: Vec<u32>,
    #[serde(default)]
    pub owner_unknown: bool,
    #[serde(default)]
    pub invert: bool,
    #[serde(default)]
    pub process_name: Vec<String>,
    #[serde(default)]
    pub process_path: Vec<String>,
    #[serde(default)]
    pub process_path_regex: Vec<String>,
    /// tag сервера.
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub response: Option<String>,
    /// Переопределение общей стратегии только для этого правила.
    #[serde(default)]
    pub strategy: Option<Strategy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeIpConfig {
    pub inet4_range: Option<IpNet>,
    /// IPv6-диапазон; `"none"` не поддерживается — просто уберите
    /// AAAA стратегией `ipv4_only`.
    pub inet6_range: Option<IpNet>,
    /// Файл, где таблица fake-IP живёт между перезапусками.
    pub cache_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,
    #[serde(default)]
    pub rules: Vec<DnsRuleConfig>,
    /// Сервер по умолчанию; не задан — первый.
    #[serde(rename = "final")]
    pub final_: Option<String>,
    /// Явный сервер для имён транспорта при внешнем TUN; расширение vpn-core.
    pub bootstrap: Option<String>,
    pub fakeip: Option<FakeIpConfig>,
    #[serde(default)]
    pub strategy: Strategy,
    /// Сколько ответов держать в кеше (по умолчанию 4096; 0 — без кеша).
    pub cache_size: Option<usize>,
}

#[derive(Clone, Copy)]
enum DnsRuleTarget {
    Upstream(usize),
    Reply(ResponseCode),
}

#[derive(Default)]
pub(crate) struct DnsOwner {
    uid: Option<u32>,
    process: Option<Arc<str>>,
}

struct DnsRule {
    domains: DomainSet,
    excluded_domains: DomainSet,
    types: Vec<u16>,
    target: DnsRuleTarget,
    strategy: Option<Strategy>,
    owner: Option<super::rules::Rule>,
    owner_unknown: bool,
    invert: bool,
}

pub struct Dns {
    servers: Vec<Arc<Upstream>>,
    rules: Vec<DnsRule>,
    final_: usize,
    bootstrap: Option<usize>,
    cache: Option<Cache>,
    fakeip: Option<Arc<FakeIp>>,
    /// Настройки fake-IP — чтобы при перечитывании настроек сохранить ту
    /// же таблицу (выданные адреса остаются действительными).
    fakeip_key: String,
    strategy: Strategy,
    network_generation: AtomicU64,
}

/// Место под DNS для выходов, которые создаются раньше него (`direct`,
/// `dns`): DNS сам ходит к серверам через выходы.
pub type DnsSlot = Arc<OnceLock<Arc<Dns>>>;

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl Dns {
    /// Invalidate upstream DNS answers after the host reports a network
    /// change. Fake-IP mappings remain stable so existing TUN destinations
    /// can still be mapped to their original names.
    pub fn network_changed(&self) {
        self.network_generation.fetch_add(1, Ordering::AcqRel);
        if let Some(cache) = &self.cache {
            cache.clear();
        }
    }

    /// Собрать из настроек. `outbound` — выход по tag, `default_detour` —
    /// выход по умолчанию для серверов без `detour`.
    pub fn build(
        cfg: &DnsConfig,
        outbound: &dyn Fn(&str) -> Option<Arc<dyn Outbound>>,
        default_detour: &str,
        geo: &GeoFiles,
        prev: Option<&Dns>,
    ) -> Result<Self> {
        if cfg.servers.is_empty() {
            return Err(Error::Config(
                "dns: не задан ни один сервер (dns.servers)".into(),
            ));
        }
        let mut servers = Vec::new();
        for s in &cfg.servers {
            if servers.iter().any(|u: &Arc<Upstream>| u.tag == s.tag) {
                return Err(Error::Config(format!(
                    "dns: два сервера с одинаковым tag = \"{}\"",
                    s.tag
                )));
            }
            let detour_tag = s.detour.as_deref().unwrap_or(default_detour);
            let detour = outbound(detour_tag);
            let (kind, host, _) = upstream::parse_address(&s.address)
                .map_err(|e| Error::Config(format!("dns-сервер {}: {e}", s.tag)))?;
            if cfg.bootstrap.as_deref() == Some(s.tag.as_str())
                && (kind != upstream::Kind::Udp
                    || matches!(host, crate::vless::Address::Domain(_))
                    || !detour.as_ref().is_some_and(|d| d.clash_type() == "Direct"))
            {
                return Err(Error::Config(
                    "dns.bootstrap требует UDP-сервер с IP-адресом и прямой detour".into(),
                ));
            }
            let needs_detour = !matches!(kind, upstream::Kind::Local | upstream::Kind::FakeIp);
            if needs_detour && detour.is_none() {
                return Err(Error::Config(format!(
                    "dns-сервер {}: нет выхода с tag = \"{detour_tag}\"",
                    s.tag
                )));
            }
            if let Some(detour) = detour.as_ref().filter(|_| needs_detour) {
                let capabilities = detour.capabilities();
                let needs_tcp = matches!(
                    kind,
                    upstream::Kind::Udp
                        | upstream::Kind::Tcp
                        | upstream::Kind::Tls
                        | upstream::Kind::Https { .. }
                );
                let needs_udp = matches!(kind, upstream::Kind::Udp | upstream::Kind::Quic);
                if (needs_tcp && capabilities.tcp == Some(false))
                    || (needs_udp && capabilities.udp == Some(false))
                {
                    return Err(Error::Config(format!(
                        "dns-сервер {}: detour «{detour_tag}» не поддерживает нужные TCP/UDP-пути",
                        s.tag
                    )));
                }
            }
            if needs_detour && detour.as_ref().is_some_and(|d| d.is_dns()) {
                return Err(Error::Config(format!(
                    "dns-сервер {}: detour не может быть выходом dns (петля)",
                    s.tag
                )));
            }
            let roots = match &s.ca_file {
                Some(p) => Some(super::config::load_ca(p)?),
                None => None,
            };
            servers.push(Arc::new(Upstream::new(
                s.tag.clone(),
                &s.address,
                detour,
                roots,
            )?));
        }
        if servers.iter().all(|s| s.is_fake()) {
            return Err(Error::Config(
                "dns: кроме fakeip нужен хотя бы один настоящий сервер".into(),
            ));
        }
        let index = |tag: &str, what: &str| {
            servers
                .iter()
                .position(|s| s.tag == tag)
                .ok_or_else(|| Error::Config(format!("{what}: нет DNS-сервера с tag = \"{tag}\"")))
        };
        let final_ = match &cfg.final_ {
            Some(t) => index(t, "dns.final")?,
            None => 0,
        };
        let bootstrap = cfg
            .bootstrap
            .as_deref()
            .map(|tag| index(tag, "dns.bootstrap"))
            .transpose()?;
        let mut rules = Vec::new();
        for (i, r) in cfg.rules.iter().enumerate() {
            let set = DomainSet::build(
                &DomainLists {
                    domain: &r.domain,
                    domain_suffix: &r.domain_suffix,
                    domain_keyword: &r.domain_keyword,
                    domain_regex: &r.domain_regex,
                    geosite: &r.geosite,
                },
                geo,
            )
            .map_err(|e| Error::Config(format!("dns-правило {}: {e}", i + 1)))?;
            let excluded_domains = DomainSet::build(
                &DomainLists {
                    domain: &r.exclude_domain,
                    domain_suffix: &r.exclude_domain_suffix,
                    domain_keyword: &[],
                    domain_regex: &[],
                    geosite: &[],
                },
                geo,
            )?;
            let owner = if r.user_id.is_empty()
                && r.process_name.is_empty()
                && r.process_path.is_empty()
                && r.process_path_regex.is_empty()
            {
                None
            } else {
                let selector = super::rules::RuleConfig {
                    user_id: r.user_id.clone(),
                    process_name: r.process_name.clone(),
                    process_path: r.process_path.clone(),
                    process_path_regex: r.process_path_regex.clone(),
                    ..Default::default()
                };
                Some(super::rules::compile(
                    i,
                    &selector,
                    Arc::new(super::outbound::BlockOutbound::new("dns-owner-selector")),
                    geo,
                )?)
            };
            if set.is_empty() && r.query_type.is_empty() && r.response.is_none() && owner.is_none()
            {
                return Err(Error::Config(format!(
                    "dns-правило {} без условий — для этого есть dns.final",
                    i + 1
                )));
            }
            if r.owner_unknown
                && (r.invert || owner.is_some() || r.response.as_deref() != Some("REFUSED"))
            {
                return Err(Error::Config(
                    "DNS owner_unknown допустимо только для блокировки".into(),
                ));
            }
            let target = match (r.response.as_deref(), r.server.is_empty()) {
                (None, false) => {
                    DnsRuleTarget::Upstream(index(&r.server, &format!("dns-правило {}", i + 1))?)
                }
                (Some("NOERROR"), true) => DnsRuleTarget::Reply(ResponseCode::NoError),
                (Some("REFUSED"), true) => DnsRuleTarget::Reply(ResponseCode::Refused),
                _ => {
                    return Err(Error::Config(format!(
                        "Некорректное действие DNS-правила {}",
                        i + 1
                    )))
                }
            };
            rules.push(DnsRule {
                domains: set,
                excluded_domains,
                types: r.query_type.clone(),
                target,
                strategy: r.strategy,
                owner,
                owner_unknown: r.owner_unknown,
                invert: r.invert,
            });
        }
        let mut fakeip_key = String::new();
        let fakeip = if servers.iter().any(|s| s.is_fake()) {
            let fc = cfg.fakeip.clone().unwrap_or(FakeIpConfig {
                inet4_range: None,
                inet6_range: None,
                cache_file: None,
            });
            fakeip_key = format!("{fc:?}");
            match prev.and_then(|p| p.fakeip.clone().filter(|_| p.fakeip_key == fakeip_key)) {
                Some(f) => Some(f),
                None => Some(Arc::new(FakeIp::new(
                    fc.inet4_range
                        .unwrap_or_else(|| crate::app::access::const_net("198.18.0.0/15")),
                    Some(
                        fc.inet6_range
                            .unwrap_or_else(|| crate::app::access::const_net("fc00::/18")),
                    ),
                    fc.cache_file,
                )?)),
            }
        } else {
            if cfg.fakeip.is_some() {
                return Err(Error::Config(
                    "dns.fakeip задан, но ни один сервер не указан как address = \"fakeip\"".into(),
                ));
            }
            None
        };
        let cache_size = cfg.cache_size.unwrap_or(4096);
        Ok(Dns {
            servers,
            rules,
            final_,
            bootstrap,
            cache: (cache_size > 0).then(|| Cache::new(cache_size)),
            fakeip,
            fakeip_key,
            strategy: cfg.strategy,
            network_generation: AtomicU64::new(0),
        })
    }

    /// Сервер для имени. `allow_fake = false` — нужен настоящий ответ
    /// (для `direct` и правил по IP): fakeip пропускается.
    /// Сервер и стратегия выбираются одним первым совпавшим правилом.
    fn policy(
        &self,
        name: &str,
        qtype: Option<RecordType>,
        allow_fake: bool,
    ) -> std::result::Result<(&Arc<Upstream>, Strategy), ResponseCode> {
        self.policy_for(name, qtype, allow_fake, None)
    }

    fn policy_for(
        &self,
        name: &str,
        qtype: Option<RecordType>,
        allow_fake: bool,
        owner: Option<&DnsOwner>,
    ) -> std::result::Result<(&Arc<Upstream>, Strategy), ResponseCode> {
        for rule in &self.rules {
            let DnsRule {
                domains: set,
                excluded_domains,
                types,
                target,
                strategy,
                owner: selector,
                owner_unknown,
                invert,
            } = rule;
            let mut hit = (set.is_empty() || set.matches(name))
                && !excluded_domains.matches(name)
                && (types.is_empty() || qtype.is_some_and(|kind| types.contains(&u16::from(kind))));
            if *owner_unknown {
                if hit && owner.is_some_and(|owner| owner.uid.is_none()) {
                    return Err(ResponseCode::Refused);
                }
                continue;
            }
            if let Some(selector) = selector {
                let Some(owner) = owner else { continue };
                if hit {
                    match selector.owner_matches(owner.uid, owner.process.as_deref()) {
                        Some(matches) => hit = matches,
                        None => return Err(ResponseCode::Refused),
                    }
                }
            }
            if hit == *invert {
                continue;
            }
            match *target {
                DnsRuleTarget::Reply(code) => return Err(code),
                DnsRuleTarget::Upstream(index) => {
                    let server = &self.servers[index];
                    if allow_fake || !server.is_fake() {
                        return Ok((server, strategy.unwrap_or(self.strategy)));
                    }
                }
            }
        }
        let f = &self.servers[self.final_];
        if allow_fake || !f.is_fake() {
            return Ok((f, self.strategy));
        }
        let real = self.servers.iter().find(|s| !s.is_fake());
        #[allow(clippy::expect_used, reason = "инвариант: проверено при сборке")]
        Ok((real.expect("проверено при сборке"), self.strategy))
    }

    /// Серверы, заданные именем (их адреса нужно узнать до включения TUN).
    pub fn server_hosts(&self) -> Vec<(String, u16)> {
        self.servers.iter().filter_map(|s| s.host_name()).collect()
    }

    /// Есть ли сервер `local` (системный резолвер).
    pub fn has_local(&self) -> bool {
        self.servers.iter().any(|s| s.kind == upstream::Kind::Local)
    }

    pub fn fakeip(&self) -> Option<&FakeIp> {
        self.fakeip.as_deref()
    }

    /// Имя по адресу fake-IP.
    pub fn reverse(&self, ip: IpAddr) -> Reverse {
        match &self.fakeip {
            Some(f) => f.reverse(ip),
            None => Reverse::NotFake,
        }
    }

    pub(crate) async fn owner_for_flow(
        &self,
        network: super::Network,
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
    ) -> DnsOwner {
        let selectors = || self.rules.iter().filter_map(|rule| rule.owner.as_ref());
        DnsOwner {
            uid: (self.rules.iter().any(|rule| rule.owner_unknown)
                || selectors().any(super::rules::Rule::needs_owner))
            .then(|| crate::connection_owner::resolve(network, src, dst))
            .flatten(),
            process: if selectors().any(super::rules::Rule::needs_process) {
                crate::connection_owner::process_image(network, src, dst).await
            } else {
                None
            },
        }
    }

    /// Ответить на запрос. Ответ есть всегда: ошибка сервера — SERVFAIL.
    pub async fn handle(&self, query: &Message, allow_fake: bool) -> Message {
        self.handle_for(query, allow_fake, None).await
    }

    async fn handle_for(
        &self,
        query: &Message,
        allow_fake: bool,
        owner: Option<&DnsOwner>,
    ) -> Message {
        match tokio::time::timeout(QUERY_TIMEOUT, self.try_handle(query, allow_fake, owner)).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "DNS: запрос не удался");
                reply(query, ResponseCode::ServFail)
            }
            Err(_) => reply(query, ResponseCode::ServFail),
        }
    }

    async fn try_handle(
        &self,
        query: &Message,
        allow_fake: bool,
        owner: Option<&DnsOwner>,
    ) -> Result<Message> {
        if query.metadata.message_type != MessageType::Query
            || query.metadata.op_code != OpCode::Query
        {
            return Ok(reply(query, ResponseCode::NotImp));
        }
        let [question] = query.queries.as_slice() else {
            return Ok(reply(query, ResponseCode::FormErr));
        };
        let name = normalize(&question.name().to_ascii());
        let qtype = question.query_type();
        let (server, strategy) = match self.policy_for(&name, Some(qtype), allow_fake, owner) {
            Ok(policy) => policy,
            Err(code) => return Ok(reply(query, code)),
        };
        if server.is_fake() {
            #[allow(
                clippy::expect_used,
                reason = "инвариант: сервер fakeip есть только с таблицей"
            )]
            let fake = self
                .fakeip
                .as_ref()
                .expect("fakeip создан вместе с сервером");
            let mut resp = reply(query, ResponseCode::NoError);
            match qtype {
                RecordType::A if strategy != Strategy::Ipv6Only => {
                    resp.add_answer(Record::from_rdata(
                        question.name().clone(),
                        FAKE_TTL,
                        RData::A(A(fake.ipv4_for(&name))),
                    ));
                }
                RecordType::AAAA if strategy != Strategy::Ipv4Only => {
                    if let Some(v6) = fake.ipv6_for(&name) {
                        resp.add_answer(Record::from_rdata(
                            question.name().clone(),
                            FAKE_TTL,
                            RData::AAAA(AAAA(v6)),
                        ));
                    }
                }
                // HTTPS/SVCB несут настоящие адреса (ipv4hint) — отдать их
                // значит обойти fake-IP; пустой ответ, браузер обойдётся.
                RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB => {}
                // Остальное (MX, TXT, SRV…) — у настоящего сервера.
                _ => {
                    return match self.policy_for(&name, Some(qtype), false, owner) {
                        Ok((server, _)) => self.forward(server, query, &name, qtype, true).await,
                        Err(code) => Ok(reply(query, code)),
                    };
                }
            }
            return Ok(resp);
        }
        if (qtype == RecordType::A && strategy == Strategy::Ipv6Only)
            || (qtype == RecordType::AAAA && strategy == Strategy::Ipv4Only)
        {
            return Ok(reply(query, ResponseCode::NoError));
        }
        self.forward(server, query, &name, qtype, true).await
    }

    async fn forward(
        &self,
        server: &Arc<Upstream>,
        query: &Message,
        name: &str,
        qtype: RecordType,
        use_cache: bool,
    ) -> Result<Message> {
        let cache = self.cache.as_ref().filter(|_| use_cache);
        let key = format!("{}|{name}", server.tag);
        let network_generation = self.network_generation.load(Ordering::Acquire);
        let cache_generation = cache.map(Cache::generation);
        if let Some(c) = cache {
            if let Some(mut m) = c.get(&key, qtype) {
                if self.network_generation.load(Ordering::Acquire) != network_generation {
                    return Err(Error::Protocol(
                        "DNS query invalidated by network change".into(),
                    ));
                }
                m.metadata.id = query.metadata.id;
                m.queries = query.queries.clone();
                return Ok(m);
            }
        }
        let answer = server.exchange(query).await?;
        if self.network_generation.load(Ordering::Acquire) != network_generation {
            return Err(Error::Protocol(
                "DNS query invalidated by network change".into(),
            ));
        }
        tracing::debug!(dns = %server.tag, name, ?qtype, rcode = ?answer.metadata.response_code, "DNS: ответ");
        if let (Some(c), Some(generation)) = (cache, cache_generation) {
            c.put_at_generation(generation, &key, qtype, &answer);
        }
        Ok(answer)
    }

    /// Настоящие адреса имени (для `direct` и правил по IP): без fake-IP,
    /// с учётом стратегии.
    pub async fn lookup(&self, name: &str) -> Result<Vec<IpAddr>> {
        self.lookup_with_server(name, None).await
    }

    /// Имена транспорта/DNS без proxy DNS и fake-IP. Без неявного отката:
    /// приложение должно явно выбрать прямой сервер через dns.bootstrap.
    pub async fn lookup_server_host(&self, name: &str) -> Result<Vec<IpAddr>> {
        let index = self.bootstrap.ok_or_else(|| {
            Error::Config("внешний TUN: для имён транспорта требуется dns.bootstrap".into())
        })?;
        let server = &self.servers[index];
        self.lookup_with_server(name, Some((server, Strategy::PreferIpv4, true)))
            .await
    }

    pub(crate) fn has_real_upstream(&self, tag: &str) -> bool {
        self.servers
            .iter()
            .any(|server| server.tag == tag && !server.is_fake())
    }

    /// Resolve a destination through an explicitly selected real DNS upstream.
    /// The caller owns the routing decision; never fall back to another tag.
    pub async fn lookup_via(
        &self,
        name: &str,
        tag: &str,
        strategy: Strategy,
        use_cache: bool,
    ) -> Result<Vec<IpAddr>> {
        let server = self
            .servers
            .iter()
            .find(|server| server.tag == tag && !server.is_fake())
            .ok_or_else(|| {
                Error::Config(format!("DNS: неизвестный или виртуальный сервер «{tag}»"))
            })?;
        self.lookup_with_server(name, Some((server, strategy, use_cache)))
            .await
    }

    async fn lookup_with_server(
        &self,
        name: &str,
        server: Option<(&Arc<Upstream>, Strategy, bool)>,
    ) -> Result<Vec<IpAddr>> {
        let name = normalize(name);
        // Bootstrap не наследует правила приложений и их IPv6-only стратегию.
        let strategy = if let Some((_, strategy, _)) = server {
            strategy
        } else {
            self.policy(&name, None, false)
                .map_or(self.strategy, |(_, strategy)| strategy)
        };
        let fqdn = Name::from_ascii(format!("{name}.")).map_err(|e| {
            tracing::debug!(%name, error = %e, "DNS: неверное имя");
            Error::Protocol(format!("DNS: неверное имя: {e}"))
        })?;
        let name = name.as_str();
        let ask = |t: RecordType| {
            let mut m = Message::query();
            m.metadata.recursion_desired = true;
            m.add_query(Query::query(fqdn.clone(), t));
            async move {
                let resp = match server {
                    Some((s, _, use_cache)) => {
                        tokio::time::timeout(QUERY_TIMEOUT, self.forward(s, &m, name, t, use_cache))
                            .await
                            .map_err(|_| {
                                Error::Protocol(
                                    "истекло время ожидания выбранного DNS-сервера".into(),
                                )
                            })??
                    }
                    None => self.handle(&m, false).await,
                };
                Ok::<Vec<IpAddr>, Error>(
                    resp.answers
                        .iter()
                        .filter_map(|r| match &r.data {
                            RData::A(a) => Some(IpAddr::V4(a.0)),
                            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                )
            }
        };
        let (v4, v6) = match strategy {
            Strategy::Ipv4Only => (ask(RecordType::A).await?, Vec::new()),
            Strategy::Ipv6Only => (Vec::new(), ask(RecordType::AAAA).await?),
            _ => {
                let (v4, v6) = tokio::join!(ask(RecordType::A), ask(RecordType::AAAA));
                (v4?, v6?)
            }
        };
        let mut out = match strategy {
            Strategy::PreferIpv6 | Strategy::Ipv6Only => [v6, v4].concat(),
            _ => [v4, v6].concat(),
        };
        out.dedup();
        if out.is_empty() {
            tracing::debug!(%name, "DNS: имя не разрешилось");
            return Err(Error::Protocol("DNS: имя не разрешилось".into()));
        }
        Ok(out)
    }

    /// Сохранять таблицу fake-IP раз в полминуты (если менялась).
    pub fn spawn_persistence(self: &Arc<Self>) {
        if self.fakeip.is_none() {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let Some(dns) = weak.upgrade() else { break };
                if let Some(f) = &dns.fakeip {
                    if let Err(e) = f.save() {
                        tracing::warn!(error = %e, "fake-IP: таблица не сохранена");
                    }
                }
            }
        });
    }

    /// Сохранить таблицу fake-IP сейчас (при выходе).
    pub fn save(&self) {
        if let Some(f) = &self.fakeip {
            if let Err(e) = f.save() {
                tracing::warn!(error = %e, "fake-IP: таблица не сохранена");
            }
        }
    }
}

/// Пустой ответ на запрос с кодом `rcode`.
pub fn reply(query: &Message, rcode: ResponseCode) -> Message {
    let mut m = Message::response(query.metadata.id, query.metadata.op_code);
    m.metadata.response_code = rcode;
    m.metadata.recursion_desired = query.metadata.recursion_desired;
    m.metadata.recursion_available = true;
    m.add_queries(query.queries.iter().cloned());
    m
}

/// Разобрать запрос и ответить (байты → байты); мусор — `None`.
pub async fn answer_bytes(dns: &Dns, packet: &[u8], allow_fake: bool) -> Option<Vec<u8>> {
    answer_bytes_for(dns, packet, allow_fake, None).await
}

pub(crate) async fn answer_bytes_for(
    dns: &Dns,
    packet: &[u8],
    allow_fake: bool,
    owner: Option<&DnsOwner>,
) -> Option<Vec<u8>> {
    let query = match Message::from_vec(packet) {
        Ok(q) => q,
        Err(_) => {
            // Ответить FORMERR можно, только если есть хотя бы номер.
            if packet.len() < 12 {
                return None;
            }
            let mut m =
                Message::response(u16::from_be_bytes([packet[0], packet[1]]), OpCode::Query);
            m.metadata.response_code = ResponseCode::FormErr;
            return m.to_vec().ok();
        }
    };
    if query.metadata.message_type != MessageType::Query {
        return None;
    }
    let resp = dns.handle_for(&query, allow_fake, owner).await;
    resp.to_vec().ok()
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    use crate::app::outbound::{BlockOutbound, DirectOutbound};

    const BOOTSTRAP_DNS: &str = "transport-dns";

    fn build_bootstrap(address: &str, detour: &str, tag: &str) -> Result<Dns> {
        let cfg: DnsConfig = serde_json::from_value(serde_json::json!({
            "servers": [
                {"tag": "remote", "address": "1.1.1.1", "detour": "blocked"},
                {"tag": tag, "address": address, "detour": detour}
            ],
            "final": "remote", "strategy": "ipv4_only",
            "bootstrap": if tag == BOOTSTRAP_DNS { Some(tag) } else { None }
        }))
        .unwrap();
        let geo = GeoFiles::load(Vec::new(), Vec::new(), "unused".as_ref(), "unused".as_ref())?;
        Dns::build(
            &cfg,
            &|tag| match tag {
                "direct" => Some(Arc::new(DirectOutbound::new("direct")) as Arc<dyn Outbound>),
                "blocked" => Some(Arc::new(BlockOutbound::new("blocked")) as Arc<dyn Outbound>),
                "socks" => Some(Arc::new(
                    crate::app::socks_out::Socks5Outbound::new(
                        "socks".into(),
                        "127.0.0.1".into(),
                        1080,
                        None,
                        None,
                    )
                    .unwrap(),
                ) as Arc<dyn Outbound>),
                _ => None,
            },
            "blocked",
            &geo,
            None,
        )
    }

    #[test]
    fn bootstrap_requires_ip_udp_and_direct() {
        assert!(build_bootstrap("1.1.1.1", "direct", BOOTSTRAP_DNS).is_ok());
        for (address, detour) in [
            ("tcp://1.1.1.1", "direct"),
            ("tls://dns.example", "direct"),
            ("local", "direct"),
            ("fakeip", "direct"),
            ("1.1.1.1", "blocked"),
        ] {
            assert!(build_bootstrap(address, detour, BOOTSTRAP_DNS).is_err());
        }
    }

    #[test]
    fn quic_dns_rejects_a_tcp_only_detour_before_startup() {
        let err = build_bootstrap("quic://1.1.1.1", "socks", "quic")
            .err()
            .expect("TCP-only detour must be rejected")
            .to_string();
        assert!(err.contains("не поддерживает нужные TCP/UDP-пути"));
    }

    #[tokio::test]
    async fn dns_question_type_and_domain_choose_the_same_rule() {
        let cfg = crate::app::config::Config::parse(
            r#"{
            "outbounds":[{"type":"direct","tag":"direct"}],
            "dns":{
                "servers":[
                    {"type":"udp","tag":"real","server":"127.0.0.1","detour":"direct"},
                    {"type":"fakeip","tag":"fake"}
                ],
                 "rules":[
                    {"domain":["blocked.example"],"action":"reject"},
                    {"query_type":["HTTPS","SVCB"],"action":"predefined","rcode":"NOERROR"},
                    {"domain":["routed.example"],"query_type":["A",28],"server":"fake"}
                ],
                "final":"real"
            }
        }"#,
        )
        .unwrap();
        let geo =
            GeoFiles::load(Vec::new(), Vec::new(), "unused".as_ref(), "unused".as_ref()).unwrap();
        let dns = Dns::build(
            cfg.dns.as_ref().unwrap(),
            &|_| Some(Arc::new(DirectOutbound::new("direct")) as Arc<dyn Outbound>),
            "direct",
            &geo,
            None,
        )
        .unwrap();
        for (host, kind, expected) in [
            ("blocked.example.", RecordType::A, ResponseCode::Refused),
            ("blocked.example.", RecordType::HTTPS, ResponseCode::Refused),
            ("routed.example.", RecordType::HTTPS, ResponseCode::NoError),
        ] {
            let mut query = Message::query();
            query.add_query(Query::query(Name::from_ascii(host).unwrap(), kind));
            let answer = dns.handle(&query, true).await;
            assert_eq!(answer.metadata.response_code, expected);
            assert!(answer.answers.is_empty());
        }
        assert!(dns
            .policy("routed.example", Some(RecordType::A), true)
            .unwrap()
            .0
            .is_fake());
        assert!(dns
            .policy("routed.example", Some(RecordType::AAAA), true)
            .unwrap()
            .0
            .is_fake());
        assert!(!dns
            .policy("routed.example", Some(RecordType::TXT), true)
            .unwrap()
            .0
            .is_fake());
        assert!(!dns
            .policy("other.example", Some(RecordType::A), true)
            .unwrap()
            .0
            .is_fake());
        assert!(!dns
            .policy("routed.example", Some(RecordType::A), false)
            .unwrap()
            .0
            .is_fake());
    }

    #[tokio::test]
    async fn dns_owner_selects_the_assigned_exit_and_unknown_is_refused() {
        let cfg = crate::app::config::Config::parse(
            r#"{
            "outbounds":[{"type":"direct","tag":"direct"}],
            "dns":{
                "servers":[
                    {"type":"udp","tag":"primary","server":"127.0.0.1","detour":"direct"},
                    {"type":"udp","tag":"secondary","server":"127.0.0.1","detour":"direct"}
                ],
                "rules":[
                    {"domain":["site.example"],"server":"primary"},
                    {"type":"logical","mode":"and","rules":[
                        {"domain_suffix":[".local"]},
                        {"domain":["vpn.local"],"domain_suffix":[".vpn.local"],"invert":true}
                    ],"action":"route","server":"primary"},
                    {"user_id":[10001],"server":"secondary"},
                    {"process_name":["ChatGPT.exe"],"server":"secondary"}
                ],
                "final":"primary"
            }
        }"#,
        )
        .unwrap();
        let geo =
            GeoFiles::load(Vec::new(), Vec::new(), "unused".as_ref(), "unused".as_ref()).unwrap();
        let build = |cfg: &DnsConfig| {
            Dns::build(
                cfg,
                &|_| Some(Arc::new(DirectOutbound::new("direct")) as Arc<dyn Outbound>),
                "direct",
                &geo,
                None,
            )
            .unwrap()
        };
        let mut cfg = cfg.dns.unwrap();
        let process_rule = cfg.rules.pop().unwrap();
        let dns = build(&cfg);
        let android = DnsOwner {
            uid: Some(10001),
            process: None,
        };
        cfg.rules.pop();
        cfg.rules.push(process_rule);
        let windows_dns = build(&cfg);
        let windows = DnsOwner {
            uid: None,
            process: Some(Arc::from(r"C:\Apps\ChatGPT.exe")),
        };
        for (dns, owner) in [(&dns, &android), (&windows_dns, &windows)] {
            assert_eq!(
                dns.policy_for("other.example", Some(RecordType::A), true, Some(owner))
                    .unwrap()
                    .0
                    .tag,
                "secondary"
            );
            assert_eq!(
                dns.policy_for("site.example", Some(RecordType::A), true, Some(owner))
                    .unwrap()
                    .0
                    .tag,
                "primary"
            );
            assert_eq!(
                dns.policy_for("lan.local", Some(RecordType::A), true, Some(owner))
                    .unwrap()
                    .0
                    .tag,
                "primary"
            );
            assert_eq!(
                dns.policy_for("sub.vpn.local", Some(RecordType::A), true, Some(owner))
                    .unwrap()
                    .0
                    .tag,
                "secondary"
            );
        }
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("other.example.").unwrap(),
            RecordType::A,
        ));
        let owner = DnsOwner::default();
        let packet = answer_bytes_for(&dns, &request.to_vec().unwrap(), true, Some(&owner))
            .await
            .unwrap();
        assert_eq!(
            Message::from_vec(&packet).unwrap().metadata.response_code,
            ResponseCode::Refused
        );
    }

    #[test]
    fn bootstrap_tag_is_explicit_and_must_exist() {
        for (tag, valid) in [("configured-dns", true), ("missing", false)] {
            let cfg = crate::app::config::Config::parse(&serde_json::json!({
                "inbounds": [{"type":"mixed", "listen":"127.0.0.1", "listen_port":0}],
                "outbounds": [{"type":"direct", "tag":"direct"}],
                "dns": {
                    "servers": [{"type":"udp", "tag":"configured-dns", "server":"127.0.0.1", "detour":"direct"}],
                    "bootstrap": tag
                }
            }).to_string()).unwrap();
            assert_eq!(crate::app::App::build(&cfg).is_ok(), valid);
        }
    }

    #[tokio::test]
    async fn bootstrap_uses_its_own_cache_and_preserves_application_dns() {
        let dns = build_bootstrap("1.1.1.1", "direct", BOOTSTRAP_DNS).unwrap();
        let name = "proxy.example";
        let mut q = Message::query();
        q.add_query(Query::query(
            Name::from_ascii("proxy.example.").unwrap(),
            RecordType::A,
        ));
        let mut answer = reply(&q, ResponseCode::NoError);
        answer.add_answer(Record::from_rdata(
            q.queries[0].name().clone(),
            60,
            RData::A(A::new(203, 0, 113, 7)),
        ));
        dns.cache
            .as_ref()
            .unwrap()
            .put(&format!("{BOOTSTRAP_DNS}|{name}"), RecordType::A, &answer);
        let mut q6 = Message::query();
        q6.add_query(Query::query(
            Name::from_ascii("proxy.example.").unwrap(),
            RecordType::AAAA,
        ));
        dns.cache.as_ref().unwrap().put(
            &format!("{BOOTSTRAP_DNS}|{name}"),
            RecordType::AAAA,
            &reply(&q6, ResponseCode::NoError),
        );
        assert_eq!(
            dns.lookup_server_host(name).await.unwrap(),
            vec!["203.0.113.7".parse::<IpAddr>().unwrap()],
        );
        // Обычный запрос по-прежнему выбирает намеренно заблокированный DNS.
        assert!(dns.lookup(name).await.is_err());
        dns.network_changed();
        assert!(dns
            .cache
            .as_ref()
            .unwrap()
            .get(&format!("{BOOTSTRAP_DNS}|{name}"), RecordType::A)
            .is_none());
    }

    #[tokio::test]
    async fn explicit_lookup_uses_only_the_selected_dns_tag_and_family() {
        let dns = build_bootstrap("1.1.1.1", "direct", BOOTSTRAP_DNS).unwrap();
        let name = "shared.example";
        let fqdn = Name::from_ascii("shared.example.").unwrap();
        let mut query = Message::query();
        query.add_query(Query::query(fqdn.clone(), RecordType::A));
        for (tag, last) in [("remote", 11), (BOOTSTRAP_DNS, 22)] {
            let mut answer = reply(&query, ResponseCode::NoError);
            answer.add_answer(Record::from_rdata(
                fqdn.clone(),
                60,
                RData::A(A::new(203, 0, 113, last)),
            ));
            dns.cache
                .as_ref()
                .unwrap()
                .put(&format!("{tag}|{name}"), RecordType::A, &answer);
        }
        assert_eq!(
            dns.lookup_via(name, "remote", Strategy::Ipv4Only, true)
                .await
                .unwrap(),
            vec!["203.0.113.11".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            dns.lookup_via(name, BOOTSTRAP_DNS, Strategy::Ipv4Only, true)
                .await
                .unwrap(),
            vec!["203.0.113.22".parse::<IpAddr>().unwrap()]
        );
        assert!(dns
            .lookup_via(name, "missing", Strategy::Ipv4Only, true)
            .await
            .is_err());
        // The remote fixture rejects network exchanges. Its cached answer
        // must not make a fresh connectivity check succeed.
        assert!(dns
            .lookup_via(name, "remote", Strategy::Ipv4Only, false)
            .await
            .is_err());
        assert!(dns
            .lookup_via(name, "remote", Strategy::Ipv4Only, true)
            .await
            .is_ok());

        let geo =
            GeoFiles::load(Vec::new(), Vec::new(), "unused".as_ref(), "unused".as_ref()).unwrap();
        let dns = Arc::new(dns);
        for (resolver, expected) in [
            ("remote", Some("203.0.113.11")),
            (BOOTSTRAP_DNS, Some("203.0.113.22")),
            ("missing", None),
        ] {
            let config = crate::app::config::Config::parse(&serde_json::json!({
                "outbounds": [{"type":"direct","tag":"vpn1"},{"type":"direct","tag":"vpn2"}],
                "route": {"final":"vpn1","rules":[
                    {"domain":[name],"action":"resolve","server":resolver,"strategy":"ipv4_only"},
                    {"domain":[name],"outbound":"vpn2"}
                ]}
            }).to_string()).unwrap();
            let mut router = crate::app::router::Router::new(
                vec![
                    Arc::new(DirectOutbound::new("vpn1")),
                    Arc::new(DirectOutbound::new("vpn2")),
                ],
                &config.route,
                &[],
                &geo,
            )
            .unwrap();
            router.set_dns(dns.clone());
            assert_eq!(router.validate_resolvers().is_ok(), expected.is_some());
            let mut meta = crate::app::Metadata {
                inbound: "tun".into(),
                source: "127.0.0.1:12345".parse().unwrap(),
                network: crate::app::Network::Tcp,
                target: crate::vless::Address::Domain(name.into()),
                port: 443,
                sniffed: None,
                inbound_type: "tun",
                user_id: None,
                process_path: None,
                destination_ip_version: None,
                rule: None,
            };
            let result = router.route(&mut meta).await;
            if let Some(expected) = expected {
                assert_eq!(result.unwrap().tag(), "vpn2");
                assert!(
                    matches!(meta.target, crate::vless::Address::Ipv4(ip) if ip.to_string() == expected)
                );
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn bootstrap_queries_direct_ip_when_default_dns_is_blocked() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap().to_string();
        let dns = build_bootstrap(&address, "direct", BOOTSTRAP_DNS).unwrap();
        let reply_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            for _ in 0..2 {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let query = Message::from_vec(&buf[..n]).unwrap();
                assert_eq!(query.queries[0].name().to_ascii(), "proxy.example.");
                let mut answer = reply(&query, ResponseCode::NoError);
                if query.queries[0].query_type() == RecordType::A {
                    answer.add_answer(Record::from_rdata(
                        query.queries[0].name().clone(),
                        60,
                        RData::A(A::new(203, 0, 113, 9)),
                    ));
                }
                socket
                    .send_to(&answer.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let ips = tokio::time::timeout(
            Duration::from_secs(2),
            dns.lookup_server_host("proxy.example"),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ips, vec!["203.0.113.9".parse::<IpAddr>().unwrap()]);
        reply_task.await.unwrap();
    }

    #[tokio::test]
    async fn missing_bootstrap_fails_without_falling_back_to_remote() {
        let dns = build_bootstrap("1.1.1.1", "direct", "other").unwrap();
        let error = dns.lookup_server_host("proxy.example").await.unwrap_err();
        assert!(error.to_string().contains("dns.bootstrap"));
    }
}

#[cfg(test)]
mod rule_strategy_tests {
    use super::*;
    use crate::app::{config::Config, outbound::DirectOutbound};
    use std::sync::Mutex;

    const BOOTSTRAP_DNS: &str = "transport-dns";

    struct LoopbackDns {
        address: String,
        queries: Arc<Mutex<Vec<(String, RecordType)>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for LoopbackDns {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn loopback_dns() -> LoopbackDns {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap().to_string();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let received = queries.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let query = Message::from_vec(&buf[..n]).unwrap();
                let question = &query.queries[0];
                let qtype = question.query_type();
                received
                    .lock()
                    .unwrap()
                    .push((question.name().to_ascii(), qtype));
                let mut answer = reply(&query, ResponseCode::NoError);
                let data = match qtype {
                    RecordType::A => RData::A(A::new(203, 0, 113, 42)),
                    RecordType::AAAA => RData::AAAA(AAAA("2001:db8::42".parse().unwrap())),
                    _ => continue,
                };
                answer.add_answer(Record::from_rdata(question.name().clone(), 60, data));
                socket
                    .send_to(&answer.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        LoopbackDns {
            address,
            queries,
            task,
        }
    }

    fn config(address: &str, strategy: &str, rules: serde_json::Value) -> Result<Config> {
        Config::parse(
            &serde_json::json!({
                "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 0}],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "dns": {
                    "servers": [
                        {"tag": "test", "address": address, "detour": "direct"},
                        {"tag": BOOTSTRAP_DNS, "address": address, "detour": "direct"},
                        {"tag": "fake", "address": "fakeip"}
                    ],
                    "final": "test", "strategy": strategy, "rules": rules,
                    "bootstrap": BOOTSTRAP_DNS
                }
            })
            .to_string(),
        )
    }

    fn build(cfg: Config) -> Dns {
        let geo =
            GeoFiles::load(Vec::new(), Vec::new(), "unused".as_ref(), "unused".as_ref()).unwrap();
        Dns::build(
            cfg.dns.as_ref().unwrap(),
            &|_| Some(Arc::new(DirectOutbound::new("direct")) as Arc<dyn Outbound>),
            "direct",
            &geo,
            None,
        )
        .unwrap()
    }

    fn query(name: &str, qtype: RecordType) -> Message {
        let mut q = Message::query();
        q.add_query(Query::query(
            Name::from_ascii(format!("{name}.")).unwrap(),
            qtype,
        ));
        q
    }

    fn rule(name: &str, strategy: &str) -> serde_json::Value {
        serde_json::json!({"domain": [name], "server": "test", "strategy": strategy})
    }

    #[test]
    fn parser_preserves_optional_strategy_and_rejects_invalid_values() {
        let cfg = config(
            "127.0.0.1:53",
            "ipv6_only",
            serde_json::json!([
                rule("a.example", "prefer_ipv4"),
                {"domain": ["b.example"], "server": "test"}
            ]),
        )
        .unwrap();
        let rules = &cfg.dns.unwrap().rules;
        assert_eq!(rules[0].strategy, Some(Strategy::PreferIpv4));
        assert_eq!(rules[1].strategy, None);
        assert!(config(
            "127.0.0.1:53",
            "prefer_ipv4",
            serde_json::json!([rule("a.example", "unsupported")]),
        )
        .is_err());
        let rule: DnsRuleConfig = serde_json::from_value(serde_json::json!({
            "domain": ["a.example"], "server": "test"
        }))
        .unwrap();
        assert_eq!(rule.strategy, None);
    }

    #[tokio::test]
    async fn matching_policy_filters_queries_and_orders_lookup_addresses() {
        let server = loopback_dns().await;
        let dns = build(
            config(
                &server.address,
                "ipv6_only",
                serde_json::json!([
                    rule("v4.example", "ipv4_only"),
                    rule("v6.example", "ipv6_only"),
                    rule("prefer4.example", "prefer_ipv4"),
                    rule("prefer6.example", "prefer_ipv6"),
                    rule("first.example", "ipv4_only"),
                    rule("first.example", "ipv6_only"),
                    {"domain": ["inherit.example"], "server": "test"}
                ]),
            )
            .unwrap(),
        );
        let v4 = "203.0.113.42".parse::<IpAddr>().unwrap();
        let v6 = "2001:db8::42".parse::<IpAddr>().unwrap();
        for (name, expected) in [
            ("v4.example", vec![v4]),
            ("v6.example", vec![v6]),
            ("PREFER4.EXAMPLE.", vec![v4, v6]),
            ("prefer6.example", vec![v6, v4]),
            ("first.example", vec![v4]),
            ("inherit.example", vec![v6]),
            ("unmatched.example", vec![v6]),
        ] {
            let actual = tokio::time::timeout(Duration::from_secs(2), dns.lookup(name))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(actual, expected, "{name}");
        }
        for (name, qtype) in [
            ("v4.example", RecordType::AAAA),
            ("v6.example", RecordType::A),
            ("inherit.example", RecordType::A),
        ] {
            let answer = dns.handle(&query(name, qtype), true).await;
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
            assert!(answer.answers.is_empty());
            assert!(!server
                .queries
                .lock()
                .unwrap()
                .iter()
                .any(|(host, ty)| { host == &format!("{name}.") && *ty == qtype }));
        }
        // Bootstrap не наследует ни IPv6-only по умолчанию, ни правило приложения.
        let ips = dns.lookup_server_host("v6.example").await.unwrap();
        assert_eq!(ips, vec![v4, v6]);
    }

    #[test]
    fn xray_dns_rule_inherits_global_strategy() {
        let cfg = Config::parse(
            r#"{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":1080}],
                "outbounds":[{"protocol":"freedom","tag":"direct"}],
                "dns":{"queryStrategy":"UseIPv6","servers":[
                    {"address":"1.1.1.1","domains":["full:xray.example"]}
                ]}}"#,
        )
        .unwrap();
        let dns = cfg.dns.unwrap();
        assert_eq!(dns.strategy, Strategy::Ipv6Only);
        assert_eq!(dns.rules[0].strategy, None);
    }

    #[tokio::test]
    async fn fakeip_uses_the_matching_rule_strategy() {
        let server = loopback_dns().await;
        let dns = build(
            config(
                &server.address,
                "ipv6_only",
                serde_json::json!([
                    {"domain": ["fake4.example"], "server": "fake", "strategy": "ipv4_only"},
                    {"domain": ["fake6.example"], "server": "fake", "strategy": "ipv6_only"}
                ]),
            )
            .unwrap(),
        );
        for (name, allowed, suppressed) in [
            ("fake4.example", RecordType::A, RecordType::AAAA),
            ("fake6.example", RecordType::AAAA, RecordType::A),
        ] {
            let answer = dns.handle(&query(name, allowed), true).await;
            assert_eq!(answer.answers.len(), 1);
            assert!(dns
                .handle(&query(name, suppressed), true)
                .await
                .answers
                .is_empty());
        }
        assert!(server.queries.lock().unwrap().is_empty());
    }
}
