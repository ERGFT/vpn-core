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
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub domain_regex: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    /// tag наборов из `route.rule_set` (берутся только домены).
    #[serde(default)]
    pub rule_set: Vec<String>,
    /// tag сервера.
    pub server: String,
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
    pub fakeip: Option<FakeIpConfig>,
    #[serde(default)]
    pub strategy: Strategy,
    /// Сколько ответов держать в кеше (по умолчанию 4096; 0 — без кеша).
    pub cache_size: Option<usize>,
}

pub struct Dns {
    servers: Vec<Arc<Upstream>>,
    rules: Vec<(DomainSet, usize)>,
    final_: usize,
    cache: Option<Cache>,
    fakeip: Option<Arc<FakeIp>>,
    /// Настройки fake-IP — чтобы при перечитывании настроек сохранить ту
    /// же таблицу (выданные адреса остаются действительными).
    fakeip_key: String,
    strategy: Strategy,
}

/// Место под DNS для выходов, которые создаются раньше него (`direct`,
/// `dns`): DNS сам ходит к серверам через выходы.
pub type DnsSlot = Arc<OnceLock<Arc<Dns>>>;

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl Dns {
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
            let (kind, _, _) = upstream::parse_address(&s.address)
                .map_err(|e| Error::Config(format!("dns-сервер {}: {e}", s.tag)))?;
            let needs_detour = !matches!(kind, upstream::Kind::Local | upstream::Kind::FakeIp);
            if needs_detour && detour.is_none() {
                return Err(Error::Config(format!(
                    "dns-сервер {}: нет выхода с tag = \"{detour_tag}\"",
                    s.tag
                )));
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
            if set.is_empty() {
                return Err(Error::Config(format!(
                    "dns-правило {} без условий — для этого есть dns.final",
                    i + 1
                )));
            }
            rules.push((set, index(&r.server, &format!("dns-правило {}", i + 1))?));
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
                        .unwrap_or_else(|| "198.18.0.0/15".parse().unwrap()),
                    Some(
                        fc.inet6_range
                            .unwrap_or_else(|| "fc00::/18".parse().unwrap()),
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
            cache: (cache_size > 0).then(|| Cache::new(cache_size)),
            fakeip,
            fakeip_key,
            strategy: cfg.strategy,
        })
    }

    /// Сервер для имени. `allow_fake = false` — нужен настоящий ответ
    /// (для `direct` и правил по IP): fakeip пропускается.
    fn pick(&self, name: &str, allow_fake: bool) -> &Arc<Upstream> {
        for (set, idx) in &self.rules {
            let s = &self.servers[*idx];
            if set.matches(name) && (allow_fake || !s.is_fake()) {
                return s;
            }
        }
        let f = &self.servers[self.final_];
        if allow_fake || !f.is_fake() {
            return f;
        }
        self.servers
            .iter()
            .find(|s| !s.is_fake())
            .expect("проверено при сборке")
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

    /// Ответить на запрос. Ответ есть всегда: ошибка сервера — SERVFAIL.
    pub async fn handle(&self, query: &Message, allow_fake: bool) -> Message {
        match tokio::time::timeout(QUERY_TIMEOUT, self.try_handle(query, allow_fake)).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "DNS: запрос не удался");
                reply(query, ResponseCode::ServFail)
            }
            Err(_) => reply(query, ResponseCode::ServFail),
        }
    }

    async fn try_handle(&self, query: &Message, allow_fake: bool) -> Result<Message> {
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
        let server = self.pick(&name, allow_fake);
        if server.is_fake() {
            let fake = self
                .fakeip
                .as_ref()
                .expect("fakeip создан вместе с сервером");
            let mut resp = reply(query, ResponseCode::NoError);
            match qtype {
                RecordType::A if self.strategy != Strategy::Ipv6Only => {
                    resp.add_answer(Record::from_rdata(
                        question.name().clone(),
                        FAKE_TTL,
                        RData::A(A(fake.ipv4_for(&name))),
                    ));
                }
                RecordType::AAAA if self.strategy != Strategy::Ipv4Only => {
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
                    return self
                        .forward(self.pick(&name, false), query, &name, qtype)
                        .await
                }
            }
            return Ok(resp);
        }
        if (qtype == RecordType::A && self.strategy == Strategy::Ipv6Only)
            || (qtype == RecordType::AAAA && self.strategy == Strategy::Ipv4Only)
        {
            return Ok(reply(query, ResponseCode::NoError));
        }
        self.forward(server, query, &name, qtype).await
    }

    async fn forward(
        &self,
        server: &Arc<Upstream>,
        query: &Message,
        name: &str,
        qtype: RecordType,
    ) -> Result<Message> {
        let key = format!("{}|{name}", server.tag);
        if let Some(c) = &self.cache {
            if let Some(mut m) = c.get(&key, qtype) {
                m.metadata.id = query.metadata.id;
                m.queries = query.queries.clone();
                return Ok(m);
            }
        }
        let answer = server.exchange(query).await?;
        tracing::debug!(dns = %server.tag, name, ?qtype, rcode = ?answer.metadata.response_code, "DNS: ответ");
        if let Some(c) = &self.cache {
            c.put(&key, qtype, &answer);
        }
        Ok(answer)
    }

    /// Настоящие адреса имени (для `direct` и правил по IP): без fake-IP,
    /// с учётом стратегии.
    pub async fn lookup(&self, name: &str) -> Result<Vec<IpAddr>> {
        let name = normalize(name);
        let fqdn = Name::from_ascii(format!("{name}."))
            .map_err(|e| Error::Protocol(format!("DNS: имя «{name}»: {e}")))?;
        let ask = |t: RecordType| {
            let mut m = Message::query();
            m.metadata.recursion_desired = true;
            m.add_query(Query::query(fqdn.clone(), t));
            async move {
                let resp = self.handle(&m, false).await;
                resp.answers
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::A(a) => Some(IpAddr::V4(a.0)),
                        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            }
        };
        let (v4, v6) = match self.strategy {
            Strategy::Ipv4Only => (ask(RecordType::A).await, Vec::new()),
            Strategy::Ipv6Only => (Vec::new(), ask(RecordType::AAAA).await),
            _ => tokio::join!(ask(RecordType::A), ask(RecordType::AAAA)),
        };
        let mut out = match self.strategy {
            Strategy::PreferIpv6 | Strategy::Ipv6Only => [v6, v4].concat(),
            _ => [v4, v6].concat(),
        };
        out.dedup();
        if out.is_empty() {
            return Err(Error::Protocol(format!("DNS: имя {name} не разрешилось")));
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
    let resp = dns.handle(&query, allow_fake).await;
    resp.to_vec().ok()
}
