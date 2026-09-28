// SPDX-License-Identifier: GPL-3.0-or-later
//! Ответы в формате Clash API (как у sing-box и mihomo) — чтобы готовые
//! веб-панели (yacd, metacubexd, zashboard) и клиенты работали с ядром без
//! переделок. Сам HTTP-сервер — `api.rs`; здесь — что отвечать.
//!
//! Форматы сверены с ответами настоящего sing-box 1.12 на тех же настройках.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use serde_json::{json, Map, Value};

use super::config::InboundKind;
use super::http_client::{self, Url};
use super::outbound::Outbound;
use super::stats::rfc3339;
use super::Controller;
use crate::error::{Error, Result};

impl Controller {
    /// Выход по имени: из маршрутизатора или участник группы (серверы
    /// подписок живут только в группах).
    pub(super) fn find_proxy(&self, name: &str) -> Option<Arc<dyn Outbound>> {
        let router = self.routers.get();
        if let Some(o) = router.get(name) {
            return Some(o);
        }
        self.groups
            .read()
            .unwrap()
            .iter()
            .flat_map(|g| g.members())
            .find(|m| m.tag() == name)
            .map(|m| m.out.clone())
    }

    /// Выход в формате Clash: тип, имя, история задержки; у групп — `now`
    /// и `all`.
    pub(super) fn proxy_json(&self, o: &dyn Outbound) -> Value {
        let history: Vec<Value> = self
            .tracker
            .last_delay(o.tag())
            .map(|(t, d)| json!({ "time": rfc3339(t), "delay": d.unwrap_or(0) }))
            .into_iter()
            .collect();
        let mut v = json!({
            "type": o.clash_type(),
            "name": o.tag(),
            "udp": true,
            "history": history,
        });
        if let Some(g) = o.as_group() {
            v["now"] = json!(g.current().unwrap_or_default());
            v["all"] = json!(g
                .members()
                .iter()
                .map(|m| m.tag().to_string())
                .collect::<Vec<_>>());
        }
        v
    }

    /// `GET /proxies`: все выходы и серверы подписок.
    pub(super) fn clash_proxies(&self) -> Value {
        let router = self.routers.get();
        let mut seen = HashSet::new();
        let mut map = Map::new();
        let mut add = |o: &dyn Outbound| {
            if seen.insert(o.tag().to_string()) {
                map.insert(o.tag().to_string(), self.proxy_json(o));
            }
        };
        for o in router.outbounds() {
            add(o.as_ref());
        }
        for g in self.groups.read().unwrap().iter() {
            for m in g.members() {
                add(m.out.as_ref());
            }
        }
        json!({ "proxies": map })
    }

    /// `GET /group`: только группы.
    pub(super) fn clash_groups(&self) -> Value {
        let list: Vec<Value> = self
            .groups
            .read()
            .unwrap()
            .iter()
            .map(|g| self.proxy_json(g.as_ref()))
            .collect();
        json!({ "proxies": list })
    }

    /// Проверить задержку выхода `name` запросом к `url`; `Ok(None)` — не
    /// ответил вовремя.
    pub(super) async fn clash_delay(
        &self,
        name: &str,
        url: &str,
        timeout: Duration,
    ) -> Result<Option<u64>> {
        let out = self
            .find_proxy(name)
            .ok_or_else(|| Error::Config(format!("нет выхода «{name}»")))?;
        let url = Url::parse(url)?;
        let r = http_client::probe(out.as_ref(), &url, timeout).await.ok();
        self.tracker.record_delay(name, r);
        Ok(r.map(|d| d.as_millis() as u64))
    }

    /// Проверить всех участников группы; ответ — задержки ответивших.
    pub(super) async fn clash_group_delay(
        &self,
        name: &str,
        url: &str,
        timeout: Duration,
    ) -> Result<Value> {
        let g = self
            .group(name)
            .ok_or_else(|| Error::Config(format!("нет группы «{name}»")))?;
        let url = Url::parse(url)?;
        let results: Vec<(String, Option<Duration>)> = futures_util::stream::iter(g.members())
            .map(|m| {
                let url = &url;
                async move {
                    let r = http_client::probe(m.out.as_ref(), url, timeout).await.ok();
                    (m.tag().to_string(), r)
                }
            })
            .buffer_unordered(8)
            .collect()
            .await;
        let mut map = Map::new();
        for (tag, r) in results {
            self.tracker.record_delay(&tag, r);
            if let Some(d) = r {
                map.insert(tag, json!(d.as_millis() as u64));
            }
        }
        Ok(Value::Object(map))
    }

    /// `GET /rules`: правила по порядку и `route.final` последним.
    pub(super) fn clash_rules(&self) -> Value {
        let router = self.routers.get();
        let proxy = |tag: &str| match tag {
            "__reject" => "reject".to_string(),
            "__hijack_dns" => "hijack-dns".to_string(),
            t => t.to_string(),
        };
        let mut list: Vec<Value> = router
            .rules()
            .map(|(label, tag)| json!({ "type": "default", "payload": label, "proxy": proxy(tag) }))
            .collect();
        list.push(json!({ "type": "Match", "payload": "", "proxy": proxy(router.final_tag()) }));
        json!({ "rules": list })
    }

    /// `GET /configs`: порты входов, режим.
    pub(super) fn clash_configs(&self) -> Value {
        let st = self.state.lock().unwrap();
        let port = |k: InboundKind| {
            st.inbounds
                .iter()
                .find(|l| l.kind == k)
                .and_then(|l| l.addr)
                .map(|a| a.port())
                .unwrap_or(0)
        };
        let allow_lan = st
            .inbounds
            .iter()
            .filter_map(|l| l.addr)
            .any(|a| !a.ip().is_loopback());
        let tun = st.inbounds.iter().any(|l| l.kind == InboundKind::Tun);
        json!({
            "port": port(InboundKind::Http),
            "socks-port": port(InboundKind::Socks),
            "redir-port": 0,
            "tproxy-port": 0,
            "mixed-port": port(InboundKind::Mixed),
            "allow-lan": allow_lan,
            "bind-address": "*",
            "mode": self.tracker.mode().clash_name(),
            "mode-list": ["Rule", "Global", "Direct"],
            "log-level": "info",
            "ipv6": true,
            "tun": { "enable": tun },
        })
    }

    /// `GET /providers/proxies`: подписки как «поставщики серверов».
    pub(super) fn clash_providers(&self) -> Value {
        let mut map = Map::new();
        for s in self.subs.read().unwrap().iter() {
            let (servers, updated) = s.servers();
            let mut p = json!({
                "name": s.cfg.tag,
                "type": "Proxy",
                "vehicleType": "HTTP",
                "proxies": servers.iter().map(|o| self.proxy_json(o.as_ref())).collect::<Vec<_>>(),
                "testUrl": super::DEFAULT_PROBE_URL,
            });
            if updated > 0 {
                p["updatedAt"] = json!(rfc3339(updated));
            }
            map.insert(s.cfg.tag.clone(), p);
        }
        json!({ "providers": map })
    }

    /// Проверить задержку всех серверов подписки.
    pub(super) async fn clash_provider_check(&self, name: &str) -> Result<()> {
        let s = self
            .subs
            .read()
            .unwrap()
            .iter()
            .find(|s| s.cfg.tag == name)
            .cloned()
            .ok_or_else(|| Error::Config(format!("нет подписки «{name}»")))?;
        let url = Url::parse(super::DEFAULT_PROBE_URL)?;
        let (servers, _) = s.servers();
        futures_util::stream::iter(servers)
            .for_each_concurrent(8, |o| {
                let url = &url;
                async move {
                    let r = http_client::probe(o.as_ref(), url, Duration::from_secs(5))
                        .await
                        .ok();
                    self.tracker.record_delay(o.tag(), r);
                }
            })
            .await;
        Ok(())
    }

    /// `GET /dns/query?name=…&type=A`: ответ своего DNS (или системного,
    /// если раздела `dns` нет) в формате Clash.
    pub(super) async fn clash_dns_query(&self, name: &str, qtype: &str) -> Result<Value> {
        let t: RecordType = qtype
            .to_ascii_uppercase()
            .parse()
            .map_err(|_| Error::Config(format!("type: «{qtype}» — например A, AAAA, CNAME")))?;
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };
        let qname =
            Name::from_ascii(&fqdn).map_err(|e| Error::Config(format!("name: «{name}»: {e}")))?;
        let mut q = Message::query();
        q.metadata.recursion_desired = true;
        q.add_query(Query::query(qname, t));
        let question = json!([{ "Name": fqdn, "Qtype": u16::from(t), "Qclass": 1 }]);
        let dns = self.routers.get().dns().cloned();
        let Some(dns) = dns else {
            // Без своего DNS — системный резолвер, только A/AAAA.
            let ips: Vec<IpAddr> = match t {
                RecordType::A | RecordType::AAAA => tokio::net::lookup_host((name, 0))
                    .await
                    .map(|it| it.map(|a| a.ip()).collect())
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            let answer: Vec<Value> = ips
                .into_iter()
                .filter(|ip| matches!((ip, t), (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA)))
                .map(|ip| json!({ "name": fqdn, "type": u16::from(t), "TTL": 0, "data": ip.to_string() }))
                .collect();
            return Ok(json!({
                "Status": 0, "TC": false, "RD": true, "RA": true, "AD": false, "CD": false,
                "Question": question, "Answer": answer, "Server": "system",
            }));
        };
        let m = dns.handle(&q, false).await;
        let answer: Vec<Value> = m
            .answers
            .iter()
            .map(|r| {
                let data = match &r.data {
                    RData::A(a) => a.0.to_string(),
                    RData::AAAA(a) => a.0.to_string(),
                    other => other.to_string(),
                };
                json!({
                    "name": r.name.to_ascii(),
                    "type": u16::from(r.record_type()),
                    "TTL": r.ttl,
                    "data": data,
                })
            })
            .collect();
        Ok(json!({
            "Status": u16::from(m.metadata.response_code),
            "TC": m.metadata.truncation,
            "RD": m.metadata.recursion_desired,
            "RA": m.metadata.recursion_available,
            "AD": m.metadata.authentic_data,
            "CD": m.metadata.checking_disabled,
            "Question": question,
            "Answer": answer,
        }))
    }
}
