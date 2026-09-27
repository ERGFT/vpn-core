// SPDX-License-Identifier: GPL-3.0-or-later
//! Группы серверов — выходы, которые выбирают одного из участников:
//!
//! - `selector` — выбранный вручную (по умолчанию первый или `default`);
//! - `urltest` — самый быстрый по проверке; текущий не меняется, пока не
//!   хуже лучшего больше чем на `tolerance` (без «прыжков» туда-сюда);
//! - `fallback` — первый работающий по порядку.
//!
//! Проверка — HTTP-запрос через каждого участника к `url` раз в
//! `interval` со случайным разбросом ±20 % (одинаковый ритм проверок сам
//! по себе мог бы стать признаком для DPI). Плюс пассивный учёт: если
//! соединение через участника не открылось, он считается упавшим до
//! следующей проверки, а соединение пробует следующего (до трёх).
//!
//! Переключение не рвёт открытых соединений: новые идут через нового
//! участника, старые доживают своё.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::StreamExt;

use super::http_client::{self, Url};
use super::outbound::{Outbound, UdpSession};
use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::AsyncStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Selector,
    UrlTest,
    Fallback,
}

/// Задержка «не работает / ещё не проверялся».
const DOWN: u32 = u32::MAX;
const UNKNOWN: u32 = u32::MAX - 1;
/// Сколько участников пробовать для одного соединения.
const MAX_TRIES: usize = 3;
/// Сколько проверок одновременно.
const CHECK_PARALLEL: usize = 8;

pub struct Member {
    pub out: Arc<dyn Outbound>,
    /// Последняя задержка в мс (`DOWN`/`UNKNOWN` — нет данных).
    delay: AtomicU32,
}

impl Member {
    pub fn new(out: Arc<dyn Outbound>) -> Arc<Self> {
        Arc::new(Member {
            out,
            delay: AtomicU32::new(UNKNOWN),
        })
    }

    pub fn tag(&self) -> &str {
        self.out.tag()
    }

    /// Задержка по последней проверке; `None` — упал или не проверялся.
    pub fn delay(&self) -> Option<Duration> {
        match self.delay.load(Ordering::Relaxed) {
            DOWN | UNKNOWN => None,
            ms => Some(Duration::from_millis(ms as u64)),
        }
    }

    fn is_down(&self) -> bool {
        self.delay.load(Ordering::Relaxed) == DOWN
    }

    fn set_delay(&self, d: Option<Duration>) {
        let v = match d {
            Some(d) => (d.as_millis() as u32).min(UNKNOWN - 1),
            None => DOWN,
        };
        self.delay.store(v, Ordering::Relaxed);
    }
}

pub struct GroupSettings {
    pub strategy: Strategy,
    pub url: Url,
    pub interval: Duration,
    pub tolerance: Duration,
    pub timeout: Duration,
}

pub struct Group {
    tag: String,
    settings: GroupSettings,
    /// Участники из настроек (задаются после сборки всех выходов).
    fixed: RwLock<Vec<Arc<Member>>>,
    /// Участники из подписок: tag подписки → серверы.
    dynamic: RwLock<HashMap<String, Vec<Arc<Member>>>>,
    /// Выбранный (selector) или текущий (urltest) участник.
    current: RwLock<Option<String>>,
}

impl Group {
    pub fn new(tag: String, settings: GroupSettings, default: Option<String>) -> Arc<Self> {
        Arc::new(Group {
            tag,
            settings,
            fixed: RwLock::new(Vec::new()),
            dynamic: RwLock::new(HashMap::new()),
            current: RwLock::new(default),
        })
    }

    pub fn strategy(&self) -> Strategy {
        self.settings.strategy
    }

    pub fn set_fixed(&self, members: Vec<Arc<dyn Outbound>>) {
        *self.fixed.write().unwrap() = members.into_iter().map(Member::new).collect();
    }

    /// Заменить серверы подписки `key` (новые участники — без истории
    /// проверок; прежние с тем же tag сохраняют задержку).
    pub fn set_dynamic(&self, key: &str, members: Vec<Arc<dyn Outbound>>) {
        let mut g = self.dynamic.write().unwrap();
        let old: HashMap<String, u32> = g
            .get(key)
            .map(|v| {
                v.iter()
                    .map(|m| (m.tag().to_string(), m.delay.load(Ordering::Relaxed)))
                    .collect()
            })
            .unwrap_or_default();
        let new = members
            .into_iter()
            .map(|o| {
                let m = Member::new(o);
                if let Some(d) = old.get(m.tag()) {
                    m.delay.store(*d, Ordering::Relaxed);
                }
                m
            })
            .collect();
        g.insert(key.to_string(), new);
    }

    /// Все участники по порядку: из настроек, затем из подписок.
    pub fn members(&self) -> Vec<Arc<Member>> {
        let mut v = self.fixed.read().unwrap().clone();
        let d = self.dynamic.read().unwrap();
        let mut keys: Vec<&String> = d.keys().collect();
        keys.sort();
        for k in keys {
            v.extend(d[k].iter().cloned());
        }
        v
    }

    pub fn current(&self) -> Option<String> {
        self.current.read().unwrap().clone()
    }

    /// Выбрать участника вручную (selector).
    pub fn select(&self, tag: &str) -> Result<()> {
        if !self.members().iter().any(|m| m.tag() == tag) {
            return Err(Error::Config(format!(
                "группа {}: нет участника «{tag}»",
                self.tag
            )));
        }
        *self.current.write().unwrap() = Some(tag.to_string());
        tracing::info!(group = %self.tag, member = tag, "группа: выбран вручную");
        Ok(())
    }

    /// Участники в порядке, в котором их пробовать.
    fn candidates(&self) -> Vec<Arc<Member>> {
        let members = self.members();
        if members.is_empty() {
            return members;
        }
        let current = self.current();
        match self.settings.strategy {
            Strategy::Selector => {
                let pick = current
                    .as_deref()
                    .and_then(|t| members.iter().find(|m| m.tag() == t))
                    .unwrap_or(&members[0]);
                vec![pick.clone()]
            }
            Strategy::Fallback => {
                // Живые — по порядку, упавшие — в конце (вдруг ожили).
                let (up, down): (Vec<_>, Vec<_>) = members.into_iter().partition(|m| !m.is_down());
                up.into_iter().chain(down).collect()
            }
            Strategy::UrlTest => {
                let mut sorted = members.clone();
                sorted.sort_by_key(|m| m.delay.load(Ordering::Relaxed));
                let best = sorted[0].delay.load(Ordering::Relaxed);
                // Текущий остаётся, если жив и не хуже лучшего больше чем на
                // tolerance.
                let keep = current.as_deref().and_then(|t| {
                    sorted.iter().position(|m| {
                        m.tag() == t
                            && !m.is_down()
                            && (m.delay.load(Ordering::Relaxed) as u64)
                                <= best as u64 + self.settings.tolerance.as_millis() as u64
                    })
                });
                if let Some(i) = keep {
                    let m = sorted.remove(i);
                    sorted.insert(0, m);
                }
                sorted
            }
        }
    }

    fn note_choice(&self, m: &Member) {
        if self.settings.strategy == Strategy::Selector {
            return;
        }
        let mut cur = self.current.write().unwrap();
        if cur.as_deref() != Some(m.tag()) {
            tracing::info!(
                group = %self.tag,
                member = m.tag(),
                delay_ms = ?m.delay().map(|d| d.as_millis()),
                "группа: переключение"
            );
            *cur = Some(m.tag().to_string());
        }
    }

    /// Проверить всех участников.
    pub async fn check_all(&self) {
        let members = self.members();
        let url = &self.settings.url;
        let timeout = self.settings.timeout;
        futures_util::stream::iter(members)
            .for_each_concurrent(CHECK_PARALLEL, |m| async move {
                let r = http_client::probe(m.out.as_ref(), url, timeout).await;
                match &r {
                    Ok(d) => tracing::debug!(group = %self.tag, member = m.tag(), ms = d.as_millis(), "проверка"),
                    Err(e) => tracing::debug!(group = %self.tag, member = m.tag(), error = %e, "проверка не прошла"),
                }
                m.set_delay(r.ok());
            })
            .await;
        // Обновить текущий по итогам проверки.
        if let Some(first) = self.candidates().first() {
            if !first.is_down() {
                self.note_choice(first);
            }
        }
    }

    /// Проверять в фоне, пока группа жива (для `selector` — ничего).
    pub async fn check_loop(weak: Weak<Group>) -> Result<()> {
        loop {
            let Some(g) = weak.upgrade() else { break };
            if g.settings.strategy == Strategy::Selector {
                break;
            }
            let interval = g.settings.interval;
            g.check_all().await;
            drop(g);
            let jitter = rand::random::<f64>() * 0.4 + 0.8;
            tokio::time::sleep(interval.mul_f64(jitter)).await;
        }
        Ok(())
    }

    async fn try_members<'a, T, F>(&'a self, meta: &'a Metadata, f: F) -> Result<T>
    where
        F: Fn(Arc<Member>, &'a Metadata) -> BoxFuture<'a, Result<T>>,
    {
        let candidates = self.candidates();
        if candidates.is_empty() {
            return Err(Error::Protocol(format!(
                "группа {}: нет ни одного сервера (подписка ещё не загружена?)",
                self.tag
            )));
        }
        let mut last = None;
        for m in candidates.into_iter().take(MAX_TRIES) {
            match f(m.clone(), meta).await {
                Ok(v) => {
                    if m.is_down() {
                        // Ожил: пусть проверка уточнит задержку.
                        m.delay.store(UNKNOWN, Ordering::Relaxed);
                    }
                    self.note_choice(&m);
                    return Ok(v);
                }
                Err(Error::Blocked) => return Err(Error::Blocked),
                Err(e) => {
                    tracing::debug!(group = %self.tag, member = m.tag(), error = %e, "участник не ответил — следующий");
                    m.set_delay(None);
                    last = Some(e);
                    if self.settings.strategy == Strategy::Selector {
                        break;
                    }
                }
            }
        }
        Err(last.unwrap_or(Error::Protocol("группа: нет участников".into())))
    }
}

impl Outbound for Group {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(self.try_members(meta, |m, meta| {
            Box::pin(async move { m.out.connect(meta).await })
        }))
    }

    fn udp<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(self.try_members(meta, |m, meta| {
            Box::pin(async move { m.out.udp(meta).await })
        }))
    }

    fn as_group(&self) -> Option<&Group> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::outbound::{BlockOutbound, DirectOutbound};

    fn group(strategy: Strategy) -> Arc<Group> {
        Group::new(
            "g".into(),
            GroupSettings {
                strategy,
                url: Url::parse("http://127.0.0.1:1/").unwrap(),
                interval: Duration::from_secs(60),
                tolerance: Duration::from_millis(50),
                timeout: Duration::from_secs(1),
            },
            None,
        )
    }

    fn outs(tags: &[&str]) -> Vec<Arc<dyn Outbound>> {
        tags.iter()
            .map(|t| Arc::new(DirectOutbound::new(*t)) as Arc<dyn Outbound>)
            .collect()
    }

    fn order(g: &Group) -> Vec<String> {
        g.candidates().iter().map(|m| m.tag().to_string()).collect()
    }

    fn set(g: &Group, tag: &str, ms: Option<u64>) {
        let m = g.members().into_iter().find(|m| m.tag() == tag).unwrap();
        m.set_delay(ms.map(Duration::from_millis));
    }

    #[test]
    fn urltest_prefers_fastest_with_tolerance() {
        let g = group(Strategy::UrlTest);
        g.set_fixed(outs(&["a", "b", "c"]));
        set(&g, "a", Some(200));
        set(&g, "b", Some(100));
        set(&g, "c", None);
        assert_eq!(order(&g), ["b", "a", "c"]);
        g.note_choice(&g.candidates()[0]);
        // b стал чуть хуже a, но в пределах tolerance — остаётся.
        set(&g, "b", Some(230));
        assert_eq!(order(&g)[0], "b");
        // Намного хуже — переключаемся.
        set(&g, "b", Some(400));
        assert_eq!(order(&g)[0], "a");
        // Текущий упал — не держимся за него.
        g.note_choice(&g.candidates()[0]);
        set(&g, "a", None);
        assert_eq!(order(&g)[0], "b");
    }

    #[test]
    fn fallback_keeps_order_skipping_down() {
        let g = group(Strategy::Fallback);
        g.set_fixed(outs(&["a", "b", "c"]));
        assert_eq!(order(&g), ["a", "b", "c"]);
        set(&g, "a", None);
        assert_eq!(order(&g), ["b", "c", "a"]);
    }

    #[test]
    fn selector_and_dynamic_members() {
        let g = group(Strategy::Selector);
        g.set_fixed(outs(&["a"]));
        g.set_dynamic("sub", outs(&["sub/x", "sub/y"]));
        assert_eq!(g.members().len(), 3);
        assert_eq!(order(&g), ["a"]);
        g.select("sub/y").unwrap();
        assert_eq!(order(&g), ["sub/y"]);
        assert!(g.select("nope").is_err());
        // Подписка обновилась — задержки сохранились у тех же tag.
        let g2 = group(Strategy::UrlTest);
        g2.set_dynamic("s", outs(&["s/1", "s/2"]));
        set(&g2, "s/2", Some(10));
        g2.set_dynamic("s", outs(&["s/2", "s/3"]));
        assert_eq!(g2.members()[0].delay(), Some(Duration::from_millis(10)));
    }

    #[tokio::test]
    async fn connect_falls_through_failed_members() {
        let g = group(Strategy::Fallback);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        g.set_fixed(vec![
            Arc::new(BlockOutbound::new("blocked")) as Arc<dyn Outbound>,
            Arc::new(DirectOutbound::new("ok")),
        ]);
        let meta = Metadata {
            inbound: "t".into(),
            source: "127.0.0.1:1".parse().unwrap(),
            network: crate::app::Network::Tcp,
            target: crate::vless::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            port,
            sniffed: None,
        };
        // block — это отказ правилом, а не сбой: дальше не пробуем.
        assert!(matches!(g.connect(&meta).await, Err(Error::Blocked)));

        let g = group(Strategy::Fallback);
        g.set_fixed(outs(&["first", "second"]));
        let dead = Metadata {
            port: 1,
            ..meta.clone()
        };
        assert!(g.connect(&dead).await.is_err());
        assert!(
            g.members().iter().all(|m| m.is_down()),
            "оба помечены упавшими"
        );
        g.connect(&meta).await.expect("ожили");
        assert_eq!(g.current().as_deref(), Some("first"));
    }

    #[tokio::test]
    async fn check_all_measures_members() {
        // «Сайт проверки» — отвечает 204.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            }
        });
        let g = Group::new(
            "g".into(),
            GroupSettings {
                strategy: Strategy::UrlTest,
                url: Url::parse(&format!("http://127.0.0.1:{port}/generate_204")).unwrap(),
                interval: Duration::from_secs(60),
                tolerance: Duration::from_millis(50),
                timeout: Duration::from_secs(2),
            },
            None,
        );
        g.set_fixed(vec![
            Arc::new(BlockOutbound::new("blocked")) as Arc<dyn Outbound>,
            Arc::new(DirectOutbound::new("direct")),
        ]);
        g.check_all().await;
        let m = g.members();
        assert!(m[0].is_down());
        assert!(m[1].delay().is_some());
        assert_eq!(g.current().as_deref(), Some("direct"));
    }
}
