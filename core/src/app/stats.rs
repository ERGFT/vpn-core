// SPDX-License-Identifier: GPL-3.0-or-later
//! Учёт соединений и трафика — для локального API (`api.rs`): сколько
//! передано всего и по выходам, какие соединения открыты сейчас, закрыть
//! соединение. Здесь же — всё, что живёт всё время работы приложения и
//! переживает перечитывание настроек: шина событий, режим маршрутизации
//! (rule/global/direct), последние задержки серверов.
//!
//! Адреса сайтов здесь — это история посещений, поэтому наружу они
//! уходят только через API (127.0.0.1 и токен) и в журнал не пишутся.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use super::events::{Bus, Event};
use super::{Metadata, Network};

/// Потолок на число одновременно учитываемых соединений (больше — не
/// учитываются, но работают).
const MAX_TRACKED: usize = 65536;

#[derive(Default)]
struct Traffic {
    up: AtomicU64,
    down: AtomicU64,
}

pub struct Tracker {
    started: Instant,
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, Arc<ConnInfo>>>,
    total: Traffic,
    per_outbound: Mutex<HashMap<String, Arc<Traffic>>>,
    /// События для `GET /events`.
    pub events: Bus,
    /// Режим маршрутизации ([`Mode`]).
    mode: AtomicU8,
    /// Последняя проверка задержки каждого выхода: время (мс Unix) и
    /// задержка (`None` — не ответил).
    delays: Mutex<HashMap<String, (u64, Option<u64>)>>,
}

/// Режим маршрутизации, как в Clash: по правилам, всё через выбранный в
/// группе `GLOBAL` выход или всё напрямую. Перехват DNS работает в любом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Rule,
    Global,
    Direct,
}

impl Mode {
    /// Как в Clash API: `Rule`, `Global`, `Direct`.
    pub fn clash_name(self) -> &'static str {
        match self {
            Mode::Rule => "Rule",
            Mode::Global => "Global",
            Mode::Direct => "Direct",
        }
    }

    /// `rule`, `global`, `direct` в любом регистре.
    pub fn parse(s: &str) -> Option<Mode> {
        match s.to_ascii_lowercase().as_str() {
            "rule" => Some(Mode::Rule),
            "global" => Some(Mode::Global),
            "direct" => Some(Mode::Direct),
            _ => None,
        }
    }
}

/// Миллисекунды Unix сейчас.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Время в RFC 3339 (UTC, с миллисекундами), как его отдаёт Clash API.
pub fn rfc3339(unix_ms: u64) -> String {
    let secs = (unix_ms / 1000) as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Гражданская дата из дней от 1970-01-01 (алгоритм Хиннанта).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        unix_ms % 1000
    )
}

pub struct ConnInfo {
    pub id: u64,
    pub inbound: Arc<str>,
    /// Вид входа: `mixed`, `tun`…
    pub inbound_type: &'static str,
    /// Приложение.
    pub source: SocketAddr,
    /// Имя, найденное sniffing'ом.
    pub sniffed: Option<String>,
    /// Какое правило выбрало выход (`None` — `route.final`).
    pub rule: Option<Arc<str>>,
    pub network: Network,
    /// Назначение (имя или адрес) и порт.
    pub target: String,
    pub port: u16,
    pub outbound: String,
    /// Участник группы, если выход — группа.
    pub member: Option<String>,
    /// Время начала, секунды Unix.
    pub start: u64,
    start_ms: u64,
    up: AtomicU64,
    down: AtomicU64,
    cancel: CancellationToken,
    outbound_traffic: Arc<Traffic>,
    opened: Instant,
}

impl ConnInfo {
    pub fn view(&self) -> ConnView {
        ConnView {
            id: self.id,
            inbound: self.inbound.to_string(),
            network: match self.network {
                Network::Tcp => "tcp",
                Network::Udp => "udp",
            },
            target: self.target.clone(),
            port: self.port,
            outbound: self.outbound.clone(),
            member: self.member.clone(),
            start: self.start,
            up: self.up(),
            down: self.down(),
            rule: self.rule.as_deref().map(str::to_string),
            sniffed: self.sniffed.clone(),
        }
    }

    /// Соединение в формате Clash API (`GET /connections`).
    pub fn clash(&self) -> serde_json::Value {
        let target_ip = self.target.parse::<std::net::IpAddr>().is_ok();
        let host = if target_ip {
            self.sniffed.clone().unwrap_or_default()
        } else {
            self.target.clone()
        };
        // Цепочка — от последнего выхода к первому, как у Clash.
        let mut chains = Vec::new();
        if let Some(m) = &self.member {
            chains.push(m.clone());
        }
        chains.push(self.outbound.clone());
        serde_json::json!({
            "id": self.id.to_string(),
            "metadata": {
                "network": match self.network {
                    Network::Tcp => "tcp",
                    Network::Udp => "udp",
                },
                "type": format!("{}/{}", self.inbound_type, self.inbound),
                "sourceIP": self.source.ip().to_canonical().to_string(),
                "sourcePort": self.source.port().to_string(),
                "destinationIP": if target_ip { self.target.as_str() } else { "" },
                "destinationPort": self.port.to_string(),
                "host": host,
                "dnsMode": "normal",
                "processPath": "",
            },
            "upload": self.up(),
            "download": self.down(),
            "start": rfc3339(self.start_ms),
            "chains": chains,
            "rule": self.rule.as_deref().unwrap_or("final"),
            "rulePayload": "",
        })
    }
    pub fn up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }
    pub fn down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }
    pub fn cancelled(&self) -> tokio_util::sync::WaitForCancellationFuture<'_> {
        self.cancel.cancelled()
    }
    fn add_up(&self, t: &Tracker, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
        self.outbound_traffic.up.fetch_add(n, Ordering::Relaxed);
        t.total.up.fetch_add(n, Ordering::Relaxed);
    }
    fn add_down(&self, t: &Tracker, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
        self.outbound_traffic.down.fetch_add(n, Ordering::Relaxed);
        t.total.down.fetch_add(n, Ordering::Relaxed);
    }
}

/// Пока жив — соединение в списке открытых.
pub struct ConnGuard {
    tracker: Arc<Tracker>,
    pub info: Arc<ConnInfo>,
    registered: bool,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if self.registered {
            self.tracker
                .conns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.info.id);
        }
        let c = &self.info;
        self.tracker.events.emit(|| Event::ConnectionClose {
            id: c.id,
            up: c.up(),
            down: c.down(),
            duration_ms: c.opened.elapsed().as_millis() as u64,
        });
    }
}

impl ConnGuard {
    /// Учесть данные UDP (у TCP это делает [`Counted`]).
    pub fn add_up(&self, n: u64) {
        self.info.add_up(&self.tracker, n);
    }
    pub fn add_down(&self, n: u64) {
        self.info.add_down(&self.tracker, n);
    }
}

/// Сводка для API.
#[derive(Debug, serde::Serialize)]
pub struct Summary {
    pub uptime_secs: u64,
    pub up: u64,
    pub down: u64,
    pub connections: usize,
    pub outbounds: Vec<OutboundTraffic>,
}

#[derive(Debug, serde::Serialize)]
pub struct OutboundTraffic {
    pub tag: String,
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnView {
    pub id: u64,
    pub inbound: String,
    pub network: &'static str,
    pub target: String,
    pub port: u16,
    pub outbound: String,
    pub member: Option<String>,
    pub start: u64,
    pub up: u64,
    pub down: u64,
    /// Правило, выбравшее выход (`None` — `route.final`).
    pub rule: Option<String>,
    /// Имя, найденное sniffing'ом.
    pub sniffed: Option<String>,
}

impl Default for Tracker {
    fn default() -> Self {
        Tracker {
            started: Instant::now(),
            next_id: AtomicU64::new(1),
            conns: Mutex::new(HashMap::new()),
            total: Traffic::default(),
            per_outbound: Mutex::new(HashMap::new()),
            events: Bus::default(),
            mode: AtomicU8::new(0),
            delays: Mutex::new(HashMap::new()),
        }
    }
}

impl Tracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn mode(&self) -> Mode {
        match self.mode.load(Ordering::Relaxed) {
            1 => Mode::Global,
            2 => Mode::Direct,
            _ => Mode::Rule,
        }
    }

    /// Сменить режим; событие `mode_change`, если он и правда сменился.
    pub fn set_mode(&self, m: Mode) {
        let v = match m {
            Mode::Rule => 0,
            Mode::Global => 1,
            Mode::Direct => 2,
        };
        if self.mode.swap(v, Ordering::Relaxed) != v {
            tracing::info!(mode = m.clash_name(), "режим маршрутизации");
            self.events.emit(|| Event::ModeChange {
                mode: m.clash_name().to_ascii_lowercase(),
            });
        }
    }

    /// Запомнить итог проверки задержки выхода `tag`.
    pub fn record_delay(&self, tag: &str, delay: Option<std::time::Duration>) {
        self.delays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                tag.to_string(),
                (now_ms(), delay.map(|d| d.as_millis() as u64)),
            );
    }

    /// Последняя проверка выхода: время (мс Unix) и задержка.
    pub fn last_delay(&self, tag: &str) -> Option<(u64, Option<u64>)> {
        self.delays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tag)
            .copied()
    }

    /// Начать учёт соединения через выход `outbound` (и участника группы).
    pub fn open(
        self: &Arc<Self>,
        meta: &Metadata,
        outbound: &str,
        member: Option<String>,
    ) -> ConnGuard {
        let traffic = self
            .per_outbound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(outbound.to_string())
            .or_default()
            .clone();
        let start_ms = now_ms();
        let info = Arc::new(ConnInfo {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            inbound: meta.inbound.clone(),
            inbound_type: meta.inbound_type,
            source: meta.source,
            sniffed: meta.sniffed.clone(),
            rule: meta.rule.clone(),
            network: meta.network,
            target: meta.target.to_string(),
            port: meta.port,
            outbound: outbound.to_string(),
            member,
            start: start_ms / 1000,
            start_ms,
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            cancel: CancellationToken::new(),
            outbound_traffic: traffic,
            opened: Instant::now(),
        });
        self.events.emit(|| Event::ConnectionOpen(info.view()));
        let mut conns = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let registered = conns.len() < MAX_TRACKED;
        if registered {
            conns.insert(info.id, info.clone());
        }
        ConnGuard {
            tracker: self.clone(),
            info,
            registered,
        }
    }

    /// Передано всего: вверх и вниз.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.total.up.load(Ordering::Relaxed),
            self.total.down.load(Ordering::Relaxed),
        )
    }

    pub fn summary(&self) -> Summary {
        let mut outbounds: Vec<OutboundTraffic> = self
            .per_outbound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(k, t)| OutboundTraffic {
                tag: k.clone(),
                up: t.up.load(Ordering::Relaxed),
                down: t.down.load(Ordering::Relaxed),
            })
            .collect();
        outbounds.sort_by(|a, b| a.tag.cmp(&b.tag));
        Summary {
            uptime_secs: self.started.elapsed().as_secs(),
            up: self.total.up.load(Ordering::Relaxed),
            down: self.total.down.load(Ordering::Relaxed),
            connections: self
                .conns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            outbounds,
        }
    }

    pub fn connections(&self) -> Vec<ConnView> {
        let mut v: Vec<ConnView> = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(|c| c.view())
            .collect();
        v.sort_by_key(|c| c.id);
        v
    }

    /// Открытые соединения в формате Clash API.
    pub fn clash_connections(&self) -> Vec<serde_json::Value> {
        let mut v: Vec<Arc<ConnInfo>> = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|c| c.id);
        v.iter().map(|c| c.clash()).collect()
    }

    /// Закрыть соединение; `false` — такого нет.
    pub fn close(&self, id: u64) -> bool {
        match self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
        {
            Some(c) => {
                c.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// Закрыть все соединения (например, через выход, которого больше нет).
    pub fn close_all(&self) -> usize {
        let conns = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for c in conns.values() {
            c.cancel.cancel();
        }
        conns.len()
    }
}

/// Поток выхода со счётчиками: запись — «вверх», чтение — «вниз».
pub struct Counted<S> {
    inner: S,
    guard: ConnGuard,
}

impl<S> Counted<S> {
    pub fn new(inner: S, guard: ConnGuard) -> Self {
        Counted { inner, guard }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            this.guard.add_down(n as u64);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            this.guard.add_up(*n as u64);
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
