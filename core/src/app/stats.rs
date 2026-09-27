//! Учёт соединений и трафика — для локального API (`api.rs`): сколько
//! передано всего и по выходам, какие соединения открыты сейчас, закрыть
//! соединение.
//!
//! Адреса сайтов здесь — это история посещений, поэтому наружу они
//! уходят только через API (127.0.0.1 и токен) и в журнал не пишутся.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

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
}

pub struct ConnInfo {
    pub id: u64,
    pub inbound: Arc<str>,
    pub network: Network,
    /// Назначение (имя или адрес) и порт.
    pub target: String,
    pub port: u16,
    pub outbound: String,
    /// Участник группы, если выход — группа.
    pub member: Option<String>,
    /// Время начала, секунды Unix.
    pub start: u64,
    up: AtomicU64,
    down: AtomicU64,
    cancel: CancellationToken,
    outbound_traffic: Arc<Traffic>,
}

impl ConnInfo {
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
            self.tracker.conns.lock().unwrap().remove(&self.info.id);
        }
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

#[derive(Debug, serde::Serialize)]
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
}

impl Default for Tracker {
    fn default() -> Self {
        Tracker {
            started: Instant::now(),
            next_id: AtomicU64::new(1),
            conns: Mutex::new(HashMap::new()),
            total: Traffic::default(),
            per_outbound: Mutex::new(HashMap::new()),
        }
    }
}

impl Tracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
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
            .unwrap()
            .entry(outbound.to_string())
            .or_default()
            .clone();
        let info = Arc::new(ConnInfo {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            inbound: meta.inbound.clone(),
            network: meta.network,
            target: meta.target.to_string(),
            port: meta.port,
            outbound: outbound.to_string(),
            member,
            start: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            cancel: CancellationToken::new(),
            outbound_traffic: traffic,
        });
        let mut conns = self.conns.lock().unwrap();
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

    pub fn summary(&self) -> Summary {
        let mut outbounds: Vec<OutboundTraffic> = self
            .per_outbound
            .lock()
            .unwrap()
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
            connections: self.conns.lock().unwrap().len(),
            outbounds,
        }
    }

    pub fn connections(&self) -> Vec<ConnView> {
        let mut v: Vec<ConnView> = self
            .conns
            .lock()
            .unwrap()
            .values()
            .map(|c| ConnView {
                id: c.id,
                inbound: c.inbound.to_string(),
                network: match c.network {
                    Network::Tcp => "tcp",
                    Network::Udp => "udp",
                },
                target: c.target.clone(),
                port: c.port,
                outbound: c.outbound.clone(),
                member: c.member.clone(),
                start: c.start,
                up: c.up(),
                down: c.down(),
            })
            .collect();
        v.sort_by_key(|c| c.id);
        v
    }

    /// Закрыть соединение; `false` — такого нет.
    pub fn close(&self, id: u64) -> bool {
        match self.conns.lock().unwrap().get(&id) {
            Some(c) => {
                c.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// Закрыть все соединения (например, через выход, которого больше нет).
    pub fn close_all(&self) -> usize {
        let conns = self.conns.lock().unwrap();
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
