// SPDX-License-Identifier: GPL-3.0-or-later
//! Общие HTTP/2-соединения для транспортов gRPC и xhttp (у Xray — общий
//! `grpc.ClientConn` на сервер и `xmux` у xhttp): несколько VLESS-сессий —
//! отдельные потоки HTTP/2 в одном соединении TLS/REALITY.
//!
//! Правила выбора — как `XmuxManager.GetXmuxClient` у Xray:
//!
//! - негодные соединения убираются: закрытые, исчерпавшие число сессий
//!   (`cMaxReuseTimes`), запросов (`hMaxRequestTimes`) или время
//!   (`hMaxReusableSecs`); сессии на них доживают своё;
//! - пусто — новое соединение; `maxConnections > 0` — новые, пока их
//!   меньше этого числа;
//! - иначе случайное из тех, где сессий меньше `maxConcurrency` (0 — без
//!   предела); таких нет — новое.
//!
//! Пределы каждого соединения выбираются случайно из диапазонов при его
//! создании (ровные числа — признак). Соединение без сессий закрывается
//! через [`IDLE`].

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use h2::client::SendRequest;
use rand::RngExt;
use tokio::sync::OnceCell;

use crate::error::{Error, Result};
use crate::transport::xhttp::Range;

/// Уменьшить счётчик на 1, если он больше нуля (без `fetch_update`: в
/// новых Rust он переименован в `try_update`, которого нет в MSRV).
fn dec_if_positive(a: &AtomicI64) {
    let mut v = a.load(Ordering::Relaxed);
    while v > 0 {
        match a.compare_exchange_weak(v, v - 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(cur) => v = cur,
        }
    }
}

/// Соединение без сессий закрывается через столько.
pub const IDLE: Duration = Duration::from_secs(90);

/// Пределы переиспользования (`xmux` у Xray); 0 — без предела.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_concurrency: Range,
    pub max_connections: u32,
    pub max_reuse: Range,
    pub max_requests: Range,
    pub max_age_secs: Range,
}

impl Limits {
    /// Всё в одном соединении, без пределов (gRPC у Xray).
    pub const UNLIMITED: Limits = Limits {
        max_concurrency: Range { from: 0, to: 0 },
        max_connections: 0,
        max_reuse: Range { from: 0, to: 0 },
        max_requests: Range { from: 0, to: 0 },
        max_age_secs: Range { from: 0, to: 0 },
    };
}

/// Отправитель запросов соединения: h2 (`SendRequest`) или h3.
pub trait Sender: Clone + Send + Sync + 'static {
    /// Дождаться готовности к новому запросу (у h2 — место в
    /// `max_concurrent_streams`); ошибка — соединение закрыто.
    fn ready(self) -> BoxFuture<'static, std::result::Result<Self, String>>;
}

impl Sender for SendRequest<Bytes> {
    fn ready(self) -> BoxFuture<'static, std::result::Result<Self, String>> {
        Box::pin(async move { SendRequest::ready(self).await.map_err(|e| e.to_string()) })
    }
}

struct Entry<S> {
    send: OnceCell<S>,
    /// Открытые сессии.
    open: AtomicUsize,
    /// Сколько ещё сессий можно начать (−1 — без предела).
    left_reuse: AtomicI64,
    /// Сколько ещё запросов (−1 — без предела).
    left_requests: AtomicI64,
    unreusable_at: Option<Instant>,
    dead: Arc<AtomicBool>,
    idle_since: Mutex<Instant>,
}

impl<S> Entry<S> {
    fn usable(&self) -> bool {
        !self.dead.load(Ordering::Relaxed)
            && self.left_reuse.load(Ordering::Relaxed) != 0
            && self.left_requests.load(Ordering::Relaxed) != 0
            && self.unreusable_at.is_none_or(|t| Instant::now() < t)
    }
}

fn pick_limit(r: Range) -> i64 {
    match r.rand() {
        0 => -1,
        n => n as i64,
    }
}

struct Pool<S> {
    entries: Mutex<Vec<Arc<Entry<S>>>>,
}

/// Пул любого типа отправителя (ключи у h2 и h3 разные).
trait AnyPool: Send + Sync {
    fn live(&self) -> usize;
    fn as_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

impl<S: Send + Sync + 'static> AnyPool for Pool<S> {
    fn live(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|e| !e.dead.load(Ordering::Relaxed))
            .count()
    }

    fn as_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

fn pools() -> &'static Mutex<HashMap<String, Arc<dyn AnyPool>>> {
    static P: std::sync::OnceLock<Mutex<HashMap<String, Arc<dyn AnyPool>>>> =
        std::sync::OnceLock::new();
    P.get_or_init(Default::default)
}

fn pool_for<S: Send + Sync + 'static>(key: &str) -> Arc<Pool<S>> {
    let mut all = pools()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(p) = all.get(key) {
        if let Ok(p) = p.clone().as_any().downcast::<Pool<S>>() {
            return p;
        }
    }
    let p = Arc::new(Pool {
        entries: Mutex::new(Vec::new()),
    });
    all.insert(key.to_string(), p.clone());
    p
}

/// Место в соединении на одну сессию; сброс освобождает его.
pub struct Lease<S = SendRequest<Bytes>> {
    entry: Arc<Entry<S>>,
    send: S,
}

impl<S: Clone> Lease<S> {
    /// Отправитель запросов этого соединения; каждый запрос уменьшает
    /// остаток `hMaxRequestTimes`.
    pub fn request(&self) -> S {
        self.note_request();
        self.send.clone()
    }

    /// Учесть ещё один запрос в этом соединении.
    pub fn note_request(&self) {
        dec_if_positive(&self.entry.left_requests);
    }

    /// Соединение закрыто.
    pub fn is_dead(&self) -> bool {
        self.entry.dead.load(Ordering::Relaxed)
    }
}

impl<S> Drop for Lease<S> {
    fn drop(&mut self) {
        if self.entry.open.fetch_sub(1, Ordering::Relaxed) == 1 {
            *self
                .entry
                .idle_since
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        }
    }
}

/// Готовое соединение: отправитель и задача, которая его ведёт.
pub type Connected<S = SendRequest<Bytes>> = (S, BoxFuture<'static, ()>);

/// Взять место в соединении для `key` или открыть новое (`connect`).
/// Соединение из пула оказалось закрытым — одна попытка на новом.
pub async fn acquire<S, F>(key: &str, limits: &Limits, connect: F) -> Result<Lease<S>>
where
    S: Sender,
    F: Fn() -> BoxFuture<'static, Result<Connected<S>>>,
{
    match acquire_once(key, limits, &connect).await {
        Err(Fail::Retry(e)) => {
            tracing::debug!(error = %e, "HTTP/2: соединение из пула закрыто — новое");
            acquire_once(key, limits, &connect)
                .await
                .map_err(Fail::into_error)
        }
        r => r.map_err(Fail::into_error),
    }
}

enum Fail {
    Fatal(Error),
    /// Соединение из пула оказалось закрытым — стоит попробовать новое.
    Retry(Error),
}

impl Fail {
    fn into_error(self) -> Error {
        match self {
            Fail::Fatal(e) | Fail::Retry(e) => e,
        }
    }
}

async fn acquire_once<S, F>(
    key: &str,
    limits: &Limits,
    connect: &F,
) -> std::result::Result<Lease<S>, Fail>
where
    S: Sender,
    F: Fn() -> BoxFuture<'static, Result<Connected<S>>>,
{
    let pool = pool_for::<S>(key);
    let entry = {
        let mut entries = pool
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|e| e.usable() && !(e.send.initialized() && idle_expired(e)));
        let conc = limits.max_concurrency;
        let candidates: Vec<&Arc<Entry<S>>> = entries
            .iter()
            .filter(|e| conc.to == 0 || e.open.load(Ordering::Relaxed) < conc.to as usize)
            .collect();
        let need_new = entries.is_empty()
            || (limits.max_connections > 0 && entries.len() < limits.max_connections as usize)
            || candidates.is_empty();
        let e = if need_new {
            let age = limits.max_age_secs.rand();
            let e = Arc::new(Entry::<S> {
                send: OnceCell::new(),
                open: AtomicUsize::new(0),
                left_reuse: AtomicI64::new(pick_limit(limits.max_reuse)),
                left_requests: AtomicI64::new(pick_limit(limits.max_requests)),
                unreusable_at: (age > 0).then(|| Instant::now() + Duration::from_secs(age as u64)),
                dead: Arc::new(AtomicBool::new(false)),
                idle_since: Mutex::new(Instant::now()),
            });
            entries.push(e.clone());
            e
        } else {
            candidates[rand::rng().random_range(0..candidates.len())].clone()
        };
        dec_if_positive(&e.left_reuse);
        e.open.fetch_add(1, Ordering::Relaxed);
        e
    };
    // Освободить место при ошибке ниже.
    let guard = OpenGuard(Some(entry.clone()));
    let dead = entry.dead.clone();
    let weak_pool = Arc::downgrade(&pool);
    let weak_entry = Arc::downgrade(&entry);
    let reused = entry.send.initialized();
    let send = entry
        .send
        .get_or_try_init(|| async move {
            let r = connect().await;
            let (send, driver) = match r {
                Ok(c) => c,
                Err(e) => {
                    dead.store(true, Ordering::Relaxed);
                    return Err(e);
                }
            };
            let d2 = dead.clone();
            tokio::spawn(async move {
                driver.await;
                d2.store(true, Ordering::Relaxed);
            });
            tokio::spawn(reaper(weak_pool, weak_entry));
            Ok::<_, Error>(send)
        })
        .await
        .map_err(Fail::Fatal)?
        .clone();
    let send = Sender::ready(send).await.map_err(|e| {
        entry.dead.store(true, Ordering::Relaxed);
        let e = Error::Protocol(format!("HTTP-соединение не готово: {e}"));
        if reused {
            Fail::Retry(e)
        } else {
            Fail::Fatal(e)
        }
    })?;
    guard.disarm();
    Ok(Lease { entry, send })
}

fn idle_expired<S>(e: &Entry<S>) -> bool {
    e.open.load(Ordering::Relaxed) == 0
        && e.idle_since
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed()
            >= IDLE
}

/// Убрать из пула соединение, простоявшее без сессий [`IDLE`]: последний
/// отправитель пропадает, и h2 закрывает соединение.
async fn reaper<S>(pool: Weak<Pool<S>>, entry: Weak<Entry<S>>) {
    loop {
        tokio::time::sleep(IDLE / 3).await;
        let (Some(p), Some(e)) = (pool.upgrade(), entry.upgrade()) else {
            break;
        };
        if e.dead.load(Ordering::Relaxed) || idle_expired(&e) || !e.usable() {
            p.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|x| !Arc::ptr_eq(x, &e));
            if e.dead.load(Ordering::Relaxed) || idle_expired(&e) {
                break;
            }
        }
    }
}

struct OpenGuard<S>(Option<Arc<Entry<S>>>);

impl<S> OpenGuard<S> {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl<S> Drop for OpenGuard<S> {
    fn drop(&mut self) {
        if let Some(e) = self.0.take() {
            e.open.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Сколько соединений сейчас в пуле `key` (для тестов).
pub fn connections(key: &str) -> usize {
    pools()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(key)
        .map(|p| p.live())
        .unwrap_or(0)
}
