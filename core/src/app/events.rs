// SPDX-License-Identifier: GPL-3.0-or-later
//! События для потоков API (`GET /events`, `/logs`, `/traffic`, `/memory`):
//! клиент узнаёт о переменах сразу, а не опрашивает API.
//!
//! [`Bus`] — одна на приложение (переживает перечитывание настроек):
//! открытие и закрытие соединений, переключение и проверка групп,
//! обновление подписок, перечитывание настроек. Пока никто не слушает,
//! событие даже не собирается — на пути соединения это одно атомарное
//! чтение.
//!
//! Журнал ([`LogLayer`]) — общий на процесс, как и сам `tracing`: слой
//! добавляется к подписчику журнала программы и отдаёт в API то, что
//! пишется в журнал (уровень задаёт `RUST_LOG`; `?level=` в API только
//! сужает).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use serde::Serialize;
use tokio::sync::broadcast;

use super::stats::ConnView;

/// Сколько событий держать для медленного слушателя; отставший получает
/// событие `lagged` и может перечитать состояние (`GET /connections`).
const CAPACITY: usize = 1024;

/// Событие приложения; в JSON — объект с полем `type`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Открыто соединение (поля — как в `GET /connections`).
    ConnectionOpen(ConnView),
    /// Соединение закрыто: итог трафика.
    ConnectionClose {
        id: u64,
        up: u64,
        down: u64,
        duration_ms: u64,
    },
    /// Группа сменила участника: сама (`urltest`/`fallback`) или вручную.
    GroupSwitch {
        group: String,
        member: String,
        previous: Option<String>,
        delay_ms: Option<u64>,
        manual: bool,
    },
    /// Проверка участников группы закончена.
    GroupCheck {
        group: String,
        current: Option<String>,
        members: Vec<MemberDelay>,
    },
    /// Подписка обновлена (`servers` — сколько серверов) или нет (`error`).
    SubscriptionUpdate {
        subscription: String,
        servers: Option<usize>,
        error: Option<String>,
    },
    /// Настройки перечитаны.
    Reload { notes: Vec<String> },
    /// Слушатель не успевал: `skipped` событий пропущено.
    Lagged { skipped: u64 },
}

#[derive(Debug, Clone, Serialize)]
pub struct MemberDelay {
    pub tag: String,
    /// `null` — упал или ещё не проверялся.
    pub delay_ms: Option<u64>,
}

/// Шина событий: `emit` — дёшево, пока никто не слушает.
#[derive(Clone)]
pub struct Bus {
    tx: broadcast::Sender<Arc<Event>>,
    listeners: Arc<AtomicUsize>,
}

impl Default for Bus {
    fn default() -> Self {
        Bus {
            tx: broadcast::channel(CAPACITY).0,
            listeners: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Bus {
    /// Отправить событие; `make` вызывается, только если есть слушатели.
    pub fn emit(&self, make: impl FnOnce() -> Event) {
        if self.listeners.load(Ordering::Relaxed) > 0 {
            let _ = self.tx.send(Arc::new(make()));
        }
    }

    pub fn subscribe(&self) -> Listener<Arc<Event>> {
        Listener::new(self.tx.subscribe(), self.listeners.clone())
    }
}

/// Подписка на шину; пока жива — события собираются.
pub struct Listener<T> {
    pub rx: broadcast::Receiver<T>,
    count: Arc<AtomicUsize>,
}

impl<T> Listener<T> {
    fn new(rx: broadcast::Receiver<T>, count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Listener { rx, count }
    }
}

impl<T> Drop for Listener<T> {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Строка журнала — как в Clash API: `{"type": "info", "payload": "…"}`.
#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    #[serde(rename = "type")]
    pub level: &'static str,
    pub payload: String,
}

/// Уровни Clash: чем меньше число, тем подробнее.
pub fn level_rank(level: &str) -> Option<u8> {
    Some(match level {
        "trace" => 0,
        "debug" => 1,
        "info" => 2,
        "warning" | "warn" => 3,
        "error" => 4,
        "silent" => 5,
        _ => return None,
    })
}

struct LogBus {
    tx: broadcast::Sender<Arc<LogLine>>,
    listeners: Arc<AtomicUsize>,
}

fn log_bus() -> &'static LogBus {
    static BUS: OnceLock<LogBus> = OnceLock::new();
    BUS.get_or_init(|| LogBus {
        tx: broadcast::channel(CAPACITY).0,
        listeners: Arc::new(AtomicUsize::new(0)),
    })
}

/// Подписаться на журнал.
pub fn subscribe_logs() -> Listener<Arc<LogLine>> {
    let b = log_bus();
    Listener::new(b.tx.subscribe(), b.listeners.clone())
}

/// Слой `tracing`, отдающий журнал в `GET /logs`:
/// `tracing_subscriber::fmt()…finish().with(LogLayer).init()`.
pub struct LogLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let bus = log_bus();
        if bus.listeners.load(Ordering::Relaxed) == 0 {
            return;
        }
        let meta = event.metadata();
        let level = match *meta.level() {
            tracing::Level::TRACE => "trace",
            tracing::Level::DEBUG => "debug",
            tracing::Level::INFO => "info",
            tracing::Level::WARN => "warning",
            tracing::Level::ERROR => "error",
        };
        let mut v = Fields::default();
        event.record(&mut v);
        let mut payload = format!("{}: {}", meta.target(), v.message);
        payload.push_str(&v.rest);
        let _ = bus.tx.send(Arc::new(LogLine { level, payload }));
    }
}

#[derive(Default)]
struct Fields {
    message: String,
    rest: String,
}

impl tracing::field::Visit for Fields {
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        if f.name() == "message" {
            self.message.push_str(v);
        } else {
            let _ = write!(self.rest, " {}={v}", f.name());
        }
    }

    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            let _ = write!(self.message, "{v:?}");
        } else {
            let _ = write!(self.rest, " {}={v:?}", f.name());
        }
    }
}

/// Память процесса, байт (Linux — VmRSS, Windows — рабочий набор;
/// где узнать нечем — 0).
pub fn memory_in_use() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("VmRSS:"))
                    .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            })
            .map(|kb| kb * 1024)
            .unwrap_or(0)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: структура — обычные числа, размер передаётся; дескриптор
        // текущего процесса — псевдодескриптор, закрывать не нужно.
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
                c.WorkingSetSize as u64
            } else {
                0
            }
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_only_with_listeners() {
        let bus = Bus::default();
        let mut built = false;
        bus.emit(|| {
            built = true;
            Event::Reload { notes: vec![] }
        });
        assert!(!built, "без слушателей событие не собирается");
        let mut l = bus.subscribe();
        bus.emit(|| Event::Reload {
            notes: vec!["x".into()],
        });
        let e = l.rx.try_recv().unwrap();
        assert_eq!(
            serde_json::to_value(&*e).unwrap(),
            serde_json::json!({ "type": "reload", "notes": ["x"] })
        );
        drop(l);
        assert_eq!(bus.listeners.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn levels() {
        assert!(level_rank("debug") < level_rank("warning"));
        assert_eq!(level_rank("warn"), level_rank("warning"));
        assert_eq!(level_rank("loud"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_is_known() {
        assert!(memory_in_use() > 1 << 20);
    }
}
