// SPDX-License-Identifier: GPL-3.0-or-later
//! Ядро как библиотека: C ABI для приложений — Android (`VpnService`),
//! iOS (Network Extension), десктопных клиентов. Заголовок —
//! `ffi/include/reality.h`, описание — `docs/LIBRARY.md`.
//!
//! Всё, что умеет API по HTTP, доступно вызовом [`rc_request`] — те же
//! пути и ответы (Clash API и свои), без сети и токена. События и журнал —
//! обратными вызовами. На Android и iOS приложение отдаёт ядру дескриптор
//! TUN и «защищает» сокеты ядра (`VpnService.protect`) обратным вызовом
//! [`rc_set_protect`].
//!
//! Строки — UTF-8 с нулём в конце. Строки, которые возвращает библиотека,
//! освобождаются [`rc_free_string`]. Паника внутри не выходит за границу
//! C: функция возвращает ошибку.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use reality_core::app::api::Api;
use reality_core::app::config::{Config, InboundKind};
use reality_core::app::{events, App, Running};
use tokio::sync::broadcast::error::RecvError;

#[cfg(unix)]
type FfiTunFd = Arc<OwnedFd>;
#[cfg(not(unix))]
type FfiTunFd = i32;

/// Ещё одна ссылка на владельца дескриптора: на Unix это `Arc`, на остальных
/// системах — просто число (`Copy`), поэтому `clone_on_copy` здесь ожидаем.
#[allow(clippy::clone_on_copy)]
fn tun_fd_handle(fd: &Option<FfiTunFd>) -> Option<FfiTunFd> {
    fd.clone()
}

/// Запущенное ядро.
pub struct RcCore {
    rt: Option<tokio::runtime::Runtime>,
    running: Option<Running>,
    api: Arc<Api>,
    /// Папка для относительных путей в настройках.
    base: PathBuf,
    /// Дескриптор TUN, если его дало приложение.
    tun_fd: Option<FfiTunFd>,
    events: Mutex<Option<tokio::task::JoinHandle<()>>>,
    logs: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Обратный вызов с JSON-строкой (событие или строка журнала).
pub type RcCallback = Option<unsafe extern "C" fn(json: *const c_char, user: *mut c_void)>;

/// Защитить сокет ядра от TUN (Android: `VpnService.protect(fd)`);
/// вернуть 1 — защищён, 0 — нет.
pub type RcProtect = Option<unsafe extern "C" fn(fd: i64, user: *mut c_void) -> c_int>;

/// Указатель приложения, который ядро только передаёт обратно.
#[derive(Clone, Copy)]
struct User(*mut c_void);
// SAFETY: ядро указатель не разыменовывает; потокобезопасность того, на
// что он указывает, — обещание приложения (описано в reality.h).
unsafe impl Send for User {}
unsafe impl Sync for User {}

impl User {
    /// Через метод, чтобы замыкание захватывало `User` целиком (а не
    /// поле-указатель, который не `Send`).
    fn ptr(self) -> *mut c_void {
        self.0
    }
}

fn set_error(error: *mut *mut c_char, msg: &str) {
    if !error.is_null() {
        let s = CString::new(msg.replace('\0', " ")).unwrap_or_default();
        // SAFETY: приложение передало место под указатель.
        unsafe { *error = s.into_raw() };
    }
}

/// Тело ошибки, как у API: `{"message": "…"}`.
fn message(msg: &str) -> Vec<u8> {
    serde_json::json!({ "message": msg })
        .to_string()
        .into_bytes()
}

fn to_c(s: &str) -> *mut c_char {
    CString::new(s.replace('\0', " "))
        .unwrap_or_default()
        .into_raw()
}

/// Строка C → &str; NULL — `None`.
unsafe fn arg<'a>(p: *const c_char) -> Result<Option<&'a str>, String> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: приложение передаёт строку с нулём в конце.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map(Some)
        .map_err(|_| "строка не в UTF-8".to_string())
}

/// Журнал ядра — один раз на процесс (`RUST_LOG`, по умолчанию `info`),
/// с отдачей в [`rc_set_log_callback`]. Если приложение уже поставило
/// свой подписчик `tracing`, остаётся его.
fn init_logging() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new("info,netstack_smoltcp=error,smoltcp=error")
        });
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(events::LogLayer)
            .try_init();
    });
}

/// Версия ядра (статическая строка, освобождать не нужно).
#[no_mangle]
pub extern "C" fn rc_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

fn parse_config(
    text: &str,
    base: &std::path::Path,
    tun_fd: Option<FfiTunFd>,
) -> Result<Config, String> {
    #[cfg(unix)]
    let raw_fd = tun_fd.as_ref().map(|fd| {
        use std::os::fd::AsRawFd;
        fd.as_raw_fd()
    });
    #[cfg(not(unix))]
    let raw_fd = tun_fd;
    let mut cfg = Config::parse_at(text, base).map_err(|e| e.to_string())?;
    if let Some(fd) = raw_fd {
        let tun = cfg
            .inbounds
            .iter_mut()
            .find(|i| i.kind == InboundKind::Tun)
            .ok_or("дескриптор TUN передан, но в настройках нет входа tun")?;
        tun.tun_fd = Some(fd);
        #[cfg(unix)]
        {
            tun.tun_fd_owner = tun_fd.clone();
        }
    }
    Ok(cfg)
}

/// Запустить ядро.
///
/// - `config` — настройки текстом (JSON sing-box или Xray-core);
/// - `base_dir` — папка для относительных путей в них (NULL — текущая);
/// - `tun_fd` — дескриптор TUN от системы или -1 (тогда вход tun, если он
///   есть, создаёт интерфейс сам — нужны права);
/// - `error` — сюда при ошибке пишется её текст (освободить
///   [`rc_free_string`]), может быть NULL.
///
/// Возвращает ядро или NULL при ошибке.
///
/// # Safety
/// Строки — с нулём в конце; `error` — NULL или место под указатель.
#[no_mangle]
pub unsafe extern "C" fn rc_start(
    config: *const c_char,
    base_dir: *const c_char,
    tun_fd: c_int,
    error: *mut *mut c_char,
) -> *mut RcCore {
    // Владение переходит сразу: охранник закроет дескриптор на любом пути ошибки.
    #[cfg(unix)]
    let fd = (tun_fd >= 0).then(|| Arc::new(unsafe { OwnedFd::from_raw_fd(tun_fd) }));
    #[cfg(not(unix))]
    let fd = (tun_fd >= 0).then_some(tun_fd);
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<RcCore, String> {
        init_logging();
        // SAFETY: обещание вызывающего (см. выше).
        let text = unsafe { arg(config) }?.ok_or("config — NULL")?;
        let base = PathBuf::from(unsafe { arg(base_dir) }?.unwrap_or("."));
        let cfg = parse_config(text, &base, tun_fd_handle(&fd))?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("reality-core")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let running = rt
            .block_on(async { App::build(&cfg)?.start().await })
            .map_err(|e| e.to_string())?;
        let api = Api::embedded(running.tracker().clone(), running.controller());
        Ok(RcCore {
            rt: Some(rt),
            running: Some(running),
            api,
            base,
            tun_fd: fd,
            events: Mutex::new(None),
            logs: Mutex::new(None),
        })
    }));
    match r {
        Ok(Ok(core)) => Box::into_raw(Box::new(core)),
        Ok(Err(e)) => {
            set_error(error, &e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_error(error, "внутренняя ошибка ядра (паника)");
            std::ptr::null_mut()
        }
    }
}

/// Остановить ядро и освободить его: входы закрываются, маршруты
/// возвращаются, обратные вызовы больше не вызываются. `core` после
/// этого недействителен. NULL — ничего.
///
/// # Safety
/// `core` — из [`rc_start`], остановлен ещё не был.
#[no_mangle]
pub unsafe extern "C" fn rc_stop(core: *mut RcCore) {
    if core.is_null() {
        return;
    }
    // SAFETY: указатель из rc_start, владение возвращается сюда.
    let mut core = unsafe { Box::from_raw(core) };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        for h in [&core.events, &core.logs] {
            if let Some(t) = h.lock().unwrap().take() {
                t.abort();
            }
        }
        if let Some(rt) = core.rt.take() {
            {
                let _enter = rt.enter();
                drop(core.running.take());
            }
            rt.shutdown_timeout(Duration::from_secs(2));
        }
    }));
}

/// Запрос к API ядра — те же пути и ответы, что по HTTP (Clash API и
/// свои: `GET /proxies`, `PUT /proxies/{группа}`, `PATCH /configs`,
/// `GET /connections`…), без сети и токена. `body` — NULL или JSON.
/// В `status` (если не NULL) пишется код ответа HTTP. Возвращает тело
/// ответа (JSON; пустая строка у 204) — освободить [`rc_free_string`].
///
/// # Safety
/// `core` — из [`rc_start`]; строки — с нулём в конце; `status` — NULL
/// или место под число.
#[no_mangle]
pub unsafe extern "C" fn rc_request(
    core: *mut RcCore,
    method: *const c_char,
    path: *const c_char,
    body: *const c_char,
    status: *mut c_int,
) -> *mut c_char {
    let r = catch_unwind(AssertUnwindSafe(|| -> (u16, Vec<u8>) {
        // SAFETY: обещание вызывающего.
        let Some(core) = (unsafe { core.as_ref() }) else {
            return (400, message("core — NULL"));
        };
        let (Ok(Some(method)), Ok(Some(path)), Ok(body)) =
            (unsafe { arg(method) }, unsafe { arg(path) }, unsafe {
                arg(body)
            })
        else {
            return (400, message("method и path обязательны, строки в UTF-8"));
        };
        let Some(rt) = &core.rt else {
            return (503, message("ядро остановлено"));
        };
        rt.block_on(core.api.local(method, path, body.unwrap_or("").as_bytes()))
    }));
    let (code, body) = r.unwrap_or_else(|_| (500, message("паника")));
    if !status.is_null() {
        // SAFETY: обещание вызывающего.
        unsafe { *status = c_int::from(code) };
    }
    to_c(&String::from_utf8_lossy(&body))
}

/// Применить новые настройки текстом без разрыва соединений (как
/// перечитывание). Возвращает JSON `{"notes": […]}` — что вступит в силу
/// только после перезапуска — или NULL при ошибке (текст — в `error`);
/// при ошибке работают прежние настройки.
///
/// # Safety
/// Как у [`rc_request`]; `error` — NULL или место под указатель.
#[no_mangle]
pub unsafe extern "C" fn rc_reload(
    core: *mut RcCore,
    config: *const c_char,
    error: *mut *mut c_char,
) -> *mut c_char {
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<String, String> {
        // SAFETY: обещание вызывающего.
        let core = unsafe { core.as_ref() }.ok_or("core — NULL")?;
        let text = unsafe { arg(config) }?.ok_or("config — NULL")?;
        // Тот же дескриптор TUN: вход TUN на ходу не меняется.
        let cfg = parse_config(text, &core.base, tun_fd_handle(&core.tun_fd))?;
        let (Some(rt), Some(running)) = (&core.rt, &core.running) else {
            return Err("ядро остановлено".into());
        };
        let notes = rt
            .block_on(running.reload(cfg))
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "notes": notes }).to_string())
    }));
    match r {
        Ok(Ok(s)) => to_c(&s),
        Ok(Err(e)) => {
            set_error(error, &e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_error(error, "внутренняя ошибка ядра (паника)");
            std::ptr::null_mut()
        }
    }
}

/// Получать события ядра (те же, что поток `GET /events`: открытие и
/// закрытие соединений, переключение групп, подписки, перечитывание,
/// смена режима) — JSON-строкой в `cb` из фонового потока ядра.
/// `cb` = NULL — перестать. Строка действительна только во время вызова.
///
/// # Safety
/// `core` — из [`rc_start`]; `cb` и `user` — живы, пока подписка не снята
/// или ядро не остановлено.
#[no_mangle]
pub unsafe extern "C" fn rc_set_event_callback(
    core: *mut RcCore,
    cb: RcCallback,
    user: *mut c_void,
) -> c_int {
    // SAFETY: обещание вызывающего.
    let Some(core) = (unsafe { core.as_ref() }) else {
        return -1;
    };
    let (Some(rt), Some(running)) = (&core.rt, &core.running) else {
        return -1;
    };
    let mut slot = core.events.lock().unwrap();
    if let Some(t) = slot.take() {
        t.abort();
    }
    let Some(cb) = cb else {
        return 0;
    };
    let user = User(user);
    // Подписка — сразу, до возврата: события после вызова не теряются.
    let mut l = running.tracker().events.subscribe();
    *slot = Some(rt.spawn(async move {
        loop {
            let json = match l.rx.recv().await {
                Ok(e) => serde_json::to_string(&*e).unwrap_or_default(),
                Err(RecvError::Lagged(n)) => {
                    serde_json::json!({ "type": "lagged", "skipped": n }).to_string()
                }
                Err(RecvError::Closed) => return,
            };
            call(cb, &json, user);
        }
    }));
    0
}

/// Получать журнал ядра не подробнее `level` (`debug`, `info`, `warning`,
/// `error`) — JSON `{"type": "info", "payload": "…"}` в `cb` из фонового
/// потока. `cb` = NULL — перестать.
///
/// # Safety
/// Как у [`rc_set_event_callback`]; `level` — NULL (`info`) или строка.
#[no_mangle]
pub unsafe extern "C" fn rc_set_log_callback(
    core: *mut RcCore,
    level: *const c_char,
    cb: RcCallback,
    user: *mut c_void,
) -> c_int {
    // SAFETY: обещание вызывающего.
    let Some(core) = (unsafe { core.as_ref() }) else {
        return -1;
    };
    let Some(rt) = &core.rt else {
        return -1;
    };
    let level = match unsafe { arg(level) } {
        Ok(l) => l.unwrap_or("info"),
        Err(_) => return -1,
    };
    let Some(min) = events::level_rank(level) else {
        return -1;
    };
    let mut slot = core.logs.lock().unwrap();
    if let Some(t) = slot.take() {
        t.abort();
    }
    let Some(cb) = cb else {
        return 0;
    };
    let user = User(user);
    let mut l = events::subscribe_logs();
    *slot = Some(rt.spawn(async move {
        loop {
            match l.rx.recv().await {
                Ok(line) if events::level_rank(line.level) >= Some(min) => {
                    let json = serde_json::to_string(&*line).unwrap_or_default();
                    call(cb, &json, user);
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return,
            }
        }
    }));
    0
}

fn call(cb: unsafe extern "C" fn(*const c_char, *mut c_void), json: &str, user: User) {
    let Ok(s) = CString::new(json) else {
        return;
    };
    // SAFETY: обещание приложения из rc_set_*_callback.
    unsafe { cb(s.as_ptr(), user.ptr()) };
}

/// Защищать каждый новый сокет ядра обратным вызовом (Android:
/// `VpnService.protect(fd)`), чтобы его трафик шёл мимо TUN. Вызывать до
/// [`rc_start`]; действует на весь процесс. `cb` = NULL — перестать.
///
/// # Safety
/// `cb` и `user` — живы, пока защита не снята; `cb` вызывается из разных
/// потоков ядра.
#[no_mangle]
pub unsafe extern "C" fn rc_set_protect(cb: RcProtect, user: *mut c_void) {
    let f = cb.map(|cb| {
        let user = User(user);
        Arc::new(move |fd: i64| {
            // SAFETY: обещание вызывающего (см. выше).
            unsafe { cb(fd, user.ptr()) != 0 }
        }) as Arc<reality_core::net_protect::ProtectFn>
    });
    reality_core::net_protect::set_callback(f);
}

/// Windows: каталог для файла блокировки `auto_route` — запись в него
/// только у SYSTEM и администраторов. Без него вход TUN с `auto_route` на
/// Windows не запускается (с готовым дескриптором TUN не нужен). Вызывать
/// до [`rc_start`], один раз; на других системах ничего не делает.
/// 0 — успех, -1 — `dir` NULL или не UTF-8.
///
/// # Safety
/// `dir` — NULL или строка с нулём в конце.
#[no_mangle]
pub unsafe extern "C" fn rc_set_lock_dir(dir: *const c_char) -> c_int {
    if dir.is_null() {
        return -1;
    }
    // SAFETY: обещание вызывающего (см. выше).
    match unsafe { CStr::from_ptr(dir) }.to_str() {
        Ok(d) => {
            reality_core::app::tun::route::set_lock_dir(PathBuf::from(d));
            0
        }
        Err(_) => -1,
    }
}

/// Освободить строку, которую вернула библиотека. NULL — ничего.
///
/// # Safety
/// `s` — из этой библиотеки и ещё не освобождена.
#[no_mangle]
pub unsafe extern "C" fn rc_free_string(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: строка создана CString::into_raw в этой библиотеке.
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tun_fd_ownership_tests {
    use super::rc_start;
    use std::{ffi::CString, fs::File, os::fd::IntoRawFd, path::PathBuf};

    #[test]
    fn rc_start_closes_system_tun_fd_when_config_parse_fails() {
        let fd = File::open("/dev/null").unwrap().into_raw_fd();
        let config = CString::new("{invalid json").unwrap();
        let base = CString::new(".").unwrap();
        let mut error = std::ptr::null_mut();
        let core = unsafe { rc_start(config.as_ptr(), base.as_ptr(), fd, &mut error) };
        assert!(core.is_null());
        assert!(!error.is_null());
        let open = PathBuf::from(format!("/proc/self/fd/{fd}")).exists();
        if open {
            unsafe extern "C" {
                fn close(fd: i32) -> i32;
            }
            unsafe {
                let _ = close(fd);
            }
        }
        assert!(
            !open,
            "rc_start leaked the TUN descriptor on a parse failure"
        );
        unsafe { super::rc_free_string(error) };
    }
}
