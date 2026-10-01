// SPDX-License-Identifier: GPL-3.0-or-later
//! Локальное API — совместимое с Clash API (как у sing-box и mihomo):
//! готовые веб-панели (yacd, metacubexd, zashboard) и клиенты работают с
//! ядром без переделок. Плюс свои запросы (статистика, события, подписки).
//! HTTP/1.1 + JSON.
//!
//! ```json
//! "experimental": {
//!   "clash_api": {
//!     "external_controller": "127.0.0.1:9090",
//!     "secret_file": "api-token.txt",            // или "secret": "…" (не короче 16 символов)
//!     "external_ui": "ui",                       // папка с панелью → http://127.0.0.1:9090/ui/
//!     "access_control_allow_origin": ["https://yacd.haishan.me"],
//!     "default_mode": "rule"
//!   }
//! }
//! ```
//!
//! Запросы Clash (ответы — как у sing-box 1.12; ошибки — `{"message": "…"}`):
//!
//! | Запрос | Что делает |
//! |---|---|
//! | `GET /`, `GET /version` | приветствие и версия |
//! | `GET /configs`, `PATCH /configs` `{"mode": "global"}` | порты входов, режим; сменить режим (rule, global, direct) |
//! | `PUT /configs` | перечитать файл настроек; с `payload` — применить новые настройки (без записи в файл, как у Clash) |
//! | `GET /proxies`, `GET /proxies/{имя}` | выходы и серверы подписок: тип, `now`/`all` у групп, история задержки |
//! | `PUT /proxies/{группа}` `{"name": "…"}` | выбрать участника (selector, в том числе `GLOBAL`) |
//! | `GET /proxies/{имя}/delay?url=…&timeout=5000` | проверить задержку |
//! | `GET /group`, `GET /group/{имя}`, `GET /group/{имя}/delay?url=…` | группы; проверить всех участников |
//! | `GET /connections`, `DELETE /connections[/{id}]` | открытые соединения; закрыть |
//! | `GET /rules` | правила маршрутизации |
//! | `GET /providers/proxies[/{имя}]`, `PUT …/{имя}`, `GET …/{имя}/healthcheck` | подписки: серверы, обновить, проверить |
//! | `GET /dns/query?name=…&type=A` | спросить DNS |
//!
//! Свои запросы:
//!
//! | Запрос | Что делает |
//! |---|---|
//! | `GET /stats` | трафик всего и по выходам, время работы, число соединений |
//! | `GET /groups`, `PUT /groups/{tag}` `{"member": "…"}`, `POST /groups/{tag}/check` | группы в своём формате |
//! | `POST /subscriptions/{tag}/update`, `POST /reload` | обновить подписку, перечитать настройки (с ответом) |
//! | `GET /config` | файл настроек: `path`, `format` (`sing-box`/`xray`), `text` |
//! | `PUT /config[?check=1][&save=0]` | новые настройки (тело — JSON sing-box или Xray): проверить, применить без разрыва соединений, сохранить в файл (прежний — в `.bak`); файлы в них — только из папки настроек |
//!
//! Потоки — ответ не кончается, пока клиент не закроет соединение: по
//! JSON-объекту на строку (`Transfer-Encoding: chunked`) или, с
//! `Upgrade: websocket`, по текстовому кадру WebSocket на объект:
//!
//! | Поток | Что присылает |
//! |---|---|
//! | `GET /events` | свои события: `connection_open`, `connection_close`, `group_switch`, `group_check`, `subscription_update`, `reload`, `mode_change`, `lagged` (см. `events.rs`) |
//! | `GET /traffic` | раз в секунду: скорость `up`/`down` (байт/с) и `upTotal`/`downTotal` |
//! | `GET /memory` | раз в секунду: `inuse` (байт) |
//! | `GET /logs?level=info` | журнал: `{"type": "info", "payload": "…"}` |
//! | `GET /connections` (только WebSocket) | раз в `interval` мс (по умолчанию 1000) — то же, что `GET /connections` |
//!
//! Потоков одновременно — не больше 16. Пока поток не слушают, события
//! не собираются.
//!
//! Безопасность:
//! - токен обязателен всегда (`Authorization: Bearer …`; для WebSocket из
//!   браузера — `?token=…`, иначе браузер его передать не может),
//!   сравнение за постоянное время, после 10 неверных подряд — пауза;
//! - заголовок `Host` должен быть адресом API (защита от DNS rebinding:
//!   страница в браузере не сможет дотянуться до API через свой домен);
//! - запрос из браузера (есть `Origin`) принимается только от своей панели
//!   (`external_ui`) и от сайтов из `access_control_allow_origin`;
//!   остальным — 403;
//! - файлы панели и приветствие `GET /` отдаются без токена (как у
//!   Clash): это статика, токен панель спросит сама;
//! - слушать не на 127.0.0.1 можно только с `allow_ip`.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_tungstenite::tungstenite::protocol::Role;
use async_tungstenite::tungstenite::Message;
use async_tungstenite::WebSocketStream;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::Semaphore;
use tokio_util::compat::TokioAsyncReadCompatExt;

use super::access::IpNet;
use super::events::{self, Event};
use super::stats::{Mode, Tracker};
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct ApiConfig {
    pub listen: SocketAddr,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    pub allow_ip: Vec<IpNet>,
    /// Сайты, которым можно обращаться к API из браузера (CORS), — адреса
    /// веб-панелей (`https://yacd.haishan.me`) или `*`. Своя панель
    /// (`external_ui`) разрешена всегда.
    pub allow_origin: Vec<String>,
    /// Разрешить странице из интернета обращаться к API на этом
    /// компьютере (Private Network Access в Chrome).
    pub allow_private_network: bool,
    /// Папка с веб-панелью (yacd, metacubexd, zashboard): открывается по
    /// адресу `http://127.0.0.1:9090/ui/`.
    pub external_ui: Option<PathBuf>,
    /// Режим маршрутизации при запуске.
    pub default_mode: Option<Mode>,
}

/// Минимальная длина токена.
pub const MIN_TOKEN: usize = 16;
const MAX_HEAD: usize = 16 * 1024;
/// Тело запроса: файл настроек со списками правил бывает не маленьким.
const MAX_BODY: usize = 1024 * 1024;
/// Сколько ждать следующего запроса и ответа на обычный запрос.
const IDLE: Duration = Duration::from_secs(60);
/// Потоков (`/events`, `/logs`…) одновременно.
const MAX_STREAMS: usize = 16;
/// Проверка задержки по умолчанию и потолок.
const DELAY_TIMEOUT: Duration = Duration::from_secs(5);
const DELAY_TIMEOUT_MAX: Duration = Duration::from_secs(30);

/// Что API умеет делать с приложением (реализует `Controller`).
pub trait Control: Send + Sync {
    /// Группы в своём формате (`GET /groups`).
    fn groups(&self) -> Value;
    fn select(&self, group: &str, member: &str) -> Result<()>;
    fn check(&self, group: &str) -> BoxFuture<'_, Result<()>>;
    fn update_subscription(&self, tag: &str) -> BoxFuture<'_, Result<usize>>;
    fn reload(&self) -> BoxFuture<'_, Result<Vec<String>>>;
    /// `GET /proxies`.
    fn proxies(&self) -> Value;
    /// `GET /group`.
    fn clash_groups(&self) -> Value;
    /// Задержка выхода: `Ok(None)` — не ответил.
    fn delay<'a>(
        &'a self,
        name: &'a str,
        url: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Option<u64>>>;
    /// Задержки всех участников группы.
    fn group_delay<'a>(
        &'a self,
        name: &'a str,
        url: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Value>>;
    fn rules(&self) -> Value;
    fn configs(&self) -> Value;
    fn providers(&self) -> Value;
    fn provider_check<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<()>>;
    fn dns_query<'a>(&'a self, name: &'a str, qtype: &'a str) -> BoxFuture<'a, Result<Value>>;
    /// Файл настроек: путь и текст.
    fn config_text(&self) -> Result<(PathBuf, String)>;
    /// Новые настройки текстом: проверить (`check`), применить и
    /// сохранить (`save`); ответ — `Applied`.
    fn apply<'a>(&'a self, text: &'a str, check: bool, save: bool) -> BoxFuture<'a, Result<Value>>;
}

pub struct Api {
    pub listen: SocketAddr,
    token: String,
    allow_ip: Vec<IpNet>,
    allow_origin: Vec<String>,
    allow_private_network: bool,
    ui: Option<PathBuf>,
    tracker: Arc<Tracker>,
    control: Arc<dyn Control>,
    failures: AtomicU32,
    streams: Arc<Semaphore>,
}

/// Потоки API.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Feed {
    Events,
    Traffic,
    Memory,
    Logs,
    Connections,
}

/// Ответ на обычный запрос.
struct Reply {
    code: u16,
    ctype: &'static str,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
}

impl Reply {
    fn json(code: u16, v: &Value) -> Self {
        Reply {
            code,
            ctype: "application/json; charset=utf-8",
            body: serde_json::to_vec(v).unwrap_or_default(),
            headers: Vec::new(),
        }
    }

    fn ok(v: Value) -> Self {
        Self::json(200, &v)
    }

    /// Ошибка — как у Clash: `{"message": "…"}`.
    fn err(code: u16, msg: impl Into<String>) -> Self {
        Self::json(code, &json!({ "message": msg.into() }))
    }

    fn empty() -> Self {
        Reply {
            code: 204,
            ctype: "",
            body: Vec::new(),
            headers: Vec::new(),
        }
    }
}

/// Что делать с запросом из браузера.
enum Cors {
    /// Не из браузера (нет `Origin`).
    None,
    /// Разрешённый сайт — в ответ идут заголовки CORS.
    Allow(String),
}

impl Api {
    pub fn new(
        cfg: &ApiConfig,
        token: String,
        tracker: Arc<Tracker>,
        control: Arc<dyn Control>,
    ) -> Result<Arc<Self>> {
        if token.len() < MIN_TOKEN {
            return Err(Error::Config(format!(
                "api: токен короче {MIN_TOKEN} символов"
            )));
        }
        let loopback = cfg.listen.ip().is_loopback();
        if !loopback && cfg.allow_ip.is_empty() {
            return Err(Error::Config(format!(
                "api: {} открывает управление клиентом в сеть — перечислите свои устройства в allow_ip",
                cfg.listen
            )));
        }
        let ui = match &cfg.external_ui {
            Some(d) => Some(
                d.canonicalize()
                    .map_err(|e| Error::Config(format!("api: external_ui {}: {e}", d.display())))?,
            ),
            None => None,
        };
        Ok(Arc::new(Api {
            listen: cfg.listen,
            token,
            allow_ip: cfg.allow_ip.clone(),
            allow_origin: cfg
                .allow_origin
                .iter()
                .map(|o| o.trim_end_matches('/').to_ascii_lowercase())
                .collect(),
            allow_private_network: cfg.allow_private_network,
            ui,
            tracker,
            control,
            failures: AtomicU32::new(0),
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
        }))
    }

    /// API без сети — для режима библиотеки: запросы идут вызовом
    /// [`Api::local`] из того же процесса, без токена.
    pub fn embedded(tracker: Arc<Tracker>, control: Arc<dyn Control>) -> Arc<Self> {
        let token: String = (0..32)
            .map(|_| char::from(b'a' + rand::random::<u8>() % 26))
            .collect();
        Arc::new(Api {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            token,
            allow_ip: Vec::new(),
            allow_origin: Vec::new(),
            allow_private_network: false,
            ui: None,
            tracker,
            control,
            failures: AtomicU32::new(0),
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
        })
    }

    /// Запрос из того же процесса (режим библиотеки): те же пути и ответы,
    /// что по HTTP, без проверок токена и браузера. Потоки так недоступны —
    /// для них подписки на события и журнал.
    pub async fn local(&self, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let req = Request {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            headers: Vec::new(),
            body: body.to_vec(),
            close: false,
        };
        if feed_of(&req).is_some() {
            let r = Reply::err(400, "потоки в режиме библиотеки — через обратные вызовы");
            return (r.code, r.body);
        }
        let r = self.route(&req).await;
        (r.code, r.body)
    }

    pub async fn serve(self: Arc<Self>, l: TcpListener) -> Result<()> {
        let local = l.local_addr()?;
        let sem = Arc::new(tokio::sync::Semaphore::new(32));
        loop {
            let (s, peer) = l.accept().await?;
            if !self.allowed(peer.ip()) {
                continue;
            }
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                continue;
            };
            let me = self.clone();
            tokio::spawn(async move {
                let _p = permit;
                me.handle(s, local).await;
            });
        }
    }

    fn allowed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_loopback() || self.allow_ip.iter().any(|n| n.contains(ip))
    }

    async fn handle(&self, s: TcpStream, local: SocketAddr) {
        let (r, mut w) = s.into_split();
        let mut r = BufReader::new(r);
        loop {
            let req = match tokio::time::timeout(IDLE, read_request(&mut r)).await {
                Err(_) | Ok(Ok(None)) => return,
                Ok(Ok(Some(req))) => req,
                Ok(Err(e)) => {
                    let _ =
                        respond(&mut w, Reply::err(400, e.to_string()), false, &Cors::None).await;
                    return;
                }
            };
            let keep = !req.close;
            // DNS rebinding: Host — только адрес самого API.
            if !host_ok(&req, local) {
                let _ = respond(&mut w, Reply::err(421, "неверный Host"), false, &Cors::None).await;
                return;
            }
            let cors = match req.header("origin") {
                None => Cors::None,
                Some(o) if self.origin_ok(o, &req) => Cors::Allow(o.to_string()),
                Some(o) => {
                    let msg = format!(
                        "запросы со страницы {o} запрещены — добавьте её в \
                         clash_api.access_control_allow_origin"
                    );
                    let _ = respond(&mut w, Reply::err(403, msg), false, &Cors::None).await;
                    return;
                }
            };
            if req.method == "OPTIONS" {
                let reply = self.preflight(&req, &cors);
                if respond(&mut w, reply, keep, &cors).await.is_err() || !keep {
                    return;
                }
                continue;
            }
            // Приветствие — без токена, как у Clash: по нему панели
            // проверяют, что по адресу вообще Clash API.
            if req.method == "GET" && req.path.split('?').next() == Some("/") {
                let browser = req
                    .header("accept")
                    .is_some_and(|a| a.contains("text/html"));
                let reply = if self.ui.is_some() && browser {
                    let mut r = Reply::empty();
                    r.code = 302;
                    r.headers.push(("Location", "/ui/".into()));
                    r
                } else {
                    Reply::ok(json!({ "hello": "clash" }))
                };
                if respond(&mut w, reply, keep, &cors).await.is_err() || !keep {
                    return;
                }
                continue;
            }
            // Файлы панели — без токена: это статика.
            if let Some(reply) = self.ui_file(&req) {
                if respond(&mut w, reply, keep, &cors).await.is_err() || !keep {
                    return;
                }
                continue;
            }
            if !self.authorized(&req).await {
                let _ = respond(
                    &mut w,
                    Reply::err(401, "нужен токен: Authorization: Bearer …"),
                    false,
                    &cors,
                )
                .await;
                return;
            }
            if let Some(feed) = feed_of(&req) {
                self.stream(feed, &req, r, w).await;
                return;
            }
            let reply = tokio::time::timeout(IDLE, self.route(&req))
                .await
                .unwrap_or_else(|_| Reply::err(504, "не успели за 60 с"));
            if respond(&mut w, reply, keep, &cors).await.is_err() || !keep {
                return;
            }
        }
    }

    /// Своя панель (тот же адрес) или сайт из `access_control_allow_origin`.
    fn origin_ok(&self, origin: &str, req: &Request) -> bool {
        let o = origin.trim_end_matches('/').to_ascii_lowercase();
        let same = req
            .header("host")
            .is_some_and(|h| o == format!("http://{}", h.to_ascii_lowercase()));
        same || self.allow_origin.iter().any(|a| a == "*" || *a == o)
    }

    /// Предварительный запрос CORS (OPTIONS): что можно странице.
    fn preflight(&self, req: &Request, cors: &Cors) -> Reply {
        let mut r = Reply::empty();
        if let Cors::Allow(_) = cors {
            r.headers.push((
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, PATCH, DELETE".into(),
            ));
            r.headers.push((
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type".into(),
            ));
            r.headers.push(("Access-Control-Max-Age", "300".into()));
            if self.allow_private_network
                && req
                    .header("access-control-request-private-network")
                    .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            {
                r.headers
                    .push(("Access-Control-Allow-Private-Network", "true".into()));
            }
        }
        r
    }

    /// Файл панели (`GET /ui/…`), если это запрос к ней.
    fn ui_file(&self, req: &Request) -> Option<Reply> {
        let path = req.path.split('?').next().unwrap_or("");
        if req.method != "GET" || !(path == "/ui" || path.starts_with("/ui/")) {
            return None;
        }
        let Some(root) = &self.ui else {
            return Some(Reply::err(
                404,
                "панель не настроена (clash_api.external_ui)",
            ));
        };
        if path == "/ui" {
            let mut r = Reply::empty();
            r.code = 301;
            r.headers.push(("Location", "/ui/".into()));
            return Some(r);
        }
        Some(serve_file(root, &path[4..]))
    }

    async fn authorized(&self, req: &Request) -> bool {
        let header = req
            .header("authorization")
            .and_then(|v| v.strip_prefix("Bearer "));
        // Браузер не умеет ставить заголовки WebSocket — токен в адресе,
        // как у Clash; только для WebSocket.
        let query = if is_upgrade(req) {
            req.query("token")
        } else {
            None
        };
        let got = header.map(str::to_string).or(query).unwrap_or_default();
        if token_eq(got.as_bytes(), self.token.as_bytes()) {
            self.failures.store(0, Ordering::Relaxed);
            return true;
        }
        let n = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= 10 {
            // Подбор токена: пауза растёт, но не больше 5 с.
            tokio::time::sleep(Duration::from_millis((n as u64 * 100).min(5000))).await;
        }
        tracing::warn!("api: неверный токен");
        false
    }

    /// Отдавать поток, пока клиент не закроет соединение.
    async fn stream(
        &self,
        feed: Feed,
        req: &Request,
        r: BufReader<OwnedReadHalf>,
        mut w: OwnedWriteHalf,
    ) {
        let Ok(_permit) = self.streams.clone().try_acquire_owned() else {
            let reply = Reply::err(503, format!("потоков уже {MAX_STREAMS}"));
            let _ = respond(&mut w, reply, false, &Cors::None).await;
            return;
        };
        let src = match self.source(feed, req) {
            Ok(s) => s,
            Err(e) => {
                let _ = respond(&mut w, Reply::err(400, e), false, &Cors::None).await;
                return;
            }
        };
        if !is_upgrade(req) {
            let head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson; charset=utf-8\r\n\
                        Transfer-Encoding: chunked\r\nCache-Control: no-store\r\n\
                        X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
            if w.write_all(head.as_bytes()).await.is_ok() {
                feed_chunked(src, r, w).await;
            }
            return;
        }
        let Some(key) = req.header("sec-websocket-key") else {
            let reply = Reply::err(400, "WebSocket: нет Sec-WebSocket-Key");
            let _ = respond(&mut w, reply, false, &Cors::None).await;
            return;
        };
        let accept = async_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        // До ответа клиент не должен ничего слать; прислал — не WebSocket.
        if w.write_all(head.as_bytes()).await.is_err() || !r.buffer().is_empty() {
            return;
        }
        let Ok(tcp) = r.into_inner().reunite(w) else {
            return;
        };
        let ws = WebSocketStream::from_raw_socket(tcp.compat(), Role::Server, None).await;
        feed_ws(src, ws).await;
    }

    fn source(
        &self,
        feed: Feed,
        req: &Request,
    ) -> std::result::Result<BoxStream<'static, Value>, String> {
        Ok(match feed {
            Feed::Events => {
                let l = self.tracker.events.subscribe();
                futures_util::stream::unfold(l, |mut l| async move {
                    let e = match l.rx.recv().await {
                        Ok(e) => serde_json::to_value(&*e).unwrap_or_default(),
                        Err(RecvError::Lagged(n)) => {
                            serde_json::to_value(Event::Lagged { skipped: n }).unwrap_or_default()
                        }
                        Err(RecvError::Closed) => return None,
                    };
                    Some((e, l))
                })
                .boxed()
            }
            Feed::Logs => {
                let level = req.query("level").unwrap_or_else(|| "info".into());
                let min = events::level_rank(&level).ok_or_else(|| {
                    format!("level: {level} — ожидалось debug, info, warning или error")
                })?;
                let l = events::subscribe_logs();
                futures_util::stream::unfold(l, move |mut l| async move {
                    loop {
                        match l.rx.recv().await {
                            Ok(line) if events::level_rank(line.level) >= Some(min) => {
                                return Some((serde_json::to_value(&*line).unwrap_or_default(), l))
                            }
                            Ok(_) | Err(RecvError::Lagged(_)) => continue,
                            Err(RecvError::Closed) => return None,
                        }
                    }
                })
                .boxed()
            }
            Feed::Traffic => {
                let t = self.tracker.clone();
                let (up, down) = t.totals();
                futures_util::stream::unfold((t, up, down), |(t, up, down)| async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let (u, d) = t.totals();
                    let v = json!({
                        "up": u.saturating_sub(up),
                        "down": d.saturating_sub(down),
                        "upTotal": u,
                        "downTotal": d,
                    });
                    Some((v, (t, u, d)))
                })
                .boxed()
            }
            Feed::Memory => futures_util::stream::unfold(true, |first| async move {
                if !first {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Some((
                    json!({ "inuse": events::memory_in_use(), "oslimit": 0 }),
                    false,
                ))
            })
            .boxed(),
            Feed::Connections => {
                let ms = match req.query("interval") {
                    Some(v) => v
                        .parse::<u64>()
                        .map_err(|_| format!("interval: «{v}» — миллисекунды"))?,
                    None => 1000,
                }
                .clamp(100, 60_000);
                let t = self.tracker.clone();
                futures_util::stream::unfold((t, true), move |(t, first)| async move {
                    if !first {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                    }
                    Some((connections_json(&t), (t, false)))
                })
                .boxed()
            }
        })
    }

    async fn route(&self, req: &Request) -> Reply {
        let path: Vec<String> = req
            .path
            .split('?')
            .next()
            .unwrap_or("")
            .split('/')
            .filter(|s| !s.is_empty())
            .map(pct_decode)
            .collect();
        let p: Vec<&str> = path.iter().map(String::as_str).collect();
        let c = &self.control;
        match (req.method.as_str(), p.as_slice()) {
            // ── Clash API ──
            ("GET", ["version"]) => Reply::ok(json!({
                "version": format!("reality-core {}", env!("CARGO_PKG_VERSION")),
                "premium": true,
                "meta": true,
            })),
            ("GET", ["configs"]) => Reply::ok(c.configs()),
            ("PATCH", ["configs"]) => self.patch_configs(&req.body),
            ("PUT", ["configs"]) => {
                #[derive(Deserialize, Default)]
                struct Put {
                    #[serde(default)]
                    path: String,
                    #[serde(default)]
                    payload: String,
                }
                let put: Put = if req.body.is_empty() {
                    Put::default()
                } else {
                    match serde_json::from_slice(&req.body) {
                        Ok(p) => p,
                        Err(e) => return Reply::err(400, format!("тело: {e}")),
                    }
                };
                if !put.path.is_empty() {
                    return Reply::err(
                        400,
                        "path не поддерживается: новые настройки — текстом в payload или \
                         PUT /config",
                    );
                }
                // payload — новые настройки (JSON sing-box или Xray);
                // применяются, но в файл не пишутся (как у Clash).
                if !put.payload.is_empty() {
                    return match c.apply(&put.payload, false, false).await {
                        Ok(_) => Reply::empty(),
                        Err(e) => Reply::err(400, e.to_string()),
                    };
                }
                match c.reload().await {
                    Ok(_) => Reply::empty(),
                    Err(e) => Reply::err(400, e.to_string()),
                }
            }
            ("GET", ["proxies"]) => Reply::ok(c.proxies()),
            ("GET", ["proxies", name]) => self.one_proxy(name),
            ("PUT", ["proxies", name]) => {
                #[derive(Deserialize)]
                struct Sel {
                    name: String,
                }
                match serde_json::from_slice::<Sel>(&req.body) {
                    Ok(s) => match c.select(name, &s.name) {
                        Ok(()) => Reply::empty(),
                        Err(e) => Reply::err(400, e.to_string()),
                    },
                    Err(e) => Reply::err(400, format!("тело: {{\"name\": \"…\"}}: {e}")),
                }
            }
            ("GET", ["proxies", name, "delay"]) => self.delay(req, name, false).await,
            ("GET", ["group"]) => Reply::ok(c.clash_groups()),
            ("GET", ["group", name]) => {
                let v = c.clash_groups();
                let found = v["proxies"]
                    .as_array()
                    .and_then(|a| a.iter().find(|g| g["name"] == *name).cloned());
                match found {
                    Some(g) => Reply::ok(g),
                    None => Reply::err(404, format!("нет группы «{name}»")),
                }
            }
            ("GET", ["group", name, "delay"]) => self.delay(req, name, true).await,
            ("GET", ["connections"]) => Reply::ok(connections_json(&self.tracker)),
            ("DELETE", ["connections"]) => {
                self.tracker.close_all();
                Reply::empty()
            }
            ("DELETE", ["connections", id]) => {
                if let Ok(id) = id.parse::<u64>() {
                    self.tracker.close(id);
                }
                Reply::empty()
            }
            ("GET", ["rules"]) => Reply::ok(c.rules()),
            ("GET", ["providers", "proxies"]) => Reply::ok(c.providers()),
            ("GET", ["providers", "proxies", name]) => {
                match c.providers()["providers"].get(*name) {
                    Some(p) => Reply::ok(p.clone()),
                    None => Reply::err(404, format!("нет подписки «{name}»")),
                }
            }
            ("PUT", ["providers", "proxies", name]) => match c.update_subscription(name).await {
                Ok(_) => Reply::empty(),
                Err(e) => Reply::err(502, e.to_string()),
            },
            ("GET", ["providers", "proxies", name, "healthcheck"]) => {
                match c.provider_check(name).await {
                    Ok(()) => Reply::empty(),
                    Err(e) => Reply::err(404, e.to_string()),
                }
            }
            ("GET", ["providers", "rules"]) => Reply::ok(json!({ "providers": {} })),
            ("GET", ["dns", "query"]) => {
                let Some(name) = req.query("name") else {
                    return Reply::err(400, "нужен name");
                };
                let qtype = req.query("type").unwrap_or_else(|| "A".into());
                match c.dns_query(&name, &qtype).await {
                    Ok(v) => Reply::ok(v),
                    Err(e) => Reply::err(400, e.to_string()),
                }
            }
            // ── свои ──
            ("GET", ["config"]) => match c.config_text() {
                Ok((path, text)) => Reply::ok(json!({
                    "path": path.display().to_string(),
                    "format": super::config::Config::format_name(&text),
                    "text": text,
                })),
                Err(e) => Reply::err(404, e.to_string()),
            },
            ("PUT", ["config"]) => {
                let Ok(text) = std::str::from_utf8(&req.body) else {
                    return Reply::err(400, "тело — текст настроек в UTF-8");
                };
                let flag = |k: &str, default: bool| match req.query(k).as_deref() {
                    Some("1" | "true") => true,
                    Some("0" | "false") => false,
                    _ => default,
                };
                match c
                    .apply(text, flag("check", false), flag("save", true))
                    .await
                {
                    Ok(v) => Reply::ok(v),
                    Err(e) => Reply::err(400, e.to_string()),
                }
            }
            ("GET", ["stats"]) => {
                Reply::ok(serde_json::to_value(self.tracker.summary()).unwrap_or_default())
            }
            ("GET", ["groups"]) => Reply::ok(c.groups()),
            ("PUT", ["groups", tag]) => {
                #[derive(Deserialize)]
                struct Sel {
                    member: String,
                }
                match serde_json::from_slice::<Sel>(&req.body) {
                    Ok(s) => match c.select(tag, &s.member) {
                        Ok(()) => Reply::ok(json!({ "group": tag, "member": s.member })),
                        Err(e) => Reply::err(400, e.to_string()),
                    },
                    Err(e) => Reply::err(400, format!("тело: {{\"member\": \"…\"}}: {e}")),
                }
            }
            ("POST", ["groups", tag, "check"]) => match c.check(tag).await {
                Ok(()) => Reply::ok(c.groups()),
                Err(e) => Reply::err(404, e.to_string()),
            },
            ("POST", ["subscriptions", tag, "update"]) => match c.update_subscription(tag).await {
                Ok(n) => Reply::ok(json!({ "subscription": tag, "servers": n })),
                Err(e) => Reply::err(502, e.to_string()),
            },
            ("POST", ["reload"]) => match c.reload().await {
                Ok(notes) => Reply::ok(json!({ "reloaded": true, "notes": notes })),
                Err(e) => Reply::err(400, e.to_string()),
            },
            _ => Reply::err(404, "нет такого запроса"),
        }
    }

    fn one_proxy(&self, name: &str) -> Reply {
        match self.control.proxies()["proxies"].get(name) {
            Some(p) => Reply::ok(p.clone()),
            None => Reply::err(404, format!("нет выхода «{name}»")),
        }
    }

    /// `PATCH /configs`: сменить режим. Остальное из Clash (порты,
    /// allow-lan, уровень журнала) меняется только в файле настроек.
    fn patch_configs(&self, body: &[u8]) -> Reply {
        let v: Value = match serde_json::from_slice(body) {
            Ok(Value::Object(m)) => Value::Object(m),
            Ok(_) | Err(_) => {
                return Reply::err(400, "тело: JSON-объект, например {\"mode\": \"global\"}")
            }
        };
        let obj = v.as_object().expect("объект");
        if let Some(k) = obj.keys().find(|k| *k != "mode") {
            return Reply::err(
                400,
                format!("«{k}» через API не меняется — только в файле настроек; можно mode"),
            );
        }
        if let Some(m) = obj.get("mode") {
            let Some(mode) = m.as_str().and_then(Mode::parse) else {
                return Reply::err(400, "mode: rule, global или direct");
            };
            self.tracker.set_mode(mode);
        }
        Reply::empty()
    }

    /// `GET /proxies/{имя}/delay` и `GET /group/{имя}/delay`.
    async fn delay(&self, req: &Request, name: &str, group: bool) -> Reply {
        let Some(url) = req.query("url") else {
            return Reply::err(400, "нужен url — адрес проверки");
        };
        let timeout = match req.query("timeout") {
            Some(t) => match t.parse::<u64>() {
                Ok(ms) => Duration::from_millis(ms).min(DELAY_TIMEOUT_MAX),
                Err(_) => return Reply::err(400, format!("timeout: «{t}» — миллисекунды")),
            },
            None => DELAY_TIMEOUT,
        };
        if group {
            return match self.control.group_delay(name, &url, timeout).await {
                Ok(v) => Reply::ok(v),
                Err(e) => Reply::err(404, e.to_string()),
            };
        }
        match self.control.delay(name, &url, timeout).await {
            Ok(Some(ms)) => Reply::ok(json!({ "delay": ms })),
            Ok(None) => Reply::err(504, format!("не ответил за {} мс", timeout.as_millis())),
            Err(e) => Reply::err(404, e.to_string()),
        }
    }
}

/// Открытые соединения в формате Clash.
fn connections_json(t: &Tracker) -> Value {
    let (up, down) = t.totals();
    json!({
        "downloadTotal": down,
        "uploadTotal": up,
        "connections": t.clash_connections(),
        "memory": events::memory_in_use(),
    })
}

fn host_ok(req: &Request, local: SocketAddr) -> bool {
    req.header("host").is_some_and(|h| {
        let h = h.trim();
        let port = local.port().to_string();
        [
            format!("{}:{port}", local.ip()),
            format!("[{}]:{port}", local.ip()),
            format!("localhost:{port}"),
            format!("127.0.0.1:{port}"),
        ]
        .iter()
        .any(|x| x.eq_ignore_ascii_case(h))
    })
}

/// Токен совпадает: длина — отдельной проверкой (длина токена не
/// секрет), байты — за постоянное время.
fn token_eq(got: &[u8], want: &[u8]) -> bool {
    if got.len() != want.len() {
        return false;
    }
    got.iter().zip(want).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
}

fn is_upgrade(req: &Request) -> bool {
    req.header("upgrade")
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
}

/// Запрос потока: `/events`, `/traffic`, `/memory`, `/logs`; `/connections`
/// — только через WebSocket (без него — один снимок).
fn feed_of(req: &Request) -> Option<Feed> {
    if req.method != "GET" {
        return None;
    }
    match req
        .path
        .split('?')
        .next()
        .unwrap_or("")
        .trim_end_matches('/')
    {
        "/events" => Some(Feed::Events),
        "/traffic" => Some(Feed::Traffic),
        "/memory" => Some(Feed::Memory),
        "/logs" => Some(Feed::Logs),
        "/connections" if is_upgrade(req) => Some(Feed::Connections),
        _ => None,
    }
}

/// Файл панели из папки `root`; `rel` — путь после `/ui/`. Выйти за
/// пределы папки нельзя: `..`, обратные косые и двоеточия отвергаются, а
/// итоговый путь проверяется после разрешения ссылок.
fn serve_file(root: &Path, rel: &str) -> Reply {
    let mut path = root.to_path_buf();
    for seg in rel.split('/').filter(|s| !s.is_empty()) {
        let seg = pct_decode(seg);
        if seg == ".." || seg == "." || seg.contains(['\\', ':', '\0']) {
            return Reply::err(400, "недопустимый путь");
        }
        path.push(seg);
    }
    if path.is_dir() {
        path.push("index.html");
    }
    let real = match path.canonicalize() {
        Ok(p) if p.starts_with(root) => p,
        // Нет файла — панели с маршрутизацией на клиенте (history API)
        // ждут index.html.
        _ => root.join("index.html"),
    };
    let Ok(body) = std::fs::read(&real) else {
        return Reply::err(404, "нет такого файла");
    };
    let ctype = match real.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    };
    Reply {
        code: 200,
        ctype,
        body,
        headers: vec![("Cache-Control", "no-cache".into())],
    }
}

/// Поток по JSON-объекту на строку, куском `chunked` на объект. Клиент
/// закрыл соединение — поток кончается.
async fn feed_chunked(
    mut src: BoxStream<'static, Value>,
    mut r: BufReader<OwnedReadHalf>,
    mut w: OwnedWriteHalf,
) {
    let mut sink = [0u8; 512];
    loop {
        tokio::select! {
            item = src.next() => {
                let Some(v) = item else { break };
                let mut line = serde_json::to_vec(&v).unwrap_or_default();
                line.push(b'\n');
                let mut chunk = format!("{:x}\r\n", line.len()).into_bytes();
                chunk.extend_from_slice(&line);
                chunk.extend_from_slice(b"\r\n");
                if w.write_all(&chunk).await.is_err() || w.flush().await.is_err() {
                    return;
                }
            }
            n = r.read(&mut sink) => {
                if !matches!(n, Ok(n) if n > 0) {
                    return;
                }
            }
        }
    }
    let _ = w.write_all(b"0\r\n\r\n").await;
}

/// Поток по текстовому кадру WebSocket на объект.
async fn feed_ws<S>(mut src: BoxStream<'static, Value>, ws: WebSocketStream<S>)
where
    S: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin,
{
    let (mut tx, mut rx) = ws.split();
    loop {
        tokio::select! {
            item = src.next() => {
                let Some(v) = item else { break };
                if tx.send(Message::text(v.to_string())).await.is_err() {
                    return;
                }
            }
            m = rx.next() => match m {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    }
    let _ = tx.close().await;
}

fn pct_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_string())
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    close: bool,
}

impl Request {
    /// Параметр строки запроса (`?level=debug`).
    fn query(&self, name: &str) -> Option<String> {
        let q = self.path.split_once('?')?.1;
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn read_request<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Result<Option<Request>> {
    let mut head = Vec::new();
    loop {
        let before = head.len();
        let n = r.read_until(b'\n', &mut head).await?;
        if n == 0 {
            return if head.is_empty() {
                Ok(None)
            } else {
                Err(Error::Protocol("оборванный запрос".into()))
            };
        }
        if head.len() > MAX_HEAD {
            return Err(Error::Protocol("слишком длинный заголовок".into()));
        }
        if &head[before..] == b"\r\n" || &head[before..] == b"\n" {
            break;
        }
    }
    let text = String::from_utf8(head).map_err(|_| Error::Protocol("не UTF-8".into()))?;
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("");
    if method.is_empty() || !path.starts_with('/') || !version.starts_with("HTTP/1.") {
        return Err(Error::Protocol("не HTTP/1.x".into()));
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut req = Request {
        method,
        path,
        headers,
        body: Vec::new(),
        close: version == "HTTP/1.0",
    };
    if req
        .header("connection")
        .is_some_and(|c| c.eq_ignore_ascii_case("close"))
    {
        req.close = true;
    }
    if req.header("transfer-encoding").is_some() {
        return Err(Error::Protocol(
            "chunked не поддерживается — Content-Length".into(),
        ));
    }
    if let Some(len) = req.header("content-length") {
        let n: usize = len
            .parse()
            .map_err(|_| Error::Protocol("Content-Length".into()))?;
        if n > MAX_BODY {
            return Err(Error::Protocol("тело слишком большое".into()));
        }
        let mut b = vec![0u8; n];
        r.read_exact(&mut b).await?;
        req.body = b;
    }
    Ok(Some(req))
}

async fn respond<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    reply: Reply,
    keep: bool,
    cors: &Cors,
) -> std::io::Result<()> {
    let code = reply.code;
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        421 => "Misdirected Request",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let mut head = format!("HTTP/1.1 {code} {reason}\r\n");
    if !reply.ctype.is_empty() {
        head.push_str(&format!("Content-Type: {}\r\n", reply.ctype));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nX-Content-Type-Options: nosniff\r\n",
        reply.body.len()
    ));
    if !reply.headers.iter().any(|(k, _)| *k == "Cache-Control") {
        head.push_str("Cache-Control: no-store\r\n");
    }
    for (k, v) in &reply.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Cors::Allow(o) = cors {
        head.push_str(&format!(
            "Access-Control-Allow-Origin: {o}\r\nVary: Origin\r\n"
        ));
    }
    if code == 401 {
        head.push_str("WWW-Authenticate: Bearer\r\n");
    }
    head.push_str(if keep {
        "\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    w.write_all(head.as_bytes()).await?;
    w.write_all(&reply.body).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::token_eq;

    #[test]
    fn token_must_match_exactly() {
        let t = b"secret";
        assert!(token_eq(t, t));
        assert!(!token_eq(b"secreT", t));
        assert!(!token_eq(b"secre", t));
        assert!(!token_eq(b"", t));
        // Длиннее ровно на 256 байт: раньше разница длин, приведённая к
        // u8, давала ноль, и лишний хвост не проверялся.
        let mut long = t.to_vec();
        long.extend([b'x'; 256]);
        assert!(!token_eq(&long, t));
    }
}
