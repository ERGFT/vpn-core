// SPDX-License-Identifier: GPL-3.0-or-later
//! Локальное API: статистика, открытые соединения, группы серверов,
//! подписки, перечитать настройки. HTTP/1.1 + JSON, как у Clash/sing-box
//! (но без веб-панели).
//!
//! ```json
//! "experimental": {
//!   "clash_api": { "external_controller": "127.0.0.1:9090", "secret_file": "api-token.txt" }
//! }
//! ```
//!
//! (или `"secret": "…"`, не короче 16 символов)
//!
//! | Запрос | Что делает |
//! |---|---|
//! | `GET /version` | версия |
//! | `GET /stats` | трафик всего и по выходам, время работы, число соединений |
//! | `GET /connections` | открытые соединения |
//! | `DELETE /connections/{id}` | закрыть соединение (`/connections` — все) |
//! | `GET /groups` | группы: участники, задержки, текущий |
//! | `PUT /groups/{tag}` `{"member": "…"}` | выбрать участника (selector) |
//! | `POST /groups/{tag}/check` | проверить участников сейчас |
//! | `POST /subscriptions/{tag}/update` | обновить подписку сейчас |
//! | `POST /reload` | перечитать файл настроек без разрыва соединений |
//!
//! Потоки — ответ не кончается, пока клиент не закроет соединение: по
//! JSON-объекту на строку (`Transfer-Encoding: chunked`) или, с
//! `Upgrade: websocket`, по текстовому кадру WebSocket на объект:
//!
//! | Поток | Что присылает |
//! |---|---|
//! | `GET /events` | события: `connection_open`, `connection_close`, `group_switch`, `group_check`, `subscription_update`, `reload`, `lagged` (см. `events.rs`) |
//! | `GET /traffic` | раз в секунду: скорость `up`/`down` (байт/с) и `upTotal`/`downTotal` — как в Clash |
//! | `GET /memory` | раз в секунду: `inuse` (байт) — как в Clash |
//! | `GET /logs?level=info` | журнал: `{"type": "info", "payload": "…"}` — как в Clash |
//!
//! Потоков одновременно — не больше 16. Пока поток не слушают, события
//! не собираются.
//!
//! Безопасность: токен обязателен всегда (`Authorization: Bearer …`,
//! сравнение за постоянное время, после 10 неверных подряд — пауза);
//! заголовок `Host` должен быть адресом API (защита от DNS rebinding:
//! страница в браузере не сможет дотянуться до API через свой домен);
//! запросы с `Origin` отвергаются (браузер кросс-доменно не пришлёт
//! `Authorization` без CORS, но и простые запросы здесь не нужны).
//! Слушать не на 127.0.0.1 можно только с `allow_ip`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
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
use super::stats::Tracker;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    pub listen: SocketAddr,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub allow_ip: Vec<IpNet>,
}

/// Минимальная длина токена.
pub const MIN_TOKEN: usize = 16;
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;
/// Сколько ждать следующего запроса и ответа на обычный запрос.
const IDLE: Duration = Duration::from_secs(60);
/// Потоков (`/events`, `/logs`…) одновременно.
const MAX_STREAMS: usize = 16;

/// Что API умеет делать с приложением (реализует `Running`).
pub trait Control: Send + Sync {
    fn groups(&self) -> Value;
    fn select(&self, group: &str, member: &str) -> Result<()>;
    fn check(&self, group: &str) -> BoxFuture<'_, Result<()>>;
    fn update_subscription(&self, tag: &str) -> BoxFuture<'_, Result<usize>>;
    fn reload(&self) -> BoxFuture<'_, Result<Vec<String>>>;
}

pub struct Api {
    pub listen: SocketAddr,
    token: String,
    allow_ip: Vec<IpNet>,
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
        Ok(Arc::new(Api {
            listen: cfg.listen,
            token,
            allow_ip: cfg.allow_ip.clone(),
            tracker,
            control,
            failures: AtomicU32::new(0),
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
        }))
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
                    let _ = respond(&mut w, 400, &json!({ "error": e.to_string() }), false).await;
                    return;
                }
            };
            if let Some(feed) = feed_of(&req) {
                if let Some((code, body)) = self.gate(&req, local).await {
                    let _ = respond(&mut w, code, &body, false).await;
                } else {
                    self.stream(feed, &req, r, w).await;
                }
                return;
            }
            let keep = !req.close;
            let (code, body) = match self.gate(&req, local).await {
                Some(denied) => denied,
                None => tokio::time::timeout(IDLE, self.route(&req))
                    .await
                    .unwrap_or_else(|_| (504, json!({ "error": "не успели за 60 с" }))),
            };
            if respond(&mut w, code, &body, keep).await.is_err() || !keep {
                return;
            }
        }
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
            let body = json!({ "error": format!("потоков уже {MAX_STREAMS}") });
            let _ = respond(&mut w, 503, &body, false).await;
            return;
        };
        let src = match self.source(feed, req) {
            Ok(s) => s,
            Err(e) => {
                let _ = respond(&mut w, 400, &json!({ "error": e }), false).await;
                return;
            }
        };
        let upgrade = req
            .header("upgrade")
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
        if !upgrade {
            let head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson; charset=utf-8\r\n\
                        Transfer-Encoding: chunked\r\nCache-Control: no-store\r\n\
                        X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
            if w.write_all(head.as_bytes()).await.is_ok() {
                feed_chunked(src, r, w).await;
            }
            return;
        }
        let Some(key) = req.header("sec-websocket-key") else {
            let body = json!({ "error": "WebSocket: нет Sec-WebSocket-Key" });
            let _ = respond(&mut w, 400, &body, false).await;
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
        })
    }

    fn authorized(&self, req: &Request) -> bool {
        let got = req
            .header("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        // Сравнение за постоянное время.
        let a = got.as_bytes();
        let b = self.token.as_bytes();
        let mut diff = (a.len() ^ b.len()) as u8;
        for (i, x) in b.iter().enumerate() {
            diff |= x ^ a.get(i).copied().unwrap_or(0);
        }
        diff == 0
    }

    /// Проверки до любого запроса: `Some` — отказ.
    async fn gate(&self, req: &Request, local: SocketAddr) -> Option<(u16, Value)> {
        // DNS rebinding: Host — только адрес самого API.
        let host_ok = req.header("host").is_some_and(|h| {
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
        });
        if !host_ok {
            return Some((421, json!({ "error": "неверный Host" })));
        }
        if req.header("origin").is_some() {
            return Some((403, json!({ "error": "запросы из браузера запрещены" })));
        }
        if !self.authorized(req) {
            let n = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= 10 {
                // Подбор токена: пауза растёт, но не больше 5 с.
                tokio::time::sleep(Duration::from_millis((n as u64 * 100).min(5000))).await;
            }
            tracing::warn!("api: неверный токен");
            return Some((
                401,
                json!({ "error": "нужен токен: Authorization: Bearer …" }),
            ));
        }
        self.failures.store(0, Ordering::Relaxed);
        None
    }

    async fn route(&self, req: &Request) -> (u16, Value) {
        let path: Vec<&str> = req
            .path
            .split('?')
            .next()
            .unwrap_or("")
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let path: Vec<String> = path.iter().map(|p| pct_decode(p)).collect();
        let p: Vec<&str> = path.iter().map(String::as_str).collect();
        let ok = |v: Value| (200, v);
        let err = |code: u16, e: String| (code, json!({ "error": e }));
        match (req.method.as_str(), p.as_slice()) {
            ("GET", ["version"]) => ok(json!({ "version": env!("CARGO_PKG_VERSION") })),
            ("GET", ["stats"]) => {
                ok(serde_json::to_value(self.tracker.summary()).unwrap_or_default())
            }
            ("GET", ["connections"]) => ok(json!({ "connections": self.tracker.connections() })),
            ("DELETE", ["connections"]) => ok(json!({ "closed": self.tracker.close_all() })),
            ("DELETE", ["connections", id]) => match id.parse::<u64>() {
                Ok(id) if self.tracker.close(id) => ok(json!({ "closed": 1 })),
                _ => err(404, "нет такого соединения".into()),
            },
            ("GET", ["groups"]) => ok(self.control.groups()),
            ("PUT", ["groups", tag]) => {
                #[derive(Deserialize)]
                struct Sel {
                    member: String,
                }
                match serde_json::from_slice::<Sel>(&req.body) {
                    Ok(s) => match self.control.select(tag, &s.member) {
                        Ok(()) => ok(json!({ "group": tag, "member": s.member })),
                        Err(e) => err(400, e.to_string()),
                    },
                    Err(e) => err(400, format!("тело: {{\"member\": \"…\"}}: {e}")),
                }
            }
            ("POST", ["groups", tag, "check"]) => match self.control.check(tag).await {
                Ok(()) => ok(self.control.groups()),
                Err(e) => err(404, e.to_string()),
            },
            ("POST", ["subscriptions", tag, "update"]) => {
                match self.control.update_subscription(tag).await {
                    Ok(n) => ok(json!({ "subscription": tag, "servers": n })),
                    Err(e) => err(502, e.to_string()),
                }
            }
            ("POST", ["reload"]) => match self.control.reload().await {
                Ok(notes) => ok(json!({ "reloaded": true, "notes": notes })),
                Err(e) => err(400, e.to_string()),
            },
            _ => err(404, "нет такого запроса".into()),
        }
    }
}

/// Запрос потока: `GET /events`, `/traffic`, `/memory`, `/logs`.
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
        _ => None,
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
    code: u16,
    body: &Value,
    keep: bool,
) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
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
    let body = serde_json::to_vec_pretty(body).unwrap_or_default();
    let mut head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
        body.len()
    );
    if code == 401 {
        head.push_str("WWW-Authenticate: Bearer\r\n");
    }
    head.push_str(if keep {
        "\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    w.write_all(head.as_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}
