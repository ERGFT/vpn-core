//! Локальное API: статистика, открытые соединения, группы серверов,
//! подписки, перечитать настройки. HTTP/1.1 + JSON, как у Clash/sing-box
//! (но без веб-панели).
//!
//! ```toml
//! [api]
//! listen = "127.0.0.1:9090"
//! token_file = "api-token.txt"     # или token = "…" (не короче 16 символов)
//! ```
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

use futures_util::future::BoxFuture;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::access::IpNet;
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
                let _ = tokio::time::timeout(Duration::from_secs(60), me.handle(s, local)).await;
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
            let req = match read_request(&mut r).await {
                Ok(Some(req)) => req,
                Ok(None) => return,
                Err(e) => {
                    let _ = respond(&mut w, 400, &json!({ "error": e.to_string() }), false).await;
                    return;
                }
            };
            let keep = !req.close;
            let (code, body) = self.route(&req, local).await;
            if respond(&mut w, code, &body, keep).await.is_err() || !keep {
                return;
            }
        }
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

    async fn route(&self, req: &Request, local: SocketAddr) -> (u16, Value) {
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
            return (421, json!({ "error": "неверный Host" }));
        }
        if req.header("origin").is_some() {
            return (403, json!({ "error": "запросы из браузера запрещены" }));
        }
        if !self.authorized(req) {
            let n = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= 10 {
                // Подбор токена: пауза растёт, но не больше 5 с.
                tokio::time::sleep(Duration::from_millis((n as u64 * 100).min(5000))).await;
            }
            tracing::warn!("api: неверный токен");
            return (
                401,
                json!({ "error": "нужен токен: Authorization: Bearer …" }),
            );
        }
        self.failures.store(0, Ordering::Relaxed);
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
