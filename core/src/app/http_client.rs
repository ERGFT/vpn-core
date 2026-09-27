// SPDX-License-Identifier: GPL-3.0-or-later
//! Маленький HTTP/1.1-клиент поверх любого выхода: проверка доступности
//! серверов (группы `urltest`/`fallback`) и загрузка подписок.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncWrite, AsyncWriteExt, BufReader};

use super::outbound::Outbound;
use super::{Metadata, Network};
use crate::error::{Error, Result};
use crate::http1;
use crate::transport::AsyncStream;
use crate::vless::Address;

/// Метка входа для запросов самого клиента.
pub const INTERNAL: &str = "internal";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Путь с запросом: `/path?x=1`.
    pub path: String,
}

impl Url {
    /// Ошибки не содержат самого адреса: в адресе подписки — токен.
    pub fn parse(s: &str) -> Result<Self> {
        let u = url::Url::parse(s.trim()).map_err(|e| Error::Config(format!("адрес: {e}")))?;
        let https = match u.scheme() {
            "https" => true,
            "http" => false,
            other => {
                return Err(Error::Config(format!(
                    "адрес: схема {other}, нужна http или https"
                )))
            }
        };
        let host = u
            .host_str()
            .ok_or_else(|| Error::Config("адрес: нет имени сервера".into()))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = u
            .port_or_known_default()
            .unwrap_or(if https { 443 } else { 80 });
        let mut path = u.path().to_string();
        if let Some(q) = u.query() {
            path.push('?');
            path.push_str(q);
        }
        Ok(Url {
            https,
            host,
            port,
            path,
        })
    }

    fn address(&self) -> Address {
        match self.host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v4)) => Address::Ipv4(v4),
            Ok(std::net::IpAddr::V6(v6)) => Address::Ipv6(v6),
            Err(_) => Address::Domain(self.host.to_ascii_lowercase()),
        }
    }

    fn host_header(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match (self.https, self.port) {
            (true, 443) | (false, 80) => h,
            (_, p) => format!("{h}:{p}"),
        }
    }
}

/// Соединение с сервером `url` через выход (с TLS для https).
/// `roots` — свои корневые сертификаты (иначе встроенные).
pub async fn open(
    out: &dyn Outbound,
    url: &Url,
    roots: Option<&rustls::RootCertStore>,
) -> Result<Box<dyn AsyncStream>> {
    let meta = Metadata {
        inbound: INTERNAL.into(),
        source: SocketAddr::from(([127, 0, 0, 1], 0)),
        network: Network::Tcp,
        target: url.address(),
        port: url.port,
        sniffed: None,
    };
    let s = out.connect(&meta).await?;
    if !url.https {
        return Ok(s);
    }
    let tls = crate::transport::tcp_tls::tls_over(
        s,
        &url.host,
        roots.cloned(),
        vec![b"http/1.1".to_vec()],
    )
    .await?;
    Ok(Box::new(tls))
}

fn request(url: &Url, headers: &[(&str, &str)]) -> String {
    let mut r = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        url.path,
        url.host_header()
    );
    for (k, v) in headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    r.push_str("\r\n");
    r
}

/// Время до первой строки ответа (задержка сервера для `urltest`).
/// Любой HTTP-ответ — успех: важно, что путь через выход работает.
pub async fn probe(out: &dyn Outbound, url: &Url, timeout: Duration) -> Result<Duration> {
    tokio::time::timeout(timeout, async {
        let t0 = Instant::now();
        let mut s = open(out, url, None).await?;
        s.write_all(request(url, &[("User-Agent", "Mozilla/5.0")]).as_bytes())
            .await?;
        s.flush().await?;
        let mut r = BufReader::new(s);
        http1::read_head(&mut r).await?;
        Ok(t0.elapsed())
    })
    .await
    .map_err(|_| Error::Protocol("проверка: нет ответа вовремя".into()))?
}

/// Буфер с потолком: больше `limit` байт — ошибка.
struct Limited {
    buf: Vec<u8>,
    limit: usize,
}

impl AsyncWrite for Limited {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.buf.len() + b.len() > self.limit {
            return Poll::Ready(Err(std::io::Error::other("ответ больше допустимого")));
        }
        self.buf.extend_from_slice(b);
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// GET с переходами по перенаправлениям (до 3; `https_only` — никуда,
/// кроме https). Тело — не больше `limit` байт.
pub async fn get(
    out: &dyn Outbound,
    url: &str,
    headers: &[(&str, &str)],
    limit: usize,
    timeout: Duration,
    https_only: bool,
    roots: Option<&rustls::RootCertStore>,
) -> Result<Response> {
    tokio::time::timeout(timeout, async {
        let mut u = Url::parse(url)?;
        for _ in 0..4 {
            if https_only && !u.https {
                return Err(Error::Config(format!(
                    "адрес {}: только https (иначе содержимое видно и подменяемо по пути)",
                    u.host
                )));
            }
            let mut s = open(out, &u, roots).await?;
            s.write_all(request(&u, headers).as_bytes()).await?;
            s.flush().await?;
            let mut r = BufReader::new(s);
            let head = http1::read_head(&mut r).await?;
            if matches!(head.status, 301 | 302 | 303 | 307 | 308) {
                let loc = head
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| Error::Protocol("перенаправление без Location".into()))?;
                let base = url::Url::parse(&format!(
                    "{}://{}{}",
                    if u.https { "https" } else { "http" },
                    u.host_header(),
                    u.path
                ))
                .map_err(|e| Error::Protocol(e.to_string()))?;
                let next = base
                    .join(&loc)
                    .map_err(|e| Error::Protocol(format!("перенаправление: {e}")))?;
                u = Url::parse(next.as_str())?;
                continue;
            }
            let mut body = Limited {
                buf: Vec::new(),
                limit,
            };
            http1::pump_body(&mut r, head.body_kind(), Some(&mut body)).await?;
            return Ok(Response {
                status: head.status,
                headers: head.headers,
                body: body.buf,
            });
        }
        Err(Error::Protocol("слишком много перенаправлений".into()))
    })
    .await
    .map_err(|_| Error::Protocol("HTTP: нет ответа вовремя".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://panel.example:8443/sub/abc?x=1").unwrap();
        assert_eq!(
            u,
            Url {
                https: true,
                host: "panel.example".into(),
                port: 8443,
                path: "/sub/abc?x=1".into()
            }
        );
        assert_eq!(u.host_header(), "panel.example:8443");
        let u = Url::parse("http://[::1]/").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.host_header().as_str()),
            ("::1", 80, "[::1]")
        );
        assert!(Url::parse("ftp://x/").is_err());
        assert!(Url::parse("nonsense").is_err());
    }
}
