// SPDX-License-Identifier: GPL-3.0-or-later
//! Транспорт `type=httpupgrade` (Xray-core, `transport/internet/httpupgrade`):
//! обычный HTTP/1.1-запрос Upgrade, как у WebSocket, но после ответа
//! `101 Switching Protocols` данные идут по соединению как есть — без
//! кадров WebSocket. Дешевле ws по накладным расходам и так же проходит
//! через CDN, умеющие WebSocket.
//!
//! Запрос — как у Xray: `GET <path>`, `Host`, заголовки Chrome
//! (`browser_headers`, вариант «ws»), `Connection: Upgrade`,
//! `Upgrade: websocket`. Ответ проверяется так же строго: статус 101 и
//! заголовки `Upgrade: websocket`, `Connection: upgrade`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::transport::browser_headers::Variant;
use crate::transport::tcp_tls::{connect_tls_by_security, SecureStream};
use crate::vless::protocol::{vless_connect, Address, Command, VlessStream};
use crate::vless::VlessConfig;

/// Потолок на размер заголовков ответа — защита от сервера, который шлёт
/// бесконечный ответ вместо 101.
const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// Поток после Upgrade: сначала байты, пришедшие вместе с ответом
/// (если сервер сразу прислал данные), затем сокет.
pub struct HttpUpgradeStream<S> {
    inner: S,
    prefix: Vec<u8>,
    pos: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpUpgradeStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(out.remaining());
            out.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpUpgradeStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub type HttpUpgradeVlessStream = HttpUpgradeStream<SecureStream>;

/// Собрать запрос Upgrade. Порядок заголовков — как у Go `http.Request.Write`:
/// `Host`, `User-Agent`, затем остальные по алфавиту.
pub fn build_request(host: &str, path: &str, browser: crate::fingerprint::Browser) -> String {
    let mut headers = crate::transport::browser_headers::headers(browser, Variant::Ws);
    #[allow(
        clippy::expect_used,
        reason = "инвариант: в заголовках браузера User-Agent есть всегда"
    )]
    let ua = headers.remove(
        headers
            .iter()
            .position(|(k, _)| *k == "User-Agent")
            .expect("User-Agent всегда есть"),
    );
    headers.push(("Connection", "Upgrade".into()));
    headers.push(("Upgrade", "websocket".into()));
    headers.sort_by(|a, b| a.0.cmp(b.0));
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\n",
        ua.1
    );
    for (k, v) in headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(&v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req
}

/// Проверить заголовки ответа и вернуть длину «головы» (до пустой строки
/// включительно). `Ok(None)` — голова ещё не пришла целиком.
pub fn parse_response(buf: &[u8]) -> Result<Option<usize>> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&buf[..end])
        .map_err(|_| Error::Protocol("httpupgrade: ответ сервера не текст".into()))?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    if !status.starts_with("HTTP/1.1 101") {
        return Err(Error::Protocol(format!(
            "httpupgrade: сервер ответил «{status}» вместо 101 (неверный path или это не httpupgrade-вход)"
        )));
    }
    let mut upgrade_ok = false;
    let mut connection_ok = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase());
            if k == "upgrade" && v == "websocket" {
                upgrade_ok = true;
            }
            if k == "connection" && v == "upgrade" {
                connection_ok = true;
            }
        }
    }
    if !(upgrade_ok && connection_ok) {
        return Err(Error::Protocol(
            "httpupgrade: в ответе 101 нет Upgrade: websocket / Connection: upgrade".into(),
        ));
    }
    Ok(Some(end + 4))
}

/// Поднять TCP (+TLS или REALITY) и выполнить HTTP Upgrade.
pub async fn connect_httpupgrade(cfg: &VlessConfig) -> Result<HttpUpgradeVlessStream> {
    // Как Xray: ALPN для httpupgrade — http/1.1 (`WithNextProto("http/1.1")`).
    let alpn = cfg.alpn().unwrap_or_else(|| vec![b"http/1.1".to_vec()]);
    let mut stream = connect_tls_by_security(cfg, alpn).await?;
    let req = build_request(cfg.ws_host(), &cfg.http_path(), cfg.browser);
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let head_len = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Protocol(
                "httpupgrade: сервер закрыл соединение, не ответив на Upgrade".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(len) = parse_response(&buf)? {
            break len;
        }
        if buf.len() > MAX_RESPONSE_HEAD {
            return Err(Error::Protocol(
                "httpupgrade: слишком длинный ответ сервера".into(),
            ));
        }
    };
    Ok(HttpUpgradeStream {
        inner: stream,
        prefix: buf.split_off(head_len),
        pos: 0,
    })
}

/// Полное открытие соединения: транспорт + заголовок VLESS.
pub async fn connect_command_httpupgrade(
    cfg: &VlessConfig,
    id: &Uuid,
    command: Command,
    target: Address,
    target_port: u16,
) -> Result<VlessStream<HttpUpgradeVlessStream>> {
    cfg.ensure_flow_supported()?;
    let stream = connect_httpupgrade(cfg).await?;
    vless_connect(stream, id, command, &target, target_port).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_go_header_order_and_chrome_headers() {
        let r = build_request("cdn.example", "/up", crate::fingerprint::Browser::Chrome);
        let lines: Vec<&str> = r.split("\r\n").collect();
        assert_eq!(lines[0], "GET /up HTTP/1.1");
        assert_eq!(lines[1], "Host: cdn.example");
        assert!(lines[2].starts_with("User-Agent: Mozilla/5.0"));
        let names: Vec<&str> = lines[3..]
            .iter()
            .take_while(|l| !l.is_empty())
            .map(|l| l.split(':').next().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "остальные заголовки — по алфавиту");
        assert!(names.contains(&"Upgrade") && names.contains(&"Connection"));
        assert!(r.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parses_101_and_rejects_others() {
        let ok = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nDATA";
        assert_eq!(parse_response(ok).unwrap(), Some(ok.len() - 4));
        assert_eq!(parse_response(b"HTTP/1.1 101 Switching").unwrap(), None);
        assert!(parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n").is_err());
        assert!(
            parse_response(b"HTTP/1.1 101 OK\r\nUpgrade: h2c\r\nConnection: upgrade\r\n\r\n")
                .is_err()
        );
    }
}
