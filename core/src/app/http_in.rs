//! HTTP-прокси: разбор запроса к прокси (RFC 9110, 9112).
//!
//! - `CONNECT host:port` — туннель (так ходит весь HTTPS);
//! - `GET http://host/path` и прочие — обычный запрос: строка запроса
//!   переписывается в вид `GET /path`, заголовки прокси убираются, и
//!   добавляется `Connection: close` — одно соединение с прокси = один
//!   запрос к одному сайту (иначе следующий запрос по тому же соединению
//!   мог бы уйти не на тот сайт).
//!
//! Логин и пароль — заголовок `Proxy-Authorization: Basic …`.

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};
use crate::socks5::Credentials;
use crate::vless::Address;

/// Потолок на заголовок запроса.
pub const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;

#[derive(Debug)]
pub struct HttpRequest {
    pub connect: bool,
    pub target: Address,
    pub port: u16,
    /// Для обычного запроса — переписанный заголовок для сайта.
    pub forward_head: Vec<u8>,
    /// Логин и пароль из `Proxy-Authorization`, если были.
    pub auth: Option<(Vec<u8>, Vec<u8>)>,
}

/// Ответы прокси.
pub const RESP_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
pub const RESP_AUTH: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
pub const RESP_BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
pub const RESP_FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
pub const RESP_BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Прочитать заголовок запроса до пустой строки. Возвращает заголовок
/// (без пустой строки) и то, что пришло после него.
pub async fn read_head<R: AsyncRead + Unpin>(r: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Protocol(
                "HTTP: соединение закрыто до конца заголовка".into(),
            ));
        }
        // Искать с небольшим перекрытием: разделитель мог разрезаться.
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        // Запрос начинается с метода (заглавные буквы): иначе это не HTTP
        // (например, SOCKS5 на входе http) — отказать сразу, а не ждать.
        if !buf[0].is_ascii_uppercase() {
            return Err(Error::Protocol("HTTP: это не HTTP-запрос".into()));
        }
        if let Some(i) = super::sniff::find(&buf[from..], b"\r\n\r\n") {
            let end = from + i;
            let rest = buf.split_off(end + 4);
            buf.truncate(end);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(Error::Protocol(
                "HTTP: заголовок запроса слишком длинный".into(),
            ));
        }
    }
}

fn bad(msg: &str) -> Error {
    Error::Protocol(format!("HTTP: {msg}"))
}

/// `host:port` (порт обязателен, если `default_port` не задан).
fn parse_authority(a: &str, default_port: Option<u16>) -> Result<(Address, u16)> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest
            .split_once(']')
            .ok_or_else(|| bad("адрес IPv6 без ']'"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p),
            None if tail.is_empty() => None,
            None => return Err(bad("мусор после адреса")),
        };
        (h, port)
    } else {
        match a.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            Some(_) => return Err(bad("адрес IPv6 без скобок")),
            None => (a, None),
        }
    };
    let port = match port {
        Some(p) => p.parse::<u16>().map_err(|_| bad("неверный порт"))?,
        None => default_port.ok_or_else(|| bad("не указан порт"))?,
    };
    if host.is_empty() || host.len() > 255 {
        return Err(bad("пустое или слишком длинное имя"));
    }
    if host
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'/' || b == b'@')
    {
        return Err(bad("недопустимые символы в имени"));
    }
    let addr = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => Address::Ipv4(v4),
        Ok(std::net::IpAddr::V6(v6)) => Address::Ipv6(v6),
        Err(_) => Address::Domain(host.to_ascii_lowercase()),
    };
    Ok((addr, port))
}

fn parse_basic(v: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let (scheme, token) = v.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .ok()?;
    let i = raw.iter().position(|&b| b == b':')?;
    Some((raw[..i].to_vec(), raw[i + 1..].to_vec()))
}

/// Заголовки, которые относятся к соединению с прокси, а не к сайту.
fn is_hop_by_hop(name: &str) -> bool {
    [
        "proxy-authorization",
        "proxy-connection",
        "connection",
        "keep-alive",
    ]
    .iter()
    .any(|h| name.eq_ignore_ascii_case(h))
}

pub fn parse_request(head: &[u8]) -> Result<HttpRequest> {
    let text = std::str::from_utf8(head).map_err(|_| bad("заголовок не в UTF-8"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (Some(method), Some(uri), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("неверная строка запроса"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(bad("поддерживается только HTTP/1.x"));
    }
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(bad("неверный метод"));
    }
    let mut headers: Vec<(&str, &str)> = Vec::new();
    for l in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(bad("слишком много заголовков"));
        }
        let (k, v) = l.split_once(':').ok_or_else(|| bad("неверный заголовок"))?;
        if k.is_empty() || k.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(bad("неверное имя заголовка"));
        }
        headers.push((k, v.trim()));
    }
    let auth = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
        .and_then(|(_, v)| parse_basic(v));

    if method == "CONNECT" {
        let (target, port) = parse_authority(uri, None)?;
        return Ok(HttpRequest {
            connect: true,
            target,
            port,
            forward_head: Vec::new(),
            auth,
        });
    }

    let rest = uri.strip_prefix("http://").or_else(|| {
        uri.get(..7)
            .filter(|p| p.eq_ignore_ascii_case("http://"))
            .map(|_| &uri[7..])
    });
    let Some(rest) = rest else {
        return Err(bad(
            "ожидается абсолютный адрес http://… (HTTPS идёт через CONNECT)",
        ));
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    if authority.contains('@') {
        return Err(bad("логин в адресе сайта не поддерживается"));
    }
    let (target, port) = parse_authority(authority, Some(80))?;

    let upgrade = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("upgrade")
    });
    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        // WebSocket через прокси: Connection: Upgrade нужно сохранить.
        if is_hop_by_hop(k) && !(upgrade && k.eq_ignore_ascii_case("connection")) {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    if !has_host {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    if !upgrade {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    Ok(HttpRequest {
        connect: false,
        target,
        port,
        forward_head: out.into_bytes(),
        auth,
    })
}

/// Проверить логин и пароль запроса.
pub fn check_auth(req: &HttpRequest, creds: &Credentials) -> bool {
    match &req.auth {
        Some((u, p)) => creds.matches(u, p),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request() {
        let r =
            parse_request(b"CONNECT Example.com:443 HTTP/1.1\r\nHost: example.com:443").unwrap();
        assert!(r.connect);
        assert_eq!(r.target, Address::Domain("example.com".into()));
        assert_eq!(r.port, 443);
        let r = parse_request(b"CONNECT [2001:db8::1]:8443 HTTP/1.1").unwrap();
        assert_eq!(r.target, Address::Ipv6("2001:db8::1".parse().unwrap()));
        assert!(
            parse_request(b"CONNECT example.com HTTP/1.1").is_err(),
            "без порта"
        );
        assert!(parse_request(b"CONNECT a b:1 HTTP/1.1").is_err());
    }

    #[test]
    fn plain_request_is_rewritten() {
        let r = parse_request(
            b"GET http://site.test:8080/a/b?x=1 HTTP/1.1\r\nHost: site.test:8080\r\n\
Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic dTpw\r\nConnection: keep-alive\r\n\
Accept: */*",
        )
        .unwrap();
        assert!(!r.connect);
        assert_eq!(r.port, 8080);
        assert_eq!(r.auth, Some((b"u".to_vec(), b"p".to_vec())));
        let h = String::from_utf8(r.forward_head).unwrap();
        assert!(h.starts_with("GET /a/b?x=1 HTTP/1.1\r\n"), "{h}");
        assert!(h.contains("Host: site.test:8080\r\n"));
        assert!(h.contains("Accept: */*\r\n"));
        assert!(h.ends_with("Connection: close\r\n\r\n"), "{h}");
        assert!(!h.to_ascii_lowercase().contains("proxy-"), "{h}");
        assert!(!h.contains("keep-alive"), "{h}");

        let r = parse_request(b"GET http://site.test HTTP/1.0").unwrap();
        assert_eq!(r.port, 80);
        let h = String::from_utf8(r.forward_head).unwrap();
        assert!(
            h.starts_with("GET / HTTP/1.0\r\nHost: site.test\r\n"),
            "{h}"
        );
    }

    #[test]
    fn websocket_keeps_upgrade() {
        let r = parse_request(
            b"GET http://ws.test/chat HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: websocket",
        )
        .unwrap();
        let h = String::from_utf8(r.forward_head).unwrap();
        assert!(
            h.contains("Connection: Upgrade\r\n") && h.contains("Upgrade: websocket\r\n"),
            "{h}"
        );
        assert!(!h.contains("close"), "{h}");
    }

    #[test]
    fn rejects_bad_requests() {
        for bad in [
            &b"GET /local HTTP/1.1"[..],
            b"GET https://secure.test/ HTTP/1.1",
            b"GET http://user@site.test/ HTTP/1.1",
            b"GET http://site.test/ HTTP/2",
            b"get http://site.test/ HTTP/1.1",
            b"GET http://site.test/ HTTP/1.1\r\nBad Header: x",
            b"GET http://site.test/ HTTP/1.1\r\nNoColon",
            b"GET http://si te.test/ HTTP/1.1",
            b"\xff\xfe",
        ] {
            assert!(
                parse_request(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[tokio::test]
    async fn head_is_read_up_to_blank_line() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        use tokio::io::AsyncWriteExt;
        b.write_all(b"CONNECT a:1 HTTP/1.1\r\n\r").await.unwrap();
        b.write_all(b"\n\x16\x03\x01").await.unwrap();
        let (head, rest) = read_head(&mut a).await.unwrap();
        assert_eq!(head, b"CONNECT a:1 HTTP/1.1");
        assert_eq!(rest, b"\x16\x03\x01");

        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        b.write_all(&vec![b'a'; MAX_HEAD + 10]).await.unwrap();
        assert!(read_head(&mut a).await.is_err());
    }
}
