// SPDX-License-Identifier: GPL-3.0-or-later
//! Sniffing: домен сайта по первым байтам соединения — SNI из TLS
//! ClientHello или `Host` из HTTP-запроса. Нужен, когда приложение само
//! разрешило имя и прислало прокси IP-адрес: без домена правила вида
//! `"geosite": [...]` к такому соединению не применить.
//!
//! Разбор только читает байты и ничего не меняет: всё прочитанное
//! отправляется дальше как есть.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Сколько ждать первых байт от приложения. Протоколы, где первым
/// говорит сервер (SMTP, SSH), ничего не пришлют — тогда маршрут
/// выбирается без домена.
pub const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
/// Больше не читаем: ClientHello с ML-KEM — около 2 КиБ.
const MAX_SNIFF: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Sniff {
    /// Найден домен.
    Domain(String),
    /// Нужно больше байт.
    NeedMore,
    /// Не TLS и не HTTP (или домена нет).
    No,
}

/// Проверить, что это похоже на имя хоста, а не на мусор или IP.
fn valid_host(h: &str) -> Option<String> {
    let h = h.trim().trim_end_matches('.');
    if h.is_empty() || h.len() > 253 || h.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let ok = h
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    (ok && !h.starts_with('.') && !h.contains("..")).then(|| h.to_ascii_lowercase())
}

fn u16_at(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

/// SNI из TLS ClientHello (первая TLS-запись).
pub fn tls_sni(b: &[u8]) -> Sniff {
    if b.is_empty() {
        return Sniff::NeedMore;
    }
    // Запись Handshake, версия 3.x.
    if b[0] != 0x16 {
        return Sniff::No;
    }
    if b.len() < 5 {
        return Sniff::NeedMore;
    }
    if b[1] != 3 {
        return Sniff::No;
    }
    let rec_len = u16_at(b, 3).unwrap();
    if b.len() < 5 + rec_len {
        return if 5 + rec_len <= MAX_SNIFF {
            Sniff::NeedMore
        } else {
            Sniff::No
        };
    }
    let hs = &b[5..5 + rec_len];
    match parse_client_hello(hs) {
        Some(Some(h)) => Sniff::Domain(h),
        _ => Sniff::No,
    }
}

/// `Some(None)` — ClientHello без SNI; `None` — не разобрался.
pub(crate) fn parse_client_hello(hs: &[u8]) -> Option<Option<String>> {
    if *hs.first()? != 1 {
        return None;
    }
    let len = (usize::from(*hs.get(1)?) << 16) | u16_at(hs, 2)?;
    // ClientHello, разрезанный на несколько записей, — редкость; берём
    // то, что есть в первой.
    let body = hs.get(4..(4 + len).min(hs.len()))?;
    let mut i = 2 + 32; // версия + random
    let sid = usize::from(*body.get(i)?);
    i += 1 + sid;
    let suites = u16_at(body, i)?;
    i += 2 + suites;
    let comp = usize::from(*body.get(i)?);
    i += 1 + comp;
    let ext_len = u16_at(body, i)?;
    i += 2;
    let end = (i + ext_len).min(body.len());
    while i + 4 <= end {
        let ty = u16_at(body, i)?;
        let l = u16_at(body, i + 2)?;
        let data = body.get(i + 4..i + 4 + l)?;
        i += 4 + l;
        if ty != 0 {
            continue;
        }
        // server_name: список, берём host_name (тип 0).
        let mut j = 2;
        while j + 3 <= data.len() {
            let nt = data[j];
            let nl = u16_at(data, j + 1)?;
            let name = data.get(j + 3..j + 3 + nl)?;
            if nt == 0 {
                return Some(valid_host(std::str::from_utf8(name).ok()?));
            }
            j += 3 + nl;
        }
        return Some(None);
    }
    Some(None)
}

const METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// `Host` из HTTP/1.x-запроса.
pub fn http_host(b: &[u8]) -> Sniff {
    let n = b.len().min(8);
    let method = METHODS
        .iter()
        .any(|m| m[..n.min(m.len())] == b[..n.min(m.len())]);
    if !method {
        return Sniff::No;
    }
    let Some(end) = find(b, b"\r\n\r\n") else {
        return if b.len() < MAX_SNIFF {
            Sniff::NeedMore
        } else {
            Sniff::No
        };
    };
    let head = String::from_utf8_lossy(&b[..end]);
    for line in head.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                return match valid_host(strip_port(v.trim())) {
                    Some(h) => Sniff::Domain(h),
                    None => Sniff::No,
                };
            }
        }
    }
    Sniff::No
}

/// `host:80` → `host`; `[::1]:80` → `::1`.
pub fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match h.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.bytes().all(|c| c.is_ascii_digit()) => {
            host
        }
        _ => h,
    }
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Разобрать уже прочитанное: TLS или HTTP.
pub fn sniff(b: &[u8]) -> Sniff {
    match tls_sni(b) {
        Sniff::No => http_host(b),
        other => other,
    }
}

/// Дочитать от приложения первые байты (не дольше [`SNIFF_TIMEOUT`]) и
/// найти домен. `buf` уже может содержать данные; прочитанное остаётся в
/// нём. Ошибка чтения — ошибка соединения.
pub async fn read_and_sniff<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<String>> {
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    loop {
        match sniff(buf) {
            Sniff::Domain(d) => return Ok(Some(d)),
            Sniff::No => return Ok(None),
            Sniff::NeedMore if buf.len() >= MAX_SNIFF => return Ok(None),
            Sniff::NeedMore => {}
        }
        let mut chunk = vec![0u8; MAX_SNIFF - buf.len()];
        match tokio::time::timeout_at(deadline, r.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok(None),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(None),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// ClientHello с одним расширением SNI.
    pub fn client_hello(host: &str) -> Vec<u8> {
        let mut sni = vec![];
        let name = host.as_bytes();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut ext = vec![0x00, 0x0a, 0x00, 0x00]; // пустое расширение перед SNI
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0];
        hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn tls_sni_found_and_partial() {
        let ch = client_hello("Example.COM");
        assert_eq!(sniff(&ch), Sniff::Domain("example.com".into()));
        assert_eq!(sniff(&ch[..3]), Sniff::NeedMore);
        assert_eq!(sniff(&ch[..ch.len() - 1]), Sniff::NeedMore);
        assert_eq!(
            sniff(&client_hello("1.2.3.4")),
            Sniff::No,
            "IP в SNI — не домен"
        );
        assert_eq!(sniff(&client_hello("bad host")), Sniff::No);
    }

    #[test]
    fn http_host_found() {
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nUser-Agent: x\r\nhost: www.Site.ru:8080\r\n\r\n"),
            Sniff::Domain("www.site.ru".into())
        );
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nHost: a.b"), Sniff::NeedMore);
        assert_eq!(sniff(b"GE"), Sniff::NeedMore);
        assert_eq!(sniff(b"SSH-2.0-OpenSSH\r\n"), Sniff::No);
        assert_eq!(sniff(b"GET / HTTP/1.0\r\n\r\n"), Sniff::No, "без Host");
    }

    #[test]
    fn garbage_never_panics() {
        let ch = client_hello("example.com");
        for cut in 0..ch.len() {
            let mut v = ch[..cut].to_vec();
            v.extend(std::iter::repeat_n(0xff, 40));
            let _ = sniff(&v);
        }
        let mut x = 1u32;
        for _ in 0..2000 {
            let v: Vec<u8> = (0..64)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let mut v2 = vec![0x16, 3, 1, 0, 60];
            v2.extend_from_slice(&v);
            let _ = sniff(&v);
            let _ = sniff(&v2);
        }
    }

    #[test]
    fn ports_are_stripped() {
        assert_eq!(strip_port("a.com:443"), "a.com");
        assert_eq!(strip_port("a.com"), "a.com");
        assert_eq!(strip_port("[::1]:80"), "::1");
        assert_eq!(strip_port("::1"), "::1");
    }

    #[tokio::test]
    async fn reads_split_client_hello_and_times_out_on_silence() {
        let ch = client_hello("split.example");
        let (mut a, mut b) = tokio::io::duplex(4096);
        let (first, second) = ch.split_at(20);
        let (first, second) = (first.to_vec(), second.to_vec());
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            b.write_all(&first).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            b.write_all(&second).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut buf = Vec::new();
        let d = read_and_sniff(&mut a, &mut buf).await.unwrap();
        assert_eq!(d.as_deref(), Some("split.example"));
        assert_eq!(buf, ch, "прочитанное сохраняется целиком");

        let (mut a, _b) = tokio::io::duplex(64);
        let t = std::time::Instant::now();
        let mut buf = Vec::new();
        assert_eq!(read_and_sniff(&mut a, &mut buf).await.unwrap(), None);
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}
