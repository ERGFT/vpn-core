//! Разбор ответа HTTP/1.1: статус, заголовки, тело (Content-Length,
//! chunked или до закрытия). Используется xhttp (HTTP/1.1), проверкой
//! доступности серверов и загрузкой подписок.

use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Потолок на строку и на все заголовки ответа.
pub const MAX_HEAD: usize = 16 * 1024;
const READ_CHUNK: usize = 16 * 1024;

pub struct Head {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

pub enum BodyKind {
    Chunked,
    Length(u64),
    UntilClose,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_kind(&self) -> BodyKind {
        if self
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
        {
            BodyKind::Chunked
        } else if let Some(n) = self
            .header("content-length")
            .and_then(|v| v.trim().parse().ok())
        {
            BodyKind::Length(n)
        } else {
            BodyKind::UntilClose
        }
    }
}

async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, limit: usize) -> io::Result<String> {
    let mut line = Vec::new();
    let n = (&mut *r)
        .take(limit as u64)
        .read_until(b'\n', &mut line)
        .await?;
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if !line.ends_with(b"\n") {
        return Err(io::Error::other("слишком длинная строка в ответе HTTP"));
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| io::Error::other("ответ HTTP — не текст"))
}

/// Прочитать статус и заголовки ответа.
pub async fn read_head<R: AsyncBufRead + Unpin>(r: &mut R) -> io::Result<Head> {
    let status_line = read_line(r, MAX_HEAD).await?;
    let status = status_line
        .strip_prefix("HTTP/1.")
        .and_then(|s| s.get(2..5))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other(format!("не HTTP-ответ: «{status_line}»")))?;
    let mut headers = Vec::new();
    let mut total = status_line.len();
    loop {
        let line = read_line(r, MAX_HEAD).await?;
        if line.is_empty() {
            break;
        }
        total += line.len();
        if total > MAX_HEAD {
            return Err(io::Error::other("слишком длинные заголовки ответа"));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Head { status, headers })
}

/// Перекачать тело ответа в `w` (или выбросить, если `w` нет).
pub async fn pump_body<R, W>(r: &mut R, kind: BodyKind, mut w: Option<&mut W>) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ_CHUNK];
    match kind {
        BodyKind::Length(mut left) => {
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                let n = r.read(&mut buf[..want]).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                if let Some(w) = w.as_deref_mut() {
                    w.write_all(&buf[..n]).await?;
                }
                left -= n as u64;
            }
        }
        BodyKind::UntilClose => loop {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(w) = w.as_deref_mut() {
                w.write_all(&buf[..n]).await?;
            }
        },
        BodyKind::Chunked => loop {
            let line = read_line(r, 1024).await?;
            let size_str = line.split(';').next().unwrap_or("").trim();
            let mut left = u64::from_str_radix(size_str, 16)
                .map_err(|_| io::Error::other(format!("битый размер чанка: «{line}»")))?;
            if left == 0 {
                // Трейлеры до пустой строки.
                while !read_line(r, MAX_HEAD).await?.is_empty() {}
                break;
            }
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                let n = r.read(&mut buf[..want]).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                if let Some(w) = w.as_deref_mut() {
                    w.write_all(&buf[..n]).await?;
                }
                left -= n as u64;
            }
            if !read_line(r, 16).await?.is_empty() {
                return Err(io::Error::other("после чанка нет CRLF"));
            }
        },
    }
    Ok(())
}
