// SPDX-License-Identifier: GPL-3.0-or-later
//! Прозрачная обёртка над любым `AsyncRead + AsyncWrite`, которая
//! попутно копирует первые `cap` записанных байт во внутренний буфер.
//!
//! Зачем: rustls не отдаёт наружу сырые байты ClientHello, который она
//! реально отправляет (это и есть корень ограничения Этапа 3 — см.
//! `PLAN.md`). Единственное надёжное место, откуда эти байты можно
//! получить не трогая внутренности rustls — это сам сокет, на уровне
//! записи в него. Оборачиваем `TcpStream` этим типом *до* того, как
//! отдать его `TlsConnector`, и после хендшейка достаём то, что
//! реально ушло в сеть, через [`CaptureFirstBytes::captured`].

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    pub struct CaptureFirstBytes<S> {
        #[pin]
        inner: S,
        captured: Vec<u8>,
        cap: usize,
    }
}

impl<S> CaptureFirstBytes<S> {
    pub fn new(inner: S, cap: usize) -> Self {
        Self {
            inner,
            captured: Vec::with_capacity(cap.min(4096)),
            cap,
        }
    }

    /// Байты, реально записанные в `inner` с начала (до `cap`
    /// включительно). Для TLS-соединения, обёрнутого до хендшейка, это
    /// TLS-рекорд(ы) ClientHello целиком (обычно укладывается в первую
    /// запись rustls за один вызов `poll_write`).
    pub fn captured(&self) -> &[u8] {
        &self.captured
    }
}

impl<S: AsyncRead> AsyncRead for CaptureFirstBytes<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite> AsyncWrite for CaptureFirstBytes<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let n = std::task::ready!(this.inner.poll_write(cx, buf))?;
        if this.captured.len() < *this.cap {
            let take = n.min(*this.cap - this.captured.len());
            this.captured.extend_from_slice(&buf[..take]);
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn captures_first_bytes_written() {
        let (mut peer, inner) = duplex(4096);
        let mut wrapped = CaptureFirstBytes::new(inner, 5);

        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let n = peer.read(&mut buf).await.unwrap();
            buf[..n].to_vec()
        });

        wrapped.write_all(b"hello world").await.unwrap();
        let got_on_other_side = reader.await.unwrap();
        assert_eq!(got_on_other_side, b"hello world");

        // захвачено ровно cap=5 байт, дальше не растёт
        assert_eq!(wrapped.captured(), b"hello");
    }
}
