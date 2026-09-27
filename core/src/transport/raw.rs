// SPDX-License-Identifier: GPL-3.0-or-later
//! Сырое TCP-соединение под TLS/REALITY — с одной особенностью, нужной
//! XTLS Vision.
//!
//! Vision в какой-то момент переключает соединение с внешнего TLS на
//! «прямую» передачу: после определённого TLS-рекорда сервер шлёт в TCP
//! уже не зашифрованные внешним TLS рекорды, а сырые байты внутреннего
//! TLS приложения. Go-реализация (`crypto/tls`) читает рекорды по одному,
//! поэтому всё, что пришло после точки переключения, лежит у неё
//! нетронутым в `rawInput`. rustls устроен иначе: `read_tls` забирает из
//! сокета сколько дадут, а `process_new_packets` расшифровывает ВСЕ
//! полные рекорды в буфере — сырые байты после точки переключения он
//! попытался бы расшифровать как внешний TLS и порвал бы соединение.
//!
//! Поэтому в режиме `record_aligned` этот тип отдаёт читателю (rustls)
//! байты строго в пределах одного TLS-рекорда за вызов, а всё прочитанное
//! из сокета сверх того держит у себя. rustls никогда не видит больше
//! одного рекорда вперёд, и после переключения остаток — ровно наш
//! внутренний буфер, как `rawInput` у Go. Для всех остальных соединений
//! режим выключен и тип — тонкая прослойка над `TcpStream` без
//! копирования.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::transport::fragment::{Fragment, Fragmenter};

/// Заголовок TLS-рекорда: тип (1), версия (2), длина (2).
const RECORD_HEADER_LEN: usize = 5;
/// Максимум тела рекорда по RFC 8446 (2^14 + 256 для шифротекста).
const MAX_RECORD_BODY: usize = 16384 + 256;
/// Буфер режима `record_aligned`: заведомо вмещает целый рекорд с запасом.
const ALIGNED_BUF: usize = 2 * (RECORD_HEADER_LEN + MAX_RECORD_BODY);

#[derive(Debug)]
pub struct RawConn {
    tcp: TcpStream,
    /// Прочитано из сокета, но ещё не отдано читателю.
    buf: Vec<u8>,
    start: usize,
    end: usize,
    /// Сколько байт текущего рекорда ещё можно отдать читателю
    /// (0 — стоим на границе рекорда).
    record_left: usize,
    record_aligned: bool,
    /// Дробление начала соединения (ClientHello), пока не закончено.
    frag: Option<Box<Fragmenter>>,
}

impl RawConn {
    pub fn new(tcp: TcpStream) -> Self {
        Self {
            tcp,
            buf: Vec::new(),
            start: 0,
            end: 0,
            record_left: 0,
            record_aligned: false,
            frag: None,
        }
    }

    /// Дробить начало соединения (см. [`crate::transport::fragment`]).
    pub fn with_fragment(mut self, f: Option<std::sync::Arc<Fragment>>) -> Self {
        self.frag = f.map(|f| Box::new(Fragmenter::new(*f)));
        self
    }

    /// Включить выдачу по одному TLS-рекорду (нужно только для Vision;
    /// включать до TLS-рукопожатия).
    pub fn set_record_aligned(&mut self, on: bool) {
        self.record_aligned = on;
        if on && self.buf.is_empty() {
            self.buf = vec![0u8; ALIGNED_BUF];
        }
    }

    /// Переключиться на прямую передачу: дальше читатель получает байты
    /// как есть — сначала то, что уже лежит в буфере (остаток после
    /// последнего внешнего рекорда), затем сокет.
    pub fn switch_to_direct(&mut self) {
        self.record_aligned = false;
        self.record_left = 0;
    }

    pub fn tcp(&self) -> &TcpStream {
        &self.tcp
    }

    fn buffered(&self) -> usize {
        self.end - self.start
    }

    /// Дочитать из сокета в буфер. `Ok(0)` — EOF.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        let mut rb = ReadBuf::new(&mut self.buf[self.end..]);
        ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        self.end += n;
        Poll::Ready(Ok(n))
    }

    fn copy_out(&mut self, out: &mut ReadBuf<'_>, limit: usize) -> usize {
        let n = limit.min(out.remaining()).min(self.buffered());
        out.put_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        n
    }
}

impl AsyncRead for RawConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.record_aligned {
            // Сначала остаток буфера (после переключения на прямую
            // передачу), потом сокет напрямую.
            if this.buffered() > 0 {
                let n = this.buffered();
                this.copy_out(out, n);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.tcp).poll_read(cx, out);
        }

        loop {
            if this.record_left == 0 {
                // На границе рекорда: нужен весь заголовок, чтобы узнать длину.
                if this.buffered() >= RECORD_HEADER_LEN {
                    let h = &this.buf[this.start..this.start + RECORD_HEADER_LEN];
                    let body = u16::from_be_bytes([h[3], h[4]]) as usize;
                    this.record_left = RECORD_HEADER_LEN + body;
                } else {
                    let n = ready!(this.poll_fill(cx))?;
                    if n == 0 {
                        // EOF: отдаём хвост как есть (rustls сам решит,
                        // что это обрыв посреди рекорда).
                        let rest = this.buffered();
                        this.copy_out(out, rest);
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
            }
            if this.buffered() == 0 {
                let n = ready!(this.poll_fill(cx))?;
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            let limit = this.record_left;
            let n = this.copy_out(out, limit);
            this.record_left -= n;
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for RawConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(f) = &mut this.frag {
            let r = f.poll_write(&mut this.tcp, cx, buf);
            if f.is_done() {
                this.frag = None;
            }
            return r;
        }
        Pin::new(&mut this.tcp).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.frag.is_some() {
            // Пока идёт дробление — по одному буферу: запись должна
            // целиком попасть к `Fragmenter`.
            let buf = bufs
                .iter()
                .find(|b| !b.is_empty())
                .map_or(&[][..], |b| &**b);
            return Pin::new(this).poll_write(cx, buf);
        }
        Pin::new(&mut this.tcp).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.frag.is_none() && self.tcp.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(f) = &mut this.frag {
            return f.poll_flush(&mut this.tcp, cx);
        }
        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(f) = &mut this.frag {
            ready!(f.poll_flush(&mut this.tcp, cx))?;
        }
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn pair() -> (RawConn, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (c, s) = tokio::join!(TcpStream::connect(addr), l.accept());
        (RawConn::new(c.unwrap()), s.unwrap().0)
    }

    fn record(body: &[u8]) -> Vec<u8> {
        let mut r = vec![0x17, 0x03, 0x03];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    /// Два рекорда и сырой хвост пришли одним куском: читатель получает
    /// строго по рекорду, хвост остаётся в буфере до переключения.
    #[tokio::test]
    async fn yields_one_record_per_read_and_keeps_tail() {
        let (mut raw, mut srv) = pair().await;
        raw.set_record_aligned(true);
        let r1 = record(b"first");
        let r2 = record(&[7u8; 300]);
        let mut wire = r1.clone();
        wire.extend_from_slice(&r2);
        wire.extend_from_slice(b"RAW-TAIL");
        srv.write_all(&wire).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = raw.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &r1[..]);
        let n = raw.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &r2[..]);

        raw.switch_to_direct();
        let n = raw.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"RAW-TAIL");
    }

    /// Рекорд, пришедший по байту, собирается, но не перескакивает границу.
    #[tokio::test]
    async fn handles_fragmented_records() {
        let (mut raw, mut srv) = pair().await;
        raw.set_record_aligned(true);
        let r1 = record(b"abc");
        let r2 = record(b"defgh");
        let mut wire = r1.clone();
        wire.extend_from_slice(&r2);
        tokio::spawn(async move {
            for b in wire {
                srv.write_all(&[b]).await.unwrap();
                srv.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
            // держим сокет открытым, пока клиент читает
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        while got.len() < r1.len() {
            let n = raw.read(&mut buf).await.unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, r1, "первый рекорд не должен захватить байты второго");
    }
}
