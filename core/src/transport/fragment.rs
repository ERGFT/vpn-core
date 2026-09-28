// SPDX-License-Identifier: GPL-3.0-or-later
//! Дробление начала соединения (`fragment` у Xray, `freedom`): против DPI,
//! который ищет имя сайта (SNI) в первом пакете и не собирает TCP-поток.
//!
//! Два режима, как у Xray:
//!
//! - `"packets": "tlshello"` — первый TLS-рекорд с ClientHello режется на
//!   несколько рекордов длиной `length` байт тела; с `interval > 0` каждый
//!   уходит отдельным TCP-сегментом с паузой `interval` мс, с
//!   `interval = 0` — все рекорды одной записью (дробление только на
//!   уровне TLS);
//! - `"packets": "1-3"` — с 1-й по 3-ю запись в соединение режутся на
//!   TCP-сегменты длиной `length` с паузами `interval` мс.
//!
//! Длины и паузы выбираются случайно из диапазонов на каждый кусок.
//! После дробления — обычная передача без накладных расходов.
//!
//! Цена: лишние RTT-доли на рукопожатие (паузы) и заметность для DPI,
//! который, наоборот, ищет ClientHello из многих рекордов. Поэтому по
//! умолчанию выключено.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
use crate::transport::xhttp::Range;

/// Что дробить.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packets {
    TlsHello,
    /// Записи с `from` по `to` (с 1).
    Writes {
        from: u32,
        to: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    pub packets: Packets,
    pub length: Range,
    /// Пауза между кусками, мс.
    pub interval: Range,
}

/// Число или строка «от-до» в файле настроек.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum NumOrRange {
    Num(u32),
    Str(String),
}

impl NumOrRange {
    pub fn range(&self, what: &str) -> Result<Range> {
        match self {
            NumOrRange::Num(n) => Ok(Range { from: *n, to: *n }),
            NumOrRange::Str(s) => parse_range(s, what),
        }
    }
}

pub fn parse_range(s: &str, what: &str) -> Result<Range> {
    let bad = || Error::Config(format!("{what}: «{s}» — нужно число или «от-до»"));
    let s = s.trim();
    let (a, b) = match s.split_once('-') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (s, s),
    };
    let from: u32 = a.parse().map_err(|_| bad())?;
    let to: u32 = b.parse().map_err(|_| bad())?;
    if from > to {
        return Err(bad());
    }
    Ok(Range { from, to })
}

/// Раздел `fragment` в настройках выхода.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentConfig {
    /// `"tlshello"` или `"от-до"` (номера записей).
    pub packets: String,
    pub length: NumOrRange,
    pub interval: NumOrRange,
}

impl FragmentConfig {
    pub fn build(&self) -> Result<Fragment> {
        let packets = match self.packets.trim() {
            "tlshello" => Packets::TlsHello,
            other => {
                let r = parse_range(other, "fragment.packets")?;
                if r.from == 0 {
                    return Err(Error::Config(
                        "fragment.packets: записи считаются с 1".into(),
                    ));
                }
                Packets::Writes {
                    from: r.from,
                    to: r.to,
                }
            }
        };
        let length = self.length.range("fragment.length")?;
        if length.from == 0 {
            return Err(Error::Config("fragment.length: от 1 байта".into()));
        }
        let interval = self.interval.range("fragment.interval")?;
        if interval.to > 1000 {
            return Err(Error::Config(
                "fragment.interval: больше секунды на кусок — соединения будут открываться вечность"
                    .into(),
            ));
        }
        Ok(Fragment {
            packets,
            length,
            interval,
        })
    }
}

/// Состояние дробления одного соединения.
#[derive(Debug)]
pub struct Fragmenter {
    cfg: Fragment,
    /// Сколько записей видели.
    count: u32,
    /// Куски к отправке: данные и пауза после.
    pending: VecDeque<(Vec<u8>, Duration)>,
    /// Сколько байт уже отправлено из первого куска.
    sent: usize,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Раздробленная запись: столько байт вернуть вызывающему по окончании.
    inflight: Option<usize>,
    done: bool,
}

fn pause(r: Range) -> Duration {
    Duration::from_millis(r.rand() as u64)
}

impl Fragmenter {
    pub fn new(cfg: Fragment) -> Self {
        Fragmenter {
            cfg,
            count: 0,
            pending: VecDeque::new(),
            sent: 0,
            sleep: None,
            inflight: None,
            done: false,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done && self.pending.is_empty() && self.inflight.is_none()
    }

    /// Разрезать запись `buf` на куски; `false` — эту запись не дробить.
    fn plan(&mut self, buf: &[u8]) -> bool {
        self.count += 1;
        let c = self.cfg;
        match c.packets {
            Packets::TlsHello => {
                self.done = true;
                if self.count != 1 || buf.len() <= 5 || buf[0] != 0x16 {
                    return false;
                }
                let rec_len = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
                if buf.len() < rec_len {
                    return false;
                }
                let body = &buf[5..rec_len];
                let mut combined = Vec::new();
                let mut from = 0;
                while from < body.len() {
                    let to = (from + c.length.rand().max(1) as usize).min(body.len());
                    let mut rec = Vec::with_capacity(5 + to - from);
                    rec.extend_from_slice(&buf[..3]);
                    rec.extend_from_slice(&((to - from) as u16).to_be_bytes());
                    rec.extend_from_slice(&body[from..to]);
                    if c.interval.to == 0 {
                        combined.extend_from_slice(&rec);
                    } else {
                        self.pending.push_back((rec, pause(c.interval)));
                    }
                    from = to;
                }
                if !combined.is_empty() {
                    self.pending.push_back((combined, Duration::ZERO));
                }
                if buf.len() > rec_len {
                    self.pending
                        .push_back((buf[rec_len..].to_vec(), Duration::ZERO));
                }
                true
            }
            Packets::Writes { from, to } => {
                if self.count > to {
                    self.done = true;
                    return false;
                }
                if self.count < from {
                    return false;
                }
                if self.count == to {
                    self.done = true;
                }
                let mut i = 0;
                while i < buf.len() {
                    let j = (i + c.length.rand().max(1) as usize).min(buf.len());
                    self.pending
                        .push_back((buf[i..j].to_vec(), pause(c.interval)));
                    i = j;
                }
                true
            }
        }
    }

    /// Отправить накопленные куски.
    fn poll_drain<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(s) = &mut self.sleep {
                ready!(s.as_mut().poll(cx));
                self.sleep = None;
            }
            let Some((data, after)) = self.pending.front() else {
                return Poll::Ready(Ok(()));
            };
            let after = *after;
            while self.sent < data.len() {
                let n = ready!(Pin::new(&mut *w).poll_write(cx, &data[self.sent..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.sent += n;
            }
            // Кусок — отдельным сегментом: сбросить до паузы.
            ready!(Pin::new(&mut *w).poll_flush(cx))?;
            self.pending.pop_front();
            self.sent = 0;
            if !after.is_zero() {
                self.sleep = Some(Box::pin(tokio::time::sleep(after)));
            }
        }
    }

    pub fn poll_write<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(n) = self.inflight {
            // Продолжение раздробленной записи (вызывающий повторил её).
            ready!(self.poll_drain(w, cx))?;
            self.inflight = None;
            return Poll::Ready(Ok(n));
        }
        ready!(self.poll_drain(w, cx))?;
        if self.done || buf.is_empty() || !self.plan(buf) {
            return Pin::new(w).poll_write(cx, buf);
        }
        self.inflight = Some(buf.len());
        ready!(self.poll_drain(w, cx))?;
        self.inflight = None;
        Poll::Ready(Ok(buf.len()))
    }

    pub fn poll_flush<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(w, cx))?;
        Pin::new(w).poll_flush(cx)
    }
}

use std::future::Future;

/// Поток с дроблением начала (для выхода `direct`).
pub struct FragmentStream<S> {
    inner: S,
    frag: Option<Fragmenter>,
}

impl<S> FragmentStream<S> {
    pub fn new(inner: S, cfg: Option<Arc<Fragment>>) -> Self {
        FragmentStream {
            inner,
            frag: cfg.map(|c| Fragmenter::new(*c)),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.frag {
            Some(f) if !f.is_done() => {
                let r = f.poll_write(&mut this.inner, cx, buf);
                if f.is_done() {
                    this.frag = None;
                }
                r
            }
            _ => Pin::new(&mut this.inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.frag {
            Some(f) => f.poll_flush(&mut this.inner, cx),
            None => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(f) = &mut this.frag {
            ready!(f.poll_flush(&mut this.inner, cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn hello(len: usize) -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01];
        v.extend_from_slice(&(len as u16).to_be_bytes());
        v.extend((0..len).map(|i| i as u8));
        v
    }

    /// Пишет в канал и записывает границы записей.
    struct Recorder {
        writes: Vec<Vec<u8>>,
        flushed: Vec<usize>,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.get_mut().writes.push(b.to_vec());
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.flushed.push(this.writes.len());
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for Recorder {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _b: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn frag(packets: Packets, len: (u32, u32), interval: (u32, u32)) -> Option<Arc<Fragment>> {
        Some(Arc::new(Fragment {
            packets,
            length: Range {
                from: len.0,
                to: len.1,
            },
            interval: Range {
                from: interval.0,
                to: interval.1,
            },
        }))
    }

    /// Разобрать поток TLS-рекордов обратно в тело.
    fn records(wire: &[u8]) -> (Vec<usize>, Vec<u8>) {
        let (mut lens, mut body, mut i) = (Vec::new(), Vec::new(), 0);
        while i < wire.len() {
            assert_eq!(&wire[i..i + 3], &[0x16, 0x03, 0x01]);
            let l = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
            lens.push(l);
            body.extend_from_slice(&wire[i + 5..i + 5 + l]);
            i += 5 + l;
        }
        (lens, body)
    }

    #[tokio::test(start_paused = true)]
    async fn tlshello_splits_into_records_with_pauses() {
        let h = hello(500);
        let mut s = FragmentStream::new(
            Recorder {
                writes: vec![],
                flushed: vec![],
            },
            frag(Packets::TlsHello, (100, 200), (10, 20)),
        );
        let t0 = tokio::time::Instant::now();
        let mut first = h.clone();
        first.extend_from_slice(b"TAIL");
        s.write_all(&first).await.unwrap();
        s.write_all(b"after").await.unwrap();
        s.flush().await.unwrap();
        let w = &s.inner.writes;
        // Каждый рекорд — своя запись; хвост и следующая запись — как есть.
        assert!(w.len() >= 4, "{}", w.len());
        let n = w.len();
        assert_eq!(w[n - 2], b"TAIL");
        assert_eq!(w[n - 1], b"after");
        let wire: Vec<u8> = w[..n - 2].concat();
        let (lens, body) = records(&wire);
        assert_eq!(body, h[5..]);
        assert!(lens[..lens.len() - 1]
            .iter()
            .all(|l| (100..=200).contains(l)));
        assert!(t0.elapsed() >= Duration::from_millis(10 * (n as u64 - 2)));
        assert!(
            s.frag.is_none(),
            "после ClientHello — без накладных расходов"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tlshello_without_interval_is_one_write() {
        let h = hello(300);
        let mut s = FragmentStream::new(
            Recorder {
                writes: vec![],
                flushed: vec![],
            },
            frag(Packets::TlsHello, (50, 50), (0, 0)),
        );
        s.write_all(&h).await.unwrap();
        assert_eq!(s.inner.writes.len(), 1);
        let (lens, body) = records(&s.inner.writes[0]);
        assert_eq!(lens, [50, 50, 50, 50, 50, 50]);
        assert_eq!(body, h[5..]);
    }

    #[tokio::test(start_paused = true)]
    async fn not_a_hello_passes_through() {
        let mut s = FragmentStream::new(
            Recorder {
                writes: vec![],
                flushed: vec![],
            },
            frag(Packets::TlsHello, (1, 2), (5, 5)),
        );
        s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert_eq!(s.inner.writes.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn writes_range_splits_tcp_segments() {
        let mut s = FragmentStream::new(
            Recorder {
                writes: vec![],
                flushed: vec![],
            },
            frag(Packets::Writes { from: 2, to: 3 }, (3, 3), (1, 1)),
        );
        s.write_all(b"one").await.unwrap();
        s.write_all(b"second").await.unwrap();
        s.write_all(b"third!!").await.unwrap();
        s.write_all(b"fourth").await.unwrap();
        let w: Vec<&[u8]> = s.inner.writes.iter().map(|v| v.as_slice()).collect();
        assert_eq!(
            w,
            [&b"one"[..], b"sec", b"ond", b"thi", b"rd!", b"!", b"fourth"]
        );
        // Каждый кусок сброшен отдельно.
        assert!(s.inner.flushed.len() >= 5);
    }

    #[tokio::test]
    async fn real_socket_receives_same_bytes() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut v = Vec::new();
            s.read_to_end(&mut v).await.unwrap();
            v
        });
        let c = tokio::net::TcpStream::connect(a).await.unwrap();
        c.set_nodelay(true).unwrap();
        let mut s = FragmentStream::new(c, frag(Packets::TlsHello, (7, 40), (0, 2)));
        let h = hello(1000);
        s.write_all(&h).await.unwrap();
        s.write_all(b"rest").await.unwrap();
        s.shutdown().await.unwrap();
        drop(s);
        let got = srv.await.unwrap();
        let (_, body) = records(&got[..got.len() - 4]);
        assert_eq!(body, h[5..]);
        assert!(got.ends_with(b"rest"));
    }

    /// `ключ='строка'` или `ключ=число` построчно → JSON-объект.
    fn kv(s: &str) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        for line in s.lines() {
            let (k, v) = line.split_once('=').unwrap();
            let v = v.trim();
            let v = match v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')) {
                Some(s) => serde_json::Value::String(s.into()),
                None => serde_json::Value::from(v.parse::<u64>().unwrap()),
            };
            m.insert(k.trim().into(), v);
        }
        serde_json::Value::Object(m)
    }

    #[test]
    fn config_parsing() {
        let c: FragmentConfig =
            serde_json::from_value(kv("packets='tlshello'\nlength='100-200'\ninterval=10"))
                .unwrap();
        let f = c.build().unwrap();
        assert_eq!(f.packets, Packets::TlsHello);
        assert_eq!(f.length, Range { from: 100, to: 200 });
        assert_eq!(f.interval, Range { from: 10, to: 10 });
        let c: FragmentConfig =
            serde_json::from_value(kv("packets='1-3'\nlength=5\ninterval='0'")).unwrap();
        assert_eq!(
            c.build().unwrap().packets,
            Packets::Writes { from: 1, to: 3 }
        );
        for bad in [
            "packets='0-3'\nlength=5\ninterval=0",
            "packets='x'\nlength=5\ninterval=0",
            "packets='tlshello'\nlength=0\ninterval=0",
            "packets='tlshello'\nlength='9-3'\ninterval=0",
            "packets='tlshello'\nlength=5\ninterval=5000",
        ] {
            let c: FragmentConfig = serde_json::from_value(kv(bad)).unwrap();
            assert!(c.build().is_err(), "{bad}");
        }
    }
}
