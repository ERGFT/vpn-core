//! Mux.Cool для TCP — несколько соединений приложения в одном VLESS-потоке
//! (как `mux.enabled` у клиента Xray-core, `common/mux`).
//!
//! Зачем: одно рукопожатие TLS/REALITY на много соединений — быстрее
//! открываются страницы с десятками запросов, меньше заметных «вспышек»
//! новых TLS-соединений к серверу. Цена — все соединения делят одно окно
//! TCP (потеря пакета тормозит все) и нет своего управления потоком:
//! медленный получатель одного соединения задерживает остальные (у Xray
//! так же).
//!
//! Поток: VLESS с командой Mux (`v1.mux.cool:666`). Кадр:
//!
//! ```text
//! 2 байта  длина метаданных
//! 2 байта  ID сессии (клиент считает с 1; 0 — у XUDP)
//! 1 байт   статус: 1 New, 2 Keep, 3 End, 4 KeepAlive
//! 1 байт   опции: 1 — есть данные, 2 — ошибка
//! только New: 1 байт сеть (1 TCP), 2 байта порт, адрес (1 IPv4 / 2 домен / 3 IPv6)
//! если есть данные: 2 байта длина, данные (у Xray — не больше 8 КиБ)
//! ```
//!
//! Как у Xray: в одном потоке одновременно не больше `concurrency`
//! соединений и не больше 128 за всю жизнь потока; поток без соединений
//! закрывается через 16 с. Конец записи приложения (`shutdown`) — кадр
//! End, после которого сервер закрывает соединение целиком: полузакрытие
//! через Mux.Cool не передаётся (у Xray так же).
//!
//! С XTLS Vision Mux.Cool для TCP несовместим (Xray-сервер рвёт такие
//! потоки) — это проверяется при сборке выхода.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};

use crate::error::{Error, Result};
use crate::transport::AsyncStream;
use crate::vless::protocol::Address;

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEPALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const NETWORK_TCP: u8 = 1;

/// Данные одного кадра (как `buf.Size` у Xray).
pub const MAX_CHUNK: usize = 8192;
/// Соединений за всю жизнь одного потока (`MaxConnection` у Xray).
pub const MAX_TOTAL: usize = 128;
/// Поток без соединений закрывается через столько.
pub const IDLE: Duration = Duration::from_secs(16);
/// Потолок метаданных кадра от сервера (у Xray — 512).
const MAX_META: usize = 512;
/// Очереди кадров к писателю и данных к каждому соединению.
const QUEUE: usize = 64;

fn frame_new(id: u16, target: &Address, port: u16) -> Vec<u8> {
    let mut b = BytesMut::with_capacity(32);
    b.put_u16(0);
    b.put_u16(id);
    b.put_u8(STATUS_NEW);
    b.put_u8(0);
    b.put_u8(NETWORK_TCP);
    b.put_u16(port);
    target.encode(&mut b);
    let meta = (b.len() - 2) as u16;
    b[0..2].copy_from_slice(&meta.to_be_bytes());
    b.to_vec()
}

fn frame_keep(id: u16, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(data.len() + 8);
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&id.to_be_bytes());
    b.push(STATUS_KEEP);
    b.push(OPTION_DATA);
    b.extend_from_slice(&(data.len() as u16).to_be_bytes());
    b.extend_from_slice(data);
    b
}

fn frame_end(id: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(6);
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&id.to_be_bytes());
    b.push(STATUS_END);
    b.push(0);
    b
}

/// Кадр от сервера: ID, статус и данные (если есть).
#[derive(Debug, PartialEq, Eq)]
pub struct InFrame {
    pub id: u16,
    pub status: u8,
    pub data: Option<Vec<u8>>,
}

/// Прочитать кадр. `Ok(None)` — поток закрыт.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<InFrame>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let meta_len = u16::from_be_bytes(len) as usize;
    if !(4..=MAX_META).contains(&meta_len) {
        return Err(Error::Protocol(format!(
            "Mux.Cool: длина метаданных {meta_len}"
        )));
    }
    let mut meta = [0u8; MAX_META];
    r.read_exact(&mut meta[..meta_len]).await?;
    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];
    let data = if option & OPTION_DATA != 0 {
        r.read_exact(&mut len).await?;
        let mut d = vec![0u8; u16::from_be_bytes(len) as usize];
        r.read_exact(&mut d).await?;
        Some(d)
    } else {
        None
    };
    Ok(Some(InFrame { id, status, data }))
}

/// Один VLESS-поток с Mux.Cool.
pub struct MuxConn {
    tx: mpsc::Sender<Vec<u8>>,
    sessions: Mutex<HashMap<u16, mpsc::Sender<Bytes>>>,
    next_id: AtomicU16,
    active: AtomicUsize,
    total: AtomicUsize,
    closed: AtomicBool,
    concurrency: usize,
    cancel: CancellationToken,
    /// Когда ушло последнее соединение.
    idle_since: Mutex<tokio::time::Instant>,
}

impl Drop for MuxConn {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl MuxConn {
    /// Запустить мультиплексор поверх готового VLESS-потока (команда Mux).
    pub fn start(stream: Box<dyn AsyncStream>, concurrency: usize) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let cancel = CancellationToken::new();
        let conn = Arc::new(MuxConn {
            tx,
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU16::new(1),
            active: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            concurrency: concurrency.max(1),
            cancel: cancel.clone(),
            idle_since: Mutex::new(tokio::time::Instant::now()),
        });
        let (mut r, mut w) = tokio::io::split(stream);
        // Писатель: кадры подряд, сброс — когда очередь опустела.
        let c1 = cancel.clone();
        tokio::spawn(async move {
            let work = async {
                while let Some(f) = rx.recv().await {
                    w.write_all(&f).await?;
                    while let Ok(f) = rx.try_recv() {
                        w.write_all(&f).await?;
                    }
                    w.flush().await?;
                }
                io::Result::Ok(())
            };
            tokio::select! {
                _ = c1.cancelled() => {}
                r = work => if let Err(e) = r {
                    tracing::debug!(error = %e, "Mux.Cool: запись оборвалась");
                    c1.cancel();
                },
            }
            let _ = w.shutdown().await;
        });
        // Читатель: данные — своим соединениям.
        let weak = Arc::downgrade(&conn);
        let c2 = cancel.clone();
        tokio::spawn(async move {
            let work = async {
                while let Some(f) = read_frame(&mut r).await? {
                    let Some(conn) = weak.upgrade() else { break };
                    let sender = conn.sessions.lock().unwrap().get(&f.id).cloned();
                    match f.status {
                        STATUS_KEEP | STATUS_NEW => {
                            if let (Some(s), Some(d)) = (sender, f.data) {
                                drop(conn);
                                // Медленный получатель держит весь поток —
                                // как у Xray (своего окна у Mux.Cool нет).
                                let _ = s.send(Bytes::from(d)).await;
                            }
                        }
                        STATUS_END => {
                            // Данные в End (бывают у Xray при ошибке) — тоже отдать.
                            if let (Some(s), Some(d)) = (&sender, f.data) {
                                let _ = s.send(Bytes::from(d)).await;
                            }
                            conn.sessions.lock().unwrap().remove(&f.id);
                        }
                        STATUS_KEEPALIVE => {}
                        other => {
                            return Err(Error::Protocol(format!(
                                "Mux.Cool: неизвестный статус {other}"
                            )))
                        }
                    }
                }
                Ok::<(), Error>(())
            };
            tokio::select! {
                _ = c2.cancelled() => {}
                r = work => {
                    if let Err(e) = r {
                        tracing::debug!(error = %e, "Mux.Cool: чтение оборвалось");
                    }
                    c2.cancel();
                }
            }
            if let Some(conn) = weak.upgrade() {
                conn.closed.store(true, Ordering::Relaxed);
                // Все соединения получат конец потока.
                conn.sessions.lock().unwrap().clear();
            }
        });
        // Закрыть поток без соединений.
        let weak = Arc::downgrade(&conn);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(IDLE / 2) => {}
                }
                let Some(c) = weak.upgrade() else { break };
                if c.active.load(Ordering::Relaxed) == 0
                    && c.idle_since.lock().unwrap().elapsed() >= IDLE
                {
                    c.closed.store(true, Ordering::Relaxed);
                    c.cancel.cancel();
                    tracing::debug!("Mux.Cool: поток без соединений закрыт");
                    break;
                }
            }
        });
        conn
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed) || self.cancel.is_cancelled()
    }

    /// Можно ли открыть в этом потоке ещё одно соединение.
    pub fn has_room(&self) -> bool {
        !self.is_closed()
            && self.active.load(Ordering::Relaxed) < self.concurrency
            && self.total.load(Ordering::Relaxed) < MAX_TOTAL
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Открыть соединение до `target:port`.
    pub async fn open(self: &Arc<Self>, target: &Address, port: u16) -> Result<MuxStream> {
        if self.is_closed() {
            return Err(Error::Protocol("Mux.Cool: поток закрыт".into()));
        }
        let n = self.total.fetch_add(1, Ordering::Relaxed);
        if n >= MAX_TOTAL {
            return Err(Error::Protocol("Mux.Cool: поток исчерпан".into()));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (dtx, drx) = mpsc::channel(QUEUE);
        self.sessions.lock().unwrap().insert(id, dtx);
        self.active.fetch_add(1, Ordering::Relaxed);
        let s = MuxStream {
            id,
            conn: self.clone(),
            rx: drx,
            pending: Bytes::new(),
            out: PollSender::new(self.tx.clone()),
            ended: false,
        };
        self.tx
            .send(frame_new(id, target, port))
            .await
            .map_err(|_| Error::Protocol("Mux.Cool: поток закрыт".into()))?;
        Ok(s)
    }
}

/// Соединение внутри Mux.Cool.
pub struct MuxStream {
    id: u16,
    conn: Arc<MuxConn>,
    rx: mpsc::Receiver<Bytes>,
    pending: Bytes,
    out: PollSender<Vec<u8>>,
    /// End отправлен.
    ended: bool,
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let c = &self.conn;
        c.sessions.lock().unwrap().remove(&self.id);
        if !self.ended && !c.is_closed() {
            let f = frame_end(self.id);
            if let Err(mpsc::error::TrySendError::Full(f)) = c.tx.try_send(f) {
                let tx = c.tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(f).await;
                });
            }
        }
        if c.active.fetch_sub(1, Ordering::Relaxed) == 1 {
            *c.idle_since.lock().unwrap() = tokio::time::Instant::now();
        }
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Mux.Cool: поток закрыт")
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                let part = self.pending.split_to(n);
                buf.put_slice(&part);
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(b)) => self.pending = b,
                // Конец соединения (End от сервера или поток закрыт).
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.ended {
            return Poll::Ready(Err(closed()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.out.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Err(closed())),
            Poll::Pending => return Poll::Pending,
        }
        let n = buf.len().min(MAX_CHUNK);
        let f = frame_keep(self.id, &buf[..n]);
        if self.out.send_item(f).is_err() {
            return Poll::Ready(Err(closed()));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Писатель сбрасывает поток сам, как только очередь пуста.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.ended {
            return Poll::Ready(Ok(()));
        }
        match self.out.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Ok(())),
            Poll::Pending => return Poll::Pending,
        }
        let f = frame_end(self.id);
        let _ = self.out.send_item(f);
        self.ended = true;
        Poll::Ready(Ok(()))
    }
}

/// Пул потоков Mux.Cool одного выхода: новое соединение идёт в поток, где
/// есть место, иначе открывается новый поток.
pub struct MuxPool {
    concurrency: usize,
    conns: Mutex<Vec<Weak<MuxConn>>>,
    /// Держит поток живым, пока в нём нет соединений (закроет таймер).
    keep: Mutex<Vec<Arc<MuxConn>>>,
}

impl MuxPool {
    pub fn new(concurrency: usize) -> Self {
        MuxPool {
            concurrency: concurrency.max(1),
            conns: Mutex::new(Vec::new()),
            keep: Mutex::new(Vec::new()),
        }
    }

    /// Поток с местом или `None`.
    pub fn pick(&self) -> Option<Arc<MuxConn>> {
        let mut keep = self.keep.lock().unwrap();
        keep.retain(|c| !c.is_closed());
        let mut conns = self.conns.lock().unwrap();
        conns.retain(|w| w.upgrade().is_some_and(|c| !c.is_closed()));
        conns
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|c| c.has_room())
            .min_by_key(|c| c.active())
    }

    /// Запустить новый поток поверх готового VLESS-потока.
    pub fn add(&self, stream: Box<dyn AsyncStream>) -> Arc<MuxConn> {
        let c = MuxConn::start(stream, self.concurrency);
        self.conns.lock().unwrap().push(Arc::downgrade(&c));
        self.keep.lock().unwrap().push(c.clone());
        c
    }

    /// Сколько живых потоков (для тестов и журнала).
    pub fn len(&self) -> usize {
        self.pick();
        self.keep.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_match_xray_layout() {
        let f = frame_new(1, &Address::Domain("a.io".into()), 443);
        // meta: id(2) New opt TCP port(2) atyp len "a.io" = 13
        assert_eq!(
            f,
            [0, 13, 0, 1, 1, 0, 1, 1, 187, 2, 4, b'a', b'.', b'i', b'o']
        );
        let f = frame_new(2, &Address::Ipv4("10.0.0.1".parse().unwrap()), 80);
        assert_eq!(f, [0, 12, 0, 2, 1, 0, 1, 0, 80, 1, 10, 0, 0, 1]);
        assert_eq!(frame_keep(3, b"hi"), [0, 4, 0, 3, 2, 1, 0, 2, b'h', b'i']);
        assert_eq!(frame_end(3), [0, 4, 0, 3, 3, 0]);
    }

    #[tokio::test]
    async fn reads_frames_and_rejects_garbage() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&frame_keep(5, b"data"));
        wire.extend_from_slice(&[0, 4, 0, 0, 4, 1, 0, 1, b'k']); // KeepAlive с данными
        wire.extend_from_slice(&frame_end(5));
        let mut r = &wire[..];
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(
            (f.id, f.status, f.data.as_deref()),
            (5, STATUS_KEEP, Some(&b"data"[..]))
        );
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(f.status, STATUS_KEEPALIVE);
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!((f.status, f.data), (STATUS_END, None));
        assert!(read_frame(&mut r).await.unwrap().is_none());
        let mut bad = &[0xff, 0xff, 0, 0][..];
        assert!(read_frame(&mut bad).await.is_err());
    }

    /// Мини-сервер Mux.Cool: эхо для каждой сессии.
    async fn echo_server(s: tokio::io::DuplexStream) {
        let (mut r, w) = tokio::io::split(s);
        let w = Arc::new(tokio::sync::Mutex::new(w));
        while let Ok(Some(f)) = read_frame(&mut r).await {
            let mut w = w.lock().await;
            match f.status {
                STATUS_KEEP => {
                    let d = f.data.unwrap();
                    w.write_all(&frame_keep(f.id, &d)).await.unwrap();
                }
                STATUS_END => {
                    w.write_all(&frame_end(f.id)).await.unwrap();
                }
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn many_sessions_share_one_stream() {
        let (a, b) = tokio::io::duplex(1 << 20);
        tokio::spawn(echo_server(b));
        let pool = MuxPool::new(8);
        let conn = pool.add(Box::new(a));
        let mut tasks = Vec::new();
        for i in 0..8u8 {
            let s = conn
                .open(&Address::Domain("x.test".into()), 80)
                .await
                .unwrap();
            tasks.push(tokio::spawn(async move {
                let mut s = s;
                let data = vec![i; 50_000];
                let (mut r, mut w) = tokio::io::split(&mut s);
                let write = async {
                    w.write_all(&data).await.unwrap();
                };
                let mut got = vec![0u8; data.len()];
                let read = async {
                    r.read_exact(&mut got).await.unwrap();
                };
                tokio::join!(write, read);
                assert_eq!(got, data);
                s.shutdown().await.unwrap();
                let mut rest = Vec::new();
                s.read_to_end(&mut rest).await.unwrap();
                assert!(rest.is_empty());
            }));
        }
        assert!(!conn.has_room(), "8 из 8 заняты");
        assert!(pool.pick().is_none());
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(conn.active(), 0);
        assert!(pool.pick().is_some(), "место освободилось");
        assert_eq!(pool.len(), 1);
    }
}
