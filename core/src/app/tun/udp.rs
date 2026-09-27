// SPDX-License-Identifier: GPL-3.0-or-later
//! UDP входа TUN: датаграммы общего UDP-сокета стека раскладываются по
//! потокам — по одному на пару (приложение, назначение), как
//! соединения TCP. Поток читается и пишется по одной датаграмме
//! (`AsyncRead`/`AsyncWrite`), ответы уходят приложению «от» адреса,
//! куда оно отправляло (в том числе от fake-IP), и закрывается сам,
//! если в обе стороны ничего не шло [`UDP_IDLE`](super::super::outbound::UDP_IDLE).

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::udp::{ReadHalf, UdpMsg, WriteHalf};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};
use tokio_util::sync::PollSender;

/// Очередь датаграмм одного потока: дальше — отбрасываются (UDP).
const FLOW_QUEUE: usize = 256;
/// Очередь ответов всех потоков к стеку.
const REPLY_QUEUE: usize = 4096;
/// Раз во столько новых потоков из таблицы убираются закрытые.
const SWEEP_EVERY: usize = 256;

/// Поток датаграмм одной пары адресов.
pub struct UdpFlow {
    local: SocketAddr,
    peer: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    tx: PollSender<UdpMsg>,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    _permit: OwnedSemaphorePermit,
}

impl UdpFlow {
    /// Адрес приложения.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Куда приложение отправляет.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn touch(&mut self) {
        let at = Instant::now() + self.idle;
        self.deadline.as_mut().reset(at);
    }
}

impl AsyncRead for UdpFlow {
    /// Одна датаграмма за чтение (не длиннее буфера); 0 байт — поток
    /// простаивал или стек закрылся.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(d)) => {
                self.touch();
                let n = d.len().min(buf.remaining());
                buf.put_slice(&d[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => match self.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for UdpFlow {
    /// Одна запись — одна датаграмма приложению.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let closed = || std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Err(closed())),
            Poll::Pending => return Poll::Pending,
        }
        let msg = (buf.to_vec(), self.peer, self.local);
        self.tx.send_item(msg).map_err(|_| closed())?;
        self.touch();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Раскладывает датаграммы стека по потокам: новый поток — в `accept`.
/// Пока предел соединений (`slots`) исчерпан, датаграммы новых пар
/// отбрасываются. Завершается, когда закрылся стек или приёмник потоков.
pub async fn dispatch(
    read: ReadHalf,
    write: WriteHalf,
    slots: Arc<Semaphore>,
    idle: Duration,
    accept: mpsc::Sender<UdpFlow>,
) {
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpMsg>(REPLY_QUEUE);
    let writer = tokio::spawn(async move {
        let mut write = write;
        while let Some(m) = reply_rx.recv().await {
            if write.send(m).await.is_err() {
                return;
            }
        }
    });

    let mut flows: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut created = 0usize;
    let mut read = read;
    while let Some((data, src, dst)) = read.next().await {
        let key = (src, dst);
        if let Some(tx) = flows.get(&key) {
            match tx.try_send(data) {
                Ok(()) => continue,
                // Поток не успевает — датаграмма теряется, как в сети.
                Err(mpsc::error::TrySendError::Full(_)) => continue,
                Err(mpsc::error::TrySendError::Closed(d)) => {
                    flows.remove(&key);
                    if !open(&mut flows, key, d, &slots, idle, &reply_tx, &accept) {
                        break;
                    }
                }
            }
        } else if !open(&mut flows, key, data, &slots, idle, &reply_tx, &accept) {
            break;
        }
        created += 1;
        if created.is_multiple_of(SWEEP_EVERY) {
            flows.retain(|_, tx| !tx.is_closed());
        }
    }
    drop(reply_tx);
    let _ = writer.await;
}

/// Открыть поток для пары и отдать ему первую датаграмму. `false` —
/// приёмника потоков больше нет.
fn open(
    flows: &mut HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>,
    (local, peer): (SocketAddr, SocketAddr),
    first: Vec<u8>,
    slots: &Arc<Semaphore>,
    idle: Duration,
    reply: &mpsc::Sender<UdpMsg>,
    accept: &mpsc::Sender<UdpFlow>,
) -> bool {
    let Ok(permit) = slots.clone().try_acquire_owned() else {
        tracing::debug!("tun: предел соединений — UDP-датаграмма отброшена");
        return true;
    };
    let (tx, rx) = mpsc::channel(FLOW_QUEUE);
    let _ = tx.try_send(first);
    let flow = UdpFlow {
        local,
        peer,
        rx,
        tx: PollSender::new(reply.clone()),
        idle,
        deadline: Box::pin(tokio::time::sleep(idle)),
        _permit: permit,
    };
    match accept.try_send(flow) {
        Ok(()) => {
            flows.insert((local, peer), tx);
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}
