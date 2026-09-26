//! Вход `dns`: DNS-сервер (UDP и TCP на одном адресе) для системы и
//! программ. Отвечает DNS-модуль (`super::dns`) — со своими правилами,
//! кешем и fake-IP.
//!
//! Открытый в сеть DNS-сервер без списка разрешённых адресов — это
//! «открытый резолвер», которым пользуются для DDoS-атак с подменой
//! адреса; поэтому в сеть — только с `allow_ip`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::access::{self, IpNet};
use super::dns::{answer_bytes, Dns};
use crate::error::Result;

/// Сколько запросов обрабатывать одновременно (UDP и TCP вместе).
const CONCURRENCY: usize = 256;
/// Сколько держать молчащее TCP-соединение.
const TCP_IDLE: Duration = Duration::from_secs(30);
/// Ответ по UDP без EDNS — не больше 512 байт (RFC 1035).
const UDP_PLAIN_MAX: usize = 512;

pub struct DnsInbound {
    pub tag: Arc<str>,
    pub allow_ip: Vec<IpNet>,
    pub dns: Arc<Dns>,
    pub max_conns: usize,
}

/// Ответ, урезанный до размера, который клиент примет по UDP: иначе —
/// флаг TC, и клиент повторит запрос по TCP.
fn fit_udp(query: &[u8], answer: Vec<u8>) -> Vec<u8> {
    let limit = Message::from_vec(query)
        .ok()
        .and_then(|q| q.edns.map(|e| e.max_payload() as usize))
        .unwrap_or(UDP_PLAIN_MAX)
        .clamp(UDP_PLAIN_MAX, 65535);
    if answer.len() <= limit {
        return answer;
    }
    match Message::from_vec(&answer)
        .ok()
        .and_then(|m| m.truncate().to_vec().ok())
    {
        Some(t) => t,
        None => answer,
    }
}

impl DnsInbound {
    pub async fn serve_udp(self: Arc<Self>, socket: UdpSocket) -> Result<()> {
        let socket = Arc::new(socket);
        let slots = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                // ICMP «порт недоступен» от прошлых ответов и т.п.
                Err(e) => {
                    tracing::debug!(error = %e, "DNS: recv_from");
                    continue;
                }
            };
            if !access::allowed(&self.allow_ip, from.ip()) {
                continue;
            }
            // Переполнено — запрос теряется (клиент повторит).
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let q = buf[..n].to_vec();
            let (this, socket) = (self.clone(), socket.clone());
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(a) = answer_bytes(&this.dns, &q, true).await {
                    let _ = socket.send_to(&fit_udp(&q, a), from).await;
                }
            });
        }
    }

    pub async fn serve_tcp(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        let slots = Arc::new(tokio::sync::Semaphore::new(self.max_conns.max(1)));
        loop {
            let (s, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "DNS: accept не удался");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            if !access::allowed(&self.allow_ip, peer.ip()) {
                continue;
            }
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let this = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                this.tcp_conn(s, peer).await;
            });
        }
    }

    async fn tcp_conn(&self, mut s: TcpStream, peer: SocketAddr) {
        loop {
            let mut len = [0u8; 2];
            match tokio::time::timeout(TCP_IDLE, s.read_exact(&mut len)).await {
                Ok(Ok(_)) => {}
                _ => return,
            }
            let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
            if tokio::time::timeout(TCP_IDLE, s.read_exact(&mut q))
                .await
                .map_or(true, |r| r.is_err())
            {
                return;
            }
            let Some(a) = answer_bytes(&self.dns, &q, true).await else {
                tracing::debug!(%peer, "DNS/TCP: не запрос — соединение закрыто");
                return;
            };
            let mut out = (a.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&a);
            if s.write_all(&out).await.is_err() {
                return;
            }
        }
    }
}
