// SPDX-License-Identifier: GPL-3.0-or-later
//! QUIC-клиент на quinn — для DNS over QUIC и xhttp через HTTP/3.
//!
//! TLS внутри QUIC — та же rustls с провайдером aws-lc-rs, только
//! TLS 1.3 (другого QUIC не знает). Сокет — либо настоящий UDP-сокет с
//! меткой `net_protect` (мимо TUN), либо UDP-сессия выхода
//! ([`SessionSocket`]): тогда QUIC-пакеты идут, например, через VLESS
//! (XUDP), и провайдер видит только соединение с VLESS-сервером.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rustls::RootCertStore;
use tokio::sync::mpsc;

use crate::app::outbound::UdpSession;
use crate::error::{Error, Result};
use crate::hysteria2_obfs::{salamander_unwrap, salamander_wrap};
use crate::vless::Address;

/// Настройки клиента QUIC: проверка сертификата по `roots` (или по
/// встроенному набору), ALPN, keep-alive.
pub fn client_config(
    roots: Option<RootCertStore>,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ClientConfig> {
    super::tcp_tls::ensure_crypto_provider();
    let roots = roots.unwrap_or_else(|| {
        let mut r = RootCertStore::empty();
        r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        r
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| Error::Protocol(format!("QUIC: TLS: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = alpn;
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|e| Error::Protocol(format!("QUIC: TLS: {e}")))?;
    let mut cc = quinn::ClientConfig::new(Arc::new(qc));
    let mut tr = quinn::TransportConfig::default();
    tr.keep_alive_interval(Some(Duration::from_secs(15)));
    #[allow(
        clippy::expect_used,
        reason = "константа: 30 с — допустимый таймаут QUIC"
    )]
    let idle = quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("30 с — допустимо");
    tr.max_idle_timeout(Some(idle));
    cc.transport_config(Arc::new(tr));
    Ok(cc)
}

/// Точка QUIC на настоящем UDP-сокете (с меткой `net_protect`).
pub fn direct_endpoint(ipv6: bool) -> Result<quinn::Endpoint> {
    let bind = if ipv6 {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
    };
    let sock = crate::net_protect::udp_bind(bind)?.into_std()?;
    let copy = sock.try_clone()?;
    match quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        sock,
        Arc::new(quinn::TokioRuntime),
    ) {
        Ok(ep) => Ok(ep),
        // quinn-udp ставит сокету параметры (ECN, GSO, «не дробить»),
        // которых где-то нет (Wine, старые системы): тогда — обычный сокет.
        Err(e) => {
            tracing::debug!(error = %e, "QUIC: сокет quinn-udp не создан — простой UDP-сокет");
            plain_endpoint(tokio::net::UdpSocket::from_std(copy)?, None)
        }
    }
}

/// Точка QUIC на обычном UDP-сокете tokio (без ECN и GSO); `server` —
/// принимать соединения.
pub fn plain_endpoint(
    sock: tokio::net::UdpSocket,
    server: Option<quinn::ServerConfig>,
) -> Result<quinn::Endpoint> {
    Ok(quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server,
        Arc::new(PlainSocket(sock)),
        Arc::new(quinn::TokioRuntime),
    )?)
}

/// Обычный UDP-сокет для quinn: по датаграмме за вызов.
#[derive(Debug)]
pub struct PlainSocket(tokio::net::UdpSocket);

#[derive(Debug)]
struct PlainPoller(Arc<PlainSocket>);

impl UdpPoller for PlainPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0 .0.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for PlainSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PlainPoller(self))
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        match t.segment_size {
            Some(seg) if seg < t.contents.len() => {
                for chunk in t.contents.chunks(seg) {
                    self.0.try_send_to(chunk, t.destination)?;
                }
                Ok(())
            }
            _ => self.0.try_send_to(t.contents, t.destination).map(|_| ()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rb = tokio::io::ReadBuf::new(&mut bufs[0]);
        let addr = std::task::ready!(self.0.poll_recv_from(cx, &mut rb))?;
        let n = rb.filled().len();
        meta[0] = RecvMeta {
            addr,
            len: n,
            stride: n,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

/// QUIC socket wrapper that applies the Hysteria 2 Salamander packet format.
pub(crate) struct SalamanderSocket {
    inner: Arc<PlainSocket>,
    key: Arc<[u8]>,
}

impl fmt::Debug for SalamanderSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderSocket")
            .field("inner", &self.inner)
            .field("key", &crate::redact::Redacted)
            .finish()
    }
}

impl SalamanderSocket {
    fn new(sock: tokio::net::UdpSocket, key: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(PlainSocket(sock)),
            key: Arc::from(key),
        })
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let send_one = |payload: &[u8]| {
            let frame = salamander_wrap(&self.key, payload);
            self.inner.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &frame,
                segment_size: None,
                src_ip: transmit.src_ip,
            })
        };
        match transmit.segment_size {
            Some(segment_size) if segment_size < transmit.contents.len() => {
                if segment_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "QUIC provided a zero-sized UDP segment",
                    ));
                }
                for packet in transmit.contents.chunks(segment_size) {
                    send_one(packet)?;
                }
                Ok(())
            }
            _ => send_one(transmit.contents),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let received = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
            if received == 0 {
                return Poll::Ready(Ok(0));
            }
            let meta = meta.first_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC did not provide receive metadata",
                )
            })?;
            let packet = bufs.first_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC did not provide a receive buffer",
                )
            })?;
            let packet = packet.get_mut(..meta.len).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP datagram length exceeds its receive buffer",
                )
            })?;
            match salamander_unwrap(&self.key, packet) {
                Ok(len) => {
                    meta.len = len;
                    meta.stride = len;
                    return Poll::Ready(Ok(1));
                }
                // Salamander has no authentication tag. QUIC rejects packets
                // produced with the wrong key; malformed short frames are dropped.
                Err(_) => continue,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }
}

/// QUIC endpoint that wraps each UDP packet in Hysteria 2 Salamander framing.
pub(crate) fn salamander_endpoint(ipv6: bool, key: &[u8]) -> Result<quinn::Endpoint> {
    let bind = if ipv6 {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    let sock = crate::net_protect::udp_bind(bind)?.into_std()?;
    sock.set_nonblocking(true)?;
    let sock = tokio::net::UdpSocket::from_std(sock)?;
    let socket = SalamanderSocket::new(sock, key);
    Ok(quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?)
}

/// Точка QUIC поверх UDP-сессии выхода. Все пакеты уходят на
/// `target:port`; для quinn удалённый адрес — возвращаемая метка.
pub fn session_endpoint(
    session: Arc<dyn UdpSession>,
    target: Address,
    port: u16,
) -> Result<(quinn::Endpoint, SocketAddr)> {
    let peer = match &target {
        Address::Ipv4(v4) => SocketAddr::from((*v4, port)),
        // Имя или IPv6: метка — любой IPv4 (quinn нужен SocketAddr, а
        // пакеты всё равно уходят на `target`).
        _ => SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), port)),
    };
    let sock = SessionSocket::new(session, target, port, peer);
    let ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    Ok((ep, peer))
}

/// Очередь к выходу: больше пакетов не копим (UDP может терять).
const QUEUE: usize = 256;

/// UDP-сокет для quinn поверх [`UdpSession`].
pub struct SessionSocket {
    out: mpsc::Sender<Vec<u8>>,
    inbox: Mutex<mpsc::Receiver<Vec<u8>>>,
    peer: SocketAddr,
    tasks: [tokio::task::AbortHandle; 2],
}

impl fmt::Debug for SessionSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSocket")
            .field("peer", &self.peer)
            .finish()
    }
}

impl SessionSocket {
    pub fn new(
        session: Arc<dyn UdpSession>,
        target: Address,
        port: u16,
        peer: SocketAddr,
    ) -> Arc<Self> {
        let (out, mut out_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (in_tx, inbox) = mpsc::channel::<Vec<u8>>(QUEUE);
        let s = session.clone();
        let writer = tokio::spawn(async move {
            while let Some(d) = out_rx.recv().await {
                if s.send(target.clone(), port, d).await.is_err() {
                    break;
                }
            }
        });
        let reader = tokio::spawn(async move {
            while let Ok(Some((_, _, data))) = session.recv().await {
                // Переполнение — потеря пакета, как в сети.
                match in_tx.try_send(data) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        });
        Arc::new(SessionSocket {
            out,
            inbox: Mutex::new(inbox),
            peer,
            tasks: [writer.abort_handle(), reader.abort_handle()],
        })
    }
}

impl Drop for SessionSocket {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for SessionSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        match self.out.try_send(t.contents.to_vec()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP-сессия выхода закрыта",
            )),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut inbox = self
            .inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match inbox.poll_recv(cx) {
            Poll::Ready(Some(d)) => {
                let n = d.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&d[..n]);
                meta[0] = RecvMeta {
                    addr: self.peer,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "UDP-сессия выхода закрыта",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    }
}

/// Понятная ошибка соединения QUIC.
pub fn connect_error(what: &str, e: impl fmt::Display) -> Error {
    Error::Protocol(format!("{what}: QUIC: {e}"))
}
