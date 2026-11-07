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
use crate::hysteria2::PortRange;
use crate::hysteria2_obfs::{salamander_unwrap, salamander_wrap};
use crate::vless::Address;

/// Настройки клиента QUIC: проверка сертификата по `roots` (или по
/// встроенному набору), ALPN, keep-alive.
pub fn client_config(
    roots: Option<RootCertStore>,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ClientConfig> {
    client_config_inner(roots, alpn, None)
}

/// Build a QUIC client config for Hysteria 2 with Quinn's BBR controller.
///
/// Hysteria uses BBR by default when no per-direction Brutal bandwidth is
/// configured. Keep the default for the repository's other QUIC users intact.
pub(crate) fn hysteria2_client_config(
    roots: Option<RootCertStore>,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ClientConfig> {
    client_config_inner(
        roots,
        alpn,
        Some(Arc::new(quinn::congestion::BbrConfig::default())),
    )
}

fn client_config_inner(
    roots: Option<RootCertStore>,
    alpn: Vec<Vec<u8>>,
    controller: Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>>,
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
    if let Some(controller) = controller {
        tr.congestion_controller_factory(controller);
    }
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::RootCertStore;

    use super::{
        client_config, hysteria2_client_config, random_hysteria2_port, PortHopSocket, PortHopState,
        RecvMeta,
    };
    use crate::hysteria2::PortRange;

    #[tokio::test]
    async fn hysteria2_uses_bbr_and_other_quic_clients_keep_cubic() {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertificateParams::new(vec!["quic-test.local".into()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let certificate = CertificateDer::from(cert.der().to_vec());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let hysteria_config =
            hysteria2_client_config(Some(roots.clone()), vec![b"h3".to_vec()]).unwrap();
        let regular_config = client_config(Some(roots), vec![b"h3".to_vec()]).unwrap();
        let server_addr = server.local_addr().unwrap();

        async fn connect(
            server: &quinn::Endpoint,
            server_addr: std::net::SocketAddr,
            config: quinn::ClientConfig,
        ) -> quinn::Connection {
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(config);
            let connecting = endpoint.connect(server_addr, "quic-test.local").unwrap();
            let accepting = async { server.accept().await.unwrap().await.unwrap() };
            let (client, _server) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(connecting, accepting)
            })
            .await
            .unwrap();
            client.unwrap()
        }

        let hysteria_connection = connect(&server, server_addr, hysteria_config).await;
        assert!(
            hysteria_connection
                .congestion_state()
                .into_any()
                .is::<quinn::congestion::Bbr>(),
            "Hysteria 2 must select Quinn BBR"
        );
        hysteria_connection.close(0u32.into(), b"test complete");

        let regular_connection = connect(&server, server_addr, regular_config).await;
        assert!(
            regular_connection
                .congestion_state()
                .into_any()
                .is::<quinn::congestion::Cubic>(),
            "existing QUIC users must keep Quinn's default Cubic controller"
        );
        regular_connection.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
    }

    #[test]
    fn initial_hysteria2_port_is_chosen_from_configured_ranges() {
        let ports = [
            PortRange {
                first: 443,
                last: 445,
            },
            PortRange {
                first: 8443,
                last: 8443,
            },
        ];
        for _ in 0..100 {
            let port = random_hysteria2_port(&ports).unwrap();
            assert!(ports
                .iter()
                .any(|range| (range.first..=range.last).contains(&port)));
        }
        assert!(random_hysteria2_port(&[]).is_err());
    }

    #[test]
    fn port_hop_never_repeats_the_current_port_when_alternatives_exist() {
        let ports = [
            PortRange {
                first: 443,
                last: 445,
            },
            PortRange {
                first: 8443,
                last: 8443,
            },
        ];
        for current in [443, 444, 445, 8443] {
            for _ in 0..100 {
                let next = PortHopState::next_port(&ports, current);
                assert_ne!(next, current);
                assert!(ports
                    .iter()
                    .any(|range| (range.first..=range.last).contains(&next)));
            }
        }
        let overlapping = [
            PortRange {
                first: 443,
                last: 444,
            },
            PortRange {
                first: 444,
                last: 445,
            },
        ];
        for _ in 0..100 {
            assert_ne!(PortHopState::next_port(&overlapping, 444), 444);
        }
    }

    #[tokio::test]
    async fn hop_uses_a_fresh_socket_and_receives_from_the_previous_socket() {
        use std::io::IoSliceMut;
        use std::task::Poll;

        use quinn::AsyncUdpSocket;

        let state = PortHopState::new(
            vec![PortRange {
                first: 443,
                last: 444,
            }],
            443,
            false,
        )
        .unwrap();
        let old_local_addr = state
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .local_addr()
            .unwrap();
        let old_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, old_local_addr.port()));

        state.rotate(false).unwrap();
        let new_addr = state
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .local_addr()
            .unwrap();
        assert_ne!(old_addr.port(), new_addr.port());

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"late packet", old_addr).await.unwrap();

        let socket = PortHopSocket { state };
        let mut buffer = [0u8; 64];
        let (received, packet_len) = {
            let mut bufs = [IoSliceMut::new(&mut buffer)];
            let mut meta = [RecvMeta {
                addr: "127.0.0.1:0".parse().unwrap(),
                len: 0,
                stride: 0,
                ecn: None,
                dst_ip: None,
            }];
            let received = tokio::time::timeout(Duration::from_secs(2), async {
                std::future::poll_fn(|cx| match socket.poll_recv(cx, &mut bufs, &mut meta) {
                    Poll::Ready(result) => Poll::Ready(result),
                    Poll::Pending => Poll::Pending,
                })
                .await
            })
            .await
            .unwrap()
            .unwrap();
            (received, meta[0].len)
        };
        assert_eq!(received, 1);
        assert_eq!(&buffer[..packet_len], b"late packet");
    }

    #[tokio::test]
    async fn hop_sends_to_the_new_remote_port() {
        use quinn::udp::Transmit;
        use quinn::AsyncUdpSocket;

        let (first, second) = (20_000..60_000)
            .find_map(|port| {
                let first = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).ok()?;
                let second = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port + 1)).ok()?;
                Some((first, second))
            })
            .expect("two consecutive localhost UDP ports should be available");
        first.set_nonblocking(true).unwrap();
        second.set_nonblocking(true).unwrap();
        let first = tokio::net::UdpSocket::from_std(first).unwrap();
        let second = tokio::net::UdpSocket::from_std(second).unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();
        let ports = vec![PortRange {
            first: first_addr.port(),
            last: second_addr.port(),
        }];
        let state = PortHopState::new(ports, first_addr.port(), false).unwrap();
        let socket = Arc::new(PortHopSocket {
            state: Arc::clone(&state),
        });
        let mut poller = Arc::clone(&socket).create_io_poller();

        tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)),
        )
        .await
        .unwrap()
        .unwrap();

        socket
            .try_send(&Transmit {
                destination: first_addr,
                ecn: None,
                contents: b"before hop",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let mut buffer = [0u8; 32];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), first.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], b"before hop");

        let selected = state.rotate(false).unwrap();
        assert_eq!(selected, second_addr.port());
        tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)),
        )
        .await
        .unwrap()
        .unwrap();
        socket
            .try_send(&Transmit {
                destination: first_addr,
                ecn: None,
                contents: b"after hop",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), second.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], b"after hop");
    }

    #[tokio::test]
    async fn port_hop_state_can_bind_ipv6_sockets() {
        let state = PortHopState::new(
            vec![PortRange {
                first: 443,
                last: 444,
            }],
            443,
            true,
        )
        .unwrap();
        let first_addr = state
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .0
            .local_addr()
            .unwrap();
        assert!(first_addr.is_ipv6());

        state.rotate(true).unwrap();
        let second_addr = state
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .0
            .local_addr()
            .unwrap();
        assert!(second_addr.is_ipv6());
        assert_ne!(first_addr.port(), second_addr.port());
    }
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

/// Hysteria keeps the previous local UDP socket open briefly while moving the
/// QUIC connection to a fresh source port. This lets in-flight packets arrive
/// during a hop instead of only changing the server destination port.
#[derive(Debug)]
struct HopSocketState {
    ports: Vec<PortRange>,
    active: Arc<PlainSocket>,
    active_port: u16,
    previous: Vec<(Arc<PlainSocket>, tokio::time::Instant)>,
}

#[derive(Debug)]
pub(crate) struct PortHopState {
    state: Mutex<HopSocketState>,
}

const PORT_HOP_SOCKET_GRACE: Duration = Duration::from_secs(2);

pub(crate) fn random_hysteria2_port(ports: &[PortRange]) -> Result<u16> {
    let total: u64 = ports
        .iter()
        .map(|range| u64::from(range.last) - u64::from(range.first) + 1)
        .sum();
    if total == 0 {
        return Err(Error::Config("Hysteria 2: список портов пуст".into()));
    }
    let mut index = rand::random::<u64>() % total;
    for range in ports {
        let width = u64::from(range.last) - u64::from(range.first) + 1;
        if index < width {
            return Ok(range.first + index as u16);
        }
        index -= width;
    }
    Err(Error::Config("Hysteria 2: не удалось выбрать порт".into()))
}

impl PortHopState {
    fn bind_socket(ipv6: bool) -> Result<Arc<PlainSocket>> {
        let bind = if ipv6 {
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        };
        let sock = crate::net_protect::udp_bind(bind)?.into_std()?;
        sock.set_nonblocking(true)?;
        Ok(Arc::new(PlainSocket(tokio::net::UdpSocket::from_std(
            sock,
        )?)))
    }

    fn new(ports: Vec<PortRange>, initial_port: u16, ipv6: bool) -> Result<Arc<Self>> {
        if ports.is_empty()
            || !ports
                .iter()
                .any(|range| (range.first..=range.last).contains(&initial_port))
        {
            return Err(Error::Config(
                "Hysteria 2: начальный порт отсутствует в списке port hopping".into(),
            ));
        }
        Ok(Arc::new(Self {
            state: Mutex::new(HopSocketState {
                ports,
                active: Self::bind_socket(ipv6)?,
                active_port: initial_port,
                previous: Vec::new(),
            }),
        }))
    }

    fn next_port(ports: &[PortRange], current: u16) -> u16 {
        let total: u64 = ports
            .iter()
            .map(|range| u64::from(range.last) - u64::from(range.first) + 1)
            .sum();
        if total <= 1 {
            return current;
        }
        let current_occurrences: u64 = ports
            .iter()
            .filter(|range| (range.first..=range.last).contains(&current))
            .count() as u64;
        let alternatives = total - current_occurrences;
        if alternatives == 0 {
            return current;
        }
        let mut index = rand::random::<u64>() % alternatives;
        for range in ports {
            let lower = u64::from(range.last) - u64::from(range.first) + 1;
            if (range.first..=range.last).contains(&current) {
                let before_current = u64::from(current - range.first);
                if index < before_current {
                    return range.first + index as u16;
                }
                index -= before_current;
                let after_current = u64::from(range.last - current);
                if index < after_current {
                    return current + 1 + index as u16;
                }
                index -= after_current;
            } else if index < lower {
                return range.first + index as u16;
            } else {
                index -= lower;
            }
        }
        current
    }

    fn rotate(&self, ipv6: bool) -> Result<u16> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .previous
            .retain(|(_, deadline)| *deadline > tokio::time::Instant::now());
        if state
            .ports
            .iter()
            .map(|range| u32::from(range.last) - u32::from(range.first) + 1)
            .sum::<u32>()
            <= 1
        {
            return Ok(state.active_port);
        }
        let next = Self::next_port(&state.ports, state.active_port);
        let socket = Self::bind_socket(ipv6)?;
        let old = std::mem::replace(&mut state.active, socket);
        state
            .previous
            .push((old, tokio::time::Instant::now() + PORT_HOP_SOCKET_GRACE));
        state.active_port = next;
        Ok(next)
    }

    pub(crate) fn start(
        self: &Arc<Self>,
        interval: Duration,
        ipv6: bool,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let ports_len: u64 = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ports
            .iter()
            .map(|range| u64::from(range.last) - u64::from(range.first) + 1)
            .sum();
        if ports_len <= 1 {
            return None;
        }
        let state = Arc::clone(self);
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match state.rotate(ipv6) {
                    Ok(port) => tracing::debug!(port, "Hysteria 2 UDP source socket rotated"),
                    Err(error) => tracing::warn!(%error, "Hysteria 2 UDP socket rotation failed"),
                }
            }
        }))
    }
}

#[derive(Debug)]
struct PortHopSocket {
    state: Arc<PortHopState>,
}

impl AsyncUdpSocket for PortHopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PortHopPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let state = self
            .state
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let socket = &state.active.0;
        let mut destination = transmit.destination;
        destination.set_port(state.active_port);
        let send_one = |contents: &[u8]| socket.try_send_to(contents, destination).map(|_| ());
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
        let mut sockets = {
            let mut state = self
                .state
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state
                .previous
                .retain(|(_, deadline)| *deadline > tokio::time::Instant::now());
            let mut sockets = vec![Arc::clone(&state.active)];
            sockets.extend(state.previous.iter().map(|(socket, _)| Arc::clone(socket)));
            sockets
        };
        let buffer = bufs.first_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC receive buffer is missing",
            )
        });
        let buffer = match buffer {
            Ok(buffer) => buffer,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let metadata = meta.first_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC receive metadata is missing",
            )
        });
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) => return Poll::Ready(Err(error)),
        };
        for socket in sockets.drain(..) {
            let mut read_buf = tokio::io::ReadBuf::new(buffer);
            match socket.0.poll_recv_from(cx, &mut read_buf) {
                Poll::Ready(Ok(addr)) => {
                    let len = read_buf.filled().len();
                    *metadata = RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .local_addr()
    }
}

#[derive(Debug)]
struct PortHopPoller {
    socket: Arc<PortHopSocket>,
}

impl UdpPoller for PortHopPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let state = self
            .socket
            .state
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active.0.poll_send_ready(cx)
    }
}

/// Create a Hysteria endpoint using a random initial remote port and a fresh
/// local UDP socket per hop; optional Salamander framing wraps each datagram.
pub(crate) fn hysteria2_endpoint(
    ipv6: bool,
    ports: Vec<PortRange>,
    initial_port: u16,
    salamander_key: Option<&[u8]>,
) -> Result<(quinn::Endpoint, Option<Arc<PortHopState>>)> {
    if !ports
        .iter()
        .any(|range| range.first != initial_port || range.last != initial_port)
    {
        let endpoint = match salamander_key {
            Some(key) => salamander_endpoint(ipv6, key)?,
            None => direct_endpoint(ipv6)?,
        };
        return Ok((endpoint, None));
    }
    let state = PortHopState::new(ports, initial_port, ipv6)?;
    let hopping: Arc<dyn AsyncUdpSocket> = Arc::new(PortHopSocket {
        state: Arc::clone(&state),
    });
    let socket: Arc<dyn AsyncUdpSocket> = match salamander_key {
        Some(key) => SalamanderSocket::new(hopping, key),
        None => hopping,
    };
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    Ok((endpoint, Some(state)))
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
    inner: Arc<dyn AsyncUdpSocket>,
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
    fn new(inner: Arc<dyn AsyncUdpSocket>, key: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            inner,
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
    let socket = SalamanderSocket::new(Arc::new(PlainSocket(sock)), key);
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
