// SPDX-License-Identifier: GPL-3.0-or-later
//! Classic Shadowsocks AEAD outbound over the existing protected socket path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::relay::socks5::Address as ShadowsocksAddress;
use shadowsocks::relay::udprelay::proxy_socket::{ProxySocket, UdpSocketType};
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use super::outbound::{Outbound, Packet, UdpSession, UDP_IDLE};
use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::{self, AsyncStream};
use crate::vless::Address;

use shadowsocks::ProxyClientStream;

const QUEUE: usize = 64;
const UDP_BUFFER: usize = 65_536;
const MAX_UDP_PAYLOAD: usize = 65_000;
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ShadowsocksOutbound {
    tag: String,
    config: Arc<ServerConfig>,
    context: SharedContext,
}

impl ShadowsocksOutbound {
    pub fn from_link(tag: impl Into<String>, link: &str) -> Result<Self> {
        let config = ServerConfig::from_url(link).map_err(|_| {
            Error::Config("shadowsocks: некорректная ссылка ss:// или учётные данные".into())
        })?;
        crate::shadowsocks_protocol::validate_classic(&config)?;
        Ok(Self {
            tag: tag.into(),
            config: Arc::new(config),
            context: Context::new_shared(ServerType::Local),
        })
    }

    fn endpoint(&self) -> Option<(String, u16)> {
        match self.config.addr() {
            ServerAddr::SocketAddr(addr) => Some((addr.ip().to_string(), addr.port())),
            ServerAddr::DomainName(host, port) => Some((host.clone(), *port)),
        }
    }
}

fn target_address(target: Address, port: u16) -> ShadowsocksAddress {
    match target {
        Address::Ipv4(ip) => {
            ShadowsocksAddress::SocketAddress(SocketAddr::new(IpAddr::V4(ip), port))
        }
        Address::Ipv6(ip) => {
            ShadowsocksAddress::SocketAddress(SocketAddr::new(IpAddr::V6(ip), port))
        }
        Address::Domain(host) => ShadowsocksAddress::DomainNameAddress(host, port),
    }
}

async fn resolve_endpoint(addr: &ServerAddr) -> Result<Vec<SocketAddr>> {
    match addr {
        ServerAddr::SocketAddr(sa) => Ok(vec![*sa]),
        ServerAddr::DomainName(host, port) => transport::tcp_tls::resolve_server(host, *port).await,
    }
}

impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn clash_type(&self) -> &'static str {
        "Shadowsocks"
    }

    fn capabilities(&self) -> super::outbound::OutboundCapabilities {
        super::outbound::OutboundCapabilities::TCP_UDP
    }

    fn server(&self) -> Option<(String, u16)> {
        self.endpoint()
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            let addr = self.config.tcp_external_addr();
            let addrs = tokio::time::timeout(DIAL_TIMEOUT, resolve_endpoint(addr))
                .await
                .map_err(|_| Error::Protocol("shadowsocks: timeout resolving server".into()))??;
            let stream = tokio::time::timeout(
                DIAL_TIMEOUT,
                transport::tcp_tls::connect_addrs(&addrs, &addr.to_string()),
            )
            .await
            .map_err(|_| Error::Protocol("shadowsocks: timeout connecting to server".into()))??;
            let target = target_address(meta.target.clone(), meta.port);
            Ok(Box::new(ProxyClientStream::from_stream(
                self.context.clone(),
                stream,
                &self.config,
                target,
            )) as Box<dyn AsyncStream>)
        })
    }

    fn udp<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            Ok(Arc::new(ShadowsocksUdp::start(
                self.config.clone(),
                self.context.clone(),
            )) as Arc<dyn UdpSession>)
        })
    }
}

/// Local adapter lets the reference codec use the core's net_protect UDP socket.
struct ProtectedUdpSocket(UdpSocket);

impl DatagramSocket for ProtectedUdpSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl DatagramReceive for ProtectedUdpSocket {
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }

    fn poll_recv_from(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<SocketAddr>> {
        self.0.poll_recv_from(cx, buf)
    }

    fn poll_recv_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_recv_ready(cx)
    }
}

impl DatagramSend for ProtectedUdpSocket {
    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send_to(cx, buf, target)
    }

    fn poll_send_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_send_ready(cx)
    }
}

struct ShadowsocksUdp {
    tx: mpsc::Sender<Packet>,
    rx: Mutex<mpsc::Receiver<Packet>>,
}

impl ShadowsocksUdp {
    fn start(config: Arc<ServerConfig>, context: SharedContext) -> Self {
        let (tx, mut up_rx) = mpsc::channel::<Packet>(QUEUE);
        let (down_tx, down_rx) = mpsc::channel::<Packet>(QUEUE);
        tokio::spawn(async move {
            let run = async {
                let addr = config.udp_external_addr();
                let addrs = resolve_endpoint(addr).await?;
                let remote = *addrs.first().ok_or_else(|| {
                    Error::Protocol("shadowsocks: server name resolved to no addresses".into())
                })?;
                let bind = if remote.is_ipv4() {
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                } else {
                    SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                };
                let socket = crate::net_protect::udp_bind(bind)?;
                socket.connect(remote).await?;
                let socket = ProxySocket::from_socket(
                    UdpSocketType::Client,
                    context,
                    &config,
                    ProtectedUdpSocket(socket),
                );
                let mut buffer = vec![0u8; UDP_BUFFER];
                loop {
                    let event = tokio::time::timeout(UDP_IDLE, async {
                        tokio::select! {
                            packet = up_rx.recv() => {
                                match packet {
                                    Some((dst, port, data)) => {
                                        socket.send_to(remote, &target_address(dst, port), &data).await
                                            .map(|_| false)
                                            .map_err(|error| Error::Protocol(format!("shadowsocks UDP: {error}")))
                                    }
                                    None => Ok(true),
                                }
                            }
                            received = socket.recv(&mut buffer) => {
                                match received {
                                    Ok((len, source, _)) => {
                                        let (dst, port) = from_shadowsocks_address(source)?;
                                        let packet = (dst, port, buffer[..len].to_vec());
                                        match down_tx.try_send(packet) {
                                            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
                                            Err(mpsc::error::TrySendError::Closed(_)) => Ok(true),
                                        }
                                    }
                                    Err(error) => Err(Error::Protocol(format!("shadowsocks UDP: {error}"))),
                                }
                            }
                        }
                    }).await;
                    match event {
                        Ok(Ok(true)) | Err(_) => break,
                        Ok(Ok(false)) => {}
                        Ok(Err(error)) => return Err(error),
                    }
                }
                Ok::<(), Error>(())
            };
            if let Err(error) = run.await {
                tracing::debug!(error = %error, "shadowsocks UDP session stopped");
            }
        });
        Self {
            tx,
            rx: Mutex::new(down_rx),
        }
    }
}

fn from_shadowsocks_address(address: ShadowsocksAddress) -> Result<(Address, u16)> {
    match address {
        ShadowsocksAddress::SocketAddress(SocketAddr::V4(sa)) => {
            Ok((Address::Ipv4(*sa.ip()), sa.port()))
        }
        ShadowsocksAddress::SocketAddress(SocketAddr::V6(sa)) => {
            Ok((Address::Ipv6(*sa.ip()), sa.port()))
        }
        ShadowsocksAddress::DomainNameAddress(host, port) => Ok((Address::Domain(host), port)),
    }
}

impl UdpSession for ShadowsocksUdp {
    fn send(&self, dst: Address, port: u16, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if data.len() > MAX_UDP_PAYLOAD {
                tracing::debug!(
                    length = data.len(),
                    "shadowsocks UDP: oversized datagram dropped"
                );
                return Ok(());
            }
            match self.tx.try_send((dst, port, data)) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Err(Error::Protocol("shadowsocks UDP session is closed".into()))
                }
            }
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move { Ok(self.rx.lock().await.recv().await) })
    }
}
