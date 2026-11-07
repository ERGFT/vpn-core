// SPDX-License-Identifier: GPL-3.0-or-later
//! Test-only protocol fixture for the outbound extension boundary.
//!
//! This deliberately stays outside the production config and protocol enums.
//! It has typed settings, a small builder, and uses the same `Outbound`,
//! `UdpSession`, router, tracker, and reload boundary as production proxies.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::config::RouteConfig;
use super::outbound::{Outbound, OutboundCapabilities, Packet, UdpSession};
use super::router::{Router, RouterHandle};
use super::{Metadata, Network};
use crate::app::rules::GeoFiles;
use crate::error::{Error, Result};
use crate::transport::AsyncStream;
use crate::vless::Address;

#[derive(Clone)]
struct TestProtocolSettings {
    tag: String,
    tcp_server: SocketAddr,
    udp_server: SocketAddr,
    timeout: Duration,
}

impl TestProtocolSettings {
    fn validate(&self) -> Result<()> {
        if self.tag.trim().is_empty() {
            return Err(Error::Config("test protocol: tag cannot be empty".into()));
        }
        for (name, address) in [
            ("tcp_server", self.tcp_server),
            ("udp_server", self.udp_server),
        ] {
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err(Error::Config(format!(
                    "test protocol: {name} must be a loopback address with a nonzero port"
                )));
            }
        }
        if self.timeout.is_zero() {
            return Err(Error::Config(
                "test protocol: timeout must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

fn build_test_protocol(settings: TestProtocolSettings) -> Result<Arc<dyn Outbound>> {
    settings.validate()?;
    Ok(Arc::new(TestProtocolOutbound { settings }))
}

struct TestProtocolOutbound {
    settings: TestProtocolSettings,
}

impl Outbound for TestProtocolOutbound {
    fn tag(&self) -> &str {
        &self.settings.tag
    }

    fn clash_type(&self) -> &'static str {
        "TEST"
    }

    fn capabilities(&self) -> OutboundCapabilities {
        OutboundCapabilities::TCP_UDP_TERMINAL
    }

    fn connect<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            let stream = tokio::time::timeout(
                self.settings.timeout,
                TcpStream::connect(self.settings.tcp_server),
            )
            .await
            .map_err(|_| Error::Protocol("test protocol: TCP connect timed out".into()))??;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }

    fn udp<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let bind = match self.settings.udp_server.ip() {
                IpAddr::V4(_) => SocketAddr::from(([127, 0, 0, 1], 0)),
                IpAddr::V6(_) => {
                    SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 0))
                }
            };
            let socket = UdpSocket::bind(bind).await?;
            Ok(Arc::new(TestProtocolUdpSession {
                socket,
                server: self.settings.udp_server,
                timeout: self.settings.timeout,
            }) as Arc<dyn UdpSession>)
        })
    }
}

struct TestProtocolUdpSession {
    socket: UdpSocket,
    server: SocketAddr,
    timeout: Duration,
}

impl UdpSession for TestProtocolUdpSession {
    fn send(&self, _dst: Address, _port: u16, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.socket.send_to(&data, self.server))
                .await
                .map_err(|_| Error::Protocol("test protocol: UDP send timed out".into()))??;
            Ok(())
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move {
            let mut data = vec![0; u16::MAX as usize];
            let (size, source) =
                tokio::time::timeout(self.timeout, self.socket.recv_from(&mut data))
                    .await
                    .map_err(|_| {
                        Error::Protocol("test protocol: UDP receive timed out".into())
                    })??;
            data.truncate(size);
            let address = match source.ip() {
                IpAddr::V4(ip) => Address::Ipv4(ip),
                IpAddr::V6(ip) => Address::Ipv6(ip),
            };
            Ok(Some((address, source.port(), data)))
        })
    }
}

fn metadata(network: Network) -> Metadata {
    Metadata {
        inbound: Arc::from("architecture-test"),
        source: SocketAddr::from(([127, 0, 0, 1], 12345)),
        user_id: None,
        network,
        target: Address::Domain("echo.test".into()),
        port: 7,
        sniffed: None,
        inbound_type: "test",
        rule: None,
    }
}

fn router_for(outbound: Arc<dyn Outbound>) -> Router {
    let route = RouteConfig {
        final_: Some(outbound.tag().to_owned()),
        ..RouteConfig::default()
    };
    let geo = GeoFiles::load(
        Vec::new(),
        Vec::new(),
        Path::new("unused"),
        Path::new("unused"),
    )
    .expect("empty geo sets do not read files");
    Router::new(vec![outbound], &route, &[], &geo).expect("test router is valid")
}

async fn tcp_echo_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

fn spawn_tcp_echo(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 4096];
                loop {
                    let Ok(size) = stream.read(&mut buffer).await else {
                        break;
                    };
                    if size == 0 || stream.write_all(&buffer[..size]).await.is_err() {
                        break;
                    }
                }
            });
        }
    })
}

fn spawn_udp_echo(socket: Arc<UdpSocket>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut data = vec![0; u16::MAX as usize];
        while let Ok((size, peer)) = socket.recv_from(&mut data).await {
            if socket.send_to(&data[..size], peer).await.is_err() {
                break;
            }
        }
    })
}

fn settings(tag: &str, tcp_server: SocketAddr, udp_server: SocketAddr) -> TestProtocolSettings {
    TestProtocolSettings {
        tag: tag.into(),
        tcp_server,
        udp_server,
        timeout: Duration::from_secs(2),
    }
}

#[tokio::test]
async fn typed_test_protocol_round_trips_tcp_udp_and_observes_shutdown() {
    let tcp = tcp_echo_listener().await;
    let tcp_addr = tcp.local_addr().unwrap();
    let tcp_task = spawn_tcp_echo(tcp);
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_addr = udp.local_addr().unwrap();
    let udp_task = spawn_udp_echo(udp);

    let invalid = settings("", tcp_addr, udp_addr);
    assert!(build_test_protocol(invalid)
        .err()
        .unwrap()
        .to_string()
        .contains("tag"));
    let invalid = settings("test", "8.8.8.8:53".parse().unwrap(), udp_addr);
    assert!(build_test_protocol(invalid)
        .err()
        .unwrap()
        .to_string()
        .contains("loopback"));

    let outbound = build_test_protocol(settings("test", tcp_addr, udp_addr)).unwrap();
    assert_eq!(
        outbound.capabilities(),
        OutboundCapabilities::TCP_UDP_TERMINAL
    );
    let router = router_for(outbound.clone());

    let mut meta = metadata(Network::Tcp);
    let selected = router.route(&mut meta).await.unwrap();
    assert_eq!(selected.tag(), "test");
    let (mut stream, info) = router.dial(&selected, &meta).await.unwrap();
    stream.write_all(b"tcp echo").await.unwrap();
    let mut response = [0; 8];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"tcp echo");
    assert_eq!(info.up(), 8);
    assert_eq!(info.down(), 8);
    assert!(router.tracker().close(info.id));
    tokio::time::timeout(Duration::from_secs(1), info.cancelled())
        .await
        .expect("tracker close must signal connection cancellation");
    drop(stream);

    let udp_meta = metadata(Network::Udp);
    let session = outbound.udp(&udp_meta).await.unwrap();
    session
        .send(Address::Domain("echo.test".into()), 7, b"udp echo".to_vec())
        .await
        .unwrap();
    let (_, _, response) = session.recv().await.unwrap().unwrap();
    assert_eq!(response, b"udp echo");

    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn test_protocol_fails_closed_on_unavailable_servers_and_udp_timeout() {
    let unavailable_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_tcp_addr = unavailable_tcp.local_addr().unwrap();
    drop(unavailable_tcp);

    let blackhole_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blackhole_udp_addr = blackhole_udp.local_addr().unwrap();
    let tcp = tcp_echo_listener().await;
    let tcp_addr = tcp.local_addr().unwrap();
    let tcp_task = spawn_tcp_echo(tcp);

    let unreachable = build_test_protocol(settings(
        "unreachable",
        unavailable_tcp_addr,
        blackhole_udp_addr,
    ))
    .unwrap();
    assert!(unreachable.connect(&metadata(Network::Tcp)).await.is_err());

    let mut short_timeout = settings("timeout", tcp_addr, blackhole_udp_addr);
    short_timeout.timeout = Duration::from_millis(20);
    let timed = build_test_protocol(short_timeout).unwrap();
    let session = timed.udp(&metadata(Network::Udp)).await.unwrap();
    session
        .send(Address::Domain("echo.test".into()), 7, b"no reply".to_vec())
        .await
        .unwrap();
    let error = session.recv().await.unwrap_err();
    assert!(error.to_string().contains("UDP receive timed out"));

    let mut invalid = settings("invalid", tcp_addr, blackhole_udp_addr);
    invalid.timeout = Duration::ZERO;
    assert!(build_test_protocol(invalid)
        .err()
        .unwrap()
        .to_string()
        .contains("timeout"));

    tcp_task.abort();
}

#[tokio::test]
async fn router_handle_replacement_keeps_old_tcp_session_and_routes_new_sessions() {
    let old_listener = tcp_echo_listener().await;
    let old_addr = old_listener.local_addr().unwrap();
    let old_task = spawn_tcp_echo(old_listener);
    let new_listener = tcp_echo_listener().await;
    let new_addr = new_listener.local_addr().unwrap();
    let new_task = spawn_tcp_echo(new_listener);
    let unused_udp = "127.0.0.1:9".parse().unwrap();

    let old_router =
        router_for(build_test_protocol(settings("old", old_addr, unused_udp)).unwrap());
    let routers = RouterHandle::new(old_router);
    let old_current = routers.get();
    let old_outbound = old_current.get("old").unwrap();
    let mut old_meta = metadata(Network::Tcp);
    let (mut old_stream, _) = old_current.dial(&old_outbound, &old_meta).await.unwrap();

    let new_router =
        router_for(build_test_protocol(settings("new", new_addr, unused_udp)).unwrap());
    routers.set(Arc::new(new_router));
    let current = routers.get();
    assert_eq!(current.final_tag(), "new");
    let new_outbound = current.route(&mut old_meta).await.unwrap();
    let (mut new_stream, _) = current.dial(&new_outbound, &old_meta).await.unwrap();

    old_stream.write_all(b"old session").await.unwrap();
    let mut old_response = [0; 11];
    old_stream.read_exact(&mut old_response).await.unwrap();
    assert_eq!(&old_response, b"old session");
    new_stream.write_all(b"new session").await.unwrap();
    let mut new_response = [0; 11];
    new_stream.read_exact(&mut new_response).await.unwrap();
    assert_eq!(&new_response, b"new session");

    drop(old_stream);
    drop(new_stream);
    old_task.abort();
    new_task.abort();
}
