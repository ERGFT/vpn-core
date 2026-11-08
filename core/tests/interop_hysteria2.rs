// SPDX-License-Identifier: GPL-3.0-or-later
//! End-to-end Hysteria 2 interoperability against the pinned official server.
//!
//! Run with `scripts/interop_hysteria2.sh`; the ignored test uses a local
//! SOCKS inbound and the production Hysteria outbound/factory.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const TIMEOUT: Duration = Duration::from_secs(12);

fn required(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required; run scripts/interop_hysteria2.sh"))
}

async fn start_app() -> Running {
    let port = required("HYSTERIA2_PORT");
    let ca_file = serde_json::to_string(&required("HYSTERIA2_CA_FILE")).unwrap();
    let json = format!(
        r#"{{
          "inbounds": [{{"type":"socks","listen":"127.0.0.1","listen_port":0}}],
          "outbounds": [{{"type":"hysteria2","tag":"hy2",
            "link":"hysteria2://interop-password@127.0.0.1:{port}?sni=localhost",
            "ca_file":{ca_file}}}],
          "route": {{"final":"hy2"}}
        }}"#
    );
    let config = Config::parse(&json).unwrap_or_else(|error| panic!("config: {error}\n{json}"));
    App::build(&config)
        .expect("build production app with Hysteria 2 outbound")
        .start()
        .await
        .expect("start app")
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

async fn udp_echo_v4() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0; 65_535];
        while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
            let reply = if size == 4096 {
                if buffer[..size].iter().all(|byte| *byte == 0x5a) {
                    &b"validated full 4096-byte payload"[..]
                } else {
                    &b"invalid large UDP payload"[..]
                }
            } else {
                &buffer[..size]
            };
            let _ = socket.send_to(reply, peer).await;
        }
    });
    addr
}

async fn udp_echo_v6() -> SocketAddr {
    let socket = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        .await
        .expect("Linux interop runner must provide IPv6 loopback");
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0; 65_535];
        while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..size], peer).await;
        }
    });
    addr
}

async fn socks_request(stream: &mut TcpStream, command: u8, bind: SocketAddr) -> (u8, SocketAddr) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);

    let SocketAddr::V4(bind) = bind else {
        panic!("SOCKS5 client endpoint is expected to be IPv4 loopback")
    };
    let mut request = vec![5, command, 0, 1];
    request.extend_from_slice(&bind.ip().octets());
    request.extend_from_slice(&bind.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();

    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    let addr = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    (reply[1], addr.into())
}

fn socks_udp_frame(destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0, 0, 0];
    match destination {
        SocketAddr::V4(addr) => {
            frame.push(1);
            frame.extend_from_slice(&addr.ip().octets());
            frame.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            frame.push(4);
            frame.extend_from_slice(&addr.ip().octets());
            frame.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

fn assert_socks_udp_reply(frame: &[u8], destination: SocketAddr, payload: &[u8]) {
    let (header, expected_len) = match destination {
        SocketAddr::V4(_) => (10, 10 + payload.len()),
        SocketAddr::V6(_) => (22, 22 + payload.len()),
    };
    assert!(frame.len() >= header, "short SOCKS UDP response");
    assert_eq!(&frame[0..3], &[0, 0, 0], "reserved and FRAG fields");
    match destination {
        SocketAddr::V4(addr) => {
            assert_eq!(frame[3], 1);
            assert_eq!(&frame[4..8], &addr.ip().octets());
            assert_eq!(u16::from_be_bytes([frame[8], frame[9]]), addr.port());
        }
        SocketAddr::V6(addr) => {
            assert_eq!(frame[3], 4);
            assert_eq!(&frame[4..20], &addr.ip().octets());
            assert_eq!(u16::from_be_bytes([frame[20], frame[21]]), addr.port());
        }
    }
    assert_eq!(frame.len(), expected_len);
    assert_eq!(&frame[header..], payload);
}

async fn udp_round_trip(
    socket: &UdpSocket,
    relay: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    expected_reply: &[u8],
) {
    let frame = socks_udp_frame(destination, payload);
    socket.send_to(&frame, relay).await.unwrap();
    let mut response = vec![0; 65_535];
    let (size, _) = tokio::time::timeout(TIMEOUT, socket.recv_from(&mut response))
        .await
        .expect("Hysteria UDP echo timed out")
        .unwrap();
    assert_socks_udp_reply(&response[..size], destination, expected_reply);
}

#[tokio::test]
#[ignore = "requires the pinned official Hysteria 2 server; run scripts/interop_hysteria2.sh"]
async fn official_server_tcp_and_udp_ipv4_ipv6_large_and_multiple_destinations() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let tcp_target = tcp_echo().await;
    let udp_v4 = udp_echo_v4().await;
    let udp_v6 = udp_echo_v6().await;
    let app = start_app().await;

    // A fresh outbound TCP relay must reach a real destination through the
    // production factory and SOCKS inbound.
    let mut tcp = TcpStream::connect(app.listen_addrs[0]).await.unwrap();
    let (reply, _) = socks_request(&mut tcp, 1, tcp_target).await;
    assert_eq!(reply, 0, "Hysteria TCP CONNECT must succeed");
    let message = b"hysteria2 official TCP interoperability";
    tcp.write_all(message).await.unwrap();
    let mut echoed = vec![0; message.len()];
    tokio::time::timeout(TIMEOUT, tcp.read_exact(&mut echoed))
        .await
        .expect("Hysteria TCP echo timed out")
        .unwrap();
    assert_eq!(&echoed, message);

    // One SOCKS UDP association is deliberately used for both address
    // families, then for the maximum payload accepted by this implementation.
    let client_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut control = TcpStream::connect(app.listen_addrs[0]).await.unwrap();
    let (reply, relay) = socks_request(&mut control, 3, client_udp.local_addr().unwrap()).await;
    assert_eq!(reply, 0, "SOCKS UDP ASSOCIATE must succeed");
    let small = b"IPv4 destination";
    udp_round_trip(&client_udp, relay, udp_v4, small, small).await;
    let small = b"IPv6 destination";
    udp_round_trip(&client_udp, relay, udp_v6, small, small).await;
    let large = vec![0x5a; 4096];
    // The official server's UDP response buffer is 4096 bytes including its
    // UDPMessage header, so confirm the full request at the echo target and
    // return a short acknowledgement rather than echoing an oversized frame.
    udp_round_trip(
        &client_udp,
        relay,
        udp_v4,
        &large,
        b"validated full 4096-byte payload",
    )
    .await;
    drop(control);
}
