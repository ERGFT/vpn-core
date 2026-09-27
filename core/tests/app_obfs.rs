// SPDX-License-Identifier: GPL-3.0-or-later
//! Фаза 6: дробление ClientHello у выхода `direct` и шум перед UDP.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const T: Duration = Duration::from_secs(10);

async fn start(toml: &str) -> Running {
    let cfg = Config::parse(toml).expect("настройки");
    App::build(&cfg)
        .expect("сборка")
        .start()
        .await
        .expect("запуск")
}

async fn socks_request(s: &mut TcpStream, cmd: u8, addr: SocketAddr) -> (u8, SocketAddr) {
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let SocketAddr::V4(v4) = addr else { panic!() };
    let mut req = vec![5, cmd, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    (
        rep[1],
        SocketAddr::from((
            [rep[4], rep[5], rep[6], rep[7]],
            u16::from_be_bytes([rep[8], rep[9]]),
        )),
    )
}

fn hello(len: usize) -> Vec<u8> {
    let mut v = vec![0x16, 0x03, 0x01];
    v.extend_from_slice(&(len as u16).to_be_bytes());
    v.extend((0..len).map(|i| (i * 7) as u8));
    v
}

#[tokio::test]
async fn direct_fragments_client_hello() {
    // «Сайт»: читает всё и отдаёт обратно, чтобы клиент увидел конец.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let site = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        let mut reads = 0;
        while !got.ends_with(b"rest") {
            let n = s.read(&mut b).await.unwrap();
            assert!(n > 0);
            reads += 1;
            got.extend_from_slice(&b[..n]);
        }
        s.write_all(b"ok").await.unwrap();
        let _ = tx.send((got, reads));
    });
    let r = start(
        r#"
[[inbounds]]
type = "socks"
listen = "127.0.0.1:0"

[[outbounds]]
tag = "direct"
type = "direct"
fragment = { packets = "tlshello", length = "40-60", interval = "3-5" }
"#,
    )
    .await;
    let mut s = TcpStream::connect(r.listen_addrs[0]).await.unwrap();
    let (code, _) = socks_request(&mut s, 1, site).await;
    assert_eq!(code, 0);
    let h = hello(600);
    let mut first = h.clone();
    first.extend_from_slice(b"rest");
    s.write_all(&first).await.unwrap();
    let mut ok = [0u8; 2];
    tokio::time::timeout(T, s.read_exact(&mut ok))
        .await
        .unwrap()
        .unwrap();
    let (wire, reads) = rx.await.unwrap();
    let mut lens = Vec::new();
    let mut body = Vec::new();
    let mut i = 0;
    while i < wire.len() && wire[i] == 0x16 {
        let l = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
        lens.push(l);
        body.extend_from_slice(&wire[i + 5..i + 5 + l]);
        i += 5 + l;
    }
    assert_eq!(body, h[5..], "тело ClientHello не искажено");
    assert_eq!(&wire[i..], b"rest");
    assert!(lens.len() >= 10, "{lens:?}");
    assert!(lens[..lens.len() - 1].iter().all(|l| (40..=60).contains(l)));
    // С паузами куски приходят по отдельности.
    assert!(reads >= 5, "прочитано за {reads} раз");
}

#[tokio::test]
async fn direct_udp_sends_noise_first() {
    let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = srv.local_addr().unwrap();
    let r = start(
        r#"
[[inbounds]]
type = "socks"
listen = "127.0.0.1:0"

[[outbounds]]
tag = "direct"
type = "direct"
noises = [
  { type = "str", packet = "hello-noise", delay = 5 },
  { type = "rand", packet = "30-40" },
]
"#,
    )
    .await;
    let app_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut ctl = TcpStream::connect(r.listen_addrs[0]).await.unwrap();
    let (code, relay) = socks_request(&mut ctl, 3, app_udp.local_addr().unwrap()).await;
    assert_eq!(code, 0);
    let SocketAddr::V4(v4) = srv_addr else {
        panic!()
    };
    let mut hdr = vec![0, 0, 0, 1];
    hdr.extend_from_slice(&v4.ip().octets());
    hdr.extend_from_slice(&v4.port().to_be_bytes());
    for i in 0..2u8 {
        let mut dg = hdr.clone();
        dg.extend_from_slice(&[i; 20]);
        app_udp.send_to(&dg, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut got = Vec::new();
    let mut b = [0u8; 2048];
    while let Ok(Ok((n, _))) =
        tokio::time::timeout(Duration::from_millis(500), srv.recv_from(&mut b)).await
    {
        got.push(b[..n].to_vec());
    }
    assert_eq!(got.len(), 4, "шум (2) — только перед первой датаграммой");
    assert_eq!(got[0], b"hello-noise");
    assert!((30..=40).contains(&got[1].len()));
    assert_eq!(got[2], [0u8; 20]);
    assert_eq!(got[3], [1u8; 20]);
    drop(ctl);
}

#[test]
fn obfs_config_errors() {
    for (toml, want) in [
        (
            "[[outbounds]]\ntag='b'\ntype='block'\nfragment={packets='tlshello',length=5,interval=0}\n",
            "только у vless, trojan и direct",
        ),
        (
            "[[outbounds]]\ntag='d'\ntype='direct'\nfragment={packets='0-1',length=5,interval=0}\n",
            "с 1",
        ),
        (
            "[[outbounds]]\ntag='v'\ntype='vless'\nlink='vless://11111111-1111-1111-1111-111111111111@h.example:443?security=tls'\nnoises=[{type='str',packet='x'}]\n",
            "только у direct",
        ),
        (
            "[[outbounds]]\ntag='d'\ntype='direct'\nnoises=[{type='rand',packet='0'}]\n",
            "rand",
        ),
    ] {
        let full = format!("[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:0'\n{toml}");
        let e = match Config::parse(&full) {
            Err(e) => e.to_string(),
            Ok(c) => App::build(&c).err().expect("ошибка").to_string(),
        };
        assert!(e.contains(want), "{toml}\n→ {e}");
    }
}
