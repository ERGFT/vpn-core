//! Приложение целиком (Фаза 0): вход SOCKS5 → маршрутизатор → выходы
//! `direct` и `block`, TCP и UDP, плюс проверки настроек при сборке.
//! Выход `vless` проверяется интероп-тестами и smoke-скриптами.

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

fn cfg(final_: &str) -> String {
    format!(
        r#"
[[inbounds]]
type = "socks"
listen = "127.0.0.1:0"

[[outbounds]]
tag = "direct"
type = "direct"

[[outbounds]]
tag = "block"
type = "block"

[route]
final = "{final_}"
"#
    )
}

/// SOCKS5 без пароля: приветствие и запрос. Возвращает код ответа.
async fn socks_request(s: &mut TcpStream, cmd: u8, addr: SocketAddr) -> (u8, SocketAddr) {
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let SocketAddr::V4(v4) = addr else { panic!() };
    let mut req = vec![5, cmd, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    let bound = SocketAddr::from((
        [rep[4], rep[5], rep[6], rep[7]],
        u16::from_be_bytes([rep[8], rep[9]]),
    ));
    (rep[1], bound)
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    a
}

#[tokio::test]
async fn tcp_through_direct() {
    let app = start(&cfg("direct")).await;
    let echo = tcp_echo().await;
    let mut s = TcpStream::connect(app.listen_addrs[0]).await.unwrap();
    let (code, _) = socks_request(&mut s, 1, echo).await;
    assert_eq!(code, 0, "CONNECT через direct должен пройти");
    s.write_all(b"hello, direct").await.unwrap();
    let mut back = [0u8; 13];
    tokio::time::timeout(T, s.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"hello, direct");
}

#[tokio::test]
async fn tcp_blocked_gets_ruleset_reply() {
    let app = start(&cfg("block")).await;
    let echo = tcp_echo().await;
    let mut s = TcpStream::connect(app.listen_addrs[0]).await.unwrap();
    let (code, _) = socks_request(&mut s, 1, echo).await;
    assert_eq!(code, 2, "block отвечает «запрещено правилами» (0x02)");
}

#[tokio::test]
async fn udp_through_direct() {
    let app = start(&cfg("direct")).await;
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = echo.recv_from(&mut b).await {
            let _ = echo.send_to(&b[..n], from).await;
        }
    });

    let app_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut ctl = TcpStream::connect(app.listen_addrs[0]).await.unwrap();
    let (code, relay) = socks_request(&mut ctl, 3, app_udp.local_addr().unwrap()).await;
    assert_eq!(code, 0);

    let SocketAddr::V4(v4) = echo_addr else {
        panic!()
    };
    let mut hdr = vec![0, 0, 0, 1];
    hdr.extend_from_slice(&v4.ip().octets());
    hdr.extend_from_slice(&v4.port().to_be_bytes());
    for i in 0..5u8 {
        let mut dg = hdr.clone();
        dg.extend_from_slice(&[i; 100]);
        app_udp.send_to(&dg, relay).await.unwrap();
        let mut b = [0u8; 2048];
        let (n, _) = tokio::time::timeout(T, app_udp.recv_from(&mut b))
            .await
            .expect("ответ по UDP")
            .unwrap();
        assert_eq!(&b[..10], &hdr[..], "источник ответа — эхо-сервер");
        assert_eq!(&b[10..n], &[i; 100][..]);
    }
    drop(ctl);
}

#[tokio::test]
async fn udp_blocked_is_dropped() {
    let app = start(&cfg("block")).await;
    let app_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut ctl = TcpStream::connect(app.listen_addrs[0]).await.unwrap();
    let (code, relay) = socks_request(&mut ctl, 3, app_udp.local_addr().unwrap()).await;
    assert_eq!(code, 0);
    let dg = [0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 1, 2, 3];
    app_udp.send_to(&dg, relay).await.unwrap();
    let mut b = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(500), app_udp.recv_from(&mut b))
            .await
            .is_err(),
        "block не должен ничего отвечать"
    );
}

fn build_err(toml: &str) -> String {
    match App::build(&Config::parse(toml).expect("разбор")) {
        Ok(_) => panic!("сборка должна была отказать:\n{toml}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn build_rejects_unsafe_or_broken_settings() {
    let direct = "[[outbounds]]\ntag='direct'\ntype='direct'\n";

    let e = build_err(&format!(
        "[[inbounds]]\ntype='socks'\nlisten='0.0.0.0:1080'\n{direct}"
    ));
    assert!(e.contains("без пароля"), "{e}");

    let e = build_err(&format!(
        "[[inbounds]]\ntype='socks'\nlisten='0.0.0.0:1080'\nauth='u:short'\n{direct}"
    ));
    assert!(e.contains("короче"), "{e}");

    let e = build_err(&format!(
        "[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:1080'\n{direct}{direct}"
    ));
    assert!(e.contains("одинаковым tag"), "{e}");

    let e = build_err(&format!(
        "[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:1080'\n{direct}[route]\nfinal='nope'\n"
    ));
    assert!(e.contains("nope"), "{e}");

    let e = build_err(direct);
    assert!(e.contains("вход"), "{e}");

    let e = build_err("[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:1080'\n");
    assert!(e.contains("выход"), "{e}");

    let e = build_err(
        "[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:1080'\n\
         [[outbounds]]\ntag='p'\ntype='vless'\n\
         link='vless://11111111-2222-3333-4444-555555555555@example.com:443?security=none'\n",
    );
    assert!(e.contains("allow_insecure"), "{e}");

    let e = build_err(
        "[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:1080'\n\
         [[outbounds]]\ntag='p'\ntype='vless'\n",
    );
    assert!(e.contains("link"), "{e}");

    // С паролем достаточной длины открыть в сеть можно.
    App::build(
        &Config::parse(&format!(
            "[[inbounds]]\ntype='socks'\nlisten='0.0.0.0:1080'\nauth='u:long-enough-password'\n{direct}"
        ))
        .unwrap(),
    )
    .expect("пароль длинный — сборка проходит");
}
