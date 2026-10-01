// SPDX-License-Identifier: GPL-3.0-or-later
//! Фаза 1: правила маршрутизации, вход HTTP/mixed, sniffing — через
//! настоящие сокеты, с выходами `direct` и `block`.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const T: Duration = Duration::from_secs(10);

async fn start(json: &str) -> Running {
    let cfg = Config::parse(json).expect("настройки");
    App::build(&cfg)
        .expect("сборка")
        .start()
        .await
        .expect("запуск")
}

const OUTBOUNDS: &str =
    r#""outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]"#;

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

/// SOCKS5 CONNECT к домену или IP; возвращает код ответа.
async fn socks_connect(proxy: SocketAddr, host: &str, port: u16) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, 1, 0];
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    (s, rep[1])
}

async fn echo_works(s: &mut TcpStream, data: &[u8]) -> bool {
    if s.write_all(data).await.is_err() {
        return false;
    }
    let mut back = vec![0u8; data.len()];
    matches!(
        tokio::time::timeout(T, s.read_exact(&mut back)).await,
        Ok(Ok(_)) if back == data
    )
}

#[tokio::test]
async fn rules_pick_outbounds_by_domain_ip_port_network() {
    let app = start(&format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  {OUTBOUNDS},
  "route": {{
    "rules": [
      {{ "domain_suffix": ["blocked.test"], "outbound": "block" }},
      {{ "ip_cidr": ["127.0.0.2/32"], "outbound": "block" }},
      {{ "port_range": ["1:1023"], "outbound": "block" }},
      {{ "network": "udp", "outbound": "block" }},
      {{ "domain": ["localhost"], "outbound": "direct" }}
    ],
    "final": "direct"
  }}
}}"#
    ))
    .await;
    let proxy = app.listen_addrs[0];
    let echo = tcp_echo().await;

    let (_s, code) = socks_connect(proxy, "a.blocked.test", echo.port()).await;
    assert_eq!(code, 2, "домен под правилом block");
    let (_s, code) = socks_connect(proxy, "127.0.0.2", echo.port()).await;
    assert_eq!(code, 2, "адрес под правилом block");
    let (_s, code) = socks_connect(proxy, "localhost", 80).await;
    assert_eq!(code, 2, "порт под правилом block (правило раньше domain)");

    let (mut s, code) = socks_connect(proxy, "127.0.0.1", echo.port()).await;
    assert_eq!(code, 0);
    assert!(echo_works(&mut s, b"direct by final").await);
    let (mut s, code) = socks_connect(proxy, "localhost", echo.port()).await;
    assert_eq!(code, 0);
    assert!(echo_works(&mut s, b"direct by rule").await);

    // UDP — под правилом network = "udp": ответа нет.
    let echo_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_udp_addr = echo_udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = echo_udp.recv_from(&mut b).await {
            let _ = echo_udp.send_to(&b[..n], from).await;
        }
    });
    let app_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut ctl = TcpStream::connect(proxy).await.unwrap();
    ctl.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    ctl.read_exact(&mut m).await.unwrap();
    let SocketAddr::V4(me) = app_udp.local_addr().unwrap() else {
        panic!()
    };
    let mut req = vec![5, 3, 0, 1];
    req.extend_from_slice(&me.ip().octets());
    req.extend_from_slice(&me.port().to_be_bytes());
    ctl.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    ctl.read_exact(&mut rep).await.unwrap();
    let relay = SocketAddr::from((
        [rep[4], rep[5], rep[6], rep[7]],
        u16::from_be_bytes([rep[8], rep[9]]),
    ));
    let mut dg = vec![0, 0, 0, 1, 127, 0, 0, 1];
    dg.extend_from_slice(&echo_udp_addr.port().to_be_bytes());
    dg.extend_from_slice(b"udp");
    app_udp.send_to(&dg, relay).await.unwrap();
    let mut b = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(500), app_udp.recv_from(&mut b))
            .await
            .is_err(),
        "UDP должен уйти в block"
    );
}

#[tokio::test]
async fn rules_by_inbound() {
    let app = start(&format!(
        r#"{{
  "inbounds": [
    {{ "type": "socks", "tag": "open", "listen": "127.0.0.1", "listen_port": 0 }},
    {{ "type": "socks", "tag": "closed", "listen": "127.0.0.1", "listen_port": 0 }}
  ],
  {OUTBOUNDS},
  "route": {{ "rules": [{{ "inbound": ["closed"], "outbound": "block" }}] }}
}}"#
    ))
    .await;
    let echo = tcp_echo().await;
    let (mut s, code) = socks_connect(app.listen_addrs[0], "127.0.0.1", echo.port()).await;
    assert_eq!(code, 0);
    assert!(echo_works(&mut s, b"x").await);
    let (_s, code) = socks_connect(app.listen_addrs[1], "127.0.0.1", echo.port()).await;
    assert_eq!(code, 2);
}

/// Прочитать HTTP-ответ до пустой строки.
async fn read_response_head(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(T, s.read(&mut b)).await.unwrap() {
            Ok(0) | Err(_) => break,
            Ok(_) => buf.push(b[0]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn mixed_serves_socks_and_http_with_auth() {
    let app = start(&format!(
        r#"{{
  "inbounds": [{{
    "type": "mixed", "listen": "127.0.0.1", "listen_port": 0,
    "users": [{{ "username": "user", "password": "correct-horse-battery" }}]
  }}],
  {OUTBOUNDS},
  "route": {{ "rules": [{{ "domain": ["forbidden.test"], "outbound": "block" }}] }}
}}"#
    ))
    .await;
    let proxy = app.listen_addrs[0];
    let echo = tcp_echo().await;

    // HTTP CONNECT без пароля — 407.
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo.port()).as_bytes())
        .await
        .unwrap();
    assert!(read_response_head(&mut s).await.starts_with("HTTP/1.1 407"));

    // Неверный пароль — 407.
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n",
            echo.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert!(read_response_head(&mut s).await.starts_with("HTTP/1.1 407"));

    // Верный пароль — туннель.
    let auth = "dXNlcjpjb3JyZWN0LWhvcnNlLWJhdHRlcnk="; // user:correct-horse-battery (тест) gitleaks:allow
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n",
            echo.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_response_head(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(echo_works(&mut s, b"through http connect").await);

    // Заблокированный домен — 403.
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        format!("CONNECT forbidden.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    assert!(read_response_head(&mut s).await.starts_with("HTTP/1.1 403"));

    // SOCKS5 на том же порту: без пароля не пускает, с паролем — да.
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0xff], "SOCKS5 без пароля отвергнут");
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 2]).await.unwrap();
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 2]);
    let (u, p) = (b"user", b"correct-horse-battery");
    let mut a = vec![1, u.len() as u8];
    a.extend_from_slice(u);
    a.push(p.len() as u8);
    a.extend_from_slice(p);
    s.write_all(&a).await.unwrap();
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [1, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    assert!(echo_works(&mut s, b"socks on mixed").await);
}

#[tokio::test]
async fn http_plain_request_is_forwarded_rewritten() {
    // «Сайт»: отвечает телом, в котором — полученный заголовок запроса.
    let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let site_addr = site.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = site.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut b = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut b).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&b[..n]);
                }
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", buf.len());
                s.write_all(resp.as_bytes()).await.unwrap();
                s.write_all(&buf).await.unwrap();
            });
        }
    });
    let app = start(&format!(
        r#"{{"inbounds": [{{"type": "http", "listen": "127.0.0.1", "listen_port": 0}}], {OUTBOUNDS}, "route": {{"final": "direct"}}}}"#
    ))
    .await;
    let mut s = TcpStream::connect(app.listen_addrs[0]).await.unwrap();
    s.write_all(
        format!(
            "GET http://127.0.0.1:{}/page?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\
             Proxy-Connection: keep-alive\r\nUser-Agent: test\r\n\r\n",
            site_addr.port(),
            site_addr.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut all = Vec::new();
    tokio::time::timeout(T, s.read_to_end(&mut all))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&all);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    assert!(text.contains("GET /page?q=1 HTTP/1.1\r\n"), "{text}");
    assert!(text.contains("User-Agent: test\r\n"), "{text}");
    assert!(text.contains("Connection: close\r\n"), "{text}");
    assert!(!text.contains("Proxy-Connection"), "{text}");

    // SOCKS5 на входе type = "http" не принимается.
    let mut s = TcpStream::connect(app.listen_addrs[0]).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut b = [0u8; 16];
    let n = tokio::time::timeout(T, s.read(&mut b))
        .await
        .unwrap()
        .unwrap_or(0);
    assert!(n == 0 || b.starts_with(b"HTTP/1.1 400"), "{:?}", &b[..n]);
}

/// Минимальный TLS ClientHello с SNI.
fn client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut sni = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1, 0];
    hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[tokio::test]
async fn sniffed_sni_drives_routing_for_ip_targets() {
    let echo = tcp_echo().await;
    let app = start(&format!(
        r#"{{
  "inbounds": [
    {{ "type": "socks", "tag": "sniffing", "listen": "127.0.0.1", "listen_port": 0 }},
    {{ "type": "socks", "tag": "override", "listen": "127.0.0.1", "listen_port": 0,
       "sniff_override_destination": true }},
    {{ "type": "socks", "tag": "plain", "listen": "127.0.0.1", "listen_port": 0 }}
  ],
  {OUTBOUNDS},
  "route": {{
    "rules": [
      {{ "inbound": ["sniffing", "override"], "action": "sniff" }},
      {{ "domain_suffix": ["ads.test"], "outbound": "block" }}
    ]
  }}
}}"#
    ))
    .await;
    let (sniffing, overriding, plain) = (
        app.listen_addrs[0],
        app.listen_addrs[1],
        app.listen_addrs[2],
    );

    // Приложение прислало IP; по SNI видно, что это реклама — соединение
    // закрывается, не дойдя до «сайта».
    let (mut s, code) = socks_connect(sniffing, "127.0.0.1", echo.port()).await;
    assert_eq!(code, 0, "при sniffing ответ «соединено» уходит сразу");
    assert!(!echo_works(&mut s, &client_hello("tracker.ads.test")).await);

    // Обычный сайт — проходит, первые байты доходят без изменений.
    let (mut s, _) = socks_connect(sniffing, "127.0.0.1", echo.port()).await;
    assert!(echo_works(&mut s, &client_hello("news.test")).await);

    // Протокол, где первым говорит сервер: ждём не дольше таймаута sniffing.
    let (mut s, _) = socks_connect(sniffing, "127.0.0.1", echo.port()).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(echo_works(&mut s, b"late bytes").await);

    // Без sniffing правило по домену к IP не применяется.
    let (mut s, _) = socks_connect(plain, "127.0.0.1", echo.port()).await;
    assert!(echo_works(&mut s, &client_hello("tracker.ads.test")).await);

    // С подстановкой домена соединение идёт на домен из SNI: имя
    // не разрешается — соединения нет, хотя IP рабочий.
    let (mut s, _) = socks_connect(overriding, "127.0.0.1", echo.port()).await;
    assert!(!echo_works(&mut s, &client_hello("no-such-host.invalid")).await);
    let (mut s, _) = socks_connect(overriding, "127.0.0.1", echo.port()).await;
    assert!(echo_works(&mut s, &client_hello("localhost")).await);
}

#[test]
fn rule_config_errors() {
    let cfg = |rules: &str, route: &str| {
        format!(
            r#"{{"inbounds": [{{"type": "socks", "listen": "127.0.0.1", "listen_port": 1080}}],
                 "outbounds": [{{"type": "direct", "tag": "direct"}}],
                 "route": {{"rules": [{rules}]{route}}}}}"#
        )
    };
    let err =
        |rules: &str, route: &str| match App::build(&Config::parse(&cfg(rules, route)).unwrap()) {
            Ok(_) => panic!("должна быть ошибка: {rules}"),
            Err(e) => e.to_string(),
        };
    assert!(err(r#"{"domain": ["a"], "outbound": "nope"}"#, "").contains("nope"));
    assert!(err(r#"{"outbound": "direct"}"#, "").contains("без условий"));
    assert!(err(r#"{"inbound": ["typo"], "outbound": "direct"}"#, "").contains("typo"));
    assert!(err(r#"{"domain_regex": ["("], "outbound": "direct"}"#, "").contains("domain_regex"));
    assert!(err(r#"{"port": [99999], "outbound": "direct"}"#, "").contains("порт"));
    let e = err(
        r#"{"geosite": ["cn"], "outbound": "direct"}"#,
        r#", "geosite_file": "/nonexistent/geosite.dat""#,
    );
    assert!(e.contains("geosite.dat"), "{e}");
    // Опечатка и неизвестная сеть — ошибка разбора.
    assert!(Config::parse(&cfg(r#"{"domian": ["a"], "outbound": "direct"}"#, "")).is_err());
    assert!(Config::parse(&cfg(r#"{"network": "icmp", "outbound": "direct"}"#, "")).is_err());
    let e = match App::build(
        &Config::parse(
            r#"{"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": 1,
                              "sniff_override_destination": true}],
                "outbounds": [{"type": "direct", "tag": "d"}]}"#,
        )
        .unwrap(),
    ) {
        Ok(_) => panic!(),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("sniff"), "{e}");
}

/// Настоящие базы v2fly (не в репозитории): GEO_DIR=папка с geosite.dat
/// (dlc.dat) и geoip.dat.
#[test]
#[ignore = "нужны настоящие geosite.dat и geoip.dat: GEO_DIR=…"]
fn real_geo_files() {
    let dir = std::env::var("GEO_DIR").expect("GEO_DIR");
    let t = std::time::Instant::now();
    let cfg = Config::parse(&format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  {OUTBOUNDS},
  "route": {{
    "rules": [
      {{ "geosite": ["category-ads-all"], "outbound": "block" }},
      {{ "geosite": ["category-ru"], "geoip": ["ru", "private"], "outbound": "direct" }}
    ],
    "geosite_file": "{dir}/geosite.dat",
    "geoip_file": "{dir}/geoip.dat",
    "final": "block"
  }}
}}"#
    ))
    .unwrap();
    App::build(&cfg).expect("базы читаются");
    eprintln!("базы прочитаны за {:?}", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(5));
}
