// SPDX-License-Identifier: GPL-3.0-or-later
//! Фаза 2: DNS-модуль целиком — вход DNS (UDP и TCP), серверы UDP, DoT,
//! DoH, правила выбора сервера, кеш, fake-IP с обратным преобразованием в
//! прокси, перехват DNS выходом `dns`, `domain_strategy = "ip_if_non_match"`.
//! «Интернет» — свои серверы на 127.0.0.1.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const T: Duration = Duration::from_secs(10);

/// Как отвечает тестовый «DNS-сервер интернета».
fn answer_for(q: &Message, ip: Ipv4Addr) -> Message {
    let mut r = Message::response(q.metadata.id, OpCode::Query);
    r.metadata.recursion_available = true;
    r.add_queries(q.queries.iter().cloned());
    let question = &q.queries[0];
    let name = question.name().to_ascii().to_ascii_lowercase();
    if name.starts_with("nx.") {
        r.metadata.response_code = ResponseCode::NXDomain;
    } else if name.starts_with("big.") && question.query_type() == RecordType::A {
        for i in 0..60u8 {
            r.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(A::new(10, 0, 0, i)),
            ));
        }
    } else if question.query_type() == RecordType::A {
        r.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A(ip)),
        ));
    }
    r
}

struct Upstream {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

/// UDP + TCP DNS-сервер на одном порту; на всё отвечает адресом `ip`.
async fn upstream(ip: Ipv4Addr) -> Upstream {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let q2 = queries.clone();
    tokio::spawn(async move {
        let mut b = [0u8; 4096];
        while let Ok((n, from)) = udp.recv_from(&mut b).await {
            q2.fetch_add(1, Ordering::SeqCst);
            let q = Message::from_vec(&b[..n]).unwrap();
            let mut a = answer_for(&q, ip).to_vec().unwrap();
            if a.len() > 512 {
                a = answer_for(&q, ip).truncate().to_vec().unwrap();
            }
            udp.send_to(&a, from).await.unwrap();
        }
    });
    let q3 = queries.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = tcp.accept().await {
            let q3 = q3.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    s.read_exact(&mut q).await.unwrap();
                    q3.fetch_add(1, Ordering::SeqCst);
                    let a = answer_for(&Message::from_vec(&q).unwrap(), ip)
                        .to_vec()
                        .unwrap();
                    let mut out = (a.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&a);
                    s.write_all(&out).await.unwrap();
                }
            });
        }
    });
    Upstream { addr, queries }
}

struct Tls {
    acceptor: tokio_rustls::TlsAcceptor,
    ca_file: PathBuf,
}

/// Сертификат на 127.0.0.1 и файл с ним для `ca_file`.
fn tls_setup(name: &str) -> Tls {
    reality_core::transport::tcp_tls::ensure_crypto_provider();
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    // Свой каталог на каждый вызов: тесты идут параллельно.
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("vpn-core-dns-{}-{name}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, ck.cert.pem()).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Tls {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(cfg)),
        ca_file,
    }
}

/// DNS over TLS на 127.0.0.1.
async fn dot_server(ip: Ipv4Addr) -> (SocketAddr, PathBuf) {
    let tls = tls_setup("dot");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acc = tls.acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acc.accept(s).await else {
                    return;
                };
                loop {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    s.read_exact(&mut q).await.unwrap();
                    let a = answer_for(&Message::from_vec(&q).unwrap(), ip)
                        .to_vec()
                        .unwrap();
                    let mut out = (a.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&a);
                    s.write_all(&out).await.unwrap();
                }
            });
        }
    });
    (addr, tls.ca_file)
}

/// DNS over HTTPS (HTTP/2, POST /dns-query) на 127.0.0.1.
async fn doh_server(ip: Ipv4Addr) -> (SocketAddr, PathBuf) {
    let tls = tls_setup("doh");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acc = tls.acceptor.clone();
            tokio::spawn(async move {
                let Ok(s) = acc.accept(s).await else { return };
                let Ok(mut conn) = h2::server::handshake(s).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    tokio::spawn(async move {
                        let ok = req.method() == "POST"
                            && req.uri().path() == "/dns-query"
                            && req.headers().get("content-type").map(|v| v.as_bytes())
                                == Some(b"application/dns-message");
                        let mut body = req.into_body();
                        let mut q = Vec::new();
                        while let Some(Ok(c)) = body.data().await {
                            let _ = body.flow_control().release_capacity(c.len());
                            q.extend_from_slice(&c);
                        }
                        let status = if ok { 200 } else { 400 };
                        let resp = http::Response::builder()
                            .status(status)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut tx = respond.send_response(resp, !ok).unwrap();
                        if ok {
                            let msg = Message::from_vec(&q).unwrap();
                            assert_eq!(msg.metadata.id, 0, "DoH: номер запроса 0 (RFC 8484)");
                            let a = answer_for(&msg, ip).to_vec().unwrap();
                            tx.send_data(Bytes::from(a), true).unwrap();
                        }
                    });
                }
            });
        }
    });
    (addr, tls.ca_file)
}

/// DNS over QUIC (RFC 9250) на 127.0.0.1: поток на запрос, длина + сообщение.
async fn doq_server(ip: Ipv4Addr) -> (SocketAddr, PathBuf, Arc<AtomicUsize>) {
    reality_core::transport::tcp_tls::ensure_crypto_provider();
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let dir = std::env::temp_dir().join(format!("vpn-core-doq-{}-{}", std::process::id(), ip));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, ck.cert.pem()).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let qc = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
    // Обычный сокет tokio (как запасной путь клиента): quinn-udp под Wine
    // не создаёт сокет (WSAEOPNOTSUPP на его параметрах).
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ep = reality_core::transport::quic::plain_endpoint(
        sock,
        Some(quinn::ServerConfig::with_crypto(Arc::new(qc))),
    )
    .unwrap();
    let addr = ep.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            let c2 = c2.clone();
            tokio::spawn(async move {
                let Ok(conn) = inc.await else { return };
                c2.fetch_add(1, Ordering::SeqCst);
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let mut len = [0u8; 2];
                        recv.read_exact(&mut len).await.unwrap();
                        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                        recv.read_exact(&mut q).await.unwrap();
                        let msg = Message::from_vec(&q).unwrap();
                        assert_eq!(msg.metadata.id, 0, "DoQ: номер запроса 0 (RFC 9250)");
                        let a = answer_for(&msg, ip).to_vec().unwrap();
                        let mut out = (a.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&a);
                        send.write_all(&out).await.unwrap();
                        send.finish().unwrap();
                    });
                }
            });
        }
    });
    (addr, ca_file, conns)
}

#[tokio::test]
async fn doq_server_works_and_reuses_connection() {
    let (doq, ca, conns) = doq_server(Ipv4Addr::new(4, 4, 4, 4)).await;
    let app = start(&dns_only(&format!(
        r#"{{ "type": "quic", "tag": "doq", "server": "{}", "server_port": {},
             "detour": "direct", "tls": {{ "certificate_path": {} }} }}"#,
        doq.ip(),
        doq.port(),
        q(&ca)
    )))
    .await;
    let dns = app.listen_addrs[0];
    for i in 0..20 {
        assert_eq!(
            ips(&ask_udp(dns, &format!("q{i}.example.net."), RecordType::A).await),
            [Ipv4Addr::new(4, 4, 4, 4)],
            "DoQ"
        );
    }
    assert_eq!(
        conns.load(Ordering::SeqCst),
        1,
        "одно QUIC-соединение на все запросы"
    );

    // Чужой сертификат — SERVFAIL, без ответа.
    let app = start(&dns_only(&format!(
        r#"{{ "tag": "doq", "address": "quic://{doq}", "detour": "direct" }}"#
    )))
    .await;
    let a = ask_udp(app.listen_addrs[0], "x.test.", RecordType::A).await;
    assert_eq!(a.metadata.response_code, ResponseCode::ServFail);
}

async fn start(json: &str) -> Running {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let cfg = Config::parse(json).unwrap_or_else(|e| panic!("{e}\n{json}"));
    App::build(&cfg)
        .unwrap_or_else(|e| panic!("{e}\n{json}"))
        .start()
        .await
        .expect("запуск")
}

fn query(name: &str, t: RecordType) -> Message {
    let mut m = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
    m
}

async fn ask_udp(server: SocketAddr, name: &str, t: RecordType) -> Message {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let q = query(name, t);
    s.send_to(&q.to_vec().unwrap(), server).await.unwrap();
    let mut b = [0u8; 4096];
    let (n, _) = tokio::time::timeout(T, s.recv_from(&mut b))
        .await
        .expect("ответ")
        .unwrap();
    let a = Message::from_vec(&b[..n]).unwrap();
    assert_eq!(a.metadata.id, q.metadata.id);
    a
}

async fn ask_tcp(server: SocketAddr, name: &str, t: RecordType) -> Message {
    let mut s = TcpStream::connect(server).await.unwrap();
    let q = query(name, t).to_vec().unwrap();
    let mut out = (q.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&q);
    s.write_all(&out).await.unwrap();
    let mut len = [0u8; 2];
    tokio::time::timeout(T, s.read_exact(&mut len))
        .await
        .unwrap()
        .unwrap();
    let mut a = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut a).await.unwrap();
    Message::from_vec(&a).unwrap()
}

fn ips(m: &Message) -> Vec<Ipv4Addr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect()
}

const OUTS: &str =
    r#""outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]"#;

/// DNS-сервер для программ: вход direct, чьи запросы — своему DNS.
const DNS_IN: &str =
    r#"{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 0}"#;
const HIJACK: &str = r#"{"inbound": ["dns-in"], "action": "hijack-dns"}"#;

/// Путь как строка JSON (на Windows — с экранированными «\\»).
fn q(p: &std::path::Path) -> String {
    serde_json::to_string(&p.display().to_string()).unwrap()
}

/// Только вход DNS и указанные DNS-серверы.
fn dns_only(servers: &str) -> String {
    format!(
        r#"{{"inbounds": [{DNS_IN}], {OUTS}, "route": {{"rules": [{HIJACK}]}},
            "dns": {{"servers": [{servers}]}}}}"#
    )
}

#[tokio::test]
async fn dns_inbound_udp_and_tcp_with_cache() {
    let up = upstream(Ipv4Addr::new(1, 2, 3, 4)).await;
    let app = start(&dns_only(&format!(
        r#"{{ "type": "udp", "tag": "up", "server": "{}", "server_port": {}, "detour": "direct" }}"#,
        up.addr.ip(),
        up.addr.port()
    )))
    .await;
    let dns = app.listen_addrs[0];
    let a = ask_udp(dns, "site.test.", RecordType::A).await;
    assert_eq!(ips(&a), [Ipv4Addr::new(1, 2, 3, 4)]);
    assert_eq!(up.queries.load(Ordering::SeqCst), 1);
    // Второй раз — из кеша (и по TCP тоже).
    let a = ask_tcp(dns, "SITE.test.", RecordType::A).await;
    assert_eq!(ips(&a), [Ipv4Addr::new(1, 2, 3, 4)]);
    assert_eq!(up.queries.load(Ordering::SeqCst), 1, "ответ из кеша");
    let a = ask_udp(dns, "nx.test.", RecordType::A).await;
    assert_eq!(a.metadata.response_code, ResponseCode::NXDomain);

    // Большой ответ: сервер урезал его по UDP — модуль переспросил по TCP,
    // а клиенту без EDNS по UDP отдаёт урезанный с флагом TC.
    let a = ask_udp(dns, "big.test.", RecordType::A).await;
    assert!(a.metadata.truncation, "клиенту без EDNS — урезанный ответ");
    let a = ask_tcp(dns, "big.test.", RecordType::A).await;
    assert_eq!(ips(&a).len(), 60, "по TCP — целиком");

    // Мусор вместо запроса не роняет вход.
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(b"\x12\x34garbage-garbage", dns).await.unwrap();
    let a = ask_udp(dns, "after.test.", RecordType::A).await;
    assert_eq!(ips(&a), [Ipv4Addr::new(1, 2, 3, 4)]);
}

#[tokio::test]
async fn rules_pick_server_and_dot_doh_work() {
    let plain = upstream(Ipv4Addr::new(1, 1, 1, 1)).await;
    let (dot, dot_ca) = dot_server(Ipv4Addr::new(2, 2, 2, 2)).await;
    let (doh, doh_ca) = doh_server(Ipv4Addr::new(3, 3, 3, 3)).await;
    let app = start(&format!(
        r#"{{
  "inbounds": [{DNS_IN}], {OUTS}, "route": {{ "rules": [{HIJACK}] }},
  "dns": {{
    "final": "doh",
    "servers": [
      {{ "tag": "plain", "address": "{}", "detour": "direct" }},
      {{ "type": "tls", "tag": "dot", "server": "{}", "server_port": {},
         "detour": "direct", "tls": {{ "certificate_path": {} }} }},
      {{ "type": "https", "tag": "doh", "server": "{}", "server_port": {},
         "detour": "direct", "tls": {{ "certificate_path": {} }} }}
    ],
    "rules": [
      {{ "domain_suffix": ["ru"], "server": "plain" }},
      {{ "domain_keyword": ["secure"], "server": "dot" }}
    ]
  }}
}}"#,
        plain.addr,
        dot.ip(),
        dot.port(),
        q(&dot_ca),
        doh.ip(),
        doh.port(),
        q(&doh_ca)
    ))
    .await;
    let dns = app.listen_addrs[0];
    assert_eq!(
        ips(&ask_udp(dns, "ya.ru.", RecordType::A).await),
        [Ipv4Addr::new(1, 1, 1, 1)]
    );
    assert_eq!(
        ips(&ask_udp(dns, "my-secure-site.com.", RecordType::A).await),
        [Ipv4Addr::new(2, 2, 2, 2)],
        "DoT"
    );
    assert_eq!(
        ips(&ask_udp(dns, "example.com.", RecordType::A).await),
        [Ipv4Addr::new(3, 3, 3, 3)],
        "DoH"
    );
    // Много запросов подряд по уже открытым соединениям DoT/DoH.
    for i in 0..20 {
        assert_eq!(
            ips(&ask_udp(dns, &format!("n{i}.secure.test."), RecordType::A).await),
            [Ipv4Addr::new(2, 2, 2, 2)]
        );
        assert_eq!(
            ips(&ask_tcp(dns, &format!("n{i}.example.org."), RecordType::A).await),
            [Ipv4Addr::new(3, 3, 3, 3)]
        );
    }
}

#[tokio::test]
async fn untrusted_dot_certificate_gives_servfail() {
    let (dot, _ca) = dot_server(Ipv4Addr::new(2, 2, 2, 2)).await;
    let app = start(&dns_only(&format!(
        r#"{{ "tag": "dot", "address": "tls://{dot}", "detour": "direct" }}"#
    )))
    .await;
    let a = ask_udp(app.listen_addrs[0], "x.test.", RecordType::A).await;
    assert_eq!(a.metadata.response_code, ResponseCode::ServFail);
    assert!(
        a.answers.is_empty(),
        "без доверенного сертификата ответа нет"
    );
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

async fn socks_connect(proxy: SocketAddr, host: &str, port: u16) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let mut req = vec![5, 1, 0];
    match host.parse::<Ipv4Addr>() {
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

#[tokio::test]
async fn fake_ip_end_to_end() {
    // «Настоящий» DNS знает, что echo.test — это 127.0.0.1.
    let up = upstream(Ipv4Addr::LOCALHOST).await;
    let echo = tcp_echo().await;
    let app = start(&format!(
        r#"{{
  "inbounds": [{DNS_IN}, {{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  {OUTS},
  "route": {{ "rules": [{HIJACK}], "final": "direct" }},
  "dns": {{
    "final": "fake",
    "servers": [
      {{ "type": "fakeip", "tag": "fake" }},
      {{ "tag": "real", "address": "udp://{}", "detour": "direct" }}
    ],
    "rules": [{{ "domain": ["real.test"], "server": "real" }}]
  }}
}}"#,
        up.addr
    ))
    .await;
    let (dns, proxy) = (app.listen_addrs[0], app.listen_addrs[1]);

    let a = ask_udp(dns, "echo.test.", RecordType::A).await;
    let fake = ips(&a)[0];
    assert_eq!(fake, Ipv4Addr::new(198, 18, 0, 2));
    assert_eq!(a.answers[0].ttl, 1, "fake-IP — с коротким TTL");
    assert_eq!(
        up.queries.load(Ordering::SeqCst),
        0,
        "fake-IP не спрашивает никого"
    );
    // AAAA — из IPv6-диапазона; HTTPS — пусто.
    let a6 = ask_udp(dns, "echo.test.", RecordType::AAAA).await;
    assert_eq!(a6.answers.len(), 1);
    assert!(ask_udp(dns, "echo.test.", RecordType::HTTPS)
        .await
        .answers
        .is_empty());
    // Исключение по правилу — настоящий ответ.
    assert_eq!(
        ips(&ask_udp(dns, "real.test.", RecordType::A).await),
        [Ipv4Addr::LOCALHOST]
    );

    // Приложение соединяется с fake-IP — прокси подставляет имя, direct
    // разрешает его настоящим DNS и соединяется.
    let (mut s, code) = socks_connect(proxy, &fake.to_string(), echo.port()).await;
    assert_eq!(code, 0);
    s.write_all(b"via fake ip").await.unwrap();
    let mut b = [0u8; 11];
    tokio::time::timeout(T, s.read_exact(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b, b"via fake ip");
    assert!(
        up.queries.load(Ordering::SeqCst) >= 1,
        "direct спросил настоящий DNS"
    );

    // Адрес из диапазона, которого модуль не выдавал, — отказ.
    let (_s, code) = socks_connect(proxy, "198.18.3.3", echo.port()).await;
    assert_ne!(code, 0);

    // UDP к fake-IP: ответ приходит «от» fake-IP, как приложение и ждёт.
    let echo_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let eport = echo_udp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = echo_udp.recv_from(&mut b).await {
            let _ = echo_udp.send_to(&b[..n], from).await;
        }
    });
    let ufake = ips(&ask_udp(dns, "udp-echo.test.", RecordType::A).await)[0];
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
    let mut hdr = vec![0, 0, 0, 1];
    hdr.extend_from_slice(&ufake.octets());
    hdr.extend_from_slice(&eport.to_be_bytes());
    let mut dg = hdr.clone();
    dg.extend_from_slice(b"udp via fake");
    app_udp.send_to(&dg, relay).await.unwrap();
    let mut b = [0u8; 2048];
    let (n, _) = tokio::time::timeout(T, app_udp.recv_from(&mut b))
        .await
        .expect("UDP-ответ")
        .unwrap();
    assert_eq!(&b[..10], &hdr[..], "источник ответа — fake-IP");
    assert_eq!(&b[10..n], b"udp via fake");
}

#[tokio::test]
async fn dns_outbound_hijacks_port_53() {
    let up = upstream(Ipv4Addr::new(5, 6, 7, 8)).await;
    let app = start(&format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  {OUTS},
  "route": {{ "rules": [{{ "port": 53, "action": "hijack-dns" }}], "final": "block" }},
  "dns": {{ "servers": [{{ "tag": "up", "address": "udp://{}", "detour": "direct" }}] }}
}}"#,
        up.addr
    ))
    .await;
    let proxy = app.listen_addrs[0];
    // DNS по TCP к «чужому» серверу 9.9.9.9:53 — отвечает модуль.
    let (mut s, code) = socks_connect(proxy, "9.9.9.9", 53).await;
    assert_eq!(code, 0);
    let q = query("hijack.test.", RecordType::A).to_vec().unwrap();
    let mut out = (q.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&q);
    s.write_all(&out).await.unwrap();
    let mut len = [0u8; 2];
    tokio::time::timeout(T, s.read_exact(&mut len))
        .await
        .unwrap()
        .unwrap();
    let mut a = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut a).await.unwrap();
    assert_eq!(
        ips(&Message::from_vec(&a).unwrap()),
        [Ipv4Addr::new(5, 6, 7, 8)]
    );

    // И по UDP через SOCKS5 UDP ASSOCIATE.
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
    let mut dg = vec![0, 0, 0, 1, 8, 8, 8, 8, 0, 53];
    dg.extend_from_slice(&query("udp-hijack.test.", RecordType::A).to_vec().unwrap());
    app_udp.send_to(&dg, relay).await.unwrap();
    let mut b = [0u8; 2048];
    let (n, _) = tokio::time::timeout(T, app_udp.recv_from(&mut b))
        .await
        .expect("ответ")
        .unwrap();
    assert_eq!(&b[4..10], &[8, 8, 8, 8, 0, 53], "ответ «от» 8.8.8.8:53");
    assert_eq!(
        ips(&Message::from_vec(&b[10..n]).unwrap()),
        [Ipv4Addr::new(5, 6, 7, 8)]
    );
}

#[tokio::test]
async fn ip_if_non_match_resolves_for_ip_rules() {
    let up = upstream(Ipv4Addr::LOCALHOST).await;
    let echo = tcp_echo().await;
    let cfg = |strategy: &str| {
        format!(
            r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  {OUTS},
  "route": {{
    "rules": [{{ "ip_cidr": ["127.0.0.0/8"], "outbound": "block" }}],
    "final": "direct",
    "domain_strategy": "{strategy}"
  }},
  "dns": {{ "servers": [{{ "tag": "up", "address": "udp://{}", "detour": "direct" }}] }}
}}"#,
            up.addr
        )
    };
    // as_is: правило по IP к имени не применяется — соединение идёт.
    let app = start(&cfg("as_is")).await;
    let (_s, code) = socks_connect(app.listen_addrs[0], "local.test", echo.port()).await;
    assert_eq!(code, 0);
    // ip_if_non_match: имя разрешено (в 127.0.0.1) — сработало правило block.
    let app = start(&cfg("ip_if_non_match")).await;
    let (_s, code) = socks_connect(app.listen_addrs[0], "local.test", echo.port()).await;
    assert_eq!(code, 2);
}

#[test]
fn dns_config_errors() {
    // inbounds, outbounds (после direct), route, dns — фрагментами JSON.
    let cfg = |inb: &str, outs: &str, route: &str, dns: &str| {
        format!(
            r#"{{"inbounds": [{inb}], "outbounds": [{{"type": "direct", "tag": "direct"}}{outs}],
                "route": {{{route}}}{dns}}}"#
        )
    };
    let err =
        |json: String| match App::build(&Config::parse(&json).unwrap_or_else(|e| panic!("{e}"))) {
            Ok(_) => panic!("должна быть ошибка:\n{json}"),
            Err(e) => e.to_string(),
        };
    let socks = r#"{"type": "socks", "listen": "127.0.0.1", "listen_port": 1}"#;
    let dns_ok =
        r#", "dns": {"servers": [{"tag": "up", "address": "1.1.1.1", "detour": "direct"}]}"#;
    let dns_in = |listen: &str| {
        format!(r#"{{"type": "direct", "tag": "dns-in", "listen": "{listen}", "listen_port": 53}}"#)
    };
    let hijack = r#""rules": [{"inbound": ["dns-in"], "action": "hijack-dns"}]"#;

    let e = err(cfg(&dns_in("0.0.0.0"), "", hijack, dns_ok));
    assert!(e.contains("открытый"), "{e}");
    let e = err(cfg(&dns_in("127.0.0.1"), "", hijack, ""));
    assert!(e.contains("раздел"), "{e}");
    let e = err(cfg(
        socks,
        "",
        r#""domain_strategy": "ip_if_non_match""#,
        "",
    ));
    assert!(e.contains("раздел"), "{e}");
    let e = err(cfg(socks, r#", {"type": "dns", "tag": "d"}"#, "", ""));
    assert!(e.contains("раздел"), "{e}");
    let e = err(cfg(
        socks,
        "",
        "",
        r#", "dns": {"servers": [{"tag": "up", "address": "1.1.1.1", "detour": "direct"}],
                   "rules": [{"domain": ["a"], "server": "nope"}]}"#,
    ));
    assert!(e.contains("nope"), "{e}");
    let e = err(cfg(
        socks,
        "",
        "",
        r#", "dns": {"servers": [{"tag": "x", "address": "udp://dns.google"}]}"#,
    ));
    assert!(e.contains("IP"), "{e}");
    let e = err(cfg(
        socks,
        r#", {"type": "dns", "tag": "d"}"#,
        "",
        r#", "dns": {"servers": [{"tag": "x", "address": "1.1.1.1", "detour": "d"}]}"#,
    ));
    assert!(e.contains("петля"), "{e}");
    let e = err(cfg(
        socks,
        "",
        "",
        r#", "dns": {"servers": [{"type": "fakeip", "tag": "f"}]}"#,
    ));
    assert!(e.contains("настоящий"), "{e}");
    let e = err(cfg(
        socks,
        "",
        "",
        r#", "dns": {"servers": [{"tag": "up", "address": "1.1.1.1", "detour": "direct"}],
                   "fakeip": {"enabled": true, "inet4_range": "198.18.0.0/15"}}"#,
    ));
    assert!(e.contains("fakeip"), "{e}");
    let e = err(cfg(
        socks,
        "",
        "",
        r#", "dns": {"servers": [{"tag": "x", "address": "1.1.1.1", "detour": "nope"}]}"#,
    ));
    assert!(e.contains("nope"), "{e}");
    // Вход direct без правила hijack-dns — не DNS-сервер: ошибка разбора.
    let e = Config::parse(&cfg(&dns_in("127.0.0.1"), "", "", dns_ok))
        .unwrap_err()
        .to_string();
    assert!(e.contains("hijack-dns"), "{e}");
    // Без detour — через route.final (здесь его нет — первый выход).
    App::build(
        &Config::parse(&cfg(
            socks,
            "",
            "",
            r#", "dns": {"servers": [{"tag": "x", "address": "tls://1.1.1.1"}]}"#,
        ))
        .unwrap(),
    )
    .expect("detour по умолчанию");
}
