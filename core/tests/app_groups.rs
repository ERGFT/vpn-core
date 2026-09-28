// SPDX-License-Identifier: GPL-3.0-or-later
//! Фаза 4: группы серверов (selector, urltest, fallback) и подписки.
//! Панель подписки — HTTPS-сервер на 127.0.0.1 со своим сертификатом.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const T: Duration = Duration::from_secs(10);

fn tmp_dir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("vpn-core-groups-{}-{name}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn start(json: &str) -> Running {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let cfg = Config::parse(json).expect("настройки");
    App::build(&cfg)
        .expect("сборка")
        .start()
        .await
        .expect("запуск")
}

fn build_err(json: &str) -> String {
    match Config::parse(json) {
        Err(e) => e.to_string(),
        Ok(c) => match App::build(&c) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("должна быть ошибка:\n{json}"),
        },
    }
}

/// Путь как строка JSON (на Windows — с экранированными «\\»).
fn q(p: &std::path::Path) -> String {
    serde_json::to_string(&p.display().to_string()).unwrap()
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

/// HTTP-сервер проверки: на всё отвечает 204. Считает запросы.
async fn probe_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let h = h.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(s);
                let mut line = String::new();
                loop {
                    line.clear();
                    if r.read_line(&mut line).await.unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                h.fetch_add(1, Ordering::SeqCst);
                let _ = r
                    .get_mut()
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    (a, hits)
}

/// SOCKS5 CONNECT на IPv4; код ответа.
async fn socks_connect(proxy: SocketAddr, dst: SocketAddr) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let SocketAddr::V4(v4) = dst else { panic!() };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(T, s.read_exact(&mut rep))
        .await
        .unwrap()
        .unwrap();
    (s, rep[1])
}

async fn echo_ok(s: &mut TcpStream) -> bool {
    if s.write_all(b"ping").await.is_err() {
        return false;
    }
    let mut b = [0u8; 4];
    matches!(
        tokio::time::timeout(T, s.read_exact(&mut b)).await,
        Ok(Ok(_))
    ) && &b == b"ping"
}

/// Порт, на котором никто не слушает.
async fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_for<F: Fn() -> bool>(f: F) -> bool {
    for _ in 0..100 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn urltest_picks_working_member_and_fallback_skips_dead() {
    let echo = tcp_echo().await;
    let (probe, hits) = probe_server().await;
    let dead = dead_port().await;
    let json = format!(
        r#"{{
  "inbounds": [
    {{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }},
    {{ "type": "socks", "tag": "via-safe", "listen": "127.0.0.1", "listen_port": 0 }},
    {{ "type": "socks", "tag": "via-manual", "listen": "127.0.0.1", "listen_port": 0 }}
  ],
  "outbounds": [
    {{ "type": "urltest", "tag": "auto", "outbounds": ["dead", "direct"],
       "url": "http://{probe}/generate_204", "interval": "10s" }},
    {{ "type": "fallback", "tag": "safe", "outbounds": ["dead", "direct"],
       "url": "http://{probe}/generate_204" }},
    {{ "type": "selector", "tag": "manual", "outbounds": ["auto", "safe", "dead"], "default": "dead" }},
    {{ "type": "vless", "tag": "dead", "server": "127.0.0.1", "server_port": {dead},
       "uuid": "11111111-1111-1111-1111-111111111111", "allow_insecure": true }},
    {{ "type": "direct", "tag": "direct" }}
  ],
  "route": {{
    "final": "auto",
    "rules": [
      {{ "inbound": ["via-safe"], "outbound": "safe" }},
      {{ "inbound": ["via-manual"], "outbound": "manual" }}
    ]
  }}
}}"#
    );
    let r = start(&json).await;
    let auto = r.group("auto").unwrap().clone();
    assert!(
        wait_for(|| auto.current().as_deref() == Some("direct")).await,
        "urltest выбрал рабочего: {:?}",
        auto.current()
    );
    assert!(hits.load(Ordering::SeqCst) >= 1, "проверка шла на url");
    let members = auto.members();
    assert_eq!(members.len(), 2);
    assert!(members[0].delay().is_none(), "мёртвый помечен");
    assert!(members[1].delay().is_some(), "у рабочего есть задержка");

    // Через urltest.
    let (mut s, rep) = socks_connect(r.listen_addrs[0], echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut s).await);
    // fallback: первый мёртв — соединение всё равно проходит.
    let (mut s, rep) = socks_connect(r.listen_addrs[1], echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut s).await);
    // selector смотрит на мёртвого: ошибка, без перебора других.
    let (_s, rep) = socks_connect(r.listen_addrs[2], echo).await;
    assert_ne!(rep, 0);
    let manual = r.group("manual").unwrap();
    manual.select("safe").unwrap();
    assert!(manual.select("nope").is_err());
    let (mut s, rep) = socks_connect(r.listen_addrs[2], echo).await;
    assert_eq!(rep, 0, "после выбора другого участника — работает");
    assert!(echo_ok(&mut s).await);
}

struct Panel {
    addr: SocketAddr,
    ca_file: PathBuf,
    hits: Arc<AtomicUsize>,
    /// Что отдавать; `None` — 503.
    body: Arc<std::sync::Mutex<Option<String>>>,
}

/// Панель подписки: HTTPS, GET /sub/<токен>.
async fn panel() -> Panel {
    reality_core::transport::tcp_tls::ensure_crypto_provider();
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let ca_file = tmp_dir("ca").join("ca.pem");
    std::fs::write(&ca_file, ck.cert.pem()).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let body: Arc<std::sync::Mutex<Option<String>>> = Arc::default();
    let (h, b) = (hits.clone(), body.clone());
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (acc, h, b) = (acc.clone(), h.clone(), b.clone());
            tokio::spawn(async move {
                let Ok(s) = acc.accept(s).await else { return };
                let mut r = BufReader::new(s);
                let mut first = String::new();
                r.read_line(&mut first).await.unwrap();
                let mut ua = String::new();
                let mut line = String::new();
                loop {
                    line.clear();
                    if r.read_line(&mut line).await.unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if line.to_ascii_lowercase().starts_with("user-agent:") {
                        ua = line[11..].trim().to_string();
                    }
                }
                h.fetch_add(1, Ordering::SeqCst);
                assert_eq!(ua, "v2rayN/7.10.0");
                let resp = match (first.starts_with("GET /sub/s3cret "), b.lock().unwrap().clone()) {
                    (true, Some(body)) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nsubscription-userinfo: upload=1; download=2; total=10\r\n\r\n{body}",
                        body.len()
                    ),
                    (false, _) => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".into(),
                    (true, None) => "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n".into(),
                };
                let _ = r.get_mut().write_all(resp.as_bytes()).await;
                let _ = r.get_mut().shutdown().await;
            });
        }
    });
    Panel {
        addr,
        ca_file,
        hits,
        body,
    }
}

fn reality_link(name: &str, port: u16) -> String {
    let pbk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    format!(
        "vless://22222222-2222-2222-2222-22222222222{}@127.0.0.1:{port}?security=reality&sni=www.site.test&pbk={pbk}&sid=ab&type=tcp#{name}",
        name.len() % 10
    )
}

#[tokio::test]
async fn subscription_loads_caches_and_survives_panel_outage() {
    let p = panel().await;
    let dead = dead_port().await;
    let list = format!(
        "{}\n{}\nvless://33333333-3333-3333-3333-333333333333@127.0.0.1:{dead}?security=none&type=tcp#plain\nvmess://eyJ2IjoyfQ==\n",
        reality_link("Germany", dead),
        reality_link("Finland", dead),
    );
    *p.body.lock().unwrap() = Some(base64::engine::general_purpose::STANDARD.encode(list));
    let dir = tmp_dir("sub");
    let url_file = dir.join("sub-url.txt");
    std::fs::write(&url_file, format!("https://{}/sub/s3cret\n", p.addr)).unwrap();
    let cache = dir.join("panel.subscription");
    let json = format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  "outbounds": [
    {{ "type": "selector", "tag": "proxy", "outbounds": ["direct"], "subscriptions": ["panel"] }},
    {{ "type": "direct", "tag": "direct" }}
  ],
  "subscriptions": [{{
    "tag": "panel", "url_file": {}, "ca_file": {}, "cache_file": {}, "detour": "direct"
  }}]
}}"#,
        q(&url_file),
        q(&p.ca_file),
        q(&cache)
    );
    let r = start(&json).await;
    let g = r.group("proxy").unwrap().clone();
    assert!(
        wait_for(|| g.members().len() == 3).await,
        "подписка загружена: {:?}",
        g.members()
            .iter()
            .map(|m| m.tag().to_string())
            .collect::<Vec<_>>()
    );
    let tags: Vec<String> = g.members().iter().map(|m| m.tag().to_string()).collect();
    assert_eq!(tags, ["direct", "panel/Germany", "panel/Finland"]);
    assert!(cache.exists(), "список сохранён");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cache).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "в списке UUID — только владельцу");
    }
    g.select("panel/Finland").unwrap();
    drop(r);

    // Панель недоступна — список берётся из сохранённого сразу при старте.
    *p.body.lock().unwrap() = None;
    let before = p.hits.load(Ordering::SeqCst);
    let r = start(&json).await;
    let g = r.group("proxy").unwrap();
    assert_eq!(g.members().len(), 3, "из сохранённого списка");
    // Сохранённый список свежий — панель при старте не дёргается.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(p.hits.load(Ordering::SeqCst), before);
    drop(r);

    // Без сохранённого списка: панель отвечает 503 — группа работает
    // с участниками из настроек.
    std::fs::remove_file(&cache).unwrap();
    let r = start(&json).await;
    assert!(wait_for(|| p.hits.load(Ordering::SeqCst) > before).await);
    let g = r.group("proxy").unwrap();
    assert_eq!(g.members().len(), 1);
    let echo = tcp_echo().await;
    let (mut s, rep) = socks_connect(r.listen_addrs[0], echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut s).await);
}

#[tokio::test]
async fn subscription_with_wrong_certificate_is_not_applied() {
    let p = panel().await;
    *p.body.lock().unwrap() = Some(reality_link("X", 1));
    let dir = tmp_dir("badca");
    let json = format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  "outbounds": [
    {{ "type": "urltest", "tag": "proxy", "subscriptions": ["panel"] }},
    {{ "type": "direct", "tag": "direct" }}
  ],
  "subscriptions": [{{
    "tag": "panel", "url": "https://{}/sub/s3cret", "cache_file": {}, "detour": "direct"
  }}]
}}"#,
        p.addr,
        q(&dir.join("c"))
    );
    let r = start(&json).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    // Сертификат не прошёл проверку — запрос не дошёл до HTTP.
    assert_eq!(p.hits.load(Ordering::SeqCst), 0);
    assert!(r.group("proxy").unwrap().members().is_empty());
}

#[test]
fn group_and_subscription_config_errors() {
    // (выходы после direct, подписки, ожидаемый текст ошибки)
    let v = |extra: &str| {
        format!(
            r#"{{"type": "vless", "tag": "v", "server": "h.example", "server_port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111", "tls": {{"enabled": true}}{extra}}}"#
        )
    };
    let sel_s = r#"{"type": "selector", "tag": "g", "subscriptions": ["s"]}"#;
    let cases: Vec<(String, &str, &str)> = vec![
        (r#"{"type": "selector", "tag": "g"}"#.into(), "", "нет участников"),
        (r#"{"type": "urltest", "tag": "g", "outbounds": ["nope"]}"#.into(), "", "нет выхода «nope»"),
        (
            r#"{"type": "selector", "tag": "a", "outbounds": ["b"]}, {"type": "fallback", "tag": "b", "outbounds": ["a"]}"#.into(),
            "",
            "по кругу",
        ),
        (r#"{"type": "selector", "tag": "a", "outbounds": ["a"]}"#.into(), "", "по кругу"),
        (r#"{"type": "selector", "tag": "g", "outbounds": ["direct"], "default": "x"}"#.into(), "", "не участник"),
        (r#"{"type": "urltest", "tag": "g", "outbounds": ["direct"], "default": "direct"}"#.into(), "", "только у selector"),
        (r#"{"type": "selector", "tag": "g", "outbounds": ["direct"], "interval": "1m"}"#.into(), "", "url и interval не нужны"),
        (r#"{"type": "urltest", "tag": "g", "outbounds": ["direct"], "interval": "1s"}"#.into(), "", "interval меньше"),
        (r#"{"type": "direct", "tag": "d2", "outbounds": ["direct"]}"#.into(), "", "ключи: outbounds"),
        (r#"{"type": "selector", "tag": "g", "outbounds": ["direct"], "link": "vless://x"}"#.into(), "", "ключи: link"),
        (sel_s.into(), "", "нет подписки «s»"),
        ("".into(), r#"{"tag": "s", "url": "https://p.example/x"}"#, "не входит ни в одну группу"),
        (sel_s.into(), r#"{"tag": "s", "url": "http://p.example/x"}"#, "должен быть https"),
        (
            r#"{"type": "selector", "tag": "g", "subscriptions": ["../s"]}"#.into(),
            r#"{"tag": "../s", "url": "https://p.example/x"}"#,
            "латиница",
        ),
        (
            r#"{"type": "selector", "tag": "g", "subscriptions": ["direct"]}"#.into(),
            r#"{"tag": "direct", "url": "https://p.example/x"}"#,
            "уже есть",
        ),
        (sel_s.into(), r#"{"tag": "s"}"#, "нужен url"),
        (sel_s.into(), r#"{"tag": "s", "url": "https://p.example/x", "include": "("}"#, "include"),
        (sel_s.into(), r#"{"tag": "s", "url": "https://p.example/x", "detour": "nope"}"#, "detour"),
        (r#"{"type": "direct", "tag": "d2", "mux": 8}"#.into(), "", "ключи: mux"),
        (v(r#", "mux": 8, "flow": "xtls-rprx-vision""#), "", "несовместим"),
        (v(r#", "mux": 0"#), "", "от 1 до 128"),
    ];
    for (outs, subs, want) in &cases {
        let outs = if outs.is_empty() {
            String::new()
        } else {
            format!(", {outs}")
        };
        let e = build_err(&format!(
            r#"{{"inbounds": [{{"type": "socks", "listen": "127.0.0.1", "listen_port": 0}}],
                "outbounds": [{{"type": "direct", "tag": "direct"}}{outs}],
                "subscriptions": [{subs}]}}"#
        ));
        assert!(e.contains(want), "{outs} {subs}\n→ {e}\nожидалось: {want}");
    }
}
