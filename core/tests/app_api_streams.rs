// SPDX-License-Identifier: GPL-3.0-or-later
//! Потоки API: `/events`, `/traffic`, `/memory`, `/logs` — построчный
//! JSON (chunked) и WebSocket.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::StreamExt;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const T: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token-0123456789abcdef";

fn config() -> String {
    format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  "outbounds": [
    {{ "type": "selector", "tag": "sel", "outbounds": ["direct", "block"] }},
    {{ "type": "direct", "tag": "direct" }},
    {{ "type": "block", "tag": "block" }}
  ],
  "experimental": {{ "clash_api": {{ "external_controller": "127.0.0.1:0", "secret": "{TOKEN}" }} }},
  "route": {{ "final": "sel" }}
}}"#
    )
}

async fn start() -> Running {
    let cfg = Config::parse(&config()).expect("настройки");
    App::build(&cfg)
        .expect("сборка")
        .start()
        .await
        .expect("запуск")
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

/// SOCKS5-соединение через вход и эхо «ping».
async fn echo_through(proxy: SocketAddr, dst: SocketAddr) -> TcpStream {
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
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    s
}

/// Открытый поток: построчный JSON поверх chunked.
struct Feed {
    r: BufReader<TcpStream>,
}

impl Feed {
    async fn open(api: SocketAddr, path: &str) -> (u16, Feed) {
        let mut s = TcpStream::connect(api).await.unwrap();
        let req =
            format!("GET {path} HTTP/1.1\r\nHost: {api}\r\nAuthorization: Bearer {TOKEN}\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut r = BufReader::new(s);
        let mut status = String::new();
        r.read_line(&mut status).await.unwrap();
        let code: u16 = status.split_whitespace().nth(1).unwrap().parse().unwrap();
        loop {
            let mut l = String::new();
            r.read_line(&mut l).await.unwrap();
            if l == "\r\n" || l.is_empty() {
                break;
            }
        }
        (code, Feed { r })
    }

    /// Следующий объект (размер куска — строкой, затем JSON и \r\n).
    async fn next(&mut self) -> Value {
        tokio::time::timeout(T, async {
            let mut size = String::new();
            self.r.read_line(&mut size).await.unwrap();
            let n = usize::from_str_radix(size.trim(), 16).expect("размер куска");
            let mut b = vec![0u8; n + 2];
            self.r.read_exact(&mut b).await.unwrap();
            assert!(b.ends_with(b"\n\r\n"), "объект на строку");
            serde_json::from_slice(&b[..n]).unwrap()
        })
        .await
        .expect("поток молчит")
    }

    /// Следующее событие типа `ty` (остальные пропускаются).
    async fn next_of(&mut self, ty: &str) -> Value {
        loop {
            let v = self.next().await;
            if v["type"] == ty {
                return v;
            }
        }
    }
}

#[tokio::test]
async fn events_stream_connections_groups_reload() {
    let echo = tcp_echo().await;
    let r = start().await;
    let api = r.api_addr.unwrap();
    let (code, mut ev) = Feed::open(api, "/events").await;
    assert_eq!(code, 200);

    let s = echo_through(r.listen_addrs[0], echo).await;
    let open = ev.next_of("connection_open").await;
    assert_eq!(open["outbound"], "sel");
    assert_eq!(open["member"], "direct");
    assert_eq!(open["port"], echo.port());
    drop(s);
    let close = ev.next_of("connection_close").await;
    assert_eq!(close["id"], open["id"]);
    assert_eq!(close["up"], 4);
    assert_eq!(close["down"], 4);

    // Ручной выбор в группе.
    let mut c = TcpStream::connect(api).await.unwrap();
    let body = r#"{"member":"block"}"#;
    let req = format!(
        "PUT /groups/sel HTTP/1.1\r\nHost: {api}\r\nAuthorization: Bearer {TOKEN}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    c.read_to_end(&mut resp).await.unwrap();
    let sw = ev.next_of("group_switch").await;
    assert_eq!(sw["group"], "sel");
    assert_eq!(sw["member"], "block");
    assert_eq!(sw["previous"], "direct");
    assert_eq!(sw["manual"], true);

    // Перечитывание настроек.
    r.reload(Config::parse(&config()).unwrap()).await.unwrap();
    let rl = ev.next_of("reload").await;
    assert_eq!(rl["notes"], serde_json::json!([]));
}

#[tokio::test]
async fn traffic_stream_counts_bytes() {
    let echo = tcp_echo().await;
    let r = start().await;
    let (code, mut tr) = Feed::open(r.api_addr.unwrap(), "/traffic").await;
    assert_eq!(code, 200);
    let _s = echo_through(r.listen_addrs[0], echo).await;
    // Не позже чем через пару секунд — байты эха в upTotal/downTotal.
    let mut seen = false;
    for _ in 0..4 {
        let v = tr.next().await;
        assert!(v["up"].is_u64() && v["down"].is_u64(), "{v}");
        if v["upTotal"].as_u64() >= Some(4) && v["downTotal"].as_u64() >= Some(4) {
            seen = true;
            break;
        }
    }
    assert!(seen, "трафик не попал в поток");
}

#[tokio::test]
async fn logs_stream_filters_by_level() {
    use tracing_subscriber::layer::SubscriberExt;
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(reality_core::app::events::LogLayer),
    );
    let r = start().await;
    let api = r.api_addr.unwrap();
    let (code, _) = Feed::open(api, "/logs?level=loud").await;
    assert_eq!(code, 400);
    let (code, mut logs) = Feed::open(api, "/logs?level=warning").await;
    assert_eq!(code, 200);
    // Поток подписан, когда пришли заголовки ответа.
    tracing::info!("не должно попасть");
    tracing::warn!(key = 7, "проверка потока журнала");
    // Журнал общий на процесс: соседние тесты тоже пишут — ждём своё.
    loop {
        let v = logs.next().await;
        assert!(v["type"] == "warning" || v["type"] == "error", "{v}");
        let p = v["payload"].as_str().unwrap();
        assert!(!p.contains("не должно попасть"), "{p}");
        if p.contains("проверка потока журнала") {
            assert!(p.contains("key=7"), "{p}");
            break;
        }
    }
}

#[tokio::test]
async fn streams_require_token_and_close_with_client() {
    let r = start().await;
    let api = r.api_addr.unwrap();
    let mut s = TcpStream::connect(api).await.unwrap();
    s.write_all(format!("GET /events HTTP/1.1\r\nHost: {api}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(T, s.read_to_end(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert!(resp.starts_with(b"HTTP/1.1 401"));

    // Закрытые клиентом потоки освобождают места: 40 подряд при лимите 16.
    for _ in 0..40 {
        let (code, f) = Feed::open(api, "/events").await;
        assert_eq!(code, 200);
        drop(f);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn memory_over_websocket() {
    use async_tungstenite::tungstenite::client::IntoClientRequest;
    use async_tungstenite::tungstenite::Message;
    let r = start().await;
    let api = r.api_addr.unwrap();
    let tcp = TcpStream::connect(api).await.unwrap();
    let mut req = format!("ws://{api}/memory").into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {TOKEN}").parse().unwrap());
    let (mut ws, resp) = async_tungstenite::client_async(req, tcp.compat())
        .await
        .expect("WebSocket");
    assert_eq!(resp.status(), 101);
    let m = tokio::time::timeout(T, ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Text(t) = m else { panic!("{m:?}") };
    let v: Value = serde_json::from_str(&t).unwrap();
    if cfg!(target_os = "linux") {
        assert!(v["inuse"].as_u64().unwrap() > 1 << 20, "{v}");
    }
    assert_eq!(v["oslimit"], 0);
    ws.close(None).await.unwrap();
}
