// SPDX-License-Identifier: GPL-3.0-or-later
//! Совместимость с Clash API: форматы ответов (сверены с sing-box 1.12),
//! режимы rule/global/direct, группа GLOBAL, задержки, CORS, WebSocket с
//! `?token=`, раздача веб-панели (`external_ui`).

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const T: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token-0123456789abcdef";

/// selector `sel` смотрит на block (первый), `final` — sel.
fn config(api_extra: &str) -> String {
    format!(
        r#"{{
  "inbounds": [{{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0 }}],
  "outbounds": [
    {{ "type": "selector", "tag": "sel", "outbounds": ["block", "direct"] }},
    {{ "type": "direct", "tag": "direct" }},
    {{ "type": "block", "tag": "block" }}
  ],
  "route": {{
    "rules": [{{ "domain_suffix": ["example.org"], "action": "reject" }}],
    "final": "sel"
  }},
  "experimental": {{ "clash_api": {{
    "external_controller": "127.0.0.1:0", "secret": "{TOKEN}"{api_extra}
  }} }}
}}"#
    )
}

async fn start(json: &str) -> Running {
    let cfg = Config::parse(json).expect("настройки");
    App::build(&cfg)
        .expect("сборка")
        .start()
        .await
        .expect("запуск")
}

/// Ответ: код, заголовки строкой, тело.
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
    extra: &str,
) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(T, s.read_to_end(&mut resp))
        .await
        .unwrap()
        .unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(resp[..split].to_vec()).unwrap();
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, head, resp[split + 4..].to_vec())
}

async fn call(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (c, _, b) = http(
        addr,
        method,
        path,
        body,
        &format!("Authorization: Bearer {TOKEN}\r\n"),
    )
    .await;
    (c, serde_json::from_slice(&b).unwrap_or(Value::Null))
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

/// HTTP-сервер, отвечающий 204 (для проверки задержки).
async fn http204() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            });
        }
    });
    a
}

/// SOCKS5 CONNECT через вход; код ответа (0 — соединено).
async fn socks(proxy: SocketAddr, dst: SocketAddr) -> (TcpStream, u8) {
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

#[tokio::test]
async fn clash_formats_match_sing_box() {
    let r = start(&config("")).await;
    let a = r.api_addr.unwrap();

    assert_eq!(call(a, "GET", "/", "").await.1, json!({ "hello": "clash" }));
    let (_, v) = call(a, "GET", "/version", "").await;
    assert_eq!(v["meta"], true);
    assert_eq!(v["premium"], true);
    assert!(v["version"].as_str().unwrap().starts_with("reality-core "));

    let (_, v) = call(a, "GET", "/configs", "").await;
    assert_eq!(v["mode"], "Rule");
    assert_eq!(v["mode-list"], json!(["Rule", "Global", "Direct"]));
    assert_eq!(v["mixed-port"], r.listen_addrs[0].port());
    assert_eq!(v["allow-lan"], false);

    let (_, v) = call(a, "GET", "/proxies", "").await;
    let p = &v["proxies"];
    assert_eq!(p["sel"]["type"], "Selector");
    assert_eq!(p["sel"]["now"], "block");
    assert_eq!(p["sel"]["all"], json!(["block", "direct"]));
    assert_eq!(p["sel"]["udp"], true);
    assert_eq!(p["sel"]["history"], json!([]));
    assert_eq!(p["direct"]["type"], "Direct");
    assert_eq!(p["block"]["type"], "Reject");
    assert!(p["direct"].get("now").is_none());
    // GLOBAL — как у Clash: все выходы, по умолчанию route.final.
    assert_eq!(p["GLOBAL"]["type"], "Selector");
    assert_eq!(p["GLOBAL"]["now"], "sel");
    assert_eq!(p["GLOBAL"]["all"], json!(["sel", "direct", "block"]));
    // Скрытые выходы действий sing-box наружу не видны.
    assert!(p.get("__reject").is_none());

    let (c, v) = call(a, "GET", "/proxies/sel", "").await;
    assert_eq!(c, 200);
    assert_eq!(v["name"], "sel");
    let (c, v) = call(a, "GET", "/proxies/nope", "").await;
    assert_eq!(c, 404);
    assert!(v["message"].is_string());

    let (_, v) = call(a, "GET", "/group", "").await;
    let names: Vec<&str> = v["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["sel", "GLOBAL"]);
    assert_eq!(call(a, "GET", "/group/sel", "").await.1["now"], "block");

    let (_, v) = call(a, "GET", "/rules", "").await;
    assert_eq!(
        v["rules"],
        json!([
            { "type": "default", "payload": "domain_suffix=example.org", "proxy": "reject" },
            { "type": "Match", "payload": "", "proxy": "sel" },
        ])
    );
    assert_eq!(
        call(a, "GET", "/providers/proxies", "").await.1,
        json!({ "providers": {} })
    );
    assert_eq!(
        call(a, "GET", "/providers/rules", "").await.1,
        json!({ "providers": {} })
    );

    // Соединений нет — формат снимка как у Clash.
    let (_, v) = call(a, "GET", "/connections", "").await;
    assert_eq!(v["connections"], json!([]));
    assert!(v["downloadTotal"].is_u64() && v["uploadTotal"].is_u64() && v["memory"].is_u64());

    // DNS без раздела dns — системный резолвер.
    let (c, v) = call(a, "GET", "/dns/query?name=localhost&type=A", "").await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["Status"], 0);
    assert!(v["Answer"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["data"] == "127.0.0.1"));
}

#[tokio::test]
async fn select_modes_and_global() {
    let echo = tcp_echo().await;
    let r = start(&config("")).await;
    let a = r.api_addr.unwrap();
    let proxy = r.listen_addrs[0];

    // rule: final → sel → block.
    assert_ne!(socks(proxy, echo).await.1, 0);
    // Выбор в selector — 204, как у sing-box; не участник и не selector — 400.
    assert_eq!(
        call(a, "PUT", "/proxies/sel", r#"{"name":"direct"}"#)
            .await
            .0,
        204
    );
    assert_eq!(call(a, "GET", "/proxies/sel", "").await.1["now"], "direct");
    let (c, v) = call(a, "PUT", "/proxies/sel", r#"{"name":"zzz"}"#).await;
    assert_eq!(c, 400);
    assert!(v["message"].is_string());
    assert_eq!(socks(proxy, echo).await.1, 0);
    assert_eq!(
        call(a, "PUT", "/proxies/sel", r#"{"name":"block"}"#)
            .await
            .0,
        204
    );

    // direct: всё напрямую, мимо правил.
    assert_eq!(
        call(a, "PATCH", "/configs", r#"{"mode":"direct"}"#).await.0,
        204
    );
    assert_eq!(call(a, "GET", "/configs", "").await.1["mode"], "Direct");
    let (_s, rep) = socks(proxy, echo).await;
    assert_eq!(rep, 0);
    let (_, v) = call(a, "GET", "/connections", "").await;
    assert_eq!(v["connections"][0]["rule"], "mode=direct");
    assert_eq!(v["connections"][0]["chains"], json!(["direct"]));

    // global: через GLOBAL (по умолчанию sel → block), потом выбрать direct.
    assert_eq!(
        call(a, "PATCH", "/configs", r#"{"mode":"Global"}"#).await.0,
        204
    );
    assert_ne!(socks(proxy, echo).await.1, 0);
    assert_eq!(
        call(a, "PUT", "/proxies/GLOBAL", r#"{"name":"direct"}"#)
            .await
            .0,
        204
    );
    assert_eq!(socks(proxy, echo).await.1, 0);

    // Неверный режим и чужие ключи — 400.
    assert_eq!(
        call(a, "PATCH", "/configs", r#"{"mode":"loud"}"#).await.0,
        400
    );
    let (c, v) = call(a, "PATCH", "/configs", r#"{"allow-lan":true}"#).await;
    assert_eq!(c, 400);
    assert!(v["message"].as_str().unwrap().contains("allow-lan"));

    // Обратно rule; выбор в группах переживает перечитывание настроек.
    assert_eq!(
        call(a, "PATCH", "/configs", r#"{"mode":"rule"}"#).await.0,
        204
    );
    assert_eq!(
        call(a, "PUT", "/proxies/sel", r#"{"name":"direct"}"#)
            .await
            .0,
        204
    );
    r.reload(Config::parse(&config("")).unwrap()).await.unwrap();
    assert_eq!(call(a, "GET", "/proxies/sel", "").await.1["now"], "direct");
    assert_eq!(
        call(a, "GET", "/proxies/GLOBAL", "").await.1["now"],
        "direct"
    );
    assert_eq!(call(a, "GET", "/configs", "").await.1["mode"], "Rule");
}

#[tokio::test]
async fn default_mode_from_config() {
    let r = start(&config(r#", "default_mode": "direct""#)).await;
    let (_, v) = call(r.api_addr.unwrap(), "GET", "/configs", "").await;
    assert_eq!(v["mode"], "Direct");
    let err = Config::parse(&config(r#", "default_mode": "fast""#)).unwrap_err();
    assert!(err.to_string().contains("default_mode"), "{err}");
    let err = Config::parse(&config(
        r#", "external_ui_download_url": "https://x/ui.zip""#,
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("external_ui_download_url"),
        "{err}"
    );
}

#[tokio::test]
async fn delay_checks_and_history() {
    let site = http204().await;
    let r = start(&config("")).await;
    let a = r.api_addr.unwrap();
    let url = format!("http://{site}/generate_204");

    let (c, v) = call(
        a,
        "GET",
        &format!("/proxies/direct/delay?url={url}&timeout=3000"),
        "",
    )
    .await;
    assert_eq!(c, 200, "{v}");
    assert!(v["delay"].is_u64());
    let (_, v) = call(a, "GET", "/proxies/direct", "").await;
    assert_eq!(v["history"].as_array().unwrap().len(), 1);
    assert!(v["history"][0]["time"].as_str().unwrap().ends_with('Z'));

    // Не отвечает — 504 и delay 0 в истории.
    let (c, _) = call(
        a,
        "GET",
        "/proxies/block/delay?url=http://127.0.0.1:9/&timeout=500",
        "",
    )
    .await;
    assert_eq!(c, 504);
    assert_eq!(
        call(a, "GET", "/proxies/block", "").await.1["history"][0]["delay"],
        0
    );
    // Без url — 400; нет выхода — 404.
    assert_eq!(call(a, "GET", "/proxies/direct/delay", "").await.0, 400);
    assert_eq!(
        call(a, "GET", &format!("/proxies/nope/delay?url={url}"), "")
            .await
            .0,
        404
    );

    // Группа: задержки ответивших участников.
    let (c, v) = call(
        a,
        "GET",
        &format!("/group/sel/delay?url={url}&timeout=2000"),
        "",
    )
    .await;
    assert_eq!(c, 200, "{v}");
    assert!(v["direct"].is_u64());
    assert!(v.get("block").is_none());
}

#[tokio::test]
async fn cors_and_websocket_token() {
    let r = start(&config(
        r#", "access_control_allow_origin": ["https://panel.example"]"#,
    ))
    .await;
    let a = r.api_addr.unwrap();

    // Предварительный запрос — без токена.
    let (c, head, _) = http(
        a,
        "OPTIONS",
        "/proxies/sel",
        "",
        "Origin: https://panel.example\r\nAccess-Control-Request-Method: PUT\r\n",
    )
    .await;
    assert_eq!(c, 204);
    assert!(
        head.contains("Access-Control-Allow-Origin: https://panel.example"),
        "{head}"
    );
    assert!(
        head.contains("Access-Control-Allow-Headers: Authorization"),
        "{head}"
    );

    let auth = format!("Authorization: Bearer {TOKEN}\r\n");
    let (c, head, _) = http(
        a,
        "GET",
        "/version",
        "",
        &format!("{auth}Origin: https://panel.example\r\n"),
    )
    .await;
    assert_eq!(c, 200);
    assert!(head.contains("Access-Control-Allow-Origin: https://panel.example"));
    // Чужой сайт — 403; своя панель (тот же адрес) — можно.
    let (c, _, b) = http(
        a,
        "GET",
        "/version",
        "",
        &format!("{auth}Origin: https://evil.example\r\n"),
    )
    .await;
    assert_eq!(c, 403);
    assert!(String::from_utf8_lossy(&b).contains("access_control_allow_origin"));
    let (c, _, _) = http(
        a,
        "GET",
        "/version",
        "",
        &format!("{auth}Origin: http://{a}\r\n"),
    )
    .await;
    assert_eq!(c, 200);

    // WebSocket из браузера: токен в адресе.
    use async_tungstenite::tungstenite::client::IntoClientRequest;
    use async_tungstenite::tungstenite::Message;
    let ws = |path: String| async move {
        let tcp = TcpStream::connect(a).await.unwrap();
        let mut req = format!("ws://{a}{path}").into_client_request().unwrap();
        req.headers_mut()
            .insert("Origin", "https://panel.example".parse().unwrap());
        async_tungstenite::client_async(req, tcp.compat()).await
    };
    let (mut s, _) = ws(format!("/connections?token={TOKEN}&interval=200"))
        .await
        .expect("WebSocket с токеном в адресе");
    let m = tokio::time::timeout(T, s.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Text(t) = m else { panic!("{m:?}") };
    let v: Value = serde_json::from_str(&t).unwrap();
    assert!(v["connections"].is_array(), "{v}");
    assert!(ws("/connections?token=wrong".into()).await.is_err());
    // Токен в адресе — только для WebSocket.
    let (c, _, _) = http(a, "GET", &format!("/version?token={TOKEN}"), "", "").await;
    assert_eq!(c, 401);
}

#[tokio::test]
async fn serves_external_ui() {
    let dir = std::env::temp_dir().join(format!("vpn-core-ui-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(dir.join("index.html"), "<html>панель</html>").unwrap();
    std::fs::write(dir.join("assets/app.js"), "console.log(1)").unwrap();
    let q = serde_json::to_string(&dir.display().to_string()).unwrap();
    let r = start(&config(&format!(r#", "external_ui": {q}"#))).await;
    let a = r.api_addr.unwrap();

    // Без токена: статика.
    let (c, head, _) = http(a, "GET", "/ui", "", "").await;
    assert_eq!(c, 301);
    assert!(head.contains("Location: /ui/"));
    let (c, head, b) = http(a, "GET", "/ui/", "", "").await;
    assert_eq!(c, 200);
    assert!(head.contains("text/html"));
    assert_eq!(b, "<html>панель</html>".as_bytes());
    let (c, head, b) = http(a, "GET", "/ui/assets/app.js", "", "").await;
    assert_eq!(c, 200);
    assert!(head.contains("text/javascript"));
    assert_eq!(b, b"console.log(1)");
    // Маршруты панели (history API) — index.html.
    let (c, _, b) = http(a, "GET", "/ui/proxies", "", "").await;
    assert_eq!(c, 200);
    assert_eq!(b, "<html>панель</html>".as_bytes());
    // Наружу из папки — нельзя.
    for p in [
        "/ui/../Cargo.toml",
        "/ui/%2e%2e/%2e%2e/etc/passwd",
        "/ui/..%2f..%2fetc%2fpasswd",
        "/ui/a%5c..%5cb",
    ] {
        let (c, _, b) = http(a, "GET", p, "", "").await;
        assert!(
            c == 400 || b == "<html>панель</html>".as_bytes(),
            "{p}: {c}"
        );
    }
    // Остальное API — по-прежнему с токеном.
    assert_eq!(http(a, "GET", "/proxies", "", "").await.0, 401);
    let _ = std::fs::remove_dir_all(&dir);

    // Нет папки — ошибка настроек, а не молчание.
    let q = serde_json::to_string(&Path::new("/нет/такой/папки").display().to_string()).unwrap();
    let cfg = Config::parse(&config(&format!(r#", "external_ui": {q}"#))).unwrap();
    let err = App::build(&cfg).err().expect("ошибка").to_string();
    assert!(err.contains("external_ui"), "{err}");
}

#[tokio::test]
async fn put_configs_reloads_file() {
    let dir = std::env::temp_dir().join(format!("vpn-core-clash-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, config("")).unwrap();
    let cfg = Config::load(&path).unwrap();
    let r = App::build(&cfg).unwrap().start().await.unwrap();
    r.set_config_path(path.clone());
    let a = r.api_addr.unwrap();
    assert_eq!(
        call(
            a,
            "PUT",
            "/configs?force=true",
            r#"{"path":"","payload":""}"#
        )
        .await
        .0,
        204
    );
    let (c, v) = call(a, "PUT", "/configs", r#"{"path":"/etc/other.json"}"#).await;
    assert_eq!(c, 400, "{v}");
    std::fs::write(&path, "{ битый").unwrap();
    assert_eq!(call(a, "PUT", "/configs", "").await.0, 400);
    let _ = std::fs::remove_dir_all(&dir);
}
