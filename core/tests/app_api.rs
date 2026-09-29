// SPDX-License-Identifier: GPL-3.0-or-later
//! Фаза 8: локальное API, перечитывание настроек без разрыва соединений,
//! пресеты правил.

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const T: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token-0123456789abcdef";

async fn start(json: &str) -> Running {
    let cfg = Config::parse(json).expect("настройки");
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

async fn echo_ok(s: &mut TcpStream, data: &[u8]) -> bool {
    if s.write_all(data).await.is_err() {
        return false;
    }
    let mut b = vec![0u8; data.len()];
    matches!(
        tokio::time::timeout(T, s.read_exact(&mut b)).await,
        Ok(Ok(_))
    ) && b == data
}

/// Запрос к API; `extra` — дополнительные заголовки.
async fn api(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    extra: &str,
) -> (u16, Value) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let body = body.unwrap_or("");
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
    let text = String::from_utf8(resp).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let code: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, serde_json::from_str(body).unwrap_or(Value::Null))
}

async fn authed(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, Value) {
    api(
        addr,
        method,
        path,
        body,
        &format!("Authorization: Bearer {TOKEN}\r\n"),
    )
    .await
}

fn base(final_: &str, extra: &str) -> String {
    base_with(final_, extra, "", "127.0.0.1")
}

/// extra — дополнительные ключи route; inbound — ещё вход; api_ip — адрес API.
fn base_with(final_: &str, extra: &str, inbound: &str, api_ip: &str) -> String {
    format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}{inbound}],
  "outbounds": [
    {{ "type": "selector", "tag": "sel", "outbounds": ["block", "direct"] }},
    {{ "type": "direct", "tag": "direct" }},
    {{ "type": "block", "tag": "block" }}
  ],
  "experimental": {{ "clash_api": {{ "external_controller": "{api_ip}:0", "secret": "{TOKEN}" }} }},
  "route": {{ "final": "{final_}"{extra} }}
}}"#
    )
}

#[tokio::test]
async fn api_groups_connections_stats_and_security() {
    let echo = tcp_echo().await;
    let r = start(&base("sel", "")).await;
    let a = r.api_addr.expect("API включено");
    let proxy = r.listen_addrs[0];

    // Без токена, с чужим Host, из браузера — отказ.
    assert_eq!(api(a, "GET", "/stats", None, "").await.0, 401);
    let (c, _) = api(
        a,
        "GET",
        "/stats",
        None,
        &format!("Authorization: Bearer {TOKEN}x\r\n"),
    )
    .await;
    assert_eq!(c, 401);
    let mut s = TcpStream::connect(a).await.unwrap();
    s.write_all(
        format!("GET /stats HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 421"), "{resp}");
    let (c, _) = api(
        a,
        "GET",
        "/stats",
        None,
        &format!("Authorization: Bearer {TOKEN}\r\nOrigin: https://evil.example\r\n"),
    )
    .await;
    assert_eq!(c, 403);

    // selector смотрит на block — соединение отвергнуто.
    let (_s, rep) = socks_connect(proxy, echo).await;
    assert_ne!(rep, 0);
    let (c, g) = authed(a, "GET", "/groups", None).await;
    assert_eq!(c, 200);
    assert_eq!(g["groups"][0]["tag"], "sel");
    assert_eq!(g["groups"][0]["members"].as_array().unwrap().len(), 2);
    // Переключить на direct.
    let (c, _) = authed(a, "PUT", "/groups/sel", Some(r#"{"member":"direct"}"#)).await;
    assert_eq!(c, 200);
    assert_eq!(
        authed(a, "PUT", "/groups/sel", Some(r#"{"member":"nope"}"#))
            .await
            .0,
        400
    );
    assert_eq!(
        authed(a, "PUT", "/groups/nope", Some(r#"{"member":"x"}"#))
            .await
            .0,
        400
    );
    let (mut s, rep) = socks_connect(proxy, echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut s, &[7u8; 5000]).await);

    // Соединение видно, трафик посчитан.
    let (c, v) = authed(a, "GET", "/connections", None).await;
    assert_eq!(c, 200);
    let conns = v["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1, "{v}");
    let conn = &conns[0];
    // Формат Clash API: цепочка от участника к группе, порты строкой.
    assert_eq!(conn["chains"], serde_json::json!(["direct", "sel"]));
    assert_eq!(conn["metadata"]["destinationIP"], "127.0.0.1");
    assert_eq!(conn["metadata"]["destinationPort"], echo.port().to_string());
    assert_eq!(conn["metadata"]["type"], "socks/socks");
    assert_eq!(conn["rule"], "final");
    assert_eq!(conn["upload"], 5000);
    assert_eq!(conn["download"], 5000);
    let (_, st) = authed(a, "GET", "/stats", None).await;
    assert!(st["up"].as_u64().unwrap() >= 5000);
    assert_eq!(st["connections"], 1);

    // Закрыть через API — приложение видит конец соединения.
    let id = conn["id"].as_str().unwrap();
    assert_eq!(
        authed(a, "DELETE", &format!("/connections/{id}"), None)
            .await
            .0,
        204
    );
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(T, s.read(&mut b))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "соединение закрыто");
    // Как у Clash: закрыть несуществующее — не ошибка.
    assert_eq!(
        authed(a, "DELETE", "/connections/999999", None).await.0,
        204
    );
    assert_eq!(authed(a, "GET", "/nope", None).await.0, 404);
    let (c, v) = authed(a, "GET", "/version", None).await;
    assert_eq!(c, 200);
    assert!(v["version"].is_string());
}

#[tokio::test]
async fn reload_keeps_open_connections_and_applies_new_rules() {
    let echo = tcp_echo().await;
    let r = start(&base("direct", "")).await;
    let proxy = r.listen_addrs[0];
    let (mut old, rep) = socks_connect(proxy, echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut old, b"before").await);

    // Ошибка в новых настройках — ничего не меняется.
    let bad = Config::parse(&base("nope", "")).unwrap();
    assert!(r.reload(bad).await.is_err());
    let (mut s, rep) = socks_connect(proxy, echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut s, b"still direct").await);

    // Новые правила: всё в block; плюс ещё один вход.
    let text = base_with(
        "block",
        "",
        r#", {"type": "http", "tag": "extra", "listen": "127.0.0.1", "listen_port": 0}"#,
        "127.0.0.1",
    );
    let new = Config::parse(&text).unwrap();
    let notes = r.reload(new).await.unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    // Старое соединение живёт.
    assert!(echo_ok(&mut old, b"after reload").await);
    assert!(echo_ok(&mut s, b"also alive").await);
    // Новое — уже по новым правилам (тот же вход не перезапускался).
    let (_n, rep) = socks_connect(proxy, echo).await;
    assert_ne!(rep, 0, "новое соединение — в block");
    let addrs = r.inbound_addrs();
    assert_eq!(addrs.len(), 2);
    assert!(addrs.iter().any(|(t, _, a)| &**t == "extra" && a.is_some()));
}

#[tokio::test]
async fn reload_via_api_from_file() {
    let echo = tcp_echo().await;
    let dir = std::env::temp_dir().join(format!("vpn-core-api-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("client.json");
    std::fs::write(&path, base("block", "")).unwrap();
    let cfg = Config::load(&path).unwrap();
    let r = App::build(&cfg).unwrap().start().await.unwrap();
    r.set_config_path(path.clone());
    let a = r.api_addr.unwrap();
    let (_s, rep) = socks_connect(r.listen_addrs[0], echo).await;
    assert_ne!(rep, 0);
    std::fs::write(&path, base("direct", "")).unwrap();
    let (c, v) = authed(a, "POST", "/reload", None).await;
    assert_eq!(c, 200, "{v}");
    let (mut s, rep) = socks_connect(r.listen_addrs[0], echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut s, b"x").await);
    // Битый файл — 400, старые настройки остаются.
    std::fs::write(&path, r#"{"inbounds": [{"type": "carrier-pigeon"}]}"#).unwrap();
    assert_eq!(authed(a, "POST", "/reload", None).await.0, 400);
    let (mut s, rep) = socks_connect(r.listen_addrs[0], echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut s, b"y").await);
}

#[tokio::test]
async fn presets_expand_to_rules() {
    let echo = tcp_echo().await;
    // final = block, но private-direct пускает к 127.0.0.1 напрямую.
    let r = start(&base("block", r#", "presets": ["private-direct"]"#)).await;
    let (mut s, rep) = socks_connect(r.listen_addrs[0], echo).await;
    assert_eq!(rep, 0);
    assert!(echo_ok(&mut s, b"preset").await);
}

#[test]
fn api_and_preset_config_errors() {
    let err = |t: &str| match Config::parse(t) {
        Err(e) => e.to_string(),
        Ok(c) => App::build(&c).err().expect("ошибка").to_string(),
    };
    let e = err(&base("direct", r#", "presets": ["mars-direct"]"#));
    assert!(e.contains("mars-direct"), "{e}");
    let e = err(&base("direct", "").replace(TOKEN, "short"));
    assert!(e.contains("короче"), "{e}");
    let e = err(&base_with("direct", "", "", "0.0.0.0"));
    assert!(e.contains("allow_ip"), "{e}");
    let e = err(
        r#"{"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": 0}],
            "outbounds": [{"type": "direct", "tag": "d"}],
            "route": {"presets": ["block-ads"]}}"#,
    );
    assert!(e.contains("block"), "{e}");
}
