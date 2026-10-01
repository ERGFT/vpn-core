// SPDX-License-Identifier: GPL-3.0-or-later
//! Смена настроек через API: `GET /config`, `PUT /config` (проверить,
//! применить, сохранить), `PUT /configs` с `payload` (как у Clash).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use reality_core::app::config::Config;
use reality_core::app::{App, Running};

const T: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token-0123456789abcdef";

/// Настройки sing-box: всё в `final_`.
fn singbox(final_: &str) -> String {
    format!(
        r#"{{
  // комментарий сохраняется как есть
  "inbounds": [{{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": 0 }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}, {{ "type": "block", "tag": "block" }}],
  "route": {{ "final": "{final_}" }},
  "experimental": {{ "clash_api": {{ "external_controller": "127.0.0.1:0", "secret": "{TOKEN}" }} }}
}}"#
    )
}

struct Setup {
    r: Running,
    path: PathBuf,
    dir: PathBuf,
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn setup(name: &str) -> Setup {
    let dir = std::env::temp_dir().join(format!("vpn-core-apicfg-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, singbox("block")).unwrap();
    let cfg = Config::load(&path).unwrap();
    let r = App::build(&cfg).unwrap().start().await.unwrap();
    r.set_config_path(path.clone());
    Setup { r, path, dir }
}

async fn call(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, Value) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, serde_json::from_str(body).unwrap_or(Value::Null))
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

/// SOCKS5 CONNECT через первый вход; код ответа (0 — соединено).
async fn socks_rep(r: &Running, dst: SocketAddr) -> u8 {
    let proxy = r.inbound_addrs()[0].2.unwrap();
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
    rep[1]
}

#[tokio::test]
async fn read_check_apply_and_save() {
    let echo = tcp_echo().await;
    let s = setup("main").await;
    let a = s.r.api_addr.unwrap();

    // Прочитать: путь, формат и текст как есть (с комментариями).
    let (c, v) = call(a, "GET", "/config", "").await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["format"], "sing-box");
    assert_eq!(v["text"], singbox("block"));
    assert!(v["path"].as_str().unwrap().ends_with("config.json"));
    assert_ne!(socks_rep(&s.r, echo).await, 0, "final — block");

    // Битые настройки — 400, ничего не меняется.
    let (c, v) = call(
        a,
        "PUT",
        "/config",
        r#"{"outbounds": [{"type": "carrier-pigeon"}]}"#,
    )
    .await;
    assert_eq!(c, 400, "{v}");
    assert!(v["message"].is_string());
    let (c, v) = call(a, "PUT", "/config", r#"{"route": {"final": "nope"}}"#).await;
    assert_eq!(c, 400, "{v}");
    assert_ne!(socks_rep(&s.r, echo).await, 0);
    assert_eq!(std::fs::read_to_string(&s.path).unwrap(), singbox("block"));

    // Только проверить.
    let (c, v) = call(a, "PUT", "/config?check=1", &singbox("direct")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["applied"], false);
    assert_ne!(socks_rep(&s.r, echo).await, 0);

    // Применить без сохранения.
    let (c, v) = call(a, "PUT", "/config?save=0", &singbox("direct")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["applied"], true);
    assert_eq!(v["saved"], false);
    assert_eq!(socks_rep(&s.r, echo).await, 0, "теперь напрямую");
    assert_eq!(std::fs::read_to_string(&s.path).unwrap(), singbox("block"));

    // Применить и сохранить: файл заменён, прежний — в .bak.
    let (c, v) = call(a, "PUT", "/config", &singbox("block")).await;
    assert_eq!(c, 200, "{v}");
    let (c, v) = call(a, "PUT", "/config", &singbox("direct")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["saved"], true);
    assert_eq!(std::fs::read_to_string(&s.path).unwrap(), singbox("direct"));
    let bak = s.dir.join("config.json.bak");
    assert_eq!(std::fs::read_to_string(bak).unwrap(), singbox("block"));
    assert_eq!(socks_rep(&s.r, echo).await, 0);
    // Сохранённое читается обратно и переживает перечитывание.
    assert_eq!(
        call(a, "GET", "/config", "").await.1["text"],
        singbox("direct")
    );
    assert_eq!(call(a, "POST", "/reload", "").await.0, 200);
    assert_eq!(socks_rep(&s.r, echo).await, 0);
}

#[tokio::test]
async fn files_only_from_config_folder() {
    let s = setup("paths").await;
    let a = s.r.api_addr.unwrap();
    for bad in [
        r#""link_file": "/etc/passwd""#,
        r#""link_file": "../outside.txt""#,
        r#""link_file": "sub/../../outside.txt""#,
    ] {
        let text = format!(
            r#"{{"outbounds": [{{"type": "vless", "tag": "p", {bad}}}, {{"type": "direct", "tag": "direct"}}]}}"#
        );
        let (c, v) = call(a, "PUT", "/config?check=1", &text).await;
        assert_eq!(c, 400, "{bad}: {v}");
        assert!(
            v["message"].as_str().unwrap().contains("папки настроек"),
            "{bad}: {v}"
        );
    }
    // Кеш подписки по умолчанию — по тегу: тег с `..` тоже не выводит
    // запись за пределы папки.
    let text = r#"{"subscriptions": [{"tag": "../../evil", "url": "https://example.test/s"}],
        "outbounds": [{"type": "direct", "tag": "direct"}]}"#;
    let (c, v) = call(a, "PUT", "/config?check=1", text).await;
    assert_eq!(c, 400, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("папки настроек"),
        "{v}"
    );
    // Символическая ссылка в папке настроек, ведущая наружу: путь без `..`,
    // но файл — за пределами папки.
    #[cfg(unix)]
    {
        let outside = s.dir.with_extension("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, s.dir.join("out")).unwrap();
        for bad in ["out/secret.txt", "out/new.txt", "out/newdir/new.txt"] {
            let text = format!(
                r#"{{"outbounds": [{{"type": "vless", "tag": "p", "link_file": "{bad}"}}]}}"#
            );
            let (c, v) = call(a, "PUT", "/config?check=1", &text).await;
            assert_eq!(c, 400, "{bad}: {v}");
            assert!(
                v["message"]
                    .as_str()
                    .unwrap()
                    .contains("символическую ссылку"),
                "{bad}: {v}"
            );
        }
        let _ = std::fs::remove_dir_all(&outside);
    }
    // Файл рядом с настройками — можно (проверка доходит до самой ссылки).
    std::fs::write(s.dir.join("server.txt"), "vless://not-a-link").unwrap();
    let text = r#"{"outbounds": [{"type": "vless", "tag": "p", "link_file": "server.txt"}]}"#;
    let (c, v) = call(a, "PUT", "/config?check=1", text).await;
    assert_eq!(c, 400);
    assert!(
        !v["message"].as_str().unwrap().contains("папки настроек"),
        "{v}"
    );
}

#[tokio::test]
async fn clash_put_configs_payload_and_xray() {
    let echo = tcp_echo().await;
    let s = setup("clash").await;
    let a = s.r.api_addr.unwrap();
    // Как у Clash: payload применяется, но в файл не пишется.
    let body = serde_json::json!({ "path": "", "payload": singbox("direct") }).to_string();
    assert_eq!(call(a, "PUT", "/configs?force=true", &body).await.0, 204);
    assert_eq!(socks_rep(&s.r, echo).await, 0);
    assert_eq!(std::fs::read_to_string(&s.path).unwrap(), singbox("block"));

    // Настройки Xray — тоже; формат определяется сам.
    let xray = format!(
        r#"{{
  "inbounds": [{{ "protocol": "socks", "tag": "in", "listen": "127.0.0.1", "port": 0 }}],
  "outbounds": [{{ "protocol": "blackhole", "tag": "block" }}, {{ "protocol": "freedom", "tag": "direct" }}],
  "experimental": {{ "clash_api": {{ "external_controller": "127.0.0.1:0", "secret": "{TOKEN}" }} }}
}}"#
    );
    let (c, v) = call(a, "PUT", "/config", &xray).await;
    assert_eq!(c, 200, "{v}");
    assert_ne!(socks_rep(&s.r, echo).await, 0, "первый выход — blackhole");
    assert_eq!(call(a, "GET", "/config", "").await.1["format"], "xray");
}

#[tokio::test]
async fn config_from_flags_cannot_be_changed() {
    // Приложение без файла настроек (как с ключами командной строки).
    let cfg = Config::parse(&singbox("block")).unwrap();
    let r = App::build(&cfg).unwrap().start().await.unwrap();
    let a = r.api_addr.unwrap();
    assert_eq!(call(a, "GET", "/config", "").await.0, 404);
    let (c, v) = call(a, "PUT", "/config", &singbox("direct")).await;
    assert_eq!(c, 400);
    assert!(v["message"].as_str().unwrap().contains("ключами"), "{v}");
}
