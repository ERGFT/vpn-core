// SPDX-License-Identifier: GPL-3.0-or-later
//! Интероп-тест против ЧУЖОЙ серверной реализации REALITY (PLAN.md,
//! "План дальнейших действий", шаг 2). Сервер —
//! `interop/go-reality-server`: Go-программа на библиотеке
//! `github.com/xtls/reality` (та же, что внутри Xray-core), с настоящим Go
//! `crypto/tls` в роли сайта-приманки. Все остальные REALITY-тесты
//! проекта проверяют клиента против собственного тестового сервера —
//! этот единственный, где серверную сторону писали не мы.
//!
//! Нужен собранный Go-стенд, поэтому по умолчанию тест пропускается
//! (`#[ignore]`). Запуск: `scripts/interop_go_reality.sh` — соберёт
//! сервер и передаст путь к бинарнику через `REALITY_GO_SERVER`.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use reality_core::transport::tcp_tls::{connect_and_handshake, ensure_crypto_provider};
use reality_core::vless::{Address, VlessConfig};

struct GoServer {
    child: Child,
    port: u16,
    events: mpsc::Receiver<String>,
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl GoServer {
    fn start(private_key: &[u8; 32], short_id: &str, uuid: &uuid::Uuid) -> Self {
        Self::start_with(private_key, short_id, uuid, &[])
    }

    fn start_with(
        private_key: &[u8; 32],
        short_id: &str,
        uuid: &uuid::Uuid,
        extra_args: &[&str],
    ) -> Self {
        let bin = std::env::var("REALITY_GO_SERVER")
            .expect("REALITY_GO_SERVER не задан — запускать через scripts/interop_go_reality.sh");
        let mut child = Command::new(bin)
            .args(extra_args)
            .arg("-private-key")
            .arg(hex::encode(private_key))
            .arg("-short-id")
            .arg(short_id)
            .arg("-uuid")
            .arg(uuid.simple().to_string())
            .arg("-sni")
            .arg("example.com")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("запустить Go REALITY-сервер");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                // Всё, что не READY/EVENT (например, отладочный вывод
                // REALITY при `-show`), — просто в stderr теста.
                if !(line.starts_with("READY ") || line.starts_with("EVENT ")) {
                    eprintln!("[go-server] {line}");
                    continue;
                }
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let ready = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("Go-сервер не сообщил READY");
        let port = ready
            .strip_prefix("READY ")
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or_else(|| panic!("неожиданная первая строка Go-сервера: {ready}"));
        GoServer {
            child,
            port,
            events: rx,
        }
    }

    fn next_event(&self) -> String {
        self.events
            .recv_timeout(Duration::from_secs(10))
            .expect("Go-сервер не прислал событие")
    }
}

fn link(port: u16, uuid: &uuid::Uuid, pbk: &[u8; 32], sid: &str) -> VlessConfig {
    let pbk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pbk);
    VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{port}?security=reality&sni=example.com&pbk={pbk}&sid={sid}&type=tcp&fp=chrome"
    ))
    .unwrap()
}

fn server_keys() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// Полный путь: REALITY-рукопожатие с Go-сервером (AuthKey, SessionId,
/// X25519MLKEM768, HMAC-сертификат, GREASE — всё, что сервер проверяет
/// сам), затем VLESS-запрос и эхо. Сервер отдаёт заголовок ответа VLESS
/// только вместе с данными, как Xray-core, — так что тест заодно
/// проверяет, что клиент не ждёт ответ до отправки (шаг 1б).
#[tokio::test]
#[ignore = "нужен Go-стенд: scripts/interop_go_reality.sh"]
async fn reality_handshake_and_vless_echo_against_go_server() {
    ensure_crypto_provider();
    let (private, public) = server_keys();
    let uuid = uuid::Uuid::new_v4();
    let server = GoServer::start(&private, "0123abcd", &uuid);
    let cfg = link(server.port, &uuid, &public, "0123abcd");

    let mut stream = tokio::time::timeout(
        Duration::from_secs(20),
        connect_and_handshake(&cfg, &cfg.id, Address::Domain("target.test".into()), 443),
    )
    .await
    .expect("рукопожатие не должно зависать")
    .expect("REALITY-рукопожатие с Go-сервером");

    let ev = server.next_event();
    assert!(
        ev.starts_with("EVENT reality-ok version=304"),
        "сервер должен принять REALITY-аутентификацию: {ev}"
    );
    let ev = server.next_event();
    assert!(
        ev.starts_with("EVENT vless-ok cmd=1 target=target.test:443"),
        "сервер должен разобрать VLESS-запрос: {ev}"
    );

    stream.write_all(b"ping over go reality").await.unwrap();
    let mut got = [0u8; 20];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
        .await
        .expect("эхо не пришло")
        .unwrap();
    assert_eq!(&got, b"ping over go reality");
}

/// Неверный ShortId: сервер НЕ должен аутентифицировать клиента и
/// переключается на прозрачную пересылку к сайту-приманке. Клиент видит
/// настоящий сертификат приманки без HMAC-подписи REALITY и обязан
/// оборвать соединение — это и есть защита от подмены сервера.
#[tokio::test]
#[ignore = "нужен Go-стенд: scripts/interop_go_reality.sh"]
async fn wrong_short_id_falls_back_to_dest_and_client_rejects_it() {
    ensure_crypto_provider();
    let (private, public) = server_keys();
    let uuid = uuid::Uuid::new_v4();
    let server = GoServer::start(&private, "0123abcd", &uuid);
    let cfg = link(server.port, &uuid, &public, "deadbeef");

    let res = tokio::time::timeout(
        Duration::from_secs(20),
        connect_and_handshake(&cfg, &cfg.id, Address::Domain("target.test".into()), 443),
    )
    .await
    .expect("не должно зависать");
    let err = res.expect_err("с неверным ShortId клиент обязан отвергнуть сертификат приманки");
    eprintln!("ошибка клиента (ожидаемая): {err}");
    // Сервер не аутентифицировал клиента, а переслал его к приманке.
    let ev = server.next_event();
    assert!(
        ev.starts_with("EVENT reality-fail"),
        "сервер не должен был принять клиента: {ev}"
    );
    assert!(
        err.to_string().to_lowercase().contains("certificate")
            || err.to_string().contains("REALITY"),
        "клиент должен отвергнуть именно сертификат приманки, а не упасть по другой причине: {err}"
    );
}

/// Неверный публичный ключ сервера (pbk): AuthKey у клиента и сервера
/// разный, сервер не может открыть SessionId → тоже пересылка к приманке
/// → клиент отвергает соединение.
#[tokio::test]
#[ignore = "нужен Go-стенд: scripts/interop_go_reality.sh"]
async fn wrong_public_key_is_rejected() {
    ensure_crypto_provider();
    let (private, _) = server_keys();
    let (_, other_public) = server_keys();
    let uuid = uuid::Uuid::new_v4();
    let server = GoServer::start(&private, "0123abcd", &uuid);
    let cfg = link(server.port, &uuid, &other_public, "0123abcd");

    let res = tokio::time::timeout(
        Duration::from_secs(20),
        connect_and_handshake(&cfg, &cfg.id, Address::Domain("target.test".into()), 443),
    )
    .await
    .expect("не должно зависать");
    let err = res.expect_err("с чужим pbk соединение обязано провалиться");
    eprintln!("ошибка клиента (ожидаемая): {err}");
    let ev = server.next_event();
    assert!(
        ev.starts_with("EVENT reality-fail"),
        "сервер не должен был принять клиента: {ev}"
    );
    assert!(
        err.to_string().to_lowercase().contains("certificate")
            || err.to_string().contains("REALITY"),
        "клиент должен отвергнуть именно сертификат приманки: {err}"
    );
}

/// `minClientVer`/`maxClientVer` у настоящего сервера: клиент объявляет
/// версию 26.9.9 (`reality/auth.rs`, `CLIENT_VERSION`). Диапазон,
/// включающий её, — клиент принят; диапазон выше неё — сервер обязан
/// отказать (и переслать к приманке). Раньше с нулевой версией любой
/// сервер с `minClientVer` отвергал бы этого клиента.
#[tokio::test]
#[ignore = "нужен Go-стенд: scripts/interop_go_reality.sh"]
async fn client_version_is_checked_by_real_server() {
    ensure_crypto_provider();
    for (min, max, accepted) in [
        ("26.0.0", "26.99.99", true),
        ("26.9.9", "26.9.9", true),
        ("26.9.10", "", false),
        ("", "26.9.8", false),
    ] {
        let (private, public) = server_keys();
        let uuid = uuid::Uuid::new_v4();
        let mut args = Vec::new();
        if !min.is_empty() {
            args.extend(["-min-client-ver", min]);
        }
        if !max.is_empty() {
            args.extend(["-max-client-ver", max]);
        }
        let server = GoServer::start_with(&private, "0123abcd", &uuid, &args);
        let cfg = link(server.port, &uuid, &public, "0123abcd");
        let res = tokio::time::timeout(
            Duration::from_secs(20),
            connect_and_handshake(&cfg, &cfg.id, Address::Domain("target.test".into()), 443),
        )
        .await
        .expect("не должно зависать");
        let ev = server.next_event();
        if accepted {
            assert!(
                res.is_ok(),
                "min={min} max={max}: клиент должен быть принят"
            );
            assert!(
                ev.starts_with("EVENT reality-ok"),
                "min={min} max={max}: {ev}"
            );
        } else {
            assert!(
                res.is_err(),
                "min={min} max={max}: клиент должен быть отвергнут"
            );
            assert!(
                ev.starts_with("EVENT reality-fail"),
                "min={min} max={max}: {ev}"
            );
        }
    }
}
