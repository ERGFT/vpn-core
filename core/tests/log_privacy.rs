// SPDX-License-Identifier: GPL-3.0-or-later
//! Адреса сайтов не попадают в тексты ошибок, которые входы пишут в журнал
//! уровня info/warn (`proxy_in`: «соединение завершилось с ошибкой»), — они
//! только в debug. Проверяются функции, через которые идёт выход `direct`.

use std::sync::{Arc, Mutex};

use reality_core::transport::tcp_tls::{connect_addrs, resolve_host};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Выполнить `f` с журналом уровня `level`; вернуть ошибку и весь журнал.
async fn logged<F, T>(level: tracing::Level, f: F) -> (String, String)
where
    F: std::future::Future<Output = reality_core::error::Result<T>>,
{
    let buf = Buf::default();
    let w = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(move || w.clone())
        .with_ansi(false)
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    let err = match f.await {
        Ok(_) => panic!("ожидалась ошибка"),
        Err(e) => e.to_string(),
    };
    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (err, log)
}

#[tokio::test]
async fn site_name_is_only_in_debug() {
    const SITE: &str = "no-such-site-for-log-test.invalid";
    let (err, log) = logged(tracing::Level::INFO, resolve_host(SITE, 443)).await;
    assert!(!err.contains(SITE), "в тексте ошибки: {err}");
    assert!(!log.contains(SITE), "в журнале info: {log}");
    let (_, log) = logged(tracing::Level::DEBUG, resolve_host(SITE, 443)).await;
    assert!(
        log.contains(SITE),
        "в debug имя остаётся для отладки: {log}"
    );
}

#[tokio::test]
async fn site_address_is_not_in_connect_error() {
    // Порт, на котором никто не слушает: соединение отклоняется сразу.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let (err, log) = logged(tracing::Level::INFO, connect_addrs(&[addr], "site.test")).await;
    assert!(
        !err.contains(&addr.to_string()) && !err.contains("site.test"),
        "{err}"
    );
    assert!(!log.contains("site.test"), "{log}");
}

/// Секреты из настроек не видны в `Debug` (`?cfg`, `.expect()`).
#[test]
fn secrets_are_not_in_debug_output() {
    use reality_core::app::config::Config;
    use reality_core::trojan::TrojanConfig;
    use reality_core::vless::uri::VlessConfig;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const PBK: &str = "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc";
    const SID: &str = "0123abcd";
    let link = format!(
        "vless://{UUID}@example.com:443?security=reality&sni=example.com&pbk={PBK}&sid={SID}\
         &type=tcp&flow=xtls-rprx-vision#name"
    );
    let v = VlessConfig::parse(&link).unwrap();
    let r = v.reality_params().unwrap();
    for s in [format!("{v:?}"), format!("{r:?}")] {
        for secret in [UUID, PBK, SID, "0x01, 0x23"] {
            assert!(!s.contains(secret), "{secret} в {s}");
        }
    }
    let t =
        TrojanConfig::parse("trojan://trojan-secret-pw@example.com:443?sni=example.com").unwrap();
    assert!(!format!("{t:?}").contains("trojan-secret-pw"));

    let cfg = Config::parse(&format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": 0,
                 "users": [{{ "username": "user-secret", "password": "pass-secret" }}] }}],
  "outbounds": [{{ "type": "vless", "tag": "proxy", "link": "{link}" }}],
  "subscriptions": [{{ "tag": "sub", "url": "https://panel.example/sub/token-secret" }}],
  "experimental": {{ "clash_api": {{ "external_controller": "127.0.0.1:0",
                                    "secret": "api-token-secret-0123456789" }} }}
}}"#
    ))
    .unwrap();
    let s = format!("{cfg:?}");
    for secret in [
        UUID,
        "user-secret",
        "pass-secret",
        "token-secret",
        "api-token-secret",
    ] {
        assert!(!s.contains(secret), "{secret} в {s}");
    }
    assert!(s.contains("***"), "видно, что секрет задан: {s}");
}
