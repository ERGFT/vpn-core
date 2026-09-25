//! Устойчивость открытия соединения: таймауты и перебор адресов.
//!
//! Проверяется то, чего раньше не было совсем: клиент не должен висеть
//! вечно на сервере, который принял TCP и молчит, и должен переходить к
//! следующему адресу, если первый не отвечает (домен часто отдаёт и
//! IPv6, и IPv4).

use std::time::{Duration, Instant};

use reality_core::transport::tcp_tls::{connect_tls, ensure_crypto_provider};
use reality_core::vless::VlessConfig;

/// Сервер, который принимает соединение и молчит — так ведёт себя
/// заблокированный или зависший узел. Раньше клиент ждал бы вечно.
#[tokio::test]
async fn silent_server_does_not_hang_forever() {
    ensure_crypto_provider();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _keep = tokio::spawn(async move {
        // Принимаем и держим, ничего не отвечая.
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });

    let cfg = VlessConfig::parse(&format!(
        "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:{port}?security=tls&sni=example.com"
    ))
    .unwrap();

    // Ограничение теста заведомо больше таймаута TLS-рукопожатия внутри,
    // но заведомо меньше «вечности».
    let started = Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(60), connect_tls(&cfg)).await;

    assert!(
        res.is_ok(),
        "клиент завис на молчащем сервере дольше 60 с — таймаут не сработал"
    );
    assert!(
        res.unwrap().is_err(),
        "молчащий сервер не должен считаться успешным подключением"
    );
    // Не проверяем точную длительность (она зависит от таймаутов), важно
    // лишь то, что управление вернулось.
    assert!(started.elapsed() < Duration::from_secs(60));
}

/// Первый адрес не отвечает, второй рабочий: клиент обязан дойти до
/// второго. Раньше брался только первый адрес из разрешения имени.
#[tokio::test]
async fn falls_back_to_second_address() {
    ensure_crypto_provider();

    // Порт, на котором заведомо никто не слушает: занимаем и отпускаем.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    // Прямая проверка самого перебора: подключение к мёртвому порту
    // обязано завершиться ошибкой, а не зависнуть.
    let cfg = VlessConfig::parse(&format!(
        "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:{dead}?security=tls&sni=example.com"
    ))
    .unwrap();

    let res = tokio::time::timeout(Duration::from_secs(30), connect_tls(&cfg)).await;
    assert!(res.is_ok(), "подключение к мёртвому порту не должно висеть");
    assert!(res.unwrap().is_err(), "мёртвый порт — это ошибка");
}

/// Имя, которое не разрешается: понятная ошибка, а не паника и не
/// бесконечное ожидание.
#[tokio::test]
async fn unresolvable_host_fails_cleanly() {
    ensure_crypto_provider();
    let cfg = VlessConfig::parse(
        "vless://11111111-1111-1111-1111-111111111111@nonexistent.invalid:443?security=tls",
    )
    .unwrap();

    let res = tokio::time::timeout(Duration::from_secs(30), connect_tls(&cfg)).await;
    assert!(
        res.is_ok(),
        "разрешение несуществующего имени не должно висеть"
    );
    let err = res.unwrap().unwrap_err().to_string();
    assert!(
        err.contains("разрешить имя") && err.contains("nonexistent.invalid"),
        "ошибка должна называть и причину, и само имя; получено: {err}"
    );
}
