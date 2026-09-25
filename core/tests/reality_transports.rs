//! Этап 5 — проверка, что `security=reality` реально доходит до
//! WS- и gRPC-транспортов (`transport::ws`/`transport::grpc`), а не
//! используется только "голым" TCP-транспортом.
//!
//! # Почему тест устроен именно так
//! Полноценный тест "весь путь + сервер, честно проходящий
//! REALITY-аутентификацию" (как `reality_handshake.rs`) здесь
//! невозможен без реализации REALITY НА СТОРОНЕ СЕРВЕРА: серверу нужно
//! подписать сертификат HMAC-ключом, который зависит от эфемерного
//! X25519-ключа КЛИЕНТА — а этот ключ приходит только внутри самого
//! ClientHello, уже после того, как соединение открыто. Публичный API
//! `rustls::server::ResolvesServerCert::resolve` (проверено по исходнику
//! патча, `server/server_conn.rs`) не отдаёт key_share клиента наружу —
//! сертификат нельзя подписать "по требованию" без ещё одного патча
//! rustls, уже на серверной стороне. Реализация REALITY-сервера никогда
//! не входила в объём этого (клиентского) проекта — см. PLAN.md, Этап 5,
//! "Не сделано".
//!
//! Поэтому здесь проверяется более узкая, но всё равно содержательная
//! вещь: что `connect_and_handshake_ws`/`connect_and_handshake_grpc`
//! (боевые функции, которые реально вызывает `bin/client`) при
//! `security=reality` действительно доходят до `RealityCertVerifier` —
//! то есть REALITY-путь не потерялся где-то в ветвлении `type=ws`/`grpc`
//! и не подменился тихо на обычную проверку цепочки X.509. Сервер
//! честно поднимает TLS (через WS/h2 в точности как обычно) и
//! предъявляет Ed25519-самоподписанный сертификат с НАСТОЯЩЕЙ (не
//! HMAC-патченной) подписью — `verify_server_cert` обязан такой
//! отвергнуть, и конкретно с текстом ошибки "не совпал с подписью", а
//! не с обычной ошибкой rustls про недоверенный корень (`UnknownIssuer`
//! и т.п.) — только это отличие доказывает, что сработал именно
//! REALITY-верификатор, а не запасной путь.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use reality_core::transport::grpc::connect_and_handshake_grpc;
use reality_core::transport::tcp_tls::ensure_crypto_provider;
use reality_core::transport::ws::connect_and_handshake_ws;
use reality_core::vless::{Address, VlessConfig};

/// Собрать `vless://` со `security=reality` и произвольным (для этого
/// теста годится любой) `pbk=`/`sid=` — сервер ниже всё равно не
/// пытается пройти настоящую REALITY-аутентификацию, важно только, что
/// клиент реально попробует её потребовать.
fn reality_uri(port: u16, extra: &str) -> String {
    use base64::Engine;
    let pbk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    let id = Uuid::new_v4();
    format!(
        "vless://{id}@127.0.0.1:{port}?encryption=none&security=reality&sni=localhost&pbk={pbk_b64}&sid=aabb{extra}"
    )
}

/// Ed25519-самоподписанный сертификат с настоящей (не HMAC-патченной)
/// подписью — ровно то, что `RealityCertVerifier` обязан отвергнуть по
/// HMAC-сравнению, но обычный `WebPkiServerVerifier` отверг бы раньше и
/// по другой причине (недоверенный корень) — поэтому важно смотреть
/// именно на текст ошибки, см. модульный докстринг выше.
fn ed25519_self_signed_cert() -> (Vec<u8>, PrivateKeyDer<'static>) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let der = cert.der().to_vec();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (der, key_der)
}

#[tokio::test]
async fn ws_transport_rejects_non_hmac_certificate_via_reality_verifier() {
    ensure_crypto_provider();

    let (cert_der, key_der) = ed25519_self_signed_cert();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.into()], key_der)
        .expect("собрать серверный TLS-конфиг");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Клиент должен оборвать рукопожатие сам, не дожидаясь от нас
        // ничего сверх обычного TLS ServerHello/Certificate — accept()
        // здесь либо завершится ошибкой (клиент разорвал соединение
        // после отказа верификатора), либо неважно как, тест смотрит
        // только на результат клиентской стороны.
        let _ = acceptor.accept(tcp).await;
    });

    let uri = reality_uri(addr.port(), "&type=ws&path=/vless");
    let cfg = VlessConfig::parse(&uri).unwrap();
    let id = cfg.id;
    let target = Address::Domain("example.com".to_string());

    let err = connect_and_handshake_ws(&cfg, &id, target, 443)
        .await
        .expect_err("REALITY-верификатор обязан отвергнуть НЕ-HMAC подпись сертификата");

    let msg = err.to_string();
    assert!(
        msg.contains("не совпал с подписью"),
        "ошибка должна прийти именно от RealityCertVerifier (HMAC-сравнение), \
         а не от запасного пути проверки цепочки сертификатов — получено: {msg}"
    );

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}

#[tokio::test]
async fn grpc_transport_rejects_non_hmac_certificate_via_reality_verifier() {
    ensure_crypto_provider();

    let (cert_der, key_der) = ed25519_self_signed_cert();
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.into()], key_der)
        .expect("собрать серверный TLS-конфиг");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = acceptor.accept(tcp).await;
    });

    let uri = reality_uri(addr.port(), "&type=grpc&serviceName=testsvc");
    let cfg = VlessConfig::parse(&uri).unwrap();
    let id = cfg.id;
    let target = Address::Domain("example.com".to_string());

    let err = connect_and_handshake_grpc(&cfg, &id, target, 443)
        .await
        .expect_err("REALITY-верификатор обязан отвергнуть НЕ-HMAC подпись сертификата");

    let msg = err.to_string();
    assert!(
        msg.contains("не совпал с подписью"),
        "ошибка должна прийти именно от RealityCertVerifier (HMAC-сравнение), \
         а не от запасного пути проверки цепочки сертификатов — получено: {msg}"
    );

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}
