//! Проверка реального TCP+TLS-провода (Этап 1), не только протокольной
//! логики: настоящий `rustls`-сервер на loopback с самоподписанным
//! сертификатом, настоящий `TcpStream`, настоящее рукопожатие TLS 1.3.
//! Доверяем в тесте только собственному тестовому сертификату — не
//! отключаем проверку (`connect_tls` в продакшене всё равно всегда идёт
//! через встроенные публичные корни, этот тест лишь даёт ему другой
//! набор корней через `connect_tls_with_roots`).

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use reality_core::transport::tcp_tls::{connect_tls_with_roots, ensure_crypto_provider};
use reality_core::vless::protocol::{vless_connect, Address, Command};
use reality_core::vless::VlessConfig;

#[tokio::test]
async fn real_tls_loopback_handshake() {
    ensure_crypto_provider();

    let cert_key = generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("генерация самоподписанного сертификата для теста");
    let cert_der = cert_key.cert.der().clone();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .expect("добавить тестовый сертификат в доверенные корни");

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("собрать серверный TLS-конфиг");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("слушать loopback");
    let addr = listener.local_addr().unwrap();

    let id = Uuid::new_v4();
    let id_for_server = id;

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor
            .accept(tcp)
            .await
            .expect("серверное TLS-рукопожатие");

        let mut prefix = [0u8; 1 + 16 + 1 + 1 + 2 + 1];
        tls.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[1..17], id_for_server.as_bytes());

        let mut len_buf = [0u8; 1];
        tls.read_exact(&mut len_buf).await.unwrap();
        let mut domain = vec![0u8; len_buf[0] as usize];
        tls.read_exact(&mut domain).await.unwrap();
        assert_eq!(domain, b"example.com");

        tls.write_all(&[0x00, 0x00]).await.unwrap(); // ответ: версия 0, addons 0
        tls.write_all(b"pong").await.unwrap();
        tls.flush().await.unwrap();
        tls.shutdown().await.ok();
    });

    let cfg_uri = format!(
        "vless://{id}@127.0.0.1:{}?encryption=none&security=tls&sni=localhost",
        addr.port()
    );
    let cfg = VlessConfig::parse(&cfg_uri).expect("разбор тестовой ссылки");

    let client_tls = connect_tls_with_roots(&cfg, roots)
        .await
        .expect("клиентское TLS-рукопожатие с доверенным тестовым корнем");

    let target = Address::Domain("example.com".to_string());
    let mut client_tls = vless_connect(client_tls, &id, Command::Tcp, &target, 443)
        .await
        .expect("vless handshake поверх настоящего TLS");

    let mut got = [0u8; 4];
    client_tls.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");

    server_task.await.unwrap();
}
