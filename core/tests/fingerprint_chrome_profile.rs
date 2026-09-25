//! Этап 3 — живая (не только юнит-тест на голой структуре) проверка
//! того, что реально уходит в сеть: cipher suites в ClientHello на
//! проводе должны быть в порядке Chrome 133 с GREASE первым. Это
//! сочетание двух вещей — `fingerprint::chrome_profile::apply_chrome133_cipher_order`
//! и GREASE-cipher из `vendor/rustls-reality-patch/src/client/hs.rs` —
//! реально подключено в `transport::tcp_tls::build_client_config` и
//! используется продакшен-клиентом. Настоящий TCP+TLS1.3-хендшейк на
//! loopback, перехват сырых байт ClientHello, разбор тем же независимым
//! парсером, что и `fpcheck`/JA3/JA4. Внутренняя логика `chrome_profile.rs`
//! здесь намеренно не переиспользуется для проверки — иначе тест
//! подтвердил бы только "код не упал", а не то, что на проводе реально
//! то, что ожидается (тот же принцип, что и везде в этом проекте — см.
//! `core/src/reality/auth.rs` за похожим рассуждением).

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use reality_core::fingerprint::{
    apply_chrome133_cipher_order, is_grease, parse_record, CaptureFirstBytes,
};
use reality_core::transport::tcp_tls::ensure_crypto_provider;

#[tokio::test]
async fn client_hello_cipher_suites_start_with_grease_then_chrome_order() {
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

    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("собрать серверный TLS-конфиг"),
    );
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("слушать loopback");
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = acceptor
            .accept(tcp)
            .await
            .expect("серверное TLS-рукопожатие");
    });

    // Тот же провайдер, что и в продакшене (`transport::tcp_tls::build_client_config`):
    // дефолтный aws-lc-rs с переставленным под Chrome порядком suite'ов.
    // GREASE-cipher добавляется НЕ здесь, а внутри самого патча rustls
    // (`client/hs.rs`) — именно поэтому важно проверить это живым
    // хендшейком, а не вызовом функции напрямую: конфиг тут ничего не
    // знает про GREASE, это чисто протокольный код патча.
    let provider = apply_chrome133_cipher_order(rustls::crypto::aws_lc_rs::default_provider());
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = Vec::new();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let captured_tcp = CaptureFirstBytes::new(tcp, 4096);
    let server_name = ServerName::try_from("localhost").unwrap();

    let tls = connector
        .connect(server_name, captured_tcp)
        .await
        .expect("клиентское TLS-рукопожатие должно пройти даже с GREASE cipher suite в списке — так требует RFC 8701 от любого совместимого сервера");

    server.await.unwrap();

    let captured = tls.get_ref().0.captured().to_vec();
    let info = parse_record(&captured).expect("разобрать перехваченный ClientHello");

    assert!(
        is_grease(info.cipher_suites[0]),
        "первый cipher suite должен быть GREASE-значением (0x?A?A), как у настоящего Chrome; получено {:#06x}",
        info.cipher_suites[0]
    );

    // Остальные (без GREASE и без TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    // который добавляется отдельно, только если TLS1.2 разрешён) должны
    // идти в порядке Chrome 133 — сверено с CHROME133_CIPHER_ORDER
    // косвенно (значения захардкожены здесь ЕЩЁ РАЗ, а не через импорт
    // константы из chrome_profile.rs, чтобы тест не мог "поймать" баг,
    // просто согласившись сам с собой при правке одной константы).
    let expected_chrome_order: [u16; 9] = [
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    ];
    let rest: Vec<u16> = info.cipher_suites[1..]
        .iter()
        .copied()
        .filter(|&cs| cs != 0x00ff) // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        .collect();
    assert_eq!(
        rest, expected_chrome_order,
        "cipher suites после GREASE должны идти в порядке Chrome 133 побайтово"
    );
}
