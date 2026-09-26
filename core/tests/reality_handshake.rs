//! Этап 5 — проверка ПОЛНОГО REALITY-рукопожатия через новый хук
//! `rustls::client::RealityClientHook` (`core/src/reality/hook.rs`,
//! патч `vendor/rustls-reality-patch/src/client/{client_conn,hs}.rs`).
//!
//! В отличие от `reality_session_id_spike.rs` (проверял только то, что
//! патч МОЖЕТ доставить произвольный SessionId на провод, через
//! отдельный от боевого пути механизм — см. объяснение в
//! `core/src/reality/hook.rs`), этот тест проверяет ровно то, что
//! реально используется:
//!
//!  1. Настоящее TLS1.3-рукопожатие ЗАВЕРШАЕТСЯ УСПЕШНО, когда клиент
//!     переиспользует один и тот же эфемерный X25519-секрет дважды —
//!     для REALITY AuthKey (ECDH с фейковым REALITY-сервером ниже) и для
//!     настоящего TLS1.3 ECDH с сервером из ServerHello. Это не
//!     очевидно заранее: если бы `RealityKeyExchange::complete`
//!     где-то перепутал секрет или байты кодирования, рукопожатие просто
//!     не установилось бы — сильный, "дешёвый" сигнал корректности.
//!  2. SessionId, реально ушедший на провод, при независимом (не через
//!     `reality-core`, отдельно написанном прямо в этом тесте) HKDF +
//!     AES-256-GCM Open с ключом, выведенным СЕРВЕРНОЙ стороной из
//!     ECDH(server_static_secret, client_key_share_из_провода) и солью
//!     random[..20] из ТЕХ ЖЕ захваченных байт, расшифровывается в
//!     ожидаемый plaintext (short_id на месте, timestamp — недавний).
//!     Значит клиент и незвисимый ("сервер") наблюдатель совершенно
//!     независимо приходят к одному и тому же AuthKey — то самое
//!     свойство, ради которого REALITY вообще существует.
//!
//! AAD переcобирается из перехваченных сырых байт вручную (обнуляем те
//! же 32 байта SessionId на смещении 39, что и `hello.Raw[39:71]` в
//! `reality.go` Xray-core) — не переиспользуя код `reality-core/hook.rs`
//! ни для этого, ни для самого AEAD Open, чтобы тест не подтверждал
//! "функция не падает", а действительно перепроверял результат другим
//! путём (тот же принцип, что и `seal_open_roundtrip_recovers_plaintext_fields`
//! в `auth.rs`).

use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rcgen::generate_simple_self_signed;
use rustls::client::{ClientConfig, ResolvesClientCert};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig, SignatureScheme};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use reality_core::fingerprint::{is_grease, parse_record, CaptureFirstBytes};
use reality_core::reality::RealityHook;
use reality_core::transport::tcp_tls::ensure_crypto_provider;

#[derive(Debug)]
struct NoClientAuth;

impl ResolvesClientCert for NoClientAuth {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        None
    }
    fn has_certs(&self) -> bool {
        false
    }
}

/// Независимая (не через `reality-core`) серверная реконструкция
/// AuthKey + Open — намеренно продублировано, а не переиспользовано, по
/// той же причине, что и в `auth.rs`: тест должен ловить расхождение
/// клиента с протоколом, а не подтверждать, что клиентский код
/// согласуется сам с собой.
fn server_side_auth_key(
    server_static: &StaticSecret,
    client_public: &[u8; 32],
    client_hello_random: &[u8; 32],
) -> [u8; 32] {
    let shared = server_static.diffie_hellman(&X25519PublicKey::from(*client_public));
    let hk = Hkdf::<Sha256>::new(Some(&client_hello_random[..20]), shared.as_bytes());
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .expect("HKDF expand для 32-байтного AuthKey не может провалиться");
    auth_key
}

#[tokio::test]
async fn full_reality_handshake_authenticates_and_completes_tls13() {
    ensure_crypto_provider();

    // --- фейковый REALITY-сервер: свой статический X25519 (pbk/priv), НЕ
    //     тот же ключ, что настоящий TLS-сертификат сервера ниже — в
    //     реальном REALITY это тоже два разных объекта (публичный ключ
    //     REALITY против TLS-сертификата "сайта прикрытия"). ---
    let mut rng = rand::rngs::OsRng;
    let server_reality_static = StaticSecret::random_from_rng(rng);
    let server_reality_public = X25519PublicKey::from(&server_reality_static).to_bytes();
    let short_id: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    // --- обычный TLS1.3-сервер на loopback (self-signed) — "сайт
    //     прикрытия", которому REALITY-хук ничего не должен сломать. ---
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

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor
            .accept(tcp)
            .await
            .expect("серверное TLS-рукопожатие");
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "сервер должен был согласовать TLS 1.3"
        );
        // Обмен байтом туда-обратно — доказывает, что после рукопожатия
        // соединение реально рабочее (общий секрет совпал), а не просто
        // "ClientHello ушёл и не упал".
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf)
            .await
            .expect("прочитать пробный payload");
        assert_eq!(&buf, b"hello");
        tls.write_all(b"world").await.expect("отправить ответ");
    });

    // --- клиент: обычный TLS1.3 ClientConfig + REALITY-хук. ---
    let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let client_creds: Arc<dyn ResolvesClientCert> = Arc::new(NoClientAuth);

    let mut client_config =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_webpki_verifier(webpki_verifier)
            .with_client_cert_resolver(client_creds);
    client_config.reality = Some(Arc::new(RealityHook::new(
        &server_reality_public,
        &short_id,
        &mut rng,
    )));

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost").unwrap();

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let captured_tcp = CaptureFirstBytes::new(tcp, 4096);
    let mut tls = connector
        .connect(server_name, captured_tcp)
        .await
        .expect("клиентское TLS-рукопожатие с REALITY-хуком");

    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "клиент тоже должен видеть TLS 1.3 — переиспользование эфемерного \
         ключа для REALITY AuthKey не должно ломать настоящий TLS1.3 ECDH"
    );

    tls.write_all(b"hello")
        .await
        .expect("отправить пробный payload");
    let mut buf = [0u8; 5];
    tls.read_exact(&mut buf)
        .await
        .expect("прочитать ответ сервера");
    assert_eq!(
        &buf, b"world",
        "приложенческие данные должны дойти оба конца — общий секрет реально совпал"
    );

    server_task.await.unwrap();

    // --- независимая проверка: разобрать перехваченный ClientHello и
    //     воспроизвести AuthKey/Open с нуля, не переиспользуя
    //     reality-core. ---
    let captured = tls.get_ref().0.captured().to_vec();
    let info = parse_record(&captured).expect("разобрать перехваченный ClientHello");

    let client_public = info
        .key_share_x25519
        .expect("ClientHello должен нести X25519 key_share (REALITY требует X25519)");
    assert_eq!(
        info.session_id.len(),
        32,
        "REALITY SessionId — всегда полные 32 байта (16 ciphertext + 16 GCM-тег)"
    );

    let auth_key = server_side_auth_key(&server_reality_static, &client_public, &info.random);

    // AAD = байты handshake-сообщения ClientHello (тип+длина+тело) с
    // обнулённым полем SessionId — то же самое смещение 39, что и
    // `hello.Raw[39:71]` в reality.go: header(4)+client_version(2)+
    // random(32)+session_id_len(1) = 39.
    // TLS record layer: content_type(1)+legacy_record_version(2)+length(2).
    // Не берём "весь остаток захваченного буфера" — после ClientHello на
    // проводе может лежать что угодно ещё (например, следующий флайт),
    // а AAD обязан быть РОВНО байтами этого одного handshake-сообщения,
    // никак не больше и не меньше — иначе AAD не совпадёт с тем, что
    // reality-core посчитал внутри rustls, и Open провалится не из-за
    // реальной ошибки протокола, а из-за неточности самого теста.
    let record_len = u16::from_be_bytes([captured[3], captured[4]]) as usize;
    let record_header_len = 5;
    let handshake_msg = &captured[record_header_len..record_header_len + record_len];
    let mut aad = handshake_msg.to_vec();
    aad[39..39 + 32].fill(0);

    let session_id: [u8; 32] = info.session_id.clone().try_into().unwrap();
    let cipher = Aes256Gcm::new_from_slice(&auth_key).unwrap();
    let nonce = Nonce::from_slice(&info.random[20..32]);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &session_id,
                aad: &aad,
            },
        )
        .expect(
            "AES-256-GCM Open независимо выведенным AuthKey должен успешно расшифровать SessionId — \
             это и есть доказательство, что клиент с сервером пришли к одному и тому же секрету",
        );

    assert_eq!(plaintext.len(), 16, "plaintext-блок REALITY всегда 16 байт");
    assert_eq!(
        &plaintext[8..12],
        &short_id,
        "восстановленный short_id должен совпасть с настроенным"
    );
    let ts = u32::from_be_bytes(plaintext[4..8].try_into().unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    assert!(
        now.saturating_sub(ts) <= 5,
        "timestamp внутри SessionId должен быть примерно текущим unix-временем, получено {ts}, сейчас {now}"
    );

    // Этап 3: REALITY-ClientHello несёт GREASE (RFC 8701) во всех тех же
    // местах, что и Chrome/utls-клиент Xray-core, — и Open выше при этом
    // прошёл, то есть GREASE-байты (в т.ч. два GREASE-расширения,
    // вписанные прямо в `ClientExtensions::encode`) вошли в AAD ровно
    // так же, как их посчитал клиент. Единственная реальная группа
    // по-прежнему одна — X25519MLKEM768 (анти-HRR-логика REALITY цела).
    assert!(
        is_grease(info.cipher_suites[0]),
        "GREASE первым cipher suite"
    );
    // Группы и доли ключа — как у Chrome 133: supported_groups
    // `[GREASE, X25519MLKEM768, X25519, P-256, P-384]`, key_share
    // `[GREASE, X25519MLKEM768, X25519]` (X25519 — тот же ключ, что в
    // гибриде; нужен сайтам-приманкам без ML-KEM).
    assert!(is_grease(info.elliptic_curves[0]), "GREASE первой группой");
    assert_eq!(
        &info.elliptic_curves[1..],
        &[0x11ec, 0x001d, 0x0017, 0x0018],
        "затем группы Chrome"
    );
    assert_eq!(
        info.key_share_groups,
        vec![info.elliptic_curves[0], 0x11ec, 0x001d],
        "key_share: GREASE, гибрид и его X25519-часть"
    );
    assert!(
        is_grease(info.supported_versions[0]),
        "GREASE первой версией"
    );
    assert_eq!(
        &info.supported_versions[1..],
        &[0x0304],
        "без профиля Chrome (этот тест собирает конфиг сам) REALITY заявляет только TLS 1.3; \
         полный профиль проверяет fingerprint_chrome_full.rs"
    );
    assert_eq!(
        info.grease_extensions.len(),
        2,
        "ровно два GREASE-расширения"
    );
    assert_eq!(info.extensions.first(), Some(&info.grease_extensions[0].0));
    assert_eq!(info.extensions.last(), Some(&info.grease_extensions[1].0));
}
