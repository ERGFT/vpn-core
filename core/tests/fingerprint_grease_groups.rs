// SPDX-License-Identifier: GPL-3.0-or-later
//! Этап 3 — живая проверка GREASE (RFC 8701) за пределами cipher suites:
//! группа в `supported_groups` (0x000a) и `key_share` (0x0033), версия в
//! `supported_versions` (0x002b) и два отдельных GREASE-расширения
//! (первое и последнее в списке). Всё это делается внутри
//! `vendor/rustls-reality-patch` (`client/hs.rs`, `client/common.rs`
//! `GreaseValues`, `msgs/handshake.rs` `ClientExtensions::encode`) —
//! конфиг клиента о GREASE ничего не знает, поэтому проверяется только
//! на проводе. REALITY-путь проверяется отдельно, в `reality_handshake.rs`
//! (вместе с AEAD-проверкой, которая доказывает, что GREASE-байты вошли в
//! AAD так же, как их посчитал клиент).
//!
//! Тот же принцип, что и в `fingerprint_chrome_profile.rs`: настоящий
//! TCP+TLS1.3-хендшейк на loopback, перехват сырых байт ClientHello,
//! разбор независимым парсером (`parse_record`), а не проверка того,
//! что структуры в памяти выглядят правильно.

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use reality_core::fingerprint::{is_grease, parse_record, CaptureFirstBytes};
use reality_core::transport::tcp_tls::ensure_crypto_provider;

#[tokio::test]
async fn client_hello_named_groups_and_key_share_start_with_matching_grease_entry() {
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

    // Обычный (не-REALITY) клиентский конфиг, провайдер по умолчанию —
    // `chrome_profile`-переупорядочивание cipher suites здесь не важно,
    // GREASE добавляется внутри патча rustls независимо от конфига.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
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
        .expect("клиентское TLS-рукопожатие должно пройти даже с GREASE-группой/key_share — так требует RFC 8701 от любого совместимого сервера");

    server.await.unwrap();

    let captured = tls.get_ref().0.captured().to_vec();
    let info = parse_record(&captured).expect("разобрать перехваченный ClientHello");

    // supported_groups (elliptic_curves): GREASE первым.
    assert!(
        is_grease(info.elliptic_curves[0]),
        "первая группа в supported_groups должна быть GREASE-значением; получено {:#06x}",
        info.elliptic_curves[0]
    );

    // Реальные группы после GREASE — то, что реально отдаёт aws-lc-rs
    // (см. `probe_kx_groups`, запускался вручную при написании этого
    // теста): X25519MLKEM768, X25519, secp256r1, secp384r1 — тот же
    // порядок, что и в Chrome 133 (см. `u_parrots.go`,
    // `SupportedCurvesExtension`), без переупорядочивания с нашей
    // стороны, так что просто сверяем как есть.
    let expected_real_groups: [u16; 4] = [0x11ec, 0x001d, 0x0017, 0x0018];
    assert_eq!(
        &info.elliptic_curves[1..],
        &expected_real_groups[..],
        "группы после GREASE должны идти как отдал провайдер"
    );

    // key_share: GREASE-запись тоже первой, и её группа СОВПАДАЕТ с
    // GREASE-группой из supported_groups выше — иначе получилось бы
    // рассогласование, которого у настоящего Chrome не бывает (см.
    // комментарий у `group_grease` в hs.rs).
    assert!(
        !info.key_share_groups.is_empty(),
        "key_share должен содержать хотя бы одну запись"
    );
    assert!(
        is_grease(info.key_share_groups[0]),
        "первая запись key_share должна быть GREASE-группой; получено {:#06x}",
        info.key_share_groups[0]
    );
    assert_eq!(
        info.key_share_groups[0], info.elliptic_curves[0],
        "GREASE-группа в key_share должна быть той же, что и в supported_groups"
    );

    // После GREASE-записи в key_share — X25519MLKEM768 и следом
    // "бесплатный" plain-X25519 (гибридный компонент той же группы,
    // добавляется существующей логикой rustls в `emit_client_hello_for_
    // retry`, никак не связанной с GREASE-патчем). Ровно то же самое
    // (без GREASE) видит `key_share_extracts_x25519_tail_from_hybrid_
    // mlkem768`-подобная логика и то же самое отдаёт настоящий Chrome
    // 133 (см. `u_parrots.go`: `KeyShareExtension{[]KeyShare{{GREASE},
    // {X25519MLKEM768}, {X25519}}}` — структурно тот же список из трёх
    // записей).
    assert_eq!(
        &info.key_share_groups[1..],
        &[0x11ec, 0x001d][..],
        "после GREASE в key_share должны быть X25519MLKEM768 и его бесплатный X25519-компонент"
    );

    // supported_versions: GREASE первой, затем TLS 1.3 и 1.2 — как у
    // Chrome (`[GREASE, 1.3, 1.2]`).
    assert!(
        is_grease(info.supported_versions[0]),
        "первая версия в supported_versions должна быть GREASE; получено {:#06x}",
        info.supported_versions[0]
    );
    assert_eq!(&info.supported_versions[1..], &[0x0304, 0x0303]);

    // Два GREASE-расширения: самое первое в списке с пустым телом и самое
    // последнее с телом из одного нулевого байта; типы разные (иначе это
    // дубликат расширения, который сервер обязан отвергнуть).
    assert_eq!(
        info.grease_extensions.len(),
        2,
        "ровно два GREASE-расширения, получено {:?}",
        info.grease_extensions
    );
    let (first_type, first_body) = &info.grease_extensions[0];
    let (last_type, last_body) = &info.grease_extensions[1];
    assert_eq!(
        info.extensions.first(),
        Some(first_type),
        "первое расширение — GREASE"
    );
    assert_eq!(
        info.extensions.last(),
        Some(last_type),
        "последнее расширение — GREASE (PSK здесь нет)"
    );
    assert!(
        first_body.is_empty(),
        "тело первого GREASE-расширения — пустое"
    );
    assert_eq!(
        last_body,
        &vec![0u8],
        "тело последнего GREASE-расширения — один нулевой байт"
    );
    assert_ne!(
        first_type, last_type,
        "типы двух GREASE-расширений обязаны различаться"
    );

    // И убеждаемся, что GREASE-запись в key_share не сломала извлечение
    // настоящего X25519-компонента (используется REALITY-хендшейком в
    // других тестах, но парсер общий — стоит проверить, что GREASE его
    // не портит и здесь).
    assert!(
        info.key_share_x25519.is_some(),
        "GREASE-запись в key_share не должна мешать распознать настоящий X25519-компонент"
    );
}

/// HelloRetryRequest-путь (НЕ-REALITY): сервер поддерживает только
/// secp256r1, клиент в первом ClientHello предлагает key_share для
/// X25519MLKEM768 — сервер обязан прислать HRR, клиент — второй ClientHello.
/// RFC 8446 §4.1.2: во втором hello key_share должен содержать РОВНО ОДНУ
/// запись — для группы, которую запросил сервер. GREASE-запись туда
/// добавлять нельзя (и BoringSSL/Chrome её там не шлют) — иначе строгий
/// сервер (rustls, Go crypto/tls) рвёт соединение.
#[tokio::test]
async fn hello_retry_request_path_still_completes_with_grease() {
    ensure_crypto_provider();

    let cert_key = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert_key.cert.der().clone();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).unwrap();

    // Сервер знает только secp256r1 — X25519MLKEM768 из первого key_share
    // ему не подходит, отсюда гарантированный HRR.
    let mut server_provider = rustls::crypto::aws_lc_rs::default_provider();
    server_provider
        .kx_groups
        .retain(|g| g.name() == rustls::NamedGroup::secp256r1);
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap(),
    );
    let acceptor = TlsAcceptor::from(server_config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor.accept(tcp).await.map(|_| ())
    });

    let client_config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let captured_tcp = CaptureFirstBytes::new(tcp, 16 * 1024);

    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), captured_tcp)
        .await
        .expect("рукопожатие через HelloRetryRequest должно пройти и с GREASE");
    server
        .await
        .unwrap()
        .expect("серверная сторона рукопожатия через HRR");

    // Разбираем ОБА ClientHello из перехваченного потока (между ними может
    // быть фиктивный ChangeCipherSpec — пропускаем любые не-handshake
    // записи).
    let captured = tls.get_ref().0.captured().to_vec();
    let mut hellos = Vec::new();
    let mut pos = 0;
    while pos + 5 <= captured.len() {
        let len = u16::from_be_bytes([captured[pos + 3], captured[pos + 4]]) as usize;
        let end = pos + 5 + len;
        if end > captured.len() {
            break;
        }
        if captured[pos] == 0x16 && captured.get(pos + 5) == Some(&0x01) {
            hellos.push(parse_record(&captured[pos..end]).expect("разобрать ClientHello"));
        }
        pos = end;
    }
    assert_eq!(
        hellos.len(),
        2,
        "ожидались ровно два ClientHello (до и после HRR)"
    );
    let (first, second) = (&hellos[0], &hellos[1]);

    assert!(
        is_grease(first.key_share_groups[0]),
        "в первом hello GREASE в key_share есть"
    );
    assert_eq!(
        second.key_share_groups,
        vec![0x0017],
        "после HRR key_share — ровно одна запись для запрошенной группы, без GREASE (RFC 8446 §4.1.2)"
    );
    // А вот остальные GREASE-значения — те же, что в первом hello:
    // они живут на соединении, не на отдельном hello (как у BoringSSL).
    assert_eq!(first.elliptic_curves, second.elliptic_curves);
    assert_eq!(first.cipher_suites, second.cipher_suites);
    assert_eq!(first.supported_versions, second.supported_versions);
    assert_eq!(first.grease_extensions, second.grease_extensions);
}
