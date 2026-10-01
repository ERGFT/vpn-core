// SPDX-License-Identifier: GPL-3.0-or-later
//! Этап 5 — полный сквозной REALITY-хендшейк через боевые функции ВСЕХ
//! ТРЁХ транспортов (`connect_and_handshake`/`_ws`/`_grpc`), включая
//! настоящую проверку сертификата через `RealityCertVerifier` — то есть
//! закрывает оба пробела, которые PLAN.md до сих пор честно числил как
//! "не сделано" для Этапа 5:
//!  1. интеграционный тест через сами `connect_tls_reality`/
//!     `connect_and_handshake` (раньше — только через `RealityHook`
//!     напрямую, см. `reality_handshake.rs`, где верификатор сертификата
//!     вообще не участвует, используется обычный `WebPkiServerVerifier`);
//!  2. REALITY-хендшейк доведённый до конца (не только "путь
//!     исполняется и корректно отвергает неверный сертификат", как в
//!     `reality_transports.rs`) через WS и gRPC.
//!
//! # Почему это вообще стало возможным
//! Раньше это было невозможно без реализации REALITY на стороне сервера:
//! серверу нужно подписать сертификат HMAC-ключом, зависящим от
//! эфемерного X25519-ключа КЛИЕНТА, известного только из его ClientHello
//! — а публичный API rustls (`ResolvesServerCert::resolve`) не отдавал
//! резолверу сертификата ни `ClientHello.random`, ни `key_share`
//! клиента (проверено по исходнику патча). Пришлось точечно расширить и
//! СЕРВЕРНУЮ часть патча (`vendor/rustls-reality-patch/src/server/{server_conn,hs}.rs`):
//! добавлены `ClientHello::client_random()`/`client_key_share_x25519()`
//! — два метода, которые просто открывают наружу то, что rustls уже и
//! так разобрал из проводных байт на этом этапе, ничего не пересчитывая
//! заново и не меняя поведение уже существующих резолверов (они это
//! поле просто не читают).
//!
//! Это НЕ делает данный проект REALITY-сервером в полном смысле —
//! декодирования SessionId, проверки short_id/анти-replay здесь нет
//! (резолверу ниже это и не нужно: подпись сертификата зависит только
//! от AuthKey, а не от того, что внутри зашифрованного SessionId) — это
//! ровно тестовая обвязка, которая позволяет честно проверить
//! КЛИЕНТСКИЙ `RealityCertVerifier` на настоящем успешном пути, а не
//! только на отказе.

use std::sync::Arc;

use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rcgen::{CertificateParams, KeyPair};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls::SignatureScheme;
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use reality_core::transport::grpc::{connect_and_handshake_grpc, encode_hunk_frame, HunkDecoder};
use reality_core::transport::tcp_tls::{connect_and_handshake, ensure_crypto_provider};
use reality_core::transport::ws::connect_and_handshake_ws;
use reality_core::vless::{Address, VlessConfig};

const REQUEST_HEADER_LEN: usize = 1 + 16 + 1 + 1 + 2 + 1 + 1 + 11; // см. ws_loopback.rs

/// Резолвер сертификата "тестового REALITY-сервера": для каждого
/// клиента заново вычисляет AuthKey (ECDH с его key_share + HKDF с
/// солью из его random — независимо от `reality-core`, HKDF/AEAD-код
/// здесь написан отдельно, тот же принцип, что и в `reality_handshake.rs`)
/// и подставляет HMAC-SHA512(AuthKey, spki) в DER сертификата вместо
/// заготовки. Требует X25519 key_share от клиента — если его нет,
/// REALITY на этом соединении невозможно в принципе, резолвер честно
/// отказывает (`None`), а не паникует.
struct RealityTestResolver {
    server_reality_static: StaticSecret,
    spki: [u8; 32],
    cert_template_der: Vec<u8>,
    sig_offset: usize,
    sig_len: usize,
    key_der_bytes: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for RealityTestResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityTestResolver")
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for RealityTestResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let client_pub = client_hello.client_key_share_x25519()?;
        let random = *client_hello.client_random();

        let shared = self
            .server_reality_static
            .diffie_hellman(&X25519PublicKey::from(client_pub));
        let hk = Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(b"REALITY", &mut auth_key).ok()?;

        let mut mac = Hmac::<Sha512>::new_from_slice(&auth_key).ok()?;
        mac.update(&self.spki);
        let hmac_sig = mac.finalize().into_bytes();

        let mut patched = self.cert_template_der.clone();
        patched[self.sig_offset..self.sig_offset + self.sig_len].copy_from_slice(&hmac_sig);

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der_bytes.clone()));
        let key = self.provider.key_provider.load_private_key(key_der).ok()?;
        Some(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(patched)],
            Arc::new(AlwaysEd25519(key)),
        )))
    }
}

/// Как настоящий REALITY-сервер (`hs.sigAlg = Ed25519` в
/// `handshake_server_tls13.go`): подписывать CertificateVerify через
/// Ed25519 всегда, даже если клиент его не заявил. Клиент заявляет
/// `signature_algorithms` как Chrome (без Ed25519), а обычный rustls-сервер
/// в таком случае честно отказывается подписывать.
#[derive(Debug)]
struct AlwaysEd25519(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for AlwaysEd25519 {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0.choose_scheme(&[SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Собрать `ServerConfig` тестового REALITY-сервера плюс его публичный
/// REALITY-ключ (`pbk=` для клиентской ссылки). `alpn` — как и везде,
/// пусто для TCP, `[b"h2"]` для gRPC.
fn build_reality_server_config(alpn: Vec<Vec<u8>>) -> (ServerConfig, [u8; 32]) {
    let provider = CryptoProvider::get_default()
        .cloned()
        .expect("crypto-провайдер должен быть установлен до вызова (ensure_crypto_provider)");

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("сгенерировать Ed25519-ключ");
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params
        .self_signed(&key_pair)
        .expect("самоподписать сертификат-заготовку");
    let cert_template_der = cert.der().to_vec();

    let (_, parsed) = x509_parser::parse_x509_certificate(&cert_template_der).unwrap();
    let spki: [u8; 32] = parsed
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .expect("Ed25519 SPKI должен быть 32 байта");
    let sig_len = parsed.signature_value.data.as_ref().len();
    let sig_offset = find_subslice(&cert_template_der, parsed.signature_value.data.as_ref())
        .expect("подпись-заготовка должна быть непрерывным срезом в DER");
    assert_eq!(
        sig_len, 64,
        "HMAC-SHA512 даёт 64 байта — ровно длина Ed25519-подписи, иначе патч сломает DER"
    );

    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let server_reality_static = StaticSecret::random_from_rng(&mut rng);
    let server_reality_public = X25519PublicKey::from(&server_reality_static).to_bytes();

    let resolver = Arc::new(RealityTestResolver {
        server_reality_static,
        spki,
        cert_template_der,
        sig_offset,
        sig_len,
        key_der_bytes: key_pair.serialize_der(),
        provider,
    });

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_config.alpn_protocols = alpn;

    (server_config, server_reality_public)
}

fn reality_client_uri(port: u16, server_pub: &[u8; 32], id: Uuid, extra: &str) -> String {
    use base64::Engine;
    let pbk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub);
    format!(
        "vless://{id}@127.0.0.1:{port}?encryption=none&security=reality&sni=localhost&pbk={pbk_b64}&sid=aabbccdd{extra}"
    )
}

#[tokio::test]
async fn reality_full_handshake_over_tcp() {
    ensure_crypto_provider();
    let (server_config, server_pub) = build_reality_server_config(Vec::new());
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let id = Uuid::new_v4();
    let id_for_server = id;

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor
            .accept(tcp)
            .await
            .expect("серверное REALITY TLS-рукопожатие должно пройти — клиент обязан принять HMAC-подписанный сертификат");
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );

        let mut prefix = [0u8; 1 + 16 + 1 + 1 + 2 + 1];
        tls.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[1..17], id_for_server.as_bytes());
        let mut len_buf = [0u8; 1];
        tls.read_exact(&mut len_buf).await.unwrap();
        let mut domain = vec![0u8; len_buf[0] as usize];
        tls.read_exact(&mut domain).await.unwrap();
        assert_eq!(domain, b"example.com");

        tls.write_all(&[0x00, 0x00]).await.unwrap();
        tls.write_all(b"pong").await.unwrap();
        tls.flush().await.unwrap();
    });

    let uri = reality_client_uri(addr.port(), &server_pub, id, "");
    let cfg = VlessConfig::parse(&uri).unwrap();
    let target = Address::Domain("example.com".to_string());

    let mut client = connect_and_handshake(&cfg, &id, target, 443)
        .await
        .expect("полный REALITY-хендшейк через боевую connect_and_handshake должен пройти");

    let mut got = [0u8; 4];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");

    server_task.await.unwrap();
}

#[tokio::test]
async fn reality_full_handshake_over_ws() {
    use async_tungstenite::accept_async;
    use async_tungstenite::tungstenite::Message;
    use futures_util::StreamExt;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    ensure_crypto_provider();
    let (server_config, server_pub) = build_reality_server_config(Vec::new());
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let id = Uuid::new_v4();
    let id_for_server = id;

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor
            .accept(tcp)
            .await
            .expect("серверное REALITY TLS-рукопожатие (под WS) должно пройти");
        let mut ws = accept_async(tls.compat())
            .await
            .expect("серверное WS-рукопожатие");

        let mut buf = Vec::new();
        while buf.len() < REQUEST_HEADER_LEN {
            match ws.next().await {
                Some(Ok(Message::Binary(b))) => buf.extend_from_slice(&b),
                other => panic!("ожидался Binary-фрейм с заголовком VLESS, получено {other:?}"),
            }
        }
        assert_eq!(&buf[1..17], id_for_server.as_bytes());

        ws.send(Message::Binary(vec![0x00, 0x00].into()))
            .await
            .unwrap();
        ws.send(Message::Binary(b"pong".to_vec().into()))
            .await
            .unwrap();
    });

    let uri = reality_client_uri(addr.port(), &server_pub, id, "&type=ws&path=/vless");
    let cfg = VlessConfig::parse(&uri).unwrap();
    let target = Address::Domain("example.com".to_string());

    let mut client = connect_and_handshake_ws(&cfg, &id, target, 443)
        .await
        .expect("полный REALITY-хендшейк через боевую connect_and_handshake_ws должен пройти");

    let mut got = [0u8; 4];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");

    server_task.await.unwrap();
}

#[tokio::test]
async fn reality_full_handshake_over_grpc() {
    use http::{Response, StatusCode};

    ensure_crypto_provider();
    let (server_config, server_pub) = build_reality_server_config(vec![b"h2".to_vec()]);
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let id = Uuid::new_v4();
    let id_for_server = id;

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor
            .accept(tcp)
            .await
            .expect("серверное REALITY TLS-рукопожатие (под gRPC/ALPN h2) должно пройти");

        let mut h2_conn = h2::server::handshake(tls)
            .await
            .expect("серверное h2-рукопожатие");
        let (request, mut respond) = h2_conn.accept().await.unwrap().unwrap();
        assert!(request.uri().path().ends_with("/Tun"));

        tokio::spawn(async move { while h2_conn.accept().await.is_some() {} });

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(response, false).unwrap();

        let mut recv_stream = request.into_body();
        let mut decoder = HunkDecoder::default();
        let mut header_buf = Vec::new();
        let mut sent_response_header = false;

        while let Some(chunk) = recv_stream.data().await {
            let chunk = chunk.unwrap();
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
            decoder.feed(&chunk);
            while let Ok(Some(payload)) = decoder.next_message() {
                if !sent_response_header {
                    header_buf.extend_from_slice(&payload);
                    if header_buf.len() >= REQUEST_HEADER_LEN {
                        assert_eq!(&header_buf[1..17], id_for_server.as_bytes());
                        // Заголовок ответа VLESS (версия=0, addons_len=0)
                        // обязан идти перед данными: `VlessStream` на
                        // клиенте снимает первые 2 байта (+N байт addons)
                        // как этот заголовок. Без него первые байты
                        // полезной нагрузки были бы приняты за
                        // (версия, addons_len) — так этот тест и падал при
                        // первой сборке.
                        send_stream
                            .send_data(Bytes::from(encode_hunk_frame(&[0x00, 0x00])), false)
                            .unwrap();
                        send_stream
                            .send_data(Bytes::from(encode_hunk_frame(b"pong")), false)
                            .unwrap();
                        sent_response_header = true;
                    }
                }
            }
        }
        let _ = send_stream.send_data(Bytes::new(), true);
    });

    let uri = reality_client_uri(
        addr.port(),
        &server_pub,
        id,
        "&type=grpc&serviceName=testsvc",
    );
    let cfg = VlessConfig::parse(&uri).unwrap();
    let target = Address::Domain("example.com".to_string());

    let mut client = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connect_and_handshake_grpc(&cfg, &id, target, 443),
    )
    .await
    .expect("не должно зависать — если зависло, значит сервер этого теста не досылает VLESS-заголовок ответа")
    .expect("полный REALITY-хендшейк через боевую connect_and_handshake_grpc должен пройти");

    let mut got = [0u8; 4];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
}
