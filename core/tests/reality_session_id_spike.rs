//! Этап 5 — СПАЙК: проверяет ЭКСПЕРИМЕНТАЛЬНО (не только по чтению
//! исходников), что минимальный патч `vendor/rustls-reality-patch` даёт
//! реальный контроль над `legacy_session_id` исходящего ClientHello, а не
//! только компилируется.
//!
//! Три вещи, которые могли бы пойти не так и которые здесь проверяются
//! на настоящем TCP+TLS до собственного тестового сервера (не юнит-тест
//! на синтетических байтах):
//!  1. Байты SessionId, которые мы просим отправить, РЕАЛЬНО оказываются
//!     на проводе — не отбрасываются, не перегенерируются.
//!  2. Согласованный протокол всё равно TLS 1.3 (фейковая TLS1.2-сессия
//!     не должна незаметно утащить рукопожатие в TLS1.2).
//!  3. Не появляется незапрошенных TLS1.2-специфичных расширений
//!     (`session_ticket`, 0x0023) — иначе это испортило бы Этап-3
//!     фингерпринт даже при рабочем REALITY.
//!
//! Механизм (см. `reality/mod.rs` и `PLAN.md`, Этап 5, для полной
//! картины): подсовываем `rustls` фейковую "TLS1.2-сессию для
//! резюмирования" через штатный (уже публичный, без патча) трейт
//! `ClientSessionStore` — но саму `Tls12ClientSessionValue` с нужным нам
//! `SessionId` смочь сконструировать вне крейта `rustls` можно только
//! благодаря патчу (без него оба типа/конструктора `pub(crate)`).
//! Тикет у фейковой сессии — пустой: по коду `client/hs.rs` (сверено
//! построчно, не угадано) это одновременно (а) не даёт `hs.rs`
//! перезаписать наш `session_id` свежим случайным, и (б) не даёт
//! `prepare_resumption` добавить расширение с тикетом — единственное,
//! что остаётся из "резюмирования" при пустом тикете и выключенном в
//! конфиге TLS1.2 — это сам факт, что `legacy_session_id` копируется из
//! нашей фейковой сессии, что нам и нужно.

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::{
    CertificateChain, ClientConfig, ClientSessionStore, ResolvesClientCert, Resumption, SessionId,
    Tls12ClientSessionValue, Tls13ClientSessionValue,
};
use rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
use rustls::internal::msgs::base::PayloadU16;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig, SignatureScheme, SupportedCipherSuite};
use rustls_pki_types::ServerName as PkiServerName;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use reality_core::fingerprint::{parse_record, CaptureFirstBytes};
use reality_core::transport::tcp_tls::ensure_crypto_provider;

/// Наш собственный "не поддерживаем клиентскую аутентификацию" резолвер
/// — не переиспользуем `rustls::client::handy::FailResolveClientCert`,
/// он `pub(crate)`; смысл тот же, реализация тривиальна.
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

/// `ClientSessionStore`, который для ЛЮБОГО `server_name` отдаёт одну и
/// ту же фейковую "TLS1.2-сессию" с заранее выбранным SessionId — и
/// больше ничего не хранит (`insert_tls13_ticket`/`set_tls12_session` —
/// no-op, нам чужие записи не нужны, только наша собственная инъекция).
#[derive(Debug)]
struct FixedSessionIdStore {
    session_id: [u8; 32],
    verifier: Arc<dyn ServerCertVerifier>,
    client_creds: Arc<dyn ResolvesClientCert>,
}

impl ClientSessionStore for FixedSessionIdStore {
    fn set_kx_hint(&self, _server_name: PkiServerName<'static>, _group: rustls::NamedGroup) {}
    fn kx_hint(&self, _server_name: &PkiServerName<'_>) -> Option<rustls::NamedGroup> {
        None
    }

    fn set_tls12_session(
        &self,
        _server_name: PkiServerName<'static>,
        _value: Tls12ClientSessionValue,
    ) {
    }

    fn tls12_session(&self, _server_name: &PkiServerName<'_>) -> Option<Tls12ClientSessionValue> {
        let SupportedCipherSuite::Tls12(suite) = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 else {
            unreachable!(
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 always resolves to the Tls12 variant"
            )
        };
        Some(Tls12ClientSessionValue::new(
            suite,
            SessionId::from_bytes_public(&self.session_id),
            Arc::new(PayloadU16::new(Vec::new())),
            &[0u8; 48], // фиктивный master_secret — не читается при пустом тикете (см. hs.rs)
            CertificateChain::empty(),
            &self.verifier,
            &self.client_creds,
            UnixTime::now(),
            0, // lifetime_secs=0 => has_expired() всегда false, см. persist.rs
            false,
        ))
    }

    fn remove_tls12_session(&self, _server_name: &PkiServerName<'static>) {}

    fn insert_tls13_ticket(
        &self,
        _server_name: PkiServerName<'static>,
        _value: Tls13ClientSessionValue,
    ) {
    }

    fn take_tls13_ticket(
        &self,
        _server_name: &PkiServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        None
    }
}

#[tokio::test]
async fn injected_session_id_reaches_the_wire_over_real_tls13() {
    ensure_crypto_provider();

    // --- тестовый сервер: самоподписанный сертификат, как в tls_loopback.rs ---
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
        let tls = acceptor
            .accept(tcp)
            .await
            .expect("серверное TLS-рукопожатие");
        // Согласованная версия протокола видна и на сервере — двойная
        // проверка (не только по тому, что видит клиент).
        let negotiated = tls.get_ref().1.protocol_version();
        assert_eq!(
            negotiated,
            Some(rustls::ProtocolVersion::TLSv1_3),
            "сервер должен был согласовать TLS 1.3, а не откатиться на 1.2"
        );
    });

    // --- клиент: тот же verifier/client_creds Arc и в ClientConfig, и в
    //     нашем ClientSessionStore — это ОБЯЗАТЕЛЬНО (Weak::ptr_eq в
    //     rustls::msgs::persist::ClientSessionCommon::compatible_config
    //     иначе молча отвергнет нашу фейковую сессию как "не для этого
    //     конфига", и мы получим случайный SessionId, ничего не заметив).
    let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let verifier_for_store: Arc<dyn ServerCertVerifier> = webpki_verifier.clone();
    let client_creds: Arc<dyn ResolvesClientCert> = Arc::new(NoClientAuth);

    let chosen_session_id: [u8; 32] = {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        } // 00 01 02 .. 1f — легко узнать в дампе
        b
    };

    // ВАЖНО (найдено эмпирически, не предсказано заранее — первый прогон
    // этого теста падал ровно тут): обычный `ClientConfig::builder()`
    // поддерживает TLS1.2 по умолчанию, и тогда `prepare_resumption`
    // добавляет расширение `session_ticket` (0x0023) даже при пустом
    // тикете — сам факт, что TLS1.2 в принципе разрешён конфигом, уже
    // достаточен. Только явное ограничение версий до TLS1.3 убирает эту
    // утечку в фингерпринт.
    let mut client_config =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_webpki_verifier(webpki_verifier)
            .with_client_cert_resolver(client_creds.clone());
    // TLS1.2 не поддерживаем вообще — иначе даже с пустым тикетом
    // `prepare_resumption` добавит расширение `session_ticket` (request),
    // а это лишний, никем не просимый штрих в фингерпринте (Этап 3).
    client_config.resumption = Resumption::store(Arc::new(FixedSessionIdStore {
        session_id: chosen_session_id,
        verifier: verifier_for_store,
        client_creds,
    }));

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost").unwrap();

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let captured_tcp = CaptureFirstBytes::new(tcp, 4096);
    let mut tls = connector
        .connect(server_name, captured_tcp)
        .await
        .expect("клиентское TLS-рукопожатие с фейковой TLS1.2-сессией для инъекции session_id");

    // Согласованная версия на клиенте — тоже TLS 1.3.
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "клиент тоже должен видеть TLS 1.3, а не откат на 1.2"
    );

    let captured = tls.get_ref().0.captured().to_vec();
    let mut buf = [0u8; 1];
    // Не нужен реальный обмен данными — но подождать закрытия сервер-таска
    // стоит, читая до EOF/ошибки, чтобы получить его assert (иначе
    // паника в spawn-таске тихо потеряется).
    let _ = tls.read(&mut buf).await;

    server_task.await.unwrap();

    let info = parse_record(&captured).expect("разобрать перехваченный ClientHello");

    assert_eq!(
        info.session_id, chosen_session_id,
        "SessionId, реально ушедший в сеть, должен побайтово совпасть с тем, что мы вычислили сами \
         (а не быть случайным/усечённым/перезаписанным rustls) — session_id из провода: {:02x?}",
        info.session_id
    );

    assert!(
        !info.extensions.contains(&0x0023),
        "не должно быть лишнего расширения session_ticket (0x0023) — иначе фейковая TLS1.2-сессия \
         протекает в фингерпринт ClientHello сверх того, что нам нужно; расширения: {:02x?}",
        info.extensions
    );
}
