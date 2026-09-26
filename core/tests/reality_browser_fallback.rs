//! Поведение при подмене REALITY-сервера настоящим сайтом.
//!
//! Цензор может перенаправить соединение на сам сайт-приманку: его
//! сертификат настоящий (здесь — выпущен тестовым CA, которому клиент
//! доверяет через `ca_roots`, как публичным корням в жизни), но проверку
//! REALITY он не проходит. Клиент обязан:
//! - довести рукопожатие до конца и сходить на сайт как браузер (как
//!   Xray), а не рвать соединение сразу после сертификата;
//! - НЕ отправить по такому соединению ни UUID, ни заголовок VLESS;
//! - вернуть вызывающему коду ошибку.
//!
//! И сертификат, которому не доверяет даже обычная проверка X.509, —
//! по-прежнему обрыв рукопожатия (так же делает Xray).

use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use reality_core::transport::dial;
use reality_core::transport::tcp_tls::ensure_crypto_provider;
use reality_core::vless::{Address, Command, VlessConfig};

/// CA и выпущенный им сертификат для `site.test`.
fn ca_and_leaf() -> (
    CertificateDer<'static>,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["site.test".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    (
        ca.der().clone(),
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
}

fn reality_cfg(port: u16, ca: Option<CertificateDer<'static>>) -> VlessConfig {
    use base64::Engine;
    let pbk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    let mut cfg = VlessConfig::parse(&format!(
        "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{port}?security=reality&sni=site.test&pbk={pbk}&sid=aa"
    ))
    .unwrap();
    if let Some(ca) = ca {
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        cfg.ca_roots = Some(Arc::new(roots));
    }
    cfg
}

/// «Настоящий сайт» по HTTP/1.1: возвращает всё, что клиент прислал
/// после рукопожатия.
async fn start_site(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> (u16, tokio::task::JoinHandle<Option<Vec<u8>>>) {
    let mut scfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    scfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(scfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.ok()?;
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let body = "<html>hello</html>";
        let _ = tls
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        let _ = tls.shutdown().await;
        Some(got)
    });
    (port, task)
}

#[tokio::test]
async fn real_site_gets_a_browser_visit_and_never_the_uuid() {
    ensure_crypto_provider();
    let (ca, chain, key) = ca_and_leaf();
    let (port, site) = start_site(chain, key).await;
    let cfg = reality_cfg(port, Some(ca));

    let err = dial(
        &cfg,
        &cfg.id,
        Command::Tcp,
        Address::Domain("x.test".into()),
        443,
    )
    .await
    .err()
    .expect("соединение с не-REALITY сайтом не должно отдаваться VLESS");
    assert!(err.to_string().contains("настоящий сайт"), "{err}");

    let got = tokio::time::timeout(Duration::from_secs(20), site)
        .await
        .unwrap()
        .unwrap()
        .expect("клиент должен завершить рукопожатие, как браузер");
    let text = String::from_utf8_lossy(&got);
    assert!(
        text.starts_with("GET / HTTP/1.1\r\nHost: site.test\r\n"),
        "{text}"
    );
    assert!(text.contains("Sec-Fetch-Mode: navigate"), "{text}");
    let uuid = cfg.id.as_bytes();
    assert!(
        !got.windows(16).any(|w| w == uuid),
        "UUID не должен уйти на настоящий сайт"
    );
}

#[tokio::test]
async fn untrusted_certificate_still_aborts_the_handshake() {
    ensure_crypto_provider();
    let (_ca, chain, key) = ca_and_leaf();
    let (port, site) = start_site(chain, key).await;
    let cfg = reality_cfg(port, None); // тестовому CA не доверяем
    let err = dial(
        &cfg,
        &cfg.id,
        Command::Tcp,
        Address::Domain("x.test".into()),
        443,
    )
    .await
    .err()
    .expect("недоверенный сертификат должен отвергаться");
    assert!(err.to_string().contains("REALITY"), "{err}");
    let got = tokio::time::timeout(Duration::from_secs(20), site)
        .await
        .unwrap()
        .unwrap();
    assert!(got.is_none(), "рукопожатие должно быть оборвано");
}

#[test]
fn degenerate_pbk_is_rejected_at_parse_time() {
    use base64::Engine;
    // Нулевой ключ и точка порядка 8 (RFC 7748) — общий секрет всегда 0.
    for key in [
        [0u8; 32],
        hex_literal("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    ] {
        let pbk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        let cfg = VlessConfig::parse(&format!(
            "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:1?security=reality&sni=s&pbk={pbk}"
        ))
        .unwrap();
        assert!(
            cfg.reality_params().is_err(),
            "pbk {pbk} должен отвергаться"
        );
    }
}

fn hex_literal(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

/// security=tls: подменный сервер с сертификатом, которому клиент не
/// доверяет (так выглядит перехват в чужой Wi-Fi), — рукопожатие
/// обрывается, UUID не уходит.
#[tokio::test]
async fn tls_link_refuses_untrusted_certificate() {
    ensure_crypto_provider();
    let (_ca, chain, key) = ca_and_leaf();
    let (port, site) = start_site(chain, key).await;
    let cfg = VlessConfig::parse(&format!(
        "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{port}?security=tls&sni=site.test"
    ))
    .unwrap();
    let err = dial(
        &cfg,
        &cfg.id,
        Command::Tcp,
        Address::Domain("x.test".into()),
        443,
    )
    .await
    .err()
    .expect("недоверенный сертификат должен отвергаться");
    assert!(
        err.to_string().to_lowercase().contains("certificate"),
        "{err}"
    );
    let got = tokio::time::timeout(Duration::from_secs(20), site)
        .await
        .unwrap()
        .unwrap();
    assert!(
        got.is_none(),
        "рукопожатие должно быть оборвано, данных нет"
    );
}
