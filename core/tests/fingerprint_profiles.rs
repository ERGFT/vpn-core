// SPDX-License-Identifier: GPL-3.0-or-later
//! Фаза 7 — ClientHello Firefox 148 и Safari 26.3 (эталоны — `u_parrots.go`
//! из refraction-networking/utls). Снимается то, что реально уходит в сеть
//! по боевому пути, и сверяется поэлементно: cipher suites, расширения В
//! ПОРЯДКЕ (у этих браузеров он фиксированный), группы, доли ключа,
//! версии, подписи, сжатие сертификата, GREASE. Плюс настоящие
//! рукопожатия: сервер, умеющий только P-256, выбирает долю P-256 Firefox;
//! алгоритмы сжатия сертификата (zlib, zstd) действительно распаковываются.

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use reality_core::fingerprint::{analyze_record, is_grease, Browser, FingerprintReport};
use reality_core::transport::dial;
use reality_core::transport::tcp_tls::{connect_tls_with_roots_alpn, ensure_crypto_provider};
use reality_core::vless::{Address, Command, VlessConfig};

const PBK: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

async fn capture(link_tail: &str) -> FingerprintReport {
    ensure_crypto_provider();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let cfg = VlessConfig::parse(&format!(
        "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:{port}?{link_tail}"
    ))
    .unwrap();
    let client = tokio::spawn(async move {
        let _ = dial(
            &cfg,
            &cfg.id,
            Command::Tcp,
            Address::Domain("x.test".into()),
            443,
        )
        .await;
    });
    let (mut s, _) = l.accept().await.unwrap();
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr).await.unwrap();
    let mut body = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
    s.read_exact(&mut body).await.unwrap();
    drop(s);
    client.abort();
    let mut rec = hdr.to_vec();
    rec.extend(body);
    analyze_record(&rec).unwrap()
}

fn no_grease(v: &[u16]) -> Vec<u16> {
    v.iter().copied().filter(|&x| !is_grease(x)).collect()
}

fn reality(fp: &str) -> String {
    format!("security=reality&sni=www.site.test&pbk={PBK}&sid=ab&type=tcp&fp={fp}")
}

const FIREFOX_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
];
const FIREFOX_LEGACY: &[u16] = &[
    0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const FIREFOX_EXTS: &[u16] = &[
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b, 0x000d,
    0x001c, 0x001b, 0xfe0d,
];
const FIREFOX_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];

const SAFARI_CIPHERS: &[u16] = &[
    0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
];
const SAFARI_LEGACY: &[u16] = &[
    0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const SAFARI_EXTS: &[u16] = &[
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b,
    0x001b,
];
const SAFARI_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

#[tokio::test]
async fn firefox_client_hello_matches_firefox_148() {
    for (tail, is_reality) in [
        (reality("firefox"), true),
        (
            "security=tls&sni=site.test&type=tcp&fp=firefox".to_string(),
            false,
        ),
    ] {
        let r = capture(&tail).await;
        let i = &r.info;
        let mut want = FIREFOX_CIPHERS.to_vec();
        if is_reality {
            want.extend_from_slice(FIREFOX_LEGACY);
        }
        assert_eq!(i.cipher_suites, want, "{tail}: у Firefox нет GREASE");
        assert_eq!(
            i.extensions, FIREFOX_EXTS,
            "{tail}: порядок расширений Firefox"
        );
        assert_eq!(
            i.elliptic_curves,
            [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
        );
        assert_eq!(i.key_share_groups, [0x11ec, 0x001d, 0x0017], "{tail}");
        assert_eq!(i.supported_versions, [0x0304, 0x0303]);
        assert_eq!(i.signature_algorithms, FIREFOX_SIGALGS);
        assert_eq!(i.compress_certificate, [1, 2, 3], "zlib, brotli, zstd");
        assert_eq!(i.alpn, ["h2", "http/1.1"]);
        assert!(i.grease_extensions.is_empty());
    }
}

#[tokio::test]
async fn safari_client_hello_matches_safari_26() {
    for fp in ["safari", "ios"] {
        for (tail, is_reality) in [
            (reality(fp), true),
            (
                format!("security=tls&sni=site.test&type=tcp&fp={fp}"),
                false,
            ),
        ] {
            let r = capture(&tail).await;
            let i = &r.info;
            assert!(is_grease(i.cipher_suites[0]), "{tail}: GREASE первым");
            let mut want = SAFARI_CIPHERS.to_vec();
            if is_reality {
                want.extend_from_slice(SAFARI_LEGACY);
            }
            assert_eq!(no_grease(&i.cipher_suites), want, "{tail}");
            // GREASE первым и последним, между ними — порядок Safari.
            assert!(is_grease(i.extensions[0]) && is_grease(*i.extensions.last().unwrap()));
            assert_eq!(no_grease(&i.extensions), SAFARI_EXTS, "{tail}");
            assert!(is_grease(i.elliptic_curves[0]));
            assert_eq!(
                no_grease(&i.elliptic_curves),
                [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
            );
            assert_eq!(i.key_share_groups[1..], [0x11ec, 0x001d]);
            assert_eq!(i.key_share_groups[0], i.elliptic_curves[0]);
            assert!(is_grease(i.supported_versions[0]));
            assert_eq!(i.supported_versions[1..], [0x0304, 0x0303]);
            assert_eq!(i.signature_algorithms, SAFARI_SIGALGS);
            assert_eq!(i.compress_certificate, [1], "только zlib");
        }
    }
}

#[tokio::test]
async fn chrome_edge_android_stay_chrome() {
    for fp in ["chrome", "edge", "android", ""] {
        let r = capture(&reality(fp)).await;
        assert_eq!(r.ja4, "t13d1516h2_8daaf6152771_d8a2da3f94cd", "fp={fp}");
    }
    assert_eq!(Browser::from_fp(Some("qq")).0, Browser::Chrome);
    assert!(
        Browser::from_fp(Some("qq")).1.is_some(),
        "неизвестный — с предупреждением"
    );
    // random — один на запуск.
    let a = Browser::from_fp(Some("random")).0;
    for _ in 0..10 {
        assert_eq!(Browser::from_fp(Some("random")).0, a);
    }
}

/// TLS-сервер с заданными группами и сжатием сертификата; отвечает "ok".
async fn tls_server(
    groups: &[rustls::NamedGroup],
    compress: Vec<&'static dyn rustls::compress::CertCompressor>,
) -> (u16, RootCertStore) {
    let ck = generate_simple_self_signed(vec!["site.test".to_string()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups.retain(|g| groups.contains(&g.name()));
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![ck.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der())),
        )
        .unwrap();
    cfg.cert_compressors = compress;
    let acc = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acc = acc.clone();
            tokio::spawn(async move {
                if let Ok(mut t) = acc.accept(s).await {
                    let _ = t.write_all(b"ok").await;
                    let _ = t.flush().await;
                    let mut b = [0u8; 16];
                    let _ = t.read(&mut b).await;
                }
            });
        }
    });
    (port, roots)
}

async fn handshake(
    port: u16,
    fp: &str,
    roots: RootCertStore,
) -> (Option<rustls::NamedGroup>, Option<rustls::HandshakeKind>) {
    let cfg = VlessConfig::parse(&format!(
        "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:{port}?security=tls&sni=site.test&fp={fp}"
    ))
    .unwrap();
    let mut t = connect_tls_with_roots_alpn(&cfg, roots, vec![])
        .await
        .unwrap_or_else(|e| panic!("fp={fp}: {e}"));
    let mut b = [0u8; 2];
    t.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ok");
    let c = t.get_ref().1;
    (
        c.negotiated_key_exchange_group().map(|g| g.name()),
        c.handshake_kind(),
    )
}

#[tokio::test]
async fn firefox_p256_share_is_real() {
    ensure_crypto_provider();
    use rustls::NamedGroup as G;
    // Сервер без X25519 и ML-KEM: Firefox завершает по своей доле P-256
    // без HelloRetryRequest; Chrome и Safari получают HRR и тоже доходят.
    let (port, roots) = tls_server(&[G::secp256r1], vec![]).await;
    use rustls::HandshakeKind as K;
    assert_eq!(
        handshake(port, "firefox", roots.clone()).await,
        (Some(G::secp256r1), Some(K::Full)),
        "Firefox: доля P-256 без HRR"
    );
    for fp in ["safari", "chrome"] {
        assert_eq!(
            handshake(port, fp, roots.clone()).await,
            (Some(G::secp256r1), Some(K::FullWithHelloRetryRequest)),
            "{fp}"
        );
    }
    // Обычный сервер — гибрид.
    let (port, roots) = tls_server(&[G::X25519MLKEM768, G::X25519, G::secp256r1], vec![]).await;
    for fp in ["firefox", "safari", "chrome"] {
        assert_eq!(
            handshake(port, fp, roots.clone()).await,
            (Some(G::X25519MLKEM768), Some(K::Full)),
            "{fp}"
        );
    }
    // Сервер только с X25519 — доля X25519 из гибрида.
    let (port, roots) = tls_server(&[G::X25519], vec![]).await;
    for fp in ["firefox", "safari", "chrome"] {
        assert_eq!(
            handshake(port, fp, roots.clone()).await.0,
            Some(G::X25519),
            "{fp}"
        );
    }
}

/// Сжатие сертификата zlib — как у сервера, который его поддерживает.
#[derive(Debug)]
struct ZlibCompressor;

impl rustls::compress::CertCompressor for ZlibCompressor {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: rustls::compress::CompressionLevel,
    ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
        Ok(miniz_oxide::deflate::compress_to_vec_zlib(&input, 6))
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Zlib
    }
}

/// zstd: «несжатые» кадры (raw block) — валидный поток zstd, который
/// обязан разобрать любой распаковщик; так тест не тянет компрессор.
#[derive(Debug)]
struct ZstdRawCompressor;

impl rustls::compress::CertCompressor for ZstdRawCompressor {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: rustls::compress::CompressionLevel,
    ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
        // Кадр: магия, заголовок (Single_Segment, размер — 4 байта), блоки.
        let mut out = vec![0x28, 0xb5, 0x2f, 0xfd, 0b1010_0000];
        out.extend_from_slice(&(input.len() as u32).to_le_bytes());
        let chunks: Vec<&[u8]> = input.chunks(100_000).collect();
        for (i, c) in chunks.iter().enumerate() {
            let last = (i + 1 == chunks.len()) as u32;
            let hdr = last | (c.len() as u32) << 3; // тип 0 — Raw
            out.extend_from_slice(&hdr.to_le_bytes()[..3]);
            out.extend_from_slice(c);
        }
        Ok(out)
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Zstd
    }
}

static ZLIB_C: ZlibCompressor = ZlibCompressor;
static ZSTD_C: ZstdRawCompressor = ZstdRawCompressor;

#[tokio::test]
async fn compressed_certificates_are_decompressed() {
    ensure_crypto_provider();
    use rustls::NamedGroup as G;
    let (port, roots) = tls_server(&[G::X25519], vec![&ZLIB_C]).await;
    handshake(port, "safari", roots.clone()).await;
    handshake(port, "firefox", roots).await;
    let (port, roots) = tls_server(&[G::X25519], vec![&ZSTD_C]).await;
    handshake(port, "firefox", roots).await;
}
