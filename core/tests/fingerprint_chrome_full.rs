//! Этап 3 — итоговая сверка ClientHello с Chrome 133 (эталон —
//! `HelloChrome_133` из refraction-networking/utls, `u_parrots.go`).
//!
//! Снимается ClientHello, который реально уходит в сеть по боевому пути
//! (`transport::dial`), и сравнивается с Chrome поэлементно, без учёта
//! GREASE-значений (они случайные) и порядка расширений (Chrome
//! перемешивает их на каждое соединение, как и мы).
//!
//! - REALITY: полное совпадение, включая JA4 — у Chrome 131+
//!   `t13d1516h2_8daaf6152771_d8a2da3f94cd`.
//! - Обычный TLS: без 6 legacy cipher suite'ов (решение пользователя —
//!   заявлять их только для REALITY) и без ALPS (rustls не умеет
//!   отвечать на согласованный ALPS, см. `chrome_profile.rs`).

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use reality_core::fingerprint::{analyze_record, is_grease, FingerprintReport};
use reality_core::transport::{dial, tcp_tls::ensure_crypto_provider};
use reality_core::vless::{Address, Command, VlessConfig};

const CHROME_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const CHROME_EXTENSIONS: &[u16] = &[
    0x0000, // server_name
    0x0017, // extended_master_secret
    0xff01, // renegotiation_info
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x0023, // session_ticket
    0x0010, // ALPN
    0x0005, // status_request
    0x000d, // signature_algorithms
    0x0012, // SCT
    0x0033, // key_share
    0x002d, // psk_key_exchange_modes
    0x002b, // supported_versions
    0x001b, // compress_certificate
    0x44cd, // ALPS (новая нумерация)
    0xfe0d, // ECH (GREASE)
];
const CHROME_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const CHROME_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

/// Поднять «сервер», который только запоминает первый TLS-рекорд, и
/// направить на него настоящий клиентский путь.
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

fn non_grease(v: &[u16]) -> Vec<u16> {
    v.iter().copied().filter(|&x| !is_grease(x)).collect()
}

fn sorted(mut v: Vec<u16>) -> Vec<u16> {
    v.sort_unstable();
    v
}

#[tokio::test]
async fn reality_client_hello_matches_chrome_133() {
    let pbk = "4vSEHUvbWnco7zA7pY5Uoaiq6XAHPN-t9i2MVzpoSDw";
    let r = capture(&format!(
        "security=reality&sni=example.com&pbk={pbk}&sid=01&type=tcp"
    ))
    .await;
    let i = &r.info;
    assert_eq!(
        non_grease(&i.cipher_suites),
        CHROME_CIPHERS,
        "cipher suites"
    );
    assert!(is_grease(i.cipher_suites[0]));
    assert_eq!(
        sorted(non_grease(&i.extensions)),
        sorted(CHROME_EXTENSIONS.to_vec()),
        "набор расширений"
    );
    assert_eq!(i.signature_algorithms, CHROME_SIGALGS);
    assert_eq!(
        non_grease(&i.elliptic_curves),
        [0x11ec, 0x001d, 0x0017, 0x0018]
    );
    assert_eq!(non_grease(&i.key_share_groups), [0x11ec, 0x001d]);
    assert_eq!(non_grease(&i.supported_versions), [0x0304, 0x0303]);
    assert_eq!(i.alpn, ["h2", "http/1.1"]);
    assert_eq!(r.ja4, CHROME_JA4, "JA4 должен совпасть с Chrome 131+");
}

#[tokio::test]
async fn tls_client_hello_is_chrome_without_legacy_suites_and_alps() {
    let r = capture("security=tls&sni=example.com&type=tcp").await;
    let i = &r.info;
    assert_eq!(non_grease(&i.cipher_suites), &CHROME_CIPHERS[..9]);
    assert!(
        !i.cipher_suites.contains(&0x00ff),
        "SCSV заменён расширением renegotiation_info"
    );
    let expected: Vec<u16> = CHROME_EXTENSIONS
        .iter()
        .copied()
        .filter(|&e| e != 0x44cd)
        .collect();
    assert_eq!(sorted(non_grease(&i.extensions)), sorted(expected));
    assert_eq!(i.signature_algorithms, CHROME_SIGALGS);
    assert_eq!(non_grease(&i.supported_versions), [0x0304, 0x0303]);
    assert!(r.ja4.starts_with("t13d0915h2_"), "{}", r.ja4);
}

#[tokio::test]
async fn websocket_offers_http11_only_and_grpc_h2_only() {
    let ws = capture("security=tls&sni=example.com&type=ws&path=%2F").await;
    assert_eq!(ws.info.alpn, ["http/1.1"]);
    let grpc = capture("security=tls&sni=example.com&type=grpc&serviceName=s").await;
    assert_eq!(grpc.info.alpn, ["h2"]);
    let custom = capture("security=tls&sni=example.com&alpn=http%2F1.1").await;
    assert_eq!(custom.info.alpn, ["http/1.1"]);
}
