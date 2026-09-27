// SPDX-License-Identifier: GPL-3.0-or-later
//! Фаза 7 — ClientHello разных браузеров (`fp=` в ссылке, как у Xray):
//! `chrome` (по умолчанию), `firefox`, `safari`, `ios`, `edge`, `android`,
//! `random`, `randomized`.
//!
//! Эталоны — `refraction-networking/utls`, `u_parrots.go` (та же библиотека,
//! на которой держится REALITY-клиент Xray): `HelloChrome_133`,
//! `HelloFirefox_148`, `HelloSafari_26_3`. Что куда отображается:
//!
//! | fp | профиль | почему |
//! |---|---|---|
//! | `chrome`, пусто | Chrome 133 | как у Xray |
//! | `firefox` | Firefox 148 | как у Xray (`HelloFirefox_Auto`) |
//! | `safari` | Safari 26.3 | как у Xray (`HelloSafari_Auto`) |
//! | `ios` | Safari 26.3 | у Xray — iOS 14 (TLS 1.3 без ML-KEM, 2020 г.); нынешний iOS — тот же стек, что Safari 26 |
//! | `edge` | Chrome 133 | у Xray — Edge 85 (2020 г.); нынешний Edge — Chromium, ClientHello как у Chrome |
//! | `android` | Chrome 133 | у Xray — OkHttp на Android 11: только TLS 1.2, с REALITY не работает вовсе |
//! | `random` | один из трёх, на весь запуск | как у Xray |
//! | `randomized` | один из трёх, на каждый выход | у Xray — случайные параметры utls; такой ClientHello не похож ни на один браузер |
//!
//! Что совпадает с эталоном: состав и порядок cipher suites (legacy-хвост —
//! только у REALITY, как и у Chrome), групп, `signature_algorithms`,
//! версий, ALPN, алгоритмов сжатия сертификата; набор расширений и их
//! порядок (у Firefox и Safari порядок фиксированный, у Chrome —
//! случайный на каждое соединение); GREASE (у Firefox его нет); доли
//! ключа (у Firefox — ещё и P-256, настоящая). Чего нет: побайтовой длины
//! ECH-GREASE у Firefox; `record_size_limit` Firefox заявляется, но свой
//! предел записей сервера клиент не соблюдает (серверы на Go, BoringSSL и
//! OpenSSL его не присылают).

use std::sync::OnceLock;

use rand::Rng;
use rustls::crypto::CryptoProvider;
use rustls::{CipherSuite, SignatureScheme};

/// Браузер, чей ClientHello и HTTP-заголовки изображаются.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Browser {
    Chrome,
    Firefox,
    Safari,
}

const ALL: [Browser; 3] = [Browser::Chrome, Browser::Firefox, Browser::Safari];

impl Browser {
    /// Браузер по `fp=` из ссылки. Второе значение — предупреждение для
    /// журнала (если значение заменено или неизвестно).
    pub fn from_fp(fp: Option<&str>) -> (Browser, Option<String>) {
        let fp = fp.unwrap_or("").trim().to_ascii_lowercase();
        match fp.as_str() {
            "" | "chrome" | "none" => (Browser::Chrome, None),
            "firefox" => (Browser::Firefox, None),
            "safari" | "ios" => (Browser::Safari, None),
            "edge" | "android" => (Browser::Chrome, None),
            "random" => {
                static R: OnceLock<Browser> = OnceLock::new();
                (*R.get_or_init(pick), None)
            }
            "randomized" | "randomizednoalpn" => (pick(), None),
            other => (
                Browser::Chrome,
                Some(format!(
                    "fp={other} не поддерживается (chrome, firefox, safari, ios, edge, android, random, randomized) — ClientHello как у Chrome"
                )),
            ),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Firefox => "firefox",
            Browser::Safari => "safari",
        }
    }
}

fn pick() -> Browser {
    ALL[rand::thread_rng().gen_range(0..ALL.len())]
}

use CipherSuite as C;

/// Реализованные suite'ы в порядке браузера (остальные — `legacy`).
fn cipher_order(b: Browser) -> &'static [CipherSuite] {
    match b {
        Browser::Chrome => &[
            C::TLS13_AES_128_GCM_SHA256,
            C::TLS13_AES_256_GCM_SHA384,
            C::TLS13_CHACHA20_POLY1305_SHA256,
            C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ],
        Browser::Firefox => &[
            C::TLS13_AES_128_GCM_SHA256,
            C::TLS13_CHACHA20_POLY1305_SHA256,
            C::TLS13_AES_256_GCM_SHA384,
            C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ],
        Browser::Safari => &[
            C::TLS13_AES_256_GCM_SHA384,
            C::TLS13_CHACHA20_POLY1305_SHA256,
            C::TLS13_AES_128_GCM_SHA256,
            C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ],
    }
}

/// Хвост списка — не реализованные suite'ы (только для REALITY: там
/// возможен лишь TLS 1.3, выбрать их сервер не может).
fn legacy_suites(b: Browser) -> &'static [u16] {
    match b {
        Browser::Chrome => super::chrome_profile::CHROME_LEGACY_SUITES,
        Browser::Firefox => &[
            0xc00a, // ECDHE_ECDSA_AES_256_CBC_SHA
            0xc009, // ECDHE_ECDSA_AES_128_CBC_SHA
            0xc013, // ECDHE_RSA_AES_128_CBC_SHA
            0xc014, // ECDHE_RSA_AES_256_CBC_SHA
            0x009c, // RSA_AES_128_GCM_SHA256
            0x009d, // RSA_AES_256_GCM_SHA384
            0x002f, // RSA_AES_128_CBC_SHA
            0x0035, // RSA_AES_256_CBC_SHA
        ],
        Browser::Safari => &[
            0xc00a, // ECDHE_ECDSA_AES_256_CBC_SHA
            0xc009, // ECDHE_ECDSA_AES_128_CBC_SHA
            0xc014, // ECDHE_RSA_AES_256_CBC_SHA
            0xc013, // ECDHE_RSA_AES_128_CBC_SHA
            0x009d, // RSA_AES_256_GCM_SHA384
            0x009c, // RSA_AES_128_GCM_SHA256
            0x0035, // RSA_AES_256_CBC_SHA
            0x002f, // RSA_AES_128_CBC_SHA
            0xc008, // ECDHE_ECDSA_3DES_EDE_CBC_SHA
            0xc012, // ECDHE_RSA_3DES_EDE_CBC_SHA
            0x000a, // RSA_3DES_EDE_CBC_SHA
        ],
    }
}

/// Переставить suite'ы провайдера в порядке браузера.
pub fn order_cipher_suites(mut provider: CryptoProvider, b: Browser) -> CryptoProvider {
    let order = cipher_order(b);
    provider.cipher_suites.sort_by_key(|cs| {
        order
            .iter()
            .position(|&w| w == cs.suite())
            .unwrap_or(order.len())
    });
    provider
}

use SignatureScheme as S;

fn signature_schemes(b: Browser) -> Vec<SignatureScheme> {
    match b {
        Browser::Chrome => super::chrome_profile::CHROME_SIGNATURE_SCHEMES.to_vec(),
        Browser::Firefox => vec![
            S::ECDSA_NISTP256_SHA256,
            S::ECDSA_NISTP384_SHA384,
            S::ECDSA_NISTP521_SHA512,
            S::RSA_PSS_SHA256,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA512,
            S::RSA_PKCS1_SHA256,
            S::RSA_PKCS1_SHA384,
            S::RSA_PKCS1_SHA512,
            S::ECDSA_SHA1_Legacy,
            S::RSA_PKCS1_SHA1,
        ],
        // Дважды RSA_PSS_SHA384 — так у Safari 26 (и в эталоне utls).
        Browser::Safari => vec![
            S::ECDSA_NISTP256_SHA256,
            S::RSA_PSS_SHA256,
            S::RSA_PKCS1_SHA256,
            S::ECDSA_NISTP384_SHA384,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA384,
            S::RSA_PKCS1_SHA384,
            S::RSA_PSS_SHA512,
            S::RSA_PKCS1_SHA512,
            S::RSA_PKCS1_SHA1,
        ],
    }
}

/// supported_groups без GREASE (его ставит патч rustls).
fn named_groups(b: Browser) -> Vec<u16> {
    match b {
        Browser::Chrome => Vec::new(), // по умолчанию: MLKEM, X25519, P-256, P-384
        Browser::Firefox => vec![0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
        Browser::Safari => vec![0x11ec, 0x001d, 0x0017, 0x0018, 0x0019],
    }
}

// Типы расширений.
const SNI: u16 = 0;
const STATUS_REQUEST: u16 = 5;
const GROUPS: u16 = 10;
const EC_POINTS: u16 = 11;
const SIGALGS: u16 = 13;
const ALPN: u16 = 16;
const SCT: u16 = 18;
const EMS: u16 = 23;
const COMPRESS_CERT: u16 = 27;
const RECORD_SIZE_LIMIT: u16 = 28;
const DELEGATED_CREDENTIALS: u16 = 34;
const SESSION_TICKET: u16 = 35;
const SUPPORTED_VERSIONS: u16 = 43;
const PSK_MODES: u16 = 45;
const KEY_SHARE: u16 = 51;
const RENEGOTIATION_INFO: u16 = 0xff01;

/// Порядок расширений (пусто — случайный, как у Chrome). GREASE-расширения
/// (первое и последнее), ECH и PSK ставит патч rustls.
fn extension_order(b: Browser) -> Vec<u16> {
    match b {
        Browser::Chrome => Vec::new(),
        Browser::Firefox => vec![
            SNI,
            EMS,
            RENEGOTIATION_INFO,
            GROUPS,
            EC_POINTS,
            SESSION_TICKET,
            ALPN,
            STATUS_REQUEST,
            DELEGATED_CREDENTIALS,
            SCT,
            KEY_SHARE,
            SUPPORTED_VERSIONS,
            SIGALGS,
            PSK_MODES,
            RECORD_SIZE_LIMIT,
            COMPRESS_CERT,
        ],
        Browser::Safari => vec![
            SNI,
            EMS,
            RENEGOTIATION_INFO,
            GROUPS,
            EC_POINTS,
            ALPN,
            STATUS_REQUEST,
            SIGALGS,
            SCT,
            KEY_SHARE,
            PSK_MODES,
            SUPPORTED_VERSIONS,
            COMPRESS_CERT,
        ],
    }
}

/// Распаковщик zlib (RFC 8879, алгоритм 1) — `miniz_oxide`, чистый Rust.
#[derive(Debug)]
struct ZlibCertDecompressor;

impl rustls::compress::CertDecompressor for ZlibCertDecompressor {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        let v = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(input, output.len())
            .map_err(|_| rustls::compress::DecompressionFailed)?;
        if v.len() != output.len() {
            return Err(rustls::compress::DecompressionFailed);
        }
        output.copy_from_slice(&v);
        Ok(())
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Zlib
    }
}

/// Распаковщик zstd (алгоритм 3) — `ruzstd`, чистый Rust.
#[derive(Debug)]
struct ZstdCertDecompressor;

impl rustls::compress::CertDecompressor for ZstdCertDecompressor {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        use std::io::Read;
        let mut d = ruzstd::decoding::StreamingDecoder::new(input)
            .map_err(|_| rustls::compress::DecompressionFailed)?;
        let mut got = 0;
        while got < output.len() {
            match d.read(&mut output[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => return Err(rustls::compress::DecompressionFailed),
            }
        }
        // Больше, чем объявлено, — тоже ошибка.
        let mut extra = [0u8; 1];
        if got != output.len() || matches!(d.read(&mut extra), Ok(n) if n > 0) {
            return Err(rustls::compress::DecompressionFailed);
        }
        Ok(())
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Zstd
    }
}

static ZLIB: ZlibCertDecompressor = ZlibCertDecompressor;
static ZSTD: ZstdCertDecompressor = ZstdCertDecompressor;

/// Привести ClientHello конфига к браузеру `b`. Порядок cipher suites
/// задаётся провайдером ([`order_cipher_suites`]) до сборки конфига.
pub fn apply(config: &mut rustls::ClientConfig, b: Browser, reality: bool) {
    // Общее с Chrome: SCT, ECH GREASE, распаковщик brotli, ALPS (REALITY).
    super::chrome_profile::apply_chrome_extensions(config, reality);
    if b == Browser::Chrome {
        return;
    }
    let ch = config
        .chrome_hello
        .as_mut()
        .expect("apply_chrome_extensions ставит chrome_hello");
    ch.signature_schemes = signature_schemes(b);
    ch.extra_cipher_suites = if reality {
        legacy_suites(b).to_vec()
    } else {
        Vec::new()
    };
    ch.named_groups = named_groups(b);
    ch.extension_order = extension_order(b);
    // Ни у Firefox, ни у Safari нет session_ticket и ALPS.
    ch.session_ticket = false;
    ch.raw_extensions = vec![(SCT, Vec::new())];
    match b {
        Browser::Firefox => {
            ch.no_grease = true;
            ch.no_psk_modes = true;
            ch.extra_p256_share = true;
            // delegated_credentials: ECDSA P-256, P-384, P-521, SHA1.
            ch.raw_extensions.push((
                DELEGATED_CREDENTIALS,
                vec![0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03],
            ));
            ch.raw_extensions
                .push((RECORD_SIZE_LIMIT, vec![0x40, 0x01]));
            config.cert_decompressors = vec![&ZLIB, super::chrome_profile::brotli(), &ZSTD];
        }
        Browser::Safari => {
            config.cert_decompressors = vec![&ZLIB];
            // У Safari нет ECH GREASE.
            config.clear_ech();
        }
        Browser::Chrome => unreachable!(),
    }
    // session_ticket от самого rustls (TLS 1.2 с билетами) — не нужен:
    // возобновление по session id остаётся.
    config.resumption = config
        .resumption
        .clone()
        .tls12_resumption(rustls::client::Tls12Resumption::SessionIdOnly);
}
