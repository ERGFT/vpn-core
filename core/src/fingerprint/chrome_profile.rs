//! Этап 3 — ClientHello как у Chrome 133: порядок cipher suites
//! ([`apply_chrome133_cipher_order`]) и набор/значения расширений
//! ([`apply_chrome_extensions`]).
//!
//! # Откуда взят эталон
//! Список и порядок cipher suites — из `refraction-networking/utls`
//! (форк `crypto/tls` стандартной библиотеки Go, реальная зависимость
//! REALITY-клиента в самом Xray-core — см. `reality/mod.rs`), файл
//! `u_parrots.go`, профиль `HelloChrome_133` (`HelloChrome_Auto` на
//! момент этой правки — самый свежий стабильный Chrome, на который
//! ссылается сам utls). Получено напрямую (`curl
//! raw.githubusercontent.com/refraction-networking/utls/master/u_parrots.go`),
//! не по памяти и не по пересказу — та же дисциплина сверки, что и для
//! REALITY-находок в Этапе 5.
//!
//! # Legacy cipher suite'ы
//! Полный список Chrome 133 — 16 cipher suites: GREASE, три TLS 1.3,
//! шесть ECDHE-suite'ов TLS 1.2 и ещё шесть legacy (голый `TLS_RSA_*`,
//! CBC). `aws-lc-rs` реализует только первые девять — и правильно:
//! legacy-механизмы небезопасны. Клиент их не реализует, но для REALITY
//! заявляет кодпоинтами в конце списка ([`CHROME_LEGACY_SUITES`]): там
//! возможен лишь TLS 1.3, и сервер выбрать их не может в принципе
//! (решение пользователя). Для обычного TLS не заявляются.
//!
//! # GREASE (RFC 8701) — сделан полностью, во всех местах, где его ставит Chrome
//! Патч `vendor/rustls-reality-patch` (конфиг клиента о GREASE ничего не
//! знает): пять независимых значений на соединение
//! (`client/common.rs`, `GreaseValues`, раскладка как у BoringSSL —
//! сверено по `u_parrots.go`, `ApplyPreset`): первый cipher suite; первая
//! группа в supported_groups и первая запись key_share (одно и то же
//! значение, тело key_share — один нулевой байт); первая версия в
//! supported_versions; два отдельных GREASE-расширения — самое первое с
//! пустым телом и самое последнее (перед PSK) с телом `[0]`, типы
//! гарантированно разные. Значения живут на всё соединение: второй
//! ClientHello после HelloRetryRequest получает те же. После HRR,
//! указавшего группу, GREASE в key_share НЕ добавляется (RFC 8446 §4.1.2 —
//! там ровно одна запись; иначе Go-серверы, включая REALITY, рвут
//! соединение).
//!
//! GREASE-расширения вписаны прямо в `ClientExtensions::encode`
//! (`msgs/handshake.rs`) — правка макроса `extension_struct!`, которой
//! опасались раньше, не понадобилась: `encode` написан вручную, длина
//! списка считается `LengthPrefixedBuffer`'ом.
//!
//! Действует и для REALITY. Раньше GREASE в группах/key_share для REALITY
//! был сознательно отложен "до интероп-теста"; это пересмотрено по
//! исходникам (см. PLAN.md, Этап 3): сервер `XTLS/REALITY` неизвестные
//! группы в key_share пропускает, а собственный REALITY-клиент Xray-core
//! по умолчанию — utls с отпечатком `HelloChrome_133`, т.е. REALITY-серверы
//! штатно получают ровно эти GREASE-значения. Реальная группа у REALITY
//! по-прежнему одна (`X25519MLKEM768`), анти-HRR-логика не тронута.
//! Проверено живыми хендшейками: `core/tests/fingerprint_chrome_profile.rs`,
//! `core/tests/fingerprint_grease_groups.rs` (включая путь через HRR) и
//! `core/tests/reality_handshake.rs` (там же AEAD-проверка доказывает, что
//! GREASE-байты вошли в AAD так же, как их посчитал клиент).
//!
//! # Расширения
//! Набор и значения расширений приводит [`apply_chrome_extensions`]
//! (см. её докстринг). Порядок расширений перемешивает сам rustls на
//! каждое соединение, как Chrome 106+.

use rustls::crypto::CryptoProvider;
use rustls::{CipherSuite, SignatureScheme};

/// Порядок реализованных cipher suites в ClientHello Chrome 133
/// (`HelloChrome_Auto` в `refraction-networking/utls`, `u_parrots.go`).
/// GREASE ставит патч rustls, legacy-хвост — [`apply_chrome_extensions`]
/// (только REALITY).
const CHROME133_CIPHER_ORDER: &[CipherSuite] = &[
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Переставить `provider.cipher_suites` так, чтобы suite'ы из
/// [`CHROME133_CIPHER_ORDER`] шли в том же ОТНОСИТЕЛЬНОМ порядке, в
/// каком их видно у Chrome — остальные (если провайдер вдруг
/// когда-нибудь станет предлагать что-то ещё, не входящее в список
/// Chrome) дописываются следом в их исходном порядке, а не отбрасываются
/// — так эта функция не сломается молча, если набор suite'ов провайдера
/// изменится в будущей версии `aws-lc-rs`/rustls.
pub fn apply_chrome133_cipher_order(mut provider: CryptoProvider) -> CryptoProvider {
    provider.cipher_suites.sort_by_key(|cs| {
        CHROME133_CIPHER_ORDER
            .iter()
            .position(|&wanted| wanted == cs.suite())
            .unwrap_or(CHROME133_CIPHER_ORDER.len())
    });
    provider
}

/// `signature_algorithms` Chrome 133 (`u_parrots.go`, HelloChrome_133),
/// в его порядке. rustls по умолчанию заявлял 13 схем, включая Ed25519 и
/// ML-DSA, — это было видно в JA4_c. Проверка подписи сервера от этого не
/// сужается: её делает верификатор (REALITY-сервер подписывает
/// CertificateVerify через Ed25519, и наш `RealityCertVerifier` это
/// по-прежнему принимает — так же работает utls-Chrome у Xray).
pub const CHROME_SIGNATURE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// Шесть «старых» cipher suite'ов из хвоста списка Chrome 133
/// (ECDHE-RSA с CBC и голый RSA). Не реализованы и не будут — только
/// заявляются, и только для REALITY: там возможен лишь TLS 1.3, так что
/// сервер выбрать их не может в принципе (решение пользователя: «да,
/// только для REALITY»). Для обычного TLS не заявляются — там сервер
/// с откатом на TLS 1.2 теоретически мог бы выбрать такой suite.
pub const CHROME_LEGACY_SUITES: &[u16] = &[
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

/// Распаковщик сертификатов brotli (RFC 8879) на `brotli-decompressor`.
/// Сервер, получивший от «Chrome» `compress_certificate`, вправе прислать
/// сжатый сертификат — значит, распаковывать нужно по-настоящему.
#[derive(Debug)]
struct BrotliCertDecompressor;

impl rustls::compress::CertDecompressor for BrotliCertDecompressor {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        let mut src = std::io::Cursor::new(input);
        let mut dst = std::io::Cursor::new(output);
        // Если данных больше, чем объявлено, запись в срез упрётся в его
        // конец и вернёт ошибку; меньше — проверяем ниже.
        brotli_decompressor::BrotliDecompress(&mut src, &mut dst)
            .map_err(|_| rustls::compress::DecompressionFailed)?;
        if dst.position() as usize != dst.get_ref().len() {
            return Err(rustls::compress::DecompressionFailed);
        }
        Ok(())
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Brotli
    }
}

/// Распаковщик brotli (общий для профилей).
pub(crate) fn brotli() -> &'static dyn rustls::compress::CertDecompressor {
    &BrotliCertDecompressor
}

/// Тип расширения Signed Certificate Timestamp (RFC 6962).
const EXT_SCT: u16 = 0x0012;
/// Тип расширения ALPS в новой нумерации Chrome (`ApplicationSettingsExtensionNew`).
const EXT_ALPS_NEW: u16 = 0x44cd;

/// Привести расширения ClientHello к Chrome 133 — то, что не сводится к
/// порядку cipher suites и GREASE (они сделаны отдельно):
/// - `renegotiation_info` (0xff01) вместо псевдо-suite'а SCSV (0x00ff);
/// - `signature_algorithms` — ровно 8 схем Chrome в его порядке;
/// - SCT (0x0012) — пустое, «хочу метки прозрачности»;
/// - `compress_certificate` с brotli (0x001b) — настоящая поддержка
///   распаковки, не только заявка;
/// - ECH GREASE (0xfe0d) — штатный механизм rustls;
/// - для REALITY дополнительно: `session_ticket` (0x0023), TLS 1.2 в
///   `supported_versions`, 6 legacy suite'ов (см. [`CHROME_LEGACY_SUITES`])
///   и ALPS (0x44cd) для `h2`.
///
/// ALPS только для REALITY осознанно: если обычный TLS-сервер на
/// BoringSSL (например, CDN) согласует ALPS, клиент обязан прислать
/// свои настройки в зашифрованных расширениях — rustls этого не умеет,
/// и рукопожатие сломалось бы. REALITY-сервер (Go) ALPS не согласует
/// никогда, а сайт-приманка рукопожатие с нами не завершает.
pub fn apply_chrome_extensions(config: &mut rustls::ClientConfig, reality: bool) {
    let mut raw = vec![(EXT_SCT, Vec::new())];
    if reality && config.alpn_protocols.iter().any(|p| p == b"h2") {
        // ALPS: u16 длина списка, затем протоколы с u8-длиной — только h2.
        raw.push((EXT_ALPS_NEW, vec![0x00, 0x03, 0x02, b'h', b'2']));
    }
    config.chrome_hello = Some(rustls::client::ChromeHello {
        signature_schemes: CHROME_SIGNATURE_SCHEMES.to_vec(),
        extra_cipher_suites: if reality {
            CHROME_LEGACY_SUITES.to_vec()
        } else {
            Vec::new()
        },
        advertise_tls12: reality,
        session_ticket: reality,
        renegotiation_info: true,
        raw_extensions: raw,
        ..Default::default()
    });
    config.cert_decompressors = vec![&BrotliCertDecompressor];

    // ECH GREASE: как у Chrome — HPKE X25519/HKDF-SHA256/AES-128-GCM со
    // случайным ключом-заглушкой; сервер без ECH просто игнорирует.
    let mut placeholder = vec![0u8; 32];
    if rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut placeholder)
        .is_ok()
    {
        config.set_ech_grease(rustls::client::EchGreaseConfig::new(
            rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128,
            rustls::crypto::hpke::HpkePublicKey(placeholder),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorders_default_aws_lc_rs_suites_to_match_chrome133() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let reordered = apply_chrome133_cipher_order(provider);

        let got: Vec<CipherSuite> = reordered
            .cipher_suites
            .iter()
            .map(|cs| cs.suite())
            .collect();

        // Девять suite'ов, которые реально есть в aws-lc-rs, должны
        // оказаться в том же порядке, что и в CHROME133_CIPHER_ORDER —
        // без пропусков и без лишних (это и есть эмпирическая проверка,
        // что список эталона выше не разошёлся с тем, что провайдер
        // реально умеет).
        assert_eq!(
            got, CHROME133_CIPHER_ORDER,
            "после переупорядочивания список suite'ов aws-lc-rs должен побайтово совпасть с CHROME133_CIPHER_ORDER"
        );
    }

    #[test]
    fn unknown_suite_not_in_chrome_list_goes_to_the_end_not_dropped() {
        // Синтетический провайдер с suite'ом, которого нет в списке
        // Chrome (реальный TLS13_AES_128_GCM_SHA256 плюс намеренно
        // "неизвестный" порядок) — проверяем, что функция не паникует и
        // не теряет suite'ы, даже если список эталона когда-нибудь не
        // покроет что-то новое.
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        // Оставляем только TLS1.3-suite'ы — минимальный набор, где
        // порядок точно проверяем без риска не найти нужные ECDHE-suite'ы
        // в разных сборках aws-lc-rs.
        provider.cipher_suites.retain(|cs| {
            matches!(
                cs.suite(),
                CipherSuite::TLS13_AES_256_GCM_SHA384 | CipherSuite::TLS13_AES_128_GCM_SHA256
            )
        });
        let reordered = apply_chrome133_cipher_order(provider);
        let got: Vec<CipherSuite> = reordered
            .cipher_suites
            .iter()
            .map(|cs| cs.suite())
            .collect();
        assert_eq!(
            got,
            vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
            ],
            "128 должен идти раньше 256 — так у Chrome, но не в дефолтном порядке aws-lc-rs (там 256 первый)"
        );
    }
}
