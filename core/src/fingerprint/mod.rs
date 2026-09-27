// SPDX-License-Identifier: GPL-3.0-or-later
//! Этап 3 — TLS-отпечаток: ClientHello как у Chrome 133 ([`chrome_profile`])
//! и инструменты сверки (разбор ClientHello, JA3/JA4).
//!
//! Итог (сверено тестом `core/tests/fingerprint_chrome_full.rs` с эталоном
//! `HelloChrome_133` из utls; `scripts/check_chrome_fingerprint.sh` следит,
//! не ушёл ли эталон вперёд):
//! - REALITY: cipher suites, набор расширений, `signature_algorithms`,
//!   группы и доли ключа, версии, ALPN — как у Chrome; JA4 совпадает
//!   (`t13d1516h2_8daaf6152771_d8a2da3f94cd`).
//! - Обычный TLS: то же, кроме 6 legacy cipher suite'ов и ALPS (почему —
//!   в докстринге [`chrome_profile::apply_chrome_extensions`]).
//! - Порядок расширений перемешивается на каждое соединение (сам rustls,
//!   `extension_order_seed`), как у Chrome 106+; GREASE — во всех местах,
//!   где его ставит Chrome.
//!
//! Чего нет и не будет без смены TLS-стека: побайтового совпадения
//! (например, длины ECH-GREASE и порядок, в котором rustls ставит ECH в
//! конец), а также настоящей поддержки ALPS.

pub mod capture;
pub mod chrome_profile;
pub mod client_hello;
pub mod ja3;
pub mod ja4;
pub mod profiles;

pub use chrome_profile::{apply_chrome133_cipher_order, apply_chrome_extensions};
pub use profiles::Browser;

pub use capture::CaptureFirstBytes;
pub use client_hello::{is_grease, parse_handshake_body, parse_record, ClientHelloInfo};

/// Готовый отчёт по одному ClientHello — удобно для CLI/логов.
#[derive(Debug, Clone)]
pub struct FingerprintReport {
    pub info: ClientHelloInfo,
    pub ja3: String,
    pub ja3_hash: String,
    pub ja4: String,
}

/// Разобрать полный TLS-рекорд с ClientHello и сразу посчитать JA3/JA4.
pub fn analyze_record(bytes: &[u8]) -> crate::error::Result<FingerprintReport> {
    let info = parse_record(bytes)?;
    Ok(FingerprintReport {
        ja3: ja3::ja3_string(&info),
        ja3_hash: ja3::ja3_hash(&info),
        ja4: ja4::ja4_string(&info),
        info,
    })
}
