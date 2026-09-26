//! Этап 3 — измерение TLS-отпечатка (JA3/JA4) и первый конкретный шаг
//! эмуляции под Chrome ([`chrome_profile`]).
//!
//! ⚠️ **Поправка (эта сессия):** раньше здесь было написано, что rustls
//! "принципиально не даёт управлять порядком cipher suites/extensions" —
//! это было неточно и эмпирически опровергнуто прямо в этой сессии, не
//! тихо исправлено:
//! - **Порядок cipher suites** управляем публично через
//!   `CryptoProvider::cipher_suites` (обычный `Vec`, без всякого патча) —
//!   см. [`chrome_profile::apply_chrome133_cipher_order`], уже применяется
//!   в `transport::tcp_tls`.
//! - **Порядок TLS-расширений** вендоренный rustls УЖЕ рандомизирует сам,
//!   на каждое соединение отдельно (`ClientHelloDetails::extension_order_seed`,
//!   `vendor/rustls-reality-patch/src/client/hs.rs`) — подтверждено
//!   эмпирически (три реальных рукопожатия на loopback дали три разных
//!   порядка одного и того же набора расширений). Это совпадает с тем,
//!   что делает сам Chrome 106+ (см. докстринг `chrome_profile`).
//!
//! **GREASE (RFC 8701):** сделан во всех местах, где его ставит Chrome
//! (cipher suite, supported_groups + key_share, supported_versions, два
//! GREASE-расширения), для всех путей, включая REALITY; значения — одни на
//! соединение, корректно ведут себя при HelloRetryRequest. Подробности и
//! источники — в докстринге [`chrome_profile`] и PLAN.md, Этап 3.
//! Открытые апстрим-issue rustls/rustls#1421, #1932, #2498 могли с тех
//! пор устареть — не перепроверялись. Набор и значения самих расширений
//! (не порядок и не GREASE) пока не сверены построчно с Chrome. Полная
//! побайтовая
//! эмуляция (если вообще понадобится за пределами того, что уже
//! достижимо без нового крипто-бэкенда) по-прежнему потребовала бы либо
//! `craftls` (github.com/3andne/craftls, не проверен на зрелость), либо
//! FFI на BoringSSL (крейт `boring`) — решение по этому остатку
//! по-прежнему не принято за пользователя. См. PLAN.md, Этап 3.

pub mod capture;
pub mod chrome_profile;
pub mod client_hello;
pub mod ja3;
pub mod ja4;

pub use chrome_profile::{apply_chrome133_cipher_order, apply_chrome_extensions};

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
