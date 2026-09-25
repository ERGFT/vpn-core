//! reality_core — ядро клиента VLESS(+REALITY).
//!
//! Статус по этапам плана (см. PLAN.md в корне репозитория):
//!   Этап 0 (замер)              — крейт `bench`, готово
//!   Этап 1 (минимальный VLESS)  — `vless`, `socks5`, `transport::tcp_tls`, готово
//!   Этап 2 (буферы)             — `relay`, готово (miri — см. PLAN.md)
//!   Этап 3 (TLS-фингерпринтинг) — `fingerprint`: измерение JA3/JA4 готово,
//!                                 эмуляция браузера — нет, это отдельное
//!                                 архитектурное решение (см. PLAN.md)
//!   Этап 4 (транспорты)         — `transport::ws`, `transport::grpc`
//!   Этап 5 (REALITY)            — `reality`: крипто-примитивы + кастомный
//!                                 `ServerCertVerifier` готовы и протестированы,
//!                                 вставка SessionId в реальный ClientHello —
//!                                 нет, тот же архитектурный тупик rustls, что
//!                                 и в Этапе 3 (см. PLAN.md, `reality/mod.rs`)
//!   Этап 6..8                   — не начаты
//!
//! Ядро не резолвит DNS самостоятельно для доменных адресов — это
//! осознанно передаётся серверу (как и в оригинальном VLESS), поэтому
//! DNS-запросы клиента не текут отдельным, отличимым от TLS трафиком
//! путём.

pub mod error;
pub mod fingerprint;
pub mod reality;
pub mod relay;
pub mod socks5;
pub mod transport;
pub mod vless;

pub use error::{Error, Result};
