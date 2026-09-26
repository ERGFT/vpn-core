//! reality_core — ядро клиента VLESS(+REALITY).
//!
//! Что где (подробно — README.md и PLAN.md в корне репозитория):
//!   `vless`       — разбор vless://-ссылки, протокол VLESS (TCP и UDP),
//!                   XTLS Vision (`vless::vision`)
//!   `transport`   — TCP (+TLS или REALITY), WebSocket, gRPC; `raw` —
//!                   сокет с выдачей по одному TLS-рекорду для Vision
//!   `reality`     — REALITY: SessionId, проверка сертификата (HMAC и
//!                   ML-DSA-65), хук в ClientHello патченного rustls
//!   `fingerprint` — ClientHello как у Chrome 133, разбор, JA3/JA4
//!   `socks5`      — локальный SOCKS5: CONNECT, UDP ASSOCIATE, логин/пароль
//!   `relay`       — двусторонний релей, один буфер на направление
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
