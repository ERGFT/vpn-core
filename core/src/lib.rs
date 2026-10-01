// SPDX-License-Identifier: GPL-3.0-or-later
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
//!   `trojan`      — протокол Trojan (поверх тех же транспортов)
//!   `socks5`      — локальный SOCKS5: CONNECT, UDP ASSOCIATE, логин/пароль
//!   `relay`       — двусторонний релей, один буфер на направление
//!   `app`         — клиент целиком: входы (SOCKS5/HTTP/DNS/TUN) →
//!                   маршрутизатор → выходы, свой DNS, файл настроек
//!   `net_protect` — метка исходящих сокетов, чтобы они шли мимо TUN
//!
//! Ядро не резолвит DNS самостоятельно для доменных адресов — это
//! осознанно передаётся серверу (как и в оригинальном VLESS), поэтому
//! DNS-запросы клиента не текут отдельным, отличимым от TLS трафиком
//! путём.

pub mod app;
pub mod error;
pub mod fingerprint;
pub mod fsutil;
pub mod http1;
pub mod net_protect;
pub mod reality;
pub mod relay;
pub mod socks5;
pub mod transport;
pub mod trojan;
pub mod vless;

pub use error::{Error, Result};
