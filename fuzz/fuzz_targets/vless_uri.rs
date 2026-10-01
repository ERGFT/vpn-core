// SPDX-License-Identifier: GPL-3.0-or-later
//! Ссылка vless:// — из подписки или от пользователя.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = reality_core::vless::uri::VlessConfig::parse(s);
    }
});
