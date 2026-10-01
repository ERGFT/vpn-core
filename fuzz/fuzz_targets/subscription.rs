// SPDX-License-Identifier: GPL-3.0-or-later
//! Тело подписки: base64-список ссылок, sing-box JSON, Clash YAML.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = reality_core::app::subscription::parse(data);
});
