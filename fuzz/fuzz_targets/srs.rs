// SPDX-License-Identifier: GPL-3.0-or-later
//! Набор правил sing-box (.srs) — файл от провайдера или по URL.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = reality_core::app::ruleset::parse_srs_for_fuzz(data);
});
