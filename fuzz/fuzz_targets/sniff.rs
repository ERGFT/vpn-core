// SPDX-License-Identifier: GPL-3.0-or-later
//! Первые байты соединения: TLS ClientHello (SNI), HTTP Host.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = reality_core::app::sniff::sniff(data);
});
