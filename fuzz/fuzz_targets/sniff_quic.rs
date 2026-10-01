// SPDX-License-Identifier: GPL-3.0-or-later
//! QUIC Initial: разбор, снятие защиты, сборка ClientHello из CRYPTO.
//! Вход — несколько датаграмм: первые два байта каждой — её длина.
#![no_main]
use libfuzzer_sys::fuzz_target;
use reality_core::app::sniff_quic::QuicSniffer;

fuzz_target!(|data: &[u8]| {
    let mut s = QuicSniffer::default();
    let mut rest = data;
    while rest.len() >= 2 {
        let n = (u16::from_be_bytes([rest[0], rest[1]]) as usize).min(rest.len() - 2);
        let _ = s.push(&rest[2..2 + n]);
        rest = &rest[2 + n..];
    }
});
