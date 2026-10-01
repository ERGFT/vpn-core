// SPDX-License-Identifier: GPL-3.0-or-later
//! Приветствие и запрос SOCKS5 (с проверкой логина и пароля) — из сети.
#![no_main]
use libfuzzer_sys::fuzz_target;
use reality_core::socks5::{handshake_with_auth, Credentials};

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    let auth = Credentials::parse("user:pass").unwrap();
    rt.block_on(async {
        let mut s = tokio::io::join(data, tokio::io::sink());
        let _ = handshake_with_auth(&mut s, Some(&auth)).await;
    });
});
