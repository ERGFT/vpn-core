// SPDX-License-Identifier: GPL-3.0-or-later
//! Кадры Mux.Cool от сервера.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    rt.block_on(async {
        let mut r = data;
        while let Ok(Some(_)) = reality_core::vless::mux::read_frame(&mut r).await {}
    });
});
