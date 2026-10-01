// SPDX-License-Identifier: GPL-3.0-or-later
//! Заголовок ответа HTTP/1.1 и тело по нему (chunked, длина, до закрытия).
#![no_main]
use libfuzzer_sys::fuzz_target;
use reality_core::http1::{pump_body, read_head};

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    rt.block_on(async {
        let mut r = data;
        if let Ok(head) = read_head(&mut r).await {
            let _ = pump_body(&mut r, head.body_kind(), None::<&mut tokio::io::Sink>).await;
        }
    });
});
