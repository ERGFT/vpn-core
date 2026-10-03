// SPDX-License-Identifier: GPL-3.0-or-later
//! Адреса сайтов не попадают в тексты ошибок, которые входы пишут в журнал
//! уровня info/warn (`proxy_in`: «соединение завершилось с ошибкой»), — они
//! только в debug. Проверяются функции, через которые идёт выход `direct`.

use std::sync::{Arc, Mutex};

use reality_core::transport::tcp_tls::{connect_addrs, resolve_host};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Выполнить `f` с журналом уровня `level`; вернуть ошибку и весь журнал.
async fn logged<F, T>(level: tracing::Level, f: F) -> (String, String)
where
    F: std::future::Future<Output = reality_core::error::Result<T>>,
{
    let buf = Buf::default();
    let w = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(move || w.clone())
        .with_ansi(false)
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    let err = match f.await {
        Ok(_) => panic!("ожидалась ошибка"),
        Err(e) => e.to_string(),
    };
    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (err, log)
}

#[tokio::test]
async fn site_name_is_only_in_debug() {
    const SITE: &str = "no-such-site-for-log-test.invalid";
    let (err, log) = logged(tracing::Level::INFO, resolve_host(SITE, 443)).await;
    assert!(!err.contains(SITE), "в тексте ошибки: {err}");
    assert!(!log.contains(SITE), "в журнале info: {log}");
    let (_, log) = logged(tracing::Level::DEBUG, resolve_host(SITE, 443)).await;
    assert!(log.contains(SITE), "в debug имя остаётся для отладки: {log}");
}

#[tokio::test]
async fn site_address_is_not_in_connect_error() {
    // Порт, на котором никто не слушает: соединение отклоняется сразу.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let (err, log) = logged(tracing::Level::INFO, connect_addrs(&[addr], "site.test")).await;
    assert!(!err.contains(&addr.to_string()) && !err.contains("site.test"), "{err}");
    assert!(!log.contains("site.test"), "{log}");
}
