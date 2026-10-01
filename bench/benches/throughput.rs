// SPDX-License-Identifier: GPL-3.0-or-later
//! Этап 0 — инфраструктура измерения. Пока нет ни буферного пула
//! (Этап 2), ни REALITY (Этап 5), здесь два независимых от сети замера,
//! которые уже сейчас дают базовую линию (baseline) для сравнения с
//! будущими этапами:
//!
//! 1. Скорость кодирования заголовка запроса VLESS (аллокации в hot path).
//! 2. Пропускная способность двустороннего релея на локальных
//!    in-memory duplex-потоках (без реальной сети/TLS) — изолирует
//!    стоимость самого копирования/релея от TCP/TLS-издержек.
//!
//! ⚠️ Ограниченность стенда (см. PLAN.md, Этап 0): цифры отсюда не
//! говорят ничего о поведении против живого DPI в проде — только о
//! CPU/аллокациях самого кода ядра.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use reality_core::vless::protocol::{encode_request, Address, Command};
use uuid::Uuid;

// Этап 7: `cargo bench -p bench --features mimalloc` сравнить с обычным
// `cargo bench -p bench` — оба замера (аллокация заголовка, релей на
// duplex-потоках) чувствительны именно к паттерну мелких аллокаций,
// который аллокатор обслуживает. См. PLAN.md, Этап 7.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn bench_encode_request(c: &mut Criterion) {
    let id = Uuid::new_v4();
    let addr = Address::Domain("example.com".to_string());
    let mut group = c.benchmark_group("vless_encode_request");
    group.throughput(Throughput::Elements(1));
    group.bench_function("domain_addr", |b| {
        b.iter(|| {
            let buf = encode_request(&id, Command::Tcp, &addr, 443);
            std::hint::black_box(buf);
        })
    });
    group.finish();
}

fn bench_relay_loopback(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("relay_loopback_in_memory");
    for size_kb in [4usize, 64, 1024] {
        group.throughput(Throughput::Bytes((size_kb * 1024) as u64));
        group.bench_function(format!("{size_kb}kb"), |b| {
            b.to_async(&rt).iter(|| async move {
                relay_once(size_kb * 1024).await;
            });
        });
    }
    group.finish();
}

/// Один цикл: клиент пишет `n` байт, echo-конец их же возвращает через
/// релей `reality_core::relay::copy_bidirectional`, клиент читает `n`
/// байт обратно. Обёрнуто таймаутом — зависший релей должен упасть с
/// понятной паникой, а не подвесить бенчмарк навсегда.
async fn relay_once(n: usize) {
    tokio::time::timeout(Duration::from_secs(5), relay_once_inner(n))
        .await
        .expect("relay_once завис — таймаут 5с");
}

async fn relay_once_inner(n: usize) {
    use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

    let (client, relay_client_side) = duplex(64 * 1024);
    let (relay_remote_side, mut echo_side) = duplex(64 * 1024);

    // Читаем и пишем на стороне "клиента" конкурентно (как это делает
    // любое реальное приложение поверх сокета) — иначе последовательные
    // write_all(все n байт) -> read_exact(все n байт) на большом `n`
    // упираются в конечный размер internal-буфера duplex(64 КБ) на
    // каждом хопе пути туда-обратно и дедлочатся сами на себя. Это баг
    // синтетического стенда бенчмарка, а не релея: `relay::copy_bidirectional`
    // и так читает/пишет свои две стороны конкурентно.
    let (mut client_read, mut client_write) = split(client);

    let echo = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match echo_side.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    if echo_side.write_all(&buf[..k]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let relay_task = tokio::spawn(async move {
        let _ = reality_core::relay::copy_bidirectional(relay_client_side, relay_remote_side).await;
    });

    let data = vec![0xABu8; n];
    let writer = tokio::spawn(async move {
        client_write.write_all(&data).await.unwrap();
        client_write
    });

    let mut got = vec![0u8; n];
    client_read.read_exact(&mut got).await.unwrap();

    let client_write = writer.await.unwrap();
    drop(client_write);
    drop(client_read);

    let _ = relay_task.await;
    let _ = echo.await;
}

criterion_group!(benches, bench_encode_request, bench_relay_loopback);
criterion_main!(benches);
