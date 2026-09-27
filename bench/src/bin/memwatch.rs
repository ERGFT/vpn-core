// SPDX-License-Identifier: GPL-3.0-or-later
//! Этап 0 — сэмплер RSS/PSS произвольного процесса по PID, снаружи (без
//! инструментирования самого клиента).
//!
//! Использование:
//!   cargo run -p bench --bin memwatch -- --pid <PID> [--interval-ms 200] [--duration-secs 30]
//!   cargo run -p bench --bin memwatch -- --pid <PID> --csv out.csv
//!
//! Без --pid следит за собственным процессом (полезно только для
//! проверки, что сэмплер вообще работает).
//!
//! Источники: /proc/<pid>/status (VmRSS — быстро, но PSS не даёт) и
//! /proc/<pid>/smaps_rollup (Pss — точнее для shared-страниц, но чуть
//! дороже читать; на некоторых ядрах файла может не быть — тогда колонка
//! пустая, а не ошибка).

use std::fs;
use std::io::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Args {
    pid: u32,
    interval_ms: u64,
    duration_secs: Option<u64>,
    csv_path: Option<String>,
}

fn parse_args() -> Args {
    let mut pid = std::process::id();
    let mut interval_ms = 200u64;
    let mut duration_secs = None;
    let mut csv_path = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--pid" => {
                pid = it
                    .next()
                    .expect("--pid требует значение")
                    .parse()
                    .expect("pid: число")
            }
            "--interval-ms" => {
                interval_ms = it
                    .next()
                    .expect("--interval-ms требует значение")
                    .parse()
                    .expect("interval-ms: число")
            }
            "--duration-secs" => {
                duration_secs = Some(
                    it.next()
                        .expect("--duration-secs требует значение")
                        .parse()
                        .expect("duration-secs: число"),
                )
            }
            "--csv" => csv_path = it.next(),
            other => {
                eprintln!("неизвестный аргумент: {other}");
                std::process::exit(2);
            }
        }
    }

    Args {
        pid,
        interval_ms,
        duration_secs,
        csv_path,
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    t_ms: u128,
    rss_kb: Option<u64>,
    pss_kb: Option<u64>,
}

fn read_rss_kb(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn read_pss_kb(pid: u32) -> Option<u64> {
    let rollup = fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok()?;
    for line in rollup.lines() {
        if let Some(rest) = line.strip_prefix("Pss:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

fn main() {
    let args = parse_args();

    if !std::path::Path::new(&format!("/proc/{}", args.pid)).exists() {
        eprintln!("процесс с pid {} не найден в /proc", args.pid);
        std::process::exit(1);
    }

    let mut out: Box<dyn std::io::Write> = match &args.csv_path {
        Some(path) => Box::new(fs::File::create(path).expect("не удалось создать csv-файл")),
        None => Box::new(std::io::stdout()),
    };

    writeln!(out, "t_ms,rss_kb,pss_kb").unwrap();

    let start = Instant::now();
    loop {
        let sample = Sample {
            t_ms: now_ms(),
            rss_kb: read_rss_kb(args.pid),
            pss_kb: read_pss_kb(args.pid),
        };
        writeln!(
            out,
            "{},{},{}",
            sample.t_ms,
            sample.rss_kb.map(|v| v.to_string()).unwrap_or_default(),
            sample.pss_kb.map(|v| v.to_string()).unwrap_or_default(),
        )
        .unwrap();
        out.flush().ok();

        if let Some(d) = args.duration_secs {
            if start.elapsed() >= Duration::from_secs(d) {
                break;
            }
        }
        if !std::path::Path::new(&format!("/proc/{}", args.pid)).exists() {
            eprintln!("процесс {} завершился, останавливаюсь", args.pid);
            break;
        }
        std::thread::sleep(Duration::from_millis(args.interval_ms));
    }
}
