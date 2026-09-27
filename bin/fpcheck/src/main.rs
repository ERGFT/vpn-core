// SPDX-License-Identifier: GPL-3.0-or-later
//! Этап 3 — инструмент "сверки": какой TLS-отпечаток (JA3/JA4) этот
//! клиент реально отправляет прямо сейчас, при живом TCP+TLS-соединении
//! до сервера (используются host/port/sni из обычной vless:// ссылки —
//! остальные поля не нужны и игнорируются).
//!
//! ⚠️ Это измерение, не подмена — см. `PLAN.md`, Этап 3: rustls не даёт
//! эмулировать чужой ClientHello, так что здесь всегда будет один и тот
//! же нейтральный "rustls-отпечаток", а не Chrome/Firefox.

use anyhow::{Context, Result};
use clap::Parser;
use reality_core::fingerprint;
use reality_core::transport::connect_tls_capturing_client_hello;
use reality_core::vless::VlessConfig;

#[derive(Parser, Debug)]
#[command(
    name = "fpcheck",
    about = "Какой TLS-отпечаток (JA3/JA4) этот клиент реально отправляет прямо сейчас"
)]
struct Args {
    /// vless:// ссылка — используются только host/port/sni
    #[arg(long)]
    server: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = VlessConfig::parse(&args.server).context("разбор vless:// ссылки")?;

    eprintln!(
        "Подключаюсь к {}:{} (SNI={})...",
        cfg.host,
        cfg.port,
        cfg.effective_sni()
    );

    let (_tls, captured) = connect_tls_capturing_client_hello(&cfg)
        .await
        .context("не удалось поднять TCP+TLS (сертификат сервера не прошёл проверку — тогда захвата не будет: см. комментарий в исходнике)")?;

    eprintln!(
        "Захвачено {} байт (TLS-рекорд с ClientHello).\n",
        captured.len()
    );

    let report = fingerprint::analyze_record(&captured)
        .context("не удалось разобрать захваченный ClientHello")?;

    println!("JA3:      {}", report.ja3);
    println!("JA3 hash: {}", report.ja3_hash);
    println!("JA4:      {}", report.ja4);
    println!();
    println!(
        "SNI:                {}",
        report.info.sni.as_deref().unwrap_or("(нет)")
    );
    println!("legacy_version:     {:#06x}", report.info.legacy_version);
    println!(
        "supported_versions: {:?}",
        hex_list(&report.info.supported_versions)
    );
    println!(
        "cipher_suites ({}): {:?}",
        report.info.cipher_suites.len(),
        hex_list(&report.info.cipher_suites)
    );
    println!(
        "extensions ({}):    {:?}",
        report.info.extensions.len(),
        hex_list(&report.info.extensions)
    );
    println!(
        "elliptic_curves:    {:?}",
        hex_list(&report.info.elliptic_curves)
    );
    println!("alpn:               {:?}", report.info.alpn);
    println!();
    println!("⚠️  Это ClientHello rustls «как есть» — Этап 3 в этом клиенте пока");
    println!("    только измеряет отпечаток, не подделывает его под браузер.");
    println!("    См. PLAN.md, Этап 3.");

    Ok(())
}

fn hex_list(values: &[u16]) -> Vec<String> {
    values.iter().map(|v| format!("{v:#06x}")).collect()
}
