//! CLI: принимает vless:// ссылку, поднимает локальный SOCKS5 и
//! проксирует через него TCP-трафик на VLESS-сервер.
//!
//! Что поддерживается (подробно — README.md):
//!   security=none / tls / reality;
//!   type=tcp (по умолчанию) / ws (`path=`) / grpc (`serviceName=`, режим "gun").
//!   flow=xtls-rprx-vision (XTLS Vision, только type=tcp с tls/reality);
//!   SOCKS5 CONNECT и UDP ASSOCIATE, логин/пароль (`--auth`).
//!
//! Примеры:
//!   reality-client --server 'vless://UUID@host:443?encryption=none&security=tls&sni=host'
//!   reality-client --server 'vless://UUID@host:443?security=reality&sni=site&pbk=KEY&sid=ID'
//!   reality-client --server 'vless://UUID@host:443?...&type=ws&path=/vless' --listen 127.0.0.1:1080
//!
//! Журнал — в stderr, уровень по умолчанию info; RUST_LOG переопределяет.

use std::net::SocketAddr;
use std::sync::Arc;

// Этап 7 — профилирование аллокаторов: системный аллокатор (glibc malloc
// по умолчанию на Linux) остаётся дефолтом; сборка с `--features mimalloc`
// подменяет глобальный аллокатор на mimalloc для сравнения. Сравнение —
// не "какой аллокатор лучше вообще", а какой лучше для ЭТОГО паттерна
// нагрузки (много мелких короткоживущих Vec<u8> на соединение из Этапа 2,
// плюс единственный буфер на всё время жизни соединения) — см. PLAN.md,
// Этап 7, и `bench/README`-заметку в PLAN.md про то, как гонять сравнение.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use reality_core::relay;
use reality_core::socks5::{self, Credentials, ReplyCode, Socks5Command, TargetAddr};
use reality_core::transport;
use reality_core::vless::{Address, Command, VlessConfig};

/// Потолок на открытие одного соединения целиком: разрешение имени, TCP,
/// TLS или REALITY и заголовок VLESS. Щедрый: на плохой сети рукопожатие
/// занимает секунды, но вечного ожидания быть не должно.
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Parser, Debug)]
#[command(
    name = "reality-client",
    version,
    about = "VLESS core — локальный SOCKS5 -> VLESS (tcp/ws/grpc, tls/reality, XTLS Vision)"
)]
struct Args {
    /// vless:// ссылка сервера
    #[arg(long)]
    server: String,

    /// Локальный адрес, на котором поднимается SOCKS5
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: SocketAddr,

    /// Требовать логин и пароль на SOCKS5: `логин:пароль`
    /// (обязательно, если слушать не только на 127.0.0.1)
    #[arg(long, value_name = "ЛОГИН:ПАРОЛЬ")]
    auth: Option<String>,

    /// PEM-файл с корневыми сертификатами для security=tls вместо
    /// встроенного набора (для сервера с самоподписанным сертификатом)
    #[arg(long, value_name = "ФАЙЛ")]
    ca: Option<std::path::PathBuf>,
}

fn load_ca(path: &std::path::Path) -> Result<rustls::RootCertStore> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(path)
        .with_context(|| format!("не удалось прочитать {}", path.display()))?
    {
        let cert = cert.with_context(|| format!("битый сертификат в {}", path.display()))?;
        roots.add(cert).with_context(|| {
            format!("сертификат из {} не подходит как корневой", path.display())
        })?;
    }
    if roots.is_empty() {
        anyhow::bail!("в {} нет ни одного сертификата", path.display());
    }
    Ok(roots)
}

#[tokio::main]
async fn main() -> Result<()> {
    // По умолчанию — уровень info: без этого при незаданном RUST_LOG
    // клиент молчал совсем, и было не понять, запустился ли он и на
    // каком порту слушает. RUST_LOG, если задан, по-прежнему главнее.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // Цвета — только в настоящем терминале и не на Windows: в старой
    // консоли cmd.exe escape-последовательности печатаются как мусор.
    let ansi = cfg!(not(windows)) && std::io::IsTerminal::is_terminal(&std::io::stderr());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .init();
    let args = Args::parse();

    let mut cfg = VlessConfig::parse(&args.server).context("разбор vless:// ссылки")?;
    // Сразу при старте, а не на каждом соединении: неподходящий flow
    // не должен выглядеть как "SOCKS5 работает, но сайты не открываются".
    cfg.ensure_flow_supported()
        .context("ссылка несовместима с этим клиентом")?;
    if cfg.security == reality_core::vless::Security::Reality {
        cfg.reality_params().context("параметры REALITY в ссылке")?;
    }
    if let Some(fp) = cfg.fingerprint.as_deref() {
        if !fp.is_empty() && fp != "chrome" {
            warn!(
                fp,
                "отпечаток TLS всегда Chrome-подобный; fp={fp} из ссылки игнорируется"
            );
        }
    }
    if let Some(ca) = &args.ca {
        cfg.ca_roots = Some(Arc::new(load_ca(ca)?));
    }
    let auth = match &args.auth {
        Some(a) => Some(Arc::new(
            Credentials::parse(a).context("--auth ожидается в виде логин:пароль")?,
        )),
        None => None,
    };
    if auth.is_none() && !args.listen.ip().is_loopback() {
        anyhow::bail!(
            "--listen {} открывает прокси для всей сети без пароля; задайте --auth логин:пароль",
            args.listen
        );
    }
    let cfg = Arc::new(cfg);
    info!(
        host = %cfg.host,
        port = cfg.port,
        sni = %cfg.effective_sni(),
        security = ?cfg.security,
        network = ?cfg.network,
        flow = ?cfg.flow,
        "конфигурация сервера загружена"
    );

    // Инициализация криптографии до того, как начнём принимать
    // соединения: внутри неё засев генератора случайных чисел, который
    // стоит ~28 мс один раз на процесс (Этап 8).
    let t_crypto = std::time::Instant::now();
    transport::tcp_tls::ensure_crypto_provider();
    tracing::debug!(ms = t_crypto.elapsed().as_millis(), "криптография готова");

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("не удалось слушать {}", args.listen))?;
    // Реальный адрес: при --listen ...:0 порт выбирает система.
    info!(addr = %listener.local_addr()?, auth = auth.is_some(), "SOCKS5 слушает");

    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // Например, кончились дескрипторы: не падать целиком,
                // подождать и продолжить.
                warn!(error = %e, "accept не удался");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        // Локальный сокет к приложению — тоже без задержки Нагла.
        socket.set_nodelay(true).ok();
        let cfg = cfg.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(socket, cfg, auth).await {
                warn!(%peer, error = %e, "соединение завершилось с ошибкой");
            }
        });
    }
}

fn to_vless_addr(a: &TargetAddr) -> Address {
    match a {
        TargetAddr::Ip(std::net::IpAddr::V4(v4)) => Address::Ipv4(*v4),
        TargetAddr::Ip(std::net::IpAddr::V6(v6)) => Address::Ipv6(*v6),
        TargetAddr::Domain(d) => Address::Domain(d.clone()),
    }
}

async fn dial(
    cfg: &VlessConfig,
    command: Command,
    target: Address,
    port: u16,
) -> anyhow::Result<Box<dyn transport::AsyncStream>> {
    match tokio::time::timeout(
        DIAL_TIMEOUT,
        transport::dial(cfg, &cfg.id, command, target, port),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow::anyhow!(
            "сервер не завершил рукопожатие за {} с",
            DIAL_TIMEOUT.as_secs()
        )),
    }
}

async fn handle_conn(
    mut socket: TcpStream,
    cfg: Arc<VlessConfig>,
    auth: Option<Arc<Credentials>>,
) -> anyhow::Result<()> {
    let req = socks5::handshake_with_auth(&mut socket, auth.as_deref()).await?;

    if req.command == Socks5Command::UdpAssociate {
        let cfg2 = cfg.clone();
        socks5::udp::serve_associate(socket, move |addr, port| {
            let cfg = cfg2.clone();
            async move {
                dial(&cfg, Command::Udp, to_vless_addr(&addr), port)
                    .await
                    .map_err(|e| reality_core::Error::Protocol(e.to_string()))
            }
        })
        .await?;
        return Ok(());
    }

    let target = to_vless_addr(&req.addr);
    // Общий потолок на всё открытие соединения — внутри есть свои
    // таймауты на отдельные шаги, но нужен и общий.
    let remote = match dial(&cfg, Command::Tcp, target.clone(), req.port).await {
        Ok(s) => s,
        Err(e) => {
            socks5::reply_error(&mut socket, ReplyCode::GeneralFailure)
                .await
                .ok();
            return Err(e);
        }
    };

    let bind_addr = socket.local_addr()?;
    socks5::reply_success(&mut socket, bind_addr).await?;
    info!(target = %target, port = req.port, network = ?cfg.network, "проксирую");

    let stats = relay::copy_bidirectional(socket, remote).await?;
    info!(
        sent = stats.client_to_remote,
        received = stats.remote_to_client,
        "соединение закрыто"
    );
    Ok(())
}
