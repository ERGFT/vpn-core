//! CLI: принимает vless:// ссылку, поднимает локальный SOCKS5 и
//! проксирует через него TCP-трафик на VLESS-сервер.
//!
//! Что поддерживается (подробно — README.md):
//!   security=none / tls / reality;
//!   type=tcp (по умолчанию) / ws (`path=`) / grpc (`serviceName=`, режим "gun").
//! Чего нет: flow=xtls-rprx-vision (клиент сразу завершается с понятной
//! ошибкой), UDP (SOCKS5 UDP ASSOCIATE), аутентификации на SOCKS5.
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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use reality_core::relay;
use reality_core::socks5::{self, ReplyCode, TargetAddr};
use reality_core::transport;
use reality_core::vless::{Address, NetworkType, VlessConfig};

/// Потолок на открытие одного соединения целиком: разрешение имени, TCP,
/// TLS или REALITY и заголовок VLESS. Щедрый: на плохой сети рукопожатие
/// занимает секунды, но вечного ожидания быть не должно.
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Parser, Debug)]
#[command(
    name = "reality-client",
    about = "VLESS core — локальный SOCKS5 -> VLESS (tcp/ws/grpc транспорт по ссылке)"
)]
struct Args {
    /// vless:// ссылка сервера
    #[arg(long)]
    server: String,

    /// Локальный адрес, на котором поднимается SOCKS5
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: SocketAddr,
}

/// Общий типаж для трёх разных конкретных типов потоков, которые
/// возвращают транспорты Этапа 1/4 (`TlsStream`, `WsStream<...>`,
/// `DuplexStream`) — чтобы `handle_conn` не знал заранее, какой из них
/// достанется, и мог отдать любой напрямую в `relay::copy_bidirectional`.
trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

#[tokio::main]
async fn main() -> Result<()> {
    // По умолчанию — уровень info: без этого при незаданном RUST_LOG
    // клиент молчал совсем, и было не понять, запустился ли он и на
    // каком порту слушает. RUST_LOG, если задан, по-прежнему главнее
    // (например, RUST_LOG=debug или RUST_LOG=warn).
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

    let cfg = Arc::new(VlessConfig::parse(&args.server).context("разбор vless:// ссылки")?);
    // Сразу при старте, а не на каждом соединении: неподдерживаемый flow
    // не должен выглядеть как "SOCKS5 работает, но сайты не открываются".
    cfg.ensure_flow_supported()
        .context("ссылка требует возможности, которой у клиента пока нет")?;
    info!(
        host = %cfg.host,
        port = cfg.port,
        sni = %cfg.effective_sni(),
        security = ?cfg.security,
        network = ?cfg.network,
        "конфигурация сервера загружена"
    );

    // Инициализация криптографии до того, как начнём принимать
    // соединения: внутри неё засев генератора случайных чисел, который
    // стоит ~28 мс один раз на процесс (Этап 8). Если не сделать это
    // здесь, цену заплатит первое соединение пользователя.
    let t_crypto = std::time::Instant::now();
    transport::tcp_tls::ensure_crypto_provider();
    tracing::debug!(ms = t_crypto.elapsed().as_millis(), "криптография готова");

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("не удалось слушать {}", args.listen))?;
    // Реальный адрес: при --listen ...:0 порт выбирает система.
    info!(addr = %listener.local_addr()?, "SOCKS5 слушает");

    loop {
        let (socket, peer) = listener.accept().await?;
        // Локальный сокет к приложению — тоже без задержки Нагла.
        // На исходящем она уже отключена; без неё здесь мелкие ответы
        // (в т.ч. ответ SOCKS5) могли ждать подтверждения предыдущих.
        socket.set_nodelay(true).ok();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(socket, cfg).await {
                warn!(%peer, error = %e, "соединение завершилось с ошибкой");
            }
        });
    }
}

async fn handle_conn(mut socket: TcpStream, cfg: Arc<VlessConfig>) -> anyhow::Result<()> {
    let req = socks5::handshake(&mut socket).await?;
    let target = match &req.addr {
        TargetAddr::Ip(std::net::IpAddr::V4(v4)) => Address::Ipv4(*v4),
        TargetAddr::Ip(std::net::IpAddr::V6(v6)) => Address::Ipv6(*v6),
        TargetAddr::Domain(d) => Address::Domain(d.clone()),
    };

    // Общий потолок на всё открытие соединения: разрешение имени, TCP,
    // TLS/REALITY и заголовок VLESS. Внутри есть свои таймауты на
    // отдельные шаги, но нужен и общий — иначе сервер, который отвечает
    // по чуть-чуть, но никогда не заканчивает рукопожатие, удерживал бы
    // задачу неограниченно долго.
    let dial = async {
        let r: Result<Box<dyn AsyncStream>, reality_core::Error> = match cfg.network {
            NetworkType::Tcp => {
                transport::connect_and_handshake(&cfg, &cfg.id, target.clone(), req.port)
                    .await
                    .map(|s| Box::new(s) as Box<dyn AsyncStream>)
            }
            NetworkType::Ws => {
                transport::ws::connect_and_handshake_ws(&cfg, &cfg.id, target.clone(), req.port)
                    .await
                    .map(|s| Box::new(s) as Box<dyn AsyncStream>)
            }
            NetworkType::Grpc => {
                transport::grpc::connect_and_handshake_grpc(&cfg, &cfg.id, target.clone(), req.port)
                    .await
                    .map(|s| Box::new(s) as Box<dyn AsyncStream>)
            }
        };
        r
    };

    let remote = match tokio::time::timeout(DIAL_TIMEOUT, dial).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            socks5::reply_error(&mut socket, ReplyCode::GeneralFailure)
                .await
                .ok();
            return Err(e.into());
        }
        Err(_) => {
            socks5::reply_error(&mut socket, ReplyCode::GeneralFailure)
                .await
                .ok();
            return Err(anyhow::anyhow!(
                "сервер не завершил рукопожатие за {} с",
                DIAL_TIMEOUT.as_secs()
            ));
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
