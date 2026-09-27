//! CLI: локальный прокси (SOCKS5 и HTTP на одном порту) → VLESS-сервер (или напрямую, или отказ — по
//! маршрутизации). Два способа запуска:
//!
//! 1. Ключи — один сервер, один SOCKS5-вход (как раньше):
//!    reality-client --server 'vless://UUID@host:443?security=reality&sni=site&pbk=KEY&sid=ID'
//!    reality-client --server-file server.txt --listen 127.0.0.1:1080
//!
//! 2. Файл настроек (TOML) — несколько входов и выходов, маршрутизация:
//!    reality-client --config client.toml
//!    Пример и описание полей — README.md и `examples/client.toml`.
//!
//! Что поддерживается (подробно — README.md):
//!   security=none / tls / reality;
//!   type=tcp (по умолчанию) / ws / grpc / httpupgrade / xhttp;
//!   flow=xtls-rprx-vision (XTLS Vision, только type=tcp с tls/reality);
//!   SOCKS5 CONNECT и UDP ASSOCIATE (UDP — через XUDP, как у Xray),
//!   логин/пароль (`--auth`).
//!
//! Журнал — в stderr, уровень по умолчанию info; RUST_LOG переопределяет.

use std::net::SocketAddr;
use std::path::PathBuf;

// Этап 7 — профилирование аллокаторов: системный аллокатор остаётся
// дефолтом; сборка с `--features mimalloc` подменяет глобальный аллокатор
// для сравнения (см. PLAN.md, Этап 7).
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod sysproxy;

use anyhow::{Context, Result};
use clap::Parser;

use reality_core::app::access::IpNet;
use reality_core::app::config::{
    Config, InboundConfig, InboundKind, OutboundConfig, OutboundKind, RouteConfig,
};
use reality_core::app::App;

#[derive(Parser, Debug)]
#[command(
    name = "reality-client",
    version,
    about = "VLESS core — локальный SOCKS5/HTTP-прокси -> VLESS (tcp/ws/grpc/httpupgrade/xhttp, tls/reality, XTLS Vision)"
)]
struct Args {
    /// Файл настроек (TOML): входы, выходы, маршрутизация. Вместо
    /// ключей --server, --listen и остальных
    #[arg(
        long,
        short = 'c',
        value_name = "ФАЙЛ",
        conflicts_with_all = ["server_file", "auth", "auth_file", "ca", "no_xudp", "allow_ip", "allow_insecure", "sniff"]
    )]
    config: Option<PathBuf>,

    /// Только проверить настройки (ссылку, пароль, файл) и выйти
    #[arg(long)]
    check: bool,

    /// Windows: на время работы включить системный прокси (браузеры и
    /// программы пойдут через HTTP-вход); при выходе вернуть как было
    #[arg(long)]
    system_proxy: bool,

    /// Windows: выключить системный прокси и выйти (если клиент был
    /// завершён аварийно и не вернул настройки)
    #[arg(long, exclusive = true)]
    system_proxy_off: bool,

    /// Linux: снять правила маршрутизации TUN (и блокировку strict_route),
    /// оставшиеся после аварийного завершения, и выйти
    #[arg(long, exclusive = true)]
    tun_cleanup: bool,

    /// vless:// ссылка сервера. В командной строке она видна другим
    /// пользователям машины (список процессов) — надёжнее
    /// --server-file или переменная окружения REALITY_SERVER
    #[arg(long, env = "REALITY_SERVER", hide_env_values = true)]
    server: Option<String>,

    /// Файл, в котором лежит vless:// ссылка (первая непустая строка)
    #[arg(long, value_name = "ФАЙЛ", conflicts_with = "server")]
    server_file: Option<PathBuf>,

    /// Локальный адрес прокси: SOCKS5 и HTTP на одном порту
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: SocketAddr,

    /// Узнавать домен по первым байтам (TLS SNI, HTTP Host), когда
    /// приложение присылает IP, и отдавать серверу домен, а не IP
    #[arg(long)]
    sniff: bool,

    /// Требовать логин и пароль на SOCKS5: `логин:пароль`
    /// (обязательно, если слушать не только на 127.0.0.1)
    #[arg(
        long,
        value_name = "ЛОГИН:ПАРОЛЬ",
        env = "REALITY_SOCKS_AUTH",
        hide_env_values = true
    )]
    auth: Option<String>,

    /// Файл с `логин:пароль` для SOCKS5 (вместо --auth)
    #[arg(long, value_name = "ФАЙЛ", conflicts_with = "auth")]
    auth_file: Option<PathBuf>,

    /// Сколько соединений SOCKS5 обслуживать одновременно; лишние
    /// сразу закрываются (защита от исчерпания дескрипторов)
    #[arg(long, default_value_t = 512)]
    max_conns: usize,

    /// PEM-файл с корневыми сертификатами для security=tls вместо
    /// встроенного набора (для сервера с самоподписанным сертификатом)
    #[arg(long, value_name = "ФАЙЛ")]
    ca: Option<PathBuf>,

    /// UDP без XUDP: отдельный VLESS-поток (команда UDP) на каждое
    /// назначение. Для серверов без поддержки XUDP; с Vision-аккаунтом
    /// Xray так UDP не примет
    #[arg(long)]
    no_xudp: bool,

    /// Кому из сети разрешено пользоваться прокси: адреса или подсети через
    /// запятую (`192.168.1.23,192.168.1.40`). Нужен при --listen в сеть:
    /// SOCKS5 не шифруется, и лучше пускать только свои устройства
    #[arg(long, value_name = "АДРЕСА", value_delimiter = ',')]
    allow_ip: Vec<IpNet>,

    /// Разрешить ссылки без шифрования (security=none). Всё, включая UUID,
    /// идёт открытым текстом: любой в той же Wi-Fi сети или по пути видит и
    /// может подменить трафик и украсть доступ к серверу
    #[arg(long)]
    allow_insecure: bool,
}

/// Настройки из ключей: один SOCKS5-вход и один выход `proxy`.
fn config_from_args(args: &Args) -> Result<Config> {
    // --server-file главнее REALITY_SERVER из окружения.
    let (link, link_file) = match (&args.server, &args.server_file) {
        (_, Some(p)) => (None, Some(p.clone())),
        (Some(s), None) => (Some(s.clone()), None),
        (None, None) => anyhow::bail!(
            "не задан сервер: --server 'vless://...', --server-file ФАЙЛ, REALITY_SERVER \
             или файл настроек --config"
        ),
    };
    // Так же и --auth-file главнее REALITY_SOCKS_AUTH.
    let (auth, auth_file) = match (&args.auth, &args.auth_file) {
        (_, Some(p)) => (None, Some(p.clone())),
        (a, None) => (a.clone(), None),
    };
    Ok(Config {
        inbounds: vec![InboundConfig {
            kind: InboundKind::Mixed,
            tag: None,
            listen: Some(args.listen),
            auth,
            auth_file,
            allow_ip: args.allow_ip.clone(),
            max_conns: Some(args.max_conns),
            sniff: args.sniff,
            sniff_override_destination: args.sniff,
            interface_name: None,
            inet4_address: None,
            inet6_address: None,
            mtu: None,
            auto_route: None,
            route_exclude: Vec::new(),
            strict_route: None,
            dns_hijack: None,
        }],
        outbounds: vec![OutboundConfig {
            tag: "proxy".into(),
            kind: OutboundKind::Vless,
            link,
            link_file,
            ca_file: args.ca.clone(),
            xudp: !args.no_xudp,
            allow_insecure: args.allow_insecure,
        }],
        route: RouteConfig {
            final_: Some("proxy".into()),
            ..Default::default()
        },
        dns: None,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // По умолчанию — уровень info: иначе при незаданном RUST_LOG было не
    // понять, запустился ли клиент и на каком порту слушает.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,ipstack=error"));
    // Цвета — только в настоящем терминале и не на Windows: в старой
    // консоли cmd.exe escape-последовательности печатаются как мусор.
    let ansi = cfg!(not(windows)) && std::io::IsTerminal::is_terminal(&std::io::stderr());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .init();
    let args = Args::parse();
    if args.tun_cleanup {
        reality_core::app::tun::route::cleanup()?;
        println!("правила TUN сняты");
        return Ok(());
    }
    if args.system_proxy_off {
        sysproxy::disable()?;
        println!("системный прокси выключен");
        return Ok(());
    }

    let cfg = match &args.config {
        Some(path) => {
            Config::load(path).with_context(|| format!("файл настроек {}", path.display()))?
        }
        None => config_from_args(&args)?,
    };
    let app = App::build(&cfg)?;
    if args.check {
        println!("настройки в порядке");
        return Ok(());
    }
    let running = app.start().await?;
    let _system_proxy = if args.system_proxy {
        let addr = running
            .inbounds
            .iter()
            .find(|(_, kind, _)| *kind != InboundKind::Socks)
            .map(|(_, _, a)| *a)
            .context("--system-proxy: нужен вход type = \"http\" или \"mixed\"")?;
        Some(sysproxy::enable(addr)?)
    } else {
        None
    };
    tokio::select! {
        r = running.wait() => r?,
        _ = shutdown_signal() => tracing::info!("завершение по сигналу"),
    }
    // Здесь `_system_proxy` уничтожается и возвращает прежние настройки.
    Ok(())
}

/// Ctrl+C, а на Windows — ещё и закрытие окна консоли и выход из системы;
/// на Unix — SIGTERM.
async fn shutdown_signal() {
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let (mut close, mut shutdown, mut logoff) = (
            windows::ctrl_close().ok(),
            windows::ctrl_shutdown().ok(),
            windows::ctrl_logoff().ok(),
        );
        async fn next(s: &mut Option<impl SignalLike>) {
            match s {
                Some(s) => s.recv_any().await,
                None => std::future::pending().await,
            }
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = next(&mut close) => {}
            _ = next(&mut shutdown) => {}
            _ = next(&mut logoff) => {}
        }
    }
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                match &mut term {
                    Some(t) => { t.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
}

#[cfg(windows)]
trait SignalLike {
    async fn recv_any(&mut self);
}

#[cfg(windows)]
macro_rules! signal_like {
    ($($t:ty),*) => {$(
        impl SignalLike for $t {
            async fn recv_any(&mut self) {
                self.recv().await;
            }
        }
    )*};
}

#[cfg(windows)]
signal_like!(
    tokio::signal::windows::CtrlClose,
    tokio::signal::windows::CtrlShutdown,
    tokio::signal::windows::CtrlLogoff
);
