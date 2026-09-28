// SPDX-License-Identifier: GPL-3.0-or-later
//! CLI: локальный прокси (SOCKS5 и HTTP на одном порту) → VLESS-сервер (или напрямую, или отказ — по
//! маршрутизации). Два способа запуска:
//!
//! 1. Ключи — один сервер, один SOCKS5-вход (как раньше):
//!    reality-client --server 'vless://UUID@host:443?security=reality&sni=site&pbk=KEY&sid=ID'
//!    reality-client --server-file server.txt --listen 127.0.0.1:1080
//!
//! 2. Файл настроек в формате sing-box или Xray-core (JSON, формат
//!    определяется сам) — несколько входов и выходов, маршрутизация:
//!    reality-client --config config.json
//!    Примеры — `examples/sing-box.json`, `examples/xray.json`, описание — README.md.
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
#[cfg(windows)]
mod winservice;

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
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        "\nCopyright (C) 2026 ERGFT\n",
        "Лицензия GPL-3.0-or-later: <https://www.gnu.org/licenses/gpl-3.0.html>.\n",
        "Это свободная программа: её можно изменять и распространять.\n",
        "Гарантий нет в той мере, в какой это допускает закон."
    ),
    about ="VLESS core — локальный SOCKS5/HTTP-прокси -> VLESS (tcp/ws/grpc/httpupgrade/xhttp, tls/reality, XTLS Vision)"
)]
struct Args {
    /// Файл настроек в формате sing-box или Xray-core (JSON): входы,
    /// выходы, маршрутизация. Вместо ключей --server, --listen и остальных
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

    /// Снять то, что TUN оставил после аварийного завершения (Linux —
    /// правила маршрутизации и блокировку strict_route, Windows — kill
    /// switch WFP), и выйти
    #[arg(long, exclusive = true)]
    tun_cleanup: bool,

    /// Писать журнал в файл (дописывая; больше 10 МБ — старый уходит в
    /// .old), а не в консоль
    #[arg(long, value_name = "ФАЙЛ")]
    log_file: Option<PathBuf>,

    /// Windows: установить (или обновить) службу с этим --config: она
    /// запускается при старте системы, до входа пользователя (для TUN).
    /// Настройки копируются в %ProgramData%\RealityClient, закрытую от
    /// записи обычным пользователям. Нужны права администратора
    #[arg(long, requires = "config")]
    service_install: bool,

    /// Windows: остановить и удалить службу
    #[arg(long, exclusive = true)]
    service_uninstall: bool,

    /// Windows: запускать при входе в систему (без окна, журнал — рядом с
    /// файлом настроек); с --system-proxy — и включать системный прокси
    #[arg(long, requires = "config")]
    autostart_install: bool,

    /// Windows: убрать запуск при входе в систему
    #[arg(long, exclusive = true)]
    autostart_uninstall: bool,

    /// Запуск диспетчером служб Windows (ставит --service-install)
    #[arg(long, hide = true, requires = "config")]
    service: bool,

    /// Windows: закрыть окно консоли (для автозапуска)
    #[arg(long, hide = true)]
    hide_console: bool,

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
            mux: None,
            fragment: None,
            noises: Vec::new(),
            outbounds: Vec::new(),
            subscriptions: Vec::new(),
            url: None,
            interval: None,
            tolerance: None,
            default: None,
        }],
        route: RouteConfig {
            final_: Some("proxy".into()),
            ..Default::default()
        },
        dns: None,
        subscriptions: Vec::new(),
        api: None,
    })
}

/// Журнал: в stderr или в файл (`--log-file`); он же — поток `GET /logs`
/// в API.
fn init_logging(log_file: Option<&std::path::Path>) -> Result<()> {
    use reality_core::app::events::LogLayer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // По умолчанию — уровень info: иначе при незаданном RUST_LOG было не
    // понять, запустился ли клиент и на каком порту слушает.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info,netstack_smoltcp=error,smoltcp=error")
    });
    if let Some(path) = log_file {
        if std::fs::metadata(path).is_ok_and(|m| m.len() > 10 << 20) {
            let mut old = path.as_os_str().to_owned();
            old.push(".old");
            let _ = std::fs::rename(path, old);
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("журнал {}", path.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::sync::Mutex::new(f))
            .with_ansi(false)
            .finish()
            .with(LogLayer)
            .init();
        return Ok(());
    }
    // Цвета — только в настоящем терминале и не на Windows: в старой
    // консоли cmd.exe escape-последовательности печатаются как мусор.
    let ansi = cfg!(not(windows)) && std::io::IsTerminal::is_terminal(&std::io::stderr());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .finish()
        .with(LogLayer)
        .init();
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

/// Выполнить `f` в новом рантайме и остановить его не дольше чем за 2 с.
/// Обычное уничтожение рантайма ждёт все `spawn_blocking` (системный
/// резолвер и т.п.) сколько угодно — служба Windows тогда не
/// останавливалась за отведённое диспетчером время.
fn block_on<F: std::future::Future>(f: F) -> Result<F::Output> {
    let rt = runtime()?;
    let r = rt.block_on(f);
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    Ok(r)
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(args.log_file.as_deref())?;
    #[cfg(windows)]
    {
        if args.hide_console {
            winservice::hide_console();
        }
        if args.service_install {
            return winservice::install(args.config.as_deref().expect("requires"));
        }
        if args.service_uninstall {
            return winservice::uninstall();
        }
        if args.autostart_install {
            return winservice::autostart_install(
                args.config.as_deref().expect("requires"),
                args.system_proxy,
            );
        }
        if args.autostart_uninstall {
            return winservice::autostart_uninstall();
        }
        if args.service {
            return winservice::run_as_service(move |stop| {
                block_on(run(args, async {
                    let _ = stop.await;
                }))?
            });
        }
    }
    #[cfg(not(windows))]
    if args.service_install
        || args.service_uninstall
        || args.autostart_install
        || args.autostart_uninstall
        || args.service
    {
        anyhow::bail!(
            "службы и автозапуск здесь — только для Windows; на Linux — systemd \
             (examples/reality-client.service)"
        );
    }
    block_on(run(args, shutdown_signal()))?
}

async fn run(args: Args, stop: impl std::future::Future<Output = ()>) -> Result<()> {
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
    if let Some(path) = &args.config {
        running.set_config_path(path.clone());
        spawn_reload_on_sighup(running.controller());
    }
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
        _ = stop => tracing::info!("завершение по сигналу"),
    }
    // Здесь `_system_proxy` уничтожается и возвращает прежние настройки.
    Ok(())
}

/// SIGHUP (Unix) — перечитать файл настроек без разрыва соединений.
fn spawn_reload_on_sighup(ctl: std::sync::Arc<reality_core::app::Controller>) {
    #[cfg(unix)]
    tokio::spawn(async move {
        let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            return;
        };
        while hup.recv().await.is_some() {
            match ctl.reload_from_file().await {
                Ok(notes) => {
                    for n in notes {
                        tracing::warn!("{n}");
                    }
                }
                Err(e) => tracing::error!(error = %e, "настройки не перечитаны — работают прежние"),
            }
        }
    });
    #[cfg(not(unix))]
    let _ = ctl;
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
