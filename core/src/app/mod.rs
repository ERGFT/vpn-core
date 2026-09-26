//! Приложение-клиент: входы → маршрутизатор → выходы (как у Xray и
//! sing-box). Собирается из файла настроек ([`config::Config`]) или из
//! ключей командной строки.
//!
//! - `socks_in` — вход SOCKS5 (CONNECT, UDP ASSOCIATE);
//! - `router` — выбор выхода для соединения;
//! - `outbound` — выходы `direct` и `block` и общий интерфейс;
//! - `vless_out` — выход `vless` (сервер);
//! - `access` — кто может пользоваться входом (адреса, подбор пароля).

pub mod access;
pub mod config;
pub mod outbound;
pub mod router;
pub mod socks_in;
pub mod vless_out;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::error::{Error, Result};
use crate::socks5::Credentials;
use crate::vless::{Address, Security, VlessConfig};
use config::{Config, InboundKind, OutboundKind};
use outbound::{BlockOutbound, DirectOutbound, Outbound};
use router::Router;
use socks_in::SocksInbound;
use vless_out::VlessOutbound;

/// Минимальная длина пароля входа, если он открыт в сеть.
pub const MIN_LAN_PASSWORD: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// Что известно о соединении, когда выбирается выход.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// tag входа.
    pub inbound: Arc<str>,
    /// Кто подключился (приложение).
    pub source: SocketAddr,
    pub network: Network,
    pub target: Address,
    pub port: u16,
}

struct BuiltInbound {
    listen: SocketAddr,
    socks: Arc<SocksInbound>,
}

/// Собранное приложение, готовое к запуску.
pub struct App {
    inbounds: Vec<BuiltInbound>,
    router: Arc<Router>,
}

/// Запущенное приложение: фактические адреса входов и задачи.
pub struct Running {
    pub listen_addrs: Vec<SocketAddr>,
    tasks: JoinSet<Result<()>>,
}

impl Running {
    /// Ждать, пока какой-нибудь вход не завершится с ошибкой.
    pub async fn wait(mut self) -> Result<()> {
        while let Some(r) = self.tasks.join_next().await {
            match r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(Error::Config(format!("вход завершился аварийно: {e}"))),
            }
        }
        Ok(())
    }
}

fn secret(
    inline: &Option<String>,
    file: &Option<std::path::PathBuf>,
    what: &str,
) -> Result<Option<String>> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(Error::Config(format!(
            "{what}: задано и значение, и файл — оставьте одно"
        ))),
        (Some(s), None) => Ok(Some(s.trim().to_string())),
        (None, Some(p)) => Ok(Some(config::read_secret_file(p)?)),
        (None, None) => Ok(None),
    }
}

fn build_vless(o: &config::OutboundConfig) -> Result<VlessOutbound> {
    let link = secret(&o.link, &o.link_file, &format!("выход {}", o.tag))?
        .ok_or_else(|| Error::Config(format!("выход {}: нужна link или link_file", o.tag)))?;
    let mut cfg = VlessConfig::parse(&link)?;
    // Сразу при старте, а не на каждом соединении: неподходящая ссылка
    // не должна выглядеть как «прокси работает, но сайты не открываются».
    cfg.validate()?;
    if cfg.security == Security::Reality {
        cfg.reality_params()?;
    }
    if cfg.security == Security::None {
        if !o.allow_insecure {
            return Err(Error::Config(format!(
                "выход {}: в ссылке security=none — соединение с сервером не шифруется. \
                 Любой в той же Wi-Fi сети (или по пути до сервера) увидит ваш UUID и весь \
                 трафик и сможет пользоваться вашим сервером. Если это осознанно, разрешите \
                 явно (--allow-insecure или allow_insecure = true)",
                o.tag
            )));
        }
        tracing::warn!(outbound = %o.tag, "security=none: соединение с сервером НЕ шифруется");
    }
    if let Some(fp) = cfg.fingerprint.as_deref() {
        if !fp.is_empty() && fp != "chrome" {
            tracing::warn!(
                fp,
                "отпечаток TLS всегда Chrome-подобный; fp={fp} из ссылки игнорируется"
            );
        }
    }
    if let Some(ca) = &o.ca_file {
        cfg.ca_roots = Some(Arc::new(config::load_ca(ca)?));
    }
    tracing::info!(
        outbound = %o.tag,
        host = %cfg.host,
        port = cfg.port,
        sni = %cfg.effective_sni(),
        security = ?cfg.security,
        network = ?cfg.network,
        flow = ?cfg.flow,
        "сервер загружен"
    );
    Ok(VlessOutbound::new(o.tag.clone(), cfg, o.xudp))
}

fn build_socks(i: &config::InboundConfig, n: usize) -> Result<BuiltInbound> {
    let tag = i.tag.clone().unwrap_or_else(|| {
        if n == 0 {
            "socks".into()
        } else {
            format!("socks-{n}")
        }
    });
    let auth = match secret(&i.auth, &i.auth_file, &format!("вход {tag}"))? {
        Some(a) => Some(Credentials::parse(&a).ok_or_else(|| {
            Error::Config(format!("вход {tag}: пароль ожидается в виде логин:пароль"))
        })?),
        None => None,
    };
    if !socks_in::is_loopback_listen(&i.listen) {
        let Some(creds) = &auth else {
            return Err(Error::Config(format!(
                "вход {tag}: {} открывает прокси для всей сети без пароля; задайте логин:пароль",
                i.listen
            )));
        };
        if creds.password.len() < MIN_LAN_PASSWORD {
            return Err(Error::Config(format!(
                "вход {tag}: пароль короче {MIN_LAN_PASSWORD} символов, а прокси открыт в сеть — \
                 его подберут; задайте пароль длиннее"
            )));
        }
        tracing::warn!(
            "прокси открыт в сеть: SOCKS5 не шифрует ни пароль, ни адреса сайтов, ни данные \
             между устройством и этим компьютером — в общей Wi-Fi их видят соседи. Пускайте \
             только свои устройства (allow_ip), в чужих сетях не открывайте"
        );
        if i.allow_ip.is_empty() {
            tracing::warn!("allow_ip не задан: пароль могут пробовать с любого адреса в сети");
        }
    }
    match i.kind {
        InboundKind::Socks => Ok(BuiltInbound {
            listen: i.listen,
            socks: Arc::new(SocksInbound {
                tag: tag.into(),
                auth,
                allow_ip: i.allow_ip.clone(),
                max_conns: i.max_conns.unwrap_or(512),
            }),
        }),
    }
}

impl App {
    /// Собрать приложение из настроек, проверив всё, что можно проверить
    /// до запуска.
    pub fn build(cfg: &Config) -> Result<Self> {
        if cfg.inbounds.is_empty() {
            return Err(Error::Config("не задан ни один вход (inbounds)".into()));
        }
        let mut outbounds: Vec<Arc<dyn Outbound>> = Vec::new();
        for o in &cfg.outbounds {
            let built: Arc<dyn Outbound> = match o.kind {
                OutboundKind::Vless => Arc::new(build_vless(o)?),
                OutboundKind::Direct => Arc::new(DirectOutbound::new(o.tag.clone())),
                OutboundKind::Block => Arc::new(BlockOutbound::new(o.tag.clone())),
            };
            outbounds.push(built);
        }
        let router = Arc::new(Router::new(outbounds, cfg.route.final_.as_deref())?);
        let inbounds = cfg
            .inbounds
            .iter()
            .enumerate()
            .map(|(n, i)| build_socks(i, n))
            .collect::<Result<Vec<_>>>()?;
        Ok(App { inbounds, router })
    }

    /// Открыть все входы и начать принимать соединения.
    pub async fn start(self) -> Result<Running> {
        crate::transport::tcp_tls::ensure_crypto_provider();
        let mut tasks = JoinSet::new();
        let mut listen_addrs = Vec::new();
        for i in self.inbounds {
            let listener = TcpListener::bind(i.listen)
                .await
                .map_err(|e| Error::Config(format!("не удалось слушать {}: {e}", i.listen)))?;
            let addr = listener.local_addr()?;
            tracing::info!(
                inbound = %i.socks.tag,
                addr = %addr,
                auth = i.socks.auth.is_some(),
                "SOCKS5 слушает"
            );
            listen_addrs.push(addr);
            tasks.spawn(i.socks.serve(listener, self.router.clone()));
        }
        Ok(Running {
            listen_addrs,
            tasks,
        })
    }
}
