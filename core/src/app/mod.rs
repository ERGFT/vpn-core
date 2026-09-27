//! Приложение-клиент: входы → маршрутизатор → выходы (как у Xray и
//! sing-box). Собирается из файла настроек ([`config::Config`]) или из
//! ключей командной строки.
//!
//! - `proxy_in`, `http_in` — входы SOCKS5, HTTP и mixed (оба на одном
//!   порту); `sniff` — домен по первым байтам (TLS SNI, HTTP Host);
//! - `router`, `rules`, `geo` — выбор выхода по правилам (домены, адреса,
//!   базы geosite/geoip, порт, сеть, вход);
//! - `outbound` — выходы `direct` и `block` и общий интерфейс;
//! - `vless_out` — выход `vless` (сервер);
//! - `access` — кто может пользоваться входом (адреса, подбор пароля);
//! - `dns`, `dns_in` — свой DNS (DoH/DoT/UDP/TCP, кеш, fake-IP) и вход
//!   DNS-сервера;
//! - `tun` — вход TUN (весь трафик компьютера) и `auto_route`.

pub mod access;
pub mod config;
pub mod dns;
pub mod dns_in;
pub mod geo;
pub mod http_in;
pub mod outbound;
pub mod proxy_in;
pub mod router;
pub mod rules;
pub mod sniff;
pub mod tun;
pub mod vless_out;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;

use crate::error::{Error, Result};
use crate::socks5::Credentials;
use crate::vless::{Address, Security, VlessConfig};
use config::{Config, InboundKind, OutboundKind};
use dns::{Dns, DnsSlot};
use dns_in::DnsInbound;
use outbound::{BlockOutbound, DirectOutbound, DnsOutbound, Outbound};
use proxy_in::ProxyInbound;
use router::Router;
use vless_out::VlessOutbound;

/// Минимальная длина пароля входа, если он открыт в сеть.
pub const MIN_LAN_PASSWORD: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
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
    /// Домен, распознанный по первым байтам (SNI, Host), — для правил,
    /// когда приложение прислало IP.
    pub sniffed: Option<String>,
}

enum InboundSvc {
    Proxy(Arc<ProxyInbound>),
    Dns(Arc<DnsInbound>),
    Tun(Arc<tun::TunInbound>),
}

struct BuiltInbound {
    /// У TUN адреса нет.
    listen: Option<SocketAddr>,
    tag: Arc<str>,
    kind: InboundKind,
    svc: InboundSvc,
}

/// Собранное приложение, готовое к запуску.
pub struct App {
    inbounds: Vec<BuiltInbound>,
    router: Arc<Router>,
    dns: Option<Arc<Dns>>,
    /// Имена серверов (VLESS, DNS), которые надо разрешить до включения
    /// маршрутов TUN.
    pinned_hosts: Vec<(String, u16)>,
}

/// Запущенное приложение: фактические адреса входов и задачи.
pub struct Running {
    pub listen_addrs: Vec<SocketAddr>,
    /// Входы: tag, вид и фактический адрес.
    pub inbounds: Vec<(Arc<str>, InboundKind, SocketAddr)>,
    tasks: JoinSet<Result<()>>,
    dns: Option<Arc<Dns>>,
    /// Маршруты TUN: держатся ради `Drop` — снимаются при уничтожении.
    #[allow(dead_code)]
    routes: Vec<tun::route::RouteGuard>,
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

    /// DNS-модуль (если настроен).
    pub fn dns(&self) -> Option<&Arc<Dns>> {
        self.dns.as_ref()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // Сначала остановить входы, потом снять маршруты (поле routes
        // уничтожится после этого метода).
        self.tasks.abort_all();
        // Таблица fake-IP переживает перезапуск.
        if let Some(d) = &self.dns {
            d.save();
        }
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

fn inbound_tag(i: &config::InboundConfig, n: usize) -> String {
    i.tag.clone().unwrap_or_else(|| {
        let base = match i.kind {
            InboundKind::Socks => "socks",
            InboundKind::Http => "http",
            InboundKind::Mixed => "mixed",
            InboundKind::Dns => "dns",
            InboundKind::Tun => "tun",
        };
        if n == 0 {
            base.to_string()
        } else {
            format!("{base}-{n}")
        }
    })
}

fn build_dns_inbound(
    i: &config::InboundConfig,
    tag: &str,
    dns: Option<&Arc<Dns>>,
) -> Result<Arc<DnsInbound>> {
    let dns = dns.ok_or_else(|| {
        Error::Config(format!("вход {tag}: type = \"dns\" требует раздела [dns]"))
    })?;
    if i.auth.is_some() || i.auth_file.is_some() || i.sniff || i.sniff_override_destination {
        return Err(Error::Config(format!(
            "вход {tag}: у DNS-входа не бывает пароля и sniffing"
        )));
    }
    let listen = i.listen_addr()?;
    if !proxy_in::is_loopback_listen(&listen) && i.allow_ip.is_empty() {
        return Err(Error::Config(format!(
            "вход {tag}: DNS-сервер, открытый в сеть ({listen}), без allow_ip — «открытый \
             резолвер»: им пользуются для DDoS-атак; перечислите свои устройства в allow_ip"
        )));
    }
    Ok(Arc::new(DnsInbound {
        tag: tag.into(),
        allow_ip: i.allow_ip.clone(),
        dns: dns.clone(),
        max_conns: i.max_conns.unwrap_or(512),
    }))
}

fn build_proxy_inbound(i: &config::InboundConfig, tag: &str) -> Result<Arc<ProxyInbound>> {
    let auth = match secret(&i.auth, &i.auth_file, &format!("вход {tag}"))? {
        Some(a) => Some(Credentials::parse(&a).ok_or_else(|| {
            Error::Config(format!("вход {tag}: пароль ожидается в виде логин:пароль"))
        })?),
        None => None,
    };
    let listen = i.listen_addr()?;
    if !proxy_in::is_loopback_listen(&listen) {
        let Some(creds) = &auth else {
            return Err(Error::Config(format!(
                "вход {tag}: {listen} открывает прокси для всей сети без пароля; задайте логин:пароль"
            )));
        };
        if creds.password.len() < MIN_LAN_PASSWORD {
            return Err(Error::Config(format!(
                "вход {tag}: пароль короче {MIN_LAN_PASSWORD} символов, а прокси открыт в сеть — \
                 его подберут; задайте пароль длиннее"
            )));
        }
        tracing::warn!(
            "прокси открыт в сеть: SOCKS5 и HTTP-прокси не шифруют ни пароль, ни адреса сайтов, ни данные \
             между устройством и этим компьютером — в общей Wi-Fi их видят соседи. Пускайте \
             только свои устройства (allow_ip), в чужих сетях не открывайте"
        );
        if i.allow_ip.is_empty() {
            tracing::warn!("allow_ip не задан: пароль могут пробовать с любого адреса в сети");
        }
    }
    if i.sniff_override_destination && !i.sniff {
        return Err(Error::Config(format!(
            "вход {tag}: sniff_override_destination работает только вместе с sniff = true"
        )));
    }
    Ok(Arc::new(ProxyInbound {
        tag: tag.into(),
        kind: i.kind,
        auth,
        allow_ip: i.allow_ip.clone(),
        max_conns: i.max_conns.unwrap_or(512),
        sniff: i.sniff,
        sniff_override: i.sniff_override_destination,
    }))
}

fn build_tun_inbound(
    i: &config::InboundConfig,
    tag: &str,
    dns: Option<&Arc<Dns>>,
) -> Result<Arc<tun::TunInbound>> {
    let settings = tun::settings(i)?;
    if settings.dns_hijack && dns.is_none() {
        return Err(Error::Config(format!(
            "вход {tag}: TUN перехватывает DNS (dns_hijack), а раздела [dns] нет; \
             добавьте [dns] или dns_hijack = false"
        )));
    }
    if settings.auto_route && dns.is_some_and(|d| d.has_local()) {
        return Err(Error::Config(format!(
            "вход {tag}: DNS-сервер address = \"local\" (системный) вместе с TUN — петля: \
             системный DNS сам идёт через TUN; укажите сервер адресом"
        )));
    }
    Ok(Arc::new(tun::TunInbound {
        tag: tag.into(),
        settings,
        dns: dns.cloned(),
    }))
}

/// Адреса VLESS-серверов (по выходам с типом vless).
fn router_vless_servers(
    router: &Router,
    outs: &[config::OutboundConfig],
) -> Vec<Option<(String, u16)>> {
    outs.iter()
        .map(|o| match o.kind {
            OutboundKind::Vless => router.get(&o.tag).and_then(|b| b.server()),
            _ => None,
        })
        .collect()
}

impl App {
    /// Собрать приложение из настроек, проверив всё, что можно проверить
    /// до запуска.
    pub fn build(cfg: &Config) -> Result<Self> {
        if cfg.inbounds.is_empty() {
            return Err(Error::Config("не задан ни один вход (inbounds)".into()));
        }
        let mut tags: Vec<String> = Vec::new();
        for i in &cfg.inbounds {
            i.check_fields()?;
        }
        if cfg
            .inbounds
            .iter()
            .filter(|i| i.kind == InboundKind::Tun)
            .count()
            > 1
        {
            return Err(Error::Config(
                "вход type = \"tun\" может быть только один".into(),
            ));
        }
        for (n, i) in cfg.inbounds.iter().enumerate() {
            let t = inbound_tag(i, n);
            if tags.contains(&t) {
                return Err(Error::Config(format!(
                    "два входа с одинаковым tag = \"{t}\""
                )));
            }
            tags.push(t);
        }

        // Выходы `direct` и `dns` получают DNS-модуль позже: он сам ходит
        // к серверам через выходы.
        let dns_slot: DnsSlot = Arc::new(std::sync::OnceLock::new());
        let mut outbounds: Vec<Arc<dyn Outbound>> = Vec::new();
        for o in &cfg.outbounds {
            let built: Arc<dyn Outbound> = match o.kind {
                OutboundKind::Vless => Arc::new(build_vless(o)?),
                OutboundKind::Direct if cfg.dns.is_some() => {
                    Arc::new(DirectOutbound::with_dns(o.tag.clone(), dns_slot.clone()))
                }
                OutboundKind::Direct => Arc::new(DirectOutbound::new(o.tag.clone())),
                OutboundKind::Block => Arc::new(BlockOutbound::new(o.tag.clone())),
                OutboundKind::Dns => {
                    if cfg.dns.is_none() {
                        return Err(Error::Config(format!(
                            "выход {}: type = \"dns\" требует раздела [dns]",
                            o.tag
                        )));
                    }
                    Arc::new(DnsOutbound::new(o.tag.clone(), dns_slot.clone()))
                }
            };
            outbounds.push(built);
        }

        let mut site_codes: Vec<String> = cfg
            .route
            .rules
            .iter()
            .flat_map(|r| r.geosite.clone())
            .collect();
        if let Some(d) = &cfg.dns {
            site_codes.extend(d.rules.iter().flat_map(|r| r.geosite.clone()));
        }
        let geo = rules::GeoFiles::load(
            site_codes,
            cfg.route
                .rules
                .iter()
                .flat_map(|r| r.geoip.clone())
                .collect(),
            cfg.route
                .geosite_file
                .as_deref()
                .unwrap_or(std::path::Path::new("geosite.dat")),
            cfg.route
                .geoip_file
                .as_deref()
                .unwrap_or(std::path::Path::new("geoip.dat")),
        )?;

        let dns = match &cfg.dns {
            Some(dc) => {
                let default_detour = cfg
                    .route
                    .final_
                    .clone()
                    .or_else(|| cfg.outbounds.first().map(|o| o.tag.clone()))
                    .unwrap_or_default();
                let find = |t: &str| outbounds.iter().find(|o| o.tag() == t).cloned();
                let d = Arc::new(Dns::build(dc, &find, &default_detour, &geo)?);
                let _ = dns_slot.set(d.clone());
                Some(d)
            }
            None => None,
        };
        if cfg.route.domain_strategy == config::DomainStrategy::IpIfNonMatch && dns.is_none() {
            return Err(Error::Config(
                "route.domain_strategy = \"ip_if_non_match\" требует раздела [dns]: \
                 иначе имена сайтов уходили бы системному DNS мимо туннеля"
                    .into(),
            ));
        }
        let mut router = Router::new(outbounds, &cfg.route, &tags, &geo)?;
        if let Some(d) = &dns {
            router.set_dns(d.clone());
        }

        let mut inbounds = Vec::new();
        for (i, tag) in cfg.inbounds.iter().zip(&tags) {
            let svc = match i.kind {
                InboundKind::Dns => InboundSvc::Dns(build_dns_inbound(i, tag, dns.as_ref())?),
                InboundKind::Tun => InboundSvc::Tun(build_tun_inbound(i, tag, dns.as_ref())?),
                _ => InboundSvc::Proxy(build_proxy_inbound(i, tag)?),
            };
            inbounds.push(BuiltInbound {
                listen: i.listen,
                tag: tag.as_str().into(),
                kind: i.kind,
                svc,
            });
        }
        let mut pinned_hosts: Vec<(String, u16)> = router_vless_servers(&router, &cfg.outbounds)
            .into_iter()
            .flatten()
            .collect();
        if let Some(d) = &dns {
            pinned_hosts.extend(d.server_hosts());
        }
        Ok(App {
            inbounds,
            router: Arc::new(router),
            dns,
            pinned_hosts,
        })
    }

    /// Открыть все входы и начать принимать соединения.
    pub async fn start(self) -> Result<Running> {
        crate::transport::tcp_tls::ensure_crypto_provider();
        let mut tasks = JoinSet::new();
        let mut listen_addrs = Vec::new();
        let mut inbounds = Vec::new();
        let bind_err = |a: SocketAddr, e: std::io::Error| {
            Error::Config(format!("не удалось слушать {a}: {e}"))
        };
        let mut routes = Vec::new();
        for i in self.inbounds {
            if let InboundSvc::Tun(t) = &i.svc {
                let dev = t.create_device()?;
                tracing::info!(inbound = %t.tag, interface = %dev.name, "TUN создан");
                if t.settings.auto_route {
                    // Адреса серверов — заранее, пока системный DNS ещё
                    // работает напрямую.
                    for (h, p) in &self.pinned_hosts {
                        if let Err(e) = crate::transport::tcp_tls::resolve_server(h, *p).await {
                            tracing::warn!(host = %h, error = %e, "tun: имя сервера не разрешилось заранее");
                        }
                    }
                    routes.push(tun::route::setup(
                        &dev.name,
                        dev.if_index,
                        dev.has_v6,
                        &t.settings.route_exclude,
                        t.settings.strict_route,
                    )?);
                }
                tasks.spawn(t.clone().serve(dev, self.router.clone()));
                inbounds.push((i.tag, i.kind, SocketAddr::from(([0, 0, 0, 0], 0))));
                continue;
            }
            let listen = i.listen.expect("проверено при сборке");
            let listener = TcpListener::bind(listen)
                .await
                .map_err(|e| bind_err(listen, e))?;
            let addr = listener.local_addr()?;
            match i.svc {
                InboundSvc::Proxy(p) => {
                    tracing::info!(
                        inbound = %p.tag,
                        proto = p.proto_name(),
                        addr = %addr,
                        auth = p.auth.is_some(),
                        sniff = p.sniff,
                        "прокси слушает"
                    );
                    tasks.spawn(p.serve(listener, self.router.clone()));
                }
                InboundSvc::Dns(d) => {
                    // UDP — на тот же порт, что и TCP (важно при порте 0).
                    let udp = UdpSocket::bind(addr).await.map_err(|e| bind_err(addr, e))?;
                    tracing::info!(inbound = %d.tag, addr = %addr, "DNS слушает (UDP и TCP)");
                    tasks.spawn(d.clone().serve_tcp(listener));
                    tasks.spawn(d.serve_udp(udp));
                }
                InboundSvc::Tun(_) => unreachable!("обработан выше"),
            }
            listen_addrs.push(addr);
            inbounds.push((i.tag, i.kind, addr));
        }
        if let Some(d) = &self.dns {
            d.spawn_persistence();
        }
        Ok(Running {
            listen_addrs,
            inbounds,
            tasks,
            dns: self.dns,
            routes,
        })
    }
}
