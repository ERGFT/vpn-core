// SPDX-License-Identifier: GPL-3.0-or-later
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
//! - `tun` — вход TUN (весь трафик компьютера) и `auto_route`;
//! - `group` — группы серверов (selector, urltest, fallback);
//! - `subscription` — серверы с панели по подписке;
//! - `http_client` — HTTP-запросы через выход (проверки, подписки).

pub mod access;
pub mod api;
mod clash;
pub mod config;
pub mod dns;
pub mod dns_in;
pub mod events;
pub mod geo;
pub mod group;
pub mod http_client;
pub mod http_in;
pub mod outbound;
pub mod proxy_in;
pub mod router;
pub mod rules;
pub mod ruleset;
pub mod sniff;
pub mod sniff_quic;
pub mod stats;
pub mod subscription;
pub mod trojan_out;
pub mod tun;
pub mod vless_out;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::error::{Error, Result};
use crate::socks5::Credentials;
use crate::vless::{Address, Security, VlessConfig};
use config::{Config, InboundKind, OutboundKind};
use dns::{Dns, DnsSlot};
use dns_in::DnsInbound;
use group::{Group, GroupSettings, Strategy};
use outbound::{BlockOutbound, DirectOutbound, DnsOutbound, Outbound};
use proxy_in::ProxyInbound;
use router::{Router, RouterHandle};
use stats::Tracker;
use subscription::Subscription;
use vless_out::VlessOutbound;

/// Служебная группа режима global (как в Clash API).
pub const GLOBAL: &str = "GLOBAL";

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
    /// Вид входа (`mixed`, `tun`, …) — для API.
    pub inbound_type: &'static str,
    /// Какое правило выбрало выход (описание; `None` — `route.final`).
    /// Заполняет маршрутизатор.
    pub rule: Option<Arc<str>>,
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
    /// Настройки входа строкой: при перечитывании настроек вход
    /// перезапускается, только если они изменились.
    key: String,
}

/// Всё, что пересобирается при перечитывании настроек (кроме самого
/// маршрутизатора — он отдаётся отдельно).
struct Core {
    dns: Option<Arc<Dns>>,
    /// Имена серверов (VLESS, DNS), которые надо разрешить до включения
    /// маршрутов TUN.
    pinned_hosts: Vec<(String, u16)>,
    groups: Vec<Arc<Group>>,
    /// Подписки и есть ли уже список серверов.
    subs: Vec<(Arc<Subscription>, bool)>,
}

/// Собранное приложение, готовое к запуску.
pub struct App {
    inbounds: Vec<BuiltInbound>,
    core: Core,
    routers: Arc<RouterHandle>,
    tracker: Arc<Tracker>,
    config: Config,
    /// Настройки API и токен.
    api: Option<(api::ApiConfig, String)>,
}

/// Запущенный вход.
struct Live {
    key: String,
    tag: Arc<str>,
    kind: InboundKind,
    addr: Option<SocketAddr>,
    tasks: Vec<AbortHandle>,
}

struct State {
    config: Config,
    dns: Option<Arc<Dns>>,
    /// Проверки групп и обновление подписок.
    core_tasks: Vec<AbortHandle>,
    inbounds: Vec<Live>,
}

/// Управление запущенным приложением: перечитать настройки, группы,
/// подписки (им пользуется API).
pub struct Controller {
    routers: Arc<RouterHandle>,
    tracker: Arc<Tracker>,
    state: std::sync::Mutex<State>,
    groups: std::sync::RwLock<Vec<Arc<Group>>>,
    subs: std::sync::RwLock<Vec<Arc<Subscription>>>,
    config_path: std::sync::RwLock<Option<std::path::PathBuf>>,
    /// Перечитывания — по одному.
    reload_lock: tokio::sync::Mutex<()>,
    errors: mpsc::UnboundedSender<Error>,
}

/// Запущенное приложение: фактические адреса входов и задачи.
pub struct Running {
    pub listen_addrs: Vec<SocketAddr>,
    /// Входы: tag, вид и фактический адрес.
    pub inbounds: Vec<(Arc<str>, InboundKind, SocketAddr)>,
    /// Адрес API (если включено).
    pub api_addr: Option<SocketAddr>,
    ctl: Arc<Controller>,
    errors: mpsc::UnboundedReceiver<Error>,
    api_task: Option<AbortHandle>,
    /// Маршруты TUN: держатся ради `Drop` — снимаются при уничтожении.
    #[allow(dead_code)]
    routes: Vec<tun::route::RouteGuard>,
    /// Задан резолвер для режима TUN — снять при остановке.
    tun_resolver: bool,
}

impl Running {
    /// Ждать, пока какой-нибудь вход не завершится с ошибкой.
    pub async fn wait(mut self) -> Result<()> {
        match self.errors.recv().await {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// DNS-модуль (если настроен).
    pub fn dns(&self) -> Option<Arc<Dns>> {
        self.ctl.routers.get().dns().cloned()
    }

    /// Группа серверов по tag.
    pub fn group(&self, tag: &str) -> Option<Arc<Group>> {
        self.ctl.group(tag)
    }

    /// Учёт соединений и трафика.
    pub fn tracker(&self) -> &Arc<Tracker> {
        &self.ctl.tracker
    }

    pub fn controller(&self) -> Arc<Controller> {
        self.ctl.clone()
    }

    /// Откуда перечитывать настройки (`reload_from_file`, API, SIGHUP).
    pub fn set_config_path(&self, p: std::path::PathBuf) {
        *self.ctl.config_path.write().unwrap() = Some(p);
    }

    /// Применить новые настройки без разрыва открытых соединений.
    /// Возвращает замечания (что вступит в силу только после перезапуска).
    pub async fn reload(&self, cfg: Config) -> Result<Vec<String>> {
        self.ctl.reload(cfg).await
    }

    /// Текущие адреса входов (после перечитывания могли измениться).
    pub fn inbound_addrs(&self) -> Vec<(Arc<str>, InboundKind, Option<SocketAddr>)> {
        self.ctl
            .state
            .lock()
            .unwrap()
            .inbounds
            .iter()
            .map(|l| (l.tag.clone(), l.kind, l.addr))
            .collect()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // Сначала остановить входы, потом снять маршруты (поле routes
        // уничтожится после этого метода).
        if let Some(a) = &self.api_task {
            a.abort();
        }
        let st = self.ctl.state.lock().unwrap();
        for l in &st.inbounds {
            for t in &l.tasks {
                t.abort();
            }
        }
        for t in &st.core_tasks {
            t.abort();
        }
        // Таблица fake-IP переживает перезапуск.
        if let Some(d) = &st.dns {
            d.save();
        }
        if self.tun_resolver {
            crate::transport::tcp_tls::set_tun_resolver(None);
        }
    }
}

/// Запустить задачу; её ошибка — в канал ошибок приложения.
fn spawn_task<F>(errors: &mpsc::UnboundedSender<Error>, f: F) -> AbortHandle
where
    F: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let tx = errors.clone();
    tokio::spawn(async move {
        if let Err(e) = f.await {
            let _ = tx.send(e);
        }
    })
    .abort_handle()
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
        .ok_or_else(|| Error::Config(format!("выход {}: не задан сервер", o.tag)))?;
    let roots = match &o.ca_file {
        Some(ca) => Some(Arc::new(config::load_ca(ca)?)),
        None => None,
    };
    let frag = build_fragment(o)?;
    let v = vless_from_link(&o.tag, &link, o.xudp, o.allow_insecure, roots, false, frag)?;
    match o.mux {
        Some(n) => v.with_mux(n),
        None => Ok(v),
    }
}

fn build_trojan(o: &config::OutboundConfig) -> Result<trojan_out::TrojanOutbound> {
    let link = secret(&o.link, &o.link_file, &format!("выход {}", o.tag))?
        .ok_or_else(|| Error::Config(format!("выход {}: не задан сервер", o.tag)))?;
    let roots = match &o.ca_file {
        Some(ca) => Some(Arc::new(config::load_ca(ca)?)),
        None => None,
    };
    trojan_from_link(
        &o.tag,
        &link,
        o.allow_insecure,
        roots,
        false,
        build_fragment(o)?,
    )
}

/// Выход Trojan из ссылки (из настроек или из подписки).
fn trojan_from_link(
    tag: &str,
    link: &str,
    allow_insecure: bool,
    ca_roots: Option<Arc<rustls::RootCertStore>>,
    quiet: bool,
    fragment: Option<Arc<crate::transport::fragment::Fragment>>,
) -> Result<trojan_out::TrojanOutbound> {
    let mut t = crate::trojan::TrojanConfig::parse(link)?;
    t.transport.validate()?;
    if t.transport.security == Security::Reality {
        t.transport.reality_params()?;
    }
    if t.transport.security == Security::None && !allow_insecure {
        return Err(Error::Config(format!(
            "выход {tag}: trojan с security=none — пароль и весь трафик идут открытым \
             текстом; если это осознанно, разрешите явно (\"allow_insecure\": true у выхода)"
        )));
    }
    if let (Some(w), false) = (
        crate::fingerprint::Browser::from_fp(t.transport.fingerprint.as_deref()).1,
        quiet,
    ) {
        tracing::warn!(outbound = %tag, "{w}");
    }
    t.transport.ca_roots = ca_roots;
    t.transport.fragment = fragment;
    if quiet {
        tracing::debug!(outbound = %tag, host = %t.transport.host, "сервер подписки (trojan)");
    } else {
        tracing::info!(
            outbound = %tag,
            host = %t.transport.host,
            port = t.transport.port,
            security = ?t.transport.security,
            network = ?t.transport.network,
            "сервер trojan загружен"
        );
    }
    Ok(trojan_out::TrojanOutbound::new(tag, t))
}

/// Выход VLESS из ссылки (из настроек или из подписки). `quiet` — не
/// писать в журнал о каждом сервере (подписка).
fn vless_from_link(
    tag: &str,
    link: &str,
    xudp: bool,
    allow_insecure: bool,
    ca_roots: Option<Arc<rustls::RootCertStore>>,
    quiet: bool,
    fragment: Option<Arc<crate::transport::fragment::Fragment>>,
) -> Result<VlessOutbound> {
    let mut cfg = VlessConfig::parse(link)?;
    // Сразу при старте, а не на каждом соединении: неподходящая ссылка
    // не должна выглядеть как «прокси работает, но сайты не открываются».
    cfg.validate()?;
    if cfg.security == Security::Reality {
        cfg.reality_params()?;
    }
    if cfg.security == Security::None {
        if !allow_insecure {
            return Err(Error::Config(format!(
                "выход {tag}: в ссылке security=none — соединение с сервером не шифруется. \
                 Любой в той же Wi-Fi сети (или по пути до сервера) увидит ваш UUID и весь \
                 трафик и сможет пользоваться вашим сервером. Если это осознанно, разрешите \
                 явно (--allow-insecure или allow_insecure = true)"
            )));
        }
        if !quiet {
            tracing::warn!(outbound = %tag, "security=none: соединение с сервером НЕ шифруется");
        }
    }
    if let (Some(w), false) = (
        crate::fingerprint::Browser::from_fp(cfg.fingerprint.as_deref()).1,
        quiet,
    ) {
        tracing::warn!(outbound = %tag, "{w}");
    }
    cfg.ca_roots = ca_roots;
    cfg.fragment = fragment;
    if quiet {
        tracing::debug!(outbound = %tag, host = %cfg.host, port = cfg.port, "сервер подписки");
    } else {
        tracing::info!(
            outbound = %tag,
            host = %cfg.host,
            port = cfg.port,
            sni = %cfg.effective_sni(),
            security = ?cfg.security,
            network = ?cfg.network,
            flow = ?cfg.flow,
            fp = cfg.browser.name(),
            "сервер загружен"
        );
    }
    Ok(VlessOutbound::new(tag.to_string(), cfg, xudp))
}

fn build_fragment(
    o: &config::OutboundConfig,
) -> Result<Option<Arc<crate::transport::fragment::Fragment>>> {
    o.fragment
        .as_ref()
        .map(|f| {
            f.build()
                .map(Arc::new)
                .map_err(|e| Error::Config(format!("выход {}: {e}", o.tag)))
        })
        .transpose()
}

fn build_direct(o: &config::OutboundConfig, dns: Option<DnsSlot>) -> Result<DirectOutbound> {
    let mut d = match dns {
        Some(slot) => DirectOutbound::with_dns(o.tag.clone(), slot),
        None => DirectOutbound::new(o.tag.clone()),
    };
    d = d.with_fragment(build_fragment(o)?);
    let noises = o
        .noises
        .iter()
        .map(|n| n.build())
        .collect::<Result<Vec<_>>>()
        .map_err(|e| Error::Config(format!("выход {}: {e}", o.tag)))?;
    Ok(d.with_noises(noises))
}

/// Адрес проверки групп по умолчанию.
pub const DEFAULT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";

fn group_settings(o: &config::OutboundConfig) -> Result<GroupSettings> {
    let strategy = match o.kind {
        OutboundKind::Selector => Strategy::Selector,
        OutboundKind::Urltest => Strategy::UrlTest,
        OutboundKind::Fallback => Strategy::Fallback,
        _ => unreachable!("только группы"),
    };
    let url = http_client::Url::parse(o.url.as_deref().unwrap_or(DEFAULT_PROBE_URL))
        .map_err(|e| Error::Config(format!("выход {}: {e}", o.tag)))?;
    let interval = o.interval.unwrap_or(180);
    if interval < 10 {
        return Err(Error::Config(format!(
            "выход {}: interval меньше 10 секунд — слишком частые проверки заметны",
            o.tag
        )));
    }
    Ok(GroupSettings {
        strategy,
        url,
        interval: std::time::Duration::from_secs(interval),
        tolerance: std::time::Duration::from_millis(o.tolerance.unwrap_or(50)),
        timeout: std::time::Duration::from_secs(5),
    })
}

/// Группа не должна входить сама в себя (прямо или через другие группы).
fn check_group_cycles(outs: &[config::OutboundConfig]) -> Result<()> {
    use std::collections::HashMap;
    let groups: HashMap<&str, &config::OutboundConfig> = outs
        .iter()
        .filter(|o| o.kind.is_group())
        .map(|o| (o.tag.as_str(), o))
        .collect();
    // 0 — не посещена, 1 — в пути, 2 — проверена.
    fn visit<'a>(
        t: &'a str,
        groups: &HashMap<&'a str, &'a config::OutboundConfig>,
        state: &mut HashMap<&'a str, u8>,
        path: &mut Vec<&'a str>,
    ) -> Result<()> {
        match state.get(t) {
            Some(2) => return Ok(()),
            Some(1) => {
                path.push(t);
                return Err(Error::Config(format!(
                    "группы входят друг в друга по кругу: {}",
                    path.join(" → ")
                )));
            }
            _ => {}
        }
        state.insert(t, 1);
        path.push(t);
        for m in &groups[t].outbounds {
            if groups.contains_key(m.as_str()) {
                visit(m, groups, state, path)?;
            }
        }
        path.pop();
        state.insert(t, 2);
        Ok(())
    }
    let mut state = HashMap::new();
    let mut tags: Vec<&str> = groups.keys().copied().collect();
    tags.sort();
    for t in tags {
        visit(t, &groups, &mut state, &mut Vec::new())?;
    }
    Ok(())
}

fn valid_sub_tag(t: &str) -> bool {
    !t.is_empty()
        && !t.starts_with('.')
        && t.len() <= 64
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
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
    has_dns: bool,
    routers: &Arc<RouterHandle>,
) -> Result<Arc<DnsInbound>> {
    if !has_dns {
        return Err(Error::Config(format!(
            "вход {tag}: DNS-серверу нужен раздел dns"
        )));
    }
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
        routers: routers.clone(),
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
            "вход {tag}: sniff_override_destination работает только вместе с sniff (правило {{\"action\": \"sniff\"}})"
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
            "вход {tag}: TUN перехватывает DNS (правило hijack-dns), а раздела dns нет; \
             добавьте раздел dns или уберите правило"
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
    }))
}

/// Адреса VLESS-серверов (по выходам с типом vless).
fn router_vless_servers(
    router: &Router,
    outs: &[config::OutboundConfig],
) -> Vec<Option<(String, u16)>> {
    outs.iter()
        .map(|o| match o.kind {
            OutboundKind::Vless | OutboundKind::Trojan => {
                router.get(&o.tag).and_then(|b| b.server())
            }
            _ => None,
        })
        .collect()
}

/// Проверить входы и вернуть их tag.
fn inbound_tags(cfg: &Config) -> Result<Vec<String>> {
    if cfg.inbounds.is_empty() {
        return Err(Error::Config("не задан ни один вход (inbounds)".into()));
    }
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
        return Err(Error::Config("вход tun может быть только один".into()));
    }
    let mut tags: Vec<String> = Vec::new();
    for (n, i) in cfg.inbounds.iter().enumerate() {
        let t = inbound_tag(i, n);
        if tags.contains(&t) {
            return Err(Error::Config(format!(
                "два входа с одинаковым tag = \"{t}\""
            )));
        }
        tags.push(t);
    }
    Ok(tags)
}

/// Наборы правил, которые включаются одной строкой (`route.presets`).
/// Идут после своих правил — своими можно переопределить любой пресет.
fn preset_rules(cfg: &Config) -> Result<Vec<config::RuleConfig>> {
    let find = |kind: OutboundKind, preset: &str| {
        cfg.outbounds
            .iter()
            .find(|o| o.kind == kind)
            .map(|o| o.tag.clone())
            .ok_or_else(|| {
                Error::Config(format!(
                    "route.presets: «{preset}» нужен выход {}",
                    match kind {
                        OutboundKind::Block => "block",
                        _ => "direct",
                    }
                ))
            })
    };
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut out = Vec::new();
    for p in &cfg.route.presets {
        let rule = match p.as_str() {
            "block-ads" => config::RuleConfig {
                geosite: s(&["category-ads-all"]),
                outbound: find(OutboundKind::Block, p)?,
                ..Default::default()
            },
            "private-direct" => config::RuleConfig {
                ip_is_private: true,
                domain_suffix: s(&["local", "lan", "localhost", "home.arpa"]),
                outbound: find(OutboundKind::Direct, p)?,
                ..Default::default()
            },
            "ru-direct" => config::RuleConfig {
                domain_suffix: s(&["ru", "su", "xn--p1ai", "xn--d1acj3b"]),
                geosite: s(&["category-ru"]),
                geoip: s(&["ru"]),
                outbound: find(OutboundKind::Direct, p)?,
                ..Default::default()
            },
            "cn-direct" => config::RuleConfig {
                domain_suffix: s(&["cn"]),
                geosite: s(&["cn"]),
                geoip: s(&["cn"]),
                outbound: find(OutboundKind::Direct, p)?,
                ..Default::default()
            },
            "ir-direct" => config::RuleConfig {
                domain_suffix: s(&["ir"]),
                geosite: s(&["category-ir"]),
                geoip: s(&["ir"]),
                outbound: find(OutboundKind::Direct, p)?,
                ..Default::default()
            },
            other => {
                return Err(Error::Config(format!(
                    "route.presets: «{other}» — есть block-ads, private-direct, ru-direct, cn-direct, ir-direct"
                )))
            }
        };
        out.push(rule);
    }
    Ok(out)
}

/// Выходы, группы, подписки, DNS и маршрутизатор.
fn build_core(
    cfg: &Config,
    tags: &[String],
    tracker: Arc<Tracker>,
    prev_dns: Option<&Arc<Dns>>,
) -> Result<(Router, Core)> {
    for o in &cfg.outbounds {
        o.check_fields()?;
    }
    check_group_cycles(&cfg.outbounds)?;
    let mut route = cfg.route.clone();
    route.rules.extend(preset_rules(cfg)?);
    for r in &mut route.rules {
        r.label = Some(rules::describe(r));
    }
    let mut dns_cfg = cfg.dns.clone();
    ruleset::expand(&mut route, dns_cfg.as_mut())?;
    let cfg_dns = dns_cfg.as_ref();

    // Выходы `direct` и `dns` получают DNS-модуль позже: он сам ходит
    // к серверам через выходы.
    let dns_slot: DnsSlot = Arc::new(std::sync::OnceLock::new());
    // Группа GLOBAL — как у Clash: выход режима global (выбирается через
    // API); создаётся, если в настройках нет своего выхода с таким tag.
    let global_cfg = config::OutboundConfig::new(GLOBAL, OutboundKind::Selector);
    let mut outbounds: Vec<Arc<dyn Outbound>> = Vec::new();
    let mut groups: Vec<(&config::OutboundConfig, Arc<Group>)> = Vec::new();
    for o in &cfg.outbounds {
        let built: Arc<dyn Outbound> = match o.kind {
            OutboundKind::Vless => Arc::new(build_vless(o)?),
            OutboundKind::Trojan => Arc::new(build_trojan(o)?),
            OutboundKind::Direct => Arc::new(build_direct(
                o,
                cfg.dns.is_some().then(|| dns_slot.clone()),
            )?),
            OutboundKind::Block => Arc::new(BlockOutbound::new(o.tag.clone())),
            OutboundKind::Dns => {
                if cfg.dns.is_none() {
                    return Err(Error::Config(if o.tag.starts_with("__") {
                        "правило hijack-dns требует раздела dns".to_string()
                    } else {
                        format!("выход {} (dns) требует раздела dns", o.tag)
                    }));
                }
                Arc::new(DnsOutbound::new(o.tag.clone(), dns_slot.clone()))
            }
            OutboundKind::Selector | OutboundKind::Urltest | OutboundKind::Fallback => {
                let g = Group::new(
                    o.tag.clone(),
                    group_settings(o)?,
                    o.default.clone(),
                    tracker.clone(),
                );
                groups.push((o, g.clone()));
                g
            }
        };
        outbounds.push(built);
    }
    // Участники групп — когда все выходы собраны.
    let find_out = |t: &str| outbounds.iter().find(|o| o.tag() == t).cloned();
    for (o, g) in &groups {
        let mut members = Vec::new();
        for t in &o.outbounds {
            let m = find_out(t)
                .ok_or_else(|| Error::Config(format!("группа {}: нет выхода «{t}»", o.tag)))?;
            members.push(m);
        }
        for s in &o.subscriptions {
            if !cfg.subscriptions.iter().any(|c| &c.tag == s) {
                return Err(Error::Config(format!(
                    "группа {}: нет подписки «{s}» (раздел subscriptions)",
                    o.tag
                )));
            }
        }
        if let Some(d) = &o.default {
            let from_sub = o
                .subscriptions
                .iter()
                .any(|s| d.starts_with(&format!("{s}/")));
            if !o.outbounds.contains(d) && !from_sub {
                return Err(Error::Config(format!(
                    "группа {}: default = «{d}» — не участник группы",
                    o.tag
                )));
            }
        }
        g.set_fixed(members);
    }
    // Подписки.
    let mut subs = Vec::new();
    for (n, sc) in cfg.subscriptions.iter().enumerate() {
        let t = &sc.tag;
        if !valid_sub_tag(t) {
            return Err(Error::Config(format!(
                "подписка «{t}»: tag — латиница, цифры, «-», «_», «.»"
            )));
        }
        if cfg.subscriptions[..n].iter().any(|c| &c.tag == t)
            || cfg.outbounds.iter().any(|o| &o.tag == t)
        {
            return Err(Error::Config(format!("подписка «{t}»: такой tag уже есть")));
        }
        let url = secret(&sc.url, &sc.url_file, &format!("подписка {t}"))?
            .ok_or_else(|| Error::Config(format!("подписка {t}: нужен url или url_file")))?;
        let members: Vec<std::sync::Weak<Group>> = groups
            .iter()
            .filter(|(o, _)| o.subscriptions.contains(t))
            .map(|(_, g)| Arc::downgrade(g))
            .collect();
        if members.is_empty() {
            return Err(Error::Config(format!(
                "подписка {t} не входит ни в одну группу: добавьте \"subscriptions\": [\"{t}\"] \
                 в selector, urltest или fallback"
            )));
        }
        let detour = match &sc.detour {
            Some(d) => Some(find_out(d).ok_or_else(|| {
                Error::Config(format!("подписка {t}: нет выхода «{d}» (detour)"))
            })?),
            None => None,
        };
        let factory: Arc<subscription::ServerFactory> = Arc::new(server_from_link);
        let direct: Arc<dyn Outbound> =
            Arc::new(DirectOutbound::new(http_client::INTERNAL.to_string()));
        let sub = Arc::new(Subscription::new(
            sc.clone(),
            url,
            members,
            detour,
            direct,
            factory,
            tracker.events.clone(),
        )?);
        let loaded = sub.load_cache().is_some();
        subs.push((sub, loaded));
    }
    let mut global_members: Vec<Arc<dyn Outbound>> = Vec::new();
    if !outbounds.iter().any(|o| o.tag() == GLOBAL) {
        global_members = outbounds
            .iter()
            .filter(|o| !o.tag().starts_with("__") && !o.is_dns())
            .cloned()
            .collect();
    }
    if !global_members.is_empty() {
        let members = global_members;
        let default = route
            .final_
            .clone()
            .filter(|t| members.iter().any(|m| m.tag() == t));
        let g = Group::new(
            GLOBAL.to_string(),
            group_settings(&global_cfg)?,
            default,
            tracker.clone(),
        );
        g.set_fixed(members);
        outbounds.push(g.clone());
        groups.push((&global_cfg, g));
    }

    let groups: Vec<Arc<Group>> = groups.into_iter().map(|(_, g)| g).collect();

    let mut site_codes: Vec<String> = route.rules.iter().flat_map(|r| r.geosite.clone()).collect();
    if let Some(d) = cfg_dns {
        site_codes.extend(d.rules.iter().flat_map(|r| r.geosite.clone()));
    }
    let geo = rules::GeoFiles::load(
        site_codes,
        route.rules.iter().flat_map(|r| r.geoip.clone()).collect(),
        route
            .geosite_file
            .as_deref()
            .unwrap_or(std::path::Path::new("geosite.dat")),
        route
            .geoip_file
            .as_deref()
            .unwrap_or(std::path::Path::new("geoip.dat")),
    )?;

    let dns = match cfg_dns {
        Some(dc) => {
            let default_detour = route
                .final_
                .clone()
                .or_else(|| cfg.outbounds.first().map(|o| o.tag.clone()))
                .unwrap_or_default();
            let find = |t: &str| outbounds.iter().find(|o| o.tag() == t).cloned();
            let d = Arc::new(Dns::build(
                dc,
                &find,
                &default_detour,
                &geo,
                prev_dns.map(|d| &**d),
            )?);
            let _ = dns_slot.set(d.clone());
            Some(d)
        }
        None => None,
    };
    if route.domain_strategy == config::DomainStrategy::IpIfNonMatch && dns.is_none() {
        return Err(Error::Config(
            "route.domain_strategy ip_if_non_match требует раздела dns: \
             иначе имена сайтов уходили бы системному DNS мимо туннеля"
                .into(),
        ));
    }
    let global = outbounds.iter().find(|o| o.tag() == GLOBAL).cloned();
    let direct = cfg
        .outbounds
        .iter()
        .find(|o| o.kind == OutboundKind::Direct)
        .and_then(|o| outbounds.iter().find(|x| x.tag() == o.tag))
        .cloned()
        .unwrap_or_else(|| Arc::new(DirectOutbound::new("direct".to_string())));
    let mut router = Router::new(outbounds, &route, tags, &geo)?;
    router.set_modes(global, direct);
    if let Some(d) = &dns {
        router.set_dns(d.clone());
    }
    router.set_tracker(tracker);
    let mut pinned_hosts: Vec<(String, u16)> = router_vless_servers(&router, &cfg.outbounds)
        .into_iter()
        .flatten()
        .collect();
    if let Some(d) = &dns {
        pinned_hosts.extend(d.server_hosts());
    }
    Ok((
        router,
        Core {
            dns,
            pinned_hosts,
            groups,
            subs,
        },
    ))
}

/// Сервер подписки из ссылки.
fn server_from_link(
    tag: &str,
    link: &str,
    o: subscription::ServerOpts,
) -> Result<Arc<dyn Outbound>> {
    if link.starts_with("trojan://") {
        return Ok(Arc::new(trojan_from_link(
            tag,
            link,
            o.allow_insecure,
            None,
            true,
            o.fragment.clone(),
        )?));
    }
    let mut v = vless_from_link(
        tag,
        link,
        o.xudp,
        o.allow_insecure,
        None,
        true,
        o.fragment.clone(),
    )?;
    if let Some(n) = o.mux {
        // С Vision mux не бывает — такие серверы без него.
        if !v.config().flow.is_vision() {
            v = v.with_mux(n)?;
        }
    }
    Ok(Arc::new(v) as Arc<dyn Outbound>)
}

fn build_inbounds(
    cfg: &Config,
    tags: &[String],
    dns: Option<&Arc<Dns>>,
    routers: &Arc<RouterHandle>,
) -> Result<Vec<BuiltInbound>> {
    let mut inbounds = Vec::new();
    for (i, tag) in cfg.inbounds.iter().zip(tags) {
        let svc = match i.kind {
            InboundKind::Dns => InboundSvc::Dns(build_dns_inbound(i, tag, dns.is_some(), routers)?),
            InboundKind::Tun => InboundSvc::Tun(build_tun_inbound(i, tag, dns)?),
            _ => InboundSvc::Proxy(build_proxy_inbound(i, tag)?),
        };
        inbounds.push(BuiltInbound {
            listen: i.listen,
            tag: tag.as_str().into(),
            kind: i.kind,
            svc,
            key: format!("{tag}|{i:?}"),
        });
    }
    Ok(inbounds)
}

/// Открыть вход, слушающий адрес (всё, кроме TUN).
async fn start_listener(
    i: BuiltInbound,
    routers: &Arc<RouterHandle>,
    errors: &mpsc::UnboundedSender<Error>,
) -> Result<Live> {
    let bind_err =
        |a: SocketAddr, e: std::io::Error| Error::Config(format!("не удалось слушать {a}: {e}"));
    let listen = i.listen.expect("проверено при сборке");
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| bind_err(listen, e))?;
    let addr = listener.local_addr()?;
    let mut tasks = Vec::new();
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
            tasks.push(spawn_task(errors, p.serve(listener, routers.clone())));
        }
        InboundSvc::Dns(d) => {
            // UDP — на тот же порт, что и TCP (важно при порте 0).
            let udp = UdpSocket::bind(addr).await.map_err(|e| bind_err(addr, e))?;
            tracing::info!(inbound = %d.tag, addr = %addr, "DNS слушает (UDP и TCP)");
            tasks.push(spawn_task(errors, d.clone().serve_tcp(listener)));
            tasks.push(spawn_task(errors, d.serve_udp(udp)));
        }
        InboundSvc::Tun(_) => unreachable!("TUN запускается отдельно"),
    }
    Ok(Live {
        key: i.key,
        tag: i.tag,
        kind: i.kind,
        addr: Some(addr),
        tasks,
    })
}

/// Проверки групп, обновление подписок, сохранение fake-IP.
fn spawn_core(
    dns: Option<&Arc<Dns>>,
    groups: &[Arc<Group>],
    subs: Vec<(Arc<Subscription>, bool)>,
    errors: &mpsc::UnboundedSender<Error>,
) -> Vec<AbortHandle> {
    if let Some(d) = dns {
        d.spawn_persistence();
    }
    let mut v = Vec::new();
    for g in groups {
        v.push(spawn_task(errors, Group::check_loop(Arc::downgrade(g))));
    }
    for (sub, loaded) in subs {
        v.push(spawn_task(errors, sub.run(loaded)));
    }
    v
}

impl App {
    /// Собрать приложение из настроек, проверив всё, что можно проверить
    /// до запуска.
    pub fn build(cfg: &Config) -> Result<Self> {
        let tags = inbound_tags(cfg)?;
        let tracker = Tracker::new();
        let (router, core) = build_core(cfg, &tags, tracker.clone(), None)?;
        let routers = RouterHandle::new(router);
        let inbounds = build_inbounds(cfg, &tags, core.dns.as_ref(), &routers)?;
        let api = match &cfg.api {
            Some(a) => {
                let token = secret(&a.token, &a.token_file, "api")?.ok_or_else(|| {
                    Error::Config("api: нужен token или token_file (не короче 16 символов)".into())
                })?;
                if token.len() < api::MIN_TOKEN {
                    return Err(Error::Config(format!(
                        "api: токен короче {} символов",
                        api::MIN_TOKEN
                    )));
                }
                if !a.listen.ip().is_loopback() && a.allow_ip.is_empty() {
                    return Err(Error::Config(format!(
                        "api: {} открывает управление клиентом в сеть — перечислите свои устройства в allow_ip",
                        a.listen
                    )));
                }
                if let Some(d) = &a.external_ui {
                    if !d.is_dir() {
                        return Err(Error::Config(format!(
                            "api: external_ui {} — нет такой папки (положите туда файлы \
                             панели: yacd, metacubexd, zashboard)",
                            d.display()
                        )));
                    }
                }
                Some((a.clone(), token))
            }
            None => None,
        };
        Ok(App {
            inbounds,
            core,
            routers,
            tracker,
            config: cfg.clone(),
            api,
        })
    }

    /// Открыть все входы и начать принимать соединения.
    pub async fn start(self) -> Result<Running> {
        crate::transport::tcp_tls::ensure_crypto_provider();
        let App {
            inbounds: built,
            core,
            routers,
            tracker,
            config,
            api,
        } = self;
        let Core {
            dns,
            pinned_hosts,
            groups,
            mut subs,
        } = core;
        let (errors_tx, errors_rx) = mpsc::unbounded_channel();
        let mut listen_addrs = Vec::new();
        let mut inbounds = Vec::new();
        let mut live = Vec::new();
        let mut routes = Vec::new();
        let mut tun_resolver = false;
        for i in built {
            if let InboundSvc::Tun(t) = &i.svc {
                let dev = t.create_device()?;
                tracing::info!(inbound = %t.tag, interface = %dev.name, "TUN создан");
                if t.settings.auto_route {
                    // Пока системный DNS ещё работает напрямую: загрузить
                    // подписки без сохранённого списка и узнать адреса
                    // всех серверов.
                    for (sub, loaded) in &mut subs {
                        if !*loaded {
                            match sub.update(true).await {
                                Ok(_) => *loaded = true,
                                Err(e) => {
                                    tracing::warn!(subscription = %sub.cfg.tag, error = %e, "подписка: не загрузилась до включения TUN")
                                }
                            }
                        }
                    }
                    let mut hosts = pinned_hosts.clone();
                    for g in &groups {
                        hosts.extend(g.members().iter().filter_map(|m| m.out.server()));
                    }
                    hosts.sort();
                    hosts.dedup();
                    pre_resolve(hosts).await;
                    routes.push(tun::route::setup(
                        &dev.name,
                        dev.if_index,
                        dev.has_v6,
                        &t.settings.route_exclude,
                        t.settings.strict_route,
                    )?);
                    if dns.is_some() {
                        // Новые имена (серверы из обновлённой подписки) —
                        // у своего DNS, а не у системы: её запросы теперь
                        // идут через TUN и могли бы получить fake-IP.
                        // DNS — текущий (после перечитывания настроек —
                        // новый).
                        let r = Arc::downgrade(&routers);
                        crate::transport::tcp_tls::set_tun_resolver(Some(Arc::new(
                            move |host: String| {
                                let r = r.clone();
                                Box::pin(async move {
                                    let d = r
                                        .upgrade()
                                        .and_then(|r| r.get().dns().cloned())
                                        .ok_or_else(|| Error::Protocol("DNS остановлен".into()))?;
                                    d.lookup(&host).await
                                })
                                    as futures_util::future::BoxFuture<'static, _>
                            },
                        )));
                        tun_resolver = true;
                    }
                }
                let task = spawn_task(&errors_tx, t.clone().serve(dev, routers.clone()));
                inbounds.push((i.tag.clone(), i.kind, SocketAddr::from(([0, 0, 0, 0], 0))));
                live.push(Live {
                    key: i.key,
                    tag: i.tag,
                    kind: i.kind,
                    addr: None,
                    tasks: vec![task],
                });
                continue;
            }
            let l = start_listener(i, &routers, &errors_tx).await?;
            let addr = l.addr.expect("у входа есть адрес");
            listen_addrs.push(addr);
            inbounds.push((l.tag.clone(), l.kind, addr));
            live.push(l);
        }
        let core_tasks = spawn_core(dns.as_ref(), &groups, subs.clone(), &errors_tx);
        let ctl = Arc::new(Controller {
            routers,
            tracker: tracker.clone(),
            state: std::sync::Mutex::new(State {
                config,
                dns,
                core_tasks,
                inbounds: live,
            }),
            groups: std::sync::RwLock::new(groups),
            subs: std::sync::RwLock::new(subs.into_iter().map(|(s, _)| s).collect()),
            config_path: std::sync::RwLock::new(None),
            reload_lock: tokio::sync::Mutex::new(()),
            errors: errors_tx.clone(),
        });
        let (api_addr, api_task) = match api {
            Some((cfg, token)) => {
                if let Some(m) = cfg.default_mode {
                    tracker.set_mode(m);
                }
                let l = TcpListener::bind(cfg.listen).await.map_err(|e| {
                    Error::Config(format!("api: не удалось слушать {}: {e}", cfg.listen))
                })?;
                let addr = l.local_addr()?;
                let a = api::Api::new(&cfg, token, tracker, ctl.clone())?;
                tracing::info!(addr = %addr, "API слушает");
                (Some(addr), Some(spawn_task(&errors_tx, a.serve(l))))
            }
            None => (None, None),
        };
        Ok(Running {
            listen_addrs,
            inbounds,
            api_addr,
            ctl,
            errors: errors_rx,
            api_task,
            routes,
            tun_resolver,
        })
    }
}

impl Controller {
    pub fn group(&self, tag: &str) -> Option<Arc<Group>> {
        self.groups
            .read()
            .unwrap()
            .iter()
            .find(|g| g.tag() == tag)
            .cloned()
    }

    /// Перечитать файл настроек, заданный `Running::set_config_path`.
    pub async fn reload_from_file(&self) -> Result<Vec<String>> {
        let path = self.config_path.read().unwrap().clone().ok_or_else(|| {
            Error::Config("настройки заданы не файлом — перечитывать нечего".into())
        })?;
        let cfg = Config::load(&path)?;
        self.reload(cfg).await
    }

    /// Применить новые настройки: новые выходы, правила, DNS, группы и
    /// подписки — сразу для новых соединений; открытые соединения живут
    /// со старыми. Входы перезапускаются, только если их настройки
    /// изменились. Ошибка в настройках — ничего не меняется.
    pub async fn reload(&self, new: Config) -> Result<Vec<String>> {
        let _one = self.reload_lock.lock().await;
        let tags = inbound_tags(&new)?;
        let (old_dns, old_api) = {
            let st = self.state.lock().unwrap();
            (st.dns.clone(), st.config.api.clone())
        };
        if let Some(d) = &old_dns {
            d.save();
        }
        let (router, core) = build_core(&new, &tags, self.tracker.clone(), old_dns.as_ref())?;
        let built = build_inbounds(&new, &tags, core.dns.as_ref(), &self.routers)?;
        let mut notes = Vec::new();
        if new.api != old_api {
            notes.push("api: изменения вступят в силу после перезапуска".to_string());
        }

        // Дальше ошибок настроек уже нет — применяем.
        self.routers.set(Arc::new(router));
        let Core {
            dns,
            pinned_hosts,
            groups,
            subs,
        } = core;
        // Выбор в группах (в том числе GLOBAL) переживает перечитывание.
        for (old, new) in self.groups.read().unwrap().iter().flat_map(|o| {
            groups
                .iter()
                .filter(move |n| n.tag() == o.tag())
                .map(move |n| (o, n))
        }) {
            if let Some(t) = old.chosen() {
                new.restore(&t);
            }
        }
        let core_tasks = spawn_core(dns.as_ref(), &groups, subs.clone(), &self.errors);
        *self.groups.write().unwrap() = groups.clone();
        *self.subs.write().unwrap() = subs.into_iter().map(|(s, _)| s).collect();

        // Входы: остановить исчезнувшие и изменившиеся, открыть новые.
        let new_keys: Vec<String> = built.iter().map(|b| b.key.clone()).collect();
        let to_start: Vec<BuiltInbound> = {
            let mut st = self.state.lock().unwrap();
            for t in std::mem::replace(&mut st.core_tasks, core_tasks) {
                t.abort();
            }
            st.dns = dns;
            st.config = new;
            let old_tun = st
                .inbounds
                .iter()
                .find(|l| l.kind == InboundKind::Tun)
                .map(|l| l.key.clone());
            let new_tun = built
                .iter()
                .find(|b| b.kind == InboundKind::Tun)
                .map(|b| b.key.clone());
            if old_tun != new_tun {
                notes.push("tun: изменения входа TUN вступят в силу после перезапуска".to_string());
            }
            let mut kept = Vec::new();
            for l in std::mem::take(&mut st.inbounds) {
                if l.kind == InboundKind::Tun || new_keys.contains(&l.key) {
                    kept.push(l);
                } else {
                    tracing::info!(inbound = %l.tag, "вход остановлен (настройки изменились)");
                    for t in &l.tasks {
                        t.abort();
                    }
                }
            }
            st.inbounds = kept;
            let running: Vec<String> = st.inbounds.iter().map(|l| l.key.clone()).collect();
            built
                .into_iter()
                .filter(|b| b.kind != InboundKind::Tun && !running.contains(&b.key))
                .collect()
        };
        for b in to_start {
            let tag = b.tag.clone();
            // Порт мог ещё не освободиться после остановки старого входа.
            let mut res = None;
            for _ in 0..20 {
                let attempt = BuiltInbound {
                    listen: b.listen,
                    tag: b.tag.clone(),
                    kind: b.kind,
                    svc: match &b.svc {
                        InboundSvc::Proxy(p) => InboundSvc::Proxy(p.clone()),
                        InboundSvc::Dns(d) => InboundSvc::Dns(d.clone()),
                        InboundSvc::Tun(t) => InboundSvc::Tun(t.clone()),
                    },
                    key: b.key.clone(),
                };
                match start_listener(attempt, &self.routers, &self.errors).await {
                    Ok(l) => {
                        res = Some(Ok(l));
                        break;
                    }
                    Err(e) => {
                        res = Some(Err(e));
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
            match res.expect("хотя бы одна попытка") {
                Ok(l) => self.state.lock().unwrap().inbounds.push(l),
                Err(e) => notes.push(format!("вход {tag}: {e}")),
            }
        }
        if crate::net_protect::tun_active() {
            // С TUN адреса новых серверов — заранее, в фоне.
            let mut hosts = pinned_hosts;
            for g in &groups {
                hosts.extend(g.members().iter().filter_map(|m| m.out.server()));
            }
            tokio::spawn(pre_resolve(hosts));
        }
        tracing::info!(notes = notes.len(), "настройки перечитаны");
        self.tracker.events.emit(|| events::Event::Reload {
            notes: notes.clone(),
        });
        Ok(notes)
    }
}

impl api::Control for Controller {
    fn groups(&self) -> serde_json::Value {
        let groups = self.groups.read().unwrap().clone();
        let list: Vec<serde_json::Value> = groups
            .iter()
            .map(|g| {
                serde_json::json!({
                    "tag": g.tag(),
                    "type": match g.strategy() {
                        Strategy::Selector => "selector",
                        Strategy::UrlTest => "urltest",
                        Strategy::Fallback => "fallback",
                    },
                    "current": g.current(),
                    "members": g.members().iter().map(|m| serde_json::json!({
                        "tag": m.tag(),
                        "delay_ms": m.delay().map(|d| d.as_millis() as u64),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        serde_json::json!({ "groups": list })
    }

    fn select(&self, group: &str, member: &str) -> Result<()> {
        let g = self
            .group(group)
            .ok_or_else(|| Error::Config(format!("нет группы «{group}»")))?;
        if g.strategy() != Strategy::Selector {
            return Err(Error::Config(format!(
                "группа {group} выбирает сама (urltest/fallback) — вручную только selector"
            )));
        }
        g.select(member)
    }

    fn check(&self, group: &str) -> futures_util::future::BoxFuture<'_, Result<()>> {
        let g = self.group(group);
        let name = group.to_string();
        Box::pin(async move {
            let g = g.ok_or_else(|| Error::Config(format!("нет группы «{name}»")))?;
            g.check_all().await;
            Ok(())
        })
    }

    fn update_subscription(&self, tag: &str) -> futures_util::future::BoxFuture<'_, Result<usize>> {
        let s = self
            .subs
            .read()
            .unwrap()
            .iter()
            .find(|s| s.cfg.tag == tag)
            .cloned();
        let name = tag.to_string();
        Box::pin(async move {
            let s = s.ok_or_else(|| Error::Config(format!("нет подписки «{name}»")))?;
            s.update(false).await
        })
    }

    fn reload(&self) -> futures_util::future::BoxFuture<'_, Result<Vec<String>>> {
        Box::pin(self.reload_from_file())
    }

    fn proxies(&self) -> serde_json::Value {
        self.clash_proxies()
    }

    fn clash_groups(&self) -> serde_json::Value {
        Controller::clash_groups(self)
    }

    fn delay<'a>(
        &'a self,
        name: &'a str,
        url: &'a str,
        timeout: std::time::Duration,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<u64>>> {
        Box::pin(self.clash_delay(name, url, timeout))
    }

    fn group_delay<'a>(
        &'a self,
        name: &'a str,
        url: &'a str,
        timeout: std::time::Duration,
    ) -> futures_util::future::BoxFuture<'a, Result<serde_json::Value>> {
        Box::pin(self.clash_group_delay(name, url, timeout))
    }

    fn rules(&self) -> serde_json::Value {
        self.clash_rules()
    }

    fn configs(&self) -> serde_json::Value {
        self.clash_configs()
    }

    fn providers(&self) -> serde_json::Value {
        self.clash_providers()
    }

    fn provider_check<'a>(
        &'a self,
        name: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<()>> {
        Box::pin(self.clash_provider_check(name))
    }

    fn dns_query<'a>(
        &'a self,
        name: &'a str,
        qtype: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<serde_json::Value>> {
        Box::pin(self.clash_dns_query(name, qtype))
    }
}

/// Узнать адреса серверов заранее (по 16 одновременно).
async fn pre_resolve(hosts: Vec<(String, u16)>) {
    use futures_util::StreamExt;
    futures_util::stream::iter(hosts)
        .for_each_concurrent(16, |(h, p)| async move {
            if let Err(e) = crate::transport::tcp_tls::resolve_server(&h, p).await {
                tracing::warn!(host = %h, error = %e, "tun: имя сервера не разрешилось заранее");
            }
        })
        .await;
}
