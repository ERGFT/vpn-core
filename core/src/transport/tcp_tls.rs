// SPDX-License-Identifier: GPL-3.0-or-later
//! Общий TCP/TLS/REALITY транспорт. VLESS поверх него дополнительно
//! открывается отдельной функцией и может использовать XTLS Vision.
//!
//! ClientHello в обоих TLS-путях — как у Chrome 133
//! (`fingerprint::chrome_profile`): порядок cipher suites, GREASE, набор
//! расширений и их значения; для REALITY совпадает и JA4.

use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::fingerprint::CaptureFirstBytes;
use crate::reality::{RealityCertVerifier, RealityHook};
use crate::transport::raw::RawConn;
use crate::transport::{Security, TransportConfig};
use crate::vless::protocol::{
    encode_request_with_flow, vless_connect, Address, Command, VlessStream,
};
use crate::vless::vision::VisionStream;
use crate::vless::Flow;

pub type TlsBoxedStream = TlsStream<RawConn>;
/// TLS-поток поверх обёртки, которая параллельно запоминает первые
/// байты, записанные в сокет (Этап 3 — снятие собственного ClientHello).
pub type CapturingTlsStream = TlsStream<CaptureFirstBytes<TcpStream>>;

/// ClientHello почти всегда укладывается в несколько сотен-полторы
/// тысяч байт даже с большим набором расширений; 4 КБ — щедрый запас,
/// с которым точно не обрежем реальный ClientHello.
const CLIENT_HELLO_CAPTURE_CAP: usize = 4096;

/// Таймауты сетевых операций. Без них соединение с сервером, который
/// принял TCP, но молчит (частый случай при блокировках или просто
/// зависший сервер), висело бы вечно: задача и её буферы не
/// освобождались бы никогда.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Интервал Happy Eyeballs между попытками подключения к разным адресам.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
/// Ограничиваем одновременно открытые сокеты и число адресов из одного DNS-ответа.
const MAX_PARALLEL_CONNECTS: usize = 2;
const MAX_CONNECT_ATTEMPTS: usize = 8;
/// Отдельно на TLS-рукопожатие: сервер может принять TCP и молчать —
/// таймаут TCP тут уже не поможет, соединение-то установлено.
/// Поймано тестом `core/tests/connect_robustness.rs`: до этого клиент
/// висел на таком сервере неограниченно долго.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Обёртка таймаута вокруг TLS-рукопожатия с понятной ошибкой.
async fn with_handshake_timeout<T>(
    what: &str,
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Error::Io(e)),
        Err(_) => Err(Error::Protocol(format!(
            "{what}: сервер не завершил TLS-рукопожатие за {} с",
            HANDSHAKE_TIMEOUT.as_secs()
        ))),
    }
}

static CRYPTO_INIT: Once = Once::new();

/// rustls 0.23 требует явно выбранного crypto-провайдера, если в бинаре
/// скомпилирован больше чем один backend. Вызывать один раз при старте
/// процесса (и в каждом тесте, который поднимает TLS) — повторные вызовы
/// безопасны и no-op.
pub fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let provider = rustls::crypto::aws_lc_rs::default_provider();

        // Прогрев генератора случайных чисел (найдено замерами Этапа 8).
        // aws-lc засевает свой ГСЧ лениво, при первом запросе случайных
        // байт, и этот засев стоит ~28 мс на процесс. Без прогрева он
        // приходился на ПЕРВОЕ соединение пользователя: оно занимало
        // ~36 мс против ~2 мс у всех последующих (у Xray-core первое
        // соединение — 1,6 мс, отсюда и было отставание в 6-21 раз).
        // Один запрос здесь переносит эту разовую цену на старт
        // процесса, где её никто не ждёт. Байты нужны только ради
        // побочного эффекта — засева, сами они никуда не идут.
        let mut warmup = [0u8; 32];
        let _ = provider.secure_random.fill(&mut warmup);

        let _ = provider.install_default();
    });
}

fn default_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

async fn connect_tcp_stream(cfg: &TransportConfig) -> Result<TcpStream> {
    let addrs = resolve_server(&cfg.host, cfg.port)
        .await
        .map_err(|e| server_error(&cfg.host, e))?;
    connect_addrs(&addrs, &cfg.host)
        .await
        .map_err(|e| server_error(&cfg.host, e))
}

/// Ошибка соединения с самим сервером — с его именем: оно и так в журнале
/// при запуске, а без него не понять, к какому серверу не подключились.
/// Ошибки [`resolve_host`] и [`connect_addrs`] адреса не содержат: те же
/// функции соединяют и с сайтами (`direct`), а адреса сайтов в журнал
/// уровня info не пишутся.
pub(crate) fn server_error(host: &str, e: Error) -> Error {
    Error::Protocol(format!("сервер {host}: {e}"))
}

/// Сколько помнить адреса VLESS-сервера и сколько ещё пользоваться ими,
/// если DNS временно не отвечает.
const SERVER_CACHE_FRESH: Duration = Duration::from_secs(120);
const SERVER_CACHE_STALE: Duration = Duration::from_secs(3600);

type ServerCache =
    std::sync::Mutex<std::collections::HashMap<String, (Vec<SocketAddr>, std::time::Instant)>>;

fn server_cache() -> &'static ServerCache {
    static C: std::sync::OnceLock<ServerCache> = std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

fn refreshing() -> &'static std::sync::Mutex<std::collections::HashSet<(u64, String)>> {
    static R: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        std::sync::OnceLock::new();
    R.get_or_init(Default::default)
}

fn server_cache_generation() -> &'static AtomicU64 {
    static G: AtomicU64 = AtomicU64::new(0);
    &G
}

/// Invalidate cached upstream IPs when the host reports a network change.
/// The generation also prevents a DNS request started on the old network
/// from repopulating the cache after invalidation.
pub fn network_changed() {
    let mut cache = server_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    server_cache_generation().fetch_add(1, Ordering::AcqRel);
    cache.clear();
    drop(cache);
    refreshing()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

/// Разрешение имён, пока включён TUN: системный резолвер тогда сам идёт
/// через TUN (и мог бы получить fake-IP), поэтому имена спрашиваются у
/// DNS-модуля клиента напрямую.
pub type HostResolver = dyn Fn(String) -> futures_util::future::BoxFuture<'static, Result<Vec<std::net::IpAddr>>>
    + Send
    + Sync;

fn tun_resolver() -> &'static std::sync::RwLock<Option<Arc<HostResolver>>> {
    static R: std::sync::OnceLock<std::sync::RwLock<Option<Arc<HostResolver>>>> =
        std::sync::OnceLock::new();
    R.get_or_init(Default::default)
}

/// Задать (или снять) резолвер для режима TUN.
pub fn set_tun_resolver(r: Option<Arc<HostResolver>>) {
    *tun_resolver()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = r;
}

/// Адреса VLESS-сервера с кешем: не спрашивать DNS на каждое соединение,
/// а при сбое DNS — продолжать работать по последним известным адресам.
/// Имя сервера всегда разрешается напрямую, системным резолвером: чтобы
/// узнать адрес сервера через сам сервер, пришлось бы уже быть к нему
/// подключённым.
pub async fn resolve_server(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let key = format!("{host}:{port}");
    loop {
        let generation = server_cache_generation().load(Ordering::Acquire);
        let cached = server_cache()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned();
        if server_cache_generation().load(Ordering::Acquire) != generation {
            continue;
        }
        if let Some((addrs, at)) = &cached {
            if at.elapsed() < SERVER_CACHE_FRESH {
                return Ok(addrs.clone());
            }
            // С TUN системный DNS сам идёт через клиент (и, возможно, через
            // этот же сервер): ждать его здесь — петля. Отдаём прежние адреса,
            // а обновляем в фоне.
            if crate::net_protect::tun_active() {
                let refresh_key = (generation, key.clone());
                // Одно обновление на имя и поколение сети: запрос DNS,
                // идущий к этому же серверу, не запустит бесконечный цикл.
                if refreshing()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(refresh_key.clone())
                {
                    let (h, k) = (host.to_string(), key.clone());
                    tokio::spawn(async move {
                        if let Ok(a) = resolve_host(&h, port).await {
                            let mut cache = server_cache()
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if server_cache_generation().load(Ordering::Acquire) == generation {
                                cache.insert(k.clone(), (a, std::time::Instant::now()));
                            }
                        }
                        refreshing()
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .remove(&refresh_key);
                    });
                }
                if server_cache_generation().load(Ordering::Acquire) == generation {
                    return Ok(addrs.clone());
                }
                continue;
            }
        }
        match resolve_host(host, port).await {
            Ok(addrs) => {
                if server_cache_generation().load(Ordering::Acquire) != generation {
                    continue;
                }
                let mut c = server_cache()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if server_cache_generation().load(Ordering::Acquire) != generation {
                    continue;
                }
                if c.len() > 64 {
                    c.clear();
                }
                c.insert(key.clone(), (addrs.clone(), std::time::Instant::now()));
                return Ok(addrs);
            }
            Err(e) => {
                if server_cache_generation().load(Ordering::Acquire) != generation {
                    continue;
                }
                match cached {
                    Some((addrs, at)) if at.elapsed() < SERVER_CACHE_STALE => {
                        tracing::warn!(host, error = %e, "DNS не ответил — использую прежние адреса сервера");
                        return Ok(addrs);
                    }
                    _ => return Err(e),
                }
            }
        }
    }
}

/// Разрешить имя системным резолвером (асинхронно, с таймаутом).
pub async fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    // Последний рубеж перед getaddrinfo: `2130706433` он прочтёт как IPv4.
    if crate::hostname::looks_like_legacy_ipv4(host) {
        return Err(Error::Protocol(
            "числовое имя, не являющееся IPv4-адресом".into(),
        ));
    }
    if crate::net_protect::tun_active() {
        let r = tun_resolver()
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(r) = r {
            let ips = tokio::time::timeout(DNS_TIMEOUT, r(host.to_string()))
                .await
                .map_err(|_| {
                    tracing::debug!(%host, "DNS: таймаут разрешения имени");
                    Error::Protocol(format!(
                        "не удалось разрешить имя за {} с",
                        DNS_TIMEOUT.as_secs()
                    ))
                })??;
            return Ok(ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect());
        }
    }
    let addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    // Асинхронное разрешение имени: раньше здесь был блокирующий
    // `to_socket_addrs`, вызванный прямо из async-кода. Рабочих потоков
    // у tokio по числу ядер (на слабой машине — два), и один медленный
    // ответ DNS останавливал обработку ВСЕХ соединений, а не только
    // своего. `lookup_host` уносит это в отдельный пул.
    let addrs: Vec<SocketAddr> = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(&addr))
        .await
        .map_err(|_| {
            tracing::debug!(%addr, "DNS: таймаут разрешения имени");
            Error::Protocol(format!(
                "не удалось разрешить имя за {} с",
                DNS_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| {
            tracing::debug!(%addr, error = %e, "DNS: имя не разрешилось");
            Error::Protocol(format!("не удалось разрешить имя: {e}"))
        })?
        .collect();

    if addrs.is_empty() {
        tracing::debug!(%addr, "DNS: имя не дало ни одного адреса");
        return Err(Error::Protocol("имя не разрешилось ни в один адрес".into()));
    }
    Ok(addrs)
}

/// TCP-соединение с `host:port`: разрешение имени системным резолвером и
/// параллельный перебор адресов по принципу Happy Eyeballs.
pub async fn connect_host(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = resolve_host(host, port).await?;
    connect_addrs(&addrs, host).await
}

/// Подключиться к первому ответившему адресу. Семейства чередуются в
/// порядке первого адреса DNS-ответа; следующая попытка стартует через
/// 250 мс, а отказ предыдущей запускает следующую сразу. Одновременно
/// выполняется не больше двух попыток, общий предел — 10 секунд.
pub async fn connect_addrs(addrs: &[SocketAddr], what: &str) -> Result<TcpStream> {
    connect_addrs_with(addrs, what, |sa| async move {
        crate::net_protect::tcp_socket(&sa)?.connect(sa).await
    })
    .await
}

fn interleave_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut v4 = VecDeque::new();
    let mut v6 = VecDeque::new();
    for sa in addrs {
        match sa {
            SocketAddr::V4(_) if v4.len() < MAX_CONNECT_ATTEMPTS && !v4.contains(sa) => {
                v4.push_back(*sa)
            }
            SocketAddr::V6(_) if v6.len() < MAX_CONNECT_ATTEMPTS && !v6.contains(sa) => {
                v6.push_back(*sa)
            }
            _ => {}
        }
    }

    let first_is_v6 = matches!(addrs.first(), Some(SocketAddr::V6(_)));
    let (mut first, mut second) = if first_is_v6 { (v6, v4) } else { (v4, v6) };
    let mut ordered = Vec::with_capacity(first.len() + second.len());
    let mut take_first = true;
    while !first.is_empty() || !second.is_empty() {
        let source = if (take_first && !first.is_empty()) || second.is_empty() {
            &mut first
        } else {
            &mut second
        };
        if let Some(sa) = source.pop_front() {
            ordered.push(sa);
        }
        take_first = !take_first;
    }
    ordered.truncate(MAX_CONNECT_ATTEMPTS);
    ordered
}

async fn connect_attempt<T, F, Fut>(
    connect: &F,
    sa: SocketAddr,
) -> (SocketAddr, std::result::Result<T, Error>)
where
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: Future<Output = std::io::Result<T>> + Send,
    T: Send,
{
    let result = match tokio::time::timeout(CONNECT_TIMEOUT, connect(sa)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(Error::Io(error)),
        Err(_) => Err(Error::Protocol(format!(
            "таймаут подключения ({} с)",
            CONNECT_TIMEOUT.as_secs()
        ))),
    };
    (sa, result)
}

async fn connect_addrs_with<T, F, Fut>(addrs: &[SocketAddr], what: &str, connect: F) -> Result<T>
where
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: Future<Output = std::io::Result<T>> + Send,
    T: Send,
{
    let candidates = interleave_addrs(addrs);
    if candidates.is_empty() {
        return Err(Error::Protocol(
            "не удалось подключиться ни к одному адресу".into(),
        ));
    }

    let started = tokio::time::Instant::now();
    let deadline = started + CONNECT_TIMEOUT;
    let mut next_start = started + HAPPY_EYEBALLS_DELAY;
    let mut next_candidate = 1;
    let mut last_error = None;
    let mut attempts = FuturesUnordered::new();
    attempts.push(connect_attempt(&connect, candidates[0]));

    loop {
        if attempts.is_empty() && next_candidate == candidates.len() {
            tracing::debug!(%what, "не удалось подключиться ни к одному адресу");
            return Err(last_error.unwrap_or_else(|| {
                Error::Protocol("не удалось подключиться ни к одному адресу".into())
            }));
        }

        if attempts.is_empty() && next_candidate < candidates.len() {
            attempts.push(connect_attempt(&connect, candidates[next_candidate]));
            next_candidate += 1;
            next_start = tokio::time::Instant::now() + HAPPY_EYEBALLS_DELAY;
            continue;
        }

        if next_candidate < candidates.len()
            && attempts.len() < MAX_PARALLEL_CONNECTS
            && tokio::time::Instant::now() >= next_start
        {
            attempts.push(connect_attempt(&connect, candidates[next_candidate]));
            next_candidate += 1;
            next_start = tokio::time::Instant::now() + HAPPY_EYEBALLS_DELAY;
            continue;
        }

        tokio::select! {
            Some((sa, result)) = attempts.next() => {
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => {
                        tracing::debug!(%sa, error = %error, "адрес не подошёл");
                        last_error = Some(error);
                        // Ошибка освобождает слот; следующую попытку можно начать сразу.
                        next_start = tokio::time::Instant::now();
                    }
                }
            }
            _ = tokio::time::sleep_until(next_start),
                if next_candidate < candidates.len() && attempts.len() < MAX_PARALLEL_CONNECTS => {}
            _ = tokio::time::sleep_until(deadline) => {
                tracing::debug!(%what, "превышен общий таймаут подключения");
                return Err(Error::Protocol(format!(
                    "таймаут подключения ({} с)",
                    CONNECT_TIMEOUT.as_secs()
                )));
            }
        }
    }
}

async fn connect_tcp(cfg: &TransportConfig) -> Result<RawConn> {
    Ok(RawConn::new(connect_tcp_stream(cfg).await?).with_fragment(cfg.fragment.clone()))
}

fn build_client_config(
    roots: RootCertStore,
    alpn: Vec<Vec<u8>>,
    browser: crate::fingerprint::Browser,
) -> ClientConfig {
    // ClientHello как у браузера `browser` (по умолчанию Chrome): порядок
    // cipher suites задаёт провайдер, остальное — профиль (см.
    // `fingerprint::profiles`). Провайдер — тот же aws-lc-rs, только с
    // переставленным `cipher_suites`, поэтому
    // `with_safe_default_protocol_versions()` не может провалиться.
    let provider = crate::fingerprint::profiles::order_cipher_suites(
        rustls::crypto::aws_lc_rs::default_provider(),
        browser,
    );
    #[allow(
        clippy::expect_used,
        reason = "инвариант: набор шифров провайдера aws-lc-rs непуст"
    )]
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("переупорядочивание cipher_suites не может сделать набор suite'ов непригодным")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    crate::fingerprint::profiles::apply(&mut config, browser, false);
    config
}

/// TLS поверх уже открытого потока (DNS over TLS/HTTPS, в том числе через
/// выход-прокси): ClientHello как у Chrome, проверка цепочки по `roots`
/// (или по встроенному набору) и имени `server_name` (домен или IP).
pub async fn tls_over<S>(
    stream: S,
    server_name: &str,
    roots: Option<RootCertStore>,
    alpn: Vec<Vec<u8>>,
) -> Result<TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    ensure_crypto_provider();
    let config = build_client_config(
        roots.unwrap_or_else(default_root_store),
        alpn,
        crate::fingerprint::Browser::Chrome,
    );
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(server_name.to_string()).map_err(Error::InvalidDnsName)?;
    with_handshake_timeout("TLS", connector.connect(name, stream)).await
}

/// Набор доверенных корней для обычного TLS: заданный пользователем
/// (`--ca`, см. [`TransportConfig::ca_roots`]) или встроенный публичный.
fn roots_for(cfg: &TransportConfig) -> RootCertStore {
    match &cfg.ca_roots {
        Some(r) => (**r).clone(),
        None => default_root_store(),
    }
}

async fn connect_tls_inner(
    cfg: &TransportConfig,
    roots: RootCertStore,
    alpn: Vec<Vec<u8>>,
    record_aligned: bool,
) -> Result<TlsBoxedStream> {
    ensure_crypto_provider();

    let mut tcp = connect_tcp(cfg).await?;
    tcp.set_record_aligned(record_aligned);
    let config = build_client_config(roots, alpn, cfg.browser);
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(cfg.tls_server_name().to_string()).map_err(Error::InvalidDnsName)?;

    let tls = with_handshake_timeout("TLS", connector.connect(server_name, tcp)).await?;
    Ok(tls)
}

/// Поднять TCP+TLS до `cfg.host:cfg.port` с SNI = `cfg.effective_sni()`,
/// проверяя цепочку сертификатов по переданному набору корней и заявляя
/// переданный список ALPN-протоколов (пусто — ALPN не отправляется).
///
/// Вынесено отдельно от [`connect_tls`], чтобы тесты могли передать
/// набор корней, где доверенным является только тестовый
/// self-signed сертификат — без ослабления проверки в продакшен-пути.
pub async fn connect_tls_with_roots_alpn(
    cfg: &TransportConfig,
    roots: RootCertStore,
    alpn: Vec<Vec<u8>>,
) -> Result<TlsBoxedStream> {
    connect_tls_inner(cfg, roots, alpn, false).await
}

/// Как [`connect_tls_with_roots_alpn`], но без ALPN.
pub async fn connect_tls_with_roots(
    cfg: &TransportConfig,
    roots: RootCertStore,
) -> Result<TlsBoxedStream> {
    connect_tls_with_roots_alpn(cfg, roots, Vec::new()).await
}

/// Поднять TCP+TLS до `cfg.host:cfg.port` с SNI = `cfg.effective_sni()`,
/// доверяя встроенному набору публичных корней (webpki-roots) или
/// заданному через `--ca`.
pub async fn connect_tls(cfg: &TransportConfig) -> Result<TlsBoxedStream> {
    connect_tls_with_roots(cfg, roots_for(cfg)).await
}

/// Как [`connect_tls`], но с ALPN.
pub async fn connect_tls_with_alpn(
    cfg: &TransportConfig,
    alpn: Vec<Vec<u8>>,
) -> Result<TlsBoxedStream> {
    connect_tls_with_roots_alpn(cfg, roots_for(cfg), alpn).await
}

/// Поднять TCP+TLS как [`connect_tls`], но обернуть сокет так, чтобы
/// запомнить сырые байты отправленного ClientHello — Этап 3, "сверка":
/// посмотреть, какой TLS-отпечаток этот клиент реально отправляет прямо
/// сейчас (см. `crate::fingerprint`).
pub async fn connect_tls_capturing_client_hello(
    cfg: &TransportConfig,
) -> Result<(CapturingTlsStream, Vec<u8>)> {
    ensure_crypto_provider();

    let tcp = connect_tcp_stream(cfg).await?;
    let captured_tcp = CaptureFirstBytes::new(tcp, CLIENT_HELLO_CAPTURE_CAP);

    let config = build_client_config(roots_for(cfg), default_alpn(cfg), cfg.browser);
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(cfg.tls_server_name().to_string()).map_err(Error::InvalidDnsName)?;

    let tls = with_handshake_timeout("TLS", connector.connect(server_name, captured_tcp)).await?;
    let captured = tls.get_ref().0.captured().to_vec();
    Ok((tls, captured))
}

/// Конфиг rustls для REALITY: только TLS 1.3, проверка сертификата —
/// HMAC REALITY (и ML-DSA-65, если в ссылке есть `pqv=`), ClientHello —
/// как у Chrome, включая заявленные, но не реализованные legacy
/// cipher suite'ы (для REALITY сервер выбрать их не может в принципе —
/// только TLS 1.3; см. `fingerprint::chrome_profile`).
pub fn reality_client_config(
    reality: &crate::transport::RealityParams,
    alpn: Vec<Vec<u8>>,
) -> Result<ClientConfig> {
    Ok(reality_client_config_inner(reality, alpn, None, crate::fingerprint::Browser::Chrome)?.0)
}

/// Сборка конфига REALITY. `browser_fallback` — корни для обычной
/// проверки X.509: с ними настоящий сертификат сайта не рвёт рукопожатие
/// (см. `transport::browser_mimic`), и тогда вызывающий код ОБЯЗАН
/// проверить `hook.is_verified()` до любой отправки своих данных.
/// Поэтому этот вариант не публичный: снаружи доступен только строгий
/// [`reality_client_config`].
fn reality_client_config_inner(
    reality: &crate::transport::RealityParams,
    alpn: Vec<Vec<u8>>,
    browser_fallback: Option<RootCertStore>,
    browser: crate::fingerprint::Browser,
) -> Result<(ClientConfig, Arc<RealityHook>)> {
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let hook = Arc::new(RealityHook::new(
        &reality.public_key,
        &reality.short_id,
        &mut rng,
    ));
    let mut verifier = RealityCertVerifier::from_hook(hook.clone()).map_err(|e| {
        Error::Protocol(format!(
            "REALITY: не удалось создать верификатор сертификата: {e}"
        ))
    })?;
    if let Some(pk) = &reality.mldsa65_verify {
        verifier = verifier.with_mldsa65(pk.clone());
    }
    if let Some(roots) = browser_fallback {
        verifier = verifier.with_browser_fallback(roots)?;
    }

    let provider = crate::fingerprint::profiles::order_cipher_suites(
        rustls::crypto::aws_lc_rs::default_provider(),
        browser,
    );
    #[allow(
        clippy::expect_used,
        reason = "инвариант: набор шифров провайдера aws-lc-rs непуст"
    )]
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("переупорядочивание cipher_suites не может сделать TLS1.3 непригодным")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.reality = Some(hook.clone());
    config.alpn_protocols = alpn;
    // Без возобновления сессий, как у Xray (`SessionTicketsDisabled`):
    // возобновлённое рукопожатие не показывает сертификат, и проверка
    // REALITY была бы пропущена. Конфиг и так одноразовый, это страховка.
    // На ClientHello не влияет (psk_key_exchange_modes уходит всегда).
    config.resumption = rustls::client::Resumption::disabled();
    crate::fingerprint::profiles::apply(&mut config, browser, true);
    Ok((config, hook))
}

async fn connect_tls_reality_inner(
    cfg: &TransportConfig,
    reality: &crate::transport::RealityParams,
    alpn: Vec<Vec<u8>>,
    record_aligned: bool,
) -> Result<TlsBoxedStream> {
    ensure_crypto_provider();

    let mut tcp = connect_tcp(cfg).await?;
    tcp.set_record_aligned(record_aligned);
    let (config, hook) =
        reality_client_config_inner(reality, alpn, Some(roots_for(cfg)), cfg.browser)?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(cfg.tls_server_name().to_string()).map_err(Error::InvalidDnsName)?;

    let tls = with_handshake_timeout("REALITY", connector.connect(server_name, tcp)).await?;
    // Единственная точка, через которую REALITY-соединение попадает к
    // VLESS: не прошедшее проверку соединение отсюда не выходит никогда.
    if !hook.is_verified() {
        crate::transport::browser_mimic::visit_in_background(
            tls,
            cfg.effective_sni().to_string(),
            cfg.browser,
        );
        return Err(Error::Protocol(
            "REALITY: вместо сервера ответил настоящий сайт (подмена соединения или \
             неверный pbk=/sni=); данные VLESS не отправлялись"
                .into(),
        ));
    }
    Ok(tls)
}

/// Поднять TCP+TLS до `cfg.host:cfg.port` с REALITY-аутентификацией
/// (Этап 5) вместо проверки цепочки X.509. SNI — `cfg.effective_sni()`,
/// домен "сайта прикрытия". Только TLS1.3.
pub async fn connect_tls_reality_with_alpn(
    cfg: &TransportConfig,
    reality: &crate::transport::RealityParams,
    alpn: Vec<Vec<u8>>,
) -> Result<TlsBoxedStream> {
    connect_tls_reality_inner(cfg, reality, alpn, false).await
}

/// Как [`connect_tls_reality_with_alpn`], но без ALPN.
pub async fn connect_tls_reality(
    cfg: &TransportConfig,
    reality: &crate::transport::RealityParams,
) -> Result<TlsBoxedStream> {
    connect_tls_reality_with_alpn(cfg, reality, Vec::new()).await
}

/// Соединение с сервером после выбора `security=`: голый TCP
/// (`security=none`) или TLS/REALITY. Раньше `security=none` всё равно
/// поднимал TLS — ссылка на сервер без TLS не работала вообще.
pub enum SecureStream {
    Plain(RawConn),
    Tls(Box<TlsBoxedStream>),
}

impl std::fmt::Debug for SecureStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureStream::Plain(_) => f.write_str("SecureStream::Plain"),
            SecureStream::Tls(_) => f.write_str("SecureStream::Tls"),
        }
    }
}

impl SecureStream {
    /// Согласованная версия TLS (`None` для голого TCP).
    pub fn tls_version(&self) -> Option<rustls::ProtocolVersion> {
        match self {
            SecureStream::Plain(_) => None,
            SecureStream::Tls(t) => t.get_ref().1.protocol_version(),
        }
    }

    /// Согласованный ALPN (`None` для голого TCP или если не согласован).
    pub fn alpn(&self) -> Option<Vec<u8>> {
        match self {
            SecureStream::Plain(_) => None,
            SecureStream::Tls(t) => t.get_ref().1.alpn_protocol().map(|p| p.to_vec()),
        }
    }
}

macro_rules! delegate {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() {
            SecureStream::Plain($s) => {
                let $s = std::pin::Pin::new($s);
                $e
            }
            SecureStream::Tls($s) => {
                let $s = std::pin::Pin::new(&mut **$s);
                $e
            }
        }
    };
}

impl tokio::io::AsyncRead for SecureStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        delegate!(self, s => s.poll_read(cx, buf))
    }
}

impl tokio::io::AsyncWrite for SecureStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        delegate!(self, s => s.poll_write(cx, buf))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        delegate!(self, s => s.poll_flush(cx))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        delegate!(self, s => s.poll_shutdown(cx))
    }
}

/// ALPN для TCP-транспорта: `alpn=` из ссылки, иначе как у Chrome
/// (`h2, http/1.1`). Раньше ALPN на TCP не отправлялся вовсе — для
/// ClientHello, выдающего себя за браузер, это заметная аномалия.
pub fn default_alpn(cfg: &TransportConfig) -> Vec<Vec<u8>> {
    cfg.alpn()
        .unwrap_or_else(|| vec![b"h2".to_vec(), b"http/1.1".to_vec()])
}

async fn connect_secure(
    cfg: &TransportConfig,
    alpn: Vec<Vec<u8>>,
    record_aligned: bool,
) -> Result<SecureStream> {
    match cfg.security {
        Security::Reality => {
            let reality = cfg.reality_params()?;
            let tls = connect_tls_reality_inner(cfg, &reality, alpn, record_aligned).await?;
            Ok(SecureStream::Tls(Box::new(tls)))
        }
        Security::Tls => {
            let tls = connect_tls_inner(cfg, roots_for(cfg), alpn, record_aligned).await?;
            Ok(SecureStream::Tls(Box::new(tls)))
        }
        Security::None => Ok(SecureStream::Plain(connect_tcp(cfg).await?)),
    }
}

/// Общая точка входа для TCP-подобных транспортов: голый TCP, обычный
/// TLS (проверка цепочки X.509) или REALITY — по `cfg.security`.
pub async fn connect_tls_by_security(
    cfg: &TransportConfig,
    alpn: Vec<Vec<u8>>,
) -> Result<SecureStream> {
    connect_secure(cfg, alpn, false).await
}

/// Поток VLESS поверх TCP-транспорта: обычный или с XTLS Vision.
pub enum TcpVlessStream {
    Plain(VlessStream<SecureStream>),
    Vision(Box<VisionStream>),
}

impl std::fmt::Debug for TcpVlessStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpVlessStream::Plain(_) => f.write_str("TcpVlessStream::Plain"),
            TcpVlessStream::Vision(_) => f.write_str("TcpVlessStream::Vision"),
        }
    }
}

macro_rules! delegate_vless {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() {
            TcpVlessStream::Plain($s) => {
                let $s = std::pin::Pin::new($s);
                $e
            }
            TcpVlessStream::Vision($s) => {
                let $s = std::pin::Pin::new(&mut **$s);
                $e
            }
        }
    };
}

impl tokio::io::AsyncRead for TcpVlessStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        delegate_vless!(self, s => s.poll_read(cx, buf))
    }
}

impl tokio::io::AsyncWrite for TcpVlessStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        delegate_vless!(self, s => s.poll_write(cx, buf))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        delegate_vless!(self, s => s.poll_flush(cx))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        delegate_vless!(self, s => s.poll_shutdown(cx))
    }
}

/// Полное открытие соединения поверх TCP-транспорта: TCP -> (TLS или
/// REALITY, по `cfg.security`) -> заголовок запроса VLESS. Заголовок
/// ответа сервера снимается лениво, при первом чтении (см.
/// `vless_connect` — почему ждать его заранее нельзя).
///
/// С `flow=xtls-rprx-vision` (только TCP-команда, только поверх TLS 1.3
/// или REALITY) возвращается [`VisionStream`]: заголовок уходит вместе с
/// первыми данными приложения, первые пакеты дополняются padding'ом, а
/// после рукопожатия внутреннего TLS обе стороны переходят на прямую
/// передачу без внешнего шифрования (см. `vless::vision`).
pub async fn connect_and_handshake(
    cfg: &TransportConfig,
    id: &Uuid,
    target: Address,
    target_port: u16,
) -> Result<TcpVlessStream> {
    connect_command_config(cfg, id, Flow::None, Command::Tcp, target, target_port).await
}

/// Как [`connect_and_handshake`], но с явной командой VLESS (TCP или UDP).
/// UDP идёт без Vision: сервер Xray принимает UDP-запрос с пустым flow и
/// от Vision-аккаунта (Vision UDP не поддерживает, `inbound.go`).
pub async fn connect_command_config(
    cfg: &TransportConfig,
    id: &Uuid,
    flow: Flow,
    command: Command,
    target: Address,
    target_port: u16,
) -> Result<TcpVlessStream> {
    // Vision — для TCP и для XUDP (команда Mux): так делает клиент Xray;
    // команду UDP с flow Vision сервер отвергает, её шлём без flow.
    let vision = flow.is_vision() && matches!(command, Command::Tcp | Command::Mux);
    if vision && cfg.security == Security::None {
        return Err(Error::InvalidUri(
            "flow=xtls-rprx-vision работает только поверх security=tls или reality".into(),
        ));
    }
    let stream = connect_secure(cfg, default_alpn(cfg), vision).await?;
    if vision {
        let SecureStream::Tls(tls) = stream else {
            unreachable!("Vision без TLS отсечён выше");
        };
        if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(Error::Protocol(
                "XTLS Vision требует внешний TLS 1.3, сервер согласовал более старую версию".into(),
            ));
        }
        let header = encode_request_with_flow(id, command, &target, target_port, flow);
        return Ok(TcpVlessStream::Vision(Box::new(VisionStream::new(
            *tls, id, header,
        ))));
    }
    let s = vless_connect(stream, id, command, &target, target_port).await?;
    Ok(TcpVlessStream::Plain(s))
}

#[cfg(test)]
mod connect_addrs_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    fn v4(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, last), port))
    }

    fn v6(last: u16, port: u16) -> SocketAddr {
        SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last), port))
    }

    #[test]
    fn address_order_interleaves_families_and_keeps_first_family_first() {
        let addresses = [v6(1, 443), v6(2, 443), v4(1, 443), v4(2, 443)];
        assert_eq!(
            interleave_addrs(&addresses),
            [v6(1, 443), v4(1, 443), v6(2, 443), v4(2, 443)]
        );

        let addresses = [v4(1, 443), v6(1, 443), v4(2, 443)];
        assert_eq!(
            interleave_addrs(&addresses),
            [v4(1, 443), v6(1, 443), v4(2, 443)]
        );
    }

    #[test]
    fn address_order_deduplicates_and_limits_connection_attempts() {
        let mut addresses = Vec::new();
        for n in 1..=12 {
            addresses.push(v6(n, 443));
            addresses.push(v4(n as u8, 443));
        }
        addresses.push(v6(1, 443));
        addresses.push(v4(1, 443));

        let ordered = interleave_addrs(&addresses);
        assert_eq!(ordered.len(), MAX_CONNECT_ATTEMPTS);
        assert_eq!(
            ordered
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            ordered.len()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn second_family_wins_without_waiting_for_first_family_timeout() {
        let addresses = [v6(1, 443), v4(1, 443)];
        let started = tokio::time::Instant::now();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let result = connect_addrs_with(&addresses, "test", {
            let attempts = attempts.clone();
            move |sa| {
                let attempts = attempts.clone();
                async move {
                    attempts.lock().unwrap().push(sa);
                    if sa.is_ipv6() {
                        std::future::pending::<()>().await;
                    }
                    Ok(sa)
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(result, v4(1, 443));
        assert_eq!(*attempts.lock().unwrap(), [v6(1, 443), v4(1, 443)]);
        assert!(tokio::time::Instant::now().duration_since(started) < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn fast_failures_start_the_next_candidate_immediately() {
        let addresses = [v6(1, 443), v4(1, 443), v6(2, 443)];
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let result = connect_addrs_with(&addresses, "test", {
            let attempts = attempts.clone();
            move |sa| {
                let attempts = attempts.clone();
                async move {
                    attempts.lock().unwrap().push(sa);
                    if sa == v6(2, 443) {
                        Ok(sa)
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "refused",
                        ))
                    }
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(result, v6(2, 443));
        assert_eq!(
            *attempts.lock().unwrap(),
            [v6(1, 443), v4(1, 443), v6(2, 443)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connection_race_never_exceeds_two_active_attempts() {
        struct Active(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let addresses = [v6(1, 443), v6(2, 443), v4(1, 443), v4(2, 443)];
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let result = connect_addrs_with(&addresses, "test", {
            let active = active.clone();
            let peak = peak.clone();
            let attempts = attempts.clone();
            move |sa| {
                let active = active.clone();
                let peak = peak.clone();
                let attempts = attempts.clone();
                async move {
                    attempts.lock().unwrap().push(sa);
                    let current = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(current, std::sync::atomic::Ordering::SeqCst);
                    let _active = Active(active);
                    if sa == v6(1, 443) {
                        tokio::time::sleep(Duration::from_millis(600)).await;
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "refused",
                        ))
                    } else if sa == v4(1, 443) {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "refused",
                        ))
                    } else if sa == v6(2, 443) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Ok(sa)
                    } else {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        Ok(sa)
                    }
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(result, v6(2, 443));
        assert_eq!(
            peak.load(std::sync::atomic::Ordering::SeqCst),
            MAX_PARALLEL_CONNECTS
        );
        assert_eq!(
            *attempts.lock().unwrap(),
            [v6(1, 443), v4(1, 443), v6(2, 443)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn all_pending_addresses_share_one_ten_second_deadline() {
        let addresses = [v6(1, 443), v4(1, 443), v6(2, 443), v4(2, 443)];
        let started = tokio::time::Instant::now();
        let result = connect_addrs_with(&addresses, "test", |_| async {
            std::future::pending::<std::io::Result<SocketAddr>>().await
        })
        .await;

        assert!(result.is_err());
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            CONNECT_TIMEOUT
        );
    }
}
