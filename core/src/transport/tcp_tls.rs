//! TCP-транспорт: голый TCP (`security=none`), TLS с проверкой цепочки
//! сертификатов (`security=tls`) или REALITY (`security=reality`), и
//! открытие VLESS-сессии поверх — с XTLS Vision, если он в ссылке.
//!
//! ClientHello в обоих TLS-путях — как у Chrome 133
//! (`fingerprint::chrome_profile`): порядок cipher suites, GREASE, набор
//! расширений и их значения; для REALITY совпадает и JA4.

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

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
use crate::vless::protocol::{
    encode_request_with_flow, vless_connect, Address, Command, VlessStream,
};
use crate::vless::uri::Security;
use crate::vless::vision::VisionStream;
use crate::vless::VlessConfig;

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

async fn connect_tcp_stream(cfg: &VlessConfig) -> Result<TcpStream> {
    let addrs = resolve_server(&cfg.host, cfg.port).await?;
    connect_addrs(&addrs, &cfg.host).await
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

/// Адреса VLESS-сервера с кешем: не спрашивать DNS на каждое соединение,
/// а при сбое DNS — продолжать работать по последним известным адресам.
/// Имя сервера всегда разрешается напрямую, системным резолвером: чтобы
/// узнать адрес сервера через сам сервер, пришлось бы уже быть к нему
/// подключённым.
pub async fn resolve_server(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let key = format!("{host}:{port}");
    let cached = server_cache().lock().unwrap().get(&key).cloned();
    if let Some((addrs, at)) = &cached {
        if at.elapsed() < SERVER_CACHE_FRESH {
            return Ok(addrs.clone());
        }
    }
    match resolve_host(host, port).await {
        Ok(addrs) => {
            let mut c = server_cache().lock().unwrap();
            if c.len() > 64 {
                c.clear();
            }
            c.insert(key, (addrs.clone(), std::time::Instant::now()));
            Ok(addrs)
        }
        Err(e) => match cached {
            Some((addrs, at)) if at.elapsed() < SERVER_CACHE_STALE => {
                tracing::warn!(host, error = %e, "DNS не ответил — использую прежние адреса сервера");
                Ok(addrs)
            }
            _ => Err(e),
        },
    }
}

/// Разрешить имя системным резолвером (асинхронно, с таймаутом).
pub async fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
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
            Error::Protocol(format!(
                "не удалось разрешить имя {addr} за {} с",
                DNS_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| Error::Protocol(format!("не удалось разрешить имя {addr}: {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(Error::Protocol(format!(
            "имя {addr} не разрешилось ни в один адрес"
        )));
    }
    Ok(addrs)
}

/// TCP-соединение с `host:port`: разрешение имени системным резолвером и
/// перебор всех адресов (с таймаутом на каждый).
pub async fn connect_host(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = resolve_host(host, port).await?;
    connect_addrs(&addrs, host).await
}

/// Подключиться к первому ответившему из адресов. Перебираем ВСЕ, а не
/// только первый: домен часто отдаёт и IPv6, и IPv4; если IPv6 в сети не
/// работает (обычное дело), раньше клиент не подключался, хотя IPv4 был
/// рядом в том же ответе.
pub async fn connect_addrs(addrs: &[SocketAddr], what: &str) -> Result<TcpStream> {
    let mut last_err = None;
    for sa in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(sa)).await {
            Ok(Ok(tcp)) => {
                tcp.set_nodelay(true).ok();
                return Ok(tcp);
            }
            Ok(Err(e)) => {
                tracing::debug!(%sa, error = %e, "адрес не подошёл, пробую следующий");
                last_err = Some(Error::Io(e));
            }
            Err(_) => {
                tracing::debug!(%sa, "таймаут подключения, пробую следующий");
                last_err = Some(Error::Protocol(format!(
                    "таймаут подключения к {sa} ({} с)",
                    CONNECT_TIMEOUT.as_secs()
                )));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::Protocol(format!("не удалось подключиться ни к одному адресу {what}"))
    }))
}

async fn connect_tcp(cfg: &VlessConfig) -> Result<RawConn> {
    Ok(RawConn::new(connect_tcp_stream(cfg).await?))
}

fn build_client_config(roots: RootCertStore, alpn: Vec<Vec<u8>>) -> ClientConfig {
    // Этап 3: cipher suites — в порядке реального Chrome, не в дефолтном
    // порядке aws-lc-rs (см. `fingerprint::chrome_profile` за источником
    // и обоснованием). Провайдер — тот же самый aws-lc-rs, только с
    // переставленным `cipher_suites`, поэтому
    // `with_safe_default_protocol_versions()` здесь не может провалиться
    // по-настоящему — `expect` фиксирует это как инвариант.
    let provider = crate::fingerprint::apply_chrome133_cipher_order(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("переупорядочивание cipher_suites не может сделать набор suite'ов непригодным")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    crate::fingerprint::apply_chrome_extensions(&mut config, false);
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
    let config = build_client_config(roots.unwrap_or_else(default_root_store), alpn);
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(server_name.to_string()).map_err(Error::InvalidDnsName)?;
    with_handshake_timeout("TLS", connector.connect(name, stream)).await
}

/// Набор доверенных корней для обычного TLS: заданный пользователем
/// (`--ca`, см. [`VlessConfig::ca_roots`]) или встроенный публичный.
fn roots_for(cfg: &VlessConfig) -> RootCertStore {
    match &cfg.ca_roots {
        Some(r) => (**r).clone(),
        None => default_root_store(),
    }
}

async fn connect_tls_inner(
    cfg: &VlessConfig,
    roots: RootCertStore,
    alpn: Vec<Vec<u8>>,
    record_aligned: bool,
) -> Result<TlsBoxedStream> {
    ensure_crypto_provider();

    let mut tcp = connect_tcp(cfg).await?;
    tcp.set_record_aligned(record_aligned);
    let config = build_client_config(roots, alpn);
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(cfg.effective_sni().to_string()).map_err(Error::InvalidDnsName)?;

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
    cfg: &VlessConfig,
    roots: RootCertStore,
    alpn: Vec<Vec<u8>>,
) -> Result<TlsBoxedStream> {
    connect_tls_inner(cfg, roots, alpn, false).await
}

/// Как [`connect_tls_with_roots_alpn`], но без ALPN.
pub async fn connect_tls_with_roots(
    cfg: &VlessConfig,
    roots: RootCertStore,
) -> Result<TlsBoxedStream> {
    connect_tls_with_roots_alpn(cfg, roots, Vec::new()).await
}

/// Поднять TCP+TLS до `cfg.host:cfg.port` с SNI = `cfg.effective_sni()`,
/// доверяя встроенному набору публичных корней (webpki-roots) или
/// заданному через `--ca`.
pub async fn connect_tls(cfg: &VlessConfig) -> Result<TlsBoxedStream> {
    connect_tls_with_roots(cfg, roots_for(cfg)).await
}

/// Как [`connect_tls`], но с ALPN.
pub async fn connect_tls_with_alpn(
    cfg: &VlessConfig,
    alpn: Vec<Vec<u8>>,
) -> Result<TlsBoxedStream> {
    connect_tls_with_roots_alpn(cfg, roots_for(cfg), alpn).await
}

/// Поднять TCP+TLS как [`connect_tls`], но обернуть сокет так, чтобы
/// запомнить сырые байты отправленного ClientHello — Этап 3, "сверка":
/// посмотреть, какой TLS-отпечаток этот клиент реально отправляет прямо
/// сейчас (см. `crate::fingerprint`).
pub async fn connect_tls_capturing_client_hello(
    cfg: &VlessConfig,
) -> Result<(CapturingTlsStream, Vec<u8>)> {
    ensure_crypto_provider();

    let tcp = connect_tcp_stream(cfg).await?;
    let captured_tcp = CaptureFirstBytes::new(tcp, CLIENT_HELLO_CAPTURE_CAP);

    let config = build_client_config(roots_for(cfg), default_alpn(cfg));
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(cfg.effective_sni().to_string()).map_err(Error::InvalidDnsName)?;

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
    reality: &crate::vless::uri::RealityParams,
    alpn: Vec<Vec<u8>>,
) -> Result<ClientConfig> {
    Ok(reality_client_config_inner(reality, alpn, None)?.0)
}

/// Сборка конфига REALITY. `browser_fallback` — корни для обычной
/// проверки X.509: с ними настоящий сертификат сайта не рвёт рукопожатие
/// (см. `transport::browser_mimic`), и тогда вызывающий код ОБЯЗАН
/// проверить `hook.is_verified()` до любой отправки своих данных.
/// Поэтому этот вариант не публичный: снаружи доступен только строгий
/// [`reality_client_config`].
fn reality_client_config_inner(
    reality: &crate::vless::uri::RealityParams,
    alpn: Vec<Vec<u8>>,
    browser_fallback: Option<RootCertStore>,
) -> Result<(ClientConfig, Arc<RealityHook>)> {
    let mut rng = rand::rngs::OsRng;
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

    let provider = crate::fingerprint::apply_chrome133_cipher_order(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
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
    crate::fingerprint::apply_chrome_extensions(&mut config, true);
    Ok((config, hook))
}

async fn connect_tls_reality_inner(
    cfg: &VlessConfig,
    reality: &crate::vless::uri::RealityParams,
    alpn: Vec<Vec<u8>>,
    record_aligned: bool,
) -> Result<TlsBoxedStream> {
    ensure_crypto_provider();

    let mut tcp = connect_tcp(cfg).await?;
    tcp.set_record_aligned(record_aligned);
    let (config, hook) = reality_client_config_inner(reality, alpn, Some(roots_for(cfg)))?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(cfg.effective_sni().to_string()).map_err(Error::InvalidDnsName)?;

    let tls = with_handshake_timeout("REALITY", connector.connect(server_name, tcp)).await?;
    // Единственная точка, через которую REALITY-соединение попадает к
    // VLESS: не прошедшее проверку соединение отсюда не выходит никогда.
    if !hook.is_verified() {
        crate::transport::browser_mimic::visit_in_background(tls, cfg.effective_sni().to_string());
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
    cfg: &VlessConfig,
    reality: &crate::vless::uri::RealityParams,
    alpn: Vec<Vec<u8>>,
) -> Result<TlsBoxedStream> {
    connect_tls_reality_inner(cfg, reality, alpn, false).await
}

/// Как [`connect_tls_reality_with_alpn`], но без ALPN.
pub async fn connect_tls_reality(
    cfg: &VlessConfig,
    reality: &crate::vless::uri::RealityParams,
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
pub fn default_alpn(cfg: &VlessConfig) -> Vec<Vec<u8>> {
    cfg.alpn()
        .unwrap_or_else(|| vec![b"h2".to_vec(), b"http/1.1".to_vec()])
}

async fn connect_secure(
    cfg: &VlessConfig,
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
    cfg: &VlessConfig,
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
    cfg: &VlessConfig,
    id: &Uuid,
    target: Address,
    target_port: u16,
) -> Result<TcpVlessStream> {
    connect_command(cfg, id, Command::Tcp, target, target_port).await
}

/// Как [`connect_and_handshake`], но с явной командой VLESS (TCP или UDP).
/// UDP идёт без Vision: сервер Xray принимает UDP-запрос с пустым flow и
/// от Vision-аккаунта (Vision UDP не поддерживает, `inbound.go`).
pub async fn connect_command(
    cfg: &VlessConfig,
    id: &Uuid,
    command: Command,
    target: Address,
    target_port: u16,
) -> Result<TcpVlessStream> {
    cfg.ensure_flow_supported()?;
    // Vision — для TCP и для XUDP (команда Mux): так делает клиент Xray;
    // команду UDP с flow Vision сервер отвергает, её шлём без flow.
    let vision = cfg.flow.is_vision() && matches!(command, Command::Tcp | Command::Mux);
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
        let header = encode_request_with_flow(id, command, &target, target_port, cfg.flow);
        return Ok(TcpVlessStream::Vision(Box::new(VisionStream::new(
            *tls, id, header,
        ))));
    }
    let s = vless_connect(stream, id, command, &target, target_port).await?;
    Ok(TcpVlessStream::Plain(s))
}
