//! Интероп-тесты против НАСТОЯЩЕГО Xray-core (сервер `xray run` с
//! VLESS-входами) — не против собственной реализации серверной стороны.
//!
//! Что проверяется (каждый тест поднимает свой экземпляр Xray):
//! - REALITY поверх TCP без flow;
//! - XTLS Vision поверх REALITY: и для не-TLS данных (только padding), и
//!   для внутреннего TLS 1.3 — с проверкой, что обе стороны реально
//!   переключились на прямую передачу и данные не исказились;
//! - Vision с ML-DSA-65 (`pqv=`), в том числе отказ при чужом ключе;
//! - WebSocket и httpupgrade без TLS и поверх TLS с собственным CA (`--ca`);
//! - gRPC поверх REALITY;
//! - xhttp: HTTP/1.1 и h2, все три режима, поверх TLS и REALITY, отказы
//!   сервера (404, 400) с понятной ошибкой;
//! - UDP (команда VLESS UDP) — эхо датаграмм; XUDP (как у клиента Xray) —
//!   с проверкой Full Cone.
//!
//! Нужен бинарник Xray-core, поэтому тесты `#[ignore]`. Запуск:
//! `XRAY_BIN=/путь/к/xray cargo test -p reality-core --test interop_xray -- --ignored`
//! или `scripts/interop_xray.sh` (сам найдёт/соберёт Xray).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x25519_dalek::{PublicKey, StaticSecret};

use reality_core::transport::tcp_tls::{connect_and_handshake, ensure_crypto_provider};
use reality_core::transport::{dial, TcpVlessStream};
use reality_core::vless::{Address, Command as VlessCommand, VlessConfig};

const SHORT_ID: &str = "0123abcd";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn self_signed(
    name: &str,
) -> (
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    String,
    String,
) {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();
    let der = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    (der, key, cert_pem, key_pem)
}

fn tls_acceptor(name: &str, alpn: &[&[u8]]) -> (TlsAcceptor, CertificateDer<'static>) {
    let (cert, key, _, _) = self_signed(name);
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    (TlsAcceptor::from(Arc::new(cfg)), cert)
}

/// «Сайт прикрытия» для REALITY: обычный TLS 1.3, ничего не отвечает.
/// Цепочка сертификатов искусственно длинная (~6 КБ, как у настоящих
/// сайтов): REALITY-сервер подгоняет свои рукопожатные записи под длины
/// записей сайта и не может сделать их КОРОЧЕ своих. С ML-DSA-65 его
/// сертификат ~3,5 КБ, и с коротенькой тестовой цепочкой сервер падает
/// с "handshake did not complete successfully".
async fn start_decoy() -> u16 {
    start_decoy_with(false).await
}

/// `classic_only` — сайт без постквантовой группы (только X25519), как
/// многие сайты на старом OpenSSL: он выберет X25519, а не гибрид.
async fn start_decoy_with(classic_only: bool) -> u16 {
    let (cert, key, _, _) = self_signed("decoy.test");
    let mut chain = vec![cert];
    for i in 0..12 {
        chain.push(self_signed(&format!("filler{i}.decoy.test")).0);
    }
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if classic_only {
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    }
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // Без сжатия сертификатов: клиент (как Chrome) предлагает brotli, и
    // сжатая цепочка стала бы короче сертификата REALITY с ML-DSA-65
    // (см. докстринг выше). Сайт без сжатия — обычный случай.
    cfg.cert_compressors = Vec::new();
    let acc = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let acc = acc.clone();
            tokio::spawn(async move {
                if let Ok(mut t) = acc.accept(s).await {
                    let mut b = [0u8; 1024];
                    while matches!(t.read(&mut b).await, Ok(n) if n > 0) {}
                }
            });
        }
    });
    port
}

/// Цель за прокси: TCP-эхо.
async fn start_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// Цель за прокси: TLS 1.3-сервер с эхом (для проверки Vision на
/// настоящем «TLS в TLS»).
async fn start_inner_tls_echo() -> (u16, CertificateDer<'static>) {
    let (acc, cert) = tls_acceptor("inner.test", &[]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let acc = acc.clone();
            tokio::spawn(async move {
                match acc.accept(s).await {
                    Ok(t) => {
                        let (mut r, mut w) = tokio::io::split(t);
                        if let Err(e) = tokio::io::copy(&mut r, &mut w).await {
                            eprintln!("inner echo: {e}");
                        }
                        let _ = w.shutdown().await;
                    }
                    Err(e) => eprintln!("inner accept: {e}"),
                }
            });
        }
    });
    (port, cert)
}

async fn start_udp_echo() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = s.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        loop {
            let Ok((n, from)) = s.recv_from(&mut b).await else {
                return;
            };
            let _ = s.send_to(&b[..n], from).await;
        }
    });
    port
}

struct Keys {
    private: String,
    public: [u8; 32],
}

fn reality_keys() -> Keys {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    Keys {
        private: b64(&secret.to_bytes()),
        public,
    }
}

fn xray_bin() -> PathBuf {
    std::env::var_os("XRAY_BIN")
        .map(PathBuf::from)
        .expect("XRAY_BIN не задан — запускать через scripts/interop_xray.sh")
}

/// `xray mldsa65` → (seed, verify).
fn mldsa65_keys() -> (String, String) {
    let out = Command::new(xray_bin()).arg("mldsa65").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string()))
            .unwrap_or_else(|| panic!("нет {k} в выводе xray mldsa65: {text}"))
    };
    (get("Seed:"), get("Verify:"))
}

struct Xray {
    child: Child,
    _dir: tempdir::Dir,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

mod tempdir {
    pub struct Dir(pub std::path::PathBuf);
    impl Dir {
        pub fn new() -> Self {
            let p = std::env::temp_dir().join(format!("xray-interop-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

impl Xray {
    /// Запустить Xray с данными inbound'ами и дождаться, пока все порты
    /// начнут принимать соединения.
    async fn start(
        inbounds: Vec<serde_json_lite::Value>,
        ports: &[u16],
        dir: tempdir::Dir,
    ) -> Self {
        let config = serde_json_lite::obj(vec![
            (
                "log",
                serde_json_lite::obj(vec![(
                    "loglevel",
                    serde_json_lite::s(std::env::var("XRAY_LOGLEVEL").unwrap_or("warning".into())),
                )]),
            ),
            ("inbounds", serde_json_lite::Value::Arr(inbounds)),
            (
                "outbounds",
                // Xray по умолчанию запрещает VLESS-входам ходить на
                // приватные адреса (`freedom.go`, defaultBlockPrivateRule),
                // а тестовые цели живут на 127.0.0.1 — явно разрешаем.
                serde_json_lite::Value::Arr(vec![serde_json_lite::obj(vec![
                    ("protocol", serde_json_lite::s("freedom")),
                    (
                        "settings",
                        serde_json_lite::obj(vec![(
                            "finalRules",
                            serde_json_lite::arr(vec![serde_json_lite::obj(vec![
                                ("action", serde_json_lite::s("allow")),
                                (
                                    "ip",
                                    serde_json_lite::arr(vec![serde_json_lite::s("127.0.0.0/8")]),
                                ),
                            ])]),
                        )]),
                    ),
                ])]),
            ),
        ]);
        let path = dir.0.join("config.json");
        std::fs::write(&path, config.to_string()).unwrap();
        let child = Command::new(xray_bin())
            .arg("run")
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("запустить xray");
        let x = Xray { child, _dir: dir };
        for &p in ports {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            loop {
                if TcpStream::connect(("127.0.0.1", p)).await.is_ok() {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "Xray не открыл порт {p}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        x
    }
}

/// Минимальный JSON-писатель — чтобы не тащить serde_json ради тестов.
mod serde_json_lite {
    pub enum Value {
        Str(String),
        Num(i64),
        Bool(bool),
        Arr(Vec<Value>),
        Obj(Vec<(String, Value)>),
    }
    pub fn s(v: impl Into<String>) -> Value {
        Value::Str(v.into())
    }
    pub fn n(v: i64) -> Value {
        Value::Num(v)
    }
    pub fn b(v: bool) -> Value {
        Value::Bool(v)
    }
    pub fn arr(v: Vec<Value>) -> Value {
        Value::Arr(v)
    }
    pub fn obj(v: Vec<(&str, Value)>) -> Value {
        Value::Obj(v.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    impl std::fmt::Display for Value {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Value::Str(s) => {
                    f.write_str("\"")?;
                    for c in s.chars() {
                        match c {
                            '"' => f.write_str("\\\"")?,
                            '\\' => f.write_str("\\\\")?,
                            '\n' => f.write_str("\\n")?,
                            c => write!(f, "{c}")?,
                        }
                    }
                    f.write_str("\"")
                }
                Value::Num(n) => write!(f, "{n}"),
                Value::Bool(b) => write!(f, "{b}"),
                Value::Arr(a) => {
                    f.write_str("[")?;
                    for (i, v) in a.iter().enumerate() {
                        if i > 0 {
                            f.write_str(",")?;
                        }
                        write!(f, "{v}")?;
                    }
                    f.write_str("]")
                }
                Value::Obj(o) => {
                    f.write_str("{")?;
                    for (i, (k, v)) in o.iter().enumerate() {
                        if i > 0 {
                            f.write_str(",")?;
                        }
                        write!(f, "\"{k}\":{v}")?;
                    }
                    f.write_str("}")
                }
            }
        }
    }
}
use serde_json_lite::{arr, b, n, obj, s};

fn vless_inbound(
    port: u16,
    uuid: &uuid::Uuid,
    flow: &str,
    stream: serde_json_lite::Value,
) -> serde_json_lite::Value {
    obj(vec![
        ("listen", s("127.0.0.1")),
        ("port", n(port as i64)),
        ("protocol", s("vless")),
        (
            "settings",
            obj(vec![
                (
                    "clients",
                    arr(vec![obj(vec![
                        ("id", s(uuid.to_string())),
                        ("flow", s(flow)),
                    ])]),
                ),
                ("decryption", s("none")),
            ]),
        ),
        ("streamSettings", stream),
    ])
}

fn reality_stream(
    network: &str,
    decoy: u16,
    keys: &Keys,
    extra: Vec<(&str, serde_json_lite::Value)>,
    mldsa_seed: Option<&str>,
) -> serde_json_lite::Value {
    let mut rs = vec![
        ("show", b(false)),
        ("target", s(format!("127.0.0.1:{decoy}"))),
        ("serverNames", arr(vec![s("decoy.test")])),
        ("privateKey", s(keys.private.clone())),
        ("shortIds", arr(vec![s(SHORT_ID)])),
    ];
    if let Some(seed) = mldsa_seed {
        rs.push(("mldsa65Seed", s(seed)));
    }
    let mut v = vec![
        ("network", s(network)),
        ("security", s("reality")),
        ("realitySettings", obj(rs)),
    ];
    v.extend(extra);
    obj(v)
}

fn reality_link(port: u16, uuid: &uuid::Uuid, keys: &Keys, rest: &str) -> VlessConfig {
    VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{port}?encryption=none&security=reality&sni=decoy.test&fp=chrome&pbk={}&sid={SHORT_ID}{rest}",
        b64(&keys.public)
    ))
    .unwrap()
}

async fn echo_roundtrip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    s: &mut S,
    size: usize,
) {
    let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(s);
    let writer = async {
        for c in data.chunks(7000) {
            w.write_all(c).await.unwrap();
        }
        w.flush().await.unwrap();
    };
    let reader = async {
        let mut got = vec![0u8; size];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(writer, reader)
    })
    .await
    .expect("эхо не должно зависать");
    assert!(got == data, "данные через прокси исказились");
}

fn target(port: u16) -> (Address, u16) {
    (Address::Ipv4("127.0.0.1".parse().unwrap()), port)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn reality_tcp_echo_against_xray() {
    reality_tcp_echo(false).await;
}

/// Сайт-приманка без ML-KEM: сервер REALITY повторяет его выбор (X25519),
/// и клиент обязан завершить рукопожатие по классической доле ключа.
/// Раньше клиент слал только гибридную долю, и с такими сайтами REALITY не
/// работал вовсе («target sent incorrect server hello»).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn reality_with_classic_x25519_decoy_against_xray() {
    reality_tcp_echo(true).await;
}

async fn reality_tcp_echo(classic_decoy: bool) {
    ensure_crypto_provider();
    let decoy = start_decoy_with(classic_decoy).await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "",
            reality_stream("raw", decoy, &keys, vec![], None),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let cfg = reality_link(port, &uuid, &keys, "&type=tcp");
    let (a, p) = target(echo);
    let mut s = connect_and_handshake(&cfg, &cfg.id, a, p).await.unwrap();
    // Первое соединение к новому «сайту прикрытия» REALITY-сервер Xray
    // держит до 5 с, пока изучает его пост-рукопожатные записи
    // (`record_detect.go` в XTLS/REALITY) — поэтому щедрый таймаут.
    s.write_all(b"ping").await.unwrap();
    let mut b4 = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut b4))
        .await
        .expect("ping")
        .unwrap();
    echo_roundtrip(&mut s, 256 * 1024).await;
}

/// Vision-аккаунт отвергает клиента без flow — именно поэтому Vision и
/// нужен: раньше этот клиент с такими серверами не работал вовсе.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn vision_account_rejects_client_without_flow() {
    ensure_crypto_provider();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "xtls-rprx-vision",
            reality_stream("raw", decoy, &keys, vec![], None),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let cfg = reality_link(port, &uuid, &keys, "&type=tcp");
    let (a, p) = target(echo);
    let mut s = connect_and_handshake(&cfg, &cfg.id, a, p).await.unwrap();
    s.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    let r = tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut buf)).await;
    assert!(
        !matches!(r, Ok(Ok(_))),
        "сервер с flow=xtls-rprx-vision не должен пропускать клиента без flow"
    );
}

/// Vision, не-TLS данные: только padding, без прямой передачи.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn vision_plain_payload_against_xray() {
    ensure_crypto_provider();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "xtls-rprx-vision",
            reality_stream("raw", decoy, &keys, vec![], None),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let cfg = reality_link(port, &uuid, &keys, "&type=tcp&flow=xtls-rprx-vision");
    let (a, p) = target(echo);
    let mut s = connect_and_handshake(&cfg, &cfg.id, a, p).await.unwrap();
    assert!(matches!(s, TcpVlessStream::Vision(_)));
    echo_roundtrip(&mut s, 300 * 1024).await;
    let TcpVlessStream::Vision(v) = &s else {
        unreachable!()
    };
    assert!(
        !v.is_write_direct() && !v.is_read_direct(),
        "для не-TLS данных прямой передачи нет"
    );
}

/// Приложение молчит: заголовок VLESS должен уйти сам через 500 мс
/// (иначе сервер, который говорит первым, ждал бы вечно).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn vision_sends_header_when_client_is_silent() {
    ensure_crypto_provider();
    let decoy = start_decoy().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    // Цель, которая говорит первой.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let banner_port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        s.write_all(b"220 hello from server\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "xtls-rprx-vision",
            reality_stream("raw", decoy, &keys, vec![], None),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let cfg = reality_link(port, &uuid, &keys, "&type=tcp&flow=xtls-rprx-vision");
    let (a, p) = target(banner_port);
    let mut s = connect_and_handshake(&cfg, &cfg.id, a, p).await.unwrap();
    let mut buf = [0u8; 23];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut buf))
        .await
        .expect("баннер должен прийти")
        .unwrap();
    assert_eq!(&buf, b"220 hello from server\r\n");
}

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

async fn vision_inner_tls(pqv: Option<(&str, &str)>, expect_ok: bool) {
    init_log();
    ensure_crypto_provider();
    let decoy = start_decoy().await;
    let (inner_port, inner_cert) = start_inner_tls_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "xtls-rprx-vision",
            reality_stream("raw", decoy, &keys, vec![], pqv.map(|p| p.0)),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let extra = match pqv {
        Some((_, verify)) => format!("&type=tcp&flow=xtls-rprx-vision&pqv={verify}"),
        None => "&type=tcp&flow=xtls-rprx-vision".into(),
    };
    let cfg = reality_link(port, &uuid, &keys, &extra);
    let (a, p) = target(inner_port);
    let res = connect_and_handshake(&cfg, &cfg.id, a, p).await;
    if !expect_ok {
        let err = res
            .expect_err("неверный pqv= должен отвергаться")
            .to_string();
        assert!(
            err.contains("ML-DSA-65"),
            "отказ должен быть именно из-за подписи ML-DSA-65: {err}"
        );
        return;
    }
    let s = res.expect("Vision поверх REALITY");

    // Настоящий TLS 1.3 внутри туннеля.
    let mut roots = RootCertStore::empty();
    roots.add(inner_cert).unwrap();
    let cc = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut tls = TlsConnector::from(Arc::new(cc))
        .connect(ServerName::try_from("inner.test").unwrap(), s)
        .await
        .expect("рукопожатие внутреннего TLS через Vision");
    if let Ok(n) = std::env::var("XT_PROBE") {
        for i in 0..n.parse::<usize>().unwrap() {
            let msg = vec![i as u8; 100 + i];
            tls.write_all(&msg).await.unwrap();
            let mut back = vec![0u8; msg.len()];
            tls.read_exact(&mut back)
                .await
                .unwrap_or_else(|e| panic!("probe {i}: {e}"));
            assert_eq!(back, msg);
        }
    }
    echo_roundtrip(&mut tls, 2 * 1024 * 1024).await;

    let TcpVlessStream::Vision(v) = tls.get_ref().0 else {
        panic!("ожидался Vision")
    };
    assert!(
        v.is_write_direct(),
        "отправка должна перейти на прямую передачу"
    );
    assert!(
        v.is_read_direct(),
        "приём должен перейти на прямую передачу"
    );
    // И после переключения всё работает в обе стороны.
    echo_roundtrip(&mut tls, 64 * 1024).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn vision_inner_tls_switches_to_direct_against_xray() {
    vision_inner_tls(None, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn vision_with_mldsa65_against_xray() {
    let (seed, verify) = mldsa65_keys();
    vision_inner_tls(Some((&seed, &verify)), true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn wrong_mldsa65_key_is_rejected() {
    let (seed, _) = mldsa65_keys();
    let (_, other_verify) = mldsa65_keys();
    vision_inner_tls(Some((&seed, &other_verify)), false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn websocket_plain_and_tls_against_xray() {
    ensure_crypto_provider();
    let echo = start_echo().await;
    let uuid = uuid::Uuid::new_v4();
    let dir = tempdir::Dir::new();
    let (_, _, cert_pem, key_pem) = self_signed("ws.test");
    let cert_path = dir.0.join("cert.pem");
    let key_path = dir.0.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    let (p_plain, p_tls) = (free_port(), free_port());
    let ws = |path: &str| ("wsSettings", obj(vec![("path", s(path))]));
    let _x = Xray::start(
        vec![
            vless_inbound(
                p_plain,
                &uuid,
                "",
                obj(vec![
                    ("network", s("ws")),
                    ("security", s("none")),
                    ws("/plain"),
                ]),
            ),
            vless_inbound(
                p_tls,
                &uuid,
                "",
                obj(vec![
                    ("network", s("ws")),
                    ("security", s("tls")),
                    (
                        "tlsSettings",
                        obj(vec![(
                            "certificates",
                            arr(vec![obj(vec![
                                ("certificateFile", s(cert_path.to_string_lossy())),
                                ("keyFile", s(key_path.to_string_lossy())),
                            ])]),
                        )]),
                    ),
                    ws("/tls"),
                ]),
            ),
        ],
        &[p_plain, p_tls],
        dir,
    )
    .await;

    let (a, p) = target(echo);
    let cfg = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_plain}?encryption=none&security=none&type=ws&path=%2Fplain"
    ))
    .unwrap();
    let mut s1 = dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
        .await
        .unwrap();
    echo_roundtrip(&mut s1, 200 * 1024).await;

    let mut cfg = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_tls}?encryption=none&security=tls&sni=ws.test&type=ws&path=%2Ftls"
    ))
    .unwrap();
    // Без своего CA самоподписанный сертификат не должен приниматься.
    assert!(dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
        .await
        .is_err());
    let mut roots = RootCertStore::empty();
    for c in rustls_pki_types::pem::PemObject::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    cfg.ca_roots = Some(Arc::new(roots));
    let mut s2 = dial(&cfg, &cfg.id, VlessCommand::Tcp, a, p).await.unwrap();
    echo_roundtrip(&mut s2, 200 * 1024).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn grpc_over_reality_against_xray() {
    ensure_crypto_provider();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "",
            reality_stream(
                "grpc",
                decoy,
                &keys,
                vec![("grpcSettings", obj(vec![("serviceName", s("tunsvc"))]))],
                None,
            ),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let cfg = reality_link(port, &uuid, &keys, "&type=grpc&serviceName=tunsvc");
    let (a, p) = target(echo);
    let mut st = dial(&cfg, &cfg.id, VlessCommand::Tcp, a, p).await.unwrap();
    echo_roundtrip(&mut st, 1024 * 1024).await;
}

/// UDP-команда VLESS — в том числе от Vision-аккаунта (сервер принимает
/// UDP с пустым flow).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn udp_echo_against_xray() {
    ensure_crypto_provider();
    let decoy = start_decoy().await;
    let udp_echo = start_udp_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "xtls-rprx-vision",
            reality_stream("raw", decoy, &keys, vec![], None),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let cfg = reality_link(port, &uuid, &keys, "&type=tcp&flow=xtls-rprx-vision");
    let (a, p) = target(udp_echo);
    let mut st = dial(&cfg, &cfg.id, VlessCommand::Udp, a, p).await.unwrap();
    let mut buf = Vec::new();
    for i in 0..20u8 {
        let pkt: Vec<u8> = (0..(100 + i as usize * 50)).map(|j| j as u8 ^ i).collect();
        reality_core::vless::udp::write_packet(&mut st, &pkt)
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(10),
            reality_core::vless::udp::read_packet(&mut st, &mut buf),
        )
        .await
        .expect("UDP-ответ должен прийти")
        .unwrap()
        .unwrap();
        assert_eq!(buf, pkt, "датаграмма {i}");
    }
    let _: SocketAddr = "127.0.0.1:0".parse().unwrap();
}

/// httpupgrade: без TLS и поверх TLS (REALITY с httpupgrade Xray не
/// поддерживает: "REALITY only supports RAW, XHTTP and gRPC"). Путь с
/// `?ed=` (ранние данные у Xray) клиент обязан отбросить и всё равно
/// попасть в тот же вход.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn httpupgrade_plain_and_tls_against_xray() {
    ensure_crypto_provider();
    let echo = start_echo().await;
    let uuid = uuid::Uuid::new_v4();
    let dir = tempdir::Dir::new();
    let (_, _, cert_pem, key_pem) = self_signed("hu.test");
    let cert_path = dir.0.join("cert.pem");
    let key_path = dir.0.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    let (p_plain, p_tls) = (free_port(), free_port());
    let hu = |path: &str| {
        (
            "httpupgradeSettings",
            obj(vec![("path", s(path)), ("host", s("cdn.test"))]),
        )
    };
    let _x = Xray::start(
        vec![
            vless_inbound(
                p_plain,
                &uuid,
                "",
                obj(vec![
                    ("network", s("httpupgrade")),
                    ("security", s("none")),
                    hu("/hu"),
                ]),
            ),
            vless_inbound(
                p_tls,
                &uuid,
                "",
                obj(vec![
                    ("network", s("httpupgrade")),
                    ("security", s("tls")),
                    (
                        "tlsSettings",
                        obj(vec![(
                            "certificates",
                            arr(vec![obj(vec![
                                ("certificateFile", s(cert_path.to_string_lossy())),
                                ("keyFile", s(key_path.to_string_lossy())),
                            ])]),
                        )]),
                    ),
                    hu("/hut"),
                ]),
            ),
        ],
        &[p_plain, p_tls],
        dir,
    )
    .await;

    let (a, p) = target(echo);
    let cfg = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_plain}?encryption=none&security=none&type=httpupgrade&host=cdn.test&path=%2Fhu%3Fed%3D2048"
    ))
    .unwrap();
    let mut st = dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
        .await
        .unwrap();
    echo_roundtrip(&mut st, 300 * 1024).await;

    // Неверный путь — сервер не отвечает 101, ошибка понятная.
    let bad = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_plain}?encryption=none&security=none&type=httpupgrade&host=cdn.test&path=%2Fwrong"
    ))
    .unwrap();
    let err = dial(&bad, &bad.id, VlessCommand::Tcp, a.clone(), p)
        .await
        .err()
        .expect("неверный path должен отвергаться")
        .to_string();
    assert!(err.contains("httpupgrade"), "{err}");

    let mut cfg = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_tls}?encryption=none&security=tls&sni=hu.test&type=httpupgrade&host=cdn.test&path=%2Fhut"
    ))
    .unwrap();
    let mut roots = RootCertStore::empty();
    for c in rustls_pki_types::pem::PemObject::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    cfg.ca_roots = Some(Arc::new(roots));
    let mut st = dial(&cfg, &cfg.id, VlessCommand::Tcp, a, p).await.unwrap();
    echo_roundtrip(&mut st, 300 * 1024).await;
}

fn tls_link(port: u16, uuid: &uuid::Uuid, sni: &str, rest: &str, cert_pem: &str) -> VlessConfig {
    let mut cfg = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{port}?encryption=none&security=tls&sni={sni}{rest}"
    ))
    .unwrap();
    let mut roots = RootCertStore::empty();
    for c in rustls_pki_types::pem::PemObject::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    cfg.ca_roots = Some(Arc::new(roots));
    cfg
}

/// Запросы xhttp уходят без ожидания ответа (как у Xray), поэтому отказ
/// сервера всплывает там, куда успеет: в `dial` (при записи заголовка
/// VLESS), при записи или при первом чтении — в любом случае с пояснением.
async fn expect_xhttp_error(cfg: &VlessConfig, a: Address, p: u16, needle: &str) {
    let err = tokio::time::timeout(Duration::from_secs(20), async {
        let mut st = dial(cfg, &cfg.id, VlessCommand::Tcp, a, p)
            .await
            .map_err(|e| e.to_string())?;
        st.write_all(b"ping").await.map_err(|e| e.to_string())?;
        st.flush().await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 16];
        st.read(&mut buf).await.map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    })
    .await
    .expect("ошибка должна прийти, а не зависнуть")
    .expect_err("ожидалась ошибка");
    assert!(err.contains("xhttp") && err.contains(needle), "{err}");
}

/// xhttp (SplitHTTP) без TLS (HTTP/1.1, packet-up) и поверх TLS: h2 во
/// всех трёх режимах и HTTP/1.1 (`alpn=http/1.1`). Один вход Xray с
/// mode=auto принимает все режимы. Плюс отказы: неверный путь (404) и
/// padding вне диапазона сервера (400) — это заодно доказывает, что
/// сервер реально проверяет наш `Referer` с `x_padding`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn xhttp_plain_and_tls_against_xray() {
    ensure_crypto_provider();
    init_log();
    let echo = start_echo().await;
    let uuid = uuid::Uuid::new_v4();
    let dir = tempdir::Dir::new();
    let (_, _, cert_pem, key_pem) = self_signed("xh.test");
    let cert_path = dir.0.join("cert.pem");
    let key_path = dir.0.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    let (p_plain, p_tls) = (free_port(), free_port());
    let _x = Xray::start(
        vec![
            vless_inbound(
                p_plain,
                &uuid,
                "",
                obj(vec![
                    ("network", s("xhttp")),
                    ("security", s("none")),
                    (
                        "xhttpSettings",
                        obj(vec![("path", s("/xh")), ("host", s("cdn.test"))]),
                    ),
                ]),
            ),
            vless_inbound(
                p_tls,
                &uuid,
                "",
                obj(vec![
                    ("network", s("xhttp")),
                    ("security", s("tls")),
                    (
                        "tlsSettings",
                        obj(vec![(
                            "certificates",
                            arr(vec![obj(vec![
                                ("certificateFile", s(cert_path.to_string_lossy())),
                                ("keyFile", s(key_path.to_string_lossy())),
                            ])]),
                        )]),
                    ),
                    ("xhttpSettings", obj(vec![("path", s("/xht"))])),
                ]),
            ),
        ],
        &[p_plain, p_tls],
        dir,
    )
    .await;
    let (a, p) = target(echo);

    // Без TLS: HTTP/1.1, packet-up; 1 МиБ — много POST'ов, порядок по seq.
    let plain = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_plain}?encryption=none&security=none&type=xhttp&host=cdn.test&path=%2Fxh"
    ))
    .unwrap();
    let mut st = dial(&plain, &plain.id, VlessCommand::Tcp, a.clone(), p)
        .await
        .unwrap();
    echo_roundtrip(&mut st, 1024 * 1024).await;
    // Пауза дольше таймаутов сервера на простаивающее keep-alive
    // соединение для POST'ов: следующая порция должна дойти (при
    // необходимости — по новому соединению), а не потеряться с дырой в seq.
    tokio::time::sleep(Duration::from_secs(6)).await;
    echo_roundtrip(&mut st, 64 * 1024).await;
    drop(st);

    // Небольшой scMaxEachPostBytes — порции заведомо режутся.
    let small = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_plain}?encryption=none&security=none&type=xhttp&host=cdn.test&path=%2Fxh&extra=%7B%22scMaxEachPostBytes%22%3A%2220000-30000%22%2C%22scMinPostsIntervalMs%22%3A5%7D"
    ))
    .unwrap();
    let mut st = dial(&small, &small.id, VlessCommand::Tcp, a.clone(), p)
        .await
        .unwrap();
    echo_roundtrip(&mut st, 300 * 1024).await;
    drop(st);

    // Неверный путь и неверный Host — 404.
    let bad = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_plain}?encryption=none&security=none&type=xhttp&host=cdn.test&path=%2Fwrong"
    ))
    .unwrap();
    expect_xhttp_error(&bad, a.clone(), p, "404").await;
    let bad = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_plain}?encryption=none&security=none&type=xhttp&host=other.test&path=%2Fxh"
    ))
    .unwrap();
    expect_xhttp_error(&bad, a.clone(), p, "404").await;
    // Padding короче диапазона сервера (100-1000) — 400.
    let bad = VlessConfig::parse(&format!(
        "vless://{uuid}@127.0.0.1:{p_plain}?encryption=none&security=none&type=xhttp&host=cdn.test&path=%2Fxh&extra=%7B%22xPaddingBytes%22%3A%225-10%22%7D"
    ))
    .unwrap();
    expect_xhttp_error(&bad, a.clone(), p, "400").await;

    // TLS: h2 во всех режимах и HTTP/1.1.
    for rest in [
        "&type=xhttp&path=%2Fxht",
        "&type=xhttp&path=%2Fxht&mode=stream-up",
        "&type=xhttp&path=%2Fxht&mode=stream-one",
        "&type=xhttp&path=%2Fxht&alpn=http%2F1.1",
    ] {
        let cfg = tls_link(p_tls, &uuid, "xh.test", rest, &cert_pem);
        let mut st = dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
            .await
            .unwrap_or_else(|e| panic!("{rest}: {e}"));
        echo_roundtrip(&mut st, 1024 * 1024).await;
    }
}

/// xhttp поверх REALITY: по умолчанию stream-one (как у Xray), а также
/// stream-up и packet-up на том же входе.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn xhttp_over_reality_against_xray() {
    ensure_crypto_provider();
    init_log();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "",
            reality_stream(
                "xhttp",
                decoy,
                &keys,
                vec![("xhttpSettings", obj(vec![("path", s("/xr"))]))],
                None,
            ),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let (a, p) = target(echo);
    for rest in [
        "&type=xhttp&path=%2Fxr",
        "&type=xhttp&path=%2Fxr&mode=stream-up",
        "&type=xhttp&path=%2Fxr&mode=packet-up",
    ] {
        let cfg = reality_link(port, &uuid, &keys, rest);
        let mut st = dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
            .await
            .unwrap_or_else(|e| panic!("{rest}: {e}"));
        echo_roundtrip(&mut st, 1024 * 1024).await;
    }
}

/// UDP-«отражатель»: отвечает портом, с которого пришёл пакет (2 байта),
/// и самим пакетом — так видно, один ли внешний UDP-сокет у сервера.
async fn start_udp_reflector() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = s.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        loop {
            let Ok((n, from)) = s.recv_from(&mut b).await else {
                return;
            };
            let mut out = from.port().to_be_bytes().to_vec();
            out.extend_from_slice(&b[..n]);
            let _ = s.send_to(&out, from).await;
        }
    });
    port
}

/// XUDP (как шлёт UDP клиент Xray): через Vision-аккаунт на REALITY и
/// через xhttp. Пакеты в два разных назначения идут одним потоком,
/// ответы приходят с адресом источника, и оба назначения видят один и
/// тот же порт сервера — это и есть Full Cone.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn xudp_full_cone_against_xray() {
    use reality_core::vless::xudp::{self, XudpWriter};
    ensure_crypto_provider();
    let decoy = start_decoy().await;
    let (r1, r2) = (start_udp_reflector().await, start_udp_reflector().await);
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let (p_vision, p_xhttp) = (free_port(), free_port());
    let _x = Xray::start(
        vec![
            vless_inbound(
                p_vision,
                &uuid,
                "xtls-rprx-vision",
                reality_stream("raw", decoy, &keys, vec![], None),
            ),
            vless_inbound(
                p_xhttp,
                &uuid,
                "",
                obj(vec![
                    ("network", s("xhttp")),
                    ("xhttpSettings", obj(vec![("path", s("/u"))])),
                ]),
            ),
        ],
        &[p_vision, p_xhttp],
        tempdir::Dir::new(),
    )
    .await;
    let links = [
        reality_link(p_vision, &uuid, &keys, "&type=tcp&flow=xtls-rprx-vision"),
        VlessConfig::parse(&format!(
            "vless://{uuid}@127.0.0.1:{p_xhttp}?encryption=none&type=xhttp&path=%2Fu"
        ))
        .unwrap(),
    ];
    for cfg in links {
        let mut st = dial(
            &cfg,
            &cfg.id,
            VlessCommand::Mux,
            Address::Domain(xudp::MUX_COOL_DOMAIN.into()),
            xudp::XUDP_PORT,
        )
        .await
        .unwrap();
        let mut w = XudpWriter::new([7; 8]);
        let mut seen_ports = Vec::new();
        for i in 0..10u8 {
            let dst = if i % 2 == 0 { r1 } else { r2 };
            let pkt: Vec<u8> = (0..(200 + i as usize * 300)).map(|j| j as u8 ^ i).collect();
            let frame = w
                .encode(&Address::Ipv4("127.0.0.1".parse().unwrap()), dst, &pkt)
                .unwrap();
            st.write_all(&frame).await.unwrap();
            st.flush().await.unwrap();
            let p = tokio::time::timeout(Duration::from_secs(10), xudp::read_packet(&mut st))
                .await
                .expect("XUDP-ответ должен прийти")
                .unwrap()
                .expect("поток не должен закрыться");
            assert_eq!(
                p.source,
                Some((Address::Ipv4("127.0.0.1".parse().unwrap()), dst)),
                "адрес источника ответа"
            );
            assert_eq!(&p.data[2..], &pkt[..], "датаграмма {i}");
            seen_ports.push(u16::from_be_bytes([p.data[0], p.data[1]]));
        }
        seen_ports.dedup();
        assert_eq!(
            seen_ports.len(),
            1,
            "оба назначения должны видеть один порт сервера (Full Cone): {seen_ports:?}"
        );
    }
}

/// TCP-посредник перед Xray: считает соединения клиента с сервером.
async fn counting_forwarder(to: u16) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut s) = TcpStream::connect(("127.0.0.1", to)).await {
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
                }
            });
        }
    });
    (port, n)
}

fn meta(port: u16) -> reality_core::app::Metadata {
    reality_core::app::Metadata {
        inbound: "test".into(),
        source: "127.0.0.1:1".parse().unwrap(),
        network: reality_core::app::Network::Tcp,
        target: Address::Ipv4("127.0.0.1".parse().unwrap()),
        port,
        sniffed: None,
    }
}

/// Mux.Cool: 20 соединений при concurrency = 8 — три потока к серверу,
/// у каждого соединения свои данные.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn mux_cool_tcp_against_xray() {
    use reality_core::app::outbound::Outbound;
    use reality_core::app::vless_out::VlessOutbound;
    ensure_crypto_provider();
    init_log();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "",
            reality_stream("raw", decoy, &keys, vec![], None),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let (fwd, count) = counting_forwarder(port).await;
    let cfg = reality_link(fwd, &uuid, &keys, "&type=tcp");
    let out = VlessOutbound::new("mux", cfg, true).with_mux(8).unwrap();
    let m = meta(echo);
    let mut streams = Vec::new();
    for _ in 0..20 {
        streams.push(out.connect(&m).await.expect("соединение через Mux.Cool"));
    }
    let mut tasks = Vec::new();
    for (i, mut s) in streams.into_iter().enumerate() {
        tasks.push(tokio::spawn(async move {
            echo_roundtrip(&mut s, 64 * 1024 + i * 1000).await;
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "20 соединений по 8 в потоке — 3 потока"
    );
    // С Vision mux не включается.
    let v = reality_link(fwd, &uuid, &keys, "&type=tcp&flow=xtls-rprx-vision");
    assert!(VlessOutbound::new("v", v, true).with_mux(8).is_err());
}

/// gRPC: потоки к одному серверу идут через одно HTTP/2-соединение.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn grpc_streams_share_connection_against_xray() {
    ensure_crypto_provider();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "",
            reality_stream(
                "grpc",
                decoy,
                &keys,
                vec![("grpcSettings", obj(vec![("serviceName", s("pool"))]))],
                None,
            ),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let (fwd, count) = counting_forwarder(port).await;
    let cfg = reality_link(fwd, &uuid, &keys, "&type=grpc&serviceName=pool");
    let (a, p) = target(echo);
    // Первый — отдельно (соединение появляется при нём), остальные разом.
    let mut first = dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
        .await
        .unwrap();
    echo_roundtrip(&mut first, 1000).await;
    let mut tasks = Vec::new();
    for i in 0..10 {
        let (cfg, a) = (cfg.clone(), a.clone());
        tasks.push(tokio::spawn(async move {
            let mut st = dial(&cfg, &cfg.id, VlessCommand::Tcp, a, p).await.unwrap();
            echo_roundtrip(&mut st, 100_000 + i * 777).await;
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// xhttp: по умолчанию сессии делят соединение (xmux 16–32), с
/// `maxConcurrency: 2` — по две на соединение.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn xhttp_xmux_against_xray() {
    ensure_crypto_provider();
    init_log();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let port = free_port();
    let _x = Xray::start(
        vec![vless_inbound(
            port,
            &uuid,
            "",
            reality_stream(
                "xhttp",
                decoy,
                &keys,
                vec![("xhttpSettings", obj(vec![("path", s("/xm"))]))],
                None,
            ),
        )],
        &[port],
        tempdir::Dir::new(),
    )
    .await;
    let (a, p) = target(echo);
    for (rest, want) in [
        ("&type=xhttp&path=%2Fxm", 1),
        ("&type=xhttp&path=%2Fxm&mode=packet-up", 1),
        (
            "&type=xhttp&path=%2Fxm&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A2%7D%7D",
            4,
        ),
    ] {
        let (fwd, count) = counting_forwarder(port).await;
        let cfg = reality_link(fwd, &uuid, &keys, rest);
        let mut streams = Vec::new();
        for _ in 0..8 {
            streams.push(
                dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
                    .await
                    .unwrap_or_else(|e| panic!("{rest}: {e}")),
            );
        }
        let mut tasks = Vec::new();
        for mut st in streams {
            tasks.push(tokio::spawn(async move {
                echo_roundtrip(&mut st, 200_000).await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            want,
            "{rest}: соединений с сервером"
        );
    }
}

/// Дробление ClientHello (`fragment`): REALITY-сервер Xray собирает его и
/// из нескольких TLS-рекордов, и из отдельных TCP-сегментов с паузами —
/// в том числе с Vision.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn fragmented_client_hello_against_xray() {
    use reality_core::transport::fragment::{Fragment, Packets};
    use reality_core::transport::xhttp::Range;
    ensure_crypto_provider();
    init_log();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let (port, vport) = (free_port(), free_port());
    let _x = Xray::start(
        vec![
            vless_inbound(
                port,
                &uuid,
                "",
                reality_stream("raw", decoy, &keys, vec![], None),
            ),
            vless_inbound(
                vport,
                &uuid,
                "xtls-rprx-vision",
                reality_stream("raw", decoy, &keys, vec![], None),
            ),
        ],
        &[port, vport],
        tempdir::Dir::new(),
    )
    .await;
    let r = |a, b| Range { from: a, to: b };
    let cases = [
        (Packets::TlsHello, r(100, 200), r(0, 0)),
        (Packets::TlsHello, r(50, 300), r(5, 15)),
        (Packets::TlsHello, r(1, 3), r(0, 0)),
        (Packets::Writes { from: 1, to: 1 }, r(30, 80), r(2, 6)),
    ];
    let (a, p) = target(echo);
    // Сначала — что именно уходит в сеть: посредник запоминает начало.
    let seen = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fwd = l.local_addr().unwrap().port();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        let (mut c, _) = l.accept().await.unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut head = vec![0u8; 4096];
        let mut got = 0;
        // Рекорды ClientHello (тело 1300+ байт) — первые байты клиента.
        while got < 1200 {
            let n = c.read(&mut head[got..]).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&head[got..got + n]).await.unwrap();
            got += n;
        }
        seen2.lock().unwrap().extend_from_slice(&head[..got]);
        let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
    });
    let mut cfg = reality_link(fwd, &uuid, &keys, "&type=tcp");
    cfg.fragment = Some(Arc::new(Fragment {
        packets: Packets::TlsHello,
        length: r(100, 200),
        interval: r(0, 0),
    }));
    let mut st = dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
        .await
        .unwrap();
    echo_roundtrip(&mut st, 1000).await;
    let wire = seen.lock().unwrap().clone();
    let mut i = 0;
    let mut lens = Vec::new();
    while i + 5 <= wire.len() && wire[i] == 0x16 {
        let l = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
        lens.push(l);
        i += 5 + l;
    }
    assert!(
        lens.len() >= 5,
        "ClientHello раздроблен на рекорды: {lens:?}"
    );
    assert!(
        lens[..lens.len() - 1]
            .iter()
            .all(|l| (100..=200).contains(l)),
        "{lens:?}"
    );

    for (packets, length, interval) in cases {
        for (srv, rest) in [
            (port, "&type=tcp"),
            (vport, "&type=tcp&flow=xtls-rprx-vision"),
        ] {
            let mut cfg = reality_link(srv, &uuid, &keys, rest);
            cfg.fragment = Some(Arc::new(Fragment {
                packets,
                length,
                interval,
            }));
            let mut st = tokio::time::timeout(
                Duration::from_secs(30),
                dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p),
            )
            .await
            .expect("рукопожатие не зависает")
            .unwrap_or_else(|e| panic!("{packets:?} {length:?} {rest}: {e}"));
            echo_roundtrip(&mut st, 100_000).await;
        }
    }
}

/// Отпечатки браузеров (fp=): REALITY-сервер Xray принимает ClientHello
/// Firefox (без GREASE, с долей P-256) и Safari — и с Vision, и через
/// xhttp/gRPC (ALPN h2).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn browser_fingerprints_against_xray() {
    ensure_crypto_provider();
    init_log();
    let decoy = start_decoy().await;
    let echo = start_echo().await;
    let keys = reality_keys();
    let uuid = uuid::Uuid::new_v4();
    let (p_raw, p_vis, p_xh, p_grpc) = (free_port(), free_port(), free_port(), free_port());
    let _x = Xray::start(
        vec![
            vless_inbound(
                p_raw,
                &uuid,
                "",
                reality_stream("raw", decoy, &keys, vec![], None),
            ),
            vless_inbound(
                p_vis,
                &uuid,
                "xtls-rprx-vision",
                reality_stream("raw", decoy, &keys, vec![], None),
            ),
            vless_inbound(
                p_xh,
                &uuid,
                "",
                reality_stream(
                    "xhttp",
                    decoy,
                    &keys,
                    vec![("xhttpSettings", obj(vec![("path", s("/fp"))]))],
                    None,
                ),
            ),
            vless_inbound(
                p_grpc,
                &uuid,
                "",
                reality_stream(
                    "grpc",
                    decoy,
                    &keys,
                    vec![("grpcSettings", obj(vec![("serviceName", s("fp"))]))],
                    None,
                ),
            ),
        ],
        &[p_raw, p_vis, p_xh, p_grpc],
        tempdir::Dir::new(),
    )
    .await;
    let (a, p) = target(echo);
    for fp in ["firefox", "safari", "ios", "edge", "random", "randomized"] {
        for (port, rest) in [
            (p_raw, "&type=tcp"),
            (p_vis, "&type=tcp&flow=xtls-rprx-vision"),
            (p_xh, "&type=xhttp&path=%2Ffp"),
            (p_grpc, "&type=grpc&serviceName=fp"),
        ] {
            let cfg = VlessConfig::parse(&format!(
                "vless://{uuid}@127.0.0.1:{port}?encryption=none&security=reality&sni=decoy.test&fp={fp}&pbk={}&sid={SHORT_ID}{rest}",
                b64(&keys.public)
            ))
            .unwrap();
            let mut st = dial(&cfg, &cfg.id, VlessCommand::Tcp, a.clone(), p)
                .await
                .unwrap_or_else(|e| panic!("fp={fp} {rest}: {e}"));
            echo_roundtrip(&mut st, 200_000).await;
        }
    }
}

fn trojan_inbound(
    port: u16,
    password: &str,
    stream: serde_json_lite::Value,
) -> serde_json_lite::Value {
    obj(vec![
        ("listen", s("127.0.0.1")),
        ("port", n(port as i64)),
        ("protocol", s("trojan")),
        (
            "settings",
            obj(vec![(
                "clients",
                arr(vec![obj(vec![("password", s(password))])]),
            )]),
        ),
        ("streamSettings", stream),
    ])
}

/// Trojan против Xray: TLS (tcp и ws) со своим CA, REALITY; TCP и UDP.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен Xray-core: scripts/interop_xray.sh"]
async fn trojan_against_xray() {
    use reality_core::app::outbound::Outbound;
    use reality_core::app::trojan_out::TrojanOutbound;
    use reality_core::trojan::TrojanConfig;
    ensure_crypto_provider();
    init_log();
    let echo = start_echo().await;
    let udp = start_udp_echo().await;
    let decoy = start_decoy().await;
    let keys = reality_keys();
    let dir = tempdir::Dir::new();
    let (_, _, cert_pem, key_pem) = self_signed("tj.test");
    let cert_path = dir.0.join("cert.pem");
    let key_path = dir.0.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    let tls = |extra: Vec<(&str, serde_json_lite::Value)>, net: &str| {
        let mut v = vec![
            ("network", s(net)),
            ("security", s("tls")),
            (
                "tlsSettings",
                obj(vec![(
                    "certificates",
                    arr(vec![obj(vec![
                        ("certificateFile", s(cert_path.to_string_lossy())),
                        ("keyFile", s(key_path.to_string_lossy())),
                    ])]),
                )]),
            ),
        ];
        v.extend(extra);
        obj(v)
    };
    let pw = "correct horse battery staple";
    let (p_tcp, p_ws, p_real) = (free_port(), free_port(), free_port());
    let _x = Xray::start(
        vec![
            trojan_inbound(p_tcp, pw, tls(vec![], "raw")),
            trojan_inbound(
                p_ws,
                pw,
                tls(vec![("wsSettings", obj(vec![("path", s("/tj"))]))], "ws"),
            ),
            trojan_inbound(
                p_real,
                pw,
                reality_stream("raw", decoy, &keys, vec![], None),
            ),
        ],
        &[p_tcp, p_ws, p_real],
        dir,
    )
    .await;
    let mut roots = RootCertStore::empty();
    for c in rustls_pki_types::pem::PemObject::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let roots = Arc::new(roots);
    let pwe = "correct%20horse%20battery%20staple";
    let links = [
        format!("trojan://{pwe}@127.0.0.1:{p_tcp}?sni=tj.test#tcp"),
        format!("trojan://{pwe}@127.0.0.1:{p_ws}?sni=tj.test&type=ws&path=%2Ftj#ws"),
        format!(
            "trojan://{pwe}@127.0.0.1:{p_real}?security=reality&sni=decoy.test&pbk={}&sid={SHORT_ID}&type=tcp#r",
            b64(&keys.public)
        ),
    ];
    for link in &links {
        let mut cfg = TrojanConfig::parse(link).unwrap();
        cfg.transport.ca_roots = Some(roots.clone());
        let out = TrojanOutbound::new("tj", cfg);
        let mut st = out
            .connect(&meta(echo))
            .await
            .unwrap_or_else(|e| panic!("{link}: {e}"));
        echo_roundtrip(&mut st, 300_000).await;
        // UDP: пакеты туда и обратно.
        let mut m = meta(udp);
        m.network = reality_core::app::Network::Udp;
        let sess = out.udp(&m).await.unwrap();
        for i in 0..5u8 {
            let data = vec![i; 100 + i as usize * 200];
            sess.send(
                Address::Ipv4("127.0.0.1".parse().unwrap()),
                udp,
                data.clone(),
            )
            .await
            .unwrap();
            let (_, port, got) = tokio::time::timeout(Duration::from_secs(10), sess.recv())
                .await
                .expect("UDP-ответ")
                .unwrap()
                .unwrap();
            assert_eq!((port, got), (udp, data), "{link}");
        }
    }
    // Неверный пароль — сервер не проксирует (у Xray — отдаёт как «сайт»).
    let mut cfg =
        TrojanConfig::parse(&format!("trojan://wrong@127.0.0.1:{p_tcp}?sni=tj.test")).unwrap();
    cfg.transport.ca_roots = Some(roots);
    let out = TrojanOutbound::new("bad", cfg);
    if let Ok(mut st) = out.connect(&meta(echo)).await {
        let _ = st.write_all(b"ping").await;
        let mut b = [0u8; 4];
        let r = tokio::time::timeout(Duration::from_secs(5), st.read_exact(&mut b)).await;
        assert!(
            !matches!(r, Ok(Ok(_)) if &b == b"ping"),
            "с неверным паролем эха быть не должно"
        );
    }
}
