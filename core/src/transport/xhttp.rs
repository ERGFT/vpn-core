// SPDX-License-Identifier: GPL-3.0-or-later
//! Транспорт `type=xhttp` (он же SplitHTTP; Xray-core,
//! `transport/internet/splithttp`): VLESS поверх обычных HTTP-запросов,
//! которые проходят через CDN и обратные прокси, не умеющие WebSocket.
//!
//! Три режима (`mode=`), как у Xray:
//!
//! - `stream-one` — один `POST <path>/`: тело запроса — поток «вверх»,
//!   тело ответа — поток «вниз». По умолчанию для REALITY.
//! - `stream-up` — `GET <path>/<session>` отдаёт поток вниз, отдельный
//!   потоковый `POST <path>/<session>` несёт поток вверх (сервер изредка
//!   пишет в ответ на него `X` — чтобы прокси не рвали молчащий запрос;
//!   их отбрасываем).
//! - `packet-up` — поток вниз такой же, а вверх данные идут отдельными
//!   `POST <path>/<session>/<seq>` с `Content-Length` (не больше
//!   `scMaxEachPostBytes`, не чаще `scMinPostsIntervalMs`); сервер
//!   упорядочивает их по `seq`. По умолчанию без REALITY — работает через
//!   любой HTTP-прокси.
//!
//! Версия HTTP выбирается как у Xray (`decideHTTPVersion`): REALITY — h2,
//! без TLS — HTTP/1.1, TLS — HTTP/1.1 только при `alpn=http/1.1`, HTTP/3
//! при `alpn=h3` (QUIC, quinn + h3), иначе h2. HTTP/1.1 — только `packet-up`
//! (как и у Xray на практике: потоковые режимы через HTTP/1.1-прокси не
//! проходят).
//!
//! Маскировка — как у Xray: заголовки Chrome (вариант «fetch»),
//! `Referer` с `x_padding=XXX…` случайной длины (сервер проверяет её
//! диапазон, по умолчанию 100–1000), `Content-Type: application/grpc` у
//! потоковых POST. Параметры тонкой настройки берутся из JSON в `extra=`
//! (как в ссылках Xray): `headers`, `xPaddingBytes`, `noGRPCHeader`,
//! `scMaxEachPostBytes`, `scMinPostsIntervalMs`, `uplinkHTTPMethod`.
//! Настройки, меняющие формат запросов (`xPaddingObfsMode`, размещение
//! session/seq/данных не в пути/теле) не поддерживаются — ссылка с ними
//! отвергается с понятной ошибкой. `downloadSettings` поддерживает
//! отдельный XHTTP-канал с собственной сетью, адресом, портом и TLS либо
//! REALITY; ограничения описаны в `docs/FEATURES.md`.
//!
//! HTTP/2-соединения переиспользуются по правилам `xmux` из `extra=`
//! (`maxConcurrency`, `maxConnections`, `cMaxReuseTimes`,
//! `hMaxRequestTimes`, `hMaxReusableSecs`; без `xmux` — умолчания Xray:
//! 16–32 сессии на соединение, 600–900 запросов, 1800–3000 с), см.
//! [`super::h2pool`]. HTTP/1.1 — соединения на сессию, как раньше.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use futures_util::FutureExt;
use h2::client::{ResponseFuture, SendRequest};
use h2::SendStream;
use http::{Method, Request};
use rand::RngExt;
use tokio::io::{
    duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadBuf,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::fingerprint::Browser;
use crate::transport::browser_headers::{headers as browser_headers, Variant};
use crate::transport::h2pool;
use crate::transport::tcp_tls::{connect_tls_by_security, SecureStream};
use crate::vless::protocol::{vless_connect, Address, Command, VlessStream};
use crate::vless::{Security, VlessConfig};

/// Сколько данных «вниз» может ждать, пока их прочитает приложение.
const DOWN_CAPACITY: usize = 256 * 1024;
/// Буфер «вверх» для потоковых режимов.
const STREAM_UP_CAPACITY: usize = 64 * 1024;
/// Потолок буфера «вверх» для packet-up (у Xray — `scMaxEachPostBytes`,
/// по умолчанию 1 МБ): столько данных может накопиться для одного POST.
const PACKET_UP_CAPACITY_MAX: usize = 1024 * 1024;
/// Сколько POST'ов packet-up могут одновременно ждать ответа. Сервер
/// держит до `scMaxBufferedPosts` (по умолчанию 30) неупорядоченных.
const MAX_INFLIGHT_POSTS: usize = 16;
/// Кусок чтения потока «вверх».
const READ_CHUNK: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    PacketUp,
    StreamUp,
    StreamOne,
}

/// Диапазон `from..=to` (как `Int32Range` у Xray: число или строка "a-b").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub from: u32,
    pub to: u32,
}

impl Range {
    const fn fixed(v: u32) -> Self {
        Range { from: v, to: v }
    }

    pub fn rand(&self) -> u32 {
        if self.from >= self.to {
            self.from
        } else {
            rand::rng().random_range(self.from..=self.to)
        }
    }

    fn parse(key: &str, v: &serde_json::Value) -> Result<Self> {
        let bad = || {
            Error::InvalidUri(format!(
                "xhttp extra: {key} должен быть числом или строкой \"от-до\", а не {v}"
            ))
        };
        let (a, b) = match v {
            serde_json::Value::Number(n) => {
                let x = n.as_u64().ok_or_else(bad)?;
                (x, x)
            }
            serde_json::Value::String(s) => {
                let s = s.trim();
                match s.split_once('-') {
                    Some((a, b)) => (
                        a.trim().parse::<u64>().map_err(|_| bad())?,
                        b.trim().parse::<u64>().map_err(|_| bad())?,
                    ),
                    None => {
                        let x = s.parse::<u64>().map_err(|_| bad())?;
                        (x, x)
                    }
                }
            }
            _ => return Err(bad()),
        };
        let (a, b) = (a.min(u32::MAX as u64) as u32, b.min(u32::MAX as u64) as u32);
        Ok(Range {
            from: a.min(b),
            to: a.max(b),
        })
    }
}

/// Всё, что нужно для построения запросов xhttp, — разобрано из ссылки
/// один раз.
#[derive(Debug, Clone)]
pub struct XhttpSettings {
    pub mode: Mode,
    /// HTTP/1.1 (иначе h2 или h3).
    pub http11: bool,
    /// HTTP/3 поверх QUIC (`alpn=h3`, только `security=tls`).
    pub h3: bool,
    /// `https` в `Referer` и в URI запросов h2.
    pub https: bool,
    /// Заголовок `Host` / `:authority` (без порта — как у Xray).
    pub host: String,
    /// Путь с ведущим и завершающим `/`.
    pub path: String,
    /// Query из `path=` (без `?`), может быть пустым.
    pub query: String,
    /// Заголовки запроса без `Referer`/`Content-Type`/`Content-Length`.
    pub headers: Vec<(String, String)>,
    pub padding: Range,
    pub no_grpc_header: bool,
    pub max_post: Range,
    pub min_interval_ms: Range,
    pub method: String,
    /// Переиспользование HTTP/2-соединений (`xmux`).
    pub xmux: h2pool::Limits,
    /// Отдельная конфигурация потока скачивания (`downloadSettings`).
    download: Option<Box<DownloadSettings>>,
}

#[derive(Debug, Clone)]
struct DownloadSettings {
    cfg: VlessConfig,
    http: XhttpSettings,
}

impl DownloadSettings {
    fn parse(cfg: &VlessConfig, upload: &XhttpSettings, value: &serde_json::Value) -> Result<Self> {
        let invalid =
            |message: String| Error::InvalidUri(format!("xhttp: downloadSettings: {message}"));
        let fields = value
            .as_object()
            .ok_or_else(|| invalid("ожидался JSON-объект".into()))?;
        for key in fields.keys() {
            if !matches!(
                key.as_str(),
                "address"
                    | "port"
                    | "network"
                    | "security"
                    | "tlsSettings"
                    | "realitySettings"
                    | "xhttpSettings"
                    | "sockopt"
            ) {
                return Err(invalid(format!("поле {key} пока не поддерживается")));
            }
        }
        if fields.get("sockopt").is_some_and(|v| !v.is_null()) {
            let empty = fields
                .get("sockopt")
                .and_then(serde_json::Value::as_object)
                .is_some_and(serde_json::Map::is_empty);
            if !empty {
                return Err(invalid(
                    "sockopt пока не поддерживается; уберите его или оставьте пустым".into(),
                ));
            }
        }

        let network = fields
            .get("network")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("network должен быть равен \"xhttp\"".into()))?;
        if network != "xhttp" {
            return Err(invalid(format!(
                "network={network} не поддерживается (пока только xhttp)"
            )));
        }
        let address = fields
            .get("address")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&cfg.host)
            .to_string();
        if !crate::http1::request_part_ok(&address) {
            return Err(invalid(
                "address содержит управляющие символы или пробелы".into(),
            ));
        }
        let port = match fields.get("port") {
            None | Some(serde_json::Value::Null) => cfg.port,
            Some(v) => v
                .as_u64()
                .filter(|n| (1..=u16::MAX as u64).contains(n))
                .map(|n| n as u16)
                .ok_or_else(|| invalid("port должен быть числом от 1 до 65535".into()))?,
        };
        let security = match fields.get("security").and_then(serde_json::Value::as_str) {
            Some("none") => Security::None,
            Some("tls") => Security::Tls,
            Some("reality") => Security::Reality,
            Some(other) => {
                return Err(invalid(format!(
                    "security={other} не поддерживается (none, tls или reality)"
                )))
            }
            None => return Err(invalid("укажите security: none, tls или reality".into())),
        };

        let mut download_cfg = cfg.clone();
        download_cfg.host = address;
        download_cfg.port = port;
        download_cfg.security = security;
        download_cfg.network = crate::vless::NetworkType::Xhttp;
        download_cfg
            .raw_params
            .insert("type".into(), "xhttp".into());
        download_cfg.raw_params.insert(
            "security".into(),
            match security {
                Security::None => "none",
                Security::Tls => "tls",
                Security::Reality => "reality",
            }
            .into(),
        );

        let tls_settings = fields.get("tlsSettings");
        let reality_settings = fields.get("realitySettings");
        match security {
            Security::None => {
                if tls_settings.is_some_and(|v| !v.is_null())
                    || reality_settings.is_some_and(|v| !v.is_null())
                {
                    return Err(invalid(
                        "tlsSettings/realitySettings нельзя задавать с security=none".into(),
                    ));
                }
                download_cfg.sni = None;
                download_cfg.raw_params.remove("sni");
                download_cfg.raw_params.remove("alpn");
            }
            Security::Tls => {
                if reality_settings.is_some_and(|v| !v.is_null()) {
                    return Err(invalid(
                        "realitySettings нельзя задавать с security=tls".into(),
                    ));
                }
                let mut alpn = None;
                if let Some(v) = tls_settings.filter(|v| !v.is_null()) {
                    let m = v
                        .as_object()
                        .ok_or_else(|| invalid("tlsSettings должен быть объектом".into()))?;
                    for key in m.keys() {
                        if !matches!(key.as_str(), "serverName" | "alpn") {
                            return Err(invalid(format!(
                                "tlsSettings.{key} пока не поддерживается"
                            )));
                        }
                    }
                    if let Some(v) = m.get("serverName") {
                        let name = v.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
                            invalid("tlsSettings.serverName должен быть непустой строкой".into())
                        })?;
                        download_cfg.sni = Some(name.to_string());
                        download_cfg
                            .raw_params
                            .insert("sni".into(), name.to_string());
                    } else {
                        download_cfg.sni = None;
                        download_cfg.raw_params.remove("sni");
                    }
                    if let Some(v) = m.get("alpn") {
                        let values = v.as_array().ok_or_else(|| {
                            invalid("tlsSettings.alpn должен быть массивом строк".into())
                        })?;
                        let values: Vec<String> = values
                            .iter()
                            .map(|x| {
                                x.as_str()
                                    .filter(|s| !s.is_empty())
                                    .map(str::to_string)
                                    .ok_or_else(|| {
                                        invalid(
                                            "tlsSettings.alpn должен быть массивом непустых строк"
                                                .into(),
                                        )
                                    })
                            })
                            .collect::<Result<_>>()?;
                        if values.is_empty()
                            || values
                                .iter()
                                .any(|x| !matches!(x.as_str(), "h2" | "http/1.1" | "h3"))
                        {
                            return Err(invalid(
                                "tlsSettings.alpn поддерживает только h2, http/1.1 и h3".into(),
                            ));
                        }
                        if values.iter().any(|x| x == "h3") && values.len() != 1 {
                            return Err(invalid(
                                "tlsSettings.alpn=h3 должен быть единственным значением".into(),
                            ));
                        }
                        alpn = Some(values);
                    }
                } else {
                    download_cfg.sni = None;
                    download_cfg.raw_params.remove("sni");
                }
                if let Some(values) = alpn {
                    download_cfg
                        .raw_params
                        .insert("alpn".into(), values.join(","));
                } else {
                    download_cfg.raw_params.remove("alpn");
                }
            }
            Security::Reality => {
                if tls_settings.is_some_and(|v| !v.is_null()) {
                    return Err(invalid(
                        "tlsSettings нельзя задавать с security=reality".into(),
                    ));
                }
                let m = reality_settings
                    .and_then(serde_json::Value::as_object)
                    .ok_or_else(|| invalid("realitySettings должен быть объектом".into()))?;
                for key in m.keys() {
                    if !matches!(key.as_str(), "serverName" | "publicKey" | "shortId") {
                        return Err(invalid(format!(
                            "realitySettings.{key} пока не поддерживается"
                        )));
                    }
                }
                let name = m
                    .get("serverName")
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| invalid("realitySettings.serverName обязателен".into()))?;
                let public_key = m
                    .get("publicKey")
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| invalid("realitySettings.publicKey обязателен".into()))?;
                let short_id = m
                    .get("shortId")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if short_id.len() > 16
                    || short_id.len() % 2 != 0
                    || !short_id.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(invalid(
                        "realitySettings.shortId должен быть hex-строкой до 16 символов".into(),
                    ));
                }
                download_cfg.sni = Some(name.to_string());
                download_cfg
                    .raw_params
                    .insert("sni".into(), name.to_string());
                download_cfg
                    .raw_params
                    .insert("pbk".into(), public_key.to_string());
                download_cfg
                    .raw_params
                    .insert("sid".into(), short_id.to_string());
                download_cfg.reality_params()?;
                download_cfg.raw_params.remove("alpn");
            }
        }

        let xhttp = fields
            .get("xhttpSettings")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| invalid("xhttpSettings должен быть объектом".into()))?;
        for key in xhttp.keys() {
            if !matches!(key.as_str(), "host" | "path") {
                return Err(invalid(format!(
                    "xhttpSettings.{key} пока не поддерживается"
                )));
            }
        }
        let path = xhttp
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(cfg.path());
        let normalize_path = |v: &str| {
            let (p, q) = v.split_once('?').unwrap_or((v, ""));
            let mut p = if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{p}")
            };
            if !p.ends_with('/') {
                p.push('/');
            }
            (p, q.to_string())
        };
        let (path, query) = normalize_path(path);
        let (upload_path, upload_query) = normalize_path(cfg.path());
        if path != upload_path || query != upload_query {
            return Err(invalid(
                "xhttpSettings.path должен совпадать с path основного канала".into(),
            ));
        }
        let host = xhttp
            .get("host")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                if security == Security::None {
                    download_cfg.host.clone()
                } else {
                    download_cfg.effective_sni().to_string()
                }
            });
        if !crate::http1::request_part_ok(&host) {
            return Err(invalid(
                "xhttpSettings.host содержит управляющие символы или пробелы".into(),
            ));
        }
        let alpn = download_cfg.alpn();
        let http11 = match security {
            Security::None => true,
            Security::Reality => false,
            Security::Tls => {
                matches!(alpn.as_deref(), Some([one]) if one.as_slice() == b"http/1.1")
            }
        };
        let h3 = matches!(alpn.as_deref(), Some([one]) if one.as_slice() == b"h3");
        if h3 && security != Security::Tls {
            return Err(invalid("HTTP/3 требует security=tls".into()));
        }
        let mut http = upload.clone();
        http.host = host;
        http.path = path;
        http.query = query;
        http.https = security != Security::None;
        http.http11 = http11;
        http.h3 = h3;
        http.download = None;
        Ok(Self {
            cfg: download_cfg,
            http,
        })
    }
}

/// `xmux` по умолчанию — как у Xray, когда в настройках его нет.
pub const XMUX_DEFAULT: h2pool::Limits = h2pool::Limits {
    max_concurrency: Range { from: 16, to: 32 },
    max_connections: 0,
    max_reuse: Range { from: 0, to: 0 },
    max_requests: Range { from: 600, to: 900 },
    max_age_secs: Range {
        from: 1800,
        to: 3000,
    },
};

fn parse_xmux(v: &serde_json::Value) -> Result<h2pool::Limits> {
    let m = match v {
        serde_json::Value::Null => return Ok(XMUX_DEFAULT),
        serde_json::Value::Object(m) => m,
        _ => {
            return Err(Error::InvalidUri(
                "xhttp extra: xmux должен быть объектом".into(),
            ))
        }
    };
    let zero = Range { from: 0, to: 0 };
    let mut l = h2pool::Limits {
        max_concurrency: zero,
        max_connections: 0,
        max_reuse: zero,
        max_requests: zero,
        max_age_secs: zero,
    };
    let mut any = false;
    for (k, v) in m {
        let r = Range::parse(k, v)?;
        any |= r.to != 0;
        match k.as_str() {
            "maxConcurrency" => l.max_concurrency = r,
            "maxConnections" => l.max_connections = r.rand(),
            "cMaxReuseTimes" => l.max_reuse = r,
            "hMaxRequestTimes" => l.max_requests = r,
            "hMaxReusableSecs" => l.max_age_secs = r,
            "hKeepAlivePeriod" => {}
            other => {
                tracing::warn!(key = %other, "xhttp extra: xmux: неизвестный параметр, пропущен")
            }
        }
    }
    if !any {
        return Ok(XMUX_DEFAULT);
    }
    if l.max_concurrency.to != 0 && l.max_connections != 0 {
        return Err(Error::InvalidUri(
            "xhttp extra: xmux: maxConnections и maxConcurrency вместе не задаются (как у Xray)"
                .into(),
        ));
    }
    Ok(l)
}

impl XhttpSettings {
    pub fn from_config(cfg: &VlessConfig) -> Result<Self> {
        let extra: serde_json::Map<String, serde_json::Value> = match cfg.raw_params.get("extra") {
            Some(s) if !s.trim().is_empty() => match serde_json::from_str(s) {
                Ok(serde_json::Value::Object(m)) => m,
                Ok(_) => {
                    return Err(Error::InvalidUri(
                        "xhttp: extra= должен быть JSON-объектом".into(),
                    ))
                }
                Err(e) => {
                    return Err(Error::InvalidUri(format!(
                        "xhttp: extra= не разбирается как JSON: {e}"
                    )))
                }
            },
            _ => serde_json::Map::new(),
        };

        let mut padding = Range {
            from: 100,
            to: 1000,
        };
        let mut no_grpc_header = false;
        let mut max_post = Range::fixed(1_000_000);
        let mut min_interval_ms = Range::fixed(30);
        let mut method = "POST".to_string();
        let mut user_headers: Vec<(String, String)> = Vec::new();
        let mut has_download_settings = false;
        let mut xmux = XMUX_DEFAULT;

        for (k, v) in &extra {
            let non_default_str = |allowed: &[&str]| -> bool {
                match v.as_str() {
                    Some(s) => !allowed.contains(&s),
                    None => !v.is_null(),
                }
            };
            match k.as_str() {
                "headers" => {
                    let m = v.as_object().ok_or_else(|| {
                        Error::InvalidUri("xhttp extra: headers должен быть объектом".into())
                    })?;
                    for (hk, hv) in m {
                        if hk.eq_ignore_ascii_case("host") {
                            return Err(Error::InvalidUri(
                                "xhttp extra: headers не может содержать host (задайте host=)"
                                    .into(),
                            ));
                        }
                        let hv = hv.as_str().ok_or_else(|| {
                            Error::InvalidUri(format!(
                                "xhttp extra: значение заголовка {hk} должно быть строкой"
                            ))
                        })?;
                        user_headers.push((canonical_header(hk), hv.to_string()));
                    }
                }
                "xPaddingBytes" => {
                    let r = Range::parse(k, v)?;
                    if r.to != 0 {
                        if r.from == 0 {
                            return Err(Error::InvalidUri(
                                "xhttp extra: xPaddingBytes нельзя отключить".into(),
                            ));
                        }
                        padding = r;
                    }
                }
                "noGRPCHeader" => no_grpc_header = v.as_bool().unwrap_or(false),
                "scMaxEachPostBytes" => {
                    let r = Range::parse(k, v)?;
                    if r.to != 0 {
                        if r.from == 0 {
                            return Err(Error::InvalidUri(
                                "xhttp extra: scMaxEachPostBytes должен быть больше 0".into(),
                            ));
                        }
                        max_post = r;
                    }
                }
                "scMinPostsIntervalMs" => {
                    let r = Range::parse(k, v)?;
                    if r.to != 0 {
                        min_interval_ms = r;
                    }
                }
                "uplinkHTTPMethod" => {
                    let m = v.as_str().unwrap_or("").trim().to_ascii_uppercase();
                    if m == "GET" {
                        return Err(Error::InvalidUri(
                            "xhttp: uplinkHTTPMethod=GET (данные в заголовках/cookie) не поддерживается"
                                .into(),
                        ));
                    }
                    if !m.is_empty() {
                        method = m;
                    }
                }
                "xPaddingObfsMode" => {
                    if v.as_bool().unwrap_or(false) {
                        return Err(Error::InvalidUri(
                            "xhttp: xPaddingObfsMode не поддерживается".into(),
                        ));
                    }
                }
                "sessionIDPlacement" | "seqPlacement" => {
                    if non_default_str(&["", "path"]) {
                        return Err(Error::InvalidUri(format!(
                            "xhttp: {k}={v} не поддерживается (только path)"
                        )));
                    }
                }
                "uplinkDataPlacement" => {
                    if non_default_str(&["", "auto", "body"]) {
                        return Err(Error::InvalidUri(format!(
                            "xhttp: uplinkDataPlacement={v} не поддерживается (только body)"
                        )));
                    }
                }
                "downloadSettings" => has_download_settings = !v.is_null(),
                "xmux" => xmux = parse_xmux(v)?,
                // Серверные или не влияющие на формат настройки, а также
                // то, что Xray берёт не из extra (host/path/mode).
                "noSSEHeader"
                | "scMaxBufferedPosts"
                | "scStreamUpServerSecs"
                | "serverMaxHeaderBytes"
                | "host"
                | "path"
                | "mode"
                | "xPaddingKey"
                | "xPaddingHeader"
                | "xPaddingPlacement"
                | "xPaddingMethod"
                | "sessionIDKey"
                | "seqKey"
                | "uplinkDataKey"
                | "uplinkChunkSize"
                | "sessionIDTable"
                | "sessionIDLength" => {
                    tracing::debug!(key = %k, "xhttp extra: параметр не влияет на этого клиента");
                }
                other => {
                    tracing::warn!(key = %other, "xhttp extra: неизвестный параметр, пропущен")
                }
            }
        }
        let https = cfg.security != Security::None;
        let alpn = cfg.alpn();
        let wants_h3 = alpn
            .as_deref()
            .is_some_and(|a| matches!(a, [one] if one.as_slice() == b"h3"));
        if wants_h3 && cfg.security != Security::Tls {
            return Err(Error::InvalidUri(
                "xhttp: HTTP/3 (alpn=h3) — только с security=tls (REALITY работает поверх TCP)"
                    .into(),
            ));
        }
        let h3 = wants_h3;
        let http11 = match cfg.security {
            Security::None => true,
            Security::Reality => false,
            Security::Tls => {
                matches!(alpn.as_deref(), Some([one]) if one.as_slice() == b"http/1.1")
            }
        };

        let mode = match cfg.raw_params.get("mode").map(|s| s.as_str()).unwrap_or("") {
            "" | "auto" => {
                if cfg.security == Security::Reality && !has_download_settings {
                    Mode::StreamOne
                } else if cfg.security == Security::Reality {
                    Mode::StreamUp
                } else {
                    Mode::PacketUp
                }
            }
            "packet-up" => Mode::PacketUp,
            "stream-up" => Mode::StreamUp,
            "stream-one" => Mode::StreamOne,
            other => {
                return Err(Error::InvalidUri(format!(
                    "xhttp: mode={other} неизвестен (auto, packet-up, stream-up, stream-one)"
                )))
            }
        };
        if http11 && mode != Mode::PacketUp {
            return Err(Error::InvalidUri(format!(
                "xhttp: режим {mode:?} через HTTP/1.1 не поддерживается — используйте \
                 mode=packet-up или h2 (security=tls без alpn=http/1.1, либо reality)"
            )));
        }
        if has_download_settings && mode == Mode::StreamOne {
            return Err(Error::InvalidUri(
                "xhttp: mode=stream-one не совместим с downloadSettings; используйте stream-up или packet-up".into(),
            ));
        }

        // Host: host= > SNI (для tls/reality) > адрес сервера.
        let host = match cfg.raw_params.get("host") {
            Some(h) if !h.is_empty() => h.clone(),
            _ if cfg.security != Security::None => cfg.effective_sni().to_string(),
            _ => cfg.host.clone(),
        };

        let raw_path = cfg.path();
        let (p, q) = raw_path.split_once('?').unwrap_or((raw_path, ""));
        let mut path = if p.starts_with('/') {
            p.to_string()
        } else {
            format!("/{p}")
        };
        if !path.ends_with('/') {
            path.push('/');
        }

        // Заголовки: пользовательские; если User-Agent не задан (или
        // задан как "chrome") — поверх заголовки Chrome, как у Xray
        // (`TryDefaultHeadersWith(header, "fetch")`).
        let ua = user_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.clone());
        // User-Agent не задан — заголовки браузера из fp=; «chrome»,
        // «firefox», «safari» — заголовки этого браузера.
        let browser = match ua.as_deref() {
            None => Some(cfg.browser),
            Some("chrome") => Some(Browser::Chrome),
            Some("firefox") => Some(Browser::Firefox),
            Some("safari") => Some(Browser::Safari),
            Some(_) => None,
        };
        let headers = if let Some(b) = browser {
            let defaults = browser_headers(b, Variant::Fetch);
            let mut h: Vec<(String, String)> = user_headers
                .into_iter()
                .filter(|(k, _)| !defaults.iter().any(|(c, _)| c.eq_ignore_ascii_case(k)))
                .collect();
            h.extend(defaults.into_iter().map(|(k, v)| (k.to_string(), v)));
            h
        } else {
            user_headers
        };

        // HTTP/1.1-запрос собирается `format!`: перевод строки в
        // host/path/query (после percent-decoding) или в значении
        // пользовательского заголовка добавил бы в запрос свои строки.
        if !crate::http1::request_part_ok(&host)
            || !crate::http1::request_part_ok(&path)
            || !crate::http1::request_part_ok(q)
        {
            return Err(Error::InvalidUri(
                "xhttp: host/path содержит управляющие символы или пробелы".into(),
            ));
        }
        for (k, v) in &headers {
            if !crate::http1::header_value_ok(k) || !crate::http1::header_value_ok(v) {
                return Err(Error::InvalidUri(format!(
                    "xhttp: заголовок «{k}» содержит управляющие символы"
                )));
            }
        }

        let mut settings = XhttpSettings {
            mode,
            http11,
            h3,
            https,
            host,
            path,
            query: q.to_string(),
            headers,
            padding,
            no_grpc_header,
            max_post,
            min_interval_ms,
            method,
            xmux,
            download: None,
        };
        if let Some(download) = extra.get("downloadSettings").filter(|v| !v.is_null()) {
            settings.download = Some(Box::new(DownloadSettings::parse(cfg, &settings, download)?));
        }
        Ok(settings)
    }

    /// Путь запроса: базовый путь, затем session и seq (если есть), затем
    /// query из `path=`.
    pub fn url_path(&self, session: Option<&str>, seq: Option<u64>) -> String {
        let mut p = self.path.clone();
        if let Some(s) = session {
            p.push_str(s);
            if let Some(n) = seq {
                p.push('/');
                p.push_str(&n.to_string());
            }
        }
        if !self.query.is_empty() {
            p.push('?');
            p.push_str(&self.query);
        }
        p
    }

    /// `Referer: <scheme>://<host><path>?x_padding=XXX…` — так Xray прячет
    /// padding; сервер проверяет длину.
    pub fn referer(&self) -> String {
        format!(
            "{}://{}{}?x_padding={}",
            if self.https { "https" } else { "http" },
            self.host,
            self.path,
            "X".repeat(self.padding.rand() as usize)
        )
    }

    /// Заголовки конкретного запроса. `stream_body` — потоковый POST
    /// (stream-up/one): к нему `Content-Type: application/grpc`.
    pub fn request_headers(&self, stream_body: bool) -> Vec<(String, String)> {
        let mut h = self.headers.clone();
        h.push(("Referer".into(), self.referer()));
        if stream_body && !self.no_grpc_header {
            h.push(("Content-Type".into(), "application/grpc".into()));
        }
        h
    }

    fn authority_uri(&self, path: &str) -> String {
        format!(
            "{}://{}{}",
            if self.https { "https" } else { "http" },
            self.host,
            path
        )
    }
}

/// `x-foo-bar` → `X-Foo-Bar`, как `http.Header.Add` в Go.
fn canonical_header(k: &str) -> String {
    let mut out = String::with_capacity(k.len());
    let mut upper = true;
    for c in k.chars() {
        if upper {
            out.extend(c.to_uppercase());
        } else {
            out.extend(c.to_lowercase());
        }
        upper = c == '-';
    }
    out
}

/// Общее состояние сессии: первая ошибка (её увидит приложение вместо
/// «соединение закрыто») и сигнал остановки всех фоновых задач.
#[derive(Default)]
struct Shared {
    err: Mutex<Option<String>>,
    cancel: CancellationToken,
    /// Место в общем HTTP/2-соединении (xmux) — на всю сессию.
    lease: std::sync::OnceLock<h2pool::Lease>,
    /// То же для HTTP/3.
    lease3: std::sync::OnceLock<h2pool::Lease<h3c::Send3>>,
    /// Дополнительное соединение для XHTTP-канала скачивания.
    download_lease: std::sync::OnceLock<h2pool::Lease>,
    /// То же для HTTP/3.
    download_lease3: std::sync::OnceLock<h2pool::Lease<h3c::Send3>>,
}

impl Shared {
    fn fail(&self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::debug!(error = %msg, "xhttp: сессия прервана");
        let mut e = self
            .err
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if e.is_none() {
            *e = Some(msg);
        }
        drop(e);
        self.cancel.cancel();
    }

    fn error(&self) -> Option<String> {
        self.err
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Поток xhttp для вызывающего кода: чтение — из потока «вниз», запись —
/// в поток «вверх». Сброс (`drop`) останавливает фоновые задачи: у h2
/// запросы отменяются (RST_STREAM), у HTTP/1.1 закрываются соединения —
/// так сервер узнаёт о конце сессии и в режиме packet-up.
pub struct XhttpStream {
    down: DuplexStream,
    up: DuplexStream,
    shared: Arc<Shared>,
}

impl Drop for XhttpStream {
    fn drop(&mut self) {
        self.shared.cancel.cancel();
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        match Pin::new(&mut this.down).poll_read(cx, out) {
            Poll::Ready(Ok(())) if out.filled().len() == before && out.remaining() > 0 => {
                match this.shared.error() {
                    Some(e) => Poll::Ready(Err(io::Error::other(e))),
                    None => Poll::Ready(Ok(())),
                }
            }
            other => other,
        }
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(e) = this.shared.error() {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        Pin::new(&mut this.up).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().up).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().up).poll_shutdown(cx)
    }
}

/// Поднять xhttp-сессию.
pub async fn connect_xhttp(cfg: &VlessConfig) -> Result<XhttpStream> {
    let st = Arc::new(XhttpSettings::from_config(cfg)?);
    let up_cap = match st.mode {
        Mode::PacketUp => (st.max_post.to as usize).clamp(READ_CHUNK, PACKET_UP_CAPACITY_MAX),
        _ => STREAM_UP_CAPACITY,
    };
    let (user_down, int_down) = duplex(DOWN_CAPACITY);
    let (user_up, int_up) = duplex(up_cap);
    let shared = Arc::new(Shared::default());
    tracing::debug!(
        mode = ?st.mode,
        http = if st.http11 { "1.1" } else if st.h3 { "3" } else { "2" },
        host = %st.host,
        "xhttp: соединение"
    );
    // Фоновые задачи запускаются по ходу настройки; если она оборвётся
    // (ошибка или таймаут вызывающего кода), XhttpStream не появится и
    // не остановит их при сбросе — это делает страж.
    let guard = CancelOnDrop(Some(shared.clone()));
    if st.http11 {
        h1::start(cfg, st, int_down, int_up, shared.clone()).await?;
    } else if st.h3 {
        h3c::start(cfg, st, int_down, int_up, shared.clone()).await?;
    } else {
        h2c::start(cfg, st, int_down, int_up, shared.clone()).await?;
    }
    guard.disarm();
    Ok(XhttpStream {
        down: user_down,
        up: user_up,
        shared,
    })
}

async fn start_download(
    settings: &DownloadSettings,
    session: &str,
    down: DuplexStream,
    shared: Arc<Shared>,
) -> Result<()> {
    if settings.http.http11 {
        h1::start_download(&settings.cfg, &settings.http, session, down, shared).await
    } else if settings.http.h3 {
        h3c::start_download(&settings.cfg, &settings.http, session, down, shared).await
    } else {
        h2c::start_download(&settings.cfg, &settings.http, session, down, shared).await
    }
}

struct CancelOnDrop(Option<Arc<Shared>>);

impl CancelOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(s) = self.0.take() {
            s.cancel.cancel();
        }
    }
}

/// Полное открытие соединения: транспорт + заголовок VLESS.
pub async fn connect_command_xhttp(
    cfg: &VlessConfig,
    id: &Uuid,
    command: Command,
    target: Address,
    target_port: u16,
) -> Result<VlessStream<XhttpStream>> {
    cfg.ensure_flow_supported()?;
    let stream = connect_xhttp(cfg).await?;
    vless_connect(stream, id, command, &target, target_port).await
}

fn status_hint(status: u16) -> &'static str {
    match status {
        404 => " (неверный path или host, либо это не xhttp-вход)",
        400 => {
            " (сервер отверг запрос: mode не совпадает с настройкой входа или не прошёл padding)"
        }
        413 => " (POST больше, чем разрешает сервер: уменьшите scMaxEachPostBytes)",
        _ => "",
    }
}

/// Собрать очередную порцию данных «вверх» для packet-up: дождаться хотя
/// бы одного байта, выдержать интервал между POST'ами (за это время
/// подтягиваются новые данные — у Xray так же склеиваются мелкие записи)
/// и забрать всё, что уже есть, но не больше `max`.
async fn next_packet(
    r: &mut DuplexStream,
    max: usize,
    last: &mut Option<Instant>,
    interval: Range,
) -> io::Result<Option<Bytes>> {
    let mut buf = BytesMut::with_capacity(READ_CHUNK.min(max));
    let mut tmp = vec![0u8; READ_CHUNK.min(max)];
    let n = r.read(&mut tmp).await?;
    if n == 0 {
        return Ok(None);
    }
    buf.extend_from_slice(&tmp[..n]);
    if let Some(t) = *last {
        let wait = Duration::from_millis(interval.rand() as u64);
        tokio::time::sleep_until((t + wait).into()).await;
    }
    while buf.len() < max {
        let want = (max - buf.len()).min(tmp.len());
        match r.read(&mut tmp[..want]).now_or_never() {
            Some(Ok(n)) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
    *last = Some(Instant::now());
    Ok(Some(buf.freeze()))
}

/// HTTP/2 (TLS или REALITY).
mod h2c {
    use super::*;

    fn builder() -> h2::client::Builder {
        // Настройки HTTP/2 как у Chrome (SETTINGS и WINDOW_UPDATE):
        // заодно большие окна не дают упереться в 64 КиБ по умолчанию.
        let mut b = h2::client::Builder::new();
        b.header_table_size(65536)
            .enable_push(false)
            .initial_window_size(6 * 1024 * 1024)
            .initial_connection_window_size(15 * 1024 * 1024)
            .max_header_list_size(262144);
        b
    }

    pub(super) fn request(
        st: &XhttpSettings,
        method: &str,
        path: &str,
        stream_body: bool,
        content_length: Option<usize>,
    ) -> Result<Request<()>> {
        let mut b = Request::builder()
            .method(
                Method::from_bytes(method.as_bytes())
                    .map_err(|_| Error::InvalidUri(format!("xhttp: метод {method}")))?,
            )
            .uri(st.authority_uri(path));
        for (k, v) in st.request_headers(stream_body) {
            b = b.header(k, v);
        }
        if let Some(n) = content_length {
            b = b.header(http::header::CONTENT_LENGTH, n);
        }
        b.body(())
            .map_err(|e| Error::Protocol(format!("xhttp: не удалось собрать запрос: {e}")))
    }

    fn connect(
        c: VlessConfig,
    ) -> futures_util::future::BoxFuture<'static, Result<h2pool::Connected>> {
        Box::pin(async move {
            let alpn = c
                .alpn()
                .unwrap_or_else(|| vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
            let tls = connect_tls_by_security(&c, alpn).await?;
            if c.security == Security::Tls {
                if let Some(p) = tls.alpn() {
                    if p != b"h2" {
                        return Err(Error::Protocol(format!(
                            "xhttp: сервер выбрал ALPN {}, а не h2 — для HTTP/1.1 укажите alpn=http/1.1",
                            String::from_utf8_lossy(&p)
                        )));
                    }
                }
            }
            let (send, conn) = builder()
                .handshake::<SecureStream, Bytes>(tls)
                .await
                .map_err(|e| Error::Protocol(format!("xhttp: h2 handshake не удался: {e}")))?;
            let driver: futures_util::future::BoxFuture<'static, ()> = Box::pin(async move {
                if let Err(e) = conn.await {
                    tracing::debug!(error = %e, "xhttp: h2-соединение завершилось");
                }
            });
            Ok((send, driver))
        })
    }

    async fn acquire(cfg: &VlessConfig, st: &XhttpSettings) -> Result<h2pool::Lease> {
        let c = cfg.clone();
        h2pool::acquire(&format!("xhttp|{}", cfg.pool_key()), &st.xmux, move || {
            connect(c.clone())
        })
        .await
    }

    pub(super) async fn start_download(
        cfg: &VlessConfig,
        st: &XhttpSettings,
        session: &str,
        down: DuplexStream,
        shared: Arc<Shared>,
    ) -> Result<()> {
        let lease = acquire(cfg, st).await?;
        let mut send = lease
            .request()
            .ready()
            .await
            .map_err(|e| Error::Protocol(format!("xhttp: h2 не готов: {e}")))?;
        let req = request(st, "GET", &st.url_path(Some(session), None), false, None)?;
        let (resp, _) = send
            .send_request(req, true)
            .map_err(|e| Error::Protocol(format!("xhttp: h2: {e}")))?;
        let _ = shared.download_lease.set(lease);
        tokio::spawn(download(resp, down, shared, "GET"));
        Ok(())
    }

    pub(super) async fn start(
        cfg: &VlessConfig,
        st: Arc<XhttpSettings>,
        down: DuplexStream,
        up: DuplexStream,
        shared: Arc<Shared>,
    ) -> Result<()> {
        // Сессии к одному серверу делят HTTP/2-соединения по правилам
        // xmux (как у Xray): меньше рукопожатий TLS/REALITY.
        let lease = acquire(cfg, &st).await?;
        let split_download = st
            .download
            .as_deref()
            .is_some_and(|download| download.cfg.pool_key() != cfg.pool_key());
        let send = if split_download {
            lease.sender()
        } else {
            lease.request()
        };
        let _ = shared.lease.set(lease);
        let mut send = send
            .ready()
            .await
            .map_err(|e| Error::Protocol(format!("xhttp: h2 не готов: {e}")))?;
        let h2err = |e: h2::Error| Error::Protocol(format!("xhttp: h2: {e}"));

        match st.mode {
            Mode::StreamOne => {
                let req = request(&st, &st.method, &st.url_path(None, None), true, None)?;
                let (resp, tx) = send.send_request(req, false).map_err(h2err)?;
                tokio::spawn(download(resp, down, shared.clone(), "POST (stream-one)"));
                tokio::spawn(upload_stream(tx, up, shared));
            }
            Mode::StreamUp | Mode::PacketUp => {
                let session = Uuid::new_v4().to_string();
                if let Some(download) = st
                    .download
                    .as_deref()
                    .filter(|download| download.cfg.pool_key() != cfg.pool_key())
                {
                    super::start_download(download, &session, down, shared.clone()).await?;
                } else {
                    let get_settings = st.download.as_deref().map_or(st.as_ref(), |d| &d.http);
                    let get = request(
                        get_settings,
                        "GET",
                        &get_settings.url_path(Some(&session), None),
                        false,
                        None,
                    )?;
                    let (resp, _) = send.send_request(get, true).map_err(h2err)?;
                    tokio::spawn(download(resp, down, shared.clone(), "GET"));
                }
                if st.mode == Mode::StreamUp {
                    let mut send = send
                        .ready()
                        .await
                        .map_err(|e| Error::Protocol(format!("xhttp: h2 не готов: {e}")))?;
                    if let Some(l) = shared.lease.get() {
                        l.note_request();
                    }
                    let req = request(
                        &st,
                        &st.method,
                        &st.url_path(Some(&session), None),
                        true,
                        None,
                    )?;
                    let (resp, tx) = send.send_request(req, false).map_err(h2err)?;
                    tokio::spawn(discard_response(resp, shared.clone(), "POST (stream-up)"));
                    tokio::spawn(upload_stream(tx, up, shared));
                } else {
                    tokio::spawn(packet_uploader(send, st, session, up, shared));
                }
            }
        }
        Ok(())
    }

    /// Поток «вниз»: тело ответа — в приложение.
    async fn download(resp: ResponseFuture, mut w: DuplexStream, shared: Arc<Shared>, what: &str) {
        let work = async {
            let r = resp
                .await
                .map_err(|e| format!("xhttp: сервер не ответил на {what}: {e}"))?;
            let status = r.status().as_u16();
            if status != 200 {
                return Err(format!(
                    "xhttp: сервер ответил {status} на {what}{}",
                    status_hint(status)
                ));
            }
            let mut body = r.into_body();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|e| format!("xhttp: поток вниз оборвался: {e}"))?;
                let _ = body.flow_control().release_capacity(chunk.len());
                if w.write_all(&chunk).await.is_err() {
                    break; // приложение закрыло поток
                }
            }
            Ok(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }

    async fn discard_response(resp: ResponseFuture, shared: Arc<Shared>, what: &'static str) {
        let work = async {
            let r = resp
                .await
                .map_err(|e| format!("xhttp: сервер не ответил на {what}: {e}"))?;
            let status = r.status().as_u16();
            if status != 200 {
                return Err(format!(
                    "xhttp: сервер ответил {status} на {what}{}",
                    status_hint(status)
                ));
            }
            let mut body = r.into_body();
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            Ok(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }

    /// Отправить `data` с учётом окна получателя.
    async fn send_all(
        tx: &mut SendStream<Bytes>,
        mut data: Bytes,
        end: bool,
    ) -> std::result::Result<(), String> {
        while !data.is_empty() {
            tx.reserve_capacity(data.len());
            match std::future::poll_fn(|cx| tx.poll_capacity(cx)).await {
                Some(Ok(0)) => continue,
                Some(Ok(c)) => {
                    let part = data.split_to(c.min(data.len()));
                    tx.send_data(part, false).map_err(|e| e.to_string())?;
                }
                Some(Err(e)) => return Err(e.to_string()),
                None => return Err("поток закрыт".into()),
            }
        }
        if end {
            tx.send_data(Bytes::new(), true)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Потоковый «вверх» (stream-one, stream-up): тело одного POST.
    async fn upload_stream(mut tx: SendStream<Bytes>, mut r: DuplexStream, shared: Arc<Shared>) {
        let work = async {
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                let n = match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                send_all(&mut tx, Bytes::copy_from_slice(&buf[..n]), false)
                    .await
                    .map_err(|e| format!("xhttp: отправка оборвалась: {e}"))?;
            }
            // Приложение закрыло запись — закрываем тело запроса.
            let _ = tx.send_data(Bytes::new(), true);
            Ok::<(), String>(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }

    /// packet-up: порции данных — отдельными POST'ами с номером.
    async fn packet_uploader(
        send: SendRequest<Bytes>,
        st: Arc<XhttpSettings>,
        session: String,
        mut r: DuplexStream,
        shared: Arc<Shared>,
    ) {
        let max = st.max_post.rand().max(1) as usize;
        let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_POSTS));
        let work = async {
            let mut send = send;
            let mut seq = 0u64;
            let mut last = None;
            while let Some(body) = next_packet(&mut r, max, &mut last, st.min_interval_ms)
                .await
                .ok()
                .flatten()
            {
                #[allow(clippy::unwrap_used, reason = "инвариант: семафор не закрывается")]
                let permit = inflight.clone().acquire_owned().await.unwrap();
                send = send
                    .ready()
                    .await
                    .map_err(|e| format!("xhttp: h2 не готов: {e}"))?;
                if let Some(l) = shared.lease.get() {
                    l.note_request();
                }
                let path = st.url_path(Some(&session), Some(seq));
                seq += 1;
                let req = request(&st, &st.method, &path, false, Some(body.len()))
                    .map_err(|e| e.to_string())?;
                let (resp, mut tx) = send
                    .send_request(req, false)
                    .map_err(|e| format!("xhttp: POST не отправлен: {e}"))?;
                send_all(&mut tx, body, true)
                    .await
                    .map_err(|e| format!("xhttp: POST оборвался: {e}"))?;
                let shared2 = shared.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    discard_response(resp, shared2, "POST (packet-up)").await;
                });
            }
            Ok::<(), String>(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }
}

/// HTTP/3 поверх QUIC (`security=tls&alpn=h3`), все три режима; соединения
/// делятся по тем же правилам `xmux`, что и HTTP/2.
mod h3c {
    use super::*;
    use crate::transport::quic;
    use crate::transport::tcp_tls::resolve_server;

    pub(crate) type Send3 = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
    type Stream3 = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
    type SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
    type RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    impl h2pool::Sender for Send3 {
        fn ready(
            self,
        ) -> futures_util::future::BoxFuture<'static, std::result::Result<Self, String>> {
            // У h3 нет ожидания места: закрытое соединение даст ошибку
            // на самом запросе.
            Box::pin(async move { Ok(self) })
        }
    }

    async fn connect(c: VlessConfig) -> Result<h2pool::Connected<Send3>> {
        let addrs = resolve_server(&c.host, c.port)
            .await
            .map_err(|e| crate::transport::tcp_tls::server_error(&c.host, e))?;
        let roots = c.ca_roots.as_ref().map(|r| (**r).clone());
        let mut last = None;
        for addr in addrs {
            let ep = quic::direct_endpoint(addr.is_ipv6())?;
            let cfg = quic::client_config(roots.clone(), vec![b"h3".to_vec()])?;
            let conn = match ep.connect_with(cfg, addr, c.tls_server_name()) {
                Ok(connecting) => tokio::time::timeout(CONNECT_TIMEOUT, connecting).await,
                Err(e) => {
                    last = Some(quic::connect_error("xhttp", e));
                    continue;
                }
            };
            let conn = match conn {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    last = Some(quic::connect_error("xhttp", e));
                    continue;
                }
                Err(_) => {
                    last = Some(Error::Protocol(format!(
                        "xhttp: QUIC-соединение с {addr} не установилось за {} с \
                         (UDP к серверу заблокирован?)",
                        CONNECT_TIMEOUT.as_secs()
                    )));
                    continue;
                }
            };
            let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
                .await
                .map_err(|e| Error::Protocol(format!("xhttp: HTTP/3: {e}")))?;
            let fut: futures_util::future::BoxFuture<'static, ()> = Box::pin(async move {
                let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                tracing::debug!(error = %e, "xhttp: HTTP/3-соединение завершилось");
                drop(ep);
            });
            return Ok((send, fut));
        }
        Err(last.unwrap_or_else(|| Error::Protocol("xhttp: нет адресов сервера".into())))
    }

    async fn acquire(cfg: &VlessConfig, st: &XhttpSettings) -> Result<h2pool::Lease<Send3>> {
        let c = cfg.clone();
        h2pool::acquire(&format!("xhttp3|{}", cfg.pool_key()), &st.xmux, move || {
            Box::pin(connect(c.clone()))
        })
        .await
    }

    pub(super) async fn start_download(
        cfg: &VlessConfig,
        st: &XhttpSettings,
        session: &str,
        down: DuplexStream,
        shared: Arc<Shared>,
    ) -> Result<()> {
        let lease = acquire(cfg, st).await?;
        let mut send = lease.request();
        let req = h2c::request(st, "GET", &st.url_path(Some(session), None), false, None)?;
        let mut stream: Stream3 = send
            .send_request(req)
            .await
            .map_err(|e| Error::Protocol(format!("xhttp: HTTP/3: {e}")))?;
        stream
            .finish()
            .await
            .map_err(|e| Error::Protocol(format!("xhttp: HTTP/3: {e}")))?;
        let (_, rx) = stream.split();
        let _ = shared.download_lease3.set(lease);
        tokio::spawn(download(rx, down, shared, "GET"));
        Ok(())
    }

    pub(super) async fn start(
        cfg: &VlessConfig,
        st: Arc<XhttpSettings>,
        down: DuplexStream,
        up: DuplexStream,
        shared: Arc<Shared>,
    ) -> Result<()> {
        let lease = acquire(cfg, &st).await?;
        let split_download = st
            .download
            .as_deref()
            .is_some_and(|download| download.cfg.pool_key() != cfg.pool_key());
        let mut send = if split_download {
            lease.sender()
        } else {
            lease.request()
        };
        let _ = shared.lease3.set(lease);
        let h3err = |e: h3::error::StreamError| Error::Protocol(format!("xhttp: HTTP/3: {e}"));

        match st.mode {
            Mode::StreamOne => {
                let req = h2c::request(&st, &st.method, &st.url_path(None, None), true, None)?;
                let stream: Stream3 = send.send_request(req).await.map_err(h3err)?;
                let (tx, rx) = stream.split();
                tokio::spawn(download(rx, down, shared.clone(), "POST (stream-one)"));
                tokio::spawn(upload_stream(tx, up, shared));
            }
            Mode::StreamUp | Mode::PacketUp => {
                let session = Uuid::new_v4().to_string();
                if let Some(download) = st
                    .download
                    .as_deref()
                    .filter(|download| download.cfg.pool_key() != cfg.pool_key())
                {
                    super::start_download(download, &session, down, shared.clone()).await?;
                } else {
                    let get_settings = st.download.as_deref().map_or(st.as_ref(), |d| &d.http);
                    let get = h2c::request(
                        get_settings,
                        "GET",
                        &get_settings.url_path(Some(&session), None),
                        false,
                        None,
                    )?;
                    let mut stream: Stream3 = send.send_request(get).await.map_err(h3err)?;
                    stream.finish().await.map_err(h3err)?;
                    let (_, rx) = stream.split();
                    tokio::spawn(download(rx, down, shared.clone(), "GET"));
                }
                if st.mode == Mode::StreamUp {
                    if let Some(l) = shared.lease3.get() {
                        l.note_request();
                    }
                    let req = h2c::request(
                        &st,
                        &st.method,
                        &st.url_path(Some(&session), None),
                        true,
                        None,
                    )?;
                    let stream: Stream3 = send.send_request(req).await.map_err(h3err)?;
                    let (tx, rx) = stream.split();
                    tokio::spawn(discard_response(rx, shared.clone(), "POST (stream-up)"));
                    tokio::spawn(upload_stream(tx, up, shared));
                } else {
                    tokio::spawn(packet_uploader(send, st, session, up, shared));
                }
            }
        }
        Ok(())
    }

    async fn download(mut rx: RecvHalf, mut w: DuplexStream, shared: Arc<Shared>, what: &str) {
        let work = async {
            let r = rx
                .recv_response()
                .await
                .map_err(|e| format!("xhttp: сервер не ответил на {what}: {e}"))?;
            let status = r.status().as_u16();
            if status != 200 {
                return Err(format!(
                    "xhttp: сервер ответил {status} на {what}{}",
                    status_hint(status)
                ));
            }
            loop {
                match rx.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let n = bytes::Buf::remaining(&chunk);
                        let data = bytes::Buf::copy_to_bytes(&mut chunk, n);
                        if w.write_all(&data).await.is_err() {
                            break; // приложение закрыло поток
                        }
                    }
                    Ok(None) => break,
                    Err(e) => return Err(format!("xhttp: поток вниз оборвался: {e}")),
                }
            }
            Ok(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }

    async fn discard_response(mut rx: RecvHalf, shared: Arc<Shared>, what: &'static str) {
        let work = async {
            let r = rx
                .recv_response()
                .await
                .map_err(|e| format!("xhttp: сервер не ответил на {what}: {e}"))?;
            let status = r.status().as_u16();
            if status != 200 {
                return Err(format!(
                    "xhttp: сервер ответил {status} на {what}{}",
                    status_hint(status)
                ));
            }
            while let Ok(Some(_)) = rx.recv_data().await {}
            Ok(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }

    async fn upload_stream(mut tx: SendHalf, mut r: DuplexStream, shared: Arc<Shared>) {
        let work = async {
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                let n = match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                tx.send_data(Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .map_err(|e| format!("xhttp: отправка оборвалась: {e}"))?;
            }
            let _ = tx.finish().await;
            Ok::<(), String>(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }

    async fn packet_uploader(
        mut send: Send3,
        st: Arc<XhttpSettings>,
        session: String,
        mut r: DuplexStream,
        shared: Arc<Shared>,
    ) {
        let max = st.max_post.rand().max(1) as usize;
        let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_POSTS));
        let work = async {
            let mut seq = 0u64;
            let mut last = None;
            while let Some(body) = next_packet(&mut r, max, &mut last, st.min_interval_ms)
                .await
                .ok()
                .flatten()
            {
                #[allow(clippy::unwrap_used, reason = "инвариант: семафор не закрывается")]
                let permit = inflight.clone().acquire_owned().await.unwrap();
                if let Some(l) = shared.lease3.get() {
                    l.note_request();
                }
                let path = st.url_path(Some(&session), Some(seq));
                seq += 1;
                let req = h2c::request(&st, &st.method, &path, false, Some(body.len()))
                    .map_err(|e| e.to_string())?;
                let mut stream: Stream3 = send
                    .send_request(req)
                    .await
                    .map_err(|e| format!("xhttp: POST не отправлен: {e}"))?;
                stream
                    .send_data(body)
                    .await
                    .map_err(|e| format!("xhttp: POST оборвался: {e}"))?;
                stream
                    .finish()
                    .await
                    .map_err(|e| format!("xhttp: POST оборвался: {e}"))?;
                let (_, rx) = stream.split();
                let shared2 = shared.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    discard_response(rx, shared2, "POST (packet-up)").await;
                });
            }
            Ok::<(), String>(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }
}

/// HTTP/1.1 (без TLS или TLS с `alpn=http/1.1`), только packet-up.
mod h1 {
    use super::*;

    /// Запрос в порядке Go `http.Request.Write`: `Host`, `User-Agent`,
    /// `Connection`/`Content-Length`, остальные по алфавиту.
    pub(super) fn request(
        st: &XhttpSettings,
        method: &str,
        path: &str,
        content_length: Option<usize>,
        close: bool,
    ) -> String {
        let mut headers = st.request_headers(false);
        let ua = headers
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|i| headers.remove(i));
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        let mut r = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", st.host);
        if let Some((_, v)) = ua {
            r.push_str(&format!("User-Agent: {v}\r\n"));
        }
        if close {
            r.push_str("Connection: close\r\n");
        }
        if let Some(n) = content_length {
            r.push_str(&format!("Content-Length: {n}\r\n"));
        }
        for (k, v) in headers {
            r.push_str(&format!("{k}: {v}\r\n"));
        }
        r.push_str("\r\n");
        r
    }

    pub(super) use crate::http1::{pump_body, read_head};

    fn alpn(cfg: &VlessConfig) -> Vec<Vec<u8>> {
        cfg.alpn().unwrap_or_else(|| vec![b"http/1.1".to_vec()])
    }

    pub(super) async fn start_download(
        cfg: &VlessConfig,
        st: &XhttpSettings,
        session: &str,
        down: DuplexStream,
        shared: Arc<Shared>,
    ) -> Result<()> {
        let mut dl = connect_tls_by_security(cfg, alpn(cfg)).await?;
        let get = request(st, "GET", &st.url_path(Some(session), None), None, true);
        dl.write_all(get.as_bytes()).await?;
        dl.flush().await?;
        tokio::spawn(download(dl, down, shared));
        Ok(())
    }

    pub(super) async fn start(
        cfg: &VlessConfig,
        st: Arc<XhttpSettings>,
        down: DuplexStream,
        up: DuplexStream,
        shared: Arc<Shared>,
    ) -> Result<()> {
        let session = Uuid::new_v4().to_string();
        if let Some(download) = st.download.as_deref() {
            super::start_download(download, &session, down, shared.clone()).await?;
        } else {
            start_download(cfg, &st, &session, down, shared.clone()).await?;
        }
        tokio::spawn(packet_uploader(cfg.clone(), st, session, up, shared));
        Ok(())
    }

    async fn download(dl: SecureStream, mut w: DuplexStream, shared: Arc<Shared>) {
        let work = async {
            let mut r = BufReader::new(dl);
            let head = read_head(&mut r)
                .await
                .map_err(|e| format!("xhttp: нет ответа на GET: {e}"))?;
            if head.status != 200 {
                return Err(format!(
                    "xhttp: сервер ответил {} на GET{}",
                    head.status,
                    status_hint(head.status)
                ));
            }
            match pump_body(&mut r, head.body_kind(), Some(&mut w)).await {
                Ok(()) => Ok(()),
                // Приложение закрыло поток — не ошибка.
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                Err(e) => Err(format!("xhttp: поток вниз оборвался: {e}")),
            }
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }

    /// Соединение для POST'ов: запросы пишутся подряд (keep-alive, без
    /// ожидания ответа — как у Xray), ответы читает отдельная задача.
    struct UploadConn {
        w: tokio::io::WriteHalf<SecureStream>,
        alive: Arc<std::sync::atomic::AtomicBool>,
    }

    async fn open_upload(cfg: &VlessConfig, shared: &Arc<Shared>) -> Result<UploadConn> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let s = connect_tls_by_security(cfg, alpn(cfg)).await?;
        let (r, w) = tokio::io::split(s);
        let alive = Arc::new(AtomicBool::new(true));
        let alive2 = alive.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut r = BufReader::new(r);
            let work = async {
                loop {
                    let head = match read_head(&mut r).await {
                        Ok(h) => h,
                        Err(_) => return Ok(()), // сервер закрыл соединение
                    };
                    if head.status != 200 {
                        return Err(format!(
                            "xhttp: сервер ответил {} на POST (packet-up){}",
                            head.status,
                            status_hint(head.status)
                        ));
                    }
                    if pump_body(&mut r, head.body_kind(), None::<&mut DuplexStream>)
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                }
            };
            tokio::select! {
                _ = shared.cancel.cancelled() => {}
                r = work => if let Err(e) = r { shared.fail(e) },
            }
            alive2.store(false, Ordering::Relaxed);
        });
        Ok(UploadConn { w, alive })
    }

    async fn packet_uploader(
        cfg: VlessConfig,
        st: Arc<XhttpSettings>,
        session: String,
        mut r: DuplexStream,
        shared: Arc<Shared>,
    ) {
        use std::sync::atomic::Ordering;
        let max = st.max_post.rand().max(1) as usize;
        let work = async {
            let mut conn: Option<UploadConn> = None;
            let mut seq = 0u64;
            let mut last = None;
            while let Some(body) = next_packet(&mut r, max, &mut last, st.min_interval_ms)
                .await
                .ok()
                .flatten()
            {
                let path = st.url_path(Some(&session), Some(seq));
                seq += 1;
                let mut req = request(&st, &st.method, &path, Some(body.len()), false).into_bytes();
                req.extend_from_slice(&body);
                // Уже открытое соединение могло быть закрыто сервером —
                // тогда одна попытка на новом (как у Xray).
                let mut fresh = false;
                loop {
                    if conn
                        .as_ref()
                        .is_none_or(|c| !c.alive.load(Ordering::Relaxed))
                    {
                        conn = Some(
                            open_upload(&cfg, &shared)
                                .await
                                .map_err(|e| format!("xhttp: соединение для POST: {e}"))?,
                        );
                        fresh = true;
                    }
                    #[allow(
                        clippy::unwrap_used,
                        reason = "инвариант: conn — прежнее живое соединение или открытое строкой выше"
                    )]
                    let c = conn.as_mut().unwrap();
                    let res = async {
                        c.w.write_all(&req).await?;
                        c.w.flush().await
                    }
                    .await;
                    match res {
                        Ok(()) => break,
                        Err(e) if fresh => return Err(format!("xhttp: POST не отправлен: {e}")),
                        Err(_) => conn = None,
                    }
                }
            }
            Ok::<(), String>(())
        };
        tokio::select! {
            _ = shared.cancel.cancelled() => {}
            r = work => if let Err(e) = r { shared.fail(e) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(tail: &str) -> VlessConfig {
        VlessConfig::parse(&format!(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?type=xhttp&{tail}"
        ))
        .unwrap()
    }

    #[test]
    fn mode_and_http_version_follow_xray() {
        let s = XhttpSettings::from_config(&cfg("security=none")).unwrap();
        assert_eq!((s.mode, s.http11, s.https), (Mode::PacketUp, true, false));
        assert_eq!(s.host, "1.2.3.4");
        let s = XhttpSettings::from_config(&cfg("security=tls&sni=a.test")).unwrap();
        assert_eq!((s.mode, s.http11), (Mode::PacketUp, false));
        assert_eq!(s.host, "a.test");
        let s = XhttpSettings::from_config(&cfg("security=tls&alpn=http%2F1.1")).unwrap();
        assert!(s.http11);
        let s = XhttpSettings::from_config(&cfg("security=reality&sni=r.test&pbk=x&host=cdn.test"))
            .unwrap();
        assert_eq!((s.mode, s.http11), (Mode::StreamOne, false));
        assert_eq!(s.host, "cdn.test");
        assert!(XhttpSettings::from_config(&cfg("security=none&mode=stream-one")).is_err());
        let s = XhttpSettings::from_config(&cfg("security=tls&alpn=h3")).unwrap();
        assert_eq!((s.mode, s.http11, s.h3), (Mode::PacketUp, false, true));
        assert!(XhttpSettings::from_config(&cfg("security=reality&alpn=h3&pbk=AAAA")).is_err());
        assert!(XhttpSettings::from_config(&cfg("mode=weird")).is_err());
    }

    #[test]
    fn headers_follow_fingerprint() {
        let ua = |s: &XhttpSettings| {
            s.headers
                .iter()
                .find(|(k, _)| k == "User-Agent")
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        let s = XhttpSettings::from_config(&cfg("security=tls&fp=firefox")).unwrap();
        assert!(ua(&s).contains("Firefox/"));
        let s = XhttpSettings::from_config(&cfg("security=tls&fp=safari")).unwrap();
        assert!(ua(&s).contains("Safari/605"));
        let s = XhttpSettings::from_config(&cfg("security=tls")).unwrap();
        assert!(ua(&s).contains("Chrome/"));
        // Явный User-Agent-ключ главнее fp.
        let extra = "%7B%22headers%22%3A%7B%22User-Agent%22%3A%22firefox%22%7D%7D";
        let s = XhttpSettings::from_config(&cfg(&format!("security=tls&extra={extra}"))).unwrap();
        assert!(ua(&s).contains("Firefox/"));
    }

    #[test]
    fn paths_and_referer() {
        let s = XhttpSettings::from_config(&cfg("path=%2Fxh%3Fa%3D1")).unwrap();
        assert_eq!(s.path, "/xh/");
        assert_eq!(s.url_path(None, None), "/xh/?a=1");
        assert_eq!(s.url_path(Some("S"), None), "/xh/S?a=1");
        assert_eq!(s.url_path(Some("S"), Some(7)), "/xh/S/7?a=1");
        let r = s.referer();
        let pad = r.strip_prefix("http://1.2.3.4/xh/?x_padding=").unwrap();
        assert!((100..=1000).contains(&pad.len()) && pad.bytes().all(|b| b == b'X'));
        let s = XhttpSettings::from_config(&cfg("path=xh")).unwrap();
        assert_eq!(s.url_path(None, None), "/xh/");
    }

    #[test]
    fn extra_json_is_parsed_and_unsupported_is_rejected() {
        let extra = "%7B%22xPaddingBytes%22%3A%2210-20%22%2C%22scMaxEachPostBytes%22%3A50000%2C%22noGRPCHeader%22%3Atrue%2C%22headers%22%3A%7B%22x-token%22%3A%22abc%22%7D%2C%22xmux%22%3A%7B%7D%7D";
        let s = XhttpSettings::from_config(&cfg(&format!("extra={extra}"))).unwrap();
        assert_eq!(s.padding, Range { from: 10, to: 20 });
        assert_eq!(s.max_post, Range::fixed(50000));
        assert!(s.no_grpc_header);
        assert!(s.headers.iter().any(|(k, v)| k == "X-Token" && v == "abc"));
        assert!(s.headers.iter().any(|(k, _)| k == "User-Agent"));

        for bad in [
            r#"{"xPaddingObfsMode":true}"#,
            r#"{"sessionIDPlacement":"header"}"#,
            r#"{"uplinkDataPlacement":"cookie"}"#,
            r#"{"headers":{"Host":"x"}}"#,
            r#"{"uplinkHTTPMethod":"GET"}"#,
            r#"[1]"#,
        ] {
            let enc: String = url::form_urlencoded::byte_serialize(bad.as_bytes()).collect();
            assert!(
                XhttpSettings::from_config(&cfg(&format!("extra={enc}"))).is_err(),
                "{bad}"
            );
        }
        // Свой User-Agent — заголовки Chrome не подмешиваются (как у Xray).
        let enc: String =
            url::form_urlencoded::byte_serialize(br#"{"headers":{"User-Agent":"my"}}"#).collect();
        let s = XhttpSettings::from_config(&cfg(&format!("extra={enc}"))).unwrap();
        assert_eq!(
            s.headers,
            vec![("User-Agent".to_string(), "my".to_string())]
        );
    }

    #[test]
    fn download_settings_build_an_independent_endpoint() {
        let encode = |v: serde_json::Value| {
            url::form_urlencoded::byte_serialize(v.to_string().as_bytes()).collect::<String>()
        };
        let extra = encode(serde_json::json!({
            "downloadSettings": {
                "address": "download.test",
                "port": 8443,
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {"serverName": "tls.download.test", "alpn": ["h2"]},
                "xhttpSettings": {"host": "cdn.download.test", "path": "/xh"}
            }
        }));
        let s = XhttpSettings::from_config(&cfg(&format!("security=tls&path=%2Fxh&extra={extra}")))
            .unwrap();
        let d = s.download.as_deref().unwrap();
        assert_eq!(
            (s.mode, d.cfg.host.as_str(), d.cfg.port),
            (Mode::PacketUp, "download.test", 8443)
        );
        assert_eq!(d.cfg.security, Security::Tls);
        assert_eq!(d.cfg.effective_sni(), "tls.download.test");
        assert_eq!(
            (d.http.host.as_str(), d.http.path.as_str()),
            ("cdn.download.test", "/xh/")
        );
        assert!(!d.http.http11 && !d.http.h3);
    }

    #[test]
    fn download_settings_validate_transport_and_shared_path() {
        let encode = |v: serde_json::Value| {
            url::form_urlencoded::byte_serialize(v.to_string().as_bytes()).collect::<String>()
        };
        let make = |download: serde_json::Value, tail: &str| {
            let extra = encode(serde_json::json!({"downloadSettings": download}));
            XhttpSettings::from_config(&cfg(&format!("{tail}&extra={extra}")))
        };
        let valid = serde_json::json!({
            "address":"download.test", "network":"xhttp", "security":"tls",
            "xhttpSettings":{"path":"/xh"}
        });
        assert!(make(valid.clone(), "security=tls&path=%2Fxh&mode=stream-one").is_err());
        assert!(make(valid.clone(), "security=tls&path=%2Fxh").is_ok());
        let mut bad_path = valid.clone();
        bad_path["xhttpSettings"]["path"] = serde_json::json!("/other");
        assert!(make(bad_path, "security=tls&path=%2Fxh").is_err());
        let mut bad_network = valid.clone();
        bad_network["network"] = serde_json::json!("tcp");
        assert!(make(bad_network, "security=tls&path=%2Fxh").is_err());
        let mut bad_port = valid;
        bad_port["port"] = serde_json::json!(70000);
        assert!(make(bad_port, "security=tls&path=%2Fxh").is_err());
    }

    #[test]
    fn download_settings_support_reality_and_http3() {
        let encode = |v: serde_json::Value| {
            url::form_urlencoded::byte_serialize(v.to_string().as_bytes()).collect::<String>()
        };
        let reality = encode(serde_json::json!({"downloadSettings": {
            "network":"xhttp", "security":"reality",
            "realitySettings":{"serverName":"reality.test", "publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "shortId":"0123abcd"},
            "xhttpSettings":{"path":"/xh"}
        }}));
        let s =
            XhttpSettings::from_config(&cfg(&format!("security=tls&path=%2Fxh&extra={reality}")))
                .unwrap();
        let d = s.download.as_deref().unwrap();
        assert_eq!(d.cfg.security, Security::Reality);
        assert_eq!(d.cfg.effective_sni(), "reality.test");

        let h3 = encode(serde_json::json!({"downloadSettings": {
            "network":"xhttp", "security":"tls", "tlsSettings":{"alpn":["h3"]},
            "xhttpSettings":{"path":"/xh"}
        }}));
        let s = XhttpSettings::from_config(&cfg(&format!("security=none&path=%2Fxh&extra={h3}")))
            .unwrap();
        let d = s.download.as_deref().unwrap();
        assert!(d.http.h3 && !d.http.http11);
        assert_eq!(s.mode, Mode::PacketUp);
    }

    #[test]
    fn h1_request_has_go_order() {
        let s = XhttpSettings::from_config(&cfg("security=none&host=h.test&path=%2Fp")).unwrap();
        let r = h1::request(&s, "POST", "/p/S/0", Some(5), false);
        let lines: Vec<&str> = r.split("\r\n").collect();
        assert_eq!(lines[0], "POST /p/S/0 HTTP/1.1");
        assert_eq!(lines[1], "Host: h.test");
        assert!(lines[2].starts_with("User-Agent: Mozilla/5.0"));
        assert_eq!(lines[3], "Content-Length: 5");
        let names: Vec<&str> = lines[4..]
            .iter()
            .take_while(|l| !l.is_empty())
            .map(|l| l.split(':').next().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(names.contains(&"Referer"));
        assert!(
            !names.contains(&"Content-Type"),
            "у packet-up нет application/grpc"
        );
    }

    #[tokio::test]
    async fn chunked_body_is_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Padding: XX\r\n\r\n5;ext=1\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\nTrailer: x\r\n\r\n";
        let mut r = BufReader::new(&raw[..]);
        let head = h1::read_head(&mut r).await.unwrap();
        assert_eq!(head.status, 200);
        let mut out = Vec::new();
        h1::pump_body(&mut r, head.body_kind(), Some(&mut out))
            .await
            .unwrap();
        assert_eq!(out, b"hello world");

        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 200 OK\r\n\r\n";
        let mut r = BufReader::new(&raw[..]);
        let head = h1::read_head(&mut r).await.unwrap();
        assert_eq!(head.status, 404);
        h1::pump_body(&mut r, head.body_kind(), None::<&mut Vec<u8>>)
            .await
            .unwrap();
        assert_eq!(h1::read_head(&mut r).await.unwrap().status, 200);
    }
}
