// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::HashMap;

use uuid::Uuid;

use crate::error::{Error, Result};
use crate::transport::TransportConfig;
pub use crate::transport::{NetworkType, RealityParams, Security};

/// `flow=` из ссылки. Значения — те, что понимает сервер Xray-core
/// (`proxy/vless/inbound/inbound.go`: пустой flow и `xtls-rprx-vision`;
/// `xtls-rprx-vision-udp443` — клиентский вариант того же Vision,
/// разрешающий UDP на 443, серверу уходит как `xtls-rprx-vision`).
/// Неизвестное значение — ошибка разбора: молча отправить пустой flow
/// значило бы получить от сервера отказ без понятной причины.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    None,
    XtlsRprxVision,
    XtlsRprxVisionUdp443,
}

impl Flow {
    pub fn parse(s: Option<&str>) -> Result<Self> {
        match s.unwrap_or("") {
            "" | "none" => Ok(Flow::None),
            "xtls-rprx-vision" => Ok(Flow::XtlsRprxVision),
            "xtls-rprx-vision-udp443" => Ok(Flow::XtlsRprxVisionUdp443),
            other => Err(Error::InvalidUri(format!(
                "неизвестный flow='{other}' (поддерживаются: пусто, xtls-rprx-vision, xtls-rprx-vision-udp443)"
            ))),
        }
    }

    pub fn is_vision(self) -> bool {
        matches!(self, Flow::XtlsRprxVision | Flow::XtlsRprxVisionUdp443)
    }
}

/// Разобранная ссылка `vless://uuid@host:port?...#remark`.
///
/// Формат ссылки не стандартизирован единым RFC — это ad-hoc конвенция,
/// которой следуют Xray-core/V2Ray-совместимые клиенты. Разбираем те
/// параметры, что реально используются нижестоящими этапами; неизвестные
/// query-параметры сохраняются в `raw_params` и не приводят к ошибке —
/// новый параметр в конфиге не должен ломать клиент.
#[derive(Clone)]
pub struct VlessConfig {
    pub id: Uuid,
    pub host: String,
    pub port: u16,
    pub encryption: String,
    pub security: Security,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    pub flow: Flow,
    pub network: NetworkType,
    pub remark: Option<String>,
    pub raw_params: HashMap<String, String>,
    /// Свой набор доверенных корневых сертификатов для `security=tls`
    /// (задаётся не ссылкой, а ключом `--ca` клиента — для серверов с
    /// самоподписанным сертификатом). `None` — встроенный публичный набор.
    pub ca_roots: Option<std::sync::Arc<rustls::RootCertStore>>,
    /// Дробление начала соединения с сервером (задаётся настройками
    /// выхода, не ссылкой), см. [`crate::transport::fragment`].
    pub fragment: Option<std::sync::Arc<crate::transport::fragment::Fragment>>,
    /// Чей ClientHello и HTTP-заголовки изображать (по `fp=`), см.
    /// [`crate::fingerprint::profiles`].
    pub browser: crate::fingerprint::Browser,
}

/// UUID и параметры ссылки (`pbk`, `sid`, `pqv`, пароли транспорта) —
/// скрыты; из `raw_params` видны только имена.
impl std::fmt::Debug for VlessConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut params: Vec<&String> = self.raw_params.keys().collect();
        params.sort();
        f.debug_struct("VlessConfig")
            .field("id", &crate::redact::Redacted)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("encryption", &self.encryption)
            .field("security", &self.security)
            .field("sni", &self.sni)
            .field("fingerprint", &self.fingerprint)
            .field("flow", &self.flow)
            .field("network", &self.network)
            .field("remark", &self.remark)
            .field("raw_params", &params)
            .field("ca_roots", &self.ca_roots.as_ref().map(|r| r.len()))
            .field("fragment", &self.fragment)
            .field("browser", &self.browser)
            .finish()
    }
}

impl VlessConfig {
    /// Ключ общих соединений (пулы HTTP/2): всё, что влияет на соединение
    /// с сервером, кроме имени ссылки.
    pub fn pool_key(&self) -> String {
        let mut params: Vec<(&String, &String)> = self.raw_params.iter().collect();
        params.sort();
        format!(
            "{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}",
            self.id,
            self.host,
            self.port,
            self.security,
            self.network,
            self.sni,
            params,
            self.ca_roots.as_ref().map(std::sync::Arc::as_ptr),
        ) + &format!("|{:?}|{:?}", self.fragment, self.browser)
    }

    pub fn parse(uri: &str) -> Result<Self> {
        let url = url::Url::parse(uri)
            .map_err(|e| Error::InvalidUri(format!("не удалось разобрать URI: {e}")))?;

        if url.scheme() != "vless" {
            return Err(Error::InvalidUri(format!(
                "ожидалась схема 'vless', получено '{}'",
                url.scheme()
            )));
        }

        let id_str = url.username();
        if id_str.is_empty() {
            return Err(Error::InvalidUri("отсутствует UUID перед '@'".into()));
        }
        let id = Uuid::parse_str(id_str)?;

        let transport = TransportConfig::from_url(&url)?;
        let mut raw_params = HashMap::new();
        for (key, value) in url.query_pairs() {
            raw_params.insert(key.into_owned(), value.into_owned());
        }

        let encryption = raw_params
            .get("encryption")
            .cloned()
            .unwrap_or_else(|| "none".to_string());
        if encryption != "none" {
            // VLESS сознательно не шифрует полезную нагрузку сам —
            // шифрование обеспечивает транспорт (TLS/REALITY). Любое
            // другое значение почти наверняка означает битую ссылку.
            return Err(Error::InvalidUri(format!(
                "неподдерживаемое значение encryption='{encryption}' (ожидалось 'none')"
            )));
        }

        let security = transport.security;
        let network = transport.network;
        let sni = transport.sni.clone();
        let fingerprint = transport.fingerprint.clone();
        let browser = transport.browser;
        let flow = Flow::parse(raw_params.get("flow").map(String::as_str))?;
        let remark = url.fragment().map(percent_decode);

        Ok(VlessConfig {
            id,
            host: transport.host,
            port: transport.port,
            encryption,
            security,
            sni,
            fingerprint,
            flow,
            network,
            remark,
            raw_params,
            ca_roots: transport.ca_roots,
            fragment: transport.fragment,
            browser,
        })
    }

    /// Проверить, что `flow=` из ссылки применим к этой ссылке. XTLS
    /// Vision в Xray-core работает только поверх «голого» TCP-транспорта
    /// с TLS или REALITY (`outbound.go`: "XTLS only supports TLS and
    /// REALITY directly") — для ws/grpc и для `security=none` понятная
    /// ошибка здесь, до соединения, а не отказ сервера без причины.
    pub fn ensure_flow_supported(&self) -> Result<()> {
        if self.flow.is_vision() {
            if self.network != NetworkType::Tcp {
                return Err(Error::InvalidUri(format!(
                    "flow=xtls-rprx-vision работает только с type=tcp, а в ссылке type={:?}",
                    self.network
                )));
            }
            if self.security == Security::None {
                return Err(Error::InvalidUri(
                    "flow=xtls-rprx-vision требует security=tls или security=reality".into(),
                ));
            }
        }
        Ok(())
    }

    /// Проверить всю ссылку на совместимость с сервером Xray-core до
    /// соединения: flow (см. [`Self::ensure_flow_supported`]) и
    /// сочетание REALITY с транспортом — Xray принимает REALITY только
    /// поверх tcp, grpc и xhttp ("REALITY only supports RAW, XHTTP and
    /// gRPC"), так что ws/httpupgrade + reality не заработают ни с одним
    /// сервером. Библиотечный `transport::dial` такие сочетания не
    /// запрещает (их используют тесты верификатора REALITY), а клиент
    /// проверяет ссылку этим методом при старте.
    pub fn validate(&self) -> Result<()> {
        self.ensure_flow_supported()?;
        // `path=`, `host=` и `serviceName=` декодируются из percent-encoding
        // и попадают в сырую строку HTTP/1.1-запроса (httpupgrade, xhttp).
        // `%0d%0a` иначе добавил бы произвольные заголовки или разбил бы
        // запрос на два — отказ здесь, до соединения.
        for (name, value) in [
            ("path", self.raw_params.get("path")),
            ("host", self.raw_params.get("host")),
            ("serviceName", self.raw_params.get("serviceName")),
        ] {
            if let Some(v) = value {
                if !crate::http1::request_part_ok(v) {
                    return Err(Error::InvalidUri(format!(
                        "{name}= содержит управляющие символы или пробелы — так можно \
                         подменить HTTP-запрос"
                    )));
                }
            }
        }
        if self.security == Security::Reality
            && matches!(self.network, NetworkType::Ws | NetworkType::HttpUpgrade)
        {
            return Err(Error::InvalidUri(format!(
                "security=reality с type={:?} не поддерживает сервер Xray-core \
                 (REALITY работает только с tcp, grpc и xhttp)",
                self.network
            )));
        }
        if self.network == NetworkType::Xhttp {
            // Параметры xhttp (mode=, extra=, alpn) — тоже до соединения.
            crate::transport::xhttp::XhttpSettings::from_config(&TransportConfig::from(self))?;
        }
        Ok(())
    }

    /// `alpn=` из ссылки (через запятую). `None` — не задан, транспорт
    /// выбирает сам.
    pub fn alpn(&self) -> Option<Vec<Vec<u8>>> {
        let v = self.raw_params.get("alpn")?;
        let list: Vec<Vec<u8>> = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes().to_vec())
            .collect();
        (!list.is_empty()).then_some(list)
    }

    /// Путь для HTTP-транспортов (ws, httpupgrade): `path=` из ссылки с
    /// ведущим `/`, без параметра `ed` (ранние данные у Xray задаются
    /// им, этот клиент их не использует — а оставленный в пути он лишь
    /// выдаёт клиента).
    pub fn http_path(&self) -> String {
        let raw = self.path();
        let (p, q) = raw.split_once('?').unwrap_or((raw, ""));
        let mut path = if p.starts_with('/') {
            p.to_string()
        } else {
            format!("/{p}")
        };
        let rest: Vec<&str> = q
            .split('&')
            .filter(|kv| !kv.is_empty() && kv.split('=').next() != Some("ed"))
            .collect();
        if !rest.is_empty() {
            path.push('?');
            path.push_str(&rest.join("&"));
        }
        path
    }

    /// `Host` для WebSocket: `host=` из ссылки, иначе SNI.
    pub fn ws_host(&self) -> &str {
        match self.raw_params.get("host") {
            Some(h) if !h.is_empty() => h,
            _ => self.effective_sni(),
        }
    }

    /// SNI, который реально пойдёт в ClientHello: явный `sni=`, иначе host.
    pub fn effective_sni(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
    }

    /// Имя для проверки сертификата (rustls, quinn): [`Self::effective_sni`]
    /// без скобок IPv6. `url` отдаёт IPv6-адрес сервера как `[2001:db8::1]`
    /// — так он нужен в `Host` и URI, а `ServerName` со скобками не
    /// разбирается, и TLS к такому серверу без `sni=` не поднимался.
    pub fn tls_server_name(&self) -> &str {
        let s = self.effective_sni();
        s.strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .unwrap_or(s)
    }

    /// Путь для транспорта Этапа 4 (`path=` в ссылке, используется WS).
    pub fn path(&self) -> &str {
        self.raw_params
            .get("path")
            .map(|s| s.as_str())
            .unwrap_or("/")
    }

    /// Имя gRPC-сервиса для транспорта Этапа 4 (`serviceName=` в ссылке).
    pub fn service_name(&self) -> &str {
        self.raw_params
            .get("serviceName")
            .map(|s| s.as_str())
            .unwrap_or("")
    }

    /// Разобрать `pbk=`/`sid=` для REALITY (Этап 5). Возвращает ошибку,
    /// если `security=reality`, но параметры отсутствуют/некорректны —
    /// молча продолжать с REALITY без публичного ключа сервера означало
    /// бы попытаться собрать SessionId с нулевым/мусорным AuthKey, то
    /// есть заведомо провальное (или, хуже, тихо небезопасное) соединение.
    /// Для `security != reality` эти параметры не нужны и не
    /// разбираются — вызывающий код должен сам проверять `self.security`
    /// перед вызовом.
    pub fn reality_params(&self) -> Result<RealityParams> {
        TransportConfig::reality_params_from(&self.raw_params)
    }
}

impl From<&VlessConfig> for TransportConfig {
    fn from(cfg: &VlessConfig) -> Self {
        let mut raw_params = cfg.raw_params.clone();
        raw_params.remove("flow");
        raw_params.remove("encryption");
        Self {
            host: cfg.host.clone(),
            port: cfg.port,
            security: cfg.security,
            sni: cfg.sni.clone(),
            fingerprint: cfg.fingerprint.clone(),
            network: cfg.network,
            raw_params,
            ca_roots: cfg.ca_roots.clone(),
            fragment: cfg.fragment.clone(),
            browser: cfg.browser,
        }
    }
}

fn percent_decode(s: &str) -> String {
    percent_decode_str(s)
}

// Малая часть percent-decoding без отдельной зависимости
// (url::Url уже тянет percent-encoding транзитивно, но публично его не
// экспортирует под этим именем — decode fragment вручную).
fn percent_decode_str(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn parses_minimal_tcp_tls_link() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=tls&type=tcp&sni=example.com&fp=chrome#my-node";
        let cfg = VlessConfig::parse(uri).unwrap();
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.security, Security::Tls);
        assert_eq!(cfg.network, NetworkType::Tcp);
        assert_eq!(cfg.sni.as_deref(), Some("example.com"));
        assert_eq!(cfg.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(cfg.remark.as_deref(), Some("my-node"));
    }

    #[test]
    fn parses_flow_values_and_rejects_unknown() {
        let base = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality";
        let cfg = VlessConfig::parse(base).unwrap();
        assert_eq!(cfg.flow, Flow::None);
        assert!(cfg.ensure_flow_supported().is_ok());

        let cfg = VlessConfig::parse(&format!("{base}&flow=xtls-rprx-vision")).unwrap();
        assert!(cfg.ensure_flow_supported().is_ok());
        assert_eq!(cfg.flow, Flow::XtlsRprxVision);
        let cfg = VlessConfig::parse(&format!("{base}&flow=xtls-rprx-vision-udp443")).unwrap();
        assert_eq!(cfg.flow, Flow::XtlsRprxVisionUdp443);

        let err = VlessConfig::parse(&format!("{base}&flow=xtls-rprx-direct")).unwrap_err();
        assert!(matches!(err, Error::InvalidUri(_)));
    }

    /// Vision поддержан, но только там, где его поддерживает сервер:
    /// TCP-транспорт и TLS/REALITY.
    #[test]
    fn vision_flow_is_checked_against_transport() {
        let base =
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?flow=xtls-rprx-vision";
        let ok = VlessConfig::parse(&format!("{base}&security=reality&type=tcp")).unwrap();
        assert!(ok.ensure_flow_supported().is_ok());
        let ws = VlessConfig::parse(&format!("{base}&security=tls&type=ws")).unwrap();
        assert!(ws.ensure_flow_supported().is_err());
        let plain = VlessConfig::parse(&format!("{base}&security=none")).unwrap();
        assert!(plain.ensure_flow_supported().is_err());
    }

    #[test]
    fn validate_rejects_reality_over_ws_and_httpupgrade() {
        let base =
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=reality&pbk=x";
        for t in ["ws", "httpupgrade"] {
            let c = VlessConfig::parse(&format!("{base}&type={t}")).unwrap();
            assert!(c.validate().is_err(), "{t}");
        }
        for t in ["tcp", "grpc", "xhttp"] {
            let c = VlessConfig::parse(&format!("{base}&type={t}")).unwrap();
            assert!(c.validate().is_ok(), "{t}");
        }
    }

    /// Сырые HTTP/1.1-запросы собираются `format!`, поэтому перевод
    /// строки в `path=`/`host=` (после percent-decoding) — инъекция.
    #[test]
    fn validate_rejects_crlf_in_http_request_parts() {
        let base =
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=tls&type=httpupgrade";
        for q in [
            "&path=%2F%0d%0aX-Evil%3A%201",
            "&host=example.com%0d%0aX-Evil%3A%201",
            "&path=%2Fws%0aX-Evil%3A%201",
        ] {
            let c = VlessConfig::parse(&format!("{base}{q}")).unwrap();
            assert!(c.validate().is_err(), "{q}");
        }
        let ok = VlessConfig::parse(&format!("{base}&path=%2Fws&host=example.com")).unwrap();
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_transport_and_security() {
        let base = "vless://11111111-1111-1111-1111-111111111111@example.com:443";
        assert!(VlessConfig::parse(&format!("{base}?type=kcp")).is_err());
        assert!(VlessConfig::parse(&format!("{base}?security=xtls")).is_err());
        assert!(VlessConfig::parse(&format!("{base}?type=tcp&headerType=http")).is_err());
        let raw = VlessConfig::parse(&format!("{base}?type=raw&security=none")).unwrap();
        assert_eq!(raw.network, NetworkType::Tcp);
        assert_eq!(raw.security, Security::None);
    }

    #[test]
    fn http_path_normalizes_and_drops_early_data() {
        let base = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?type=ws";
        let p = |q: &str| {
            VlessConfig::parse(&format!("{base}{q}"))
                .unwrap()
                .http_path()
        };
        assert_eq!(p(""), "/");
        assert_eq!(p("&path=ws"), "/ws");
        assert_eq!(p("&path=%2Fws%3Fed%3D2048"), "/ws");
        assert_eq!(p("&path=%2Fws%3Fa%3D1%26ed%3D2048"), "/ws?a=1");
    }

    #[test]
    fn parses_alpn_and_ws_host() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=tls&sni=a.example&type=ws&host=cdn.example&alpn=h2%2Chttp%2F1.1";
        let cfg = VlessConfig::parse(uri).unwrap();
        assert_eq!(
            cfg.alpn().unwrap(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(cfg.ws_host(), "cdn.example");
        let cfg = VlessConfig::parse(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?sni=a.example",
        )
        .unwrap();
        assert!(cfg.alpn().is_none());
        assert_eq!(cfg.ws_host(), "a.example");
    }

    #[test]
    fn rejects_wrong_scheme() {
        let err = VlessConfig::parse("vmess://x@example.com:443").unwrap_err();
        assert!(matches!(err, Error::InvalidUri(_)));
    }

    #[test]
    fn rejects_non_none_encryption() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=aes-256";
        let err = VlessConfig::parse(uri).unwrap_err();
        assert!(matches!(err, Error::InvalidUri(_)));
    }

    #[test]
    fn ipv6_server_name_without_brackets() {
        let c = VlessConfig::parse(
            "vless://11111111-1111-1111-1111-111111111111@[2001:db8::1]:443?security=tls",
        )
        .unwrap();
        assert_eq!(c.ws_host(), "[2001:db8::1]", "в Host — со скобками");
        assert_eq!(c.tls_server_name(), "2001:db8::1");
        assert!(rustls::pki_types::ServerName::try_from(c.tls_server_name()).is_ok());
        let c = VlessConfig::parse(
            "vless://11111111-1111-1111-1111-111111111111@[2001:db8::1]:443?security=tls&sni=a.test",
        )
        .unwrap();
        assert_eq!(c.tls_server_name(), "a.test");
    }

    #[test]
    fn parses_reality_pbk_and_sid() {
        // pbk= — 32 случайных байта в base64url без padding; sid= — hex.
        let pbk_bytes = [7u8; 32];
        let pbk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pbk_bytes);
        let uri = format!(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=reality&sni=example.com&pbk={pbk_b64}&sid=aabbccdd"
        );
        let cfg = VlessConfig::parse(&uri).unwrap();
        assert_eq!(cfg.security, Security::Reality);

        let reality = cfg.reality_params().unwrap();
        assert_eq!(reality.public_key, pbk_bytes);
        assert_eq!(reality.short_id, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn reality_params_requires_pbk() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=reality&sni=example.com";
        let cfg = VlessConfig::parse(uri).unwrap();
        let err = cfg.reality_params().unwrap_err();
        assert!(matches!(err, Error::InvalidUri(_)));
    }

    #[test]
    fn reality_params_accepts_missing_sid() {
        let pbk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let uri = format!(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=reality&sni=example.com&pbk={pbk_b64}"
        );
        let cfg = VlessConfig::parse(&uri).unwrap();
        let reality = cfg.reality_params().unwrap();
        assert!(reality.short_id.is_empty());
    }
}
