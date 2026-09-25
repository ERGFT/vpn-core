use std::collections::HashMap;

use base64::Engine;
use uuid::Uuid;

use crate::error::{Error, Result};

/// Тип нижележащего транспорта (`type=` в URI). На Этапе 1 поддержан
/// только `tcp`; `ws`/`grpc` появятся на Этапе 4, `security=reality`
/// разбирается уже сейчас (чтобы конфиг не терялся), но не реализован —
/// см. `VlessConfig::security`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Tcp,
    Ws,
    Grpc,
}

impl NetworkType {
    fn parse(s: &str) -> Self {
        match s {
            "ws" => NetworkType::Ws,
            "grpc" => NetworkType::Grpc,
            _ => NetworkType::Tcp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    None,
    Tls,
    Reality,
}

impl Security {
    fn parse(s: &str) -> Self {
        match s {
            "tls" => Security::Tls,
            "reality" => Security::Reality,
            _ => Security::None,
        }
    }
}

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
#[derive(Debug, Clone)]
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
}

/// Разобранные параметры REALITY (`pbk=`/`sid=` в ссылке) — Этап 5.
/// Живут отдельно от [`VlessConfig`], потому что осмысленны только при
/// `security=reality`; см. [`VlessConfig::reality_params`].
#[derive(Debug, Clone)]
pub struct RealityParams {
    /// Статический X25519-публичный ключ сервера (`pbk=`) — 32 байта,
    /// base64url без padding, как у Xray-core.
    pub public_key: [u8; 32],
    /// ShortId (`sid=`) — hex-строка длиной 0-16 символов (0-8 байт) в
    /// ссылке; более длинный short_id протоколом REALITY не
    /// предусмотрен (Xray-core сам обрежет/отвергнет).
    pub short_id: Vec<u8>,
}

impl VlessConfig {
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

        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidUri("отсутствует host".into()))?
            .to_string();
        let port = url
            .port()
            .ok_or_else(|| Error::InvalidUri("отсутствует port".into()))?;

        let mut raw_params: HashMap<String, String> = HashMap::new();
        for (k, v) in url.query_pairs() {
            raw_params.insert(k.into_owned(), v.into_owned());
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

        let security = raw_params
            .get("security")
            .map(|s| Security::parse(s))
            .unwrap_or(Security::None);
        let network = raw_params
            .get("type")
            .map(|s| NetworkType::parse(s))
            .unwrap_or(NetworkType::Tcp);

        let sni = raw_params.get("sni").cloned();
        let fingerprint = raw_params.get("fp").cloned();
        let flow = Flow::parse(raw_params.get("flow").map(String::as_str))?;
        let remark = url.fragment().map(percent_decode);

        Ok(VlessConfig {
            id,
            host,
            port,
            encryption,
            security,
            sni,
            fingerprint,
            flow,
            network,
            remark,
            raw_params,
        })
    }

    /// Проверить, что `flow=` из ссылки этот клиент умеет. Сейчас XTLS
    /// Vision не реализован (PLAN.md, "План дальнейших действий", шаг 3):
    /// сервер с `flow = xtls-rprx-vision` отвергает TCP-запрос с пустым
    /// flow (`inbound.go`: "rejected since the client flow is empty"),
    /// так что вместо тихого отказа на стороне сервера — понятная ошибка
    /// здесь, до установки соединения.
    pub fn ensure_flow_supported(&self) -> Result<()> {
        if self.flow.is_vision() {
            return Err(Error::InvalidUri(
                "flow=xtls-rprx-vision (XTLS Vision) пока не поддерживается этим клиентом; \
                 сервер с таким flow отвергнет соединение без него"
                    .into(),
            ));
        }
        Ok(())
    }

    /// SNI, который реально пойдёт в ClientHello: явный `sni=`, иначе host.
    pub fn effective_sni(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
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
        let pbk_str = self
            .raw_params
            .get("pbk")
            .ok_or_else(|| Error::InvalidUri("security=reality, но в ссылке нет pbk=".into()))?;
        let pbk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(pbk_str.trim_end_matches('='))
            .map_err(|e| Error::InvalidUri(format!("pbk= не является base64url: {e}")))?;
        if pbk_bytes.len() != 32 {
            return Err(Error::InvalidUri(format!(
                "pbk= должен декодироваться в 32 байта (X25519-ключ), получено {}",
                pbk_bytes.len()
            )));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&pbk_bytes);

        // sid= необязателен у Xray-core (сервер может быть настроен с
        // пустым shortIds), поэтому отсутствие ключа — не ошибка, в
        // отличие от pbk=.
        let short_id = match self.raw_params.get("sid") {
            Some(s) if !s.is_empty() => hex::decode(s)
                .map_err(|e| Error::InvalidUri(format!("sid= не является hex: {e}")))?,
            _ => Vec::new(),
        };
        if short_id.len() > crate::reality::SHORT_ID_LEN {
            return Err(Error::InvalidUri(format!(
                "sid= длиннее {} байт: {}",
                crate::reality::SHORT_ID_LEN,
                short_id.len()
            )));
        }

        Ok(RealityParams {
            public_key,
            short_id,
        })
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
        assert_eq!(cfg.flow, Flow::XtlsRprxVision);
        let cfg = VlessConfig::parse(&format!("{base}&flow=xtls-rprx-vision-udp443")).unwrap();
        assert_eq!(cfg.flow, Flow::XtlsRprxVisionUdp443);

        let err = VlessConfig::parse(&format!("{base}&flow=xtls-rprx-direct")).unwrap_err();
        assert!(matches!(err, Error::InvalidUri(_)));
    }

    /// Пока Vision не реализован — явная ошибка до соединения, а не
    /// пустой flow, который сервер молча отвергнет.
    #[test]
    fn vision_flow_is_reported_as_unsupported_for_now() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&flow=xtls-rprx-vision";
        let cfg = VlessConfig::parse(uri).unwrap();
        let err = cfg.ensure_flow_supported().unwrap_err();
        assert!(err.to_string().contains("xtls-rprx-vision"));
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
