//! Транспорт Этапа 4: VLESS поверх WebSocket-соединения внутри TLS.
//!
//! Используем готовые библиотеки (`async-tungstenite` — само
//! WS-рукопожатие и фреймирование, `ws_stream_tungstenite` — превращает
//! его в обычный поток) — см. риск "соло против комьюнити" в PLAN.md,
//! Этап 4: фреймер WebSocket самим не пишем.
//!
//! `ws_stream_tungstenite` внутри работает поверх `futures_io`, а не
//! `tokio::io` (так устроен `async-tungstenite`, на котором она
//! построена) — оборачиваем наш `TlsStream` через `tokio_util::compat`,
//! а на выходе `WsStream` (feature `tokio_io`) уже сама отдаёт
//! `tokio::io::AsyncRead + AsyncWrite`, которые ждут `vless_handshake` и
//! `relay::copy_bidirectional`.

use async_tungstenite::client_async_with_config;
use async_tungstenite::tungstenite::handshake::client::generate_key;
use async_tungstenite::tungstenite::http::Request;
use async_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use uuid::Uuid;
use ws_stream_tungstenite::WsStream;

use crate::error::{Error, Result};
use crate::transport::tcp_tls::{connect_tls_by_security, SecureStream};
use crate::vless::protocol::{vless_connect, Address, Command, VlessStream};
use crate::vless::VlessConfig;

/// Потолок на одно сообщение WebSocket от сервера.
const MAX_WS_MESSAGE: usize = 1024 * 1024;

pub type WsVlessStream = WsStream<Compat<SecureStream>>;

/// Поднять TCP (+TLS или REALITY, по `cfg.security`) и выполнить поверх
/// него HTTP Upgrade до WebSocket: `path=` из ссылки (по умолчанию `/`),
/// `Host` — `host=` из ссылки или SNI.
pub async fn connect_ws(cfg: &VlessConfig) -> Result<WsVlessStream> {
    // WebSocket — это HTTP/1.1 Upgrade, поэтому ALPN по умолчанию
    // `http/1.1` (как делает Xray для ws); `alpn=` из ссылки главнее.
    let alpn = cfg.alpn().unwrap_or_else(|| vec![b"http/1.1".to_vec()]);
    let stream = connect_tls_by_security(cfg, alpn).await?;
    let compat_tls = stream.compat();

    // Host — `host=` из ссылки (для CDN он часто отличается от SNI), иначе SNI.
    let host = cfg.ws_host();
    let scheme = if cfg.security == crate::vless::Security::None {
        "ws"
    } else {
        "wss"
    };
    let uri = format!("{scheme}://{host}{}", cfg.http_path());

    // Заголовки Chrome, как делает Xray (`TryDefaultHeadersWith(.., "ws")`):
    // запрос Upgrade без User-Agent и Sec-Fetch-* выделяется среди
    // браузерных — особенно в логах CDN.
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", host);
    for (k, v) in crate::transport::browser_headers::headers(
        cfg.browser,
        crate::transport::browser_headers::Variant::Ws,
    ) {
        builder = builder.header(k, v);
    }
    let request = builder
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())
        .map_err(|e| Error::Protocol(format!("не удалось собрать WS-запрос: {e}")))?;

    // Пределы на сообщение и кадр от сервера: по умолчанию у tungstenite
    // 64 МиБ и 16 МиБ, и каждое соединение могло копить столько в памяти.
    // Xray шлёт кадры по ~8 КиБ.
    let limits = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE));
    let (ws, _response) = client_async_with_config(request, compat_tls, Some(limits))
        .await
        .map_err(|e| Error::Protocol(format!("WS upgrade не удался: {e}")))?;

    Ok(WsStream::new(ws))
}

/// Полное открытие соединения Этапа 4 (WS): TCP -> TLS -> WS upgrade ->
/// заголовок запроса VLESS (ответ снимается
/// лениво, см. `vless_connect`).
pub async fn connect_and_handshake_ws(
    cfg: &VlessConfig,
    id: &Uuid,
    target: Address,
    target_port: u16,
) -> Result<VlessStream<WsVlessStream>> {
    connect_command_ws(cfg, id, Command::Tcp, target, target_port).await
}

/// Как [`connect_and_handshake_ws`], но с явной командой VLESS (TCP/UDP).
pub async fn connect_command_ws(
    cfg: &VlessConfig,
    id: &Uuid,
    command: Command,
    target: Address,
    target_port: u16,
) -> Result<VlessStream<WsVlessStream>> {
    cfg.ensure_flow_supported()?;
    let stream = connect_ws(cfg).await?;
    vless_connect(stream, id, command, &target, target_port).await
}
