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

use async_tungstenite::client_async;
use async_tungstenite::tungstenite::handshake::client::generate_key;
use async_tungstenite::tungstenite::http::Request;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use uuid::Uuid;
use ws_stream_tungstenite::WsStream;

use crate::error::{Error, Result};
use crate::transport::tcp_tls::{connect_tls_by_security, TlsBoxedStream};
use crate::vless::protocol::{vless_connect, Address, Command, VlessStream};
use crate::vless::VlessConfig;

pub type WsVlessStream = WsStream<Compat<TlsBoxedStream>>;

/// Поднять TCP+TLS (обычный или REALITY, по `cfg.security` — Этап 5) и
/// выполнить поверх него обычный HTTP Upgrade до WebSocket, используя
/// `path=` из ссылки (по умолчанию `/`) и `Host` = SNI-сервера. Маскировка
/// TLS-отпечатка под браузер (Этап 3) по-прежнему не делается — это
/// отдельный архитектурный вопрос, см. PLAN.md.
pub async fn connect_ws(cfg: &VlessConfig) -> Result<WsVlessStream> {
    let tls = connect_tls_by_security(cfg, Vec::new()).await?;
    let compat_tls = tls.compat();

    let host = cfg.effective_sni();
    let uri = format!("wss://{host}{}", cfg.path());

    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())
        .map_err(|e| Error::Protocol(format!("не удалось собрать WS-запрос: {e}")))?;

    let (ws, _response) = client_async(request, compat_tls)
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
    cfg.ensure_flow_supported()?;
    let stream = connect_ws(cfg).await?;
    vless_connect(stream, id, Command::Tcp, &target, target_port).await
}
