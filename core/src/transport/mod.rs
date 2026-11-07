// SPDX-License-Identifier: GPL-3.0-or-later
pub mod browser_headers;
pub mod browser_mimic;
pub mod config;
pub mod fragment;
pub mod grpc;
pub mod h2pool;
pub mod httpupgrade;
pub mod noise;
pub mod quic;
pub mod raw;
pub mod tcp_tls;
pub mod ws;
pub mod xhttp;

pub use tcp_tls::{
    connect_and_handshake, connect_tls, connect_tls_capturing_client_hello, connect_tls_with_alpn,
    connect_tls_with_roots, CapturingTlsStream, SecureStream, TcpVlessStream, TlsBoxedStream,
};

use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::error::Result;
use crate::vless::{Address, Command, Flow, VlessConfig};
pub use config::{NetworkType, RealityParams, Security, TransportConfig};

/// Любой поток, который возвращают транспорты (TCP/TLS/REALITY, Vision,
/// WebSocket, gRPC), — чтобы вызывающему коду не знать конкретный тип.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// Открыть VLESS-сессию с командой `command` (TCP или UDP) до
/// `target:port` через транспорт из ссылки (`type=`).
pub async fn dial(
    cfg: &VlessConfig,
    id: &Uuid,
    command: Command,
    target: Address,
    port: u16,
) -> Result<Box<dyn AsyncStream>> {
    cfg.ensure_flow_supported()?;
    dial_config(
        &TransportConfig::from(cfg),
        id,
        cfg.flow,
        command,
        target,
        port,
    )
    .await
}

/// Открыть VLESS-сессию, используя общий транспортный конфиг и отдельно
/// переданные VLESS credentials/flow.
pub async fn dial_config(
    cfg: &TransportConfig,
    id: &Uuid,
    flow: Flow,
    command: Command,
    target: Address,
    port: u16,
) -> Result<Box<dyn AsyncStream>> {
    if flow.is_vision() && cfg.network != NetworkType::Tcp {
        return Err(crate::error::Error::InvalidUri(format!(
            "flow=xtls-rprx-vision работает только с type=tcp, а в конфигурации type={:?}",
            cfg.network
        )));
    }
    if flow.is_vision() && cfg.security == Security::None {
        return Err(crate::error::Error::InvalidUri(
            "flow=xtls-rprx-vision требует security=tls или security=reality".into(),
        ));
    }
    Ok(match cfg.network {
        NetworkType::Tcp => {
            Box::new(tcp_tls::connect_command_config(cfg, id, flow, command, target, port).await?)
        }
        NetworkType::Ws => {
            Box::new(ws::connect_command_ws_config(cfg, id, command, target, port).await?)
        }
        NetworkType::Grpc => {
            Box::new(grpc::connect_command_grpc_config(cfg, id, command, target, port).await?)
        }
        NetworkType::HttpUpgrade => Box::new(
            httpupgrade::connect_command_httpupgrade_config(cfg, id, command, target, port).await?,
        ),
        NetworkType::Xhttp => {
            Box::new(xhttp::connect_command_xhttp_config(cfg, id, command, target, port).await?)
        }
    })
}

/// Поднять транспорт из ссылки (TLS/REALITY и ws, grpc, httpupgrade,
/// xhttp) без заголовка VLESS — для других протоколов поверх тех же
/// транспортов (Trojan).
pub async fn open(cfg: &TransportConfig) -> Result<Box<dyn AsyncStream>> {
    Ok(match cfg.network {
        NetworkType::Tcp => {
            Box::new(tcp_tls::connect_tls_by_security(cfg, tcp_tls::default_alpn(cfg)).await?)
        }
        NetworkType::Ws => Box::new(ws::connect_ws(cfg).await?),
        NetworkType::Grpc => Box::new(grpc::connect_grpc(cfg).await?),
        NetworkType::HttpUpgrade => Box::new(httpupgrade::connect_httpupgrade(cfg).await?),
        NetworkType::Xhttp => Box::new(xhttp::connect_xhttp(cfg).await?),
    })
}
