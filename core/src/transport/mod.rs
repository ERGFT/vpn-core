pub mod browser_headers;
pub mod grpc;
pub mod httpupgrade;
pub mod raw;
pub mod tcp_tls;
pub mod ws;

pub use tcp_tls::{
    connect_and_handshake, connect_tls, connect_tls_capturing_client_hello, connect_tls_with_alpn,
    connect_tls_with_roots, CapturingTlsStream, SecureStream, TcpVlessStream, TlsBoxedStream,
};

use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::error::Result;
use crate::vless::{Address, Command, NetworkType, VlessConfig};

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
    Ok(match cfg.network {
        NetworkType::Tcp => {
            Box::new(tcp_tls::connect_command(cfg, id, command, target, port).await?)
        }
        NetworkType::Ws => Box::new(ws::connect_command_ws(cfg, id, command, target, port).await?),
        NetworkType::Grpc => {
            Box::new(grpc::connect_command_grpc(cfg, id, command, target, port).await?)
        }
        NetworkType::HttpUpgrade => Box::new(
            httpupgrade::connect_command_httpupgrade(cfg, id, command, target, port).await?,
        ),
        NetworkType::Xhttp => {
            return Err(crate::Error::InvalidUri(
                "type=xhttp пока не поддерживается".into(),
            ))
        }
    })
}
