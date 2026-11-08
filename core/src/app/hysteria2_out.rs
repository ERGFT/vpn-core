// SPDX-License-Identifier: GPL-3.0-or-later
//! Production outbound for the Hysteria 2 QUIC transport.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;

use super::outbound::{Outbound, OutboundCapabilities, UdpSession};
use super::Metadata;
use crate::error::Result;
use crate::hysteria2::Hysteria2Config;
use crate::hysteria2_transport::{self, Hysteria2Connection};
use crate::transport::AsyncStream;

pub struct Hysteria2Outbound {
    tag: String,
    config: Hysteria2Config,
    roots: Option<rustls::RootCertStore>,
    network_generation: AtomicU64,
    connection: Mutex<Option<(u64, Arc<Hysteria2Connection>)>>,
    connecting: tokio::sync::Mutex<()>,
}

impl Hysteria2Outbound {
    pub fn new(tag: impl Into<String>, config: Hysteria2Config) -> Self {
        Self {
            tag: tag.into(),
            config,
            roots: None,
            network_generation: AtomicU64::new(0),
            connection: Mutex::new(None),
            connecting: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) fn with_roots(mut self, roots: Option<rustls::RootCertStore>) -> Self {
        self.roots = roots;
        self
    }

    async fn connection(&self) -> Result<Arc<Hysteria2Connection>> {
        loop {
            let generation = self.network_generation.load(Ordering::Acquire);
            if let Some(connection) = self.cached_connection(generation) {
                return Ok(connection);
            }

            // Serialize first dials without holding a synchronous lock over
            // the network await. A network-change callback can invalidate the
            // generation while the handshake is in progress.
            let _connecting = self.connecting.lock().await;
            let generation = self.network_generation.load(Ordering::Acquire);
            if let Some(connection) = self.cached_connection(generation) {
                return Ok(connection);
            }

            let fresh =
                Arc::new(hysteria2_transport::connect(&self.config, self.roots.clone()).await?);
            let mut current = self
                .connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.network_generation.load(Ordering::Acquire) != generation {
                fresh
                    .connection
                    .close(0u32.into(), b"network changed during connect");
                continue;
            }
            if let Some((cached_generation, connection)) = current.as_ref() {
                if *cached_generation == generation
                    && connection.connection.close_reason().is_none()
                {
                    return Ok(connection.clone());
                }
            }

            let previous = current.replace((generation, fresh.clone()));
            drop(current);
            if let Some((_, previous)) = previous {
                previous.connection.close(0u32.into(), b"network changed");
            }
            return Ok(fresh);
        }
    }

    fn cached_connection(&self, generation: u64) -> Option<Arc<Hysteria2Connection>> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|(cached_generation, connection)| {
                *cached_generation == generation && connection.connection.close_reason().is_none()
            })
            .map(|(_, connection)| connection.clone())
    }
}

impl Outbound for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn clash_type(&self) -> &'static str {
        "Hysteria2"
    }

    fn capabilities(&self) -> OutboundCapabilities {
        // This transport owns a protected UDP socket and cannot currently be
        // carried by another outbound's TCP detour.
        OutboundCapabilities::TCP_UDP_TERMINAL
    }

    fn network_changed(&self) {
        self.network_generation.fetch_add(1, Ordering::AcqRel);
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((_, connection)) = connection {
            connection.connection.close(0u32.into(), b"network changed");
        }
    }

    fn server(&self) -> Option<(String, u16)> {
        self.config
            .ports
            .first()
            .map(|port| (self.config.server.clone(), port.first))
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            self.connection()
                .await?
                .connect_tcp(&meta.target, meta.port)
                .await
        })
    }

    fn udp<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move { self.connection().await?.open_udp_session().await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_change_advances_generation_and_clears_cached_connection() {
        let config = Hysteria2Config::parse("hy2://password@localhost").unwrap();
        let outbound = Hysteria2Outbound::new("hy2", config);

        outbound.network_changed();

        assert_eq!(outbound.network_generation.load(Ordering::Acquire), 1);
        assert!(outbound
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none());
    }
}
