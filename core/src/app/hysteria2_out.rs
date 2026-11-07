// SPDX-License-Identifier: GPL-3.0-or-later
//! Production outbound for the Hysteria 2 QUIC transport.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use tokio::sync::Mutex;

use super::outbound::{Outbound, OutboundCapabilities, UdpSession};
use super::Metadata;
use crate::error::Result;
use crate::hysteria2::Hysteria2Config;
use crate::hysteria2_transport::{self, Hysteria2Connection};
use crate::transport::AsyncStream;

pub struct Hysteria2Outbound {
    tag: String,
    config: Hysteria2Config,
    connection: Mutex<Option<Arc<Hysteria2Connection>>>,
}

impl Hysteria2Outbound {
    pub fn new(tag: impl Into<String>, config: Hysteria2Config) -> Self {
        Self {
            tag: tag.into(),
            config,
            connection: Mutex::new(None),
        }
    }

    async fn connection(&self) -> Result<Arc<Hysteria2Connection>> {
        let mut current = self.connection.lock().await;
        if let Some(connection) = current
            .as_ref()
            .filter(|connection| connection.connection.close_reason().is_none())
        {
            return Ok(connection.clone());
        }

        let connection = Arc::new(hysteria2_transport::connect(&self.config).await?);
        *current = Some(connection.clone());
        Ok(connection)
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
