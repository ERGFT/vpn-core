// SPDX-License-Identifier: GPL-3.0-or-later
//! Выход `trojan`: сервер Trojan поверх TLS/REALITY и транспортов VLESS.
//! TCP — поток на соединение; UDP — один поток (команда UDP) на
//! UDP-сессию, в нём пакеты к любым адресам.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};

use super::outbound::{Outbound, Packet, UdpSession, UDP_IDLE};
use super::vless_out::DIAL_TIMEOUT;
use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::{self, AsyncStream};
use crate::trojan::{self, TrojanConfig};

const QUEUE: usize = 64;

pub struct TrojanOutbound {
    tag: String,
    cfg: Arc<TrojanConfig>,
    key: Arc<str>,
}

impl TrojanOutbound {
    pub fn new(tag: impl Into<String>, cfg: TrojanConfig) -> Self {
        let key = cfg.key().into();
        TrojanOutbound {
            tag: tag.into(),
            cfg: Arc::new(cfg),
            key,
        }
    }

    pub fn config(&self) -> &TrojanConfig {
        &self.cfg
    }
}

async fn open(
    cfg: &TrojanConfig,
    key: &str,
    cmd: u8,
    target: &crate::vless::Address,
    port: u16,
) -> Result<Box<dyn AsyncStream>> {
    tokio::time::timeout(DIAL_TIMEOUT, async {
        let mut s = transport::open(&cfg.transport).await?;
        s.write_all(&trojan::request(key, cmd, target, port))
            .await?;
        s.flush().await?;
        Ok(s)
    })
    .await
    .map_err(|_| {
        Error::Protocol(format!(
            "trojan: сервер не ответил за {} с",
            DIAL_TIMEOUT.as_secs()
        ))
    })?
}

impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn clash_type(&self) -> &'static str {
        "Trojan"
    }

    fn server(&self) -> Option<(String, u16)> {
        Some((self.cfg.transport.host.clone(), self.cfg.transport.port))
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(open(
            &self.cfg,
            &self.key,
            trojan::CMD_TCP,
            &meta.target,
            meta.port,
        ))
    }

    fn udp<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            Ok(
                Arc::new(TrojanUdp::start(self.cfg.clone(), self.key.clone()))
                    as Arc<dyn UdpSession>,
            )
        })
    }
}

/// UDP-сессия: поток открывается при первой датаграмме (её адрес — в
/// заголовке, как у Xray).
struct TrojanUdp {
    tx: mpsc::Sender<Packet>,
    rx: Mutex<mpsc::Receiver<Packet>>,
}

impl TrojanUdp {
    fn start(cfg: Arc<TrojanConfig>, key: Arc<str>) -> Self {
        let (tx, mut up_rx) = mpsc::channel::<Packet>(QUEUE);
        let (down_tx, down_rx) = mpsc::channel::<Packet>(QUEUE);
        tokio::spawn(async move {
            let Some(first) = up_rx.recv().await else {
                return;
            };
            let stream = match open(&cfg, &key, trojan::CMD_UDP, &first.0, first.1).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "trojan UDP: поток не открылся");
                    return;
                }
            };
            let (mut r, mut w) = tokio::io::split(stream);
            let up = async {
                let mut next = Some(first);
                loop {
                    let p = match next.take() {
                        Some(p) => p,
                        None => match tokio::time::timeout(UDP_IDLE, up_rx.recv()).await {
                            Ok(Some(p)) => p,
                            _ => break,
                        },
                    };
                    let Some(pkt) = trojan::udp_packet(&p.0, p.1, &p.2) else {
                        continue;
                    };
                    if w.write_all(&pkt).await.is_err() || w.flush().await.is_err() {
                        break;
                    }
                }
            };
            let down = async {
                while let Ok(Ok(Some(p))) =
                    tokio::time::timeout(UDP_IDLE, trojan::read_udp_packet(&mut r)).await
                {
                    if down_tx.send(p).await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = up => {}
                _ = down => {}
            }
        });
        TrojanUdp {
            tx,
            rx: Mutex::new(down_rx),
        }
    }
}

impl UdpSession for TrojanUdp {
    fn send(
        &self,
        dst: crate::vless::Address,
        port: u16,
        data: Vec<u8>,
    ) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            match self.tx.try_send((dst, port, data)) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Err(Error::Protocol("trojan UDP: поток закрыт".into()))
                }
            }
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move { Ok(self.rx.lock().await.recv().await) })
    }
}
