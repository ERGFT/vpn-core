//! Выход `vless`: VLESS-сервер (любой транспорт, REALITY/TLS, Vision).
//!
//! TCP — `transport::dial` с общим потолком времени. UDP — две схемы:
//! XUDP (по умолчанию, как у клиента Xray: все назначения в одном потоке,
//! Full Cone) и «поток на назначение» (команда UDP) для серверов без XUDP.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};

use super::outbound::{Outbound, Packet, UdpSession, UDP_IDLE};
use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::{self, AsyncStream};
use crate::vless::mux::MuxPool;
use crate::vless::{xudp, Address, Command, VlessConfig};

/// Потолок на открытие одного соединения целиком: разрешение имени, TCP,
/// TLS или REALITY и заголовок VLESS.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Очередь датаграмм к потоку, который ещё открывается; лишнее
/// отбрасывается (для UDP это нормально при перегрузке).
const QUEUE: usize = 64;
/// Режим без XUDP: не больше стольких назначений на одну сессию.
const MAX_DESTS: usize = 256;
/// Режим без XUDP: потолок на данные в очередях одной сессии.
const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;

pub struct VlessOutbound {
    tag: String,
    cfg: Arc<VlessConfig>,
    xudp: bool,
    /// Mux.Cool для TCP (если включён).
    mux: Option<MuxPool>,
    /// Новый поток Mux.Cool открывается по одному.
    mux_opening: Mutex<()>,
}

impl VlessOutbound {
    /// Адрес сервера (для заблаговременного разрешения имени перед TUN).
    pub fn server_addr(&self) -> (String, u16) {
        (self.cfg.host.clone(), self.cfg.port)
    }

    pub fn new(tag: impl Into<String>, cfg: VlessConfig, xudp: bool) -> Self {
        VlessOutbound {
            tag: tag.into(),
            cfg: Arc::new(cfg),
            xudp,
            mux: None,
            mux_opening: Mutex::new(()),
        }
    }

    /// Включить Mux.Cool: до `concurrency` TCP-соединений в одном потоке.
    /// С XTLS Vision несовместим.
    pub fn with_mux(mut self, concurrency: u16) -> Result<Self> {
        if self.cfg.flow.is_vision() {
            return Err(Error::Config(format!(
                "выход {}: mux несовместим с flow=xtls-rprx-vision (Xray рвёт такие \
                 потоки); уберите mux или flow",
                self.tag
            )));
        }
        if !(1..=128).contains(&concurrency) {
            return Err(Error::Config(format!(
                "выход {}: mux — от 1 до 128 соединений в потоке",
                self.tag
            )));
        }
        self.mux = Some(MuxPool::new(concurrency as usize));
        Ok(self)
    }

    /// Соединение через Mux.Cool.
    async fn connect_mux(&self, pool: &MuxPool, meta: &Metadata) -> Result<Box<dyn AsyncStream>> {
        for _ in 0..2 {
            let conn = match pool.pick() {
                Some(c) => c,
                None => {
                    let _one = self.mux_opening.lock().await;
                    match pool.pick() {
                        Some(c) => c,
                        None => {
                            let s = dial(
                                &self.cfg,
                                Command::Mux,
                                Address::Domain(xudp::MUX_COOL_DOMAIN.into()),
                                xudp::XUDP_PORT,
                            )
                            .await?;
                            tracing::debug!(outbound = %self.tag, "Mux.Cool: новый поток");
                            pool.add(s)
                        }
                    }
                }
            };
            match conn.open(&meta.target, meta.port).await {
                Ok(s) => return Ok(Box::new(s)),
                // Поток закрылся между выбором и открытием — ещё раз.
                Err(e) => tracing::debug!(error = %e, "Mux.Cool: поток закрыт, повтор"),
            }
        }
        Err(Error::Protocol(
            "Mux.Cool: не удалось открыть соединение".into(),
        ))
    }

    pub fn config(&self) -> &VlessConfig {
        &self.cfg
    }
}

async fn dial(
    cfg: &VlessConfig,
    command: Command,
    target: Address,
    port: u16,
) -> Result<Box<dyn AsyncStream>> {
    tokio::time::timeout(
        DIAL_TIMEOUT,
        transport::dial(cfg, &cfg.id, command, target, port),
    )
    .await
    .map_err(|_| {
        Error::Protocol(format!(
            "сервер не завершил рукопожатие за {} с",
            DIAL_TIMEOUT.as_secs()
        ))
    })?
}

impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn server(&self) -> Option<(String, u16)> {
        Some(self.server_addr())
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        if let Some(pool) = &self.mux {
            return Box::pin(self.connect_mux(pool, meta));
        }
        Box::pin(dial(
            &self.cfg,
            Command::Tcp,
            meta.target.clone(),
            meta.port,
        ))
    }

    fn udp<'a>(&'a self, _meta: &'a Metadata) -> BoxFuture<'a, Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let s: Arc<dyn UdpSession> = if self.xudp {
                Arc::new(XudpSession::start(self.cfg.clone()))
            } else {
                Arc::new(PerDestSession::new(self.cfg.clone()))
            };
            Ok(s)
        })
    }
}

/// XUDP: один VLESS-поток с командой Mux на всю сессию. Поток открывается
/// в фоне; датаграммы до этого ждут в очереди.
struct XudpSession {
    tx: mpsc::Sender<Packet>,
    rx: Mutex<mpsc::Receiver<Packet>>,
}

impl XudpSession {
    fn start(cfg: Arc<VlessConfig>) -> Self {
        let (tx, mut up_rx) = mpsc::channel::<Packet>(QUEUE);
        let (down_tx, down_rx) = mpsc::channel::<Packet>(QUEUE);
        // GlobalID — один на сессию: сервер закрепляет за ней внешний порт.
        let mut global_id = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut global_id);
        tokio::spawn(async move {
            let stream = match dial(
                &cfg,
                Command::Mux,
                Address::Domain(xudp::MUX_COOL_DOMAIN.into()),
                xudp::XUDP_PORT,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "UDP: не удалось открыть XUDP-поток");
                    return;
                }
            };
            tracing::info!("UDP: XUDP-поток открыт");
            let (mut r, mut w) = tokio::io::split(stream);
            let last = std::sync::Mutex::new(tokio::time::Instant::now());
            let touch = || *last.lock().unwrap() = tokio::time::Instant::now();
            let mut writer = xudp::XudpWriter::new(global_id);
            // Если сервер не указал источник ответа — считаем им первое назначение.
            let first_dest: std::sync::Mutex<Option<(Address, u16)>> = std::sync::Mutex::new(None);
            let up = async {
                while let Some((addr, port, data)) = up_rx.recv().await {
                    touch();
                    first_dest
                        .lock()
                        .unwrap()
                        .get_or_insert_with(|| (addr.clone(), port));
                    let Some(frame) = writer.encode(&addr, port, &data) else {
                        continue;
                    };
                    if w.write_all(&frame).await.is_err() || w.flush().await.is_err() {
                        break;
                    }
                }
            };
            let down = async {
                while let Ok(Some(p)) = xudp::read_packet(&mut r).await {
                    touch();
                    let Some((addr, port)) =
                        p.source.or_else(|| first_dest.lock().unwrap().clone())
                    else {
                        continue;
                    };
                    if down_tx.send((addr, port, p.data)).await.is_err() {
                        break;
                    }
                }
            };
            let idle = async {
                loop {
                    let deadline = *last.lock().unwrap() + UDP_IDLE;
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::time::sleep_until(deadline).await;
                }
            };
            tokio::select! {
                _ = up => {}
                _ = down => {}
                _ = idle => {}
            }
            tracing::debug!("UDP: XUDP-поток закрыт");
        });
        XudpSession {
            tx,
            rx: Mutex::new(down_rx),
        }
    }
}

impl UdpSession for XudpSession {
    fn send(&self, dst: Address, port: u16, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if data.len() > xudp::MAX_PAYLOAD {
                tracing::debug!(
                    len = data.len(),
                    "UDP: датаграмма больше, чем принимает XUDP, — отброшена"
                );
                return Ok(());
            }
            match self.tx.try_send((dst, port, data)) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Err(Error::Protocol("XUDP-поток закрыт".into()))
                }
            }
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move { Ok(self.rx.lock().await.recv().await) })
    }
}

/// Без XUDP: для каждого назначения свой VLESS-поток с командой UDP.
/// Назначение → очередь его датаграмм.
type DestMap = HashMap<(Address, u16), mpsc::Sender<Vec<u8>>>;

struct PerDestSession {
    cfg: Arc<VlessConfig>,
    dests: Mutex<DestMap>,
    down_tx: mpsc::Sender<Packet>,
    down_rx: Mutex<mpsc::Receiver<Packet>>,
    budget: Arc<AtomicUsize>,
}

impl PerDestSession {
    fn new(cfg: Arc<VlessConfig>) -> Self {
        let (down_tx, down_rx) = mpsc::channel(QUEUE);
        PerDestSession {
            cfg,
            dests: Mutex::new(HashMap::new()),
            down_tx,
            down_rx: Mutex::new(down_rx),
            budget: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn spawn_dest(&self, addr: Address, port: u16) -> mpsc::Sender<Vec<u8>> {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let cfg = self.cfg.clone();
        let down = self.down_tx.clone();
        let budget = self.budget.clone();
        tokio::spawn(async move {
            let session = async {
                let stream = match dial(&cfg, Command::Udp, addr.clone(), port).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "UDP: не удалось открыть поток");
                        return;
                    }
                };
                let (mut r, mut w) = tokio::io::split(stream);
                let up = async {
                    while let Ok(Some(p)) = tokio::time::timeout(UDP_IDLE, rx.recv()).await {
                        budget.fetch_sub(p.len(), Ordering::Relaxed);
                        if crate::vless::udp::write_packet(&mut w, &p).await.is_err() {
                            break;
                        }
                    }
                };
                let down_loop = async {
                    let mut pkt = Vec::new();
                    while let Ok(Ok(Some(()))) = tokio::time::timeout(
                        UDP_IDLE,
                        crate::vless::udp::read_packet(&mut r, &mut pkt),
                    )
                    .await
                    {
                        if down
                            .send((addr.clone(), port, std::mem::take(&mut pkt)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                };
                tokio::select! {
                    _ = up => {}
                    _ = down_loop => {}
                }
            };
            session.await;
            rx.close();
            while let Ok(p) = rx.try_recv() {
                budget.fetch_sub(p.len(), Ordering::Relaxed);
            }
        });
        tx
    }
}

impl UdpSession for PerDestSession {
    fn send(&self, dst: Address, port: u16, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let len = data.len();
            if self.budget.load(Ordering::Relaxed) + len > MAX_QUEUED_BYTES {
                return Ok(());
            }
            self.budget.fetch_add(len, Ordering::Relaxed);
            let mut dests = self.dests.lock().await;
            let key = (dst, port);
            let data = match dests.get(&key) {
                Some(tx) => match tx.try_send(data) {
                    Ok(()) => return Ok(()),
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        self.budget.fetch_sub(len, Ordering::Relaxed);
                        return Ok(());
                    }
                    Err(mpsc::error::TrySendError::Closed(d)) => {
                        dests.remove(&key);
                        d
                    }
                },
                None => data,
            };
            dests.retain(|_, tx| !tx.is_closed());
            if dests.len() >= MAX_DESTS {
                tracing::warn!("UDP: слишком много назначений в одной ассоциации");
                self.budget.fetch_sub(len, Ordering::Relaxed);
                return Ok(());
            }
            let tx = self.spawn_dest(key.0.clone(), key.1);
            if tx.try_send(data).is_err() {
                self.budget.fetch_sub(len, Ordering::Relaxed);
            }
            dests.insert(key, tx);
            Ok(())
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move {
            // Сессия живёт, пока жив хоть один поток; сама по себе она не
            // закрывается — закрытие по тишине делает ассоциация.
            let mut rx = self.down_rx.lock().await;
            loop {
                match tokio::time::timeout(UDP_IDLE, rx.recv()).await {
                    Ok(p) => return Ok(p),
                    Err(_) => {
                        let dests = self.dests.lock().await;
                        if dests.values().all(|t| t.is_closed()) {
                            return Ok(None);
                        }
                    }
                }
            }
        })
    }
}
