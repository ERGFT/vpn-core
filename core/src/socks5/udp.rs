//! SOCKS5 UDP ASSOCIATE (RFC 1928 §7) поверх VLESS.
//!
//! Приложение (DNS-клиент, QUIC в браузере, игра) шлёт датаграммы на
//! выданный нами UDP-порт, каждая с заголовком SOCKS5 (адрес назначения).
//! Два способа доставки:
//!
//! - [`serve_associate_xudp`] (по умолчанию в клиенте) — XUDP, как у
//!   клиента Xray: все назначения в одном VLESS-потоке, Full Cone NAT
//!   (`crate::vless::xudp`);
//! - [`serve_associate`] — для каждого назначения свой VLESS-поток с
//!   командой UDP, пакеты внутри с 2-байтной длиной (`crate::vless::udp`).
//!
//! Ответы уходят приложению с заголовком, где адрес — источник ответа.
//!
//! Ассоциация живёт, пока открыто управляющее TCP-соединение (так требует
//! RFC); поток к назначению закрывается после [`SESSION_IDLE`] тишины.
//! Датаграммы принимаются только с IP-адреса, открывшего ассоциацию.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::{reply_success, TargetAddr};
use crate::error::{Error, Result};
use crate::vless::{xudp, Address};

/// Поток к назначению закрывается после стольких секунд без пакетов.
pub const SESSION_IDLE: Duration = Duration::from_secs(120);
/// Не больше стольких одновременных назначений на одну ассоциацию.
const MAX_SESSIONS: usize = 256;
/// Очередь пакетов к ещё открывающемуся потоку; лишнее отбрасывается
/// (для UDP это нормальное поведение при перегрузке).
const QUEUE: usize = 64;
/// Потолок на данные, ждущие в очередях одной ассоциации (режим без
/// XUDP): пока потоки к назначениям открываются, датаграммы копятся.
/// Без него сотня назначений по 64 датаграммы по 64 КиБ занимала
/// гигабайты.
const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;

/// Разобрать заголовок датаграммы SOCKS5: `RSV(2) FRAG(1) ATYP АДРЕС ПОРТ`.
/// Возвращает назначение и смещение данных. Фрагменты (`FRAG != 0`) не
/// поддерживаются — RFC разрешает их отбрасывать.
pub fn parse_datagram(buf: &[u8]) -> Result<(TargetAddr, u16, usize)> {
    let bad = || Error::Socks5("битый заголовок UDP-датаграммы".into());
    if buf.len() < 4 {
        return Err(bad());
    }
    if buf[2] != 0 {
        return Err(Error::Socks5(
            "фрагментированные UDP-датаграммы не поддерживаются".into(),
        ));
    }
    let (addr, at) = match buf[3] {
        0x01 => {
            let b: [u8; 4] = buf.get(4..8).ok_or_else(bad)?.try_into().unwrap();
            (TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(b))), 8)
        }
        0x04 => {
            let b: [u8; 16] = buf.get(4..20).ok_or_else(bad)?.try_into().unwrap();
            (TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(b))), 20)
        }
        0x03 => {
            let len = *buf.get(4).ok_or_else(bad)? as usize;
            let d = buf.get(5..5 + len).ok_or_else(bad)?;
            let d = String::from_utf8(d.to_vec())
                .map_err(|_| Error::Socks5("домен не в UTF-8".into()))?;
            (TargetAddr::Domain(d), 5 + len)
        }
        other => return Err(Error::UnsupportedAddressType(other)),
    };
    let p = buf.get(at..at + 2).ok_or_else(bad)?;
    Ok((addr, u16::from_be_bytes([p[0], p[1]]), at + 2))
}

/// Собрать датаграмму для приложения: заголовок с адресом-источником + данные.
pub fn encode_datagram(addr: &TargetAddr, port: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 32);
    out.extend_from_slice(&[0, 0, 0]);
    match addr {
        TargetAddr::Ip(IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        TargetAddr::Ip(IpAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
        TargetAddr::Domain(d) => {
            out.push(0x03);
            out.push(d.len().min(255) as u8);
            out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Обслужить одну UDP-ассоциацию. `control` — управляющее TCP-соединение
/// (запрос UDP ASSOCIATE уже разобран), `open` — открыть VLESS-поток с
/// командой UDP до назначения.
pub async fn serve_associate<F, Fut, S>(
    mut control: TcpStream,
    requested_port: u16,
    open: F,
) -> Result<()>
where
    F: Fn(TargetAddr, u16) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let local_ip = control.local_addr()?.ip();
    let client_ip = control.peer_addr()?.ip();
    let udp = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    reply_success(&mut control, udp.local_addr()?).await?;
    tracing::info!(udp = %udp.local_addr()?, "SOCKS5 UDP: ассоциация открыта");

    let mut filter = ClientFilter::new(client_ip, requested_port);
    let budget = Arc::new(AtomicUsize::new(0));
    let open = Arc::new(open);
    let mut sessions: HashMap<(TargetAddr, u16), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut buf = vec![0u8; 65536];
    let mut ctl = [0u8; 64];

    loop {
        tokio::select! {
            // Управляющее соединение закрыто — ассоциация кончилась.
            r = control.read(&mut ctl) => {
                if matches!(r, Ok(0) | Err(_)) {
                    break;
                }
            }
            r = udp.recv_from(&mut buf) => {
                let Some((n, from)) = recv_result(r)? else { continue };
                if !filter.accept(from) {
                    tracing::debug!(%from, "SOCKS5 UDP: датаграмма не от владельца ассоциации — отброшена");
                    continue;
                }
                let (addr, port, off) = match parse_datagram(&buf[..n]) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, "SOCKS5 UDP: датаграмма отброшена");
                        continue;
                    }
                };
                // Общий потолок на данные в очередях ассоциации: пока
                // потоки открываются, датаграммы копятся в памяти.
                if budget.load(Ordering::Relaxed) + (n - off) > MAX_QUEUED_BYTES {
                    tracing::debug!("SOCKS5 UDP: очередь переполнена — датаграмма отброшена");
                    continue;
                }
                budget.fetch_add(n - off, Ordering::Relaxed);
                let payload = buf[off..n].to_vec();
                let key = (addr.clone(), port);
                let len = payload.len();
                let payload = match sessions.get(&key) {
                    Some(tx) => match tx.try_send(payload) {
                        Ok(()) => continue,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            budget.fetch_sub(len, Ordering::Relaxed);
                            continue;
                        }
                        // поток истёк по тишине — откроем заново ниже
                        Err(mpsc::error::TrySendError::Closed(p)) => {
                            sessions.remove(&key);
                            p
                        }
                    },
                    None => payload,
                };
                sessions.retain(|_, tx| !tx.is_closed());
                if sessions.len() >= MAX_SESSIONS {
                    tracing::warn!("SOCKS5 UDP: слишком много назначений в одной ассоциации");
                    budget.fetch_sub(len, Ordering::Relaxed);
                    continue;
                }
                let tx = spawn_session(&mut tasks, &open, &udp, from, key.clone(), budget.clone());
                if tx.try_send(payload).is_err() {
                    budget.fetch_sub(len, Ordering::Relaxed);
                }
                sessions.insert(key, tx);
            }
            // Уборка завершившихся задач, чтобы JoinSet не рос.
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    tracing::info!("SOCKS5 UDP: ассоциация закрыта");
    Ok(())
}

fn spawn_session<F, Fut, S>(
    tasks: &mut JoinSet<()>,
    open: &Arc<F>,
    udp: &Arc<UdpSocket>,
    client: SocketAddr,
    (addr, port): (TargetAddr, u16),
    budget: Arc<AtomicUsize>,
) -> mpsc::Sender<Vec<u8>>
where
    F: Fn(TargetAddr, u16) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE);
    let open = open.clone();
    let udp = udp.clone();
    tasks.spawn(async move {
        let session = async {
            let stream = match open(addr.clone(), port).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "SOCKS5 UDP: не удалось открыть поток");
                    tracing::debug!(target = %addr, port, "SOCKS5 UDP: назначение неудачного потока");
                    return;
                }
            };
            tracing::debug!(target = %addr, port, "SOCKS5 UDP: поток открыт");
            let (mut r, mut w) = tokio::io::split(stream);
            let up = async {
                while let Ok(Some(p)) = tokio::time::timeout(SESSION_IDLE, rx.recv()).await {
                    budget.fetch_sub(p.len(), Ordering::Relaxed);
                    if crate::vless::udp::write_packet(&mut w, &p).await.is_err() {
                        break;
                    }
                }
            };
            let down = async {
                let mut pkt = Vec::new();
                while let Ok(Ok(Some(()))) = tokio::time::timeout(
                    SESSION_IDLE,
                    crate::vless::udp::read_packet(&mut r, &mut pkt),
                )
                .await
                {
                    // Ошибка отправки одной датаграммы — не повод рвать поток.
                    let dg = encode_datagram(&addr, port, &pkt);
                    let _ = udp.send_to(&dg, client).await;
                }
            };
            // Кто первый закончил (тишина, ошибка, закрытие) — тот и закрывает поток.
            tokio::select! {
                _ = up => {}
                _ = down => {}
            }
            tracing::debug!(target = %addr, port, "SOCKS5 UDP: поток закрыт");
        };
        session.await;
        // Непрочитанное — вернуть в общий бюджет ассоциации.
        rx.close();
        while let Ok(p) = rx.try_recv() {
            budget.fetch_sub(p.len(), Ordering::Relaxed);
        }
    });
    tx
}

/// Кто может пользоваться UDP-ассоциацией. RFC 1928: DST.ADDR/DST.PORT в
/// запросе UDP ASSOCIATE — адрес, с которого клиент будет слать
/// датаграммы. Раньше проверялся только IP, и другой процесс или
/// пользователь на той же машине мог слать пакеты в туннель и
/// перехватывать ответы (включая DNS). Теперь: IP управляющего
/// соединения, порт из запроса (если не 0), а первый принятый отправитель
/// закрепляется за ассоциацией целиком (IP и порт).
struct ClientFilter {
    ip: IpAddr,
    port: Option<u16>,
    locked: Option<SocketAddr>,
}

impl ClientFilter {
    fn new(control_peer: IpAddr, requested_port: u16) -> Self {
        ClientFilter {
            ip: control_peer.to_canonical(),
            port: (requested_port != 0).then_some(requested_port),
            locked: None,
        }
    }

    fn accept(&mut self, from: SocketAddr) -> bool {
        if from.ip().to_canonical() != self.ip {
            return false;
        }
        if self.port.is_some_and(|p| p != from.port()) {
            return false;
        }
        match self.locked {
            None => {
                self.locked = Some(from);
                true
            }
            Some(l) => l == from,
        }
    }
}

/// Результат `recv_from`: ошибки отдельных датаграмм (на Windows после
/// ICMP «порт недоступен» приходит WSAECONNRESET) пропускаются, а не
/// рвут всю ассоциацию.
fn recv_result(r: std::io::Result<(usize, SocketAddr)>) -> Result<Option<(usize, SocketAddr)>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            tracing::debug!(error = %e, "SOCKS5 UDP: ошибка отдельной датаграммы пропущена");
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

fn to_vless(addr: &TargetAddr) -> Address {
    match addr {
        TargetAddr::Ip(IpAddr::V4(v4)) => Address::Ipv4(*v4),
        TargetAddr::Ip(IpAddr::V6(v6)) => Address::Ipv6(*v6),
        TargetAddr::Domain(d) => Address::Domain(d.clone()),
    }
}

fn from_vless(addr: Address) -> TargetAddr {
    match addr {
        Address::Ipv4(v4) => TargetAddr::Ip(IpAddr::V4(v4)),
        Address::Ipv6(v6) => TargetAddr::Ip(IpAddr::V6(v6)),
        Address::Domain(d) => TargetAddr::Domain(d),
    }
}

/// Обслужить UDP-ассоциацию через XUDP (`crate::vless::xudp`): все
/// назначения — в одном VLESS-потоке, который открывает `open` (команда
/// Mux). Поток открывается при первой датаграмме и переоткрывается, если
/// закрылся (ошибка сервера или [`SESSION_IDLE`] тишины в обе стороны);
/// GlobalID один на всю ассоциацию — сервер сохраняет за ней тот же
/// внешний UDP-порт.
pub async fn serve_associate_xudp<F, Fut, S>(
    mut control: TcpStream,
    requested_port: u16,
    open: F,
) -> Result<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let local_ip = control.local_addr()?.ip();
    let client_ip = control.peer_addr()?.ip();
    let udp = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    reply_success(&mut control, udp.local_addr()?).await?;
    tracing::info!(udp = %udp.local_addr()?, "SOCKS5 UDP (XUDP): ассоциация открыта");
    let mut filter = ClientFilter::new(client_ip, requested_port);

    let mut global_id = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut global_id);
    let open = Arc::new(open);
    let mut session: Option<mpsc::Sender<(Address, u16, Vec<u8>)>> = None;
    let mut tasks = JoinSet::new();
    let mut buf = vec![0u8; 65536];
    let mut ctl = [0u8; 64];

    loop {
        tokio::select! {
            r = control.read(&mut ctl) => {
                if matches!(r, Ok(0) | Err(_)) {
                    break;
                }
            }
            r = udp.recv_from(&mut buf) => {
                let Some((n, from)) = recv_result(r)? else { continue };
                if !filter.accept(from) {
                    tracing::debug!(%from, "SOCKS5 UDP: датаграмма не от владельца ассоциации — отброшена");
                    continue;
                }
                let (addr, port, off) = match parse_datagram(&buf[..n]) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, "SOCKS5 UDP: датаграмма отброшена");
                        continue;
                    }
                };
                if n - off > xudp::MAX_PAYLOAD {
                    tracing::debug!(len = n - off, "SOCKS5 UDP: датаграмма больше, чем принимает XUDP, — отброшена");
                    continue;
                }
                let pkt = (to_vless(&addr), port, buf[off..n].to_vec());
                // Нет живого потока (ещё не открыт или закрылся) — открываем
                // новый и отдаём ему пакет; переполненная очередь — пакет
                // отбрасывается, как при перегрузке любого UDP.
                let retry = match &session {
                    Some(tx) => match tx.try_send(pkt) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => None,
                        Err(mpsc::error::TrySendError::Closed(p)) => Some(p),
                    },
                    None => Some(pkt),
                };
                if let Some(p) = retry {
                    let tx = spawn_xudp(&mut tasks, &open, &udp, from, global_id);
                    let _ = tx.try_send(p);
                    session = Some(tx);
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    tracing::info!("SOCKS5 UDP (XUDP): ассоциация закрыта");
    Ok(())
}

fn spawn_xudp<F, Fut, S>(
    tasks: &mut JoinSet<()>,
    open: &Arc<F>,
    udp: &Arc<UdpSocket>,
    client: SocketAddr,
    global_id: [u8; 8],
) -> mpsc::Sender<(Address, u16, Vec<u8>)>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (tx, mut rx) = mpsc::channel::<(Address, u16, Vec<u8>)>(QUEUE);
    let open = open.clone();
    let udp = udp.clone();
    tasks.spawn(async move {
        let stream = match open().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "SOCKS5 UDP: не удалось открыть XUDP-поток");
                return;
            }
        };
        tracing::debug!("SOCKS5 UDP: XUDP-поток открыт");
        let (mut r, mut w) = tokio::io::split(stream);
        // Время последнего пакета в любую сторону — для закрытия по тишине.
        let last = std::sync::Mutex::new(tokio::time::Instant::now());
        let touch = || *last.lock().unwrap() = tokio::time::Instant::now();
        let mut writer = xudp::XudpWriter::new(global_id);
        // Если сервер не указал источник ответа — считаем им первое назначение.
        let first_dest: std::sync::Mutex<Option<(Address, u16)>> = std::sync::Mutex::new(None);
        let up = async {
            use tokio::io::AsyncWriteExt;
            while let Some((addr, port, data)) = rx.recv().await {
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
                let Some((addr, port)) = p.source.or_else(|| first_dest.lock().unwrap().clone())
                else {
                    continue;
                };
                // Ошибка отправки одной датаграммы — не повод рвать поток.
                let dg = encode_datagram(&from_vless(addr), port, &p.data);
                let _ = udp.send_to(&dg, client).await;
            }
        };
        let idle = async {
            loop {
                let deadline = *last.lock().unwrap() + SESSION_IDLE;
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
        tracing::debug!("SOCKS5 UDP: XUDP-поток закрыт");
    });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_header_roundtrip() {
        for addr in [
            TargetAddr::Ip("1.2.3.4".parse().unwrap()),
            TargetAddr::Ip("2001:db8::1".parse().unwrap()),
            TargetAddr::Domain("dns.example".into()),
        ] {
            let dg = encode_datagram(&addr, 53, b"payload");
            let (a, p, off) = parse_datagram(&dg).unwrap();
            assert_eq!(a, addr);
            assert_eq!(p, 53);
            assert_eq!(&dg[off..], b"payload");
        }
    }

    #[test]
    fn association_accepts_only_its_owner() {
        let owner: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut f = ClientFilter::new("127.0.0.1".parse().unwrap(), 0);
        assert!(!f.accept("127.0.0.2:5000".parse().unwrap()), "чужой IP");
        assert!(f.accept(owner), "первый отправитель закрепляется");
        assert!(f.accept(owner));
        assert!(
            !f.accept("127.0.0.1:5001".parse().unwrap()),
            "тот же IP, другой порт"
        );
        // IPv4 через IPv6-сокет — тот же адрес.
        let mut f = ClientFilter::new("::ffff:127.0.0.1".parse().unwrap(), 7000);
        assert!(
            !f.accept("127.0.0.1:7001".parse().unwrap()),
            "порт из запроса"
        );
        assert!(f.accept("127.0.0.1:7000".parse().unwrap()));
    }

    #[test]
    fn rejects_fragments_and_garbage() {
        let mut dg = encode_datagram(&TargetAddr::Ip("1.2.3.4".parse().unwrap()), 53, b"x");
        dg[2] = 1;
        assert!(parse_datagram(&dg).is_err());
        assert!(parse_datagram(&[0, 0, 0, 3, 200, b'a']).is_err());
        assert!(parse_datagram(&[0, 0]).is_err());
    }
}
