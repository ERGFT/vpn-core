//! SOCKS5 UDP ASSOCIATE (RFC 1928 §7) поверх VLESS.
//!
//! Приложение (DNS-клиент, QUIC в браузере, игра) шлёт датаграммы на
//! выданный нами UDP-порт, каждая с заголовком SOCKS5 (адрес назначения).
//! Для каждого адреса назначения открывается свой VLESS-поток с командой
//! UDP — так устроен VLESS: один поток — одно назначение, пакеты внутри
//! с 2-байтной длиной (`crate::vless::udp`). Ответы уходят приложению с
//! тем же заголовком, где адрес — источник ответа.
//!
//! Ассоциация живёт, пока открыто управляющее TCP-соединение (так требует
//! RFC); поток к назначению закрывается после [`SESSION_IDLE`] тишины.
//! Датаграммы принимаются только с IP-адреса, открывшего ассоциацию.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::{reply_success, TargetAddr};
use crate::error::{Error, Result};

/// Поток к назначению закрывается после стольких секунд без пакетов.
pub const SESSION_IDLE: Duration = Duration::from_secs(120);
/// Не больше стольких одновременных назначений на одну ассоциацию.
const MAX_SESSIONS: usize = 256;
/// Очередь пакетов к ещё открывающемуся потоку; лишнее отбрасывается
/// (для UDP это нормальное поведение при перегрузке).
const QUEUE: usize = 64;

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
pub async fn serve_associate<F, Fut, S>(mut control: TcpStream, open: F) -> Result<()>
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
                let (n, from) = r?;
                if from.ip() != client_ip {
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
                let payload = buf[off..n].to_vec();
                let key = (addr.clone(), port);
                if let Some(tx) = sessions.get(&key) {
                    match tx.try_send(payload) {
                        Ok(()) => continue,
                        Err(mpsc::error::TrySendError::Full(_)) => continue,
                        Err(mpsc::error::TrySendError::Closed(p)) => {
                            sessions.remove(&key);
                            // поток истёк по тишине — откроем заново ниже
                            if let Some(tx) = spawn_session(&mut tasks, &open, &udp, from, key.clone()) {
                                let _ = tx.try_send(p);
                                sessions.insert(key, tx);
                            }
                            continue;
                        }
                    }
                }
                sessions.retain(|_, tx| !tx.is_closed());
                if sessions.len() >= MAX_SESSIONS {
                    tracing::warn!("SOCKS5 UDP: слишком много назначений в одной ассоциации");
                    continue;
                }
                if let Some(tx) = spawn_session(&mut tasks, &open, &udp, from, key.clone()) {
                    let _ = tx.try_send(payload);
                    sessions.insert(key, tx);
                }
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
) -> Option<mpsc::Sender<Vec<u8>>>
where
    F: Fn(TargetAddr, u16) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE);
    let open = open.clone();
    let udp = udp.clone();
    tasks.spawn(async move {
        let stream = match open(addr.clone(), port).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(target = %addr, port, error = %e, "SOCKS5 UDP: не удалось открыть поток");
                return;
            }
        };
        tracing::debug!(target = %addr, port, "SOCKS5 UDP: поток открыт");
        let (mut r, mut w) = tokio::io::split(stream);
        let up = async {
            while let Ok(Some(p)) = tokio::time::timeout(SESSION_IDLE, rx.recv()).await {
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
                let dg = encode_datagram(&addr, port, &pkt);
                if udp.send_to(&dg, client).await.is_err() {
                    break;
                }
            }
        };
        // Кто первый закончил (тишина, ошибка, закрытие) — тот и закрывает поток.
        tokio::select! {
            _ = up => {}
            _ = down => {}
        }
        tracing::debug!(target = %addr, port, "SOCKS5 UDP: поток закрыт");
    });
    Some(tx)
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
    fn rejects_fragments_and_garbage() {
        let mut dg = encode_datagram(&TargetAddr::Ip("1.2.3.4".parse().unwrap()), 53, b"x");
        dg[2] = 1;
        assert!(parse_datagram(&dg).is_err());
        assert!(parse_datagram(&[0, 0, 0, 3, 200, b'a']).is_err());
        assert!(parse_datagram(&[0, 0]).is_err());
    }
}
