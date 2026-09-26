//! SOCKS5 UDP ASSOCIATE (RFC 1928 §7): формат датаграмм и правило «кто
//! владелец ассоциации». Сама ассоциация (маршрутизация датаграмм по
//! выходам, XUDP) — `crate::app::proxy_in`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::TargetAddr;
use crate::error::{Error, Result};

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

/// Кто может пользоваться UDP-ассоциацией. RFC 1928: DST.ADDR/DST.PORT в
/// запросе UDP ASSOCIATE — адрес, с которого клиент будет слать
/// датаграммы. Раньше проверялся только IP, и другой процесс или
/// пользователь на той же машине мог слать пакеты в туннель и
/// перехватывать ответы (включая DNS). Теперь: IP управляющего
/// соединения, порт из запроса (если не 0), а первый принятый отправитель
/// закрепляется за ассоциацией целиком (IP и порт).
pub struct ClientFilter {
    ip: IpAddr,
    port: Option<u16>,
    locked: Option<SocketAddr>,
}

impl ClientFilter {
    pub fn new(control_peer: IpAddr, requested_port: u16) -> Self {
        ClientFilter {
            ip: control_peer.to_canonical(),
            port: (requested_port != 0).then_some(requested_port),
            locked: None,
        }
    }

    pub fn accept(&mut self, from: SocketAddr) -> bool {
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
pub fn recv_result(r: std::io::Result<(usize, SocketAddr)>) -> Result<Option<(usize, SocketAddr)>> {
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
