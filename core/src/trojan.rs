// SPDX-License-Identifier: GPL-3.0-or-later
//! Trojan (trojan-gfw, в Xray — `proxy/trojan`): пароль вместо UUID,
//! поверх TLS или REALITY и тех же транспортов, что у VLESS.
//!
//! Заголовок запроса:
//!
//! ```text
//! hex(SHA-224(пароль))   56 байт
//! CRLF
//! команда                1 байт: 1 — TCP, 3 — UDP
//! адрес                  как в SOCKS5: 1 IPv4 / 3 домен / 4 IPv6, затем порт
//! CRLF
//! ```
//!
//! Ответа у сервера нет: дальше идут данные. UDP — пакеты
//! `адрес, порт, длина (2 байта), CRLF, данные` в обе стороны.
//!
//! Ссылка: `trojan://пароль@host:port?security=tls&sni=…&type=ws&path=…#имя`
//! — параметры транспорта те же, что у `vless://`; без `security` — TLS
//! (как у всех клиентов).

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};
use crate::vless::{Address, VlessConfig};

pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 3;
/// Больше датаграмма не бывает (длина — 2 байта).
pub const MAX_UDP: usize = 65535;

/// Разобранная ссылка trojan://.
#[derive(Debug, Clone)]
pub struct TrojanConfig {
    pub password: String,
    /// Параметры транспорта (TLS/REALITY, ws, grpc, …) — в том же виде,
    /// что у VLESS; UUID в нём не используется.
    pub transport: VlessConfig,
}

impl TrojanConfig {
    pub fn parse(link: &str) -> Result<Self> {
        let rest = link
            .trim()
            .strip_prefix("trojan://")
            .ok_or_else(|| Error::InvalidUri("ожидалась ссылка trojan://".into()))?;
        let (userinfo, hostpart) = rest
            .rsplit_once('@')
            .ok_or_else(|| Error::InvalidUri("trojan://: нет пароля (пароль@host:port)".into()))?;
        let password =
            url::form_urlencoded::parse(format!("p={}", userinfo.replace('+', "%2B")).as_bytes())
                .next()
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
        if password.is_empty() {
            return Err(Error::InvalidUri("trojan://: пустой пароль".into()));
        }
        // По умолчанию — TLS, как у всех клиентов Trojan.
        let mut host = hostpart.to_string();
        let has_security = host
            .split(['?', '#'])
            .nth(1)
            .is_some_and(|q| q.split('&').any(|kv| kv.starts_with("security=")));
        if !has_security {
            host = match host.split_once('?') {
                Some((a, q)) => format!("{a}?security=tls&{q}"),
                None => match host.split_once('#') {
                    Some((a, f)) => format!("{a}?security=tls#{f}"),
                    None => format!("{host}?security=tls"),
                },
            };
        }
        let transport = VlessConfig::parse(&format!(
            "vless://00000000-0000-0000-0000-000000000000@{host}"
        ))?;
        if transport.flow.is_vision() {
            return Err(Error::InvalidUri(
                "trojan: flow=xtls-rprx-vision бывает только у VLESS".into(),
            ));
        }
        Ok(TrojanConfig {
            password,
            transport,
        })
    }

    /// hex(SHA-224(пароль)).
    pub fn key(&self) -> String {
        hex::encode(Sha224::digest(self.password.as_bytes()))
    }
}

/// Адрес и порт в форме SOCKS5.
pub fn encode_addr(b: &mut BytesMut, addr: &Address, port: u16) {
    match addr {
        Address::Ipv4(v4) => {
            b.put_u8(1);
            b.put_slice(&v4.octets());
        }
        Address::Domain(d) => {
            let d = &d.as_bytes()[..d.len().min(255)];
            b.put_u8(3);
            b.put_u8(d.len() as u8);
            b.put_slice(d);
        }
        Address::Ipv6(v6) => {
            b.put_u8(4);
            b.put_slice(&v6.octets());
        }
    }
    b.put_u16(port);
}

/// Заголовок запроса.
pub fn request(key: &str, cmd: u8, addr: &Address, port: u16) -> BytesMut {
    let mut b = BytesMut::with_capacity(56 + 2 + 1 + 260 + 2);
    b.put_slice(key.as_bytes());
    b.put_slice(b"\r\n");
    b.put_u8(cmd);
    encode_addr(&mut b, addr, port);
    b.put_slice(b"\r\n");
    b
}

/// UDP-пакет.
pub fn udp_packet(addr: &Address, port: u16, data: &[u8]) -> Option<BytesMut> {
    if data.len() > MAX_UDP {
        return None;
    }
    let mut b = BytesMut::with_capacity(data.len() + 264);
    encode_addr(&mut b, addr, port);
    b.put_u16(data.len() as u16);
    b.put_slice(b"\r\n");
    b.put_slice(data);
    Some(b)
}

/// Прочитать UDP-пакет от сервера. `Ok(None)` — поток закрыт.
pub async fn read_udp_packet<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Option<(Address, u16, Vec<u8>)>> {
    let atyp = match r.read_u8().await {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let addr = match atyp {
        1 => {
            let mut o = [0u8; 4];
            r.read_exact(&mut o).await?;
            Address::Ipv4(Ipv4Addr::from(o))
        }
        3 => {
            let n = r.read_u8().await? as usize;
            let mut d = vec![0u8; n];
            r.read_exact(&mut d).await?;
            Address::Domain(String::from_utf8_lossy(&d).into_owned())
        }
        4 => {
            let mut o = [0u8; 16];
            r.read_exact(&mut o).await?;
            Address::Ipv6(Ipv6Addr::from(o))
        }
        other => {
            return Err(Error::Protocol(format!(
                "trojan: неизвестный тип адреса {other} в UDP-пакете"
            )))
        }
    };
    let port = r.read_u16().await?;
    let len = r.read_u16().await? as usize;
    let mut crlf = [0u8; 2];
    r.read_exact(&mut crlf).await?;
    if &crlf != b"\r\n" {
        return Err(Error::Protocol("trojan: битый UDP-пакет (нет CRLF)".into()));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).await?;
    Ok(Some((addr, port, data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_links_and_defaults_to_tls() {
        let c = TrojanConfig::parse("trojan://p%40ss@t.example:443?sni=s.example#Name").unwrap();
        assert_eq!(c.password, "p@ss");
        assert_eq!(c.transport.host, "t.example");
        assert_eq!(c.transport.security, crate::vless::Security::Tls);
        assert_eq!(c.transport.effective_sni(), "s.example");
        let c = TrojanConfig::parse("trojan://x@1.2.3.4:8443").unwrap();
        assert_eq!(c.transport.security, crate::vless::Security::Tls);
        let c = TrojanConfig::parse("trojan://x@h:1?security=none&type=ws&path=%2Fw").unwrap();
        assert_eq!(c.transport.security, crate::vless::Security::None);
        assert!(TrojanConfig::parse("trojan://@h:1").is_err());
        assert!(TrojanConfig::parse("vless://x@h:1").is_err());
        assert!(TrojanConfig::parse("trojan://x@h:1?flow=xtls-rprx-vision&type=tcp").is_err());
    }

    #[test]
    fn header_and_udp_layout() {
        let c = TrojanConfig::parse("trojan://password@h:1").unwrap();
        // SHA-224("password")
        assert_eq!(
            c.key(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        let h = request(&c.key(), CMD_TCP, &Address::Domain("a.io".into()), 443);
        assert_eq!(&h[56..], b"\r\n\x01\x03\x04a.io\x01\xbb\r\n");
        let p = udp_packet(&Address::Ipv4("1.2.3.4".parse().unwrap()), 53, b"q").unwrap();
        assert_eq!(&p[..], b"\x01\x01\x02\x03\x04\x00\x35\x00\x01\r\nq");
    }

    #[tokio::test]
    async fn reads_udp_packets() {
        let mut wire = udp_packet(&Address::Ipv6("::1".parse().unwrap()), 7, b"abc")
            .unwrap()
            .to_vec();
        wire.extend_from_slice(&udp_packet(&Address::Domain("x".into()), 8, b"").unwrap());
        let mut r = &wire[..];
        let (a, p, d) = read_udp_packet(&mut r).await.unwrap().unwrap();
        assert_eq!(
            (a, p, d),
            (Address::Ipv6("::1".parse().unwrap()), 7, b"abc".to_vec())
        );
        let (a, p, d) = read_udp_packet(&mut r).await.unwrap().unwrap();
        assert_eq!((a, p, d.len()), (Address::Domain("x".into()), 8, 0));
        assert!(read_udp_packet(&mut r).await.unwrap().is_none());
    }
}
