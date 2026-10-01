// SPDX-License-Identifier: GPL-3.0-or-later
//! XUDP — UDP поверх VLESS так, как его по умолчанию шлёт клиент Xray-core
//! (`common/xudp`, `common/mux/frame.go`): один VLESS-поток с командой Mux
//! (`v1.mux.cool:666`, адрес в заголовке не пишется), внутри — кадры
//! Mux.Cool одной сессии (ID 0), у каждого пакета свой адрес назначения.
//!
//! Чем лучше простой команды UDP (`crate::vless::udp`, «один поток — одно
//! назначение»): все назначения идут через одно соединение и один
//! UDP-сокет на сервере — это Full Cone NAT (нужен играм, звонкам, STUN) и
//! на порядок меньше рукопожатий TLS/REALITY. С Vision-аккаунтом Xray
//! принимает UDP только так (команду UDP при flow Vision он отвергает).
//!
//! Кадр клиента:
//!   2 байта  длина метаданных
//!   2 байта  ID сессии (0)
//!   1 байт   статус: 1 New (первый пакет), 2 Keep (остальные)
//!   1 байт   опции: 1 — за метаданными идут данные
//!   1 байт   сеть: 2 — UDP
//!   2 байта  порт, затем адрес (1 IPv4 / 2 домен / 3 IPv6)
//!   8 байт   GlobalID — только в New
//!   2 байта  длина данных, затем данные
//!
//! Кадр сервера — Keep с адресом источника ответа (или без адреса),
//! KeepAlive (4) — пропустить, End (3) — сессия закрыта.
//!
//! GlobalID — 8 байт, по которым сервер узнаёт «того же клиента» при
//! переоткрытии потока и сохраняет за ним тот же внешний UDP-порт.
//! Xray выводит его из адреса локального UDP-клиента; здесь — случайный
//! на каждую SOCKS5-ассоциацию, что даёт то же самое в её пределах.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};
use crate::vless::protocol::Address;

/// Адрес, порт назначения XUDP-потока в заголовке VLESS (сам адрес при
/// команде Mux не передаётся, но Xray его подставляет).
pub const MUX_COOL_DOMAIN: &str = "v1.mux.cool";
pub const XUDP_PORT: u16 = 666;

/// Больше этого сервер Xray не примет (буфер `buf.Size`) и разорвёт
/// поток целиком, поэтому такие пакеты отбрасываются на клиенте.
pub const MAX_PAYLOAD: usize = 8192;

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEPALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;

/// Кодировщик кадров одного XUDP-потока: первый кадр — New с GlobalID.
pub struct XudpWriter {
    first: bool,
    global_id: [u8; 8],
}

impl XudpWriter {
    pub fn new(global_id: [u8; 8]) -> Self {
        XudpWriter {
            first: true,
            global_id,
        }
    }

    /// Кадр с пакетом `data` для `addr:port`. `None` — пакет слишком
    /// большой для сервера (отбрасывается, как у Xray).
    pub fn encode(&mut self, addr: &Address, port: u16, data: &[u8]) -> Option<BytesMut> {
        if data.len() > MAX_PAYLOAD {
            return None;
        }
        let mut b = BytesMut::with_capacity(data.len() + 48);
        b.put_u16(0); // длина метаданных — ниже
        b.put_u16(0); // ID сессии
        b.put_u8(if self.first { STATUS_NEW } else { STATUS_KEEP });
        b.put_u8(OPTION_DATA);
        b.put_u8(NETWORK_UDP);
        b.put_u16(port);
        addr.encode(&mut b);
        if self.first {
            b.put_slice(&self.global_id);
            self.first = false;
        }
        let meta_len = (b.len() - 2) as u16;
        b[0..2].copy_from_slice(&meta_len.to_be_bytes());
        b.put_u16(data.len() as u16);
        b.put_slice(data);
        Some(b)
    }
}

/// Пакет от сервера: адрес источника (если сервер его указал) и данные.
#[derive(Debug, PartialEq, Eq)]
pub struct XudpPacket {
    pub source: Option<(Address, u16)>,
    pub data: Vec<u8>,
}

fn parse_addr_port(b: &[u8]) -> Result<(Address, u16)> {
    let bad = || Error::Protocol("XUDP: битый адрес в кадре".into());
    if b.len() < 3 {
        return Err(bad());
    }
    let port = u16::from_be_bytes([b[0], b[1]]);
    let addr = match b[2] {
        1 => {
            let o: [u8; 4] = b.get(3..7).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
            Address::Ipv4(Ipv4Addr::from(o))
        }
        3 => {
            let o: [u8; 16] = b
                .get(3..19)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?;
            Address::Ipv6(Ipv6Addr::from(o))
        }
        2 => {
            let l = *b.get(3).ok_or_else(bad)? as usize;
            let d = b.get(4..4 + l).ok_or_else(bad)?;
            Address::Domain(String::from_utf8_lossy(d).into_owned())
        }
        _ => return Err(bad()),
    };
    Ok((addr, port))
}

/// Прочитать следующий пакет. `Ok(None)` — сервер закрыл сессию (End)
/// или поток.
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<XudpPacket>> {
    loop {
        let mut len = [0u8; 2];
        match r.read_exact(&mut len).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let meta_len = u16::from_be_bytes(len) as usize;
        if meta_len < 4 {
            return Ok(None);
        }
        let mut meta = vec![0u8; meta_len];
        r.read_exact(&mut meta).await?;
        let status = meta[2];
        let option = meta[3];
        let mut discard = false;
        let mut source = None;
        match status {
            STATUS_KEEP => {
                if meta_len > 4 && meta[4] == NETWORK_UDP {
                    source = Some(parse_addr_port(&meta[5..])?);
                }
            }
            STATUS_KEEPALIVE => discard = true,
            STATUS_END => return Ok(None),
            _ => return Ok(None),
        }
        if option & OPTION_DATA == 0 {
            continue;
        }
        r.read_exact(&mut len).await?;
        let n = u16::from_be_bytes(len) as usize;
        let mut data = vec![0u8; n];
        r.read_exact(&mut data).await?;
        if discard {
            continue;
        }
        return Ok(Some(XudpPacket { source, data }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_frame_is_new_with_global_id_then_keep() {
        let mut w = XudpWriter::new([9; 8]);
        let a = Address::Ipv4("1.2.3.4".parse().unwrap());
        let f = w.encode(&a, 53, b"q").unwrap();
        // meta: id(2) New Opt UDP port(2) atyp ip(4) gid(8) = 20
        assert_eq!(
            &f[..],
            &[0, 20, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4, 9, 9, 9, 9, 9, 9, 9, 9, 0, 1, b'q']
        );
        let f = w
            .encode(&Address::Domain("d.io".into()), 443, b"xy")
            .unwrap();
        assert_eq!(
            &f[..],
            &[0, 13, 0, 0, 2, 1, 2, 1, 187, 2, 4, b'd', b'.', b'i', b'o', 0, 2, b'x', b'y']
        );
        assert!(w.encode(&a, 1, &vec![0; MAX_PAYLOAD + 1]).is_none());
    }

    #[tokio::test]
    async fn reads_keep_with_source_skips_keepalive_stops_on_end() {
        let mut wire = Vec::new();
        // KeepAlive с данными — пропустить.
        wire.extend_from_slice(&[0, 4, 0, 0, 4, 1, 0, 1, b'z']);
        // Keep с адресом источника (IPv6).
        let mut meta = vec![0, 0, 2, 1, 2, 0x13, 0x88, 3];
        meta.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        wire.extend_from_slice(&(meta.len() as u16).to_be_bytes());
        wire.extend_from_slice(&meta);
        wire.extend_from_slice(&[0, 3, b'a', b'b', b'c']);
        // Keep без адреса.
        wire.extend_from_slice(&[0, 4, 0, 0, 2, 1, 0, 1, b'!']);
        // End.
        wire.extend_from_slice(&[0, 4, 0, 0, 3, 0]);
        let mut r = &wire[..];
        let p = read_packet(&mut r).await.unwrap().unwrap();
        assert_eq!(
            p.source,
            Some((Address::Ipv6("2001:db8::1".parse().unwrap()), 5000))
        );
        assert_eq!(p.data, b"abc");
        let p = read_packet(&mut r).await.unwrap().unwrap();
        assert_eq!((p.source, p.data), (None, b"!".to_vec()));
        assert!(read_packet(&mut r).await.unwrap().is_none());
    }
}
