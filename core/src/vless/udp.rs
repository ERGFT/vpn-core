// SPDX-License-Identifier: GPL-3.0-or-later
//! UDP поверх VLESS (команда `0x02`): один VLESS-поток — одна пара
//! «локальный UDP-клиент — адрес назначения», каждый датаграммный пакет
//! внутри потока — `длина (2 байта BE) + данные` (`LengthPacketWriter`/
//! `LengthPacketReader` в `proxy/vless/encoding/addons.go`).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Максимум данных в одном пакете: длина — 16 бит.
pub const MAX_PACKET: usize = u16::MAX as usize;

/// Записать один UDP-пакет в VLESS-поток.
pub async fn write_packet<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_PACKET {
        return Err(Error::Protocol(format!(
            "UDP-пакет {} байт не помещается в VLESS (максимум {MAX_PACKET})",
            data.len()
        )));
    }
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Прочитать один UDP-пакет из VLESS-потока. `Ok(None)` — поток закрыт
/// на границе пакета.
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Result<Option<()>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u16::from_be_bytes(len) as usize;
    buf.resize(n, 0);
    r.read_exact(buf).await?;
    Ok(Some(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packets_roundtrip_with_length_prefix() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_packet(&mut a, b"dns-query").await.unwrap();
        write_packet(&mut a, b"").await.unwrap();
        drop(a);
        let mut buf = Vec::new();
        assert!(read_packet(&mut b, &mut buf).await.unwrap().is_some());
        assert_eq!(buf, b"dns-query");
        assert!(read_packet(&mut b, &mut buf).await.unwrap().is_some());
        assert!(buf.is_empty());
        assert!(read_packet(&mut b, &mut buf).await.unwrap().is_none());
    }
}
