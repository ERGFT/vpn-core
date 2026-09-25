//! Минимальный SOCKS5-сервер (RFC 1928) на стороне клиента: локальное
//! приложение подключается сюда, а мы проксируем его трафик в VLESS.
//!
//! Поддержано: no-auth (0x00), команда CONNECT (0x01). BIND и
//! UDP ASSOCIATE не реализованы — они не нужны для типичного сценария
//! "браузер/curl -> локальный SOCKS5 -> VLESS-сервер".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Код ответа при ошибке (REP-поле), см. RFC 1928 §6.
#[derive(Debug, Clone, Copy)]
pub enum ReplyCode {
    GeneralFailure = 0x01,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddr::Ip(ip) => write!(f, "{ip}"),
            TargetAddr::Domain(d) => write!(f, "{d}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub addr: TargetAddr,
    pub port: u16,
}

/// Выполнить приветствие SOCKS5 (без аутентификации) и разобрать запрос
/// CONNECT. При ошибке протокола соединение стоит закрыть — ответ уже
/// не отправляем, т.к. на этапе приветствия ещё нечего адресовать.
pub async fn handshake<S>(stream: &mut S) -> Result<Socks5Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- Приветствие ---
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    let (ver, nmethods) = (hdr[0], hdr[1]);
    if ver != SOCKS_VERSION {
        return Err(Error::UnsupportedSocksVersion(ver));
    }
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await?;
        return Err(Error::Socks5("клиент не предложил метод no-auth".into()));
    }
    stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;

    // --- Запрос ---
    let mut req_hdr = [0u8; 4];
    stream.read_exact(&mut req_hdr).await?;
    let (ver, cmd, _rsv, atyp) = (req_hdr[0], req_hdr[1], req_hdr[2], req_hdr[3]);
    if ver != SOCKS_VERSION {
        reply(stream, ReplyCode::GeneralFailure as u8, default_bind()).await?;
        return Err(Error::UnsupportedSocksVersion(ver));
    }
    if cmd != CMD_CONNECT {
        reply(stream, ReplyCode::CommandNotSupported as u8, default_bind()).await?;
        return Err(Error::UnsupportedSocksCommand(cmd));
    }

    let addr = match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut b = vec![0u8; len_buf[0] as usize];
            stream.read_exact(&mut b).await?;
            let domain = String::from_utf8(b)
                .map_err(|_| Error::Socks5("домен не в UTF-8".into()))?;
            TargetAddr::Domain(domain)
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        other => {
            reply(stream, ReplyCode::AddressTypeNotSupported as u8, default_bind()).await?;
            return Err(Error::UnsupportedAddressType(other));
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(Socks5Request { addr, port })
}

fn default_bind() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

/// Отправить финальный успешный ответ CONNECT.
pub async fn reply_success<S>(stream: &mut S, bind: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    reply(stream, 0x00, bind).await
}

pub async fn reply_error<S>(stream: &mut S, code: ReplyCode) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    reply(stream, code as u8, default_bind()).await
}

async fn reply<S>(stream: &mut S, rep: u8, bind: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut buf = vec![SOCKS_VERSION, rep, 0x00];
    match bind.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&bind.port().to_be_bytes());
    stream.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn parses_connect_to_domain() {
        let (mut client, mut server) = duplex(256);

        let client_task = tokio::spawn(async move {
            // greeting: no-auth
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x05, 0x00]);

            // request: CONNECT example.com:443
            let domain = b"example.com";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            req.extend_from_slice(domain);
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).await.unwrap();

            let mut final_resp = [0u8; 10];
            client.read_exact(&mut final_resp).await.unwrap();
            assert_eq!(final_resp[1], 0x00); // success
        });

        let req = handshake(&mut server).await.unwrap();
        assert_eq!(req.addr, TargetAddr::Domain("example.com".to_string()));
        assert_eq!(req.port, 443);
        reply_success(&mut server, default_bind()).await.unwrap();

        client_task.await.unwrap();
    }
}
