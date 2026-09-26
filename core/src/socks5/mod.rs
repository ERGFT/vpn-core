//! Минимальный SOCKS5-сервер (RFC 1928) на стороне клиента: локальное
//! приложение подключается сюда, а мы проксируем его трафик в VLESS.
//!
//! Поддержано: без аутентификации (0x00) или логин/пароль (0x02,
//! RFC 1929 — если задан `--auth`), команды CONNECT (0x01) и
//! UDP ASSOCIATE (0x03, см. [`udp`]). BIND не реализован — его не
//! использует ни браузер, ни типичные программы.

pub mod udp;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const USER_PASS_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

/// Команда SOCKS5-запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Command {
    Connect,
    UdpAssociate,
}

/// Пауза перед ответом «неверный пароль».
const AUTH_FAILURE_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub command: Socks5Command,
    pub addr: TargetAddr,
    pub port: u16,
}

/// Логин и пароль для SOCKS5 (RFC 1929).
#[derive(Clone)]
pub struct Credentials {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &String::from_utf8_lossy(&self.username))
            .finish_non_exhaustive()
    }
}

impl Credentials {
    /// Разобрать `логин:пароль`.
    pub fn parse(s: &str) -> Option<Self> {
        let (u, p) = s.split_once(':')?;
        if u.is_empty() || u.len() > 255 || p.len() > 255 {
            return None;
        }
        Some(Self {
            username: u.as_bytes().to_vec(),
            password: p.as_bytes().to_vec(),
        })
    }

    /// Сравнение без раннего выхода: время ответа не выдаёт, сколько
    /// символов совпало.
    fn matches(&self, user: &[u8], pass: &[u8]) -> bool {
        fn ct_eq(a: &[u8], b: &[u8]) -> bool {
            // Сравнение длин — как usize: `(a ^ b) as u8` обнулялось бы
            // при разнице длин, кратной 256.
            let mut diff = u8::from(a.len() != b.len());
            for i in 0..a.len().max(b.len()) {
                diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0xff);
            }
            diff == 0
        }
        ct_eq(&self.username, user) & ct_eq(&self.password, pass)
    }
}

/// Выполнить приветствие SOCKS5 без аутентификации и разобрать запрос.
pub async fn handshake<S>(stream: &mut S) -> Result<Socks5Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake_with_auth(stream, None).await
}

/// Выполнить приветствие SOCKS5 и разобрать запрос. Если `auth` задан,
/// клиент обязан пройти проверку логина/пароля (RFC 1929); без неё
/// соединение закрывается. При ошибке протокола соединение стоит закрыть.
pub async fn handshake_with_auth<S>(
    stream: &mut S,
    auth: Option<&Credentials>,
) -> Result<Socks5Request>
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

    match auth {
        None => {
            if !methods.contains(&METHOD_NO_AUTH) {
                stream
                    .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
                    .await?;
                return Err(Error::Socks5("клиент не предложил метод no-auth".into()));
            }
            stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        }
        Some(creds) => {
            if !methods.contains(&METHOD_USER_PASS) {
                stream
                    .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
                    .await?;
                return Err(Error::Socks5(
                    "требуется логин/пароль, а клиент их не предложил".into(),
                ));
            }
            stream.write_all(&[SOCKS_VERSION, METHOD_USER_PASS]).await?;
            // RFC 1929: VER(1)=1, ULEN(1), UNAME, PLEN(1), PASSWD.
            let mut ver = [0u8; 2];
            stream.read_exact(&mut ver).await?;
            if ver[0] != USER_PASS_VERSION {
                return Err(Error::Socks5(format!(
                    "неизвестная версия проверки логина/пароля: {}",
                    ver[0]
                )));
            }
            let mut user = vec![0u8; ver[1] as usize];
            stream.read_exact(&mut user).await?;
            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut pass = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut pass).await?;
            if !creds.matches(&user, &pass) {
                // Пауза перед отказом замедляет подбор пароля (при
                // `--listen` в сеть) и не мешает честному клиенту.
                tokio::time::sleep(AUTH_FAILURE_DELAY).await;
                stream.write_all(&[USER_PASS_VERSION, 0x01]).await?;
                return Err(Error::Socks5AuthFailed);
            }
            stream.write_all(&[USER_PASS_VERSION, 0x00]).await?;
        }
    }

    // --- Запрос ---
    let mut req_hdr = [0u8; 4];
    stream.read_exact(&mut req_hdr).await?;
    let (ver, cmd, _rsv, atyp) = (req_hdr[0], req_hdr[1], req_hdr[2], req_hdr[3]);
    if ver != SOCKS_VERSION {
        reply(stream, ReplyCode::GeneralFailure as u8, default_bind()).await?;
        return Err(Error::UnsupportedSocksVersion(ver));
    }
    let command = match cmd {
        CMD_CONNECT => Socks5Command::Connect,
        CMD_UDP_ASSOCIATE => Socks5Command::UdpAssociate,
        _ => {
            reply(stream, ReplyCode::CommandNotSupported as u8, default_bind()).await?;
            return Err(Error::UnsupportedSocksCommand(cmd));
        }
    };

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
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            match String::from_utf8(b) {
                Ok(d) if !d.is_empty() => {
                    return Ok(Socks5Request {
                        command,
                        addr: TargetAddr::Domain(d),
                        port: u16::from_be_bytes(port),
                    })
                }
                _ => {
                    reply(
                        stream,
                        ReplyCode::AddressTypeNotSupported as u8,
                        default_bind(),
                    )
                    .await?;
                    return Err(Error::Socks5("пустой домен или домен не в UTF-8".into()));
                }
            }
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        other => {
            reply(
                stream,
                ReplyCode::AddressTypeNotSupported as u8,
                default_bind(),
            )
            .await?;
            return Err(Error::UnsupportedAddressType(other));
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(Socks5Request {
        command,
        addr,
        port,
    })
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

    async fn greet_user_pass(user: &str, pass: &str) -> (Result<Socks5Request>, [u8; 2]) {
        let (mut client, mut server) = duplex(512);
        let creds = Credentials::parse("alice:s3cret").unwrap();
        let (user, pass) = (user.to_string(), pass.to_string());
        let client_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0x02], "сервер должен выбрать логин/пароль");
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            client.write_all(&auth).await.unwrap();
            let mut status = [0u8; 2];
            client.read_exact(&mut status).await.unwrap();
            if status[1] == 0 {
                client
                    .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
            status
        });
        let res = handshake_with_auth(&mut server, Some(&creds)).await;
        (res, client_task.await.unwrap())
    }

    #[tokio::test]
    async fn user_pass_auth_accepts_right_and_rejects_wrong() {
        let (res, status) = greet_user_pass("alice", "s3cret").await;
        assert_eq!(status, [0x01, 0x00]);
        let req = res.unwrap();
        assert_eq!(req.command, Socks5Command::UdpAssociate);

        let (res, status) = greet_user_pass("alice", "wrong").await;
        assert_eq!(status, [0x01, 0x01]);
        assert!(res.is_err());
    }

    #[test]
    fn credentials_compare_lengths_fully() {
        let c = Credentials {
            username: b"u".to_vec(),
            password: Vec::new(),
        };
        assert!(c.matches(b"u", b""));
        assert!(!c.matches(b"u", &[0u8; 256]));
        assert!(!c.matches(b"u", b"x"));
        assert!(!c.matches(b"uu", b""));
    }

    #[tokio::test]
    async fn empty_or_non_utf8_domain_gets_error_reply() {
        for domain in [&b""[..], &[0xff, 0xfe][..]] {
            let (mut client, mut server) = duplex(256);
            let mut req = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            req.extend_from_slice(domain);
            req.extend_from_slice(&[0, 80]);
            client.write_all(&req).await.unwrap();
            assert!(handshake(&mut server).await.is_err());
            let mut r = [0u8; 12];
            client.read_exact(&mut r).await.unwrap();
            assert_eq!(&r[..2], &[0x05, 0x00]);
            assert_eq!(&r[2..4], &[0x05, ReplyCode::AddressTypeNotSupported as u8]);
        }
    }

    #[tokio::test]
    async fn auth_required_but_client_offers_only_no_auth() {
        let (mut client, mut server) = duplex(64);
        let creds = Credentials::parse("a:b").unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        assert!(handshake_with_auth(&mut server, Some(&creds))
            .await
            .is_err());
        let mut m = [0u8; 2];
        client.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [0x05, 0xFF]);
    }
}
