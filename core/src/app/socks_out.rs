// SPDX-License-Identifier: GPL-3.0-or-later
//! Исходящий SOCKS5: только TCP CONNECT (RFC 1928), без UDP ASSOCIATE.

use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use super::outbound::{Outbound, UdpSession};
use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::AsyncStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Socks5Outbound {
    tag: String,
    server: String,
    port: u16,
    username: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
}

impl Socks5Outbound {
    pub fn new(
        tag: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<Self> {
        let username = username.map(Zeroizing::new);
        let password = password.map(Zeroizing::new);
        if server.trim().is_empty()
            || server.trim() != server
            || server.chars().any(char::is_control)
            || port == 0
        {
            return Err(Error::Config(format!(
                "выход {tag}: SOCKS5 требует корректный server и server_port от 1 до 65535"
            )));
        }
        if username.is_some() != password.is_some()
            || username
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 255)
            || password
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 255)
        {
            return Err(Error::Config(format!(
                "выход {tag}: SOCKS5 username и password должны быть заданы парой и занимать 1–255 байт"
            )));
        }
        Ok(Self {
            tag,
            server,
            port,
            username,
            password,
        })
    }
}

impl Outbound for Socks5Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn clash_type(&self) -> &'static str {
        "Socks5"
    }

    fn server(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
                let addrs =
                    crate::transport::tcp_tls::resolve_server(&self.server, self.port).await?;
                let mut stream =
                    crate::transport::tcp_tls::connect_addrs(&addrs, "SOCKS5 proxy").await?;
                handshake(
                    &mut stream,
                    meta,
                    self.username.as_ref().map(|s| s.as_str()),
                    self.password.as_ref().map(|s| s.as_str()),
                )
                .await?;
                Ok::<_, Error>(stream)
            })
            .await
            .map_err(|_| {
                Error::Protocol("SOCKS5: превышено время подключения или ответа прокси".into())
            })??;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }

    fn udp<'a>(
        &'a self,
        _meta: &'a Metadata,
    ) -> BoxFuture<'a, Result<std::sync::Arc<dyn UdpSession>>> {
        Box::pin(async {
            Err(Error::Protocol(
                "SOCKS5 outbound: UDP ASSOCIATE пока не поддерживается".into(),
            ))
        })
    }
}

async fn handshake(
    stream: &mut TcpStream,
    meta: &Metadata,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let authenticated = username.is_some();
    if authenticated {
        stream.write_all(&[5, 1, 2]).await?;
    } else {
        stream.write_all(&[5, 1, 0]).await?;
    }
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    let expected_method = if authenticated { 2 } else { 0 };
    if method[0] != 5 || method[1] != expected_method {
        return Err(Error::Socks5(
            "прокси не принял предложенный способ аутентификации".into(),
        ));
    }

    if let (Some(username), Some(password)) = (username, password) {
        let user = username.as_bytes();
        let pass = password.as_bytes();
        if user.is_empty() || user.len() > 255 || pass.is_empty() || pass.len() > 255 {
            return Err(Error::Socks5("некорректная длина учётных данных".into()));
        }
        let mut auth = Zeroizing::new(Vec::with_capacity(user.len() + pass.len() + 3));
        auth.extend_from_slice(&[1, user.len() as u8]);
        auth.extend_from_slice(user);
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass);
        stream.write_all(&auth).await?;
        let mut result = [0; 2];
        stream.read_exact(&mut result).await?;
        if result != [1, 0] {
            return Err(Error::Socks5("прокси отклонил учётные данные".into()));
        }
    }

    let mut request = vec![5, 1, 0];
    match &meta.target {
        crate::vless::Address::Ipv4(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        crate::vless::Address::Domain(domain) => {
            let name = domain.as_bytes();
            if name.is_empty() || name.len() > 255 || domain.chars().any(char::is_control) {
                return Err(Error::Socks5("некорректное имя назначения".into()));
            }
            request.extend_from_slice(&[3, name.len() as u8]);
            request.extend_from_slice(name);
        }
        crate::vless::Address::Ipv6(ip) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&meta.port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 || head[2] != 0 {
        return Err(Error::Socks5("некорректный ответ CONNECT от прокси".into()));
    }
    match head[3] {
        1 => {
            let mut address_and_port = [0; 6];
            stream.read_exact(&mut address_and_port).await?;
        }
        3 => {
            let mut len = [0; 1];
            stream.read_exact(&mut len).await?;
            let mut address_and_port = vec![0; len[0] as usize + 2];
            stream.read_exact(&mut address_and_port).await?;
        }
        4 => {
            let mut address_and_port = [0; 18];
            stream.read_exact(&mut address_and_port).await?;
        }
        _ => {
            return Err(Error::Socks5(
                "неподдерживаемый тип адреса в ответе прокси".into(),
            ))
        }
    }
    if head[1] != 0 {
        return Err(Error::Socks5(format!(
            "прокси отказал в CONNECT (код {})",
            head[1]
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    fn metadata(target: crate::vless::Address, port: u16) -> Metadata {
        Metadata {
            inbound: Arc::from("test"),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            user_id: None,
            network: crate::app::Network::Tcp,
            target,
            port,
            sniffed: None,
            inbound_type: "test",
            rule: None,
        }
    }

    async fn proxy_pair() -> (TcpStream, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).await.unwrap();

            let mut auth_header = [0; 2];
            stream.read_exact(&mut auth_header).await.unwrap();
            assert_eq!(auth_header[0], 1);
            let mut username = vec![0; auth_header[1] as usize];
            stream.read_exact(&mut username).await.unwrap();
            let mut password_len = [0; 1];
            stream.read_exact(&mut password_len).await.unwrap();
            let mut password = vec![0; password_len[0] as usize];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"user");
            assert_eq!(password, b"pass");
            stream.write_all(&[1, 0]).await.unwrap();

            let mut request = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 3, 11]);
            let mut domain = [0; 11];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(&domain, b"example.com");
            let mut port = [0; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        (TcpStream::connect(address).await.unwrap(), server)
    }

    #[tokio::test]
    async fn authenticated_connect_preserves_domain_and_port() {
        let (mut client, server) = proxy_pair().await;
        handshake(
            &mut client,
            &metadata(crate::vless::Address::Domain("example.com".into()), 443),
            Some("user"),
            Some("pass"),
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_refusal_is_returned_as_an_error() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            let mut domain = vec![0; request[4] as usize + 2];
            stream.read_exact(&mut domain).await.unwrap();
            stream
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        let error = handshake(
            &mut client,
            &metadata(crate::vless::Address::Domain("closed.example".into()), 443),
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("код 5"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn outbound_connect_uses_proxy_and_returns_the_tunnel_stream() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 1]);
            let mut address_and_port = [0; 6];
            stream.read_exact(&mut address_and_port).await.unwrap();
            assert_eq!(&address_and_port[..4], &[127, 0, 0, 1]);
            assert_eq!(
                u16::from_be_bytes([address_and_port[4], address_and_port[5]]),
                80
            );
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        let outbound = Socks5Outbound::new(
            "proxy".into(),
            address.ip().to_string(),
            address.port(),
            None,
            None,
        )
        .unwrap();
        let meta = metadata(crate::vless::Address::Ipv4(Ipv4Addr::LOCALHOST), 80);
        let _stream = outbound.connect(&meta).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_is_explicitly_unsupported() {
        let outbound =
            Socks5Outbound::new("proxy".into(), "127.0.0.1".into(), 1080, None, None).unwrap();
        let meta = metadata(crate::vless::Address::Ipv4(Ipv4Addr::LOCALHOST), 53);
        let error = outbound.udp(&meta).await.err().unwrap();
        assert!(error
            .to_string()
            .contains("UDP ASSOCIATE пока не поддерживается"));
    }

    #[tokio::test]
    async fn rejected_credentials_return_a_sanitized_error() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth_header = [0; 2];
            stream.read_exact(&mut auth_header).await.unwrap();
            let mut username = vec![0; auth_header[1] as usize];
            stream.read_exact(&mut username).await.unwrap();
            let mut password_len = [0; 1];
            stream.read_exact(&mut password_len).await.unwrap();
            let mut password = vec![0; password_len[0] as usize];
            stream.read_exact(&mut password).await.unwrap();
            stream.write_all(&[1, 1]).await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        let error = handshake(
            &mut client,
            &metadata(crate::vless::Address::Ipv4(Ipv4Addr::LOCALHOST), 443),
            Some("private-user"),
            Some("private-pass"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("отклонил учётные данные"));
        assert!(!error.contains("private-user"));
        assert!(!error.contains("private-pass"));
        server.await.unwrap();
    }
}
