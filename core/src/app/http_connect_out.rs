// SPDX-License-Identifier: GPL-3.0-or-later
//! Исходящий HTTP CONNECT: только TCP-туннель через HTTP/1.1 proxy.

use std::time::Duration;

use base64::Engine as _;
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::outbound::{Outbound, UdpSession};
use super::Metadata;
use crate::error::{Error, Result};
use crate::transport::AsyncStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_HEADER_LIMIT: usize = 16 * 1024;
const MAX_INFORMATIONAL_RESPONSES: usize = 5;

pub struct HttpConnectOutbound {
    tag: String,
    server: String,
    port: u16,
    username: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    tls: bool,
    tls_server_name: String,
    tls_roots: Option<rustls::RootCertStore>,
}

impl std::fmt::Debug for HttpConnectOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConnectOutbound")
            .field("tag", &self.tag)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("username", &crate::redact::opt(&self.username))
            .field("password", &crate::redact::opt(&self.password))
            .field("tls", &self.tls)
            .field("tls_server_name", &self.tls_server_name)
            .field(
                "tls_roots",
                &self.tls_roots.as_ref().map(|_| "custom roots"),
            )
            .finish()
    }
}

impl HttpConnectOutbound {
    pub fn new(
        tag: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: bool,
        tls_server_name: Option<String>,
    ) -> Result<Self> {
        let username = username.map(Zeroizing::new);
        let password = password.map(Zeroizing::new);
        if server.trim().is_empty()
            || server.trim() != server
            || server.chars().any(char::is_control)
            || port == 0
        {
            return Err(Error::Config(format!(
                "выход {tag}: HTTP CONNECT требует корректный server и server_port от 1 до 65535"
            )));
        }
        if username.is_some() != password.is_some()
            || username.as_ref().is_some_and(|u| {
                u.is_empty() || u.len() > 4096 || u.contains(':') || u.chars().any(char::is_control)
            })
            || password
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 4096 || p.chars().any(char::is_control))
        {
            return Err(Error::Config(format!(
                "выход {tag}: HTTP CONNECT username и password должны быть заданы парой и быть корректными для Basic auth"
            )));
        }
        if !tls && tls_server_name.is_some() {
            return Err(Error::Config(format!(
                "выход {tag}: tls.server_name можно задавать только при tls.enabled = true"
            )));
        }
        let tls_server_name = tls_server_name.unwrap_or_else(|| server.clone());
        if tls_server_name.trim().is_empty()
            || tls_server_name.trim() != tls_server_name
            || tls_server_name.chars().any(char::is_control)
        {
            return Err(Error::Config(format!(
                "выход {tag}: некорректное имя tls.server_name"
            )));
        }
        Ok(Self {
            tag,
            server,
            port,
            username,
            password,
            tls,
            tls_server_name,
            tls_roots: None,
        })
    }

    pub(crate) fn with_roots(mut self, roots: Option<rustls::RootCertStore>) -> Self {
        self.tls_roots = roots;
        self
    }
}

impl Outbound for HttpConnectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn clash_type(&self) -> &'static str {
        "HTTP"
    }

    fn server(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn connect<'a>(&'a self, meta: &'a Metadata) -> BoxFuture<'a, Result<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
                let addrs =
                    crate::transport::tcp_tls::resolve_server(&self.server, self.port).await?;
                let tcp =
                    crate::transport::tcp_tls::connect_addrs(&addrs, "HTTP CONNECT proxy").await?;
                let mut stream: Box<dyn AsyncStream> = if self.tls {
                    Box::new(
                        crate::transport::tcp_tls::tls_over(
                            tcp,
                            &self.tls_server_name,
                            self.tls_roots.clone(),
                            Vec::new(),
                        )
                        .await?,
                    )
                } else {
                    Box::new(tcp)
                };
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
                Error::Protocol("HTTP CONNECT: превышено время подключения или ответа proxy".into())
            })??;
            Ok(stream)
        })
    }

    fn udp<'a>(
        &'a self,
        _meta: &'a Metadata,
    ) -> BoxFuture<'a, Result<std::sync::Arc<dyn UdpSession>>> {
        Box::pin(async {
            Err(Error::Protocol(
                "HTTP CONNECT outbound поддерживает только TCP".into(),
            ))
        })
    }
}

async fn handshake<S>(
    stream: &mut S,
    meta: &Metadata,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let authority = authority(&meta.target, meta.port)?;
    let mut request = Zeroizing::new(Vec::with_capacity(256));
    request.extend_from_slice(b"CONNECT ");
    request.extend_from_slice(authority.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(authority.as_bytes());
    request.extend_from_slice(b"\r\nProxy-Connection: Keep-Alive\r\n");
    if let (Some(username), Some(password)) = (username, password) {
        let mut credentials =
            Zeroizing::new(Vec::with_capacity(username.len() + password.len() + 1));
        credentials.extend_from_slice(username.as_bytes());
        credentials.push(b':');
        credentials.extend_from_slice(password.as_bytes());
        let encoded =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*credentials));
        request.extend_from_slice(b"Proxy-Authorization: Basic ");
        request.extend_from_slice(encoded.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    stream.write_all(&request).await?;

    for _ in 0..=MAX_INFORMATIONAL_RESPONSES {
        let head = read_response_head(stream).await?;
        let status = parse_status(&head)?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        if !(100..200).contains(&status) || status == 101 {
            return Err(Error::Protocol(format!(
                "HTTP CONNECT proxy отказал в туннеле (HTTP {status})"
            )));
        }
    }
    Err(Error::Protocol(
        "HTTP CONNECT proxy вернул слишком много промежуточных ответов".into(),
    ))
}

fn authority(target: &crate::vless::Address, port: u16) -> Result<String> {
    if port == 0 {
        return Err(Error::Protocol(
            "HTTP CONNECT: порт назначения равен нулю".into(),
        ));
    }
    let host = match target {
        crate::vless::Address::Ipv4(ip) => ip.to_string(),
        crate::vless::Address::Ipv6(ip) => format!("[{ip}]"),
        crate::vless::Address::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 1024
                || domain.trim() != domain
                || domain.chars().any(|c| {
                    c.is_control()
                        || c.is_whitespace()
                        || matches!(c, '/' | '@' | '[' | ']' | ':' | '?' | '#' | '\\')
                })
            {
                return Err(Error::Protocol(
                    "HTTP CONNECT: некорректное имя назначения".into(),
                ));
            }
            domain.clone()
        }
    };
    Ok(format!("{host}:{port}"))
}

async fn read_response_head<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while head.len() < RESPONSE_HEADER_LIMIT {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err(Error::Protocol(
        "HTTP CONNECT proxy прислал слишком большой заголовок ответа".into(),
    ))
}

fn parse_status(head: &[u8]) -> Result<u16> {
    let end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| Error::Protocol("HTTP CONNECT proxy прислал неверный ответ".into()))?;
    let line = std::str::from_utf8(&head[..end])
        .map_err(|_| Error::Protocol("HTTP CONNECT proxy прислал неверный статус".into()))?;
    let mut parts = line.split_ascii_whitespace();
    let version = parts.next();
    let status = parts.next().and_then(|s| s.parse::<u16>().ok());
    if !matches!(version, Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(Error::Protocol(
            "HTTP CONNECT proxy вернул ответ не HTTP/1.0 или HTTP/1.1".into(),
        ));
    }
    status
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| Error::Protocol("HTTP CONNECT proxy прислал неверный код статуса".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};

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

    async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            assert!(request.len() <= RESPONSE_HEADER_LIMIT);
        }
        request
    }

    #[tokio::test]
    async fn connect_establishes_tunnel_and_preserves_bytes_after_response_headers() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert!(request.starts_with(b"CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(request.windows(6).any(|w| w == b"Host: "));
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\nhello")
                .await
                .unwrap();
        });
        let outbound = HttpConnectOutbound::new(
            "proxy".into(),
            address.ip().to_string(),
            address.port(),
            None,
            None,
            false,
            None,
        )
        .unwrap();
        let meta = metadata(crate::vless::Address::Domain("example.com".into()), 443);
        let mut tunnel = outbound.connect(&meta).await.unwrap();
        let mut payload = [0u8; 5];
        tunnel.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn basic_auth_is_sent_only_as_encoded_proxy_header() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert!(request
                .windows(b"Proxy-Authorization: Basic dXNlcjpwYXNz".len())
                .any(|w| w == b"Proxy-Authorization: Basic dXNlcjpwYXNz"));
            assert!(!request.windows(9).any(|w| w == b"user:pass"));
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });
        let outbound = HttpConnectOutbound::new(
            "proxy".into(),
            address.ip().to_string(),
            address.port(),
            Some("user".into()),
            Some("pass".into()),
            false,
            None,
        )
        .unwrap();
        let meta = metadata(crate::vless::Address::Ipv4(Ipv4Addr::LOCALHOST), 80);
        outbound.connect(&meta).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls_proxy_verifies_custom_root_and_sends_auth_inside_tls() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        crate::transport::tcp_tls::ensure_crypto_provider();
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec!["proxy.local".into()]).unwrap();
        let cert = params.signed_by(&key_pair, &ca_cert, &ca_key).unwrap();
        let certificate = CertificateDer::from(cert.der().to_vec());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let request = read_request(&mut stream).await;
            assert!(request
                .windows(b"Proxy-Authorization: Basic dXNlcjpwYXNz".len())
                .any(|w| w == b"Proxy-Authorization: Basic dXNlcjpwYXNz"));
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .unwrap();
        let outbound = HttpConnectOutbound::new(
            "proxy".into(),
            address.ip().to_string(),
            address.port(),
            Some("user".into()),
            Some("pass".into()),
            true,
            Some("proxy.local".into()),
        )
        .unwrap()
        .with_roots(Some(roots));
        let meta = metadata(crate::vless::Address::Domain("example.org".into()), 443);
        outbound.connect(&meta).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_proxy_errors_and_malformed_status_lines() {
        for response in [
            &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
            &b"NOT-HTTP 200 OK\r\n\r\n"[..],
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let response = response.to_vec();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _request = read_request(&mut stream).await;
                stream.write_all(&response).await.unwrap();
            });
            let outbound = HttpConnectOutbound::new(
                "proxy".into(),
                address.ip().to_string(),
                address.port(),
                None,
                None,
                false,
                None,
            )
            .unwrap();
            let meta = metadata(crate::vless::Address::Domain("example.org".into()), 443);
            assert!(outbound.connect(&meta).await.is_err());
            server.await.unwrap();
        }
    }

    #[test]
    fn authority_brackets_ipv6_and_rejects_header_injection() {
        assert_eq!(
            authority(
                &crate::vless::Address::Ipv6("2001:db8::1".parse().unwrap()),
                443
            )
            .unwrap(),
            "[2001:db8::1]:443"
        );
        assert!(authority(&crate::vless::Address::Domain("bad\r\nHost:x".into()), 443).is_err());
    }

    #[test]
    fn credentials_are_redacted_from_debug() {
        let outbound = HttpConnectOutbound::new(
            "proxy".into(),
            "proxy.example".into(),
            8080,
            Some("private-user".into()),
            Some("private-pass".into()),
            true,
            Some("proxy.example".into()),
        )
        .unwrap();
        let debug = format!("{outbound:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-pass"));
    }
}
