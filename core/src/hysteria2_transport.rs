// SPDX-License-Identifier: GPL-3.0-or-later
//! QUIC and HTTP/3 authentication for the Hysteria 2 client.
//!
//! This stage establishes and authenticates a protocol connection. TCP/UDP
//! relays and production outbound wiring are implemented in later stages.

use std::time::Duration;

use bytes::Buf;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use quinn::Connection;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::hysteria2::{Hysteria2Config, Obfuscation};
use crate::transport::{quic, tcp_tls};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_AUTH_RESPONSE_BODY: usize = 16 * 1024;
const AUTH_PATH: &str = "/auth";
const AUTH_HOST: &str = "hysteria";
const HYSTERIA_AUTH: &str = "Hysteria-Auth";
const HYSTERIA_CC_RX: &str = "Hysteria-CC-RX";
const HYSTERIA_UDP: &str = "Hysteria-UDP";
const HYSTERIA_PADDING: &str = "Hysteria-Padding";

/// Server's receive-rate instruction returned during authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerRxRate {
    /// The server returned `0`: it has no receive-rate limit.
    Unlimited,
    /// The server returned `auto`: the client must use congestion control.
    Auto,
    /// The server returned an explicit rate in bytes per second.
    BytesPerSecond(u64),
}

/// Negotiated capabilities needed by later TCP and UDP relay stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthNegotiation {
    pub(crate) udp_supported: bool,
    pub(crate) server_rx_rate: ServerRxRate,
}

/// An authenticated Hysteria 2 QUIC connection and its HTTP/3 driver.
///
/// The QUIC connection is shared by concurrent relays in later stages. Drop
/// closes the connection and stops the HTTP/3 driver deterministically.
#[allow(dead_code, reason = "consumed by the TCP and UDP relay stages")]
pub(crate) struct Hysteria2Connection {
    _endpoint: quinn::Endpoint,
    pub(crate) connection: Connection,
    pub(crate) auth: AuthNegotiation,
    driver: JoinHandle<()>,
}

impl Drop for Hysteria2Connection {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"client shutdown");
        self.driver.abort();
    }
}

/// Connect securely to a single-port Hysteria 2 server and authenticate it.
/// Advanced TLS, port hopping, and obfuscation options are rejected until
/// their dedicated transport stages are implemented.
#[allow(dead_code, reason = "wired into Outbound in the next Hysteria stage")]
pub(crate) async fn connect(config: &Hysteria2Config) -> Result<Hysteria2Connection> {
    validate_supported_options(config)?;
    let port = config
        .ports
        .first()
        .map(|range| range.first)
        .ok_or_else(|| Error::Config("Hysteria 2: не задан порт сервера".into()))?;
    let addrs = tcp_tls::resolve_server(&config.server, port).await?;
    let tls_name = config.sni.as_deref().unwrap_or(&config.server);
    let client_config = quic::client_config(None, vec![b"h3".to_vec()])?;
    let mut last_error = None;

    for addr in addrs {
        let endpoint = quic::direct_endpoint(addr.is_ipv6())?;
        let connecting = endpoint
            .connect_with(client_config.clone(), addr, tls_name)
            .map_err(|error| quic::connect_error("Hysteria 2", error))?;
        let connection = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                last_error = Some(quic::connect_error("Hysteria 2", error));
                continue;
            }
            Err(_) => {
                last_error = Some(Error::Protocol(format!(
                    "Hysteria 2: QUIC handshake with {addr} timed out"
                )));
                continue;
            }
        };

        let (mut h3_connection, mut sender) =
            match h3::client::new(h3_quinn::Connection::new(connection.clone())).await {
                Ok(client) => client,
                Err(error) => {
                    connection.close(0u32.into(), b"HTTP/3 setup failed");
                    last_error = Some(Error::Protocol(format!(
                        "Hysteria 2: HTTP/3 setup failed: {error}"
                    )));
                    continue;
                }
            };
        let driver = tokio::spawn(async move {
            let result = std::future::poll_fn(|cx| h3_connection.poll_close(cx)).await;
            if let Err(error) = result {
                tracing::debug!(error = %error, "Hysteria 2: HTTP/3 connection closed");
            }
        });

        let authenticated = tokio::time::timeout(AUTH_TIMEOUT, async {
            authenticate(&mut sender, &connection, config).await
        })
        .await;
        let auth = match authenticated {
            Ok(Ok(auth)) => auth,
            Ok(Err(error)) => {
                connection.close(0u32.into(), b"authentication failed");
                driver.abort();
                return Err(error);
            }
            Err(_) => {
                connection.close(0u32.into(), b"authentication timed out");
                driver.abort();
                return Err(Error::Protocol(
                    "Hysteria 2: authentication request timed out".into(),
                ));
            }
        };

        return Ok(Hysteria2Connection {
            _endpoint: endpoint,
            connection,
            auth,
            driver,
        });
    }

    Err(last_error.unwrap_or_else(|| {
        Error::Protocol("Hysteria 2: server DNS lookup returned no addresses".into())
    }))
}

fn validate_supported_options(config: &Hysteria2Config) -> Result<()> {
    if config.ports.len() != 1 || config.ports[0].first != config.ports[0].last {
        return Err(Error::Config(
            "Hysteria 2: port hopping is not supported yet".into(),
        ));
    }
    if config.insecure {
        return Err(Error::Config(
            "Hysteria 2: insecure TLS is not supported; certificate verification remains enabled"
                .into(),
        ));
    }
    if config.pin_sha256.is_some() {
        return Err(Error::Config(
            "Hysteria 2: certificate pinning is not supported yet".into(),
        ));
    }
    if config.ech.is_some() {
        return Err(Error::Config("Hysteria 2: ECH is not supported yet".into()));
    }
    if matches!(config.obfuscation, Some(Obfuscation::Salamander { .. })) {
        return Err(Error::Config(
            "Hysteria 2: Salamander obfuscation is not supported yet".into(),
        ));
    }
    if matches!(config.obfuscation, Some(Obfuscation::Gecko { .. })) {
        return Err(Error::Config(
            "Hysteria 2: Gecko obfuscation is not supported yet".into(),
        ));
    }
    Ok(())
}

async fn authenticate(
    sender: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    connection: &Connection,
    config: &Hysteria2Config,
) -> Result<AuthNegotiation> {
    let request = auth_request(config)?;
    let mut stream = sender
        .send_request(request)
        .await
        .map_err(|error| Error::Protocol(format!("Hysteria 2: auth request failed: {error}")))?;
    stream
        .finish()
        .await
        .map_err(|error| Error::Protocol(format!("Hysteria 2: auth request failed: {error}")))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| Error::Protocol(format!("Hysteria 2: auth response failed: {error}")))?;
    let auth = match parse_auth_response(response.status(), response.headers()) {
        Ok(auth) => auth,
        Err(error) => {
            connection.close(0u32.into(), b"authentication rejected");
            return Err(error);
        }
    };

    let mut received = 0usize;
    while let Some(mut chunk) = stream.recv_data().await.map_err(|error| {
        Error::Protocol(format!("Hysteria 2: auth response body failed: {error}"))
    })? {
        received = received.saturating_add(chunk.remaining());
        if received > MAX_AUTH_RESPONSE_BODY {
            connection.close(0u32.into(), b"auth response too large");
            return Err(Error::Protocol(
                "Hysteria 2: authentication response body exceeds the limit".into(),
            ));
        }
    }
    Ok(auth)
}

fn auth_request(config: &Hysteria2Config) -> Result<Request<()>> {
    let auth = HeaderValue::from_bytes(config.auth.as_deref().unwrap_or("").as_bytes())
        .map_err(|_| Error::Config("Hysteria 2: auth value is not a valid HTTP header".into()))?;
    let padding = random_padding();
    Request::builder()
        .method(Method::POST)
        // HTTP/3 encodes this authority as :authority; the Hysteria protocol
        // requires the value `hysteria` for its auth request.
        .uri(format!("https://{AUTH_HOST}{AUTH_PATH}"))
        .header(HYSTERIA_AUTH, auth)
        // No explicit client receive-rate setting exists yet; protocol value
        // 0 means unknown and asks the server to use congestion control.
        .header(HYSTERIA_CC_RX, "0")
        .header(HYSTERIA_PADDING, padding)
        .body(())
        .map_err(|error| Error::Config(format!("Hysteria 2: invalid auth request: {error}")))
}

fn parse_auth_response(status: StatusCode, headers: &HeaderMap) -> Result<AuthNegotiation> {
    if status.as_u16() != 233 {
        return Err(Error::Protocol(format!(
            "Hysteria 2: authentication rejected (HTTP status {})",
            status.as_u16()
        )));
    }
    let udp_supported = match required_header(headers, HYSTERIA_UDP)? {
        "true" => true,
        "false" => false,
        _ => {
            return Err(Error::Protocol(
                "Hysteria 2: invalid Hysteria-UDP response header".into(),
            ))
        }
    };
    let server_rx_rate = match required_header(headers, HYSTERIA_CC_RX)? {
        "auto" => ServerRxRate::Auto,
        "0" => ServerRxRate::Unlimited,
        value => ServerRxRate::BytesPerSecond(value.parse().map_err(|_| {
            Error::Protocol("Hysteria 2: invalid Hysteria-CC-RX response header".into())
        })?),
    };
    Ok(AuthNegotiation {
        udp_supported,
        server_rx_rate,
    })
}

fn required_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            Error::Protocol(format!(
                "Hysteria 2: missing or invalid {name} response header"
            ))
        })
}

fn random_padding() -> String {
    use rand::RngExt;

    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    // Match the reference client's 256..2048-byte padding range.
    let len = rng.random_range(256..2048);
    (0..len)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect()
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method, StatusCode};

    use super::{
        auth_request, parse_auth_response, validate_supported_options, AuthNegotiation,
        ServerRxRate, AUTH_HOST, HYSTERIA_AUTH, HYSTERIA_CC_RX, HYSTERIA_PADDING, HYSTERIA_UDP,
    };
    use crate::hysteria2::Hysteria2Config;

    #[test]
    fn builds_protocol_auth_request_with_unknown_client_rate_and_padding() {
        let config = Hysteria2Config::parse("hy2://secret@example.com:443").unwrap();
        let request = auth_request(&config).unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/auth");
        assert_eq!(request.uri().authority().unwrap().host(), AUTH_HOST);
        assert_eq!(request.headers()[HYSTERIA_AUTH], "secret");
        assert_eq!(request.headers()[HYSTERIA_CC_RX], "0");
        let padding = request.headers()[HYSTERIA_PADDING].to_str().unwrap();
        assert!((256..2048).contains(&padding.len()));
    }

    #[test]
    fn parses_successful_auth_and_distinguishes_rate_modes() {
        let mut headers = HeaderMap::new();
        headers.insert(HYSTERIA_UDP, HeaderValue::from_static("true"));
        headers.insert(HYSTERIA_CC_RX, HeaderValue::from_static("auto"));
        assert_eq!(
            parse_auth_response(StatusCode::from_u16(233).unwrap(), &headers).unwrap(),
            AuthNegotiation {
                udp_supported: true,
                server_rx_rate: ServerRxRate::Auto,
            }
        );

        headers.insert(HYSTERIA_CC_RX, HeaderValue::from_static("0"));
        assert_eq!(
            parse_auth_response(StatusCode::from_u16(233).unwrap(), &headers)
                .unwrap()
                .server_rx_rate,
            ServerRxRate::Unlimited
        );
        headers.insert(HYSTERIA_CC_RX, HeaderValue::from_static("1250000"));
        assert_eq!(
            parse_auth_response(StatusCode::from_u16(233).unwrap(), &headers)
                .unwrap()
                .server_rx_rate,
            ServerRxRate::BytesPerSecond(1_250_000)
        );
    }

    #[test]
    fn rejects_non_hyok_status_and_malformed_negotiation() {
        let mut headers = HeaderMap::new();
        headers.insert(HYSTERIA_UDP, HeaderValue::from_static("yes"));
        headers.insert(HYSTERIA_CC_RX, HeaderValue::from_static("auto"));
        assert!(parse_auth_response(StatusCode::OK, &headers).is_err());
        assert!(parse_auth_response(StatusCode::from_u16(233).unwrap(), &headers).is_err());

        headers.insert(HYSTERIA_UDP, HeaderValue::from_static("false"));
        headers.insert(HYSTERIA_CC_RX, HeaderValue::from_static("unknown"));
        assert!(parse_auth_response(StatusCode::from_u16(233).unwrap(), &headers).is_err());
        headers.remove(HYSTERIA_CC_RX);
        assert!(parse_auth_response(StatusCode::from_u16(233).unwrap(), &headers).is_err());
    }

    #[test]
    fn rejects_transport_options_until_their_stages_are_implemented() {
        for uri in [
            "hy2://secret@example.com:443,444",
            "hy2://secret@example.com:443?sni=front.example&insecure=1",
            "hy2://secret@example.com:443?pinSHA256=abcd",
            "hy2://secret@example.com:443?ech=YWJj",
            "hy2://secret@example.com:443?obfs=salamander&obfs-password=secret",
            "hy2://secret@example.com:443?obfs=gecko&obfs-password=secret",
        ] {
            let config = Hysteria2Config::parse(uri).unwrap();
            assert!(validate_supported_options(&config).is_err(), "{uri}");
        }
        let secure =
            Hysteria2Config::parse("hy2://secret@example.com:443?sni=front.example").unwrap();
        assert!(validate_supported_options(&secure).is_ok());
    }
}
