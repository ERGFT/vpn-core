// SPDX-License-Identifier: GPL-3.0-or-later
//! QUIC, HTTP/3 authentication, and TCP relay for the Hysteria 2 client.
//!
//! Production outbound wiring is implemented in a later stage.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Buf;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use quinn::Connection;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

use crate::error::{Error, Result};
use crate::hysteria2::{Hysteria2Config, Obfuscation};
use crate::hysteria2_udp::UdpDatagramMux;
use crate::transport::{quic, tcp_tls, AsyncStream};
use crate::vless::Address;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_AUTH_RESPONSE_BODY: usize = 16 * 1024;
const TCP_REQUEST_ID: u64 = 0x401;
const MAX_TCP_ADDRESS: usize = 2048;
const MAX_TCP_RESPONSE_MESSAGE: usize = 2048;
const MAX_TCP_PADDING: usize = 4096;
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
/// The QUIC connection is shared by concurrent TCP and UDP relays. Drop
/// closes the connection and stops the HTTP/3 driver deterministically.
#[allow(dead_code, reason = "consumed by the TCP and UDP relay stages")]
pub(crate) struct Hysteria2Connection {
    _endpoint: quinn::Endpoint,
    pub(crate) connection: Connection,
    pub(crate) auth: AuthNegotiation,
    udp_mux: std::sync::Arc<UdpDatagramMux>,
    udp_driver: JoinHandle<()>,
    next_udp_session_id: AtomicU64,
    driver: JoinHandle<()>,
}

impl Hysteria2Connection {
    /// Open one TCP relay stream on the authenticated QUIC connection.
    pub(crate) async fn connect_tcp(
        &self,
        target: &Address,
        port: u16,
    ) -> Result<Box<dyn AsyncStream>> {
        let request = encode_tcp_request(target, port)?;
        let (mut send, mut recv) =
            tokio::time::timeout(TCP_OPEN_TIMEOUT, self.connection.open_bi())
                .await
                .map_err(|_| Error::Protocol("Hysteria 2: opening TCP stream timed out".into()))?
                .map_err(|error| {
                    Error::Protocol(format!("Hysteria 2: opening TCP stream failed: {error}"))
                })?;
        tokio::time::timeout(TCP_OPEN_TIMEOUT, async {
            send.write_all(&request).await?;
            send.flush().await
        })
        .await
        .map_err(|_| Error::Protocol("Hysteria 2: sending TCP request timed out".into()))?
        .map_err(|error| {
            Error::Protocol(format!("Hysteria 2: sending TCP request failed: {error}"))
        })?;

        match tokio::time::timeout(TCP_OPEN_TIMEOUT, read_tcp_response(&mut recv)).await {
            Ok(Ok(())) => Ok(Box::new(tokio::io::join(recv, send))),
            Ok(Err(error)) => {
                let _ = send.reset(1u32.into());
                Err(error)
            }
            Err(_) => {
                let _ = send.reset(1u32.into());
                Err(Error::Protocol("Hysteria 2: TCP response timed out".into()))
            }
        }
    }

    /// Open one Hysteria UDP association on the shared QUIC connection.
    pub(crate) async fn open_udp_session(
        &self,
    ) -> Result<std::sync::Arc<dyn crate::app::outbound::UdpSession>> {
        if !self.auth.udp_supported {
            return Err(Error::Protocol(
                "Hysteria 2: server did not enable UDP relay".into(),
            ));
        }
        let session_id = allocate_udp_session_id(&self.next_udp_session_id)?;
        self.udp_mux.open_session(session_id).await
    }
}

impl Drop for Hysteria2Connection {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"client shutdown");
        self.driver.abort();
        // Closing QUIC wakes read_datagram(); let it clear per-session routes.
    }
}

// Keep `fetch_update` for the repository's MSRV; newer stable toolchains deprecate it.
#[allow(deprecated)]
fn allocate_udp_session_id(next: &AtomicU64) -> Result<u32> {
    next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
        (id <= u64::from(u32::MAX)).then_some(id + 1)
    })
    .map(|id| id as u32)
    .map_err(|_| Error::Protocol("Hysteria 2: UDP session ID space is exhausted".into()))
}

/// Connect securely to a single-port Hysteria 2 server and authenticate it.
/// Advanced TLS, port hopping, and obfuscation options are rejected until
/// their dedicated transport stages are implemented.
#[allow(
    dead_code,
    reason = "wired into the production outbound in a later stage"
)]
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
            let error = std::future::poll_fn(|cx| h3_connection.poll_close(cx)).await;
            tracing::debug!(error = %error, "Hysteria 2: HTTP/3 connection closed");
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

        let udp_mux = UdpDatagramMux::new(connection.clone());
        let udp_driver = udp_mux.clone().spawn();
        return Ok(Hysteria2Connection {
            _endpoint: endpoint,
            connection,
            auth,
            udp_mux,
            udp_driver,
            next_udp_session_id: AtomicU64::new(0),
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
    while let Some(chunk) = stream.recv_data().await.map_err(|error| {
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

fn encode_tcp_request(target: &Address, port: u16) -> Result<Vec<u8>> {
    let host = match target {
        Address::Ipv4(ip) => ip.to_string(),
        Address::Domain(domain) => domain.clone(),
        Address::Ipv6(ip) => format!("[{ip}]"),
    };
    let address = format!("{host}:{port}");
    if address.is_empty() || address.len() > MAX_TCP_ADDRESS {
        return Err(Error::Protocol(
            "Hysteria 2: TCP destination address exceeds the protocol limit".into(),
        ));
    }

    let padding = random_tcp_padding();
    let mut request = Vec::with_capacity(address.len() + padding.len() + 16);
    encode_quic_varint(TCP_REQUEST_ID, &mut request);
    encode_quic_varint(address.len() as u64, &mut request);
    request.extend_from_slice(address.as_bytes());
    encode_quic_varint(padding.len() as u64, &mut request);
    request.extend_from_slice(padding.as_bytes());
    Ok(request)
}

pub(crate) fn encode_quic_varint(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        _ => output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

async fn read_quic_varint<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u64> {
    let first = reader
        .read_u8()
        .await
        .map_err(|error| tcp_response_error("reading variable-length integer", error))?;
    let len = 1usize << (first >> 6);
    let mut encoded = [0u8; 8];
    encoded[0] = first;
    if len > 1 {
        reader
            .read_exact(&mut encoded[1..len])
            .await
            .map_err(|error| tcp_response_error("reading variable-length integer", error))?;
    }
    decode_quic_varint(&encoded[..len]).map(|(value, _)| value)
}

pub(crate) fn decode_quic_varint(encoded: &[u8]) -> Result<(u64, usize)> {
    let first = *encoded
        .first()
        .ok_or_else(|| Error::Protocol("Hysteria 2: empty QUIC variable-length integer".into()))?;
    let len = 1usize << (first >> 6);
    if encoded.len() < len {
        return Err(Error::Protocol(
            "Hysteria 2: truncated QUIC variable-length integer".into(),
        ));
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &encoded[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, len))
}

async fn read_tcp_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let status = reader
        .read_u8()
        .await
        .map_err(|error| tcp_response_error("reading status", error))?;
    let message_len = read_quic_varint(reader).await?;
    if message_len > MAX_TCP_RESPONSE_MESSAGE as u64 {
        return Err(Error::Protocol(
            "Hysteria 2: TCP response message exceeds the protocol limit".into(),
        ));
    }
    let mut message = vec![0; message_len as usize];
    reader
        .read_exact(&mut message)
        .await
        .map_err(|error| tcp_response_error("reading message", error))?;
    let padding_len = read_quic_varint(reader).await?;
    if padding_len > MAX_TCP_PADDING as u64 {
        return Err(Error::Protocol(
            "Hysteria 2: TCP response padding exceeds the protocol limit".into(),
        ));
    }
    let mut remaining = padding_len;
    let mut discard = [0u8; 512];
    while remaining > 0 {
        let count = remaining.min(discard.len() as u64) as usize;
        reader
            .read_exact(&mut discard[..count])
            .await
            .map_err(|error| tcp_response_error("reading padding", error))?;
        remaining -= count as u64;
    }

    match status {
        0 => Ok(()),
        1 => Err(Error::Protocol(format!(
            "Hysteria 2: TCP relay rejected: {}",
            String::from_utf8_lossy(&message)
        ))),
        _ => Err(Error::Protocol(format!(
            "Hysteria 2: invalid TCP response status {status}"
        ))),
    }
}

fn tcp_response_error(context: &str, error: io::Error) -> Error {
    Error::Protocol(format!("Hysteria 2: error {context}: {error}"))
}

fn random_tcp_padding() -> String {
    use rand::RngExt;

    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    let len = rng.random_range(64..512);
    (0..len)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect()
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
        allocate_udp_session_id, auth_request, decode_quic_varint, encode_quic_varint,
        encode_tcp_request, parse_auth_response, read_quic_varint, read_tcp_response,
        validate_supported_options, AuthNegotiation, ServerRxRate, AUTH_HOST, HYSTERIA_AUTH,
        HYSTERIA_CC_RX, HYSTERIA_PADDING, HYSTERIA_UDP,
    };
    use crate::hysteria2::Hysteria2Config;
    use crate::vless::Address;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn udp_session_ids_are_unique_until_the_wire_space_is_exhausted() {
        let next = AtomicU64::new(u64::from(u32::MAX) - 1);
        assert_eq!(allocate_udp_session_id(&next).unwrap(), u32::MAX - 1);
        assert_eq!(allocate_udp_session_id(&next).unwrap(), u32::MAX);
        assert!(allocate_udp_session_id(&next).is_err());
    }

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

    #[test]
    fn encodes_tcp_request_with_quic_varints_and_random_padding() {
        let request = encode_tcp_request(&Address::Domain("example.com".into()), 443).unwrap();
        let (request_id, request_id_len) = decode_quic_varint(&request).unwrap();
        assert_eq!(request_id, 0x401);
        let (address_len, address_len_len) =
            decode_quic_varint(&request[request_id_len..]).unwrap();
        let address_len = address_len as usize;
        let address_start = request_id_len + address_len_len;
        assert_eq!(
            &request[address_start..address_start + address_len],
            b"example.com:443"
        );
        let padding_len_offset = address_start + address_len;
        let (padding_len, padding_len_len) =
            decode_quic_varint(&request[padding_len_offset..]).unwrap();
        let padding_len = padding_len as usize;
        assert!((64..512).contains(&padding_len));
        assert_eq!(
            request.len(),
            padding_len_offset + padding_len_len + padding_len
        );

        let ipv6 =
            encode_tcp_request(&Address::Ipv6("2001:db8::1".parse().unwrap()), 8443).unwrap();
        assert!(ipv6
            .windows(b"[2001:db8::1]:8443".len())
            .any(|w| w == b"[2001:db8::1]:8443"));
    }

    #[tokio::test]
    async fn round_trips_quic_varint_width_boundaries() {
        use tokio::io::AsyncWriteExt;

        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            (1u64 << 62) - 1,
        ] {
            let mut encoded = Vec::new();
            encode_quic_varint(value, &mut encoded);
            let (mut writer, mut reader) = tokio::io::duplex(16);
            writer.write_all(&encoded).await.unwrap();
            assert_eq!(read_quic_varint(&mut reader).await.unwrap(), value);
        }
    }

    #[tokio::test]
    async fn accepts_tcp_ok_and_leaves_tunnel_payload_unread() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[0, 0, 0]).await.unwrap(); // status, empty message, no padding
        writer.write_all(b"tunnel-data").await.unwrap();
        read_tcp_response(&mut reader).await.unwrap();
        let mut payload = [0; 11];
        reader.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"tunnel-data");
    }

    #[tokio::test]
    async fn rejects_tcp_error_malformed_status_and_oversized_response() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&[1, 4, b'd', b'e', b'n', b'y', 0])
            .await
            .unwrap();
        let error = read_tcp_response(&mut reader).await.unwrap_err();
        assert!(error.to_string().contains("deny"));

        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[2, 0, 0]).await.unwrap();
        assert!(read_tcp_response(&mut reader).await.is_err());

        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[0, 0x48, 0x01]).await.unwrap(); // message length 2049
        assert!(read_tcp_response(&mut reader).await.is_err());
    }
}
