// SPDX-License-Identifier: GPL-3.0-or-later
//! Plaintext VMess AEAD request-header fields and codec.
//!
//! The returned plaintext is sealed separately by [`super::aead::seal_header`].
//! This module does not open a socket or imply a complete VMess client.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

const VERSION: u8 = 0;
const FIXED_PREFIX_LEN: usize = 38;
const CHECKSUM_LEN: usize = 4;
const MAX_PADDING: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Security {
    Aes128Gcm = 3,
    Chacha20Poly1305 = 4,
    None = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

/// Fields encoded inside the authenticated VMess request-header payload.
/// Random values and padding are explicit so callers can supply CSPRNG output
/// while tests can assert exact reference vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_header: u8,
    pub options: u8,
    pub security: Security,
    pub command: Command,
    pub destination: Option<(Address, u16)>,
    pub padding: Vec<u8>,
}

/// Encode the plaintext request header, including its FNV-1a checksum.
pub fn encode_request_header(header: &RequestHeader) -> Result<Vec<u8>> {
    validate(header)?;
    let mut output = Vec::with_capacity(FIXED_PREFIX_LEN + 300 + CHECKSUM_LEN);
    output.push(VERSION);
    output.extend_from_slice(&header.request_body_iv);
    output.extend_from_slice(&header.request_body_key);
    output.push(header.response_header);
    output.push(header.options);
    output.push(((header.padding.len() as u8) << 4) | header.security as u8);
    output.push(0); // reserved
    output.push(header.command as u8);
    if let Some((address, port)) = &header.destination {
        output.extend_from_slice(&port.to_be_bytes());
        match address {
            Address::Ipv4(address) => {
                output.push(1);
                output.extend_from_slice(&address.octets());
            }
            Address::Domain(domain) => {
                output.push(2);
                output.push(domain.len() as u8);
                output.extend_from_slice(domain.as_bytes());
            }
            Address::Ipv6(address) => {
                output.push(3);
                output.extend_from_slice(&address.octets());
            }
        }
    }
    output.extend_from_slice(&header.padding);
    let checksum = fnv1a(&output);
    output.extend_from_slice(&checksum.to_be_bytes());
    Ok(output)
}

/// Decode and authenticate one plaintext VMess request-header payload.
/// Returns the decoded header and the exact number of bytes consumed.
pub fn decode_request_header(input: &[u8]) -> Result<(RequestHeader, usize)> {
    if input.len() < FIXED_PREFIX_LEN + CHECKSUM_LEN {
        return Err(protocol_error("truncated VMess request header"));
    }
    if input[0] != VERSION {
        return Err(protocol_error("unsupported VMess request-header version"));
    }
    let mut request_body_iv = [0; 16];
    request_body_iv.copy_from_slice(&input[1..17]);
    let mut request_body_key = [0; 16];
    request_body_key.copy_from_slice(&input[17..33]);
    let response_header = input[33];
    let options = input[34];
    let padding_len = usize::from(input[35] >> 4);
    let security = match input[35] & 0x0f {
        3 => Security::Aes128Gcm,
        4 => Security::Chacha20Poly1305,
        5 => Security::None,
        _ => return Err(protocol_error("unsupported VMess request-header security")),
    };
    if input[36] != 0 {
        return Err(protocol_error(
            "non-zero VMess request-header reserved byte",
        ));
    }
    let command = match input[37] {
        1 => Command::Tcp,
        2 => Command::Udp,
        3 => Command::Mux,
        _ => return Err(protocol_error("unsupported VMess request-header command")),
    };

    let mut cursor = FIXED_PREFIX_LEN;
    let destination = if command == Command::Mux {
        None
    } else {
        require(input, cursor, 3, "truncated VMess destination")?;
        let port = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
        cursor += 2;
        let address_type = input[cursor];
        cursor += 1;
        let address = match address_type {
            1 => {
                require(input, cursor, 4, "truncated VMess IPv4 address")?;
                let address = Ipv4Addr::new(
                    input[cursor],
                    input[cursor + 1],
                    input[cursor + 2],
                    input[cursor + 3],
                );
                cursor += 4;
                Address::Ipv4(address)
            }
            2 => {
                require(input, cursor, 1, "truncated VMess domain length")?;
                let len = usize::from(input[cursor]);
                cursor += 1;
                require(input, cursor, len, "truncated VMess domain")?;
                let domain = std::str::from_utf8(&input[cursor..cursor + len])
                    .map_err(|_| protocol_error("VMess domain is not valid UTF-8"))?;
                if domain.is_empty() {
                    return Err(protocol_error("VMess destination domain is empty"));
                }
                cursor += len;
                Address::Domain(domain.to_owned())
            }
            3 => {
                require(input, cursor, 16, "truncated VMess IPv6 address")?;
                let mut octets = [0; 16];
                octets.copy_from_slice(&input[cursor..cursor + 16]);
                cursor += 16;
                Address::Ipv6(Ipv6Addr::from(octets))
            }
            _ => return Err(protocol_error("unsupported VMess destination address type")),
        };
        Some((address, port))
    };
    require(
        input,
        cursor,
        padding_len + CHECKSUM_LEN,
        "truncated VMess padding or checksum",
    )?;
    let padding = input[cursor..cursor + padding_len].to_vec();
    cursor += padding_len;
    let checksum_end = cursor + CHECKSUM_LEN;
    let expected = fnv1a(&input[..cursor]);
    let mut checksum_bytes = [0; CHECKSUM_LEN];
    checksum_bytes.copy_from_slice(&input[cursor..checksum_end]);
    let actual = u32::from_be_bytes(checksum_bytes);
    if actual != expected {
        return Err(protocol_error(
            "VMess request-header FNV-1a checksum mismatch",
        ));
    }
    let header = RequestHeader {
        request_body_iv,
        request_body_key,
        response_header,
        options,
        security,
        command,
        destination,
        padding,
    };
    validate(&header)?;
    Ok((header, checksum_end))
}

fn validate(header: &RequestHeader) -> Result<()> {
    if header.padding.len() > MAX_PADDING {
        return Err(protocol_error(
            "VMess padding must contain at most 15 bytes",
        ));
    }
    if header.command == Command::Mux {
        if header.destination.is_some() {
            return Err(protocol_error(
                "VMess Mux request cannot carry a destination",
            ));
        }
    } else if header
        .destination
        .as_ref()
        .is_none_or(|(_, port)| *port == 0)
    {
        return Err(protocol_error(
            "VMess TCP/UDP request requires a non-zero destination port",
        ));
    }
    if let Some((Address::Domain(domain), _)) = &header.destination {
        if domain.is_empty()
            || domain.len() > u8::MAX as usize
            || domain.chars().any(char::is_control)
        {
            return Err(protocol_error(
                "VMess destination domain must be 1..=255 UTF-8 bytes",
            ));
        }
    }
    Ok(())
}

fn require(input: &[u8], offset: usize, len: usize, message: &str) -> Result<()> {
    if input.len().saturating_sub(offset) < len {
        Err(protocol_error(message))
    } else {
        Ok(())
    }
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

fn protocol_error(message: &str) -> Error {
    Error::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RequestHeader {
        RequestHeader {
            request_body_iv: [0x11; 16],
            request_body_key: [0x22; 16],
            response_header: 0x33,
            options: 0x04,
            security: Security::Aes128Gcm,
            command: Command::Tcp,
            destination: Some((Address::Domain("example.com".into()), 443)),
            padding: vec![0xaa, 0xbb],
        }
    }

    #[test]
    fn request_header_round_trip_and_checksum() {
        let header = sample();
        let encoded = encode_request_header(&header).unwrap();
        let (decoded, consumed) = decode_request_header(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, encoded.len());
        assert_eq!(fnv1a(b"hello"), 0x4f9f_2cab);
    }

    #[test]
    fn request_header_rejects_bad_checksum_and_truncation() {
        let mut encoded = encode_request_header(&sample()).unwrap();
        assert!(decode_request_header(&encoded[..encoded.len() - 1]).is_err());
        encoded[38] ^= 1;
        assert!(decode_request_header(&encoded).is_err());
    }

    #[test]
    fn mux_header_has_no_destination() {
        let mut header = sample();
        header.command = Command::Mux;
        header.destination = None;
        let encoded = encode_request_header(&header).unwrap();
        let (decoded, consumed) = decode_request_header(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn ipv4_and_ipv6_addresses_round_trip() {
        for address in [
            Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            Address::Ipv6("2001:db8::1".parse().unwrap()),
        ] {
            let mut header = sample();
            header.command = Command::Udp;
            header.destination = Some((address, 53));
            let encoded = encode_request_header(&header).unwrap();
            let (decoded, consumed) = decode_request_header(&encoded).unwrap();
            assert_eq!(decoded, header);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn encoder_rejects_invalid_destination_and_padding() {
        let mut header = sample();
        header.padding = vec![0; MAX_PADDING + 1];
        assert!(encode_request_header(&header).is_err());

        header = sample();
        header.destination = Some((Address::Domain(String::new()), 443));
        assert!(encode_request_header(&header).is_err());

        header = sample();
        header.destination = Some((Address::Domain("x".repeat(256)), 443));
        assert!(encode_request_header(&header).is_err());

        header = sample();
        header.destination = Some((Address::Domain("example.com".into()), 0));
        assert!(encode_request_header(&header).is_err());
    }
}
