// SPDX-License-Identifier: GPL-3.0-or-later
//! Plaintext VMess response-header payload framing.
//!
//! AEAD opening is handled by [`super::aead::open_response_header`]. This
//! module validates and decodes the resulting payload without interpreting
//! optional command data or enabling VMess network connections.

use crate::error::{Error, Result};

/// Opaque command frame carried by a VMess response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseCommand {
    /// Protocol command identifier. Unknown identifiers are retained so a
    /// caller can reject or handle them explicitly.
    pub id: u8,
    /// Command-specific bytes, whose meaning depends on `id`.
    pub data: Vec<u8>,
}

/// Decoded plaintext VMess response-header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    /// Authentication marker copied from the corresponding request header.
    pub response_header: u8,
    /// Protocol option bits. They are preserved without enabling deprecated
    /// connection-reuse behavior.
    pub options: u8,
    pub command: Option<ResponseCommand>,
}

/// Decode one plaintext VMess response-header payload.
///
/// The payload starts with a four-byte response marker, option, command ID,
/// and command-data length. A non-zero command ID is followed by that many
/// command-specific bytes. Returns the decoded fields and exact bytes used,
/// leaving any following bytes untouched.
pub fn decode_response_header(
    input: &[u8],
    expected_response_header: u8,
) -> Result<(ResponseHeader, usize)> {
    if input.len() < 4 {
        return Err(protocol_error("truncated VMess response header"));
    }
    if input[0] != expected_response_header {
        return Err(protocol_error("unexpected VMess response header marker"));
    }

    let response_header = input[0];
    let options = input[1];
    let command_id = input[2];
    let command_len = usize::from(input[3]);
    let (command, consumed) = if command_id == 0 {
        (None, 4)
    } else {
        let consumed = 4 + command_len;
        if input.len() < consumed {
            return Err(protocol_error("truncated VMess response command data"));
        }
        (
            Some(ResponseCommand {
                id: command_id,
                data: input[4..consumed].to_vec(),
            }),
            consumed,
        )
    };

    Ok((
        ResponseHeader {
            response_header,
            options,
            command,
        },
        consumed,
    ))
}

fn protocol_error(message: &str) -> Error {
    Error::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_response_header_without_command_and_preserves_following_bytes() {
        let input = [0x5a, 0x01, 0x00, 0x00, 0xde, 0xad];
        let (header, consumed) = decode_response_header(&input, 0x5a).unwrap();

        assert_eq!(header.response_header, 0x5a);
        assert_eq!(header.options, 0x01);
        assert_eq!(header.command, None);
        assert_eq!(consumed, 4);
        assert_eq!(&input[consumed..], &[0xde, 0xad]);
    }

    #[test]
    fn decodes_opaque_response_command() {
        let input = [0xa7, 0x00, 0x01, 0x03, 0x10, 0x20, 0x30, 0xff];
        let (header, consumed) = decode_response_header(&input, 0xa7).unwrap();

        assert_eq!(
            header.command,
            Some(ResponseCommand {
                id: 1,
                data: vec![0x10, 0x20, 0x30],
            })
        );
        assert_eq!(consumed, 7);
        assert_eq!(input[consumed], 0xff);
    }

    #[test]
    fn rejects_invalid_marker_and_truncated_fields() {
        assert!(decode_response_header(&[0, 0, 0, 0], 1).is_err());
        assert!(decode_response_header(&[1, 0, 0], 1).is_err());
        assert!(decode_response_header(&[1, 0, 1], 1).is_err());
        assert!(decode_response_header(&[1, 0, 1, 2, 0xaa], 1).is_err());
    }

    #[test]
    fn accepts_maximum_sized_command_payload() {
        let mut input = vec![0x33, 0, 0x7f, u8::MAX];
        input.extend([0xa5; u8::MAX as usize]);
        let (header, consumed) = decode_response_header(&input, 0x33).unwrap();

        assert_eq!(header.command.unwrap().data.len(), u8::MAX as usize);
        assert_eq!(consumed, input.len());
    }
}
