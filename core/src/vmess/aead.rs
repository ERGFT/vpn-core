// SPDX-License-Identifier: GPL-3.0-or-later
//! Primitives used by modern VMess AEAD framing.
//!
//! The nested HMAC construction and authentication ID layout follow Xray's
//! VMess AEAD implementation. These low-level helpers do not constitute a
//! complete or interoperably verified VMess client and are not yet stable API.

use aes::cipher::{Block, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use md5::Md5;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const KDF_SALT: &[u8] = b"VMess AEAD KDF";
const AUTH_ID_ENCRYPTION_KEY: &str = "AES Auth ID Encryption";
const HEADER_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const HEADER_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const HEADER_PAYLOAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const RESPONSE_HEADER_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
const RESPONSE_HEADER_LENGTH_NONCE: &[u8] = b"AEAD Resp Header Len IV";
const RESPONSE_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const RESPONSE_HEADER_PAYLOAD_NONCE: &[u8] = b"AEAD Resp Header IV";
const UUID_CMD_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// Per-connection keys carried in the encrypted VMess request header.
///
/// Debug is intentionally not implemented so traffic keys cannot be logged
/// accidentally.
pub struct SessionKeys {
    pub request_body_key: [u8; 16],
    pub request_body_iv: [u8; 16],
    pub response_body_key: [u8; 16],
    pub response_body_iv: [u8; 16],
    pub response_header: u8,
}

/// Derive response keys from the random request keys using Xray's VMess rule.
pub fn session_keys(
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_header: u8,
) -> SessionKeys {
    let key_hash: [u8; 32] = Sha256::digest(request_body_key).into();
    let iv_hash: [u8; 32] = Sha256::digest(request_body_iv).into();
    let mut response_body_key = [0u8; 16];
    let mut response_body_iv = [0u8; 16];
    response_body_key.copy_from_slice(&key_hash[..16]);
    response_body_iv.copy_from_slice(&iv_hash[..16]);
    SessionKeys {
        request_body_key,
        request_body_iv,
        response_body_key,
        response_body_iv,
        response_header,
    }
}

/// Derive the VMess key using Xray's nested HMAC-SHA256 construction.
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut layers = Vec::with_capacity(path.len() + 1);
    layers.push(KDF_SALT);
    layers.extend_from_slice(path);
    nested_hmac(key, &layers)
}

fn nested_hmac(data: &[u8], layers: &[&[u8]]) -> [u8; 32] {
    let Some((key, parent)) = layers.split_last() else {
        return Sha256::digest(data).into();
    };

    let mut normalized_key = [0u8; 64];
    if key.len() > normalized_key.len() {
        normalized_key[..32].copy_from_slice(&nested_hmac(key, parent));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    let mut outer = [0u8; 64];
    for (index, byte) in normalized_key.iter().copied().enumerate() {
        inner.push(byte ^ 0x36);
        outer[index] = byte ^ 0x5c;
    }
    inner.extend_from_slice(data);
    let inner_hash = nested_hmac(&inner, parent);
    let mut outer_input = Vec::with_capacity(96);
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_hash);
    nested_hmac(&outer_input, parent)
}

/// Return the fixed VMess command key derived from a user UUID.
pub fn command_key(id: &Uuid) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(id.as_bytes());
    digest.update(UUID_CMD_KEY_SUFFIX);
    digest.finalize().into()
}

/// Build a modern VMess authentication ID from a timestamp and 4 random bytes.
pub fn create_auth_id(command_key: &[u8; 16], timestamp: u64, random: [u8; 4]) -> [u8; 16] {
    let encryption_key = kdf(command_key, &[AUTH_ID_ENCRYPTION_KEY.as_bytes()]);
    let mut key = [0u8; 16];
    key.copy_from_slice(&encryption_key[..16]);
    let cipher = Aes128::new(&key.into());

    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&timestamp.to_be_bytes());
    plain[8..12].copy_from_slice(&random);
    let checksum = crc32_ieee(&plain[..12]);
    plain[12..].copy_from_slice(&checksum.to_be_bytes());

    let mut block = Block::<Aes128>::from(plain);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Seal the modern AEAD request header using Xray's two-layer AES-128-GCM format.
///
/// Randomness is supplied by the caller so callers can use the operating
/// system CSPRNG and tests can exercise stable wire vectors.
pub fn seal_header(
    command_key: &[u8; 16],
    auth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    plaintext: &[u8],
) -> crate::error::Result<Vec<u8>> {
    if plaintext.len() > u16::MAX as usize {
        return Err(crate::error::Error::Protocol(
            "VMess request header exceeds the 65535-byte wire limit".into(),
        ));
    }
    let derive = |key_label: &[u8], nonce_label: &[u8]| {
        let path = [key_label, auth_id, connection_nonce];
        let key = kdf(command_key, &path);
        let nonce_path = [nonce_label, auth_id, connection_nonce];
        let nonce = kdf(command_key, &nonce_path);
        (key, nonce)
    };

    let (length_key, length_nonce) = derive(HEADER_LENGTH_KEY, HEADER_LENGTH_NONCE);
    let mut length_key_128 = [0u8; 16];
    length_key_128.copy_from_slice(&length_key[..16]);
    let length_cipher = Aes128Gcm::new(&length_key_128.into());
    let length_bytes = (plaintext.len() as u16).to_be_bytes();
    let mut length_nonce_96 = [0u8; 12];
    length_nonce_96.copy_from_slice(&length_nonce[..12]);
    let encrypted_length = length_cipher
        .encrypt(
            &Nonce::from(length_nonce_96),
            Payload {
                msg: &length_bytes,
                aad: auth_id,
            },
        )
        .map_err(|_| crate::error::Error::Protocol("failed to seal VMess header length".into()))?;

    let (payload_key, payload_nonce) = derive(HEADER_PAYLOAD_KEY, HEADER_PAYLOAD_NONCE);
    let mut payload_key_128 = [0u8; 16];
    payload_key_128.copy_from_slice(&payload_key[..16]);
    let payload_cipher = Aes128Gcm::new(&payload_key_128.into());
    let mut payload_nonce_96 = [0u8; 12];
    payload_nonce_96.copy_from_slice(&payload_nonce[..12]);
    let encrypted_payload = payload_cipher
        .encrypt(
            &Nonce::from(payload_nonce_96),
            Payload {
                msg: plaintext,
                aad: auth_id,
            },
        )
        .map_err(|_| crate::error::Error::Protocol("failed to seal VMess request header".into()))?;

    let mut output = Vec::with_capacity(42 + encrypted_payload.len());
    output.extend_from_slice(auth_id);
    output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(connection_nonce);
    output.extend_from_slice(&encrypted_payload);
    Ok(output)
}

/// Open a VMess AEAD request header payload.
///
/// `encrypted` begins immediately after the 16-byte AuthID and contains the
/// encrypted 2-byte length, 8-byte connection nonce, then encrypted payload.
/// The returned byte count lets the caller continue reading the stream after
/// the header without consuming any body bytes.
pub fn open_header(
    command_key: &[u8; 16],
    auth_id: &[u8; 16],
    encrypted: &[u8],
) -> crate::error::Result<(Vec<u8>, usize)> {
    if encrypted.len() < 26 {
        return Err(crate::error::Error::Protocol(
            "truncated VMess AEAD request header prefix".into(),
        ));
    }
    let encrypted_length = &encrypted[..18];
    let connection_nonce: &[u8; 8] = encrypted[18..26]
        .try_into()
        .map_err(|_| crate::error::Error::Protocol("invalid VMess connection nonce".into()))?;

    let derive = |key_label: &[u8], nonce_label: &[u8]| {
        let key = kdf(command_key, &[key_label, auth_id, connection_nonce]);
        let nonce = kdf(command_key, &[nonce_label, auth_id, connection_nonce]);
        (key, nonce)
    };
    let (length_key, length_nonce) = derive(HEADER_LENGTH_KEY, HEADER_LENGTH_NONCE);
    let length_cipher = Aes128Gcm::new_from_slice(&length_key[..16])
        .map_err(|_| crate::error::Error::Protocol("invalid VMess header length key".into()))?;
    let length_nonce: [u8; 12] = length_nonce[..12]
        .try_into()
        .map_err(|_| crate::error::Error::Protocol("invalid VMess header length nonce".into()))?;
    let length_plaintext = length_cipher
        .decrypt(
            &Nonce::from(length_nonce),
            Payload {
                msg: encrypted_length,
                aad: auth_id,
            },
        )
        .map_err(|_| {
            crate::error::Error::Protocol(
                "VMess request header length authentication failed".into(),
            )
        })?;
    let length_bytes: [u8; 2] = length_plaintext
        .as_slice()
        .try_into()
        .map_err(|_| crate::error::Error::Protocol("invalid VMess request header length".into()))?;
    let payload_len = usize::from(u16::from_be_bytes(length_bytes));
    let consumed = 26usize + payload_len + 16;
    if encrypted.len() < consumed {
        return Err(crate::error::Error::Protocol(
            "truncated VMess AEAD request header payload".into(),
        ));
    }

    let (payload_key, payload_nonce) = derive(HEADER_PAYLOAD_KEY, HEADER_PAYLOAD_NONCE);
    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key[..16])
        .map_err(|_| crate::error::Error::Protocol("invalid VMess header payload key".into()))?;
    let payload_nonce: [u8; 12] = payload_nonce[..12]
        .try_into()
        .map_err(|_| crate::error::Error::Protocol("invalid VMess header payload nonce".into()))?;
    let payload = payload_cipher
        .decrypt(
            &Nonce::from(payload_nonce),
            Payload {
                msg: &encrypted[26..consumed],
                aad: auth_id,
            },
        )
        .map_err(|_| {
            crate::error::Error::Protocol("VMess request header authentication failed".into())
        })?;
    Ok((payload, consumed))
}

/// Open the two-layer AEAD response header from a VMess server.
///
/// The returned byte count identifies exactly how many stream bytes belong to
/// the response header, leaving the encrypted response body untouched.
pub fn open_response_header(
    keys: &SessionKeys,
    encrypted: &[u8],
) -> crate::error::Result<(Vec<u8>, usize)> {
    let consumed = response_header_wire_len(keys, encrypted)?;
    if encrypted.len() < consumed {
        return Err(crate::error::Error::Protocol(
            "truncated VMess response header payload".into(),
        ));
    }
    let payload_key = kdf(&keys.response_body_key, &[RESPONSE_HEADER_PAYLOAD_KEY]);
    let payload_nonce = kdf(&keys.response_body_iv, &[RESPONSE_HEADER_PAYLOAD_NONCE]);
    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key[..16])
        .map_err(|_| crate::error::Error::Protocol("invalid VMess response payload key".into()))?;
    let payload_nonce: [u8; 12] = payload_nonce[..12].try_into().map_err(|_| {
        crate::error::Error::Protocol("invalid VMess response payload nonce".into())
    })?;
    let payload = payload_cipher
        .decrypt(
            &Nonce::from(payload_nonce),
            Payload {
                msg: &encrypted[18..consumed],
                aad: &[],
            },
        )
        .map_err(|_| {
            crate::error::Error::Protocol("VMess response header authentication failed".into())
        })?;
    Ok((payload, consumed))
}

/// Authenticate the encrypted response-header length and return its total
/// wire size. Callers can read exactly this many bytes from a stream without
/// consuming the following encrypted body.
pub fn response_header_wire_len(
    keys: &SessionKeys,
    encrypted_length: &[u8],
) -> crate::error::Result<usize> {
    if encrypted_length.len() < 18 {
        return Err(crate::error::Error::Protocol(
            "truncated VMess response header length".into(),
        ));
    }
    let length_key = kdf(&keys.response_body_key, &[RESPONSE_HEADER_LENGTH_KEY]);
    let length_nonce = kdf(&keys.response_body_iv, &[RESPONSE_HEADER_LENGTH_NONCE]);
    let length_cipher = Aes128Gcm::new_from_slice(&length_key[..16])
        .map_err(|_| crate::error::Error::Protocol("invalid VMess response length key".into()))?;
    let length_nonce: [u8; 12] = length_nonce[..12]
        .try_into()
        .map_err(|_| crate::error::Error::Protocol("invalid VMess response length nonce".into()))?;
    let length_plaintext = length_cipher
        .decrypt(
            &Nonce::from(length_nonce),
            Payload {
                msg: &encrypted_length[..18],
                aad: &[],
            },
        )
        .map_err(|_| {
            crate::error::Error::Protocol(
                "VMess response header length authentication failed".into(),
            )
        })?;
    let length_bytes: [u8; 2] = length_plaintext.as_slice().try_into().map_err(|_| {
        crate::error::Error::Protocol("invalid VMess response header length".into())
    })?;
    let payload_len = usize::from(u16::from_be_bytes(length_bytes));
    // Xray response headers contain a 2-byte fixed prefix and an optional
    // command frame whose one-byte length is itself bounded to 255 bytes.
    if payload_len > 259 {
        return Err(crate::error::Error::Protocol(
            "VMess response header exceeds its protocol limit".into(),
        ));
    }
    Ok(18usize + payload_len + 16)
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::KeyInit;

    #[test]
    fn kdf_without_path_matches_xray_sha256_hmac() {
        let actual = kdf(b"key", &[]);
        assert_eq!(
            hex::encode(actual),
            "385e28ac08671660f62ac976f5e64a31827aea172eff77cb2b046c52de9c08b0"
        );
    }

    #[test]
    fn nested_kdf_auth_id_key_regression_vector() {
        assert_eq!(
            hex::encode(kdf(&[7; 16], &[AUTH_ID_ENCRYPTION_KEY.as_bytes()])),
            "a9f74429d7f2d57b3988116ad1b94a27cca21edfc47edf082a6e295fc9b1a00f"
        );
    }

    #[test]
    fn command_key_uses_uuid_bytes_and_xray_suffix() {
        let id = Uuid::parse_str("a8098c1a-f86e-11da-bd1a-00112444be1e").unwrap();
        assert_eq!(
            hex::encode(command_key(&id)),
            "f1a8f3fd133f194af35b684e680a42f4"
        );
    }

    #[test]
    fn auth_id_is_deterministic_for_fixed_timestamp_and_randomness() {
        let key = [7u8; 16];
        let first = create_auth_id(&key, 1_700_000_000, [1, 2, 3, 4]);
        assert_eq!(hex::encode(first), "58b73300c6843c787f516cf4583f3ae1");
        assert_eq!(first, create_auth_id(&key, 1_700_000_000, [1, 2, 3, 4]));
        assert_ne!(first, create_auth_id(&key, 1_700_000_000, [1, 2, 3, 5]));
    }

    #[test]
    fn sealed_header_round_trips_and_authenticates_each_layer() {
        let key = [9u8; 16];
        let auth_id = [3u8; 16];
        let connection_nonce = [4u8; 8];
        let plaintext = b"request header fixture";
        let sealed = seal_header(&key, &auth_id, &connection_nonce, plaintext).unwrap();

        assert_eq!(&sealed[..16], &auth_id);
        assert_eq!(&sealed[34..42], &connection_nonce);

        let length_key = kdf(&key, &[HEADER_LENGTH_KEY, &auth_id, &connection_nonce]);
        let length_nonce = kdf(&key, &[HEADER_LENGTH_NONCE, &auth_id, &connection_nonce]);
        let length_cipher = Aes128Gcm::new_from_slice(&length_key[..16]).unwrap();
        let length = length_cipher
            .decrypt(
                &Nonce::from(<[u8; 12]>::try_from(&length_nonce[..12]).unwrap()),
                Payload {
                    msg: &sealed[16..34],
                    aad: &auth_id,
                },
            )
            .unwrap();
        assert_eq!(length, (plaintext.len() as u16).to_be_bytes());

        let payload_key = kdf(&key, &[HEADER_PAYLOAD_KEY, &auth_id, &connection_nonce]);
        let payload_nonce = kdf(&key, &[HEADER_PAYLOAD_NONCE, &auth_id, &connection_nonce]);
        let payload_cipher = Aes128Gcm::new_from_slice(&payload_key[..16]).unwrap();
        let payload = payload_cipher
            .decrypt(
                &Nonce::from(<[u8; 12]>::try_from(&payload_nonce[..12]).unwrap()),
                Payload {
                    msg: &sealed[42..],
                    aad: &auth_id,
                },
            )
            .unwrap();
        assert_eq!(payload, plaintext);

        let mut altered = sealed;
        altered[42] ^= 1;
        assert!(payload_cipher
            .decrypt(
                &Nonce::from(<[u8; 12]>::try_from(&payload_nonce[..12]).unwrap()),
                Payload {
                    msg: &altered[42..],
                    aad: &auth_id,
                },
            )
            .is_err());
    }

    #[test]
    fn opens_sealed_request_header_and_preserves_following_body() {
        let key = [9u8; 16];
        let auth_id = [3u8; 16];
        let connection_nonce = [4u8; 8];
        let plaintext = b"request header fixture";
        let mut wire = seal_header(&key, &auth_id, &connection_nonce, plaintext).unwrap();
        wire.extend_from_slice(b"encrypted body follows");

        let (opened, consumed) = open_header(&key, &auth_id, &wire[16..]).unwrap();
        assert_eq!(opened, plaintext);
        assert_eq!(consumed, wire.len() - 16 - b"encrypted body follows".len());
    }

    #[test]
    fn request_header_open_rejects_truncation_and_tampering() {
        let key = [9u8; 16];
        let auth_id = [3u8; 16];
        let sealed = seal_header(&key, &auth_id, &[4u8; 8], b"header").unwrap();

        assert!(open_header(&key, &auth_id, &sealed[16..25]).is_err());
        assert!(open_header(&key, &auth_id, &sealed[16..sealed.len() - 1]).is_err());
        let mut altered_length = sealed[16..].to_vec();
        altered_length[0] ^= 1;
        assert!(open_header(&key, &auth_id, &altered_length).is_err());
        let mut altered_payload = sealed[16..].to_vec();
        altered_payload[26] ^= 1;
        assert!(open_header(&key, &auth_id, &altered_payload).is_err());
    }

    fn seal_response_fixture(keys: &SessionKeys, plaintext: &[u8]) -> Vec<u8> {
        let length_key = kdf(&keys.response_body_key, &[RESPONSE_HEADER_LENGTH_KEY]);
        let length_nonce = kdf(&keys.response_body_iv, &[RESPONSE_HEADER_LENGTH_NONCE]);
        let length_cipher = Aes128Gcm::new_from_slice(&length_key[..16]).unwrap();
        let encrypted_length = length_cipher
            .encrypt(
                &Nonce::from(<[u8; 12]>::try_from(&length_nonce[..12]).unwrap()),
                Payload {
                    msg: &(plaintext.len() as u16).to_be_bytes(),
                    aad: &[],
                },
            )
            .unwrap();
        let payload_key = kdf(&keys.response_body_key, &[RESPONSE_HEADER_PAYLOAD_KEY]);
        let payload_nonce = kdf(&keys.response_body_iv, &[RESPONSE_HEADER_PAYLOAD_NONCE]);
        let payload_cipher = Aes128Gcm::new_from_slice(&payload_key[..16]).unwrap();
        let encrypted_payload = payload_cipher
            .encrypt(
                &Nonce::from(<[u8; 12]>::try_from(&payload_nonce[..12]).unwrap()),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .unwrap();
        let mut wire = encrypted_length;
        wire.extend_from_slice(&encrypted_payload);
        wire
    }

    #[test]
    fn response_header_keys_and_aead_decode_match_xray_layout() {
        let keys = session_keys([1; 16], [2; 16], 0x5a);
        assert_eq!(keys.response_header, 0x5a);
        let plaintext = [0x5a, 0x00];
        let mut wire = seal_response_fixture(&keys, &plaintext);
        assert_eq!(
            response_header_wire_len(&keys, &wire[..18]).unwrap(),
            wire.len()
        );
        wire.extend_from_slice(b"response body follows");

        let (opened, consumed) = open_response_header(&keys, &wire).unwrap();
        assert_eq!(opened, plaintext);
        assert_eq!(consumed, wire.len() - b"response body follows".len());
    }

    #[test]
    fn response_header_decoder_rejects_truncation_and_bad_tags() {
        let keys = session_keys([1; 16], [2; 16], 0x5a);
        let mut wire = seal_response_fixture(&keys, &[0x5a, 0]);
        assert!(open_response_header(&keys, &wire[..17]).is_err());
        assert!(open_response_header(&keys, &wire[..wire.len() - 1]).is_err());
        wire[0] ^= 1;
        assert!(open_response_header(&keys, &wire).is_err());
    }

    #[test]
    fn crc32_matches_ieee_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }
}
