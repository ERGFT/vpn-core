// SPDX-License-Identifier: GPL-3.0-or-later
//! Primitives used by modern VMess AEAD framing.
//!
//! The nested HMAC construction and authentication ID layout follow Xray's
//! VMess AEAD implementation. These low-level helpers do not constitute a
//! complete or interoperably verified VMess client and are not yet stable API.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::cipher::{Block, BlockEncrypt};
use aes_gcm::aes::Aes128;
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
const UUID_CMD_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

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

    let mut block = Block::<Aes128>::clone_from_slice(&plain);
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
    let encrypted_length = length_cipher
        .encrypt(
            Nonce::from_slice(&length_nonce[..12]),
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
    let encrypted_payload = payload_cipher
        .encrypt(
            Nonce::from_slice(&payload_nonce[..12]),
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
                Nonce::from_slice(&length_nonce[..12]),
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
                Nonce::from_slice(&payload_nonce[..12]),
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
                Nonce::from_slice(&payload_nonce[..12]),
                Payload {
                    msg: &altered[42..],
                    aad: &auth_id,
                },
            )
            .is_err());
    }

    #[test]
    fn crc32_matches_ieee_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }
}
