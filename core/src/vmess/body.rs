// SPDX-License-Identifier: GPL-3.0-or-later
//! Authenticated VMess body chunk framing.
//!
//! This codec implements the Xray/V2Ray AEAD chunk profile for AES-128-GCM
//! and ChaCha20-Poly1305. It is a framing primitive, not a VMess stream or
//! packet session; transport semantics and interop vectors remain separate.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Nonce,
};
use chacha20poly1305::{aead::Aead as ChaChaAead, ChaCha20Poly1305, Nonce as ChaChaNonce};
use sha2::Digest;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

const TAG_LEN: usize = 16;
/// Bound encrypted body chunks to the protocol maximum of 2^14 bytes.
pub const MAX_CHUNK_PLAINTEXT: usize = (1 << 14) - TAG_LEN;
const MAX_CHUNK_COUNT: u32 = u16::MAX as u32 + 1;

/// Cipher selected by a validated modern VMess configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BodyCipher {
    Aes128Gcm,
    Chacha20Poly1305,
}

/// Stateful codec for one direction of a VMess body stream.
///
/// Create independent instances for request and response directions using
/// their respective derived key and IV. Authenticated lengths use the
/// protocol's `auth_len` KDF input and have an independent nonce counter. For
/// response chunks, the input is the original request body key, as in Xray
/// and V2Ray.
/// Secret key material is cleared when the codec is dropped.
pub struct BodyChunkCodec {
    cipher: BodyCipher,
    key: Zeroizing<[u8; 16]>,
    authenticated_length_key: Option<Zeroizing<[u8; 16]>>,
    iv: [u8; 16],
    next_chunk: u32,
}

impl BodyChunkCodec {
    pub fn new(
        cipher: BodyCipher,
        key: [u8; 16],
        iv: [u8; 16],
        authenticated_length_key: Option<[u8; 16]>,
    ) -> Self {
        Self {
            cipher,
            key: Zeroizing::new(key),
            authenticated_length_key: authenticated_length_key.map(Zeroizing::new),
            iv,
            next_chunk: 0,
        }
    }

    fn authenticated_length(&self) -> bool {
        self.authenticated_length_key.is_some()
    }

    /// Seal one plaintext chunk, returning its two-byte size prefix and AEAD
    /// ciphertext. An empty plaintext produces the protocol's empty-chunk
    /// terminator. Callers split stream data into bounded chunks beforehand.
    pub fn seal_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_CHUNK_PLAINTEXT {
            return Err(protocol_error("VMess plaintext chunk exceeds the limit"));
        }
        let index = self.take_chunk_index()?;
        let nonce = chunk_nonce(&self.iv, index);
        let ciphertext = self.seal_payload(plaintext, &nonce)?;
        let size = u16::try_from(if self.authenticated_length() {
            plaintext.len()
        } else {
            ciphertext.len()
        })
        .map_err(|_| protocol_error("VMess encrypted chunk length exceeds u16"))?;

        let mut frame = Vec::with_capacity(
            2 + ciphertext.len() + usize::from(self.authenticated_length()) * TAG_LEN,
        );
        let size_bytes = size.to_be_bytes();
        if self.authenticated_length() {
            let length_nonce = chunk_nonce(&self.iv, index);
            frame.extend_from_slice(&self.seal_length(&size_bytes, &length_nonce)?);
        } else {
            frame.extend_from_slice(&size_bytes);
        }
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Open exactly one chunk from the start of `input`, returning its
    /// plaintext and consumed wire length. Following bytes are left untouched.
    pub fn open_chunk(&mut self, input: &[u8]) -> Result<(Vec<u8>, usize)> {
        let index = self.next_chunk;
        if index >= MAX_CHUNK_COUNT {
            return Err(protocol_error("VMess chunk nonce counter exhausted"));
        }
        let consumed = self.chunk_wire_len(input)?;
        if input.len() < consumed {
            return Err(protocol_error("truncated VMess encrypted chunk"));
        }

        let nonce = chunk_nonce(&self.iv, index);
        let prefix_len = self.length_prefix_len();
        let plaintext = self.open_payload(&input[prefix_len..consumed], &nonce)?;
        if plaintext.len() > MAX_CHUNK_PLAINTEXT {
            return Err(protocol_error("VMess plaintext chunk exceeds the limit"));
        }
        self.next_chunk += 1;
        Ok((plaintext, consumed))
    }

    /// Return the encoded prefix size for one chunk in this framing profile.
    pub fn length_prefix_len(&self) -> usize {
        if self.authenticated_length() {
            2 + TAG_LEN
        } else {
            2
        }
    }

    /// Authenticate and decode a chunk prefix without consuming its payload.
    /// The returned length includes both the prefix and the encrypted chunk.
    pub fn chunk_wire_len(&self, prefix: &[u8]) -> Result<usize> {
        let prefix_len = self.length_prefix_len();
        if prefix.len() < prefix_len {
            return Err(protocol_error("truncated VMess chunk length"));
        }
        if self.next_chunk >= MAX_CHUNK_COUNT {
            return Err(protocol_error("VMess chunk nonce counter exhausted"));
        }
        let payload_len = if self.authenticated_length() {
            let nonce = chunk_nonce(&self.iv, self.next_chunk);
            let clear = self.open_length(&prefix[..prefix_len], &nonce)?;
            let size: [u8; 2] = clear
                .as_slice()
                .try_into()
                .map_err(|_| protocol_error("invalid authenticated VMess chunk length"))?;
            usize::from(u16::from_be_bytes(size)) + TAG_LEN
        } else {
            usize::from(u16::from_be_bytes([prefix[0], prefix[1]]))
        };
        if !(TAG_LEN..=MAX_CHUNK_PLAINTEXT + TAG_LEN).contains(&payload_len) {
            return Err(protocol_error(
                "VMess encrypted chunk length is out of bounds",
            ));
        }
        prefix_len
            .checked_add(payload_len)
            .ok_or_else(|| protocol_error("VMess chunk wire length overflow"))
    }

    fn take_chunk_index(&mut self) -> Result<u32> {
        if self.next_chunk >= MAX_CHUNK_COUNT {
            return Err(protocol_error("VMess chunk nonce counter exhausted"));
        }
        let index = self.next_chunk;
        self.next_chunk += 1;
        Ok(index)
    }

    fn seal_payload(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        match self.cipher {
            BodyCipher::Aes128Gcm => {
                <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(self.key.as_ref())
                    .map_err(|_| protocol_error("invalid VMess AES-128-GCM key"))?
                    .encrypt(
                        &Nonce::from(*nonce),
                        Payload {
                            msg: plaintext,
                            aad: &[],
                        },
                    )
                    .map_err(|_| protocol_error("failed to seal VMess body chunk"))
            }
            BodyCipher::Chacha20Poly1305 => {
                let key = chacha_key(&self.key);
                <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new_from_slice(&key[..])
                    .map_err(|_| protocol_error("invalid VMess ChaCha20-Poly1305 key"))?
                    .encrypt(&ChaChaNonce::from(*nonce), plaintext)
                    .map_err(|_| protocol_error("failed to seal VMess body chunk"))
            }
        }
    }

    fn open_payload(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        match self.cipher {
            BodyCipher::Aes128Gcm => {
                <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(self.key.as_ref())
                    .map_err(|_| protocol_error("invalid VMess AES-128-GCM key"))?
                    .decrypt(
                        &Nonce::from(*nonce),
                        Payload {
                            msg: ciphertext,
                            aad: &[],
                        },
                    )
                    .map_err(|_| protocol_error("VMess body chunk authentication failed"))
            }
            BodyCipher::Chacha20Poly1305 => {
                let key = chacha_key(&self.key);
                <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new_from_slice(&key[..])
                    .map_err(|_| protocol_error("invalid VMess ChaCha20-Poly1305 key"))?
                    .decrypt(&ChaChaNonce::from(*nonce), ciphertext)
                    .map_err(|_| protocol_error("VMess body chunk authentication failed"))
            }
        }
    }

    fn seal_length(&self, size: &[u8; 2], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let length_key = self
            .authenticated_length_key
            .as_ref()
            .ok_or_else(|| protocol_error("authenticated VMess length is disabled"))?;
        let key = Zeroizing::new(crate::vmess::aead::kdf(length_key.as_ref(), &[b"auth_len"]));
        let mut key16 = Zeroizing::new([0; 16]);
        key16.copy_from_slice(&key[..16]);
        let length_cipher = Self::new(self.cipher, *key16, self.iv, None);
        length_cipher.seal_payload(size, nonce)
    }

    fn open_length(&self, encoded: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let length_key = self
            .authenticated_length_key
            .as_ref()
            .ok_or_else(|| protocol_error("authenticated VMess length is disabled"))?;
        let key = Zeroizing::new(crate::vmess::aead::kdf(length_key.as_ref(), &[b"auth_len"]));
        let mut key16 = Zeroizing::new([0; 16]);
        key16.copy_from_slice(&key[..16]);
        let length_cipher = Self::new(self.cipher, *key16, self.iv, None);
        length_cipher.open_payload(encoded, nonce)
    }
}

fn chunk_nonce(iv: &[u8; 16], index: u32) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce.copy_from_slice(&iv[..12]);
    nonce[..2].copy_from_slice(&(index as u16).to_be_bytes());
    nonce
}

fn chacha_key(key: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    use md5::Md5;

    let mut first = Md5::digest(key);
    let mut second = Md5::digest(first);
    let mut expanded = Zeroizing::new([0; 32]);
    expanded[..16].copy_from_slice(&first);
    expanded[16..].copy_from_slice(&second);
    first.zeroize();
    second.zeroize();
    expanded
}

fn protocol_error(message: &str) -> Error {
    Error::Protocol(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec(cipher: BodyCipher, authenticated_length: bool) -> BodyChunkCodec {
        BodyChunkCodec::new(
            cipher,
            [0x31; 16],
            [0x72; 16],
            authenticated_length.then_some([0x31; 16]),
        )
    }

    #[test]
    fn aes_gcm_chunks_round_trip_with_plain_and_authenticated_lengths() {
        for authenticated_length in [false, true] {
            let mut sender = codec(BodyCipher::Aes128Gcm, authenticated_length);
            let mut receiver = codec(BodyCipher::Aes128Gcm, authenticated_length);
            let frame = sender.seal_chunk(b"VMess authenticated payload").unwrap();
            let (opened, consumed) = receiver.open_chunk(&frame).unwrap();
            assert_eq!(opened, b"VMess authenticated payload");
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn chacha20_poly1305_chunks_round_trip_with_plain_and_authenticated_lengths() {
        for authenticated_length in [false, true] {
            let mut sender = codec(BodyCipher::Chacha20Poly1305, authenticated_length);
            let mut receiver = codec(BodyCipher::Chacha20Poly1305, authenticated_length);
            let frame = sender.seal_chunk(b"VMess authenticated payload").unwrap();
            let (opened, consumed) = receiver.open_chunk(&frame).unwrap();
            assert_eq!(opened, b"VMess authenticated payload");
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn response_authenticated_length_uses_request_body_key() {
        let request_key = [0x31; 16];
        let response_key = [0x55; 16];
        let iv = [0x72; 16];
        let mut sender =
            BodyChunkCodec::new(BodyCipher::Aes128Gcm, response_key, iv, Some(request_key));
        let mut receiver =
            BodyChunkCodec::new(BodyCipher::Aes128Gcm, response_key, iv, Some(request_key));
        let frame = sender.seal_chunk(b"response").unwrap();
        assert_eq!(receiver.open_chunk(&frame).unwrap().0, b"response");
    }

    #[test]
    fn maximum_protocol_chunk_round_trips_with_both_length_formats() {
        for authenticated_length in [false, true] {
            let mut sender = codec(BodyCipher::Aes128Gcm, authenticated_length);
            let mut receiver = codec(BodyCipher::Aes128Gcm, authenticated_length);
            let payload = vec![0x5a; MAX_CHUNK_PLAINTEXT];
            let frame = sender.seal_chunk(&payload).unwrap();
            let (opened, consumed) = receiver.open_chunk(&frame).unwrap();
            assert_eq!(opened, payload);
            assert_eq!(consumed, frame.len());
        }
    }
    #[test]
    fn chunk_nonce_advances_and_empty_chunk_is_preserved() {
        let mut sender = codec(BodyCipher::Aes128Gcm, false);
        let mut receiver = codec(BodyCipher::Aes128Gcm, false);
        for payload in [&b"first"[..], &b"second"[..], &b""[..]] {
            let frame = sender.seal_chunk(payload).unwrap();
            let (opened, consumed) = receiver.open_chunk(&frame).unwrap();
            assert_eq!(opened, payload);
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn chunk_codec_rejects_tampering_truncation_and_oversize() {
        let mut sender = codec(BodyCipher::Aes128Gcm, true);
        let mut receiver = codec(BodyCipher::Aes128Gcm, true);
        let frame = sender.seal_chunk(b"authenticated").unwrap();
        assert!(receiver.open_chunk(&frame[..3]).is_err());
        let mut tampered = frame.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(receiver.open_chunk(&tampered).is_err());

        let mut receiver = codec(BodyCipher::Aes128Gcm, true);
        let mut tampered_length = frame.clone();
        tampered_length[0] ^= 1;
        assert!(receiver.open_chunk(&tampered_length).is_err());

        let mut sender = codec(BodyCipher::Aes128Gcm, false);
        assert!(sender
            .seal_chunk(&vec![0; MAX_CHUNK_PLAINTEXT + 1])
            .is_err());
    }

    #[test]
    fn decoder_leaves_following_frame_bytes_untouched() {
        let mut sender = codec(BodyCipher::Chacha20Poly1305, false);
        let first = sender.seal_chunk(b"first").unwrap();
        let second = sender.seal_chunk(b"second").unwrap();
        let mut wire = first.clone();
        wire.extend_from_slice(&second);

        let mut receiver = codec(BodyCipher::Chacha20Poly1305, false);
        let (opened_first, consumed) = receiver.open_chunk(&wire).unwrap();
        assert_eq!(opened_first, b"first");
        let (opened_second, second_consumed) = receiver.open_chunk(&wire[consumed..]).unwrap();
        assert_eq!(opened_second, b"second");
        assert_eq!(consumed + second_consumed, wire.len());
    }

    #[test]
    fn chunk_wire_len_authenticates_prefix_without_advancing_counter() {
        for cipher in [BodyCipher::Aes128Gcm, BodyCipher::Chacha20Poly1305] {
            for authenticated_length in [false, true] {
                let mut sender = codec(cipher, authenticated_length);
                let frame = sender.seal_chunk(b"length prefix").unwrap();
                let receiver = codec(cipher, authenticated_length);
                let prefix_len = receiver.length_prefix_len();

                assert_eq!(
                    receiver.chunk_wire_len(&frame[..prefix_len]).unwrap(),
                    frame.len()
                );
                assert_eq!(receiver.next_chunk, 0);
            }
        }
    }

    #[test]
    fn nonce_counter_exhaustion_fails_closed() {
        let mut sender = codec(BodyCipher::Aes128Gcm, false);
        sender.next_chunk = MAX_CHUNK_COUNT;
        assert!(sender.seal_chunk(b"no nonce reuse").is_err());

        let mut receiver = codec(BodyCipher::Aes128Gcm, false);
        receiver.next_chunk = MAX_CHUNK_COUNT;
        assert!(receiver.open_chunk(&[0, TAG_LEN as u8]).is_err());
    }
}
