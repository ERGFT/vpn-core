// SPDX-License-Identifier: GPL-3.0-or-later
//! Hysteria 2 packet obfuscation primitives.

use std::io;

pub(crate) const SALAMANDER_OVERHEAD: usize = 8;
const MASK_LEN: usize = 32;

/// Add a random eight-byte salt and XOR the payload with BLAKE2b-256(key || salt).
pub(crate) fn salamander_wrap(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALAMANDER_OVERHEAD];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut salt);
    salamander_wrap_with_salt(key, &salt, payload)
}

fn salamander_wrap_with_salt(
    key: &[u8],
    salt: &[u8; SALAMANDER_OVERHEAD],
    payload: &[u8],
) -> Vec<u8> {
    let mask = salamander_mask(key, salt);
    let mut frame = Vec::with_capacity(SALAMANDER_OVERHEAD + payload.len());
    frame.extend_from_slice(salt);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| *byte ^ mask[index % MASK_LEN]),
    );
    frame
}

/// Remove the salt and XOR mask in place. Returns the resulting packet length.
pub(crate) fn salamander_unwrap(key: &[u8], datagram: &mut [u8]) -> io::Result<usize> {
    if datagram.len() < SALAMANDER_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Salamander packet is shorter than its salt",
        ));
    }
    let mut salt = [0u8; SALAMANDER_OVERHEAD];
    salt.copy_from_slice(&datagram[..SALAMANDER_OVERHEAD]);
    let payload_len = datagram.len() - SALAMANDER_OVERHEAD;
    let mask = salamander_mask(key, &salt);
    for (index, byte) in datagram[SALAMANDER_OVERHEAD..].iter_mut().enumerate() {
        *byte ^= mask[index % MASK_LEN];
    }
    datagram.copy_within(SALAMANDER_OVERHEAD.., 0);
    Ok(payload_len)
}

fn salamander_mask(key: &[u8], salt: &[u8; SALAMANDER_OVERHEAD]) -> [u8; MASK_LEN] {
    let mut state = blake2b_simd::Params::new().hash_length(MASK_LEN).to_state();
    state.update(key);
    state.update(salt);
    let digest = state.finalize();
    let mut mask = [0u8; MASK_LEN];
    mask.copy_from_slice(digest.as_bytes());
    mask
}

#[cfg(test)]
mod tests {
    use super::{
        salamander_unwrap, salamander_wrap, salamander_wrap_with_salt, SALAMANDER_OVERHEAD,
    };

    #[test]
    fn matches_the_protocol_blake2b_256_packet_vector() {
        let frame = salamander_wrap_with_salt(b"test-key", &[0, 1, 2, 3, 4, 5, 6, 7], b"hello");
        assert_eq!(frame, hex::decode("0001020304050607a993af144f").unwrap());
    }

    #[test]
    fn wrap_and_unwrap_round_trip_and_widen_by_salt_length() {
        let key = b"shared obfuscation password";
        let payload = b"a QUIC packet";
        let mut frame = salamander_wrap(key, payload);
        assert_eq!(frame.len(), payload.len() + SALAMANDER_OVERHEAD);
        let len = salamander_unwrap(key, &mut frame).unwrap();
        assert_eq!(&frame[..len], payload);
    }

    #[test]
    fn rejects_datagrams_shorter_than_the_salt() {
        let mut frame = [0u8; SALAMANDER_OVERHEAD - 1];
        assert!(salamander_unwrap(b"key", &mut frame).is_err());
    }
}
