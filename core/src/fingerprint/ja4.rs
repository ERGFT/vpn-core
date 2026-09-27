// SPDX-License-Identifier: GPL-3.0-or-later
//! JA4 (FoxIO, 2023) — преемник JA3 с более грубой, но более стабильной
//! схемой (сортированные списки вместо порядка, явный TLS-версии/ALPN в
//! самой строке). Спецификация и рабочий пример:
//! <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
//!
//! ⚠️ ALPN-часть (первый/последний символ первого ALPN-протокола)
//! реализована по общему правилу "нечитаемый ASCII → '9'"; отдельно от
//! рабочего примера (`h2`) это правило независимо не перепроверено —
//! если понадобится байт-в-байт точное совпадение с эталонной
//! реализацией FoxIO на экзотичных ALPN-строках, стоит свериться с их
//! кодом напрямую.

use sha2::{Digest, Sha256};

use super::client_hello::{is_grease, ClientHelloInfo};

pub fn ja4_string(info: &ClientHelloInfo) -> String {
    let proto = 't'; // TLS через TCP; QUIC/DTLS этот клиент не использует
    let version = version_code(info);
    let sni_flag = if info.sni.is_some() { 'd' } else { 'i' };

    let ciphers: Vec<u16> = info
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let ext_no_grease: Vec<u16> = info
        .extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();

    let cipher_count = ciphers.len().min(99);
    let ext_count = ext_no_grease.len().min(99);
    let alpn = alpn_chars(&info.alpn);

    let part_b = cipher_hash(&ciphers);
    let part_c = extension_hash(&ext_no_grease, &info.signature_algorithms);

    format!("{proto}{version}{sni_flag}{cipher_count:02}{ext_count:02}{alpn}_{part_b}_{part_c}")
}

fn version_code(info: &ClientHelloInfo) -> &'static str {
    let from_ext = info
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max();
    let v = from_ext.unwrap_or(info.legacy_version);
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn alpn_chars(alpn: &[String]) -> String {
    let Some(proto) = alpn.first() else {
        return "00".to_string();
    };
    let bytes = proto.as_bytes();
    if bytes.is_empty() {
        return "00".to_string();
    }
    let norm = |b: u8| -> char {
        if b.is_ascii_alphanumeric() {
            b as char
        } else {
            '9'
        }
    };
    format!("{}{}", norm(bytes[0]), norm(bytes[bytes.len() - 1]))
}

fn cipher_hash(ciphers: &[u16]) -> String {
    let mut sorted = ciphers.to_vec();
    sorted.sort_unstable();
    let joined = sorted
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    sha256_hex12_or_zero(&joined)
}

fn extension_hash(extensions: &[u16], signature_algorithms: &[u16]) -> String {
    const EXT_SNI: u16 = 0x0000;
    const EXT_ALPN: u16 = 0x0010;

    let mut sorted: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|v| *v != EXT_SNI && *v != EXT_ALPN)
        .collect();
    sorted.sort_unstable();
    let ext_list = sorted
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    // Signature algorithms — в исходном порядке клиента, НЕ сортируются.
    let sig_list = signature_algorithms
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let combined = format!("{ext_list}_{sig_list}");
    sha256_hex12_or_zero(&combined)
}

fn sha256_hex12_or_zero(input: &str) -> String {
    if input.is_empty() || input == "_" {
        return "000000000000".to_string();
    }
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Рабочий пример из технического описания JA4 (FoxIO): 15 cipher
    /// suites и 16 расширений после фильтрации GREASE дают ровно этот
    /// результат. Проверено независимо (вручную через sha256sum) перед
    /// тем, как попасть в этот тест — см. PLAN.md, Этап 3.
    #[test]
    fn matches_published_foxio_example() {
        let ciphers = vec![
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
            0xc02f, 0xc030, 0xcca8, 0xcca9,
        ];
        let extensions = vec![
            0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
            0x0033, 0x4469, 0xff01,
        ];
        let sig_algs = vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];

        assert_eq!(cipher_hash(&ciphers), "8daaf6152771");
        assert_eq!(extension_hash(&extensions, &sig_algs), "e5627efa2ab1");
    }

    #[test]
    fn empty_lists_use_zero_fallback() {
        assert_eq!(cipher_hash(&[]), "000000000000");
    }

    #[test]
    fn alpn_chars_h2() {
        assert_eq!(alpn_chars(&["h2".to_string()]), "h2");
        assert_eq!(alpn_chars(&[]), "00");
    }

    #[test]
    fn full_string_shape_is_well_formed() {
        let info = ClientHelloInfo {
            legacy_version: 0x0303,
            supported_versions: vec![0x0304],
            cipher_suites: vec![0x1301, 0x0a0a],
            extensions: vec![0x0000, 0x0010, 0x000a],
            elliptic_curves: vec![0x001d],
            ec_point_formats: vec![0],
            alpn: vec!["h2".to_string()],
            signature_algorithms: vec![0x0403],
            sni: Some("example.com".to_string()),
            session_id: Vec::new(),
            ..Default::default()
        };
        let s = ja4_string(&info);
        assert!(s.starts_with("t13d"), "получено: {s}");
        assert!(s.contains('_'), "должен содержать разделители частей: {s}");
    }
}
