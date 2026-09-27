// SPDX-License-Identifier: GPL-3.0-or-later
//! JA3 (Salesforce, 2017): старейший и до сих пор самый распространённый
//! TLS-клиентский фингерпринт. Формула проверена в тесте против
//! опубликованного примера — см. `tests::matches_published_example`
//! (строка и md5 из практического разбора JA3:
//! <https://medium.com/cu-cyber/impersonating-ja3-fingerprints-b9f555880e42>).

use super::client_hello::{is_grease, ClientHelloInfo};

/// Строка JA3 до хеширования: версия, cipher suites, extensions,
/// elliptic curves, точки — все в десятичном виде, поля через запятую,
/// элементы внутри поля через дефис, в исходном порядке клиента.
///
/// GREASE-значения исключаются из всех четырёх списков — так делает
/// подавляющее большинство реализаций JA3 начиная с 2019 (иначе
/// фингерпринт Chrome/Firefox был бы разным на каждом соединении из-за
/// случайного GREASE).
pub fn ja3_string(info: &ClientHelloInfo) -> String {
    let version = info.legacy_version;
    let ciphers = join_decimal_no_grease(&info.cipher_suites);
    let extensions = join_decimal_no_grease(&info.extensions);
    let curves = join_decimal_no_grease(&info.elliptic_curves);
    let points = info
        .ec_point_formats
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join("-");

    format!("{version},{ciphers},{extensions},{curves},{points}")
}

pub fn ja3_hash(info: &ClientHelloInfo) -> String {
    use md5::{Digest, Md5};
    let s = ja3_string(info);
    let digest = Md5::digest(s.as_bytes());
    hex::encode(digest)
}

fn join_decimal_no_grease(values: &[u16]) -> String {
    values
        .iter()
        .filter(|v| !is_grease(**v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Не парсинг, а прямая проверка формулы: те же поля, что в разборе
    /// примера по ссылке в модульном комментарии, дают ту же строку и
    /// тот же md5 — независимо перепроверено (см. PLAN.md, Этап 3).
    #[test]
    fn matches_published_example() {
        let info = ClientHelloInfo {
            legacy_version: 771,
            cipher_suites: vec![
                4865, 4866, 4867, 49196, 49195, 49188, 49187, 49162, 49161, 52393, 49200, 49199,
                49192, 49191, 49172, 49171, 52392, 157, 156, 61, 60, 53, 47, 49160, 49170, 10,
            ],
            extensions: vec![65281, 0, 23, 13, 5, 18, 16, 11, 51, 45, 43, 10, 21],
            elliptic_curves: vec![29, 23, 24, 25],
            ec_point_formats: vec![0],
            ..Default::default()
        };

        assert_eq!(
            ja3_string(&info),
            "771,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24-25,0"
        );
        assert_eq!(ja3_hash(&info), "6fa3244afc6bb6f9fad207b6b52af26b");
    }

    #[test]
    fn strips_grease_from_all_lists() {
        let info = ClientHelloInfo {
            legacy_version: 771,
            cipher_suites: vec![0x0a0a, 0x1301],
            extensions: vec![0x1a1a, 0x0000],
            elliptic_curves: vec![0x2a2a, 0x001d],
            ec_point_formats: vec![0],
            ..Default::default()
        };
        assert_eq!(ja3_string(&info), "771,4865,0,29,0");
    }
}
