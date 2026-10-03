// SPDX-License-Identifier: GPL-3.0-or-later
//! Проверки имён хоста, общие для входов, маршрутизатора и выходов.

/// Имя «заканчивается числом» (WHATWG URL, «ends in a number»): последняя
/// метка — десятичное или `0x`-шестнадцатеричное число.
///
/// Настоящие домены так не заканчиваются (TLD не бывает числовым), а
/// системный резолвер (`getaddrinfo`) читает такое имя как IPv4 в старой
/// записи: `2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1` → 127.0.0.1. Как
/// домен оно обходило бы правила по IP. Вызывать **после** строгого
/// разбора IP: для `127.0.0.1` функция тоже вернёт `true`.
pub fn looks_like_legacy_ipv4(host: &str) -> bool {
    let last = host.trim_end_matches('.').rsplit('.').next().unwrap_or("");
    if last.is_empty() {
        return false;
    }
    match last.strip_prefix("0x").or_else(|| last.strip_prefix("0X")) {
        // «0x» без цифр — тоже число (0), как в WHATWG.
        Some(h) => h.bytes().all(|b| b.is_ascii_hexdigit()),
        None => last.bytes().all(|b| b.is_ascii_digit()),
    }
}

/// Имя, которое нельзя отдавать дальше как домен: числовая форма IPv4 не в
/// строгой записи (см. [`looks_like_legacy_ipv4`]). Строгий IP (`1.2.3.4`)
/// — не отвергается: его разбирают как адрес.
pub fn is_disguised_ip(host: &str) -> bool {
    host.trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_err()
        && looks_like_legacy_ipv4(host)
}

#[cfg(test)]
mod tests {
    use super::{is_disguised_ip, looks_like_legacy_ipv4 as numeric};

    #[test]
    fn legacy_numeric_forms() {
        for h in [
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "127.1",
            "0xc0.0xa8.1.1",
            "3232235777",
            "1.2.3.4.",
            "0X7F.1",
            "0x",
        ] {
            assert!(numeric(h), "{h}");
            assert!(is_disguised_ip(h), "{h}");
        }
    }

    #[test]
    fn real_names_and_strict_ips_pass() {
        for h in [
            "example.com",
            "a1.example",
            "1.example",
            "localhost",
            "xn--80ak6aa92e.com",
            "0xg.example",
            "example.com.",
            "",
        ] {
            assert!(!numeric(h), "{h}");
        }
        for h in [
            "127.0.0.1",
            "192.168.1.1",
            "::1",
            "[2001:db8::1]",
            "example.com",
        ] {
            assert!(!is_disguised_ip(h), "{h}");
        }
    }
}
