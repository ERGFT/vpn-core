// SPDX-License-Identifier: GPL-3.0-or-later
//! HTTP-заголовки браузера для HTTP-транспортов (ws, httpupgrade, xhttp)
//! — того же, чей ClientHello изображается (`fp=`, Фаза 7): Chrome,
//! Firefox или Safari. TLS-отпечаток Firefox с User-Agent Chrome —
//! сочетание, которого у настоящих браузеров не бывает.
//!
//! Chrome — Перенос `common/utils/browser.go` из Xray-core
//! (`TryDefaultHeadersWith(header, "ws"/"fetch")`): без них запрос
//! Upgrade без `User-Agent` и `Sec-Fetch-*` заметно отличается от
//! браузерного — особенно за CDN, где такие запросы видны в логах.
//!
//! Версия Chrome вычисляется от даты так же, как у Xray: 144 на
//! 2026-01-13, +1 каждые 35 дней, со случайным «отставанием» до ~105 дней
//! (браузеры обновляются не мгновенно). Значение выбирается один раз на
//! процесс.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;

use crate::fingerprint::Browser;

/// Для чего запрос: `Ws` — Upgrade (ws, httpupgrade), `Fetch` — обычный
/// XHR/fetch (xhttp), `Nav` — открытие страницы (переход по адресу).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Ws,
    Fetch,
    Nav,
}

struct Chrome {
    ua: String,
    ch_ua: String,
}

const GREASE_NA: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const GREASE_VER: [&str; 3] = ["8", "99", "24"];

fn chrome() -> &'static Chrome {
    static C: OnceLock<Chrome> = OnceLock::new();
    C.get_or_init(|| {
        let days_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / 86400)
            .unwrap_or(0) as i64;
        // 2026-01-13 в днях от эпохи.
        let days_start: i64 = 20466;
        let r: f64 = rand::thread_rng().gen();
        let lag = (r * r * 105.0).floor() as i64;
        let diff = (days_now - days_start - 35 - lag).max(0);
        let v = 144 + diff / 35;
        let brand = format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            GREASE_NA[(v as usize) % GREASE_NA.len()],
            GREASE_NA[(v as usize + 1) % GREASE_NA.len()],
            GREASE_VER[(v as usize) % GREASE_VER.len()]
        );
        let mut parts = [
            brand,
            format!("\"Chromium\";v=\"{v}\""),
            format!("\"Google Chrome\";v=\"{v}\""),
        ];
        // Порядок брендов у Chrome зависит от версии — как в Xray.
        let perms: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        let p = perms[(v as usize) % perms.len()];
        let src = parts.clone();
        for (i, &dst) in p.iter().enumerate() {
            parts[dst] = src[i].clone();
        }
        Chrome {
            ua: format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
            ),
            ch_ua: parts.join(", "),
        }
    })
}

/// Версия Firefox — от даты, как у Chrome: 148 на 2026-02-24, +1 каждые
/// 28 дней, со случайным отставанием до ~8 недель. Один раз на процесс.
fn firefox_version() -> i64 {
    static V: OnceLock<i64> = OnceLock::new();
    *V.get_or_init(|| {
        let days_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / 86400)
            .unwrap_or(0) as i64;
        let days_start: i64 = 20508; // 2026-02-24
        let r: f64 = rand::thread_rng().gen();
        let lag = (r * r * 56.0).floor() as i64;
        148 + (days_now - days_start - lag).max(0) / 28
    })
}

/// Заголовки браузера `b` для данного вида запроса.
pub fn headers(b: Browser, variant: Variant) -> Vec<(&'static str, String)> {
    match b {
        Browser::Chrome => chrome_headers(variant),
        Browser::Firefox => {
            let v = firefox_version();
            let mut h = vec![
                (
                    "User-Agent",
                    format!(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"
                    ),
                ),
                ("Accept-Language", "en-US,en;q=0.5".into()),
            ];
            match variant {
                Variant::Nav => {
                    h.push((
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
                    ));
                    h.push(("Upgrade-Insecure-Requests", "1".into()));
                    h.push(("Sec-Fetch-Dest", "document".into()));
                    h.push(("Sec-Fetch-Mode", "navigate".into()));
                    h.push(("Sec-Fetch-Site", "none".into()));
                    h.push(("Sec-Fetch-User", "?1".into()));
                    h.push(("Priority", "u=0, i".into()));
                }
                Variant::Ws | Variant::Fetch => {
                    h.push(("Accept", "*/*".into()));
                    h.push(("Sec-Fetch-Dest", "empty".into()));
                    h.push((
                        "Sec-Fetch-Mode",
                        if variant == Variant::Ws {
                            "websocket"
                        } else {
                            "cors"
                        }
                        .into(),
                    ));
                    h.push(("Sec-Fetch-Site", "same-origin".into()));
                    if variant == Variant::Fetch {
                        h.push(("Priority", "u=4".into()));
                    }
                    h.push(("Pragma", "no-cache".into()));
                    h.push(("Cache-Control", "no-cache".into()));
                }
            }
            h
        }
        Browser::Safari => {
            let mut h = vec![
                (
                    "User-Agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
                     (KHTML, like Gecko) Version/26.3 Safari/605.1.15"
                        .into(),
                ),
                ("Accept-Language", "en-US,en;q=0.9".into()),
            ];
            match variant {
                Variant::Nav => {
                    h.push((
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
                    ));
                    h.push(("Sec-Fetch-Site", "none".into()));
                    h.push(("Sec-Fetch-Mode", "navigate".into()));
                    h.push(("Sec-Fetch-Dest", "document".into()));
                    h.push(("Priority", "u=0, i".into()));
                }
                Variant::Ws | Variant::Fetch => {
                    h.push(("Accept", "*/*".into()));
                    h.push(("Sec-Fetch-Site", "same-origin".into()));
                    h.push((
                        "Sec-Fetch-Mode",
                        if variant == Variant::Ws {
                            "websocket"
                        } else {
                            "cors"
                        }
                        .into(),
                    ));
                    h.push(("Sec-Fetch-Dest", "empty".into()));
                    if variant == Variant::Fetch {
                        h.push(("Priority", "u=3, i".into()));
                    }
                    h.push(("Pragma", "no-cache".into()));
                    h.push(("Cache-Control", "no-cache".into()));
                }
            }
            h
        }
    }
}

/// Заголовки Chrome для данного вида запроса, в виде пар (имя, значение).
/// `Host`, `Connection`, `Upgrade` сюда не входят — их ставит транспорт.
pub fn chrome_headers(variant: Variant) -> Vec<(&'static str, String)> {
    let c = chrome();
    let mut h = vec![
        ("User-Agent", c.ua.clone()),
        ("Sec-CH-UA", c.ch_ua.clone()),
        ("Sec-CH-UA-Mobile", "?0".into()),
        ("Sec-CH-UA-Platform", "\"Windows\"".into()),
        ("DNT", "1".into()),
        ("Accept-Language", "en-US,en;q=0.9".into()),
    ];
    match variant {
        Variant::Nav => {
            h.push(("Cache-Control", "max-age=0".into()));
            h.push(("Upgrade-Insecure-Requests", "1".into()));
            h.push((
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,\
                 image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
                    .into(),
            ));
            h.push(("Sec-Fetch-Site", "none".into()));
            h.push(("Sec-Fetch-Mode", "navigate".into()));
            h.push(("Sec-Fetch-User", "?1".into()));
            h.push(("Sec-Fetch-Dest", "document".into()));
            h.push(("Priority", "u=0, i".into()));
            return h;
        }
        Variant::Ws => {
            h.push(("Sec-Fetch-Mode", "websocket".into()));
            h.push(("Sec-Fetch-Dest", "empty".into()));
            h.push(("Sec-Fetch-Site", "same-origin".into()));
        }
        Variant::Fetch => {
            h.push(("Sec-Fetch-Mode", "cors".into()));
            h.push(("Sec-Fetch-Dest", "empty".into()));
            h.push(("Sec-Fetch-Site", "same-origin".into()));
            h.push(("Priority", "u=1, i".into()));
        }
    }
    h.push(("Cache-Control", "no-cache".into()));
    h.push(("Pragma", "no-cache".into()));
    h.push(("Accept", "*/*".into()));
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_and_safari_headers() {
        let f = headers(Browser::Firefox, Variant::Fetch);
        let ua = &f[0].1;
        assert!(ua.contains("Firefox/") && ua.contains("rv:"), "{ua}");
        assert!(
            !f.iter().any(|(k, _)| k.starts_with("Sec-CH")),
            "у Firefox нет Client Hints"
        );
        let s = headers(Browser::Safari, Variant::Ws);
        assert!(s[0].1.contains("Version/26") && s[0].1.contains("Safari/605"));
        assert!(s
            .iter()
            .any(|(k, v)| *k == "Sec-Fetch-Mode" && v == "websocket"));
        assert_eq!(
            headers(Browser::Chrome, Variant::Nav),
            chrome_headers(Variant::Nav)
        );
    }

    #[test]
    fn chrome_version_is_plausible_and_consistent() {
        let h = chrome_headers(Variant::Ws);
        let ua = &h.iter().find(|(k, _)| *k == "User-Agent").unwrap().1;
        let v: u32 = ua
            .split("Chrome/")
            .nth(1)
            .and_then(|s| s.split('.').next())
            .and_then(|s| s.parse().ok())
            .unwrap();
        assert!((144..300).contains(&v), "{ua}");
        let ch = &h.iter().find(|(k, _)| *k == "Sec-CH-UA").unwrap().1;
        assert!(ch.contains(&format!("\"Google Chrome\";v=\"{v}\"")), "{ch}");
        assert!(ch.contains("Brand\""), "{ch}");
    }
}
