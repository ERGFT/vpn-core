//! HTTP-заголовки «как у Chrome» для HTTP-транспортов (ws, httpupgrade,
//! xhttp). Перенос `common/utils/browser.go` из Xray-core
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
