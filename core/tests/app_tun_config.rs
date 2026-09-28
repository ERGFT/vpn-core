// SPDX-License-Identifier: GPL-3.0-or-later
//! Фаза 3: проверки настроек входа `tun` (без создания интерфейса —
//! для этого нужны права root; сам TUN проверяет scripts/tun_netns.sh).

use reality_core::app::config::Config;
use reality_core::app::App;

/// Настройки: входы, правила route и раздел dns — фрагментами JSON.
fn cfg(inbounds: &str, rules: &str, dns: &str) -> String {
    format!(
        r#"{{"inbounds": [{inbounds}], "outbounds": [{{"type": "direct", "tag": "direct"}}],
            "route": {{"rules": [{rules}]}}{dns}}}"#
    )
}
const DNS: &str =
    r#", "dns": {"servers": [{"tag": "up", "address": "1.1.1.1", "detour": "direct"}]}"#;
const HIJACK: &str = r#"{"protocol": "dns", "action": "hijack-dns"}"#;
const TUN: &str = r#"{"type": "tun", "tag": "tun"}"#;

fn err(json: &str) -> String {
    let cfg = match Config::parse(json) {
        Ok(c) => c,
        Err(e) => return e.to_string(),
    };
    match App::build(&cfg) {
        Ok(_) => panic!("должна быть ошибка:\n{json}"),
        Err(e) => e.to_string(),
    }
}

fn ok(json: &str) {
    App::build(&Config::parse(json).unwrap()).unwrap_or_else(|e| panic!("{e}\n{json}"));
}

#[test]
fn tun_config_checks() {
    // Перехват DNS (правило hijack-dns) — нужен раздел dns.
    let e = err(&cfg(TUN, HIJACK, ""));
    assert!(e.contains("раздела dns"), "{e}");
    // Без правила hijack-dns DNS не перехватывается — раздел не нужен.
    ok(&cfg(TUN, "", ""));
    ok(&cfg(TUN, HIJACK, DNS));

    // Системный DNS вместе с TUN — петля.
    let e = err(&cfg(
        TUN,
        HIJACK,
        r#", "dns": {"servers": [{"type": "local", "tag": "l"}]}"#,
    ));
    assert!(e.contains("петля"), "{e}");

    let e = err(&cfg(
        r#"{"type": "tun", "listen": "127.0.0.1", "listen_port": 1}"#,
        "",
        DNS,
    ));
    assert!(e.contains("listen"), "{e}");
    let e = err(&cfg(
        r#"{"type": "socks", "listen": "127.0.0.1", "listen_port": 1, "auto_route": true}"#,
        "",
        "",
    ));
    assert!(e.contains("auto_route"), "{e}");
    let e = err(&cfg(r#"{"type": "socks"}"#, "", ""));
    assert!(e.contains("listen"), "{e}");
    let e = err(&cfg(
        &format!(r#"{TUN}, {{"type": "tun", "tag": "t2"}}"#),
        "",
        DNS,
    ));
    assert!(e.contains("только один"), "{e}");
    let e = err(&cfg(
        r#"{"type": "tun", "address": ["10.0.0.1/31"]}"#,
        "",
        DNS,
    ));
    assert!(e.contains("/30"), "{e}");
    let e = err(&cfg(r#"{"type": "tun", "mtu": 500}"#, "", DNS));
    assert!(e.contains("mtu"), "{e}");
    ok(&cfg(
        r#"{"type": "tun", "interface_name": "t0", "address": ["10.7.0.1/24", "fdfe::1/126"], "mtu": 9000,
            "route_exclude_address": ["192.168.0.0/16", "fd00::/8"], "stack": "system"}"#,
        r#"{"action": "sniff"}"#,
        DNS,
    ));
    // Старые поля sing-box (до 1.10) тоже понимаются.
    ok(&cfg(
        r#"{"type": "tun", "inet4_address": "10.7.0.1/24", "inet4_route_exclude_address": ["192.168.0.0/16"],
            "sniff": true}"#,
        "",
        DNS,
    ));
    // Возможности, которых нет, — ошибка, а не молчаливый пропуск.
    let e = err(&cfg(
        r#"{"type": "tun", "include_package": ["com.example"]}"#,
        "",
        DNS,
    ));
    assert!(e.contains("include_package"), "{e}");
}
