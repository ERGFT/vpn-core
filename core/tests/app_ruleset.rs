// SPDX-License-Identifier: GPL-3.0-or-later
//! Наборы правил sing-box (`[[route.rule_set]]`) в маршрутизации и DNS;
//! сверка с настоящим sing-box — если задан `SING_BOX_BIN`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use reality_core::app::config::Config;
use reality_core::app::ruleset::{self, RuleSet, RuleSetConfig};
use reality_core::app::App;

fn tmp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rc-ruleset-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Путь как строка JSON (на Windows — с экранированными «\\»).
fn q(p: &Path) -> String {
    serde_json::to_string(&p.display().to_string()).unwrap()
}

fn cfg(dir: &Path, rule: &str) -> String {
    format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}, {{ "type": "block", "tag": "block" }}],
  "route": {{
    "rule_set": [
      {{ "type": "local", "tag": "local", "path": "local.json" }},
      {{ "type": "local", "tag": "names", "path": {names} }}
    ],
    "rules": [{rule}],
    "final": "direct"
  }}
}}"#,
        names = q(&dir.join("names.json"))
    )
}

async fn socks_connect(app: SocketAddr, to: SocketAddr) -> u8 {
    let mut s = TcpStream::connect(app).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let SocketAddr::V4(v4) = to else { panic!() };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    rep[1]
}

#[tokio::test]
async fn rule_set_blocks_by_address_and_relative_path_works() {
    let dir = tmp_dir("route");
    std::fs::write(
        dir.join("local.json"),
        r#"{"version":3,"rules":[{"ip_cidr":["127.0.0.0/8"]},{"domain_suffix":["example.invalid"]}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("names.json"),
        r#"{"version":3,"rules":[{"domain":"a.invalid"}]}"#,
    )
    .unwrap();
    let path = dir.join("client.json");
    std::fs::write(
        &path,
        cfg(&dir, r#"{"rule_set": ["local"], "outbound": "block"}"#),
    )
    .unwrap();
    // Config::load: относительный путь набора — от папки файла настроек.
    let c = Config::load(&path).expect("настройки");
    assert_eq!(c.route.rule_set[0].path, dir.join("local.json"));
    let app = App::build(&c).unwrap().start().await.unwrap();

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let to = l.local_addr().unwrap();
    tokio::spawn(async move { while l.accept().await.is_ok() {} });
    assert_eq!(
        socks_connect(app.listen_addrs[0], to).await,
        2,
        "127.0.0.1 — в наборе"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rule_set_errors_are_clear() {
    let dir = tmp_dir("errors");
    std::fs::write(
        dir.join("names.json"),
        r#"{"version":3,"rules":[{"domain":"a.invalid"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("ips.json"),
        r#"{"version":3,"rules":[{"ip_cidr":"10.0.0.0/8"}]}"#,
    )
    .unwrap();
    std::fs::write(dir.join("empty.json"), r#"{"version":3,"rules":[]}"#).unwrap();
    std::fs::write(
        dir.join("port.json"),
        r#"{"version":3,"rules":[{"domain":"a.invalid","port":443}]}"#,
    )
    .unwrap();
    // sets — элементы route.rule_set; tail — rules и прочее в route, dns.
    let with = |sets: &str, rules: &str, dns: &str| {
        let json = format!(
            r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": 0 }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "rule_set": [{sets}], "rules": [{rules}] }}{dns}
}}"#
        );
        match App::build(&Config::parse(&json).expect("разбор")) {
            Ok(_) => panic!("сборка должна была отказать:\n{json}"),
            Err(e) => e.to_string(),
        }
    };
    let set = |tag: &str, file: &str| {
        format!(
            r#"{{"type": "local", "tag": "{tag}", "path": {}}}"#,
            q(&dir.join(file))
        )
    };
    let rule = r#"{"rule_set": ["x"], "outbound": "direct"}"#;

    let e = with("", rule, "");
    assert!(e.contains("нет такого набора"), "{e}");
    let e = with(
        &(set("x", "names.json") + ", " + &set("x", "ips.json")),
        rule,
        "",
    );
    assert!(e.contains("повторяется"), "{e}");
    let e = with(&set("x", "empty.json"), rule, "");
    assert!(e.contains("пуст"), "{e}");
    let e = with(&set("x", "port.json"), rule, "");
    assert!(e.contains("port") && e.contains("не поддерживается"), "{e}");
    let e = with(&set("x", "missing.json"), rule, "");
    assert!(e.contains("не удалось прочитать"), "{e}");
    let e = with(
        &set("x", "ips.json"),
        "",
        r#", "dns": {"servers": [{"type": "local", "tag": "l"}], "rules": [{"rule_set": ["x"], "server": "l"}]}"#,
    );
    assert!(e.contains("нет доменов"), "{e}");
    // Неиспользуемый битый набор не мешает (читаются только нужные).
    std::fs::write(dir.join("bad.srs"), b"SRS\x01garbage").unwrap();
    let json = format!(
        r#"{{"inbounds": [{{"type": "socks", "listen": "127.0.0.1", "listen_port": 0}}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}],
            "route": {{"rule_set": [{}]}}}}"#,
        set("unused", "bad.srs")
    );
    App::build(&Config::parse(&json).unwrap()).expect("неиспользуемый набор");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── сверка с sing-box ──

fn normalized(s: &RuleSet) -> Vec<String> {
    let mut v = Vec::new();
    v.extend(s.domain.iter().map(|d| format!("domain {d}")));
    v.extend(s.domain_suffix.iter().map(|d| format!("suffix {d}")));
    v.extend(s.domain_keyword.iter().map(|d| format!("keyword {d}")));
    v.extend(s.domain_regex.iter().map(|d| format!("regex {d}")));
    v.extend(
        s.ip_cidr
            .iter()
            .map(|n| format!("ip {}/{}", n.addr(), n.prefix())),
    );
    v.sort();
    v.dedup();
    v
}

fn load(tag: &str, path: &Path) -> RuleSet {
    ruleset::load(&RuleSetConfig {
        tag: tag.into(),
        path: path.to_path_buf(),
        format: None,
    })
    .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn matches_sing_box_compile_and_decompile() {
    let Ok(bin) = std::env::var("SING_BOX_BIN") else {
        eprintln!("SING_BOX_BIN не задан — сверка с sing-box пропущена");
        return;
    };
    let dir = tmp_dir("singbox");
    let mut domains: Vec<String> = (0..3000).map(|i| format!("host{i}.example.com")).collect();
    domains.extend([
        "пример.рф".into(),
        "a.b".into(),
        "x".into(),
        "both.example".into(),
    ]);
    let source = serde_json::json!({
        "version": 3,
        "rules": [
            {
                "domain": domains,
                "domain_suffix": ["root.example", ".sub.example", ".both.example", "рф", "c"],
                "domain_keyword": ["ads", "трекер"],
                "domain_regex": ["^ad[0-9]+\\.example$"]
            },
            {
                "ip_cidr": ["10.0.0.0/8", "10.1.0.0/16", "192.168.1.7", "1.2.3.0/25",
                            "1.2.3.128/25", "2001:db8::/32", "::1/128", "0.0.0.0/32"]
            }
        ]
    });
    for version in [1, 2, 3] {
        let mut src = source.clone();
        src["version"] = version.into();
        let json = dir.join(format!("v{version}.json"));
        let srs = dir.join(format!("v{version}.srs"));
        let back = dir.join(format!("v{version}-back.json"));
        std::fs::write(&json, serde_json::to_vec(&src).unwrap()).unwrap();
        let ok = Command::new(&bin)
            .args(["rule-set", "compile", "--output"])
            .arg(&srs)
            .arg(&json)
            .status()
            .unwrap()
            .success();
        assert!(ok, "sing-box rule-set compile");
        let ok = Command::new(&bin)
            .args(["rule-set", "decompile", "--output"])
            .arg(&back)
            .arg(&srs)
            .status()
            .unwrap()
            .success();
        assert!(ok, "sing-box rule-set decompile");
        let ours = normalized(&load("srs", &srs));
        let theirs = normalized(&load("back", &back));
        assert_eq!(
            ours, theirs,
            "версия {version}: наш разбор .srs ≠ decompile sing-box"
        );
        assert!(ours.contains(&"domain пример.рф".to_string()));
        assert!(ours.contains(&"suffix both.example".to_string()));
        assert!(ours.contains(&"suffix .sub.example".to_string()));
        assert!(ours.contains(&"ip 1.2.3.0/24".to_string()));
    }
    // Настоящие наборы (SagerNet/sing-geosite, sing-geoip), если скачаны.
    if let Ok(samples) = std::env::var("SING_BOX_SRS_SAMPLES") {
        for entry in std::fs::read_dir(samples).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().is_none_or(|e| e != "srs") {
                continue;
            }
            let back = dir.join("sample-back.json");
            let ok = Command::new(&bin)
                .args(["rule-set", "decompile", "--output"])
                .arg(&back)
                .arg(&p)
                .status()
                .unwrap()
                .success();
            assert!(ok);
            let ours = normalized(&load("srs", &p));
            assert!(!ours.is_empty());
            assert_eq!(ours, normalized(&load("back", &back)), "{}", p.display());
            eprintln!("{}: {} записей совпали", p.display(), ours.len());
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
