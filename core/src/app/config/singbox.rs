// SPDX-License-Identifier: GPL-3.0-or-later
//! Настройки в формате sing-box (JSON) → [`Config`].
//!
//! Поддерживается то, что умеет это ядро; всё остальное — ошибка с путём
//! до ключа. Формат — современный (1.11+: действия правил `sniff`,
//! `hijack-dns`, `reject`, DNS-серверы с `type`), плюс частые старые поля
//! (`inet4_address`, `sniff` у входа, `address` у DNS-сервера).
//!
//! Расширения этого ядра (в sing-box их нет): выход `fallback`,
//! `subscriptions` (в корне и у групп), `link`/`link_file` у vless и
//! trojan, `mux` (Mux.Cool), `fragment`/`noises`, `allow_insecure`,
//! `allow_ip`/`max_conns` у входов, `route.presets`,
//! `route.geosite_file`/`geoip_file`, `route.domain_strategy`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde_json::Value;

use super::link::LinkBuilder;
use super::obj::{duration, Obj};
use super::{
    Config, DomainStrategy, InboundConfig, InboundKind, OutboundConfig, OutboundKind, PortSpec,
    RouteConfig, RuleConfig,
};
use crate::app::access::IpNet;
use crate::app::api::ApiConfig;
use crate::app::dns::{DnsConfig, DnsRuleConfig, DnsServerConfig, FakeIpConfig, Strategy};
use crate::app::ruleset::RuleSetConfig;
use crate::app::Network;
use crate::error::{Error, Result};

/// Скрытые выходы для действий правил `reject` и `hijack-dns`.
const REJECT: &str = "__reject";
const HIJACK_DNS: &str = "__hijack_dns";

pub fn parse(root: &Obj<'_>) -> Result<Config> {
    root.ignore(&["log"]);
    root.unsupported("ntp", "синхронизация времени")?;
    root.unsupported(
        "certificate",
        "свои доверенные сертификаты — tls.certificate_path у выхода",
    )?;
    root.unsupported("endpoints", "WireGuard и другие endpoints")?;
    root.unsupported("services", "services")?;

    let mut inbounds = Vec::new();
    for o in root.objs("inbounds")? {
        inbounds.push(inbound(o)?);
    }
    let mut outbounds = Vec::new();
    for o in root.objs("outbounds")? {
        outbounds.push(outbound(o)?);
    }
    let mut route = RouteConfig::default();
    let mut hijack: Vec<Hijack> = Vec::new();
    let mut sniff: Vec<Option<Vec<String>>> = Vec::new();
    if let Some(r) = root.obj("route")? {
        route_section(r, &mut route, &mut hijack, &mut sniff)?;
    }
    let dns = match root.obj("dns")? {
        Some(d) => Some(dns_section(d)?),
        None => None,
    };
    let mut api = None;
    if let Some(e) = root.obj("experimental")? {
        e.ignore(&["cache_file"]);
        e.unsupported("v2ray_api", "статистика V2Ray API")?;
        if let Some(c) = e.obj("clash_api")? {
            api = clash_api(c)?;
        }
        e.finish()?;
    }
    let mut subscriptions = Vec::new();
    for (i, v) in root
        .get("subscriptions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        subscriptions.push(
            serde_json::from_value(v.clone())
                .map_err(|e| Error::Config(format!("subscriptions[{i}]: {e}")))?,
        );
    }

    // Действие sniff: включить у входов (всех или перечисленных).
    for s in &sniff {
        for i in &mut inbounds {
            let hit = match s {
                None => true,
                Some(tags) => i.tag.as_ref().is_some_and(|t| tags.contains(t)),
            };
            if hit {
                i.sniff = true;
            }
        }
    }
    // hijack-dns: у TUN — перехват DNS до маршрутизации; вход `direct`,
    // чьи запросы идут в hijack-dns, — это DNS-сервер.
    for i in &mut inbounds {
        let covered = |h: &Hijack| match (&h.inbound, &i.tag) {
            (None, _) => true,
            (Some(tags), Some(t)) => tags.contains(t),
            (Some(_), None) => false,
        };
        match i.kind {
            InboundKind::Tun => i.dns_hijack = Some(hijack.iter().any(covered)),
            InboundKind::Dns if !hijack.iter().any(|h| h.inbound.is_some() && covered(h)) => {
                return Err(Error::Config(format!(
                    "вход {} (type = \"direct\"): как DNS-сервер нужен правилом \
                     {{\"inbound\": \"{0}\", \"action\": \"hijack-dns\"}}; перенаправление \
                     (direct/dokodemo-door) иначе не поддерживается",
                    i.tag.as_deref().unwrap_or("без tag")
                )));
            }
            _ => {}
        }
    }
    if route.rules.iter().any(|r| r.outbound == REJECT) {
        outbounds.push(OutboundConfig::new(REJECT, OutboundKind::Block));
    }
    if route.rules.iter().any(|r| r.outbound == HIJACK_DNS) {
        outbounds.push(OutboundConfig::new(HIJACK_DNS, OutboundKind::Dns));
    }
    Ok(Config {
        inbounds,
        outbounds,
        route,
        dns,
        subscriptions,
        api,
    })
}

struct Hijack {
    inbound: Option<Vec<String>>,
}

fn listen(o: &Obj<'_>) -> Result<Option<SocketAddr>> {
    let host = o.str("listen")?;
    let port = o.u16("listen_port")?;
    match (host, port) {
        (None, None) => Ok(None),
        (Some(h), Some(p)) => {
            let ip: IpAddr = h
                .trim_matches(['[', ']'])
                .parse()
                .map_err(|_| o.err("listen", format!("«{h}» — не IP-адрес")))?;
            Ok(Some(SocketAddr::new(ip, p)))
        }
        (None, Some(p)) => Ok(Some(SocketAddr::from(([127, 0, 0, 1], p)))),
        (Some(_), None) => Err(o.err("listen_port", "не задан")),
    }
}

pub(super) fn ipnets(o: &Obj<'_>, key: &str) -> Result<Vec<IpNet>> {
    o.strs(key)?
        .into_iter()
        .map(|s| s.parse().map_err(|e| o.err(key, e)))
        .collect()
}

fn inbound(o: Obj<'_>) -> Result<InboundConfig> {
    let ty = o.req_str("type")?;
    let kind = match ty.as_str() {
        "socks" => InboundKind::Socks,
        "http" => InboundKind::Http,
        "mixed" => InboundKind::Mixed,
        "tun" => InboundKind::Tun,
        // DNS-сервер: вход direct + правило hijack-dns (проверяется выше).
        "direct" => InboundKind::Dns,
        other => {
            return Err(o.err(
                "type",
                format!(
                "вход «{other}» не поддерживается (есть: socks, http, mixed, tun, direct для DNS)"
            ),
            ))
        }
    };
    let mut i = InboundConfig::new(kind);
    i.tag = o.str("tag")?;
    o.ignore(&[
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "udp_timeout",
        "sniff_timeout",
    ]);
    i.sniff = o.bool("sniff")?.unwrap_or(false);
    i.sniff_override_destination = o.bool("sniff_override_destination")?.unwrap_or(false);
    o.unsupported("domain_strategy", "у входа")?;
    o.unsupported("detour", "у входа")?;
    i.allow_ip = ipnets(&o, "allow_ip")?;
    i.max_conns = o.u64("max_conns")?.map(|n| n as usize);
    match kind {
        InboundKind::Tun => {
            i.interface_name = o.str("interface_name")?;
            let mut addrs = ipnets(&o, "address")?;
            addrs.extend(ipnets(&o, "inet4_address")?);
            addrs.extend(ipnets(&o, "inet6_address")?);
            i.inet4_address = addrs.iter().find(|n| n.addr().is_ipv4()).copied();
            i.inet6_address = addrs.iter().find(|n| n.addr().is_ipv6()).copied();
            i.mtu = o.u16("mtu")?;
            i.auto_route = o.bool("auto_route")?;
            i.strict_route = o.bool("strict_route")?;
            let mut ex = ipnets(&o, "route_exclude_address")?;
            ex.extend(ipnets(&o, "inet4_route_exclude_address")?);
            ex.extend(ipnets(&o, "inet6_route_exclude_address")?);
            i.route_exclude = ex;
            o.ignore(&["stack", "endpoint_independent_nat", "platform", "gso"]);
            for k in [
                "route_address",
                "inet4_route_address",
                "inet6_route_address",
                "auto_redirect",
                "include_interface",
                "exclude_interface",
                "include_uid",
                "exclude_uid",
                "include_package",
                "exclude_package",
                "include_android_user",
                "loopback_address",
                "iproute2_table_index",
                "iproute2_rule_index",
            ] {
                o.unsupported(k, "у tun")?;
            }
        }
        InboundKind::Dns => {
            i.listen = listen(&o)?;
            o.unsupported("override_address", "перенаправление")?;
            o.unsupported("override_port", "перенаправление")?;
            o.ignore(&["network"]);
        }
        _ => {
            i.listen = listen(&o)?;
            let users = o.objs("users")?;
            if users.len() > 1 {
                return Err(o.err("users", "поддерживается один пользователь"));
            }
            if let Some(u) = users.into_iter().next() {
                i.auth = Some(format!(
                    "{}:{}",
                    u.req_str("username")?,
                    u.req_str("password")?
                ));
                u.finish()?;
            }
            o.unsupported("set_system_proxy", "включается ключом --system-proxy")?;
        }
    }
    o.ignore(&["type"]);
    i.check_fields()?;
    o.finish()?;
    Ok(i)
}

fn outbound(o: Obj<'_>) -> Result<OutboundConfig> {
    let ty = o.req_str("type")?;
    let tag = o.req_str("tag")?;
    let kind = match ty.as_str() {
        "vless" => OutboundKind::Vless,
        "trojan" => OutboundKind::Trojan,
        "direct" => OutboundKind::Direct,
        "block" => OutboundKind::Block,
        "dns" => OutboundKind::Dns,
        "selector" => OutboundKind::Selector,
        "urltest" => OutboundKind::Urltest,
        "fallback" => OutboundKind::Fallback,
        other => {
            return Err(o.err(
                "type",
                format!(
                    "выход «{other}» не поддерживается (есть: vless, trojan, direct, block, \
                     selector, urltest; расширение — fallback)"
                ),
            ))
        }
    };
    let mut out = OutboundConfig::new(&tag, kind);
    o.ignore(&["type", "tag"]);
    match kind {
        OutboundKind::Vless | OutboundKind::Trojan => server(&o, &mut out)?,
        OutboundKind::Direct => {
            out.fragment = fragment(&o)?;
            out.noises = match o.get("noises") {
                None => Vec::new(),
                Some(v) => serde_json::from_value(v.clone()).map_err(|e| o.err("noises", e))?,
            };
            o.unsupported("override_address", "перенаправление")?;
            o.unsupported("override_port", "перенаправление")?;
            o.unsupported("domain_strategy", "у выхода direct")?;
        }
        OutboundKind::Block | OutboundKind::Dns => {}
        OutboundKind::Selector | OutboundKind::Urltest | OutboundKind::Fallback => {
            out.outbounds = o.strs("outbounds")?;
            out.subscriptions = o.strs("subscriptions")?;
            out.default = o.str("default")?;
            out.url = o.str("url")?;
            out.interval = duration(&o, "interval")?.map(|d| d.as_secs().max(1));
            out.tolerance = o.u64("tolerance")?;
            o.ignore(&["interrupt_exist_connections", "idle_timeout"]);
        }
    }
    out.check_fields()?;
    o.finish()?;
    Ok(out)
}

fn fragment(o: &Obj<'_>) -> Result<Option<crate::transport::fragment::FragmentConfig>> {
    match o.get("fragment") {
        None => Ok(None),
        Some(v) => serde_json::from_value(v.clone())
            .map(Some)
            .map_err(|e| o.err("fragment", e)),
    }
}

/// vless/trojan: поля сервера → ссылка (её разбирает и проверяет тот же
/// код, что и ссылку из командной строки).
fn server(o: &Obj<'_>, out: &mut OutboundConfig) -> Result<()> {
    let vless = out.kind == OutboundKind::Vless;
    out.allow_insecure = o.bool("allow_insecure")?.unwrap_or(false);
    out.fragment = fragment(o)?;
    out.mux = o.u16("mux")?;
    // Расширение: ссылка вместо полей (удобно держать секрет в файле).
    out.link = o.str("link")?;
    out.link_file = o.str("link_file")?.map(PathBuf::from);
    if out.link.is_some() || out.link_file.is_some() {
        return Ok(());
    }
    o.ignore(&[
        "connect_timeout",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
    ]);
    o.unsupported("detour", "цепочки выходов")?;
    o.unsupported("multiplex", "мультиплексирование sing-box (smux/yamux/h2mux); у Xray-серверов — расширение \"mux\": N (Mux.Cool)")?;
    if let Some(n) = o.str("network")? {
        if n != "tcp" && n != "udp" {
            return Err(o.err("network", format!("«{n}» — ожидалось tcp или udp")));
        }
    }
    const KNOWN: &[&str] = &[
        "type",
        "tag",
        "server",
        "server_port",
        "uuid",
        "password",
        "flow",
        "network",
        "packet_encoding",
        "tls",
        "transport",
        "multiplex",
        "detour",
        "connect_timeout",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "allow_insecure",
        "fragment",
        "mux",
        "link",
        "link_file",
    ];
    let typos = o.unknown_among(KNOWN);
    if !typos.is_empty() {
        return Err(Error::Config(format!(
            "{}: неизвестные или неподдерживаемые ключи: {}",
            o.at("").trim_end_matches('.'),
            typos.join(", ")
        )));
    }
    let mut b = LinkBuilder {
        scheme: if vless { "vless" } else { "trojan" },
        uuid: o.req_str(if vless { "uuid" } else { "password" })?,
        host: o.req_str("server")?,
        port: o
            .u16("server_port")?
            .ok_or_else(|| o.err("server_port", "не задан"))?,
        params: Vec::new(),
        name: out.tag.clone(),
    };
    if vless {
        b.param("flow", o.str("flow")?.unwrap_or_default());
        match o.str("packet_encoding")?.as_deref() {
            None | Some("xudp") => {}
            Some("" | "none") => out.xudp = false,
            Some(other) => {
                return Err(o.err(
                    "packet_encoding",
                    format!("«{other}» не поддерживается (xudp или пусто)"),
                ))
            }
        }
    }
    let mut security = "none";
    if let Some(t) = o.obj("tls")? {
        if t.bool("enabled")?.unwrap_or(false) {
            security = "tls";
        }
        b.param("sni", t.str("server_name")?.unwrap_or_default());
        b.param("alpn", t.strs("alpn")?.join(","));
        if t.bool("insecure")?.unwrap_or(false) {
            return Err(t.err(
                "insecure",
                "проверку сертификата отключить нельзя; самоподписанный — tls.certificate_path",
            ));
        }
        if let Some(p) = t.str("certificate_path")? {
            out.ca_file = Some(PathBuf::from(p));
        }
        if let Some(u) = t.obj("utls")? {
            if u.bool("enabled")?.unwrap_or(false) {
                b.param("fp", u.str("fingerprint")?.unwrap_or_default());
            } else {
                u.ignore(&["fingerprint"]);
            }
            u.finish()?;
        }
        if let Some(r) = t.obj("reality")? {
            if r.bool("enabled")?.unwrap_or(false) {
                security = "reality";
                b.param("pbk", r.req_str("public_key")?);
                b.param("sid", r.str("short_id")?.unwrap_or_default());
                b.param("pqv", r.str("mldsa65_verify")?.unwrap_or_default());
            } else {
                r.ignore(&["public_key", "short_id", "mldsa65_verify"]);
            }
            r.finish()?;
        }
        for k in [
            "certificate",
            "disable_sni",
            "min_version",
            "max_version",
            "cipher_suites",
            "ech",
            "fragment",
            "record_fragment",
        ] {
            t.unsupported(k, "у tls выхода")?;
        }
        t.finish()?;
    }
    b.param("security", security);
    match o.obj("transport")? {
        None => b.param("type", "tcp"),
        Some(t) => {
            let ty = t.req_str("type")?;
            match ty.as_str() {
                "ws" | "httpupgrade" => {
                    b.param("type", ty.as_str());
                    b.param("path", t.str("path")?.unwrap_or_default());
                    let mut host = t.str("host")?.unwrap_or_default();
                    if let Some(h) = t.obj("headers")? {
                        if let Some(v) = h.strs("Host")?.into_iter().next() {
                            host = v;
                        }
                        h.finish()?;
                    }
                    b.param("host", host);
                    if t.u64("max_early_data")?.unwrap_or(0) > 0 {
                        return Err(t.err("max_early_data", "не поддерживается"));
                    }
                    t.ignore(&["early_data_header_name"]);
                }
                "grpc" => {
                    b.param("type", "grpc");
                    b.param("serviceName", t.str("service_name")?.unwrap_or_default());
                    t.ignore(&["idle_timeout", "ping_timeout", "permit_without_stream"]);
                }
                // Расширение: в sing-box xhttp нет, поля — как у ссылки.
                "xhttp" => {
                    b.param("type", "xhttp");
                    b.param("path", t.str("path")?.unwrap_or_default());
                    b.param("host", t.str("host")?.unwrap_or_default());
                    b.param("mode", t.str("mode")?.unwrap_or_default());
                    if let Some(x) = t.get("extra") {
                        b.param("extra", x.to_string());
                    }
                }
                "http" | "quic" => {
                    return Err(t.err(
                        "type",
                        format!("транспорт {ty} удалён из Xray-core; его заменяет xhttp"),
                    ))
                }
                other => {
                    return Err(t.err("type", format!("транспорт «{other}» не поддерживается")))
                }
            }
            t.finish()?;
        }
    }
    out.link = Some(b.build());
    Ok(())
}

fn route_section(
    r: Obj<'_>,
    route: &mut RouteConfig,
    hijack: &mut Vec<Hijack>,
    sniff: &mut Vec<Option<Vec<String>>>,
) -> Result<()> {
    route.final_ = r.str("final")?;
    r.ignore(&[
        "auto_detect_interface",
        "override_android_vpn",
        "find_process",
    ]);
    r.unsupported(
        "default_interface",
        "клиент сам выбирает физический интерфейс",
    )?;
    r.unsupported("default_mark", "метка задаётся самим клиентом")?;
    r.unsupported(
        "default_domain_resolver",
        "имена серверов разрешаются самим клиентом",
    )?;
    route.geosite_file = r.str("geosite_file")?.map(PathBuf::from);
    route.geoip_file = r.str("geoip_file")?.map(PathBuf::from);
    route.presets = r.strs("presets")?;
    route.domain_strategy = match r.str("domain_strategy")?.as_deref() {
        None | Some("as_is") => DomainStrategy::AsIs,
        Some("ip_if_non_match") => DomainStrategy::IpIfNonMatch,
        Some(o) => {
            return Err(r.err(
                "domain_strategy",
                format!("«{o}»: as_is или ip_if_non_match"),
            ))
        }
    };
    for g in ["geosite", "geoip"] {
        if r.has(g) {
            return Err(r.err(
                g,
                "старые базы sing-box (.db) не поддерживаются; базы v2fly (.dat) — route.geosite_file/geoip_file",
            ));
        }
    }
    for s in r.objs("rule_set")? {
        let ty = s.str("type")?.unwrap_or_else(|| "local".into());
        if ty != "local" {
            return Err(s.err(
                "type",
                format!(
                    "набор «{ty}» не поддерживается: скачайте файл и укажите type = local, path"
                ),
            ));
        }
        route.rule_set.push(RuleSetConfig {
            tag: s.req_str("tag")?,
            path: PathBuf::from(s.req_str("path")?),
            format: s.str("format")?,
        });
        s.finish()?;
    }
    for rule in r.objs("rules")? {
        let action = rule.str("action")?.unwrap_or_else(|| "route".into());
        let inbound = rule.strs("inbound")?;
        match action.as_str() {
            "sniff" => {
                rule.ignore(&["sniffer", "timeout"]);
                sniff.push((!inbound.is_empty()).then_some(inbound));
                rule.finish()?;
                continue;
            }
            "hijack-dns" => {
                let c = conditions(&rule, inbound.clone(), HIJACK_DNS.into())?;
                hijack.push(Hijack {
                    inbound: (!inbound.is_empty()).then_some(inbound),
                });
                route.rules.push(c);
                rule.finish()?;
                continue;
            }
            "reject" => {
                rule.ignore(&["method", "no_drop"]);
                route.rules.push(conditions(&rule, inbound, REJECT.into())?);
                rule.finish()?;
                continue;
            }
            "route" => {
                let target = rule.req_str("outbound")?;
                route.rules.push(conditions(&rule, inbound, target)?);
                rule.ignore(&["override_address", "override_port"]);
                rule.finish()?;
            }
            other => {
                return Err(rule.err(
                    "action",
                    format!("«{other}» не поддерживается (есть: route, reject, sniff, hijack-dns)"),
                ))
            }
        }
    }
    r.finish()
}

/// Условия правила sing-box → [`RuleConfig`].
fn conditions(r: &Obj<'_>, inbound: Vec<String>, outbound: String) -> Result<RuleConfig> {
    if r.has("type") && r.str("type")?.as_deref() == Some("logical") {
        return Err(r.err("type", "логические правила (and/or) не поддерживаются"));
    }
    r.ignore(&["type", "outbound", "action"]);
    r.unsupported("invert", "invert")?;
    let mut c = RuleConfig {
        domain: r.strs("domain")?,
        domain_suffix: r.strs("domain_suffix")?,
        domain_keyword: r.strs("domain_keyword")?,
        domain_regex: r.strs("domain_regex")?,
        geosite: r.strs("geosite")?,
        rule_set: r.strs("rule_set")?,
        ip_cidr: ipnets(r, "ip_cidr")?,
        ip_is_private: r.bool("ip_is_private")?.unwrap_or(false),
        geoip: r.strs("geoip")?,
        port: r.strs("port")?.into_iter().map(PortSpec::Str).collect(),
        network: None,
        inbound,
        outbound,
        label: None,
    };
    for p in r.strs("port_range")? {
        c.port.push(PortSpec::Str(p.replace(':', "-")));
    }
    let nets = r.strs("network")?;
    if let Some(n) = nets.iter().find(|n| *n != "tcp" && *n != "udp") {
        return Err(r.err("network", format!("«{n}»: tcp или udp")));
    }
    c.network = match (
        nets.iter().any(|n| n == "tcp"),
        nets.iter().any(|n| n == "udp"),
    ) {
        (true, false) => Some(Network::Tcp),
        (false, true) => Some(Network::Udp),
        _ => None,
    };
    for p in r.strs("protocol")? {
        match p.as_str() {
            "dns" => c.port.push(PortSpec::Num(53)),
            other => {
                return Err(r.err(
                    "protocol",
                    format!("«{other}» не поддерживается (только dns)"),
                ))
            }
        }
    }
    Ok(c)
}

fn dns_section(d: Obj<'_>) -> Result<DnsConfig> {
    let mut cfg = DnsConfig {
        servers: Vec::new(),
        rules: Vec::new(),
        final_: d.str("final")?,
        fakeip: None,
        strategy: strategy(&d, "strategy")?,
        cache_size: d.u64("cache_capacity")?.map(|n| n as usize),
    };
    if d.bool("disable_cache")?.unwrap_or(false) {
        cfg.cache_size = Some(0);
    }
    d.ignore(&["disable_expire", "independent_cache", "reverse_mapping"]);
    d.unsupported("client_subnet", "EDNS client subnet")?;
    if let Some(f) = d.obj("fakeip")? {
        if f.bool("enabled")?.unwrap_or(false) {
            cfg.fakeip = Some(FakeIpConfig {
                inet4_range: f
                    .str("inet4_range")?
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|e| f.err("inet4_range", e))?,
                inet6_range: f
                    .str("inet6_range")?
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|e| f.err("inet6_range", e))?,
                cache_file: f.str("cache_file")?.map(PathBuf::from),
            });
        } else {
            f.ignore(&["inet4_range", "inet6_range"]);
        }
        f.finish()?;
    }
    for s in d.objs("servers")? {
        let tag = s.req_str("tag")?;
        let detour = s.str("detour")?;
        let mut ca_file = None;
        let address = if let Some(a) = s.str("address")? {
            // Старый формат: адрес строкой.
            s.ignore(&["address_resolver", "address_strategy"]);
            s.unsupported("strategy", "у DNS-сервера")?;
            s.unsupported("client_subnet", "EDNS client subnet")?;
            if a.starts_with("rcode://") || a.starts_with("dhcp://") {
                return Err(s.err("address", format!("«{a}» не поддерживается")));
            }
            a
        } else {
            let ty = s.req_str("type")?;
            let host = || s.req_str("server");
            let port = s.u16("server_port")?;
            let hp = |h: String, def: u16| {
                let h = if h.contains(':') { format!("[{h}]") } else { h };
                format!("{h}:{}", port.unwrap_or(def))
            };
            s.ignore(&["domain_resolver"]);
            if let Some(t) = s.obj("tls")? {
                if let Some(p) = t.str("certificate_path")? {
                    ca_file = Some(PathBuf::from(p));
                }
                t.ignore(&["enabled", "server_name"]);
                t.finish()?;
            }
            match ty.as_str() {
                "udp" => format!("udp://{}", hp(host()?, 53)),
                "tcp" => format!("tcp://{}", hp(host()?, 53)),
                "tls" => format!("tls://{}", hp(host()?, 853)),
                "quic" => format!("quic://{}", hp(host()?, 853)),
                "https" => {
                    let path = s.str("path")?.unwrap_or_else(|| "/dns-query".into());
                    s.ignore(&["headers"]);
                    format!("https://{}{path}", hp(host()?, 443))
                }
                "local" => "local".into(),
                "fakeip" => {
                    cfg.fakeip = Some(FakeIpConfig {
                        inet4_range: s.str("inet4_range")?.map(|x| x.parse()).transpose().map_err(|e| s.err("inet4_range", e))?,
                        inet6_range: s.str("inet6_range")?.map(|x| x.parse()).transpose().map_err(|e| s.err("inet6_range", e))?,
                        cache_file: s.str("cache_file")?.map(PathBuf::from),
                    });
                    "fakeip".into()
                }
                other => {
                    return Err(s.err(
                        "type",
                        format!("DNS-сервер «{other}» не поддерживается (есть: udp, tcp, tls, https, quic, local, fakeip)"),
                    ))
                }
            }
        };
        cfg.servers.push(DnsServerConfig {
            tag,
            address,
            detour,
            ca_file,
        });
        s.finish()?;
    }
    for r in d.objs("rules")? {
        // Правила «для имён самих серверов» (outbound: any) не нужны:
        // имена серверов клиент разрешает сам, до маршрутизации.
        if r.has("outbound") {
            r.ignore(&["outbound", "server", "action"]);
            r.finish()?;
            continue;
        }
        let action = r.str("action")?.unwrap_or_else(|| "route".into());
        if action != "route" {
            return Err(r.err(
                "action",
                format!("«{action}» не поддерживается (только route)"),
            ));
        }
        cfg.rules.push(DnsRuleConfig {
            domain: r.strs("domain")?,
            domain_suffix: r.strs("domain_suffix")?,
            domain_keyword: r.strs("domain_keyword")?,
            domain_regex: r.strs("domain_regex")?,
            geosite: r.strs("geosite")?,
            rule_set: r.strs("rule_set")?,
            server: r.req_str("server")?,
        });
        r.ignore(&["disable_cache", "rewrite_ttl"]);
        r.finish()?;
    }
    d.finish()?;
    Ok(cfg)
}

fn strategy(o: &Obj<'_>, key: &str) -> Result<Strategy> {
    match o.str(key)? {
        None => Ok(Strategy::default()),
        Some(s) => serde_json::from_value(Value::String(s.clone())).map_err(|_| {
            o.err(
                key,
                format!("«{s}»: prefer_ipv4, prefer_ipv6, ipv4_only или ipv6_only"),
            )
        }),
    }
}

pub(super) fn clash_api(c: Obj<'_>) -> Result<Option<ApiConfig>> {
    c.unsupported(
        "external_ui_download_url",
        "скачивание панели — положите её файлы в папку external_ui",
    )?;
    c.unsupported(
        "external_ui_download_detour",
        "скачивание панели — положите её файлы в папку external_ui",
    )?;
    let Some(listen) = c.str("external_controller")? else {
        c.finish()?;
        return Ok(None);
    };
    let listen: SocketAddr = listen.parse().map_err(|_| {
        c.err(
            "external_controller",
            format!("«{listen}» — ожидалось 127.0.0.1:9090"),
        )
    })?;
    let api = ApiConfig {
        listen,
        token: c.str("secret")?.filter(|s| !s.is_empty()),
        token_file: c.str("secret_file")?.map(PathBuf::from),
        allow_ip: ipnets(&c, "allow_ip")?,
        allow_origin: c.strs("access_control_allow_origin")?,
        allow_private_network: c
            .bool("access_control_allow_private_network")?
            .unwrap_or(false),
        external_ui: c
            .str("external_ui")?
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        allow_query_token: c.bool("allow_query_token")?,
        default_mode: match c.str("default_mode")? {
            None => None,
            Some(m) => Some(crate::app::stats::Mode::parse(&m).ok_or_else(|| {
                c.err("default_mode", format!("«{m}» — rule, global или direct"))
            })?),
        },
    };
    c.finish()?;
    Ok(Some(api))
}
