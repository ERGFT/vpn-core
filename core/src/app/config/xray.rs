// SPDX-License-Identifier: GPL-3.0-or-later
//! Настройки в формате Xray-core (JSON) → [`Config`].
//!
//! Поддерживается то, что умеет это ядро; всё остальное — ошибка с путём
//! до ключа. Соответствия:
//! - входы `socks`, `http`, `mixed`, `tun`; `dokodemo-door`/`tunnel`,
//!   чьи запросы маршрутизация отдаёт выходу `dns`, — DNS-сервер;
//! - выходы `vless`, `trojan`, `freedom` (direct, с `fragment`/`noises`),
//!   `blackhole` (block), `dns`;
//! - `routing.balancers` со стратегией `leastPing`/`leastLoad` — группы
//!   `urltest` (адрес и период проверки — из `observatory`);
//! - `dns.servers` с `domains` — правила DNS; `+local` — через `direct`;
//!   `fakedns` — fake-IP.
//!
//! Расширения этого ядра: `subscriptions` в корне, `experimental.clash_api`
//! (локальное API) — как в формате sing-box.

use std::path::PathBuf;

use serde_json::{Map, Value};

use super::link::LinkBuilder;
use super::obj::{duration, Obj};
use super::singbox::{clash_api, ipnets};
use super::{
    Config, DomainStrategy, InboundConfig, InboundKind, OutboundConfig, OutboundKind, PortSpec,
    RouteConfig, RuleConfig,
};
use crate::app::dns::{DnsConfig, DnsRuleConfig, DnsServerConfig, FakeIpConfig, Strategy};
use crate::app::Network;
use crate::error::{Error, Result};

pub fn parse(root: &Obj<'_>) -> Result<Config> {
    root.ignore(&["log", "api", "stats", "policy", "metrics", "version"]);
    root.unsupported("reverse", "reverse")?;
    root.unsupported(
        "transport",
        "общие настройки транспорта — streamSettings у выхода",
    )?;

    // Выходы — первыми: входы dokodemo-door смотрят, куда их отправляет
    // маршрутизация.
    let mut outbounds = Vec::new();
    for o in root.objs("outbounds")? {
        outbounds.push(outbound(o)?);
    }
    let mut route = RouteConfig::default();
    let mut balancers = Vec::new();
    if let Some(r) = root.obj("routing")? {
        balancers = routing(r, &mut route)?;
    }
    let (probe_url, probe_interval) = observatory(root)?;
    for (tag, prefixes) in balancers {
        let members: Vec<String> = outbounds
            .iter()
            .map(|o: &OutboundConfig| o.tag.clone())
            .filter(|t| prefixes.iter().any(|p| t.starts_with(p.as_str())))
            .collect();
        if members.is_empty() {
            return Err(Error::Config(format!(
                "routing.balancers {tag}: selector не подошёл ни к одному выходу"
            )));
        }
        let mut g = OutboundConfig::new(&tag, OutboundKind::Urltest);
        g.outbounds = members;
        g.url = probe_url.clone();
        g.interval = probe_interval;
        outbounds.push(g);
    }
    let direct_tag = outbounds
        .iter()
        .find(|o| o.kind == OutboundKind::Direct)
        .map(|o| o.tag.clone());
    let dns = match root.obj("dns")? {
        Some(d) => Some(dns_section(d, direct_tag.as_deref())?),
        None => None,
    };
    let mut dns = dns;
    fakedns(root, &mut dns)?;

    let dns_outbounds: Vec<String> = outbounds
        .iter()
        .filter(|o| o.kind == OutboundKind::Dns)
        .map(|o| o.tag.clone())
        .collect();
    let mut inbounds = Vec::new();
    for o in root.objs("inbounds")? {
        inbounds.push(inbound(o, &route, &dns_outbounds)?);
    }

    let mut api = None;
    if let Some(e) = root.obj("experimental")? {
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
    Ok(Config {
        inbounds,
        outbounds,
        route,
        dns,
        subscriptions,
        api,
    })
}

fn listen(o: &Obj<'_>) -> Result<std::net::SocketAddr> {
    let host = o.str("listen")?.unwrap_or_else(|| "0.0.0.0".into());
    let port = o.u16("port")?.ok_or_else(|| o.err("port", "не задан"))?;
    let ip: std::net::IpAddr = host
        .trim_matches(['[', ']'])
        .parse()
        .map_err(|_| o.err("listen", format!("«{host}» — не IP-адрес")))?;
    Ok(std::net::SocketAddr::new(ip, port))
}

fn inbound(o: Obj<'_>, route: &RouteConfig, dns_outbounds: &[String]) -> Result<InboundConfig> {
    let proto = o.req_str("protocol")?;
    let kind = match proto.as_str() {
        "socks" => InboundKind::Socks,
        "http" => InboundKind::Http,
        "mixed" => InboundKind::Mixed,
        "tun" => InboundKind::Tun,
        "dokodemo-door" | "tunnel" => InboundKind::Dns,
        other => {
            return Err(o.err(
                "protocol",
                format!("вход «{other}» не поддерживается (есть: socks, http, mixed, tun, dokodemo-door для DNS)"),
            ))
        }
    };
    let mut i = InboundConfig::new(kind);
    i.tag = o.str("tag")?;
    o.ignore(&["protocol", "allocate"]);
    o.unsupported("streamSettings", "у входа")?;
    i.allow_ip = ipnets(&o, "allow_ip")?;
    i.max_conns = o.u64("max_conns")?.map(|n| n as usize);
    if let Some(s) = o.obj("sniffing")? {
        let on = s.bool("enabled")?.unwrap_or(false);
        i.sniff = on;
        // У Xray найденный домен по умолчанию заменяет адрес назначения;
        // routeOnly — только для правил.
        i.sniff_override_destination = on && !s.bool("routeOnly")?.unwrap_or(false);
        s.ignore(&["destOverride", "metadataOnly"]);
        s.unsupported("domainsExcluded", "domainsExcluded")?;
        s.finish()?;
    }
    let settings = o.obj("settings")?;
    match kind {
        InboundKind::Tun => {
            if let Some(s) = settings {
                i.interface_name = s.str("name")?;
                i.mtu = match s.u16("MTU")? {
                    Some(m) => Some(m),
                    None => s.u16("mtu")?,
                };
                s.ignore(&["userLevel"]);
                s.finish()?;
            }
            o.ignore(&["listen", "port"]);
        }
        InboundKind::Dns => {
            i.listen = Some(listen(&o)?);
            let tag = i.tag.clone().unwrap_or_default();
            let to_dns = route
                .rules
                .iter()
                .any(|r| r.inbound.contains(&tag) && dns_outbounds.contains(&r.outbound));
            if !to_dns {
                return Err(o.err(
                    "protocol",
                    "dokodemo-door — только как DNS-сервер: нужно правило routing \
                     {\"inboundTag\": [этот tag], \"outboundTag\": выход protocol = \"dns\"}",
                ));
            }
            if let Some(s) = settings {
                s.ignore(&["address", "port", "network", "userLevel"]);
                s.unsupported("followRedirect", "прозрачный прокси")?;
                s.finish()?;
            }
        }
        _ => {
            i.listen = Some(listen(&o)?);
            if let Some(s) = settings {
                let accounts = s.objs("accounts")?;
                if accounts.len() > 1 {
                    return Err(s.err("accounts", "поддерживается один пользователь"));
                }
                if let Some(a) = accounts.into_iter().next() {
                    i.auth = Some(format!("{}:{}", a.req_str("user")?, a.req_str("pass")?));
                    a.ignore(&["level", "email"]);
                    a.finish()?;
                }
                if let Some(auth) = s.str("auth")? {
                    if auth == "password" && i.auth.is_none() {
                        return Err(s.err("accounts", "auth = password, но нет accounts"));
                    }
                }
                s.ignore(&["udp", "ip", "userLevel", "timeout"]);
                s.unsupported("allowTransparent", "прозрачный прокси")?;
                s.finish()?;
            }
        }
    }
    i.check_fields()?;
    o.finish()?;
    Ok(i)
}

fn outbound(o: Obj<'_>) -> Result<OutboundConfig> {
    let proto = o.req_str("protocol")?;
    let tag = o.str("tag")?.unwrap_or_else(|| proto.clone());
    let kind = match proto.as_str() {
        "vless" => OutboundKind::Vless,
        "trojan" => OutboundKind::Trojan,
        "freedom" => OutboundKind::Direct,
        "blackhole" => OutboundKind::Block,
        "dns" => OutboundKind::Dns,
        other => {
            return Err(o.err(
                "protocol",
                format!(
                "выход «{other}» не поддерживается (есть: vless, trojan, freedom, blackhole, dns)"
            ),
            ))
        }
    };
    let mut out = OutboundConfig::new(&tag, kind);
    o.ignore(&["protocol", "tag"]);
    o.unsupported("proxySettings", "цепочки выходов")?;
    o.unsupported("sendThrough", "sendThrough")?;
    let settings = o.obj("settings")?;
    match kind {
        OutboundKind::Vless | OutboundKind::Trojan => {
            let s = settings.ok_or_else(|| o.err("settings", "не задано"))?;
            server(&o, s, &mut out)?;
        }
        OutboundKind::Direct => {
            if let Some(s) = settings {
                out.fragment = match s.get("fragment") {
                    None => None,
                    Some(v) => {
                        Some(serde_json::from_value(v.clone()).map_err(|e| s.err("fragment", e))?)
                    }
                };
                for (n, x) in s.objs("noises")?.into_iter().enumerate() {
                    let mut m = Map::new();
                    m.insert("type".into(), x.get("type").cloned().unwrap_or(Value::Null));
                    m.insert(
                        "packet".into(),
                        x.get("packet").cloned().unwrap_or(Value::Null),
                    );
                    if let Some(d) = x.get("delay") {
                        m.insert("delay".into(), d.clone());
                    }
                    if let Some(a) = x.get("applyTo") {
                        m.insert("apply_to".into(), a.clone());
                    }
                    x.finish()?;
                    out.noises.push(
                        serde_json::from_value(Value::Object(m))
                            .map_err(|e| Error::Config(format!("{}[{n}]: {e}", s.at("noises"))))?,
                    );
                }
                s.ignore(&["domainStrategy", "userLevel", "finalRules"]);
                s.unsupported("redirect", "перенаправление")?;
                s.unsupported("proxyProtocol", "PROXY protocol")?;
                s.finish()?;
            }
            if let Some(ss) = o.obj("streamSettings")? {
                ss.ignore(&["sockopt"]);
                ss.finish()?;
            }
        }
        OutboundKind::Block | OutboundKind::Dns => {
            if let Some(s) = settings {
                s.ignore(&[
                    "response",
                    "network",
                    "address",
                    "port",
                    "nonIPQuery",
                    "blockTypes",
                    "userLevel",
                ]);
                s.finish()?;
            }
        }
        _ => unreachable!(),
    }
    out.check_fields()?;
    o.finish()?;
    Ok(out)
}

/// vless/trojan: settings + streamSettings + mux → ссылка.
fn server(o: &Obj<'_>, s: Obj<'_>, out: &mut OutboundConfig) -> Result<()> {
    let vless = out.kind == OutboundKind::Vless;
    // Старая форма (vnext/servers) и новая (адрес прямо в settings).
    let list = s.objs(if vless { "vnext" } else { "servers" })?;
    let addr: Obj<'_> = match list.len() {
        0 => s,
        1 => {
            let mut list = list;
            let a = list.pop().unwrap();
            s.finish()?;
            a
        }
        _ => {
            return Err(s.err(
                if vless { "vnext" } else { "servers" },
                "поддерживается один сервер",
            ))
        }
    };
    let host = addr.req_str("address")?;
    let port = addr
        .u16("port")?
        .ok_or_else(|| addr.err("port", "не задан"))?;
    let mut b = LinkBuilder {
        scheme: if vless { "vless" } else { "trojan" },
        uuid: String::new(),
        host,
        port,
        params: Vec::new(),
        name: out.tag.clone(),
    };
    if vless {
        let users = addr.objs("users")?;
        let user = match users.len() {
            0 => None,
            1 => users.into_iter().next(),
            _ => return Err(addr.err("users", "поддерживается один пользователь")),
        };
        let u = user.as_ref().unwrap_or(&addr);
        b.uuid = u.req_str("id")?;
        let enc = u.str("encryption")?.unwrap_or_else(|| "none".into());
        if enc != "none" {
            return Err(u.err(
                "encryption",
                "VLESS Encryption не поддерживается (только none)",
            ));
        }
        b.param("flow", u.str("flow")?.unwrap_or_default());
        u.ignore(&["level", "email"]);
        if let Some(u) = user {
            u.finish()?;
        }
    } else {
        b.uuid = addr.req_str("password")?;
        addr.ignore(&["level", "email", "flow"]);
    }
    addr.finish()?;

    let mut security = "none".to_string();
    if let Some(ss) = o.obj("streamSettings")? {
        security = ss.str("security")?.unwrap_or_else(|| "none".into());
        let network = ss.str("network")?.unwrap_or_else(|| "raw".into());
        ss.ignore(&["sockopt"]);
        match security.as_str() {
            "none" => {}
            "tls" => {
                if let Some(t) = ss.obj("tlsSettings")? {
                    b.param("sni", t.str("serverName")?.unwrap_or_default());
                    b.param("fp", t.str("fingerprint")?.unwrap_or_default());
                    b.param("alpn", t.strs("alpn")?.join(","));
                    if t.bool("allowInsecure")?.unwrap_or(false) {
                        return Err(t.err(
                            "allowInsecure",
                            "проверку сертификата отключить нельзя; самоподписанный — certificates с usage = verify",
                        ));
                    }
                    for c in t.objs("certificates")? {
                        let usage = c.str("usage")?.unwrap_or_default();
                        if usage != "verify" {
                            return Err(c.err("usage", "у клиента — только verify"));
                        }
                        out.ca_file = Some(PathBuf::from(c.req_str("certificateFile")?));
                        c.finish()?;
                    }
                    t.ignore(&[
                        "disableSystemRoot",
                        "minVersion",
                        "maxVersion",
                        "masterKeyLog",
                        "enableSessionResumption",
                    ]);
                    for k in [
                        "pinnedPeerCertificateChainSha256",
                        "echConfigList",
                        "curvePreferences",
                        "cipherSuites",
                    ] {
                        t.unsupported(k, "у tlsSettings")?;
                    }
                    t.finish()?;
                }
            }
            "reality" => {
                let r = ss
                    .obj("realitySettings")?
                    .ok_or_else(|| ss.err("realitySettings", "не задано"))?;
                b.param("sni", r.str("serverName")?.unwrap_or_default());
                b.param("fp", r.str("fingerprint")?.unwrap_or_default());
                // Xray 25.x переименовал publicKey в password.
                let pbk = match r.str("publicKey")? {
                    Some(k) => k,
                    None => r.req_str("password")?,
                };
                b.param("pbk", pbk);
                b.param("sid", r.str("shortId")?.unwrap_or_default());
                b.param("pqv", r.str("mldsa65Verify")?.unwrap_or_default());
                r.ignore(&["spiderX", "show"]);
                r.finish()?;
            }
            other => return Err(ss.err("security", format!("«{other}»: none, tls или reality"))),
        }
        match network.as_str() {
            "raw" | "tcp" => {
                b.param("type", "tcp");
                for k in ["rawSettings", "tcpSettings"] {
                    if let Some(t) = ss.obj(k)? {
                        if let Some(h) = t.obj("header")? {
                            let ty = h.str("type")?.unwrap_or_else(|| "none".into());
                            if ty != "none" {
                                return Err(h.err("type", "маскировка под HTTP не поддерживается"));
                            }
                            h.finish()?;
                        }
                        t.ignore(&["acceptProxyProtocol"]);
                        t.finish()?;
                    }
                }
            }
            "ws" | "websocket" => {
                b.param("type", "ws");
                if let Some(w) = ss.obj("wsSettings")? {
                    path_host(&w, &mut b)?;
                    w.ignore(&["heartbeatPeriod", "acceptProxyProtocol"]);
                    w.finish()?;
                }
            }
            "httpupgrade" => {
                b.param("type", "httpupgrade");
                if let Some(w) = ss.obj("httpupgradeSettings")? {
                    path_host(&w, &mut b)?;
                    w.ignore(&["acceptProxyProtocol"]);
                    w.finish()?;
                }
            }
            "grpc" | "gun" => {
                b.param("type", "grpc");
                if let Some(g) = ss.obj("grpcSettings")? {
                    b.param("serviceName", g.str("serviceName")?.unwrap_or_default());
                    if g.bool("multiMode")?.unwrap_or(false) {
                        return Err(g.err("multiMode", "не поддерживается (только режим gun)"));
                    }
                    g.ignore(&[
                        "authority",
                        "user_agent",
                        "idle_timeout",
                        "health_check_timeout",
                        "permit_without_stream",
                        "initial_windows_size",
                    ]);
                    g.finish()?;
                }
            }
            "xhttp" | "splithttp" => {
                b.param("type", "xhttp");
                let key = if ss.has("xhttpSettings") {
                    "xhttpSettings"
                } else {
                    "splithttpSettings"
                };
                if let Some(x) = ss.obj(key)? {
                    b.param("path", x.str("path")?.unwrap_or_default());
                    b.param("host", x.str("host")?.unwrap_or_default());
                    b.param("mode", x.str("mode")?.unwrap_or_default());
                    let mut extra = match x.get("extra") {
                        Some(Value::Object(m)) => m.clone(),
                        Some(_) => return Err(x.err("extra", "ожидался объект")),
                        None => Map::new(),
                    };
                    // Эти поля Xray допускает и прямо в xhttpSettings.
                    for k in [
                        "headers",
                        "xPaddingBytes",
                        "noGRPCHeader",
                        "scMaxEachPostBytes",
                        "scMinPostsIntervalMs",
                        "uplinkHTTPMethod",
                        "xmux",
                        "noSSEHeader",
                        "scMaxBufferedPosts",
                        "scStreamUpServerSecs",
                        "downloadSettings",
                    ] {
                        if let Some(v) = x.get(k) {
                            extra.insert(k.to_string(), v.clone());
                        }
                    }
                    if !extra.is_empty() {
                        b.param("extra", Value::Object(extra).to_string());
                    }
                    x.finish()?;
                }
            }
            "kcp" | "mkcp" => return Err(ss.err("network", "mKCP не поддерживается")),
            "quic" | "h2" | "http" | "domainsocket" => {
                return Err(ss.err(
                    "network",
                    format!("{network} удалён из Xray-core; его заменяет xhttp"),
                ))
            }
            other => return Err(ss.err("network", format!("«{other}» не поддерживается"))),
        }
        ss.finish()?;
    } else {
        b.param("type", "tcp");
    }
    b.param("security", security);
    if let Some(m) = o.obj("mux")? {
        if m.bool("enabled")?.unwrap_or(false) {
            let c = m.u64("concurrency").ok().flatten();
            // -1 у Xray — TCP без Mux (только XUDP).
            let c = match m.get("concurrency") {
                Some(Value::Number(n)) if n.as_i64() == Some(-1) => None,
                _ => Some(c.unwrap_or(8).clamp(1, 1024) as u16),
            };
            out.mux = c;
        }
        m.ignore(&["concurrency", "xudpConcurrency", "xudpProxyUDP443"]);
        m.finish()?;
    }
    out.link = Some(b.build());
    Ok(())
}

fn path_host(w: &Obj<'_>, b: &mut LinkBuilder) -> Result<()> {
    b.param("path", w.str("path")?.unwrap_or_default());
    let mut host = w.str("host")?.unwrap_or_default();
    if let Some(h) = w.obj("headers")? {
        if let Some(v) = h.strs("Host")?.into_iter().next() {
            host = v;
        }
        h.finish()?;
    }
    b.param("host", host);
    Ok(())
}

/// Правила и балансировщики. Возвращает балансировщики: (tag, selector).
fn routing(r: Obj<'_>, route: &mut RouteConfig) -> Result<Vec<(String, Vec<String>)>> {
    route.domain_strategy = match r.str("domainStrategy")?.as_deref() {
        None | Some("AsIs") => DomainStrategy::AsIs,
        Some("IPIfNonMatch") => DomainStrategy::IpIfNonMatch,
        Some(o) => {
            return Err(r.err(
                "domainStrategy",
                format!("«{o}» не поддерживается (AsIs или IPIfNonMatch)"),
            ))
        }
    };
    r.ignore(&["domainMatcher"]);
    let mut balancers = Vec::new();
    for b in r.objs("balancers")? {
        let tag = b.req_str("tag")?;
        let selector = b.strs("selector")?;
        if let Some(s) = b.obj("strategy")? {
            let ty = s.str("type")?.unwrap_or_else(|| "random".into());
            if !matches!(ty.as_str(), "leastPing" | "leastLoad") {
                return Err(s.err(
                    "type",
                    format!(
                        "стратегия «{ty}» не поддерживается (leastPing, leastLoad — самый быстрый)"
                    ),
                ));
            }
            s.ignore(&["settings"]);
            s.finish()?;
        } else {
            return Err(b.err("strategy", "random не поддерживается: укажите leastPing"));
        }
        b.ignore(&["fallbackTag"]);
        b.finish()?;
        balancers.push((tag, selector));
    }
    for rule in r.objs("rules")? {
        rule.ignore(&["type", "ruleTag", "domainMatcher"]);
        let target = match (rule.str("outboundTag")?, rule.str("balancerTag")?) {
            (Some(t), None) | (None, Some(t)) => t,
            _ => return Err(rule.err("outboundTag", "нужен outboundTag или balancerTag")),
        };
        let mut c = RuleConfig {
            inbound: rule.strs("inboundTag")?,
            outbound: target,
            ..Default::default()
        };
        for d in rule
            .strs("domain")?
            .into_iter()
            .chain(rule.strs("domains")?)
        {
            match d.split_once(':') {
                Some(("geosite", v)) => c.geosite.push(v.into()),
                Some(("domain", v)) => c.domain_suffix.push(v.into()),
                Some(("full", v)) => c.domain.push(v.into()),
                Some(("regexp", v)) => c.domain_regex.push(v.into()),
                Some(("keyword", v)) => c.domain_keyword.push(v.into()),
                Some(("ext", _)) => {
                    return Err(rule.err(
                        "domain",
                        format!("«{d}»: свои файлы ext: не поддерживаются"),
                    ))
                }
                _ => c.domain_keyword.push(d),
            }
        }
        for ip in rule.strs("ip")? {
            if ip.starts_with('!') || ip.starts_with("ext:") {
                return Err(rule.err("ip", format!("«{ip}» не поддерживается")));
            }
            match ip.strip_prefix("geoip:") {
                Some(v) => c.geoip.push(v.into()),
                None => c.ip_cidr.push(ip.parse().map_err(|e| rule.err("ip", e))?),
            }
        }
        for p in rule.strs("port")? {
            for part in p.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                c.port.push(PortSpec::Str(part.into()));
            }
        }
        if let Some(n) = rule.str("network")? {
            let n = n.to_lowercase();
            c.network = match (n.contains("tcp"), n.contains("udp")) {
                (true, false) => Some(Network::Tcp),
                (false, true) => Some(Network::Udp),
                _ => None,
            };
        }
        rule.unsupported("protocol", "условие по протоколу (sniffing)")?;
        rule.finish()?;
        route.rules.push(c);
    }
    r.finish()?;
    Ok(balancers)
}

/// `observatory`/`burstObservatory`: адрес и период проверки для групп.
fn observatory(root: &Obj<'_>) -> Result<(Option<String>, Option<u64>)> {
    if let Some(o) = root.obj("observatory")? {
        let url = match o.str("probeURL")? {
            Some(u) => Some(u),
            None => o.str("probeUrl")?,
        };
        let interval = duration(&o, "probeInterval")?.map(|d| d.as_secs().max(1));
        o.ignore(&["subjectSelector", "enableConcurrency"]);
        o.finish()?;
        return Ok((url, interval));
    }
    if let Some(o) = root.obj("burstObservatory")? {
        o.ignore(&["subjectSelector"]);
        let mut url = None;
        let mut interval = None;
        if let Some(p) = o.obj("pingConfig")? {
            url = p.str("destination")?;
            interval = duration(&p, "interval")?.map(|d| d.as_secs().max(1));
            p.ignore(&["connectivity", "sampling", "timeout"]);
            p.finish()?;
        }
        o.finish()?;
        return Ok((url, interval));
    }
    Ok((None, None))
}

fn dns_section(d: Obj<'_>, direct: Option<&str>) -> Result<DnsConfig> {
    let mut cfg = DnsConfig {
        servers: Vec::new(),
        rules: Vec::new(),
        final_: None,
        fakeip: None,
        strategy: strategy(&d, "queryStrategy")?,
        cache_size: None,
    };
    if d.bool("disableCache")?.unwrap_or(false) {
        cfg.cache_size = Some(0);
    }
    d.ignore(&[
        "tag",
        "disableFallback",
        "disableFallbackIfMatch",
        "useSystemHosts",
        "enableParallelQuery",
        "serveStale",
        "serveExpiredTTL",
    ]);
    d.unsupported("hosts", "статические записи hosts")?;
    d.unsupported("clientIp", "EDNS client subnet")?;
    let servers = match d.get("servers") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err(d.err("servers", "ожидался список")),
    };
    for (n, v) in servers.iter().enumerate() {
        let tag = format!("dns-{n}");
        let path = format!("{}[{n}]", d.at("servers"));
        let (addr, port, domains, skip) = match v {
            Value::String(s) => (s.clone(), None, Vec::new(), false),
            Value::Object(_) => {
                let s = Obj::new(path.clone(), v)?;
                let a = s.req_str("address")?;
                let port = s.u16("port")?;
                let domains = s.strs("domains")?;
                let skip = s.bool("skipFallback")?.unwrap_or(false);
                s.ignore(&[
                    "tag",
                    "timeoutMs",
                    "finalQuery",
                    "queryStrategy",
                    "allowUnexpectedIPs",
                ]);
                for k in ["expectedIPs", "expectIPs", "unexpectedIPs", "clientIP"] {
                    s.unsupported(k, "у DNS-сервера")?;
                }
                s.finish()?;
                (a, port, domains, skip)
            }
            _ => {
                return Err(Error::Config(format!(
                    "{path}: ожидалась строка или объект"
                )))
            }
        };
        let (address, detour) =
            dns_address(&addr, port, direct).map_err(|e| Error::Config(format!("{path}: {e}")))?;
        if address == "fakeip" && cfg.fakeip.is_none() {
            cfg.fakeip = Some(FakeIpConfig {
                inet4_range: None,
                inet6_range: None,
                cache_file: None,
            });
        }
        if !domains.is_empty() {
            let mut r = DnsRuleConfig {
                domain: Vec::new(),
                domain_suffix: Vec::new(),
                domain_keyword: Vec::new(),
                domain_regex: Vec::new(),
                geosite: Vec::new(),
                rule_set: Vec::new(),
                server: tag.clone(),
            };
            for dm in domains {
                match dm.split_once(':') {
                    Some(("geosite", x)) => r.geosite.push(x.into()),
                    Some(("domain", x)) => r.domain_suffix.push(x.into()),
                    Some(("full", x)) => r.domain.push(x.into()),
                    Some(("regexp", x)) => r.domain_regex.push(x.into()),
                    Some(("keyword", x)) => r.domain_keyword.push(x.into()),
                    Some(("ext", _)) => {
                        return Err(Error::Config(format!(
                            "{path}: «{dm}»: свои файлы ext: не поддерживаются"
                        )))
                    }
                    _ => r.domain_keyword.push(dm),
                }
            }
            cfg.rules.push(r);
        }
        if !skip && cfg.final_.is_none() {
            cfg.final_ = Some(tag.clone());
        }
        cfg.servers.push(DnsServerConfig {
            tag,
            address,
            detour,
            ca_file: None,
        });
    }
    d.finish()?;
    Ok(cfg)
}

/// Адрес DNS-сервера Xray → (адрес этого ядра, detour).
fn dns_address(
    a: &str,
    port: Option<u16>,
    direct: Option<&str>,
) -> std::result::Result<(String, Option<String>), String> {
    let with_port = |s: &str| match port {
        Some(p) if !s.contains("://") => {
            let h = if s.contains(':') {
                format!("[{s}]")
            } else {
                s.to_string()
            };
            format!("{h}:{p}")
        }
        _ => s.to_string(),
    };
    match a {
        "localhost" => return Ok(("local".into(), None)),
        "fakedns" => return Ok(("fakeip".into(), None)),
        _ => {}
    }
    let local = |scheme: &str| -> std::result::Result<Option<String>, String> {
        match direct {
            Some(d) => Ok(Some(d.to_string())),
            None => Err(format!(
                "{scheme}+local:// — нужен выход freedom (напрямую)"
            )),
        }
    };
    for (xray, ours) in [
        ("https+local", "https"),
        ("tcp+local", "tcp"),
        ("quic+local", "quic"),
        ("h2c+local", ""),
    ] {
        if let Some(rest) = a.strip_prefix(&format!("{xray}://")) {
            if ours.is_empty() {
                return Err(format!("«{a}» не поддерживается"));
            }
            return Ok((format!("{ours}://{rest}"), local(xray)?));
        }
    }
    for scheme in ["https", "tcp", "quic", "tls", "udp"] {
        if a.starts_with(&format!("{scheme}://")) {
            return Ok((a.to_string(), None));
        }
    }
    if a.contains("://") {
        return Err(format!("«{a}» не поддерживается"));
    }
    // Голый адрес — UDP.
    Ok((with_port(a), None))
}

fn strategy(o: &Obj<'_>, key: &str) -> Result<Strategy> {
    Ok(match o.str(key)?.as_deref() {
        None | Some("UseIP") | Some("UseSystem") => Strategy::PreferIpv4,
        Some("UseIPv4") => Strategy::Ipv4Only,
        Some("UseIPv6") => Strategy::Ipv6Only,
        Some(s) => return Err(o.err(key, format!("«{s}»: UseIP, UseIPv4 или UseIPv6"))),
    })
}

/// `fakedns`: пулы адресов для fake-IP.
fn fakedns(root: &Obj<'_>, dns: &mut Option<DnsConfig>) -> Result<()> {
    let pools: Vec<Value> = match root.get("fakedns") {
        None => return Ok(()),
        Some(Value::Array(a)) => a.clone(),
        Some(v @ Value::Object(_)) => vec![v.clone()],
        Some(_) => return Err(root.err("fakedns", "ожидался объект или список")),
    };
    let mut f = FakeIpConfig {
        inet4_range: None,
        inet6_range: None,
        cache_file: None,
    };
    for (n, p) in pools.iter().enumerate() {
        let o = Obj::new(format!("fakedns[{n}]"), p)?;
        let pool: crate::app::access::IpNet = o
            .req_str("ipPool")?
            .parse()
            .map_err(|e| o.err("ipPool", e))?;
        o.ignore(&["poolSize"]);
        o.finish()?;
        if pool.addr().is_ipv4() {
            f.inet4_range = Some(pool);
        } else {
            f.inet6_range = Some(pool);
        }
    }
    match dns {
        Some(d) if d.fakeip.is_some() || d.servers.iter().any(|s| s.address == "fakeip") => {
            d.fakeip = Some(f)
        }
        _ => {}
    }
    Ok(())
}
