# reality-core

[Русский](README.md) | **English**

[![CI](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ERGFT/vpn-core?include_prereleases&sort=semver)](https://github.com/ERGFT/vpn-core/releases)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg?logo=rust)
![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)

A from-scratch **VLESS (+REALITY, +XTLS Vision)** client core in Rust: the
`reality-client` command-line program takes a `vless://` link and starts a
local **SOCKS5 proxy** (TCP and UDP). Traffic from programs pointed at this
proxy goes to a VLESS server (Xray-core and compatible servers).

The project was written from scratch in stages — the history, decisions and
risks of every stage are in [`PLAN.md`](PLAN.md) (in Russian); how the core
works inside is in [`docs/ARCHITECTURE.en.md`](docs/ARCHITECTURE.en.md), and
how to embed the core in an app (Android, iOS, desktop) is in
[`docs/LIBRARY.en.md`](docs/LIBRARY.en.md). It is a learning and research
project, not a replacement for mature clients: what works and what does not
is listed honestly below.

**Contents:** [Features](#features) · [Building](#building) ·
[Running](#running) · [Config file](#config-file) ·
[TUN](#tun--all-of-the-computers-traffic) · [DNS](#dns) ·
[Security](#security) · [Testing](#testing) ·
[Layout](#layout) · [Comparison with Xray-core](#comparison-with-xray-core) ·
[Known gaps](#known-gaps) · [License](#license)

## Features

| Feature | Status |
|---|---|
| `security=none` / `tls` / `reality` | ✅ all three tested against real Xray-core |
| Transport `type=tcp` (a.k.a. `raw`) | ✅ |
| Transports `type=ws` (`path=`, `host=`), `type=grpc` (`serviceName=`, "gun" mode), `type=httpupgrade` | ✅ tested against real Xray-core; request HTTP headers match Chrome (as Xray does) |
| Transport `type=xhttp` (SplitHTTP): modes `packet-up`, `stream-up`, `stream-one`, HTTP/2, HTTP/1.1 and HTTP/3 (`alpn=h3`, QUIC), `extra=` | ✅ all modes tested against Xray-core, including over REALITY (see below for what is not supported) |
| `flow=xtls-rprx-vision` (XTLS Vision) | ✅ padding, inner TLS detection, direct copy in both directions; tested against Xray-core. As in Xray — only `type=tcp` with `tls`/`reality` |
| REALITY: X25519MLKEM768 (with fallback to X25519 for sites without ML-KEM), ShortId, `minClientVer`/`maxClientVer`, HMAC certificate | ✅ |
| REALITY: ML-DSA-65 (`pqv=`) | ✅ |
| Chrome 133 TLS fingerprint | ✅ REALITY — exact match, including JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`; plain TLS — without legacy cipher suites and ALPS (see below) |
| `fp=firefox` (Firefox 148), `safari`/`ios` (Safari 26.3), `edge`/`android` (same as Chrome), `random`, `randomized` | ✅ cipher suites, extensions in browser order, groups, key shares (real P-256 for Firefox), signature algorithms, certificate compression (zlib, brotli, zstd — with decompression), GREASE — checked against utls; ws/httpupgrade/xhttp HTTP headers of the same browser; tested against an Xray REALITY server (tcp, Vision, xhttp, gRPC) |
| UDP (SOCKS5 UDP ASSOCIATE) over XUDP — like the Xray client: all destinations in one stream, Full Cone NAT | ✅ including with Vision (the only way an Xray Vision account accepts UDP); `--no-xudp` — one stream per destination |
| SOCKS5 username/password (`--auth`) | ✅ |
| Config file (`--config`) in the **sing-box or Xray-core** format (JSON, detected automatically): multiple inbounds and outbounds | ✅ anything unsupported is an error with the path to the key, not silence |
| Server groups `selector`, `urltest`, `fallback` (HTTP health checks, failover to the next one); subscriptions: base64/plain text/sing-box JSON/Clash YAML, on-disk cache | ✅ tested with an HTTPS panel and an Xray server |
| SOCKS5, HTTP proxy (CONNECT and plain requests) and `mixed` inbounds — both on one port | ✅ |
| Routing: domain (exact, suffix, keyword, regex), IP/subnet, private addresses, port, network, inbound, `geosite.dat`/`geoip.dat` databases (v2fly), sing-box rule sets (`.srs` and `.json`) | ✅ `.srs` parsing checked against `sing-box rule-set decompile` on real SagerNet and MetaCubeX sets; only domains and addresses in rule sets |
| Sniffing: domain from TLS SNI and HTTP Host when the app sent an IP; in TUN — also from QUIC (HTTP/3, v1 and v2) | ✅ QUIC tested on RFC 9001/9369 vectors and real Chromium packets (ClientHello split across two packets, shuffled CRYPTO frames) |
| Windows system proxy (`--system-proxy`) | ✅ tested under Wine |
| Autostart: Windows service (`--service-install`, config in a locked-down ProgramData folder), start at logon (`--autostart-install`), systemd on Linux | ✅ service — on real Windows (CI: install, ProgramData folder permissions, stop and start, removal); autostart at logon — under Wine |
| TUN — all of the computer's traffic (like a VPN): own TCP/IP stack, `auto_route`, DNS hijacking, fake-IP, `route_exclude`, `strict_route` kill switch | ✅ Linux — tested against Xray in an isolated netns (TCP, UDP, DNS, fake-IP, ~200 MiB/s, resilient to packet loss); ✅ Windows (Wintun) — on real Windows (CI: service, `auto_route`, HTTPS through TUN, kill switch: process killed — network closed) |
| Own DNS: UDP, TCP, DoT, DoH, DNS over QUIC (`quic://`) and system servers; server selection by domain and geosite; cache; DNS server inbound; DNS hijacking (`hijack-dns`); fake-IP; `domain_strategy`: `ip_if_non_match` | ✅ DoH/DoT/DoQ tested on own servers, UDP DNS and DoQ — through Xray (XUDP) |
| Mux.Cool for TCP (`"mux": 8` on an outbound or subscription; not together with Vision) | ✅ tested against Xray-core |
| Shared HTTP/2 connections: gRPC — all streams in one connection (as in Xray), xhttp — `xmux` (Xray defaults: 16–32 sessions per connection; for both HTTP/2 and HTTP/3) | ✅ tested against Xray-core (connection count) |
| Anti-DPI: ClientHello fragmentation (`fragment`: TLS records and/or TCP segments with delays) on `vless` and `direct`, noise before UDP (`noises`) on `direct` | ✅ fragmentation tested against an Xray REALITY server (including 1–3 byte records and Vision); off by default |
| Local API compatible with the Clash API (127.0.0.1 + token): outbounds and groups, server selection, latency tests, connections and closing them, rules, subscriptions, rule/global/direct modes, DNS queries; event, traffic, memory and log streams (WebSocket); web dashboard from a folder (`external_ui`); config reload without dropping connections (API, SIGHUP); rule presets | ✅ responses checked against sing-box 1.12; metacubexd and yacd tested in a browser |
| `trojan` outbound (`trojan://` link, TLS or REALITY, all VLESS transports, TCP and UDP); Trojan servers in subscriptions | ✅ tested against Xray-core (tcp, ws, REALITY, UDP) |
| Transport `kcp` | ❌ not supported (see below why); `quic`/`h2` have been removed from Xray-core itself — the error suggests `xhttp` |
| Linux | ✅ builds and tested |
| Windows | ✅ CI on real Windows: all tests, the `.exe` build, the service and TUN with real traffic; smoke test against Xray-core — under Wine ([`docs/WINDOWS.en.md`](docs/WINDOWS.en.md)) |

There has been no third-party crypto review of the REALITY implementation
(details — `PLAN.md`, Stage 5).

## Building

You need Rust (stable). On Linux:

```sh
cargo build --release -p reality-client
# -> target/release/reality-client  (~14 MB)
```

On Windows — see [`docs/WINDOWS.en.md`](docs/WINDOWS.en.md) or run
`powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1`.

## Running

```sh
# the link on the first line of a file readable only by you
printf '%s\n' 'vless://UUID@host:443?encryption=none&security=reality&sni=site.example&pbk=KEY&sid=SHORTID&type=tcp&flow=xtls-rprx-vision' > server.txt
chmod 600 server.txt
reality-client --server-file server.txt --listen 127.0.0.1:1080
```

- `--server-file` — a file with the link (first non-empty line); the same
  via the `REALITY_SERVER` environment variable. There is also
  `--server 'vless://…'` (the whole link, in quotes: it contains `&`), but
  ⚠️ command-line arguments are visible to every user of the machine (the
  process list), and the link contains your UUID; the client then prints a
  warning.
- `--listen` — local proxy address, `127.0.0.1:1080` by default. The port
  serves both SOCKS5 and HTTP proxy (detected by the first byte).
- `--auth user:password` — require a SOCKS5 username and password. The client
  refuses to listen on anything other than `127.0.0.1` without a password.
  Without the command line: `--auth-file file` or `REALITY_SOCKS_AUTH`.
- `--allow-ip addresses` — who on the network may use the proxy (addresses
  or subnets, comma-separated: `192.168.1.23,192.168.1.40`). This computer is
  always allowed. After 5 wrong passwords in a row an address is blocked for
  a minute (then twice as long each time, up to an hour).
- `--allow-insecure` — allow a link with `security=none`. Without this flag
  the client will not start such a link: the UUID and all traffic would go in
  plain text.
- `--max-conns N` — how many connections to serve at once (512 by default);
  extra ones are closed immediately.
- `--ca file.pem` — custom root certificates for `security=tls` (a server
  with a self-signed certificate).
- `--sniff` — if an app sends an IP instead of a name, recover the name from
  the first bytes (TLS SNI, HTTP Host) and send the name to the server.
- `--system-proxy` (Windows) — turn on the system proxy while running:
  browsers and most programs go through the client with no setup. On exit
  (Ctrl+C, closing the window) the previous settings are restored; if the
  client was killed — `--system-proxy-off`.
- `--no-xudp` — UDP without XUDP (a separate stream per destination) — for
  servers that do not know XUDP.
- Log — to stderr, `info` level by default; `--log-file file` — to a file
  (over 10 MB the previous one is moved to `.old`). Visited site addresses
  are not logged at this level (only with `RUST_LOG=debug`).

### Autostart

**Windows, service** (starts at boot, before logon — needed for TUN; run as
administrator):

```bat
reality-client --service-install --config C:\path\config.json
reality-client --service-uninstall
```

The config file, the files it refers to (they must be in the same folder)
and `reality-client.exe` itself (with `wintun.dll`) are copied to
`%ProgramData%\RealityClient`, which only SYSTEM and administrators can write
to: the service runs as SYSTEM, and an exe or config writable by a regular
user would let any of that user's programs gain system rights. The installer
refuses a folder created beforehand by a non-administrator (delete it and try
again). The log is there too, `reality-client.log`. Changed the config? Run
`--service-install` again (the service is updated and restarted). After a
crash the service restarts itself (after 5 s, 30 s, 2 min).

**Windows, at user logon** (for `--system-proxy`: the system proxy is a
per-user setting):

```bat
reality-client --autostart-install --config C:\path\config.json --system-proxy
reality-client --autostart-uninstall
```

Starts without a window; the log is `reality-client.log` next to the config.

**Linux** — systemd: [`examples/reality-client.service`](examples/reality-client.service)
(config in `/etc/reality-client`, the only root capability is `CAP_NET_ADMIN`
for TUN, `systemctl reload` rereads the config without dropping connections).

Checking that everything works:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

In a browser — set the SOCKS5 proxy to `127.0.0.1:1080` (in Firefox —
"Connection Settings", together with "Proxy DNS when using SOCKS v5").

### Config file

For multiple inbounds and outbounds, use a config file instead of flags, in
the **sing-box** or **Xray-core** format (JSON, comments allowed); the format
is detected automatically. Annotated examples:
[`examples/sing-box.json`](examples/sing-box.json) and
[`examples/xray.json`](examples/xray.json).

```sh
reality-client --config config.json --check   # validate only
reality-client --config config.json
```

Existing sing-box and Xray configs (from v2rayN, panels, etc.) work too:
everything the core supports behaves as it does there. Whatever the core does
not support (other protocols, outbound chains, sing-box multiplexing…) is an
error at startup with the path to the key, e.g. `outbounds[2].multiplex: не
поддерживается` (not supported), rather than a silently ignored setting. A
typo in a key name is an error too.

```json
{
  "inbounds": [
    { "type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": 1080 }
  ],
  "outbounds": [
    { "type": "vless", "tag": "proxy", "server": "server.example.com", "server_port": 443,
      "uuid": "…", "flow": "xtls-rprx-vision",
      "tls": { "enabled": true, "server_name": "www.example.com",
               "utls": { "enabled": true, "fingerprint": "chrome" },
               "reality": { "enabled": true, "public_key": "…", "short_id": "…" } } },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [
      { "action": "sniff" },                              // domain from SNI/Host if the app sent an IP
      { "geosite": ["category-ads-all"], "outbound": "block" },
      { "ip_is_private": true, "outbound": "direct" },
      { "domain_suffix": ["ru", "su"], "geoip": ["ru"], "outbound": "direct" }
    ],
    "final": "proxy"                                      // where everything not matched by rules goes
  }
}
```

What each format supports:

| | sing-box | Xray-core |
|---|---|---|
| Inbounds | `socks`, `http`, `mixed`, `tun`; `direct` + a `hijack-dns` rule — DNS server | `socks`, `http`, `mixed`, `tun`; `dokodemo-door` routed to a `dns` outbound — DNS server |
| Outbounds | `vless`, `trojan`, `direct`, `block`, `dns`, `selector`, `urltest` | `vless`, `trojan`, `freedom` (with `fragment`, `noises`), `blackhole`, `dns`; `balancers` with `leastPing`/`leastLoad` — a `urltest` group (checks from `observatory`) |
| Transport and TLS | `tls` (`reality`, `utls`, `alpn`, `certificate_path`), `transport`: `ws`, `grpc`, `httpupgrade` | `streamSettings`: `raw`/`tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`; `tls`/`reality`; `mux` (Mux.Cool) |
| Rules | `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `geosite`, `geoip`, `ip_cidr`, `ip_is_private`, `port`, `port_range`, `network`, `inbound`, `rule_set`, `protocol: dns`; actions `route`, `reject`, `sniff`, `hijack-dns` | `domain` (`geosite:`, `domain:`, `full:`, `regexp:`, `keyword:`, plain substring), `ip` (`geoip:`, addresses), `port`, `network`, `inboundTag`, `outboundTag`/`balancerTag`; `domainStrategy` `AsIs`/`IPIfNonMatch` |
| DNS | `servers` (with `type`, and the legacy form with `address`), `rules`, `final`, `strategy`, `fakeip` | `servers` (strings and objects with `domains`; `+local` — direct), `queryStrategy`, `fakedns` |
| API | `experimental.clash_api`: `external_controller`, `secret` | the same `experimental.clash_api` extension |

Rules are checked in order; the first match wins. Within one rule the
"where" conditions (domains, `geosite`, addresses, `geoip`) are combined with
"or", and with port, network and inbound — with "and" (as in sing-box). An IP
rule only matches if the app sent an IP; a domain rule — if it sent a name or
the name was found by sniffing. The `geosite.dat` (`dlc.dat` from
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/releases))
and `geoip.dat` ([v2fly/geoip](https://github.com/v2fly/geoip/releases))
databases are in the Xray format, sing-box configs included; they are looked
up next to the config file, and only the needed categories are read (both
full databases — ~0.2 s).

sing-box rule sets — `.srs` (e.g. from
[SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite/tree/rule-set),
[sing-geoip](https://github.com/SagerNet/sing-geoip/tree/rule-set) or
MetaCubeX/meta-rules-dat) and source `.json`, `type: local` only:

```json
"route": {
  "rule_set": [{ "type": "local", "tag": "ru", "format": "binary", "path": "geosite-category-ru.srs" }],
  "rules": [{ "rule_set": ["ru"], "outbound": "direct" }]
}
```

`rule_set` can also be used in DNS rules (domains are taken). Only rule sets
referenced by rules are loaded, and they are reloaded on config reload. Rule
sets with other conditions (port, process, logical `and`/`or`, `invert`) are
rejected with an error: silently simplifying them would route differently
from what was intended. The client does not download rule sets by URL — put
the file next to the config.

**Extensions of this core** — keys that are not part of the formats
themselves (sing-box and Xray will not accept them):

- on `vless`/`trojan` outbounds: `link` or `link_file` — a
  `vless://`/`trojan://` link instead of fields (the secret can live in a
  separate file); `allow_insecure` — allow an unencrypted server; `mux` —
  Mux.Cool (in sing-box: `"mux": 8`); `fragment`;
- on `direct` (sing-box): `fragment`, `noises` — as on `freedom` in Xray;
- the `fallback` outbound (first working) and `subscriptions` on groups;
- at the root: `subscriptions` — panel subscriptions;
- on inbounds: `allow_ip`, `max_conns`; on `transport` (sing-box): `type: xhttp`;
- in `route` (sing-box): `presets`, `geosite_file`, `geoip_file`,
  `domain_strategy`; on `fakeip`: `cache_file`.

Command-line flags are a shortcut for one `mixed` inbound and one `proxy`
outbound. The `direct` outbound does not let network clients reach services
of this computer (`127.0.0.1`, `localhost`); the `block` outbound replies with
SOCKS5 code 0x02 or HTTP 403.

### Server groups and subscriptions

Several servers make a group; a group is itself an outbound, and its tag is
used in rules and `route.final`:

```json
"outbounds": [
  { "type": "urltest", "tag": "auto",            // fastest; "fallback" — first working;
    "outbounds": ["proxy"],                      // "selector" — selected (default or first)
    "subscriptions": ["my-panel"],               // + servers from the panel
    "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50 }
],
"subscriptions": [
  { "tag": "my-panel", "url_file": "subscription.txt",   // the subscription URL is a secret, like a UUID
    "update_interval": 43200, "detour": "direct", "include": "Germany|Finland" }
]
```

In the Xray format — the same via `routing.balancers` with the `leastPing`
strategy and `observatory` (check URL and interval).

- Health check — an HTTP request through each member every `interval` with
  ±20 % jitter; `urltest` does not switch while the current member is worse
  than the best by no more than `tolerance` ms. If a connection fails to
  open, the next member is tried (up to three), and the failed one is
  considered down until the next check. Switching does not drop open
  connections.
- Subscription: a base64 list of links (3x-ui, Marzban, Remnawave), plain
  text, sing-box JSON, Clash YAML — only VLESS and Trojan are taken, the rest
  is counted in the log. HTTPS only, with certificate verification
  (`ca_file` — for a panel's self-signed certificate); `security=none`
  servers are skipped without `allow_insecure`. Downloads go through the
  group, and while the list is empty — through `direct` (or `detour`). The
  last list is saved to `<tag>.subscription` next to the config (mode 600):
  the client starts without the panel. Only the panel's host name is logged,
  not the subscription URL. With TUN, a subscription without a saved list is
  downloaded before routes are enabled.

### Anti-DPI: fragment and noises

```json
{ "type": "direct", "tag": "direct",
  "fragment": { "packets": "tlshello", "length": "100-200", "interval": "10-20" },
  "noises": [{ "type": "rand", "packet": "10-20", "delay": "10-16" }] }
```

In Xray — the same fields in the `settings` of a `freedom` outbound.
`fragment` (on `vless` — towards the server, on `direct` — towards sites)
splits the first TLS record with the ClientHello into records of `length`
bytes; with `interval > 0` — also into separate TCP segments with delays
(ms). `packets = "1-3"` splits the 1st–3rd records of the connection instead.
It helps against DPI that looks for the site name in the first packet and
does not reassemble the stream; against DPI that reassembles, it does not,
and an unusual ClientHello is noticeable in itself. `noises` — dummy packets
(`rand`, `str`, `base64`, `hex`) before the first UDP datagram to an address;
not sent to port 53. Both are off by default; parameters are as in Xray's
`freedom`.

### API, web dashboards and config reload

The API is compatible with the **Clash API** (as in sing-box and mihomo):
ready-made web dashboards — [metacubexd](https://github.com/MetaCubeX/metacubexd),
[yacd](https://github.com/haishanh/yacd), zashboard — and clients that speak
the Clash API work with the core unchanged. metacubexd and yacd were tested
against the real core in a browser: groups, server selection, latency
tests, connections, rules, logs, mode.

```json
"experimental": {
  "clash_api": {
    "external_controller": "127.0.0.1:9090",
    "secret_file": "api-token.txt",
    "external_ui": "ui",
    "default_mode": "rule"
  }
},
"route": { "presets": ["block-ads", "private-direct", "ru-direct"] }
```

- `secret` — the token right in the config, `secret_file` (extension) — in
  a separate file; at least 16 characters.
- `external_ui` — a folder with dashboard files (e.g. metacubexd's unpacked
  `compressed-dist.tgz`); it opens at `http://127.0.0.1:9090/ui/`. The client
  does not download dashboards itself (`external_ui_download_url` is an
  error): put the files into the folder.
- `access_control_allow_origin` — dashboard sites allowed to call the API
  from a browser (`["https://metacubex.github.io"]` or `["*"]`); your own
  dashboard from `external_ui` is always allowed.
  `access_control_allow_private_network: true` — needed by Chrome for a
  dashboard hosted on the internet.
- `default_mode` — the mode at startup: `rule` (by rules), `global`
  (everything through the outbound selected in the `GLOBAL` group) or
  `direct` (everything direct). DNS hijacking works in every mode. The
  `GLOBAL` group (all outbounds, `route.final` by default) is created
  automatically, as in Clash.

Clash requests — the same paths and responses as sing-box:

```sh
T="Authorization: Bearer $(cat api-token.txt)"
curl -H "$T" http://127.0.0.1:9090/proxies                         # outbounds and groups
curl -H "$T" -X PUT -d '{"name":"my-panel/Finland"}' http://127.0.0.1:9090/proxies/proxy
curl -H "$T" "http://127.0.0.1:9090/proxies/proxy/delay?url=https://www.gstatic.com/generate_204&timeout=5000"
curl -H "$T" -X PATCH -d '{"mode":"global"}' http://127.0.0.1:9090/configs
curl -H "$T" http://127.0.0.1:9090/connections
curl -H "$T" -X DELETE http://127.0.0.1:9090/connections/42
curl -H "$T" "http://127.0.0.1:9090/dns/query?name=example.com&type=A"
```

| Request | What it does |
|---|---|
| `GET /configs`, `PATCH /configs` | inbound ports and the mode; change the mode (`mode`; ports and the rest — only in the config file) |
| `PUT /configs` | reread the config file; with `payload` — apply a new config (without writing the file, as in Clash) |
| `GET /proxies[/{name}]`, `PUT /proxies/{group}` | outbounds, groups (`now`, `all`), subscription servers; select a selector member |
| `GET /proxies/{name}/delay`, `GET /group/{name}/delay` | test the latency of an outbound or of all group members |
| `GET /connections`, `DELETE /connections[/{id}]` | open connections (outbound, chain, rule, traffic); close |
| `GET /rules` | rules in order and `route.final` |
| `GET /providers/proxies[/{name}]`, `PUT …/{name}`, `GET …/{name}/healthcheck` | subscriptions: servers, update, check |
| `GET /dns/query?name=&type=` | ask the client's DNS |

Own requests (not in the Clash API): `GET /stats` (traffic per outbound),
`GET /groups`, `PUT /groups/{tag}`, `POST /groups/{tag}/check`,
`POST /subscriptions/{tag}/update`, `POST /reload` (with notes in the
response).

**Changing the config via the API** — the client does not have to write the
file and restart the core itself:

```sh
curl -H "$T" http://127.0.0.1:9090/config               # {"path", "format", "text"}
curl -H "$T" -X PUT --data-binary @new.json "http://127.0.0.1:9090/config?check=1"   # validate only
curl -H "$T" -X PUT --data-binary @new.json http://127.0.0.1:9090/config             # apply and save
```

- The `PUT /config` body is the whole config, sing-box or Xray (the format
  is detected automatically). It is validated, applied without dropping
  connections (like a reload) and written to the config file atomically,
  the previous one kept as `<file>.bak`; `?save=0` applies without writing.
  An error is a 400 and nothing changes. Response:
  `{"applied", "saved", "notes"}` (`notes` — what takes effect only after a
  restart, e.g. the API address or the TUN inbound).
- Files in such a config (`link_file`, `rule_set`, databases,
  certificates…) must come from the config folder, as a relative path
  without `..` and not through a symlink leading outside (the file's real
  location is checked): otherwise anyone with the token could make the
  client (the Windows service — as SYSTEM) read any file on the computer.
- `GET /config` returns the whole file — including UUIDs and passwords, like
  the rest of the API: the token gives full control of the client.
- Works only if the client was started with a config file (`--config`).

Streams — the client learns about changes immediately, without polling. The
response does not end until the client closes the connection: one JSON
object per line or, with `Upgrade: websocket`, one WebSocket frame per
object.

```sh
curl -N -H "$T" http://127.0.0.1:9090/events            # events
curl -N -H "$T" http://127.0.0.1:9090/traffic           # speed every second
curl -N -H "$T" "http://127.0.0.1:9090/logs?level=warning"
```

| Stream | What it sends |
|---|---|
| `/events` | own events: `connection_open` (fields as in `/connections`), `connection_close` (traffic totals, duration), `group_switch` (a group changed its member: by itself or manually), `group_check` (delays after a check), `subscription_update` (server count or error), `reload`, `mode_change`; `lagged` — the client was too slow and some events were skipped (re-read `/connections`) |
| `/traffic` | every second: `up`, `down` — bytes per second, `upTotal`, `downTotal` — totals |
| `/memory` | every second: `inuse` — process memory, bytes |
| `/logs?level=info` | the log: `{"type": "warning", "payload": "…"}`; `level` — `debug`, `info`, `warning`, `error`; never more detailed than what is logged (`RUST_LOG`) |
| `/connections` (WebSocket only) | every `interval` ms (1000 by default) — the same as `GET /connections` |

While nobody listens to a stream, events are not even assembled. Up to 16
streams at a time.

- The token is always required (`Authorization: Bearer`; a WebSocket from a
  browser — `?token=`). Only dashboard files and the `GET /` greeting are
  served without it, as in Clash. `Host` must be the API address (DNS
  rebinding protection); browser requests are accepted only from your own
  dashboard and sites in `access_control_allow_origin`; listening on
  anything but 127.0.0.1 requires `allow_ip`. Site addresses in
  `/connections` are browsing history, so they are only in the API, not in
  the log.
- Reload (`PUT /configs`, `POST /reload`, on Linux also `kill -HUP`): if the
  file has an error, the previous config keeps working. New outbounds,
  rules, DNS, groups and subscriptions apply immediately to new
  connections, open ones keep the old ones; group selections and the mode
  are kept. Inbounds are restarted only if their settings changed; the TUN
  inbound and the API — after a program restart. The fake-IP table is kept.
- Presets (after your own rules, so your rules can override them):
  `block-ads` (geosite `category-ads-all` → the first `block`),
  `private-direct` (private addresses, `.local`, `.lan` → the first
  `direct`), `ru-direct`, `cn-direct`, `ir-direct` (country domains,
  geosite, geoip → `direct`).

### TUN — all of the computer's traffic

The `tun` inbound creates a virtual network interface, and the traffic of all
programs goes through the client, not only of those configured to use the
proxy:

```json
"inbounds": [
  { "type": "tun", "tag": "tun",
    "address": ["172.19.0.1/30"],               // default, plus fdfe:dcba:9876::1/126
    "auto_route": true,                         // all traffic into TUN (default)
    "strict_route": true,                       // kill switch
    "route_exclude_address": ["192.168.0.0/16"] }
],
"route": {
  "rules": [
    { "action": "sniff" },                       // domain from SNI/Host and from QUIC (HTTP/3)
    { "protocol": "dns", "action": "hijack-dns" } // DNS to port 53 of any address — dns section
  ]
}
```

In Xray — the `"protocol": "tun"` inbound (`settings.name`, `settings.MTU`);
DNS is hijacked by an `inboundTag` rule → a `dns` outbound.

- `sniff` in TUN also finds the domain of QUIC: the ClientHello is assembled
  from the first Initial packets (their keys are derived from the plaintext
  Connection ID), so domain rules work for HTTP/3 too. Non-QUIC — no delay;
  QUIC waits for the second packet for at most 300 ms.
- Requires administrator (Windows) or root (Linux) rights. On Windows,
  `wintun.dll` (from [wintun.net](https://www.wintun.net/), amd64) must be
  next to `reality-client.exe`.
- `auto_route` sends all traffic into TUN; the client's own connections (to
  the server, `direct`, DNS) bypass TUN: on Linux they are marked
  (`SO_MARK`), on Windows they are bound to the physical interface. There is
  no loop, and `direct` rules work as usual. If the computer has no IPv6,
  IPv6 is not routed into TUN.
- With a `hijack-dns` rule, DNS queries to port 53 of any address are
  answered by the `dns` section (without it — a config error). Fake-IP works
  fully with TUN: the program gets a 198.18.x.x address, and the client
  connects by name through the server.
- Exiting the client (Ctrl+C, closing the window) restores the routes. If
  the client is killed, the interface disappears together with its routes —
  the network works directly again. With `strict_route` — the opposite:
  the network stays closed (kill switch) until the client is started again
  or `reality-client --tun-cleanup` is run (only `route_exclude_address`
  and essentials stay open: DHCP, and NDP for IPv6). On Linux this is an
  `unreachable` rule, on Windows — persistent WFP filters (they survive
  even a reboot); the Windows service restarts itself after a crash. After
  a crash the system DNS is closed too: the server name resolves on restart
  if the server address is an IP or the `dns` section has a server by IP
  with `"detour": "direct"`. On Windows, for the first few seconds after
  the kill switch turns on, the system is still "identifying" the TUN
  interface and its DNS queries may fail; after a few seconds names
  resolve through the tunnel.
- `auto_route` is held by one instance per computer (on Linux — per
  network namespace): the routing table, rules and WFP filters are shared.
  A second instance with `auto_route` will not start ("auto_route уже
  держит другой запущенный экземпляр" — already held by another running
  instance), and `--tun-cleanup` touches nothing while one is running and
  exits with an error.
- A system DNS server (`"type": "local"`) together with TUN is a config
  error: system DNS itself goes through TUN (a loop).
- Limitations: ICMP (ping) does not pass through TUN; on Windows
  `route_exclude_address` is IPv4 only, and with the local network
  excluded Windows may query the router's DNS directly.

### DNS

The `dns` section — own DNS instead of the system one:

```json
"inbounds": [
  { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 53 }   // DNS server for the system
],
"route": { "rules": [{ "inbound": ["dns-in"], "action": "hijack-dns" }] },
"dns": {
  "servers": [
    { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },
    { "type": "https", "tag": "local", "server": "common.dot.dns.yandex.net", "detour": "direct" }
  ],
  "rules": [{ "geosite": ["category-ru"], "server": "local" }],
  "final": "remote"
}
```

In Xray: `"dns": {"servers": ["https://1.1.1.1/dns-query",
{"address": "https+local://…", "domains": ["geosite:category-ru"]}]}` —
`domains` become rules, `+local` — queries go directly.

- Servers: `udp`, `tcp`, `tls` (DNS over TLS, port 853), `https` (DNS over
  HTTPS, `path` defaults to `/dns-query`), `quic` (DNS over QUIC, RFC 9250,
  UDP port 853 — goes over XUDP through a VLESS outbound), `local` (system
  resolver), `fakeip`. The legacy sing-box form —
  `"address": "https://1.1.1.1/dns-query"` — is understood too. `udp` and
  `tcp` need an IP: there is nothing to resolve the DNS server's own name
  with. DoT/DoH/DoQ certificates are verified (own roots —
  `tls.certificate_path`).
- `detour` — which outbound to use to reach the server; defaults to
  `route.final`, i.e. usually through the VLESS server: this way neither
  your ISP nor your Wi-Fi neighbours see which names you look up.
- Who uses the module: the DNS inbound (set `127.0.0.1` as DNS in the network
  settings — then all programs' queries go through it); the `hijack-dns`
  rule (programs' DNS queries going through the proxy or TUN); the `direct`
  outbound (resolves names with it rather than with the system);
  `route.domain_strategy` `ip_if_non_match` (IP rules for names).
- Cache: by answer TTL (at most an hour; negative — at most a minute), up to
  4096 answers (`cache_capacity`; `disable_cache` — no cache).
- Fake-IP (a `"type": "fakeip"` server): the program immediately gets an
  address from `198.18.0.0/15` (and `fc00::/18`), and when connecting to it
  through the proxy it reaches the real site — the server resolves the name.
  Only makes sense with TUN or for programs that use this proxy: otherwise
  the program goes to 198.18.x.x directly and gets nowhere. The table can be
  kept across restarts (`cache_file` — extension).
- A DNS inbound open to the network requires `allow_ip`: otherwise it is an
  "open resolver" used for DDoS attacks.

### Supported link parameters

| Parameter | Value |
|---|---|
| `security` | `none`, `tls`, `reality`; anything else is an error |
| `type` | `tcp`/`raw` (default), `ws`, `grpc`, `httpupgrade`, `xhttp` (`splithttp`); anything else is an error |
| `sni` | server name for TLS/REALITY (defaults to host) |
| `pbk`, `sid` | REALITY public key and ShortId |
| `pqv` | the REALITY server's ML-DSA-65 key (optional) |
| `flow` | empty or `xtls-rprx-vision` (`-udp443` too); anything else is an error |
| `path`, `host` | path and Host header for ws, httpupgrade, xhttp (`?ed=` in the path is dropped) |
| `mode` | for xhttp: `auto` (default: REALITY — `stream-one`, otherwise `packet-up`), `packet-up`, `stream-up`, `stream-one` |
| `extra` | for xhttp: JSON as in Xray — `headers`, `xPaddingBytes`, `noGRPCHeader`, `scMaxEachPostBytes`, `scMinPostsIntervalMs`, `uplinkHTTPMethod`; settings that change the request format (`xPaddingObfsMode`, session/seq/data placed outside the path, `downloadSettings`) are an error |
| `serviceName` | gRPC service name |
| `alpn` | comma-separated ALPN list; default `h2,http/1.1` (like Chrome), `http/1.1` for ws and httpupgrade, always `h2` for gRPC; for xhttp `alpn=http/1.1` turns on HTTP/1.1, `alpn=h3` — HTTP/3 over QUIC (`security=tls` only) |
| `encryption` | `none` only |
| `headerType` | `none` only |
| `fp` | `chrome` (default), `firefox`, `safari`, `ios` (= Safari 26), `edge`, `android` (= Chrome), `random` (one browser per run), `randomized` (per outbound); anything else (`360`, `qq`) — Chrome and a warning |

## Security

What the client guarantees and what it protects against (details and
history — `PLAN.md`, section "Аудит безопасности" / security audit):

- **The UUID goes to nobody but the real REALITY server.** VLESS data is sent
  only after a full handshake with REALITY verification (certificate HMAC,
  ML-DSA-65 with `pqv=`). There is no fallback to regular certificate
  verification; a degenerate `pbk=` is rejected.
- **Replacing the server with a real site does not give the client away:**
  like Xray, the client completes the handshake with the site, opens its home
  page like Chrome and only then reports an error — the UUID is not sent.
- **No DNS leaks:** site names are resolved by the server; only the VLESS
  server's own name is resolved locally.
- **The local proxy does not hold on to "dead" connections:** 10 s for the
  SOCKS5/HTTP greeting, idle timeout (300 s; 30 s if one side has already
  closed), a limit on concurrent connections.
- **The server cannot crash the client** with an overlong gRPC, WebSocket or
  xhttp message: all parsers have limits.
- **A UDP association is used only by its owner** (IP and port), not by any
  process on the same machine.

### If an attacker is on the same Wi-Fi network

What they **cannot** do (with `security=reality` or `tls`):

- read or tamper with traffic to the server or learn the UUID — even if they
  intercept the connection (DNS spoofing, a rogue access point): without the
  server's key they fail REALITY verification, without a trusted certificate —
  TLS verification; the handshake is aborted before the UUID is sent;
- connect to the proxy: by default it listens on `127.0.0.1` only.

What they **can** do, and how it is mitigated:

| What | Protection |
|---|---|
| A link with `security=none`: the UUID and traffic are visible to everyone on the network, anyone can use the server | the client does not start such a link without `--allow-insecure` |
| The proxy is open to the network (`--listen 0.0.0.0`): password guessing | password of at least 12 characters, address blocked after 5 failures, `--allow-ip` |
| The proxy is open to the network: SOCKS5 and HTTP proxy are **not encrypted** — the password, site addresses and data between the phone and the computer are visible on shared Wi-Fi | that is how these protocols work, the client cannot fix it; it warns at startup. Open the proxy to the network only at home, for your own devices, with `--allow-ip` |
| The proxy is open to the network and there is a rule with the `direct` outbound: a device on the network acts "on behalf of" this computer — including on networks it cannot reach itself (work VPN, Docker, WSL) | `direct` does not let network clients reach the computer's own services (`127.0.0.1`, `localhost`); otherwise — let only your own devices use the proxy (password, `--allow-ip`) and do not route subnets they do not need to `direct` |
| Sees the very fact of a connection to the server's IP, and the volume and timing of traffic | no VPN hides this; REALITY only disguises it as a visit to an ordinary site |
| DNS queries on the local network are visible and can be spoofed (plain DNS is not encrypted) | the `dns` section with DoH/DoT through the server and a DNS inbound (`direct` + a `hijack-dns` rule) as the system DNS; UDP answers are checked (ID, question, server address) |
| Traffic of programs **not** configured to use the proxy bypasses it | this is a proxy, not a system-wide VPN: configure programs or turn on `--system-proxy` (Windows; not all programs honour it); in a browser with SOCKS5, turn on "Proxy DNS when using SOCKS v5", otherwise site names go to the local network's DNS (with an HTTP proxy names go to the proxy anyway) |

## Testing

One command — everything available on this machine:

```sh
scripts/ci.sh          # fmt, SPDX headers, clippy (no warnings), tests, release build,
                       # + interop and smoke with the Go test server and Xray-core, fingerprint check
scripts/ci.sh --quick  # fmt, SPDX headers, clippy, tests only
```

Individually:

| Script | What it checks |
|---|---|
| `cargo test --workspace` | 209 tests (144 unit + 65 integration), all on loopback; with `GEO_DIR=…` and `--ignored` — also a check against real geosite/geoip databases |
| `scripts/fetch_sing_box.sh` + `ci.sh` | `.srs` parsing against real sing-box: sets of versions 1–3 built with `sing-box rule-set compile` (3000+ domains, IDN, suffixes, IPv4/IPv6 ranges), and 5 real geosite/geoip sets — record-by-record match with `rule-set decompile` |
| `scripts/interop_xray.sh` | 23 tests against **real Xray-core**: REALITY (including with a site without ML-KEM), Vision (padding and switching to direct copy), ML-DSA-65 (and rejection of a wrong key), WebSocket and httpupgrade without TLS and with TLS + `--ca`, gRPC over REALITY, xhttp in all modes (HTTP/1.1, h2, HTTP/3, over REALITY; 404/400 rejections with a clear error), DNS over QUIC over VLESS, UDP and XUDP (Full Cone), a Vision account refusing a client without flow, Mux.Cool (20 connections — 3 streams), shared HTTP/2 connections for gRPC and xhttp (`xmux`), fragmented ClientHello (`fragment`), `fp=firefox/safari/…` fingerprints |
| `scripts/smoke_xray.sh` | the built binary, as a user would run it, against Xray-core: SOCKS5 with a password → REALITY → Vision → VLESS, 1 MiB of inner TLS round trip with a switch to direct copy, 20 UDP datagrams over XUDP; config file: `--check`, typos, `mixed` inbound (SOCKS5 and HTTP CONNECT), `block` rule, DNS inbound with a query through Xray |
| `scripts/tun_netns.sh` | TUN with `auto_route` in an isolated network namespace (root) against Xray-core: TCP (32 MiB round trip), `direct` without a loop, `route_exclude`, UDP/XUDP, QUIC sniffing on Chromium packets, DNS hijacking to 8.8.8.8, fake-IP, route restore on Ctrl+C, network after `kill -9`, `strict_route` kill switch and `--tun-cleanup` |
| `scripts/cross_windows.sh` | Windows `.exe` (mingw-w64) + all tests and the smoke test against Xray-core under Wine, `--system-proxy`: registry write and restore on Ctrl+C; service: install (config copied to ProgramData), start, clean stop and removal; autostart at logon |
| `scripts/interop_go_reality.sh` | 4 tests against a REALITY server built on the Go library `XTLS/REALITY` (needs Go ≥ 1.27) |
| `scripts/smoke_e2e.sh` | the binary against the Go test server; an incompatible link is rejected at startup |
| `scripts/check_chrome_fingerprint.sh` | whether the Chrome reference in utls has changed: cipher suites, extension set, `signature_algorithms` (worth running every month or two) |
| `scripts/check_license_headers.sh` | every own source file has an `SPDX-License-Identifier` header |
| `scripts/third_party_licenses.sh` | `THIRD-PARTY-LICENSES.html` from `Cargo.lock` (cargo-about); fails on a dependency with a license not in `about.toml` |
| `cargo run -p fpcheck -- --server 'vless://...'` | JA3/JA4 of this client's real ClientHello |

On GitHub the platform does the same (`.github/workflows/ci.yml`) on every
push to `main` and every pull request: on Linux — all of `scripts/ci.sh`
(including interop with the Go REALITY server and Xray-core), TUN in a netns
and the dependency license list; on **real Windows** — tests, the `.exe`
build (downloadable from the run page, "Artifacts") and
`scripts/windows_live_test.ps1`: the service, its folder permissions and TUN
with real traffic. Release — `git tag v0.2.0 && git push origin v0.2.0`:
`.github/workflows/release.yml` builds Windows and Linux binaries with
SHA-256 sums, `LICENSE` and `THIRD-PARTY-LICENSES.html` into a draft release.

Xray-core for tests: `scripts/fetch_xray.sh` (download a release) or
`scripts/build_xray_from_source.sh` (build from source via git — for
environments without access to releases and `proxy.golang.org`). In such an
environment the Go test server is prepared by
`scripts/interop_sandbox_bootstrap.sh`.

## Layout

```
bin/client/            reality-client: CLI (flags or --config), sysproxy.rs,
                       winservice.rs (Windows service and autostart)
core/src/
  app/                 application: inbounds -> router -> outbounds;
                       config/ (sing-box, Xray → one model), proxy_in.rs + http_in.rs
                       (socks/http/mixed inbounds), sniff.rs + sniff_quic.rs, router.rs + rules.rs +
                       geo.rs (rules, geosite/geoip), ruleset.rs
                       (sing-box .srs/.json rule sets), outbound.rs
                       (direct, block, dns), vless_out.rs, access.rs,
                       dns/ (upstream.rs: UDP/TCP/DoT/DoH/DoQ, cache.rs,
                       fakeip.rs), dns_in.rs (DNS inbound), tun/ (TUN inbound
                       on smoltcp + tun-rs, udp.rs: UDP flows,
                       route.rs: auto_route)
  net_protect.rs       marking outgoing sockets (bypassing TUN)
  vless/               vless:// parsing (uri.rs), VLESS protocol (protocol.rs),
                       XTLS Vision (vision.rs), UDP packets (udp.rs), XUDP (xudp.rs)
  transport/           tcp_tls.rs (TCP, TLS, REALITY), raw.rs (a socket that yields
                       one TLS record at a time for Vision), ws.rs, grpc.rs,
                       httpupgrade.rs, xhttp.rs, quic.rs (quinn: DoQ, HTTP/3),
                       browser_headers.rs (Chrome headers)
  reality/             REALITY: keys and SessionId (auth.rs), ClientHello hook
                       (hook.rs), certificate verification: HMAC and ML-DSA-65 (verifier.rs)
  fingerprint/         Chrome-like ClientHello (chrome_profile.rs), parsing, JA3/JA4
  socks5/              SOCKS5 protocol: greeting, username/password, UDP headers
  relay.rs             bidirectional relay, one buffer per direction
core/tests/            integration tests (loopback) + interop_xray.rs, interop_go_reality.rs
vendor/rustls-reality-patch/
                       rustls 0.23.45 with a patch: REALITY, GREASE, Chrome ClientHello
                       profile (wired in via [patch.crates-io])
interop/go-reality-server/
                       REALITY test server on the XTLS/REALITY library
bin/fpcheck/           JA3/JA4 capture
ffi/                   the core as a library: C ABI (reality.h), a C example
bench/                 benchmarks (criterion) and memory measurement (memwatch, Linux)
scripts/               ci, interop, smoke, Xray build, fingerprint check,
                       Windows build, instructions for Stages 2 and 8
docs/                  ARCHITECTURE.md (how the core works), LIBRARY.md
                       (the core in an app), WINDOWS.md,
                       crypto review checklist (Stage 5)
examples/              example configs: sing-box.json, xray.json, systemd
PLAN.md                stage plan, decision history, open risks (in Russian)
```

## Comparison with Xray-core

`scripts/stage8_compare_with_xray.sh` — an automated comparison with real
Xray-core under the same load (both clients talk to the same REALITY test
server, the load comes from the same code). Three runs, 8 connections x
16 MiB, loopback, 2 cores, Xray-core 26.9.9:

| metric | reality-core | Xray-core 26.9.9 |
|---|---|---|
| idle memory | **6.3 MiB** | 30.4 MiB |
| peak memory under load | **8.9 MiB** | 35.3 MiB |
| time to first data byte | 25.4 ms | 35.8 ms (a tie — spread is comparable) |
| throughput | 625 MiB/s | 572 MiB/s (a tie — spread is comparable) |

The memory advantage is largely the price of universality: Xray-core carries
dozens of protocols and routing, while this client does one thing.

⚠️ Time to the **first data byte**, not to the SOCKS5 CONNECT reply: Xray
answers CONNECT in advance, without waiting for the server connection (it
replies "success" even if there is no server), so its CONNECT reply cannot be
compared with ours. Details — `PLAN.md`, Stage 8.

## Performance and memory

Benchmarks and the allocator choice — `PLAN.md`, Stages 0 and 7. In short:
one buffer (17 KiB — so that a whole TLS record fits, which matters for
Vision) per connection direction, no global pool; the system allocator by
default (`--features mimalloc` is optional, and gave a larger idle RSS in
measurements).

```sh
cargo bench -p bench
cargo run -p bench --bin memwatch -- --pid <PID> --duration-secs 30 --csv rss.csv   # Linux
```

## Known gaps

- Mux.Cool — only without Vision (the Xray server drops Vision streams with
  TCP inside); connection half-close is not carried over Mux.Cool (as in
  Xray). UDP goes over XUDP in a separate stream.
- `kcp` (mKCP — a custom reliable protocol over UDP, ~2.5k lines in Xray) is
  not implemented: a rare transport that is easy for DPI to spot.
- xhttp: no `downloadSettings`; over HTTP/1.1 connections are not reused
  across sessions (h2 and h3 use `xmux`). The ClientHello inside QUIC
  (HTTP/3, DoQ) is rustls's, not Chrome's (Xray uses quic-go, also not
  Chrome); `fp=` has no effect on QUIC.
- Plain TLS (`security=tls`) differs from Chrome in two ways, deliberately:
  the 6 legacy cipher suites are not offered (a server falling back to
  TLS 1.2 could pick one) and neither is ALPS (if a BoringSSL-based CDN
  negotiates it, the client must answer, and rustls cannot). With REALITY the
  match is exact.
- On real Windows (CI) the tests, the service and TUN are checked; the system proxy, autostart at logon and Xray-core interop — only under Wine so far.
- A third-party crypto review (Stage 5) and the decision to publish (Stage 8)
  are up to people: `docs/stage5-crypto-review-and-interop.en.md`.

## Contributing

How to send a fix — [CONTRIBUTING.md](CONTRIBUTING.md#english); how to
report a vulnerability privately — [SECURITY.md](SECURITY.md#english); where
to get help — [SUPPORT.md](SUPPORT.md#english); community rules —
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md#english); what changed —
[CHANGELOG.md](CHANGELOG.md#english).

## License

Copyright (C) 2026 ERGFT.

GNU General Public License v3.0 or later (`GPL-3.0-or-later`) — the full text
is in [`LICENSE`](LICENSE); every source file carries an
`SPDX-License-Identifier` header. The sources in `vendor/rustls-reality-patch`
are a patched rustls and stay under its licenses (Apache-2.0 / ISC / MIT,
`LICENSE-*` files there). The licenses of all dependencies included in the
binary are in the `THIRD-PARTY-LICENSES.html` file of every release
(`scripts/third_party_licenses.sh`).
