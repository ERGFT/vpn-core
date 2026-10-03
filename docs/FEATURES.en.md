# Features and limitations

[Русский](FEATURES.md) | **English**

The full list: what `reality-client` can do and how each feature was tested. Short version — [README](../README.en.md#features).

## Features

Statuses:

- **ready** — works and is covered by tests (where stated — against real Xray-core);
- **experimental** — works, but has little testing or the result depends on the network;
- **not supported** — not available and not planned soon;
- **not tested on this platform** — the code exists but has not been properly tested on this OS.

| Feature | Status | How it was tested |
|---|---|---|
| `security=none` / `tls` / `reality` | ready | all three tested against real Xray-core |
| Transport `type=tcp` (a.k.a. `raw`) | ready | interop with Xray-core |
| Transports `type=ws` (`path=`, `host=`), `type=grpc` (`serviceName=`, "gun" mode), `type=httpupgrade` | ready | tested against real Xray-core; request HTTP headers match Chrome (as Xray does) |
| Transport `type=xhttp` (SplitHTTP): modes `packet-up`, `stream-up`, `stream-one`, HTTP/2, HTTP/1.1 and HTTP/3 (`alpn=h3`, QUIC), `extra=` | ready | all modes tested against Xray-core, including over REALITY (see below for what is not supported) |
| `flow=xtls-rprx-vision` (XTLS Vision) | ready | padding, inner TLS detection, direct copy in both directions; tested against Xray-core. As in Xray — only `type=tcp` with `tls`/`reality` |
| REALITY: X25519MLKEM768 (with fallback to X25519 for sites without ML-KEM), ShortId, `minClientVer`/`maxClientVer`, HMAC certificate | ready | against Xray-core and the XTLS/REALITY Go library; no third-party crypto review |
| REALITY: ML-DSA-65 (`pqv=`) | ready | against Xray-core, including rejection of a wrong key |
| Chrome 133 TLS fingerprint | ready | REALITY — exact match, including JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`; plain TLS — without legacy cipher suites and ALPS (see below) |
| `fp=firefox` (Firefox 148), `safari`/`ios` (Safari 26.3), `edge`/`android` (same as Chrome), `random`, `randomized` | ready | cipher suites, extensions in browser order, groups, key shares (real P-256 for Firefox), signature algorithms, certificate compression (zlib, brotli, zstd — with decompression), GREASE — checked against utls; ws/httpupgrade/xhttp HTTP headers of the same browser; tested against an Xray REALITY server (tcp, Vision, xhttp, gRPC) |
| UDP (SOCKS5 UDP ASSOCIATE) over XUDP — like the Xray client: all destinations in one stream, Full Cone NAT | ready | including with Vision (the only way an Xray Vision account accepts UDP); `--no-xudp` — one stream per destination |
| SOCKS5 username/password (`--auth`) | ready | smoke test of the binary against Xray-core |
| Config file (`--config`) in the **sing-box or Xray-core** format (JSON, detected automatically): multiple inbounds and outbounds | ready | anything unsupported is an error with the path to the key, not silence |
| Server groups `selector`, `urltest`, `fallback` (HTTP health checks, failover to the next one); subscriptions: base64/plain text/sing-box JSON/Clash YAML, on-disk cache | ready | tested with an HTTPS panel and an Xray server |
| SOCKS5, HTTP proxy (CONNECT and plain requests) and `mixed` inbounds — both on one port | ready | smoke test: SOCKS5 and HTTP CONNECT on one port |
| Routing: domain (exact, suffix, keyword, regex), IP/subnet, private addresses, port, network, inbound, `geosite.dat`/`geoip.dat` databases (v2fly), sing-box rule sets (`.srs` and `.json`) | ready | `.srs` parsing checked against `sing-box rule-set decompile` on real SagerNet and MetaCubeX sets; only domains and addresses in rule sets |
| Sniffing: domain from TLS SNI and HTTP Host when the app sent an IP; in TUN — also from QUIC (HTTP/3, v1 and v2) | ready | QUIC tested on RFC 9001/9369 vectors and real Chromium packets (ClientHello split across two packets, shuffled CRYPTO frames) |
| Windows system proxy (`--system-proxy`) | not tested on this platform | tested under Wine |
| Autostart: Windows service (`--service-install`, config in a locked-down ProgramData folder), start at logon (`--autostart-install`), systemd on Linux | ready | service — on real Windows (CI: install, ProgramData folder permissions, stop and start, removal); autostart at logon — under Wine |
| TUN — all of the computer's traffic (like a VPN): own TCP/IP stack, `auto_route`, DNS hijacking, fake-IP, `route_exclude`, `strict_route` kill switch | ready | Linux — tested against Xray in an isolated netns (TCP, UDP, DNS, fake-IP, ~200 MiB/s, resilient to packet loss); Windows (Wintun) — on real Windows (CI: service, `auto_route`, HTTPS through TUN, kill switch: process killed — network closed) |
| Own DNS: UDP, TCP, DoT, DoH, DNS over QUIC (`quic://`) and system servers; server selection by domain and geosite; cache; DNS server inbound; DNS hijacking (`hijack-dns`); fake-IP; `domain_strategy`: `ip_if_non_match` | ready | DoH/DoT/DoQ tested on own servers, UDP DNS and DoQ — through Xray (XUDP) |
| Mux.Cool for TCP (`"mux": 8` on an outbound or subscription; not together with Vision) | ready | tested against Xray-core |
| Shared HTTP/2 connections: gRPC — all streams in one connection (as in Xray), xhttp — `xmux` (Xray defaults: 16–32 sessions per connection; for both HTTP/2 and HTTP/3) | ready | tested against Xray-core (connection count) |
| Anti-DPI: ClientHello fragmentation (`fragment`: TLS records and/or TCP segments with delays) on `vless` and `direct`, noise before UDP (`noises`) on `direct` | experimental | fragmentation tested against an Xray REALITY server (including 1–3 byte records and Vision); off by default |
| Local API compatible with the Clash API (127.0.0.1 + token): outbounds and groups, server selection, latency tests, connections and closing them, rules, subscriptions, rule/global/direct modes, DNS queries; event, traffic, memory and log streams (WebSocket); web dashboard from a folder (`external_ui`); config reload without dropping connections (API, SIGHUP); rule presets | ready | responses checked against sing-box 1.12; metacubexd and yacd tested in a browser |
| `trojan` outbound (`trojan://` link, TLS or REALITY, all VLESS transports, TCP and UDP); Trojan servers in subscriptions | ready | tested against Xray-core (tcp, ws, REALITY, UDP) |
| Transport `kcp` | not supported | not supported (see below why); `quic`/`h2` have been removed from Xray-core itself — the error suggests `xhttp` |
| Linux | ready | builds and tested |
| Windows | ready | CI on real Windows: all tests, the `.exe` build, the service and TUN with real traffic; smoke test against Xray-core — under Wine ([`docs/WINDOWS.en.md`](WINDOWS.en.md)) |
| Library mode (C ABI): Android, iOS, desktop — [LIBRARY.en.md](LIBRARY.en.md) | experimental | built in CI for Android and iOS; the C example runs on Linux; not tested on phones |
| ICMP (ping) through TUN | not supported | — |
| macOS | not tested on this platform | the library builds for iOS/macOS; the `reality-client` program has not been tested on macOS |

There has been no third-party crypto review of the REALITY implementation
(details — `PLAN.md`, Stage 5).

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
