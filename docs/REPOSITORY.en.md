# Repository map

[Русский](REPOSITORY.md) | **English**

Where to find code, checks, and integration material. The architecture is
described in [ARCHITECTURE.en.md](ARCHITECTURE.en.md); the full guide index is
in [README.en.md](README.en.md).

## Main components

| Path | Purpose |
|---|---|
| `core/` | Rust `reality-core` library: inbounds, routing, DNS, TUN, proxy outbounds, VLESS/Trojan, transports, and REALITY |
| `bin/client/` | `reality-client`: CLI, core startup, Windows service, and system proxy |
| `bin/fpcheck/` | utility for capturing and analyzing JA3/JA4 ClientHellos |
| `ffi/` | `reality-ffi`: C ABI, `reality.h`, examples, and ABI baseline for app integration |
| `bench/` | Criterion benchmarks and `memwatch`/`warmup_probe` utilities |
| `fuzz/` | fuzz targets for parsers, network headers, and subscriptions |
| `interop/go-reality-server/` | Go REALITY server for interoperability checks |
| `vendor/rustls-reality-patch/` | patched rustls copy; scope and patch-porting notes are in [RUSTLS_PATCH.en.md](RUSTLS_PATCH.en.md) |
| `vendor/smoltcp-window-patch.md`, `vendor/smoltcp-window-patch/` | project notes for the smoltcp window patch; upstream sources and licenses are kept separately |

## Inside `core/src/`

| Directory/file | Purpose |
|---|---|
| `app/` | core lifecycle, config, SOCKS5/HTTP/mixed/DNS/TUN inbounds, rules and router, DNS, groups, subscriptions, and local API |
| `app/config/` | configuration model and parsers for native files, links, and supported subsets of sing-box/Xray formats |
| `app/access.rs` | allowed IP/network lists and temporary blocks after authentication failures |
| `app/dns_in.rs`, `app/dns/` | UDP/TCP DNS inbound, upstream servers, cache, and fake-IP |
| `app/rules.rs`, `app/ruleset.rs`, `app/geo.rs` | routing predicates, local rule sets, and geosite/geoip databases |
| `app/sniff.rs`, `app/sniff_quic.rs` | domain detection from supported TCP protocols and QUIC Initial packets |
| `app/group.rs`, `app/subscription.rs`, `app/http_client.rs` | outbound groups, subscription updates, and HTTP requests for subscriptions/node checks |
| `app/stats.rs`, `app/events.rs` | connection and traffic tracking, plus the API event bus |
| `app/api.rs`, `app/clash.rs` | local control/observation API and selected Clash-compatible API responses |
| `app/socks_out.rs`, `app/http_connect_out.rs` | SOCKS5 and HTTP CONNECT TCP outbounds, including `detour` chains |
| `app/vless_out.rs`, `app/trojan_out.rs`, `app/outbound.rs` | proxy outbound construction and shared TCP/UDP interfaces |
| `app/tun/` | TUN flows, routes, UDP, and the platform WFP implementation |
| `connection_owner.rs` | trusted connection-owner metadata supplied by the host app |
| `vless/`, `trojan.rs` | VLESS/Trojan link and protocol formats, Vision, UDP, XUDP, and Mux.Cool |
| `transport/` | protocol-independent `TransportConfig`; TCP/TLS/REALITY, WebSocket, gRPC, HTTPUpgrade, XHTTP, QUIC/DoQ/HTTP/3, HTTP/2 pools, fragmentation, and browser imitation |
| `reality/`, `fingerprint/` | REALITY handshake and verification; ClientHello profiles, capture, JA3/JA4 |
| `socks5/`, `relay.rs`, `http1.rs` | protocol framing, bidirectional relay, and HTTP/1.1 response parsing |
| `net_protect.rs`, `hostname.rs`, `fsutil.rs`, `redact.rs` | bypassing TUN for the core's own sockets and shared networking/file helpers with secret redaction |

## Checks and integration

| Path | Purpose |
|---|---|
| `core/tests/` | core integration tests, including interop with Xray-core and the Go REALITY server |
| `scripts/ci.sh`, `.github/workflows/ci.yml` | local and GitHub CI checks; the workflow covers Linux, real Windows, MSRV, coverage, dependency audits, and advisory mobile cross-builds |
| `scripts/package_ffi_sdk.py`, `scripts/ffi_sdk_metadata.py`, `scripts/check_ffi_sdk.py` | SDK archive packaging, CMake/pkg-config metadata, and archive/manifest verification |
| `scripts/sdk-consumer/`, `scripts/test_ffi_sdk_consumer.py` | independent C/C++ consumers built from extracted SDKs; run on supported desktop runners, while Android/iOS are cross-linked only |
| `.github/workflows/release.yml` | manual non-publishing preflight and publication when a version tag is pushed |
| `.github/workflows/fuzz.yml`, `benchmark-xray-rust.yml` | fuzz runs and comparative benchmark workflow |
| `scripts/interop_*.sh`, `smoke_*.sh`, `tun_netns.sh` | interoperability, CLI smoke, and TUN checks; exact coverage is listed in [TESTING.en.md](TESTING.en.md) |
| `examples/` | sing-box/Xray config examples and a systemd unit |

## Public material

- `docs/` — technical guides in Russian and English, indexed in the
  [documentation catalog](README.en.md).
- `README.md`, `README.en.md`, `CHANGELOG.md` — project overview and history of
  published and upcoming changes.
- `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `CODE_OF_CONDUCT.md` —
  contribution rules, vulnerability reporting, support, and community rules.
- `.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md` — issue and
  pull request templates.
- `PLAN.md` / `PLAN.en.md` — the Russian historical decision log and its
  English translation; neither is the source of current project status.
  Actual capabilities and limits are in
  `docs/FEATURES.en.md`.
