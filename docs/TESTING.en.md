# Testing, comparison and performance

[Русский](TESTING.md) | **English**

How the project is tested, the comparison with Xray-core, memory and speed measurements.

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
| `cargo test --workspace` | all tests (unit and integration), all on loopback; with `GEO_DIR=…` and `--ignored` — also a check against real geosite/geoip databases |
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
with real traffic. Release — `git tag v0.1.0 && git push origin v0.1.0`:
`.github/workflows/release.yml` builds Windows and Linux binaries with
SHA-256 sums, `LICENSE`, `THIRD-PARTY-LICENSES.html` and an SBOM
(`reality-client.sbom.cdx.json`, CycloneDX) into a draft release; the
binaries' provenance is signed (GitHub attestation) — to check:
`gh attestation verify reality-client-linux-x86_64 --repo ERGFT/vpn-core`.

Xray-core for tests: `scripts/fetch_xray.sh` (download a release) or
`scripts/build_xray_from_source.sh` (build from source via git — for
environments without access to releases and `proxy.golang.org`). In such an
environment the Go test server is prepared by
`scripts/interop_sandbox_bootstrap.sh`.

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
