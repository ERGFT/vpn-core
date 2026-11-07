# Testing, comparison and performance

[Русский](TESTING.md) | **English**

How the project is tested, the comparison with Xray-core, memory and speed measurements.

## Testing

One command — everything available on this machine:

```sh
scripts/ci.sh          # all available checks; optional tools run when installed
scripts/ci.sh --quick  # fmt, SPDX, doc links, script syntax, warning-free clippy, tests
```

`--quick` skips the release build, interoperability and end-to-end checks,
platform builds, and dependency patch checks. Without this flag, the script
runs every additional check available on the machine; missing tools are
reported as `SKIP`.

Individually:

| Script | What it checks |
|---|---|
| `cargo test --workspace` | all tests (unit and integration), all on loopback; with `GEO_DIR=…` and `--ignored` — also a check against real geosite/geoip databases |
| `scripts/fetch_sing_box.sh` + `ci.sh` | `.srs` parsing against real sing-box: sets of versions 1–3 built with `sing-box rule-set compile` (3000+ domains, IDN, suffixes, IPv4/IPv6 ranges), and 5 real geosite/geoip sets — record-by-record match with `rule-set decompile` |
| `scripts/interop_xray.sh` | 28 tests against **real Xray-core**: REALITY (including a classic X25519 site without ML-KEM), Vision (padding, sending a header while the client is silent, switching to direct copy, and rejection without `flow`), ML-DSA-65 and rejection of a wrong key, WebSocket and HTTPUpgrade without TLS and with TLS + `--ca`, gRPC over REALITY, Trojan, classic Shadowsocks AEAD (TCP and UDP echo), and SIP022/Shadowsocks 2022 (TCP and UDP echo for both required AES methods, including concurrent identical datagrams; all 28 tests passed in CI on head `2c0d14e`); all XHTTP modes over HTTP/1.1/h2 and with REALITY, including `downloadSettings`; HTTP/3 and `downloadSettings` with TLS (HTTP/3 over REALITY is unsupported); clear 404/400 errors, DNS over QUIC over VLESS, UDP and XUDP (Full Cone), Mux.Cool (20 connections — 3 streams), shared HTTP/2 connections for gRPC and XHTTP (`xmux`), fragmented ClientHello (`fragment`), and `fp=firefox/safari/…` fingerprints |
| `scripts/smoke_xray.sh` | the built binary, as a user would run it, against Xray-core: SOCKS5 with a password → REALITY → Vision → VLESS, 1 MiB of inner TLS round trip with a switch to direct copy, 20 UDP datagrams over XUDP; config file: `--check`, typos, `mixed` inbound (SOCKS5 and HTTP CONNECT), `block` rule, DNS inbound with a query through Xray |
| `scripts/tun_netns.sh` | TUN with `auto_route` in an isolated network namespace (root) against Xray-core: TCP (32 MiB round trip), `direct` without a loop, `route_exclude`, UDP/XUDP, QUIC sniffing on Chromium packets, DNS hijacking to 8.8.8.8, fake-IP, route restore on Ctrl+C, network after `kill -9`, `strict_route` kill switch and `--tun-cleanup` |
| `scripts/cross_windows.sh` | Windows `.exe` (mingw-w64) + all tests and the smoke test against Xray-core under Wine, `--system-proxy`: registry write and restore on Ctrl+C; service: install (config copied to ProgramData), start, clean stop and removal; autostart at logon |
| `scripts/interop_go_reality.sh` | 4 tests against a REALITY server built on the Go library `XTLS/REALITY` (needs Go ≥ 1.27) |
| `scripts/smoke_e2e.sh` | the binary against the Go test server; an incompatible link is rejected at startup |
| `scripts/check_chrome_fingerprint.sh` | whether the Chrome reference in utls has changed: cipher suites, extension set, `signature_algorithms` (worth running every month or two) |
| `scripts/check_license_headers.sh` | every own source file has an `SPDX-License-Identifier` header |
| `scripts/check_doc_links.py` | links between documents point to an existing file and a heading for the `#anchor` (as GitHub computes it) |
| `scripts/third_party_licenses.sh` | `THIRD-PARTY-LICENSES.html` from `Cargo.lock` (cargo-about); fails on a dependency with a license not in `about.toml` |
| `cargo run -p fpcheck -- --server 'vless://...'` | JA3/JA4 of this client's real ClientHello |

Unit tests in `core/src/transport/tcp_tls.rs` use a paused clock to verify
IPv4/IPv6 interleaving, fast fallback to the other family, immediate retry
after a refusal, the address-attempt limit, a maximum of two concurrent
attempts, and an overall connection deadline without external DNS or network
dependencies.

`cargo test -p reality-core protocol_architecture_test` runs the internal test
proxy: typed settings and builder, TCP and UDP echo through `Outbound`/router,
settings validation, an unavailable-server error, a timeout, tracker
cancellation, and router replacement while an existing TCP stream stays open.
The fixture is included through `#[cfg(test)]`; it is not a user protocol and
is absent from release builds.

The GitHub workflow `.github/workflows/ci.yml` runs on pushes to `main` and
pull requests. The `linux` job runs `scripts/ci.sh`, checks the C ABI and
dependency license list, and runs TUN in a network namespace; the TUN step is
skipped for pull requests from forks. The `windows` job runs on **real
Windows** and performs tests, builds the `.exe` (downloadable from the run
page under "Artifacts"), and runs `scripts/windows_live_test.ps1` to check the
service, its folder permissions, and TUN with real traffic.

Separate jobs run as well: `audit` checks advisories and dependency sources,
including the patched rustls; `msrv` checks the workspace with Rust 1.89;
`coverage` uploads an lcov report without a coverage threshold; and `secrets`
scans the full Git history. The weekly scheduled workflow runs only `audit`.
The `mobile` job is described below. See the [release guide](RELEASING.en.md).
For a new release,
use a version and tag that have not been published before; `v0.1.0` already
exists. First run the non-publishing preflight on the exact `main` SHA, then
push the new tag at that checked SHA. Preflight does not create a release; the
tag workflow publishes a release (not a draft) only after the CLI and every
SDK target build successfully. Verify provenance with
`gh attestation verify <file> --repo ERGFT/vpn-core`.

The separate `mobile` job cross-compiles `reality-ffi` for Android arm64-v8a
and iOS arm64. It has `continue-on-error: true`, so a failed mobile build does
not fail the workflow. A successful build confirms library compilation, not
execution on a device.

The release workflow attaches C ABI SDKs for Linux x86_64, Windows x86_64,
macOS arm64, Android arm64-v8a, and iOS arm64 alongside the CLI. Archive
contents and metadata vary by version; do not assume current packaging features
are present in older ZIPs.

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
| time to first data byte | 25.4 ms | 35.8 ms |
| throughput | 625 MiB/s | 572 MiB/s |

This is a historical summary recorded in the [project plan](../PLAN.en.md)
for the 2026-09-26 remeasurement. The repository does not contain the raw
JSON/CSV for the three runs, the machine model, or the run-to-run spread. The
table therefore does not document how those runs were aggregated or support
a conclusion about a meaningful performance difference; the earlier “tie”
labels cannot be confirmed from the available raw data. One invocation of the
current script performs one measurement per client and writes JSON/CSV under
`target/stage8/`; it does not repeat the measurement three times. For a new
comparison, retain each run's data, environment, and script SHA separately.

Xray-core covers a broader range of protocols and routing scenarios. `vpn-core`
also includes DNS, TUN, rules, server groups, subscriptions, a local API, and a
C ABI, while its protocol coverage and ecosystem remain narrower. This table
compares only the specific scenario below; it does not compare feature
completeness.

⚠️ Time to the **first data byte**, not to the SOCKS5 CONNECT reply: Xray
answers CONNECT in advance, without waiting for the server connection (it
replies "success" even if there is no server), so its CONNECT reply cannot be
compared with ours. Details — `PLAN.en.md`, Stage 8.

## Comparison with xray-rust

Use the dedicated scenario for a new comparison; the older table above is a
separate Xray-core result:

```sh
scripts/fetch_xray.sh
scripts/stage6_compare_with_xray_rust.sh
```

The harness pins `xray-rust` to tag `v0.8.0` (commit
[`fcce4be`](https://github.com/aimalygin/xray-rust/tree/fcce4be2771c1fb3f11e9503741d39a4d8df314e))
and uses Xray-core `v26.9.9` as the shared VLESS + REALITY + Vision server.
Both clients run on the same host with the same parameters, Chrome
fingerprint, eight concurrent flows, and an inner TLS 1.3 echo. Each flow sends
and verifies a 64 KiB echo block before sending the next; all eight flows run
concurrently. Client order alternates across five runs. Each run
saves JSON and RSS/PSS CSV; the final
manifest records commits, binary versions, SHA-256 hashes, OS, and CPU model.
Metrics include throughput, time to first application data after the TLS
handshake, idle/peak RSS/PSS, client CPU milliseconds per transferred GiB, and
application-request recovery.

Override settings with `RUNS`, `CONNS`, `MIB`, and `OUTDIR`. Results are written
to `target/stage6-xray-rust/`; by default, each of five runs transfers 8 × 64
MiB in each direction for each core. The shared server is then stopped for
`OUTAGE_SECS` (2 seconds by default) and restarted while the client process stays
alive. `stage6_recovery_probe.py` retries SOCKS5 CONNECT and an inner TLS 1.3
echo until the first successful request. The time from server TCP readiness to
that echo is stored separately in `*.recovery.json`; `RECOVERY_POLL_MS` sets the
polling interval and `RECOVERY_TIMEOUT_SECS` sets the deadline. Preserve all
parameters and raw JSON/CSV, and do not draw conclusions from only the best run.
This is a loopback server-outage scenario, not a physical network-interface
change: it does not model WAN loss, energy use, or handling of the host
`rc_network_changed` signal. Conclusions will follow only after the full
methodology succeeds.

### First published run

[GitHub Actions run #41678957797](https://github.com/ERGFT/vpn-core/actions/runs/41678957797)
successfully completed all five paired runs on `ubuntu-24.04` (Azure, x86_64,
AMD EPYC 9V74, 4 logical CPUs). The table shows medians; the full manifest and
per-run JSON/CSV files are available in the workflow artifact for 30 days.

| Metric | vpn-core | xray-rust v0.8.0 | Observation in this scenario |
|---|---:|---:|---|
| Throughput, MiB/s | 24.280 | 23.967 | vpn-core was about 1.3% higher |
| First byte after TLS handshake, ms | 40.994 | 41.140 | vpn-core was about 0.4% faster |
| Peak PSS, KiB | 11,405 | 14,641 | vpn-core was about 22.1% lower |
| CPU, ms per transferred GiB | 980 | 1,260 | vpn-core used about 22.2% less CPU |
| Recovery after server restart, ms | 86.230 | 45.939 | xray-rust recovered faster |

This is one cloud runner, loopback, one profile, and five repetitions; Rust
compiler versions differed (`1.99.1` for vpn-core and `1.96.0` for xray-rust).
Treat it as a reproducible baseline, not an independent VPS benchmark or a
claim of an advantage on real networks. In particular, recovery includes a
50 ms polling interval and must not be read as a universal network-change
recovery time.

## Performance and memory

Benchmarks and the allocator choice — `PLAN.en.md`, Stages 0 and 7. In short:
one buffer (17 KiB — so that a whole TLS record fits, which matters for
Vision) per connection direction, no global pool; the system allocator by
default (`--features mimalloc` is optional, and gave a larger idle RSS in
measurements).

```sh
cargo bench -p bench
cargo run -p bench --bin memwatch -- --pid <PID> --duration-secs 30 --csv rss.csv   # Linux
```
