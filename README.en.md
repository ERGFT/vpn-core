# vpn-core

**A compact VLESS core in Rust** for a local proxy, a TUN client, or embedding into apps through a C ABI.

Supports **REALITY** and **XTLS Vision**, and works with compatible Xray-core servers. This is an experimental project: check the status table and the full [feature matrix](docs/FEATURES.en.md) before relying on specific features or mobile integration.

This repository provides an embeddable core library. It includes
`reality-client` as a CLI client and usage example, but it is not a ready-made
graphical VPN app. A host app supplies its own UI, OS permissions, and platform
lifecycle integration; see the [C ABI guide](docs/LIBRARY.en.md).

[Русский](README.md) | **English**

[![CI](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg?logo=rust)](https://www.rust-lang.org/)

## Choose your path

| Your goal | Start here |
|---|---|
| Run the client on your computer | [Quick start](#quick-start) |
| Embed the core in your app | [For developers](#for-developers) · [library guide](docs/LIBRARY.en.md) |
| Check protocol support and limits | [Features and status](#features-and-status) · [full matrix](docs/FEATURES.en.md) |
| Understand internals and testing | [Documentation](#documentation) |

## Project overview

| Component | Purpose |
|---|---|
| `reality-core` (`core/`) | Library for protocols, routing, DNS, and TUN |
| `reality-client` (`bin/client/`) | CLI client with SOCKS5/HTTP proxy and TUN |
| `reality-ffi` (`ffi/`, `libreality`) | C ABI for embedding the core into apps written in other languages |

### Platforms and maturity

| Platform | CLI client | Integration SDK | Status |
|---|---:|---:|---|
| Linux x86_64 | Yes | Yes | Client and library are checked in CI |
| Windows x86_64 | Yes | Yes | Client and library are checked in CI; some system features have specific limits |
| macOS arm64 | No | Yes | SDK is built for release packages; running an app on-device is not confirmed |
| Android arm64-v8a | No | Yes | Experimental integration; the app must connect the TUN itself |
| iOS arm64 | No | Yes | SDK cross-link only; no `NEPacketTunnelFlow` adapter, and no VPN app has been tested on-device |

The release workflow builds SDK archives for these ABIs when a versioned tag is pushed. Each archive includes the library, `reality.h`, a minimal C example, and API documentation. Check [Releases](https://github.com/ERGFT/vpn-core/releases) for published packages; if none are available, build from source using the [library guide](docs/LIBRARY.en.md).

The Releases page may contain prereleases for integration testing. Check the
tag and **Pre-release** label before downloading: these packages are not stable
releases and correspond to a specific commit, not the current `main` branch.

## Quick start

Rust **1.89 or newer** is required. On Windows, install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the *Desktop development with C++* workload and [Git](https://git-scm.com/download/win). See the [Windows guide](docs/WINDOWS.en.md).

**Linux**

```sh
sudo apt install build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/ERGFT/vpn-core.git
cd vpn-core
cargo build --release -p reality-client
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/ERGFT/vpn-core.git
cd vpn-core
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
```

Save the `vless://…` link from your server administrator or panel in `server.txt`. It contains a UUID; restrict access to the file and do not publish it.

```sh
./target/release/reality-client --server-file server.txt
```

On Windows, run `.\target\release\reality-client.exe --server-file server.txt --system-proxy`. The proxy listens on `127.0.0.1:1080` (SOCKS5 and HTTP on the same port). Check the connection with:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

The executable is in `target/release/` on Linux and `target\release\` on Windows. More options and setup details: [CLI](docs/CLI.en.md) · [configuration](docs/CONFIG.en.md) · [Windows guide](docs/WINDOWS.en.md).

## For developers

The SDK lets an application embed `vpn-core` as its networking core. It can connect to VLESS and Trojan servers; its public interface is a C ABI. The [library guide](docs/LIBRARY.en.md) and [`reality.h`](ffi/include/reality.h) describe memory ownership, threads, callbacks, and platform integration.

| API | Purpose |
|---|---|
| `rc_validate` | Validate configuration before startup; return success or failure without exposing its values |
| `rc_start` / `rc_stop` | Create, start, and cleanly stop a core instance |
| `rc_request` | Call the core API directly, without a network HTTP server or token |
| `rc_reload` | Apply a new configuration without recreating the whole app |
| `rc_network_changed` | Notify the core of a network change detected by the host application |
| `rc_is_alive` / `rc_last_error_code` | Check whether the instance is running; get its error category after it exits |
| Callbacks | Receive events/logs and provide platform functions such as socket protection or UID lookup |

The [library guide](docs/LIBRARY.en.md) covers CMake and pkg-config, platform
shared/static linking, checksum/manifest verification, and connecting an SDK
from an extracted ZIP. Public headers and examples are in [`ffi/`](ffi/).

## Features and status

| Layer | Capabilities |
|---|---|
| Protocols and flow | VLESS, Trojan, and XTLS Vision |
| Connection security | REALITY and TLS |
| Transports | TCP, WebSocket, gRPC, HTTPUpgrade, and XHTTP |
| Inbounds | SOCKS5, HTTP, and mixed |
| Outbounds | Include VLESS, Trojan, direct, block, DNS, and server groups. SOCKS5 and HTTP CONNECT are supported only for TCP and only in sing-box format; `detour` chains are also available there |
| Configuration | Supported subsets of the Xray-core and sing-box formats; rules, server groups, and subscriptions |
| Networking and routing | UDP over VLESS through XUDP, DNS (DoH/DoT/DoQ), TUN, kill switch, and IPv4/IPv6 selection (Happy Eyeballs) |
| Management and platform integration | Local Clash API, metacubexd and yacd dashboards, systemd, and Windows service; Android/iOS C ABI integration remains experimental, and no iOS `NEPacketTunnelFlow` adapter is provided |
| Experimental | `fragment`, `noises`, and application routing integration |
| Not supported | KCP transport; ICMP/ping through TUN |
Importing an Xray-core or sing-box config does not imply support for every option in those formats.
The Hysteria 2 TCP/UDP runtime is wired into the outbound factory, sing-box configuration, and URI subscriptions. A local Windows TCP/UDP echo run against the official v2.13.0 server passed on PR #201 head `fdc24a8` with a custom CA. This is a limited loopback smoke test; overall production readiness, network handover, and connection recovery remain unverified. See the [Hysteria 2 plan](docs/HYSTERIA2_IMPLEMENTATION_PLAN.en.md).

The [feature matrix](docs/FEATURES.en.md) lists capabilities, maturity, and specific checks. Scenarios and test results are documented in the [testing guide](docs/TESTING.en.md).

## Choosing a core

These projects cover different scopes. This table compares their intended use, not quality or speed.

| Project | Strength | Consider it when |
|---|---|---|
| **vpn-core** | Focused Rust VLESS client core; CLI and C ABI for embedding | You need VLESS/REALITY and a custom app integration |
| [Xray-core](https://github.com/XTLS/Xray-core) | Broad proxy platform and network scenarios | You need the wider Xray ecosystem or more protocols |
| [sing-box](https://github.com/SagerNet/sing-box) | Multi-protocol proxy with many inbounds, outbounds, and network features | You need a general-purpose proxy platform or an existing sing-box integration |

The [test results](docs/TESTING.en.md) describe the local Xray-core comparison and a separate reproducible methodology for `xray-rust`, including recovery after a test-server outage. Each comparison applies only to its stated setup and does not establish general superiority.

## Documentation

| Topic | Guides |
|---|---|
| Running and configuration | [CLI](docs/CLI.en.md) · [config](docs/CONFIG.en.md) · [`vless://` parameters](docs/LINK.en.md) |
| Networking | [DNS](docs/DNS.en.md) · [TUN](docs/TUN.en.md) · [application routing](docs/APPLICATION_ROUTING.en.md) |
| Development | [core as a library](docs/LIBRARY.en.md) · [API](docs/API.en.md) · [internals](docs/README.en.md) |
| Reliability and security | [features and tests](docs/FEATURES.en.md) · [comparison and methodology](docs/TESTING.en.md) · [security model](docs/SECURITY-MODEL.en.md) |

The internal [REALITY review](docs/reviews/2026-11-04-reality-internal-review.en.md)
describes its scope and limitations. It is an internal report, not an
independent external audit.

## Security and limitations

This is an educational and research project with no independent external security audit. REALITY has received only an internal review; its scope is described in the [report](docs/stage5-crypto-review-and-interop.en.md). The [security model](docs/SECURITY-MODEL.en.md) explains threats, DNS behavior, and failure handling in detail. A listed feature does not guarantee security for every configuration.

- With `security=none`, traffic is not encrypted; the CLI requires the explicit `--allow-insecure` option. The sing-box `allow_insecure` setting is documented in the [configuration guide](docs/CONFIG.en.md).
- With REALITY, the UUID is sent only after REALITY verification. With TLS, the server must present a valid certificate.
- By default, the local proxy listens only on `127.0.0.1`. DNS behavior depends on traffic type and configuration; see the [security model](docs/SECURITY-MODEL.en.md).
- Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
- The project is licensed under [GPL-3.0-or-later](LICENSE); check how the license applies to your app and distribution before embedding the core.

## Contributing and license

Contributions and help: [CONTRIBUTING.md](CONTRIBUTING.md) · [SUPPORT.md](SUPPORT.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [CHANGELOG.md](CHANGELOG.md).

Copyright (C) 2026 ERGFT. The main code is distributed under GNU GPL v3 or later. The patch in `vendor/rustls-reality-patch` keeps the rustls licenses; dependency licenses are generated by [`scripts/third_party_licenses.sh`](scripts/third_party_licenses.sh).
