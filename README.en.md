# vpn-core

**A compact VLESS core in Rust** for a local proxy, a TUN client, or embedding into apps through a C ABI.

Supports **REALITY** and **XTLS Vision**, and works with compatible Xray-core servers. This is an experimental project: check the status table and the full [feature matrix](docs/FEATURES.en.md) before relying on specific features or mobile integration.

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
| iOS arm64 | No | Yes | Experimental integration; no ready-to-use client app |

The release workflow builds SDK archives for these ABIs when a versioned tag is pushed. Each archive includes the library, `reality.h`, a minimal C example, and API documentation. Check [Releases](https://github.com/ERGFT/vpn-core/releases) for published packages; if none are available, build from source using the [library guide](docs/LIBRARY.en.md).

## Quick start

Rust **1.89 or newer** is required. On Windows, install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the *Desktop development with C++* workload and [Git](https://git-scm.com/download/win). See the [Windows guide](docs/WINDOWS.en.md).

**Linux**

```sh
sudo apt install build-essential git
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

The SDK is for apps that need an embedded VLESS client. Its public interface is a C ABI. The [library guide](docs/LIBRARY.en.md) and [`reality.h`](ffi/include/reality.h) describe memory ownership, threads, callbacks, and platform integration.

| API | Purpose |
|---|---|
| `rc_validate` | Validate configuration before startup; return success or failure without exposing its values |
| `rc_start` / `rc_stop` | Create, start, and cleanly stop a core instance |
| `rc_request` | Call the core API directly, without a network HTTP server or token |
| `rc_reload` | Apply a new configuration without recreating the whole app |
| `rc_is_alive` | Check the instance state and detect a terminal error |
| Callbacks | Receive events/logs and provide platform functions such as socket protection or UID lookup |

The [library guide](docs/LIBRARY.en.md) has a minimal example and lists each SDK archive's contents. Public headers and examples are in [`ffi/`](ffi/).

## Features and status

| Area | Support |
|---|---|
| Protocol | VLESS, REALITY, TLS, XTLS Vision; TCP, WebSocket, gRPC, HTTPUpgrade, and XHTTP |
| Network | SOCKS5/HTTP/mixed inbounds; sing-box SOCKS5 and HTTP CONNECT TCP outbounds with `detour` chains; fast IPv4/IPv6 address selection (Happy Eyeballs); UDP/XUDP, DNS (DoH/DoT/DoQ), TUN, kill switch |
| Configuration | Xray-core format and part of sing-box format; rules, server groups, subscriptions |
| Management | Local Clash API, metacubexd and yacd dashboards, systemd and Windows service |
| Experimental | Android/iOS through C ABI; `fragment` and `noises`; application routing integration |
| Not supported | KCP transport; ICMP/ping through TUN |

Importing a sing-box config **does not mean full compatibility** with all of its options. See the [full matrix](docs/FEATURES.en.md) for each feature's status and test coverage.

## Choosing a core

These projects cover different scopes. This table compares their intended use, not quality or speed.

| Project | Strength | Consider it when |
|---|---|---|
| **vpn-core** | Focused Rust VLESS client core; CLI and C ABI for embedding | You need VLESS/REALITY and a custom app integration |
| [Xray-core](https://github.com/XTLS/Xray-core) | Broad proxy platform and network scenarios | You need the wider Xray ecosystem or more protocols |
| [sing-box](https://github.com/SagerNet/sing-box) | Multi-protocol proxy with many inbounds, outbounds, and network features | You need a general-purpose proxy platform or an existing sing-box integration |

The [test results](docs/TESTING.en.md) describe the local Xray-core comparison and a separate reproducible methodology for `xray-rust`. Each comparison applies only to its stated setup and does not establish general superiority.

## Documentation

| Topic | Guides |
|---|---|
| Running and configuration | [CLI](docs/CLI.en.md) · [config](docs/CONFIG.en.md) · [`vless://` parameters](docs/LINK.en.md) |
| Networking | [DNS](docs/DNS.en.md) · [TUN](docs/TUN.en.md) · [application routing](docs/APPLICATION_ROUTING.en.md) |
| Development | [core as a library](docs/LIBRARY.en.md) · [API](docs/API.en.md) · [internals](docs/README.en.md) |
| Reliability and security | [features and tests](docs/FEATURES.en.md) · [comparison and methodology](docs/TESTING.en.md) · [security model](docs/SECURITY-MODEL.en.md) |

## Security and limitations

This is an educational and research project. It has not had a third-party security audit or cryptographic review of REALITY. A listed feature is not a security guarantee for every configuration.

- With `security=none`, traffic is not encrypted; this mode requires the explicit `--allow-insecure` option.
- With REALITY, the UUID is sent only after REALITY verification. With TLS, the server must present a valid certificate.
- By default, the local proxy listens only on `127.0.0.1`. DNS behavior depends on traffic type and configuration; see the [security model](docs/SECURITY-MODEL.en.md).
- The project is licensed under [GPL-3.0-or-later](LICENSE). Check how the license applies to your app and distribution before embedding the core.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md), not in a public issue.

## Contributing and license

Contributions and help: [CONTRIBUTING.md](CONTRIBUTING.md) · [SUPPORT.md](SUPPORT.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [CHANGELOG.md](CHANGELOG.md).

Copyright (C) 2026 ERGFT. The main code is distributed under GNU GPL v3 or later. The patch in `vendor/rustls-reality-patch` keeps the rustls licenses; dependency licenses are generated by [`scripts/third_party_licenses.sh`](scripts/third_party_licenses.sh).
