# vpn-core

[Русский](README.md) | **English**

[![CI](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg?logo=rust)
![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)

A **VLESS** client (with **REALITY** and **XTLS Vision**) written from
scratch in Rust. It runs a local proxy (SOCKS5 and HTTP) on your computer or
captures all traffic (TUN, like a VPN) and sends it to an Xray-core or
compatible server.

## Names

| Name | What it is |
|---|---|
| **vpn-core** | this repository |
| **reality-client** | the program you run (`bin/client/`) |
| **reality-core** | the library with the core itself: protocols, routing, DNS, TUN (`core/`); `reality-client` is built on it |
| **reality-ffi** (`libreality`) | the same core for embedding into apps in other languages via a C ABI (`ffi/`) |

## Platforms and status

- **Linux, Windows** — the `reality-client` program: ready.
- **macOS** — not tested on this platform.
- **Android, iOS** — only as a library for your own app: experimental
  ([LIBRARY.en.md](docs/LIBRARY.en.md)).

This is an educational and research project. Everything listed as "ready"
is covered by tests, including against real Xray-core, but there has been
no third-party security audit or crypto review of REALITY. It is not a
replacement for mature clients (v2rayN, sing-box, Xray).

> [!WARNING]
> **There are no prebuilt binaries yet.** [Releases](https://github.com/ERGFT/vpn-core/releases)
> is empty: you need to build the program yourself, which takes 5–10 minutes
> (below). When prebuilt files appear, installation, update and removal
> instructions will be here.

## Quick start

### 1. Install Rust

Rust 1.89 or newer is required.

**Linux** (Debian, Ubuntu; other distributions — their own package
manager):

```sh
sudo apt install build-essential git       # C compiler and git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Windows:**

1. Rust — the installer from [rustup.rs](https://rustup.rs) (the default
   `x86_64-pc-windows-msvc`).
2. [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/),
   the "Desktop development with C++" workload.
3. [Git](https://git-scm.com/download/win).

Details — [docs/WINDOWS.en.md](docs/WINDOWS.en.md).

### 2. Build

**Linux:**

```sh
git clone https://github.com/ERGFT/vpn-core.git
cd vpn-core
cargo build --release -p reality-client
# done: target/release/reality-client
```

**Windows** (PowerShell):

```powershell
git clone https://github.com/ERGFT/vpn-core.git
cd vpn-core
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
# done: target\release\reality-client.exe
```

### 3. Prepare the settings

You need a `vless://…` link — your server panel (3x-ui, Marzban, Remnawave)
or administrator gives it to you. Save it to a file: the link contains your
UUID, and command-line arguments are visible to other programs.

**Linux:**

```sh
printf '%s\n' 'vless://…your link…' > server.txt
chmod 600 server.txt
```

**Windows:** create a file `server.txt` in Notepad with the link on the
first line.

Several servers, "this goes direct, this goes through the server" rules,
subscriptions — in the [config file](docs/CONFIG.en.md).

### 4. Run

**Linux:**

```sh
./target/release/reality-client --server-file server.txt
```

**Windows:**

```powershell
.\target\release\reality-client.exe --server-file server.txt --system-proxy
```

The log shows the lines `сервер загружен …` ("server loaded") and
`прокси слушает … addr=127.0.0.1:1080` ("proxy listening"); log messages
are in Russian. The proxy is on `127.0.0.1:1080`, SOCKS5 and HTTP on one
port. With `--system-proxy` (Windows only) browsers and most programs go
through the client without any setup. Stop — `Ctrl+C`. All options —
[docs/CLI.en.md](docs/CLI.en.md).

### 5. Check the connection

In another terminal window (Windows 10 and newer already has `curl`):

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

If an HTML page comes back, the connection through the server works. In a
browser, set the SOCKS5 proxy `127.0.0.1:1080`; in Firefox also enable
"Proxy DNS when using SOCKS v5", otherwise site names go to the regular DNS.

### Updating and removing

- **Update:** in the `vpn-core` folder — `git pull`, then step 2 again.
- **Remove:** if you set up autostart, remove it first: on Windows
  `reality-client --service-uninstall` or `--autostart-uninstall`; on
  Linux `sudo systemctl disable --now reality-client` and delete what you
  copied following [`examples/reality-client.service`](examples/reality-client.service)
  (`/etc/systemd/system/reality-client.service`,
  `/usr/local/bin/reality-client`, `/etc/reality-client`). Then delete the
  `vpn-core` folder. If the client was killed with `--system-proxy` on and
  the internet is gone — `reality-client --system-proxy-off`.

## Features

Short version; the full list, how each feature was tested, and the
limitations — [docs/FEATURES.en.md](docs/FEATURES.en.md).

| Feature | Status |
|---|---|
| VLESS with `security=none`, `tls`, `reality`; XTLS Vision | ready |
| Transports `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` (HTTP/1.1, HTTP/2, HTTP/3) | ready |
| UDP over XUDP; Mux.Cool; `trojan` outbound | ready |
| Browser TLS fingerprints (`fp=chrome`, `firefox`, `safari` and others) | ready |
| SOCKS5, HTTP, `mixed` inbounds; config file in sing-box or Xray-core format | ready |
| Routing: domains, IPs, geosite/geoip, sing-box rule sets; sniffing | ready |
| Server groups (`selector`, `urltest`, `fallback`), subscriptions | ready |
| Own DNS: DoH, DoT, DoQ, cache, fake-IP | ready |
| TUN — all of the computer's traffic, kill switch (Linux, Windows) | ready |
| Local API (Clash API), metacubexd and yacd web dashboards | ready |
| Windows service, systemd | ready |
| System proxy and autostart at logon on Windows | not tested on this platform (only under Wine) |
| Anti-DPI: `fragment`, `noises` | experimental |
| Embedding into Android and iOS (C ABI) | experimental |
| `kcp` transport; ICMP (ping) through TUN | not supported |

Statuses: **ready** — works and is covered by tests; **experimental** —
works, but has little testing or the result depends on the network; **not
supported** — not available; **not tested on this platform** — the code
exists but has not been properly tested on this OS.

## Documentation

| | |
|---|---|
| [Command line and autostart](docs/CLI.en.md) | all options, Windows service, systemd |
| [Config file](docs/CONFIG.en.md) | sing-box and Xray formats, rules, server groups, subscriptions, `fragment` |
| [DNS](docs/DNS.en.md) · [TUN](docs/TUN.en.md) · [API](docs/API.en.md) | own DNS, all traffic through the client, control and web dashboards |
| [Link parameters](docs/LINK.en.md) | what is understood in `vless://…` |
| [Windows](docs/WINDOWS.en.md) | building and running on Windows |
| [Security model](docs/SECURITY-MODEL.en.md) | what is guaranteed, threats on a shared Wi-Fi network |
| [The core as a library](docs/LIBRARY.en.md) | embedding into apps |
| [All pages](docs/README.en.md) | core internals, testing, comparison with Xray-core |

## Security

- With `security=reality` the UUID goes only to a server that passed
  REALITY verification; a connection to a server that failed it is never
  handed to the app, even if the server has a genuine certificate. With
  `security=tls` — only to whoever presents a valid certificate for that
  name. With `security=none` anyone on the path to the server sees it.
- For proxied traffic in which the app passes the site name (SOCKS5 with a
  hostname, HTTP proxy, TUN with fake-IP), the name is resolved by the
  server and the local DNS does not see it. Exceptions — the app resolved
  the name itself, the `direct` outbound, DNS servers with
  `detour: direct` or `type: local`; details are in the security model.
- The client refuses to run a `security=none` link (everything in plain
  text) without `--allow-insecure`; by default the proxy listens only on
  `127.0.0.1`.

Details — [docs/SECURITY-MODEL.en.md](docs/SECURITY-MODEL.en.md). Found a
vulnerability — [SECURITY.md](SECURITY.md), not in public issues.

## Contributing

How to send a fix — [CONTRIBUTING.md](CONTRIBUTING.md#contributing); where to
get help — [SUPPORT.md](SUPPORT.md); code of conduct —
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md); what changed and what is
planned — [CHANGELOG.md](CHANGELOG.md#changelog); decision history by stage —
[PLAN.md](PLAN.md) (Russian).

## License

Copyright (C) 2026 ERGFT.

GNU General Public License v3.0 or later (`GPL-3.0-or-later`) — full text
in [`LICENSE`](LICENSE); every source file carries an
`SPDX-License-Identifier` tag.
The sources in `vendor/rustls-reality-patch` are a rustls patch and remain
under its licenses (Apache-2.0 / ISC / MIT, `LICENSE-*` files there).
Licenses of all dependencies included in the binary —
`scripts/third_party_licenses.sh` (to be attached to every release).
