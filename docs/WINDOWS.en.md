# reality-client on Windows

[Русский](WINDOWS.md) | **English**

The client and the library use nothing Unix-specific (checked in the code:
no `std::os::unix`, `libc`, `/proc`). The only part of the project that runs
on Linux only is the auxiliary memory sampler `bench/src/bin/memwatch.rs`
(it reads `/proc`); it does not affect the client build.

## 0. The prebuilt .exe and how it was tested

In the development environment the Windows version is cross-compiled
(`scripts/cross_windows.sh`: target `x86_64-pc-windows-gnu`, mingw-w64
linker) and tested under **Wine 9**:

- all 210 workspace tests, built for Windows, pass under Wine;
- a smoke test against real Xray-core with the same `.exe`: SOCKS5 with a
  password → REALITY → XTLS Vision (switch to direct copy in both
  directions), 1 MiB of inner TLS, UDP over XUDP; config file, subscription,
  DNS inbound;
- `--system-proxy`, installing and removing the service, autostart at logon.

The resulting file is `dist\windows\reality-client.exe` (~11 MB, depends only
on Windows system DLLs).

> To be honest: Wine is not real Windows. The network stack and the console
> are emulated there; this `.exe` has not been run on real Windows. The
> "native" build (MSVC, section 2) has not been run either — it is described
> from the `aws-lc-sys` documentation.

## 1. What to install

1. **Rust** — <https://rustup.rs>. During installation choose the
   `stable-x86_64-pc-windows-msvc` toolchain (the default). Check:
   `rustup show active-toolchain` → should contain `msvc`.
2. **Visual Studio Build Tools** — <https://visualstudio.microsoft.com/visual-cpp-build-tools/>,
   the **"Desktop development with C++"** workload. It is needed because the
   TLS cryptography (`aws-lc-rs` → `aws-lc-sys`) is built from C code.
3. **NASM is optional.** Without it, `aws-lc-sys` can use prebuilt assembler
   object files, but only if explicitly allowed by the
   `AWS_LC_SYS_PREBUILT_NASM=1` variable (the script below sets it itself).
   CMake is not needed by default.

## 2. Building

From the repository root, in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
```

Or manually:

```powershell
$env:AWS_LC_SYS_PREBUILT_NASM = "1"   # if NASM is not installed
cargo build --release -p reality-client
```

Result: `target\release\reality-client.exe`.

An alternative without Visual Studio is the `stable-x86_64-pc-windows-gnu`
toolchain (MSYS2/mingw-w64): that is how the `.exe` from section 0 is built
and tested.

## 3. Running

```powershell
.\target\release\reality-client.exe --server "vless://UUID@host:443?encryption=none&security=reality&sni=site&pbk=KEY&sid=ID&type=tcp" --listen 127.0.0.1:1080
```

Put the link in double quotes: it contains `&`, which the shell would
otherwise interpret. It is safer to put the link in a file and run with
`--server-file link.txt`: command-line arguments are visible to other
programs and users of the computer, and the link contains your UUID. The
console will show the lines `сервер загружен ...` ("server loaded") and
`прокси слушает ... addr=127.0.0.1:1080` ("proxy listening"). For a more
detailed log: `$env:RUST_LOG = "debug"` before starting.

Stop with `Ctrl+C`.

## 4. How to use it

The client starts a proxy on `127.0.0.1:1080` (or the `--listen` address):
one port serves both **SOCKS5** and **HTTP proxy**. It is not a system-wide
VPN: traffic goes through it only for programs that use this proxy.

- **The easiest way is `--system-proxy`:** while running, the client turns
  on the Windows system proxy ("Settings → Network & Internet → Proxy"), and
  Chrome, Edge, Firefox (with "Use system proxy settings"), the app store and
  most programs go through it. On exit (Ctrl+C or closing the window) the
  previous settings are restored. If the client was terminated abnormally
  (for example, from Task Manager) and the internet "disappeared" —
  `reality-client.exe --system-proxy-off`.

- **Firefox:** Settings → Network Settings → Manual proxy configuration →
  SOCKS host `127.0.0.1`, port `1080`, SOCKS v5, and the "Proxy DNS when
  using SOCKS v5" checkbox.
- **curl** (included in Windows 10+):
  `curl --socks5-hostname 127.0.0.1:1080 https://example.com`
- **Chrome/Edge** — with a launch flag:
  `--proxy-server="socks5://127.0.0.1:1080"`.

### Autostart

- **With the system proxy, at Windows logon** (regular user):
  `reality-client.exe --autostart-install --config C:\path\client.toml --system-proxy`.
  The client starts without a window; the log is `reality-client.log` next
  to the config. Remove: `--autostart-uninstall`.
- **Service — for TUN** (starts before logon, run as administrator):
  `reality-client.exe --service-install --config C:\path\client.toml`.
  The config, the files next to it, `reality-client.exe` and `wintun.dll` are
  copied to `C:\ProgramData\RealityClient` — only administrators can change
  this folder (the service runs as SYSTEM, and a regular program cannot
  replace its files). The log is there too. Changed the config? Repeat
  `--service-install`; remove the service with `--service-uninstall`. The
  service shows up in "Services" (services.msc) as "Reality Client" and
  restarts itself after a crash.

## 5. More options

- `--config client.toml` — config file: multiple inbounds and outbounds,
  routing rules (ads to `block`, Russian sites and the local network direct,
  etc.). Example — `examples/client.toml`. Write Windows paths in the file in
  single quotes: `link_file = 'C:\Users\me\server.txt'`. Check the file
  without starting anything: `--config client.toml --check`.
- **TUN — like a real VPN** (the `type = "tun"` inbound, see the README):
  traffic from all programs goes through the client. Run as administrator
  and put `wintun.dll` next to `reality-client.exe` (from
  [wintun.net](https://www.wintun.net/), the `amd64` folder).
  ⚠️ On Windows TUN has not yet been tested on a real machine — it only
  builds. If something goes wrong, close the client: the routes disappear
  together with the interface.
- Own DNS (the `[dns]` section and the `type = "dns"` inbound in the config,
  see the README): if you set `127.0.0.1` in "Settings → Network & Internet →
  Adapter properties → DNS", all programs' name lookups go through the
  client — encrypted (DoH/DoT) and through the server, not in plain text over
  Wi-Fi. Remember to set DNS back to "Automatic" when the client is not
  running, otherwise names will stop resolving.
- `--sniff` — if a program sends the proxy an IP address instead of a site
  name, recover the name from the first bytes of the connection (needed for
  domain rules).

- `--auth user:password` — require a username and password for the proxy.
  Without it the client agrees to listen only on `127.0.0.1`; to open the
  proxy to other devices on the network (`--listen 0.0.0.0:1080`), a password
  is required.
- `--allow-ip 192.168.1.23` — if the proxy is open to the network, let in
  only your own devices. SOCKS5 and HTTP proxy are not encrypted: on shared
  Wi-Fi neighbours can see the password and site addresses, so do not open
  the proxy to the network on other people's networks.
- `--ca file.pem` — custom root certificates for `security=tls` (a server
  with a self-signed certificate).
- `--allow-insecure` — start a link with `security=none` (no encryption;
  without this flag the client refuses — on Wi-Fi such traffic is visible to
  everyone).

UDP (DNS, QUIC, games) works through SOCKS5 UDP ASSOCIATE — if the program
supports UDP over SOCKS5. UDP goes over XUDP, like the Xray client (Full Cone
NAT); `--no-xudp` — the old way, a stream per destination. Windows may ask to
allow the client incoming UDP packets from localhost in the firewall (it asks
on the first UDP request).

## 6. Limitations (same as on Linux)

- XTLS Vision works only with `type=tcp` and `security=tls`/`reality` — as in
  Xray-core itself; for ws/grpc/xhttp the client says right away that this is
  not allowed.
- No `kcp` transport; `quic`/`h2` have been removed from Xray-core itself
  (replaced by `xhttp`, including over HTTP/3 — `alpn=h3`).

The full list is in [`README.en.md`](../README.en.md), section "Features".
