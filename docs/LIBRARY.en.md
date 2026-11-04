[Русский](LIBRARY.md) | [English](LIBRARY.en.md)

# The core as a library

SDK archives with a library, C ABI header, and sample are published on the
[Releases](https://github.com/ERGFT/vpn-core/releases) page for versioned
releases. If an archive for your platform is not available, build from source
using the instructions below. Choose the archive for your target platform;
binaries are not interchangeable across operating systems or architectures. Each archive contains
`include/reality.h`, libraries in `lib/`, a C example, and local copies of
this guide and the API documentation.

The versioned release workflow builds SDKs for Linux x86_64, Windows x86_64,
macOS arm64, Android arm64-v8a, and iOS arm64. Each ZIP has a separate
`.sha256` file. CI checks archive contents and checksums; it builds and runs
the unpacked C example on Linux, Windows, and macOS. Android and iOS are checked
by cross-linking the example. These mobile checks do not replace an
on-device run. Dependency license notices, SBOM, and build provenance are
published as separate release files.

Each SDK ZIP contains `manifest.json` with `schema_version: 1`. It records the
version/tag, platform and Rust target triple, `rustc`/Cargo versions, and build
runner OS. Every file except the manifest itself has a relative path, size, and
SHA-256; libraries also have a kind (`shared`, `static`, or `import`). The
`static_link.arguments` field records native linker arguments reported by
`rustc` for the static library built for that target. Verify the
external `.sha256` for the ZIP, then verify the manifest against the extracted
files. `minimum_os` contains a minimum version explicitly set by the build
(currently iOS 13.0); `null` means the project does not declare one separately
and is not a compatibility guarantee for every OS version. Consumers should
ignore unknown fields. Incompatible schema changes require incrementing
`schema_version`.

Combined app/site rules use the added `rc_set_connection_owner` API:
[contract, fail-closed behavior and Android integration](APPLICATION_ROUTING.en.md).

The core can be embedded directly into an app — Android (`VpnService`), iOS
(Network Extension), a desktop client — instead of running `reality-client`
as a separate process. The interface is a C ABI: usable from Kotlin/Java
(JNI), Swift, C/C++, Go (cgo), C# (P/Invoke), Python (ctypes) and anything
else that can call C functions.

- Header: [`ffi/include/reality.h`](../ffi/include/reality.h).
- Minimal embedding example: [`ffi/examples/minimal.c`](../ffi/examples/minimal.c).
- Code: [`ffi/src/lib.rs`](../ffi/src/lib.rs), a C example —
  [`ffi/examples/smoke.c`](../ffi/examples/smoke.c) (built and run by
  `scripts/ffi_smoke.sh`).
- License — the same GPL-3.0-or-later: an app with the embedded core is
  distributed under the GPL (including the app's source code).

## C ABI compatibility

Public C function signatures, `typedef`s, and numeric `RC_*` enum values are recorded in
[`ffi/abi-baseline.json`](../ffi/abi-baseline.json). Linux CI compares this
snapshot with the C header and Rust exports, so an accidental function removal
or rename, argument/result type change, callback typedef change, or error-code
renumbering fails the PR. A new function can be added by explicitly updating
the snapshot and checking consumer compatibility. Changing a published API is
a breaking change that must be planned and documented before release.

Run the check locally with `python scripts/check_ffi_abi.py`; test the checker
with `python scripts/test_check_ffi_abi.py`. The `--update-baseline` flag rewrites
the snapshot, so use it only after reviewing the diff and compatibility impact
in the PR.

## Building

```sh
cargo build --release -p reality-ffi
# target/release/libreality.so (Linux, Android), libreality.dylib (macOS, iOS),
# reality.dll (Windows) and the static libreality.a / reality.lib
```

For Android — with [cargo-ndk](https://github.com/bbqsrc/cargo-ndk):

```sh
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o app/src/main/jniLibs \
    build --release -p reality-ffi
```

For iOS — `IPHONEOS_DEPLOYMENT_TARGET=13.0 cargo build --release -p
reality-ffi --target aarch64-apple-ios` (the static `libreality.a` inside an
XCFramework). Rust and aws-lc's C code need the same minimum iOS version:
without it aws-lc is built for the SDK's iOS while Rust links for 10.0 —
a `___chkstk_darwin` error.

## Lifecycle

```c
#include "reality.h"

char *err = NULL;
RcCore *core = rc_start(config_json, base_dir, /*tun_fd*/ -1, &err);
if (!core) { printf("error: %s\n", err); rc_free_string(err); return; }

int status;
char *proxies = rc_request(core, "GET", "/proxies", NULL, &status);
/* … */
rc_free_string(proxies);

rc_stop(core);
```

- **`rc_start(config, base_dir, tun_fd, &err)`**:
  - `config` — the config as text (sing-box or Xray-core JSON, as for
    `reality-client --config`);
  - `base_dir` — the folder for relative paths in it (geosite/geoip
    databases, rule sets, subscription caches);
  - `tun_fd` — a TUN descriptor or -1.

  On a config error it returns NULL and puts the text in `err`.
- **`rc_request(core, method, path, body, &status)`** — everything the
  HTTP API can do ([API.en.md](API.en.md)), with the same
  path and the same response, but without the network or a token:
  - groups and server selection (`/proxies`);
  - the mode (`PATCH /configs`);
  - connections (`/connections`);
  - latency tests;
  - subscriptions (`/providers/proxies`);
  - DNS queries;
  - statistics (`/stats`).

  The response is JSON (an empty string for 204); the code goes into
  `status`.
- **`rc_reload(core, config, &err)`** — apply a new config without dropping
  connections. On error the previous config keeps working. The response is
  `{"notes": […]}`: what takes effect only after a restart.
- **`rc_network_changed(core)`** — report a network change detected by the
  embedding host. The core clears its DNS and server-address caches, cancels
  tracked TCP/UDP sessions, and keeps its inbounds and current config running.
  New connections resolve names again; the core does not automatically replay
  application traffic, so the host must retry requests according to its own
  policy. Returns `0` when handled, or `-1` for a NULL handle or an internal
  error.
- **`rc_set_event_callback(core, cb, user)`** — events (like the
  `GET /events` stream): connections opening and closing, group switches,
  subscription updates, reloads, mode changes. The callback receives a
  temporary JSON string on a background thread. `cb = NULL` unsubscribes;
  replacing or removing a callback waits for any active invocation. You can
  release the old callback and `user` after the call returns.
- **`rc_set_log_callback(core, level, cb, user)`** — the core's log. At
  the `info` level (the default) it contains no site addresses; at
  `debug` (and with `RUST_LOG=debug`) the log — both the callback and
  `GET /logs` — includes the domains of visited sites and DNS results. Do
  not send such a log to a server or show it without the user knowing.
  Removing or replacing the callback uses the same completion barrier.
- **`rc_stop(core)`** — stop: inbounds close and routes are restored. Before
  returning, it waits for callbacks to finish; no new callback starts after
  return. You can release `user` data and callback resources after `rc_stop`.
  `NULL` is accepted as a no-op.
- **`rc_free_string(s)`** — free a string returned by the library.

After `rc_is_alive(core) == 0`, retrieve the cause with
`rc_last_error_code(core)` and `rc_last_error_message(core)`. Polling is
non-blocking and the terminal error remains available on repeated reads until
`rc_stop`; the handle is invalid after stop. Errors from an individual
`rc_request` or `rc_reload` are returned by those calls and do not change a
healthy core's terminal state.
`RC_ERROR_*` values are stable ABI values: `0` means no error yet, `-1` is a
NULL handle, `1` configuration/startup, `2` I/O, `3` blocked by routing,
`4` protocol/connection, `5` TLS, `6` DNS name, `7` authentication, and `255`
an internal C ABI error. The message is a short English string, or empty while
healthy; NULL returns `Invalid core handle`. Detailed source errors are not
exposed because they may contain addresses or config values. Free the returned
string with `rc_free_string`.

Call `rc_network_changed` only after a platform host API reports a transition
(for example, Wi-Fi/cellular or default-route changes). The core does not poll
the OS or determine Internet availability. A duplicate notification also
cancels sessions opened after the previous one, so coalesce duplicate events
in the host. This function does not recreate the TUN descriptor, VPN
permission, routes, or system-interface settings; stop and start the core
again when those resources must be recreated.

Functions may be called from any thread, but the application must serialize
operations on the same `RcCore`. Do not call `rc_is_alive`, either diagnostic
function or another operation concurrently on that handle; the handle is
invalid after `rc_stop`. Event/log callbacks arrive on background threads.
Move their data to your own thread and return quickly. Do not call functions
for the same `RcCore` from a callback: calls can block each other, and
`rc_stop`/unsubscribe wait for the callback to return.

## SOCKS5 outbound

The core can send TCP connections through a SOCKS5 proxy configured in
sing-box format. Set `network: "tcp"` so the config does not enable unsupported
UDP. Minimal `rc_start` config:

```json
{
  "outbounds": [
    { "type": "socks", "tag": "upstream", "server": "proxy.example", "server_port": 1080, "network": "tcp" }
  ],
  "route": { "final": "upstream" }
}
```

For authentication, set `username` and `password`; the vpn-core `password_file`
extension stores the password separately. Restrict access to that file using
the OS. Credentials are redacted from config `Debug` output. Only TCP CONNECT
is supported: UDP ASSOCIATE and TLS to the proxy are not supported yet. If the
proxy refuses or cannot open the connection, that connection returns an error.
SOCKS5 does not encrypt the connection to the proxy; RFC 1929 sends the
password without encryption. Use this proxy only on a trusted network or
inside a separate protected transport.

## HTTP CONNECT outbound

Use `type: "http"` to send outgoing TCP connections through an HTTP/1.1 proxy:

```json
{
  "outbounds": [
    {
      "type": "http",
      "tag": "upstream",
      "server": "proxy.example",
      "server_port": 8080,
      "username": "user",
      "password_file": "proxy.pass",
      "tls": { "enabled": true, "server_name": "proxy.example" }
    }
  ],
  "route": { "final": "upstream" }
}
```

Authentication uses Basic and is sent only after TLS is established when
`tls.enabled` is true. Certificate verification is mandatory and uses the
built-in public roots; `tls.server_name` sets both SNI and the verification name,
defaulting to `server`. The vpn-core `ca_file` extension adds PEM trust roots.
Omit `tls` for a plain HTTP proxy.
Only HTTP/1.1 CONNECT
is supported: arbitrary headers, HTTP/2, HTTP/3, and UDP are unsupported. Proxy
errors are returned to the caller; traffic never falls back automatically to
`direct`. Set the password inline or with the vpn-core `password_file` extension,
but not both.

## TCP chains with `detour`

SOCKS5 and HTTP CONNECT outbounds can use `detour` to open their proxy-server
connection through another TCP outbound. For example, HTTP CONNECT can run
through SOCKS5:

```json
{
  "outbounds": [
    { "type": "socks", "tag": "entry", "server": "entry.example", "server_port": 1080, "network": "tcp" },
    { "type": "http", "tag": "exit", "server": "exit.example", "server_port": 8080, "detour": "entry" }
  ],
  "route": { "final": "exit" }
}
```

Set `detour` on SOCKS5 or HTTP CONNECT outbounds. Chains can contain more of
these proxy outbounds; a base outbound can also be `direct`, VLESS, or Trojan.
Groups, `block`, and `dns` are not valid detours. Missing tags and cycles are
rejected. A failure at any hop is returned to the caller without falling back
to `direct`. Only TCP is supported; UDP chains are not.

## Android

Before transferring the FD, `rc_validate(config, base_dir)` returns 1 when
parsing/building the configuration succeeds, otherwise 0 without potentially
sensitive error text. It reads files (CA, rules) but starts no listeners and
does not check VPN permission, FD validity or connectivity. Success does not
guarantee a successful `rc_start`.

On a live handle `rc_is_alive(core)` returns 1 until the task channel reports
a terminal error, then 0 persistently. NULL returns 0. This is not a ping,
connectivity check or complete monitor of every background task. Errors from
`spawn_task`, including unwinding panics, reach this channel; `panic=abort`
cannot be caught. `Running::wait` retains an error observed by polling.
The application stops the core and informs the user after failure; the
library does not automatically switch traffic to a direct connection.

After `rc_is_alive(core) == 0`, use `rc_last_error_code` and
`rc_last_error_message` to choose a safe user-facing message or recovery
policy. The message is intentionally generic and contains no server address,
UUID, link or config secret. Repeated polling returns the same terminal error;
serialize calls on a handle.

With external TUN, VPN/DoH server hostnames must not use a DNS path that
itself requires a connection to that VPN server. Set the vpn-core extension
`dns.bootstrap` to the tag of a direct IP-literal UDP DNS server
([DNS.en.md](DNS.en.md)). Without it transport hostname resolution fails,
rather than falling back to system/proxy DNS. This direct DNS can see
transport server names; application queries continue to use their own rules.
System `local` DNS with external TUN is rejected because it would loop.

1. Call `VpnService.Builder` — addresses, routes (`addRoute("0.0.0.0", 0)`),
   DNS — then `establish()` → `ParcelFileDescriptor`.
2. Before `rc_start`, call `rc_set_protect` with a callback that calls
   `VpnService.protect(fd)` for every core socket (connections to the
   server, `direct`, DNS). Otherwise they would go into your own VPN.
3. Call `rc_start(config, filesDir, pfd.detachFd(), &err)`:
   - ownership passes to the core on call; it closes the descriptor on
     startup failure and in `rc_stop` after a successful start;
   - the config needs a `{"type": "tun", "tag": "tun"}` inbound;
   - `VpnService` sets addresses, routes and the kill switch, so
     `auto_route`/`strict_route` do not apply;
   - DNS hijacking (`hijack-dns`), sniffing and fake-IP work as usual.

A JNI wrapper sketch (Kotlin):

```kotlin
object Core {
    init { System.loadLibrary("reality") }       // libreality.so
    external fun start(config: String, dir: String, tunFd: Int): Long   // 0 — error
    external fun request(core: Long, method: String, path: String, body: String?): String
    external fun stop(core: Long)
}
```

The C side of the wrapper (`jni.c`) calls `rc_start`/`rc_request`/`rc_stop`.
It passes `rc_set_protect` a callback that calls `VpnService.protect(int)`
through `JNIEnv` (attach the thread with `AttachCurrentThread`).

## iOS, macOS

Inside `NEPacketTunnelProvider`, the utun descriptor can be found among the
process's open descriptors (WireGuard and sing-box do this) and passed to
`rc_start`. In a Network Extension, the core's sockets bypass the tunnel
without `rc_set_protect`.

## Desktop

The simplest option is `rc_start(config, dir, -1, …)` with a config as for
`reality-client`:

- a `tun` inbound creates the interface and routes itself (needs
  administrator or root rights);
- `mixed` is the proxy;
- control goes through `rc_request`, without HTTP.

On Windows call `rc_set_lock_dir(dir)` before `rc_start`: the folder for
the `auto_route` lock file, writable only by SYSTEM and administrators
(like `%ProgramData%\RealityClient` for `reality-client`). Without it a
`tun` inbound with `auto_route` will not start: in a shared folder any
user could take the lock first.

## Verification

- `cargo test -p reality-ffi` — C ABI calls from Rust (on Linux and Windows
  in CI).
- `scripts/ffi_smoke.sh` — a real C program that covers:
  - start and a config error;
  - `rc_request`: server selection, mode, 404;
  - traffic through the core's SOCKS5 inbound to an echo server;
  - events delivered to a callback;
  - `rc_set_protect` for the core's sockets;
  - `rc_reload` and `rc_stop`;
  - with root, also a start with a ready TUN descriptor (as from
    `VpnService`).
- The smoke verifies that invalid `rc_request` arguments and an `rc_reload`
  error do not become a terminal core error, and that removing an event
  callback waits for its active call and does not use `user` afterwards. A
  Rust unit test checks the gate while a callback is already running.
- The unpacked SDK example runs on Linux, Windows, and macOS. It checks a
  configuration error and frees its message, performs three
  `rc_start`/`rc_request`/`rc_stop` cycles, and calls `rc_stop(NULL)` safely.
  The Linux smoke additionally verifies that no event callback is invoked
  after `rc_stop` returns.
