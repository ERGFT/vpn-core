[Русский](LIBRARY.md) | [English](LIBRARY.en.md)

# The core as a library

The core can be embedded directly into an app — Android (`VpnService`), iOS
(Network Extension), a desktop client — instead of running `reality-client`
as a separate process. The interface is a C ABI: usable from Kotlin/Java
(JNI), Swift, C/C++, Go (cgo), C# (P/Invoke), Python (ctypes) and anything
else that can call C functions.

- Header: [`ffi/include/reality.h`](../ffi/include/reality.h).
- Code: [`ffi/src/lib.rs`](../ffi/src/lib.rs), a C example —
  [`ffi/examples/smoke.c`](../ffi/examples/smoke.c) (built and run by
  `scripts/ffi_smoke.sh`).
- License — the same GPL-3.0-or-later: an app with the embedded core is
  distributed under the GPL (including the app's source code).

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
- **`rc_set_event_callback(core, cb, user)`** — events (like the
  `GET /events` stream): connections opening and closing, group switches,
  subscription updates, reloads, mode changes.
- **`rc_set_log_callback(core, level, cb, user)`** — the core's log. At
  the `info` level (the default) it contains no site addresses; at
  `debug` (and with `RUST_LOG=debug`) the log — both the callback and
  `GET /logs` — includes the domains of visited sites and DNS results. Do
  not send such a log to a server or show it without the user knowing.
- **`rc_stop(core)`** — stop: inbounds close, routes are restored.
- **`rc_free_string(s)`** — free a string returned by the library.

Functions may be called from any thread. Callbacks arrive on the core's
background threads and the core waits until each one returns, so hand the
data over to your own (UI) thread and return quickly.

## Android

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
