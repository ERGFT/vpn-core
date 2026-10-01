English | [Русский](RUSTLS_PATCH.md)

# The rustls patch

`vendor/rustls-reality-patch/` is a full copy of rustls 0.23.45 with
changes for REALITY and the browser fingerprint. Via `[patch.crates-io]`
in the root `Cargo.toml` it replaces rustls across the whole dependency
graph, tokio-rustls included. This is **security-critical code**: it
builds the ClientHello, runs the TLS 1.3 key exchange and parses the
server's reply.

The full extent of the changes is in `vendor/rustls-reality-patch.diff`
(the difference from the crates.io archive of the same rustls version).
`scripts/rustls_patch.sh` regenerates and checks it; the full
`scripts/ci.sh` checks the file is up to date. At the time of writing:
13 files, about +800/−90 lines.

## What changed

| File | What and why |
|---|---|
| `client/client_conn.rs` | `RealityClientHook` — the REALITY hook: its own X25519MLKEM768 hybrid key share, AEAD sealing of `session_id` (AuthKey), ECDH completion, the raw ServerHello. `ChromeHello` — the browser's ClientHello profile (signatures, cipher suites, GREASE, extension order and raw extensions, P-256 as in Firefox). The `reality` and `chrome_hello` fields on `ClientConfig`; `set_ech_grease`, `clear_ech`. |
| `client/hs.rs` | The main logic: building the ClientHello from `ChromeHello`, GREASE (RFC 8701) laid out as in Chrome, a `session_id` of 32 zeros later sealed by the hook, replacing `key_share` with the hook's share (only in the first ClientHello), a separate entry for the hybrid's X25519 part, `RealityKeyExchange` and the P-256 share. |
| `client/common.rs` | `GreaseValues` — the connection's GREASE values (the same after a HelloRetryRequest). |
| `client/tls13.rs` | Picks the extra key share (P-256) if the server chose it. |
| `crypto/mod.rs` | `ActiveKeyExchange::extra_share` / `complete_extra` — an extra share (none by default). |
| `msgs/handshake.rs` | Encoding extensions in a given order and raw extensions, GREASE entries; `SessionId::from_bytes_public`, `pub` on `SessionId` and `CertificateChain`. |
| `msgs/persist.rs`, `lib.rs` | `Tls12ClientSessionValue::new` and the types it needs made public; re-exports of the new types. |
| `client/builder.rs` | Defaults for the new fields. |
| `server/hs.rs`, `server/server_conn.rs`, `server/test.rs` | The server certificate resolver gets `ClientHello.random` and the X25519 part of the client's share — only the test REALITY server in the core's tests needs this. |
| `Cargo.toml` | An empty `[workspace]` so the crate builds on its own. |

Not everything is gated on `reality` / `chrome_hello`: GREASE
(RFC 8701) — in cipher suites, groups, key shares, versions and
extensions — is added by the patch to **every** ClientHello of this
rustls (except with a `no_grease` profile), i.e. to the core's other TLS
connections too (DoH/DoT, subscription downloads). Servers must ignore
GREASE, but it is a change in rustls behaviour for the whole process.

## Updating rustls

rustls is pinned to the patch's version (dependabot leaves it alone). A
new release — especially one with a security fix — means porting the
patch:

1. Read rustls's release notes and security advisories
   ([GitHub](https://github.com/rustls/rustls/releases),
   [RustSec](https://rustsec.org/packages/rustls.html)): are any files
   from the table above affected?
2. Put the new crates.io version into `vendor/rustls-reality-patch/`
   (same path) and apply `vendor/rustls-reality-patch.diff`:
   `patch -p1 -d vendor/rustls-reality-patch < vendor/rustls-reality-patch.diff`.
   Resolve conflicts by meaning: in `client/hs.rs` the changes are in the
   ClientHello construction itself.
3. Bump the version in `Cargo.lock` (`cargo update -p rustls`),
   regenerate the `.diff` (`scripts/rustls_patch.sh`) and read it in full —
   only what was intended went in.
4. The full `scripts/ci.sh`: REALITY tests (`reality_full_stack`,
   `reality_handshake`), interop with real Xray-core, the Chrome
   fingerprint check (`scripts/check_chrome_fingerprint.sh`), the live
   Windows test in CI.
5. In the CHANGELOG — the new rustls version and what had to change in
   the patch.

A rustls security fix that lands in the changed places is ported by
hand — and first.
