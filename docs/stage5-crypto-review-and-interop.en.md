# Stage 5 — checklist: third-party crypto review and an interop test against a live server

[Русский](stage5-crypto-review-and-interop.md) | **English**

Neither item can be closed from the sandbox (there is no third person and no
network access to a real Xray-core server) — see PLAN.md, Stage 5, and
"Дорожная карта до финала" (the roadmap to the finish). This file is not a
box-ticking formality but a concrete checklist so that context is not lost
between sessions.

## 1. Third-party crypto review

The plan itself requires it "before starting, not after" (PLAN.md, Stage 5)
— that did not happen, and the solo re-check (see below) does NOT replace
it, it only lowers the probability of certain classes of mistakes.

What to show the reviewer — the whole REALITY authentication and TLS
substitution implementation, in increasing order of risk:

- `core/src/reality/auth.rs` — X25519 ECDH, HKDF-SHA256(AuthKey),
  AES-256-GCM seal/open of the SessionId, HMAC-SHA512 certificate check.
- `core/src/reality/hook.rs` — the actual hook into the handshake, including
  the hybrid `X25519MLKEM768` (ML-KEM-768 + X25519) and the client version
  announcement (`CLIENT_VERSION`).
- `core/src/reality/verifier.rs` — replacing X.509 chain verification with
  the HMAC check.
- `vendor/rustls-reality-patch/src/client/{client_conn,hs}.rs` — the rustls
  patch itself: key_share substitution, the `named_groups` restriction,
  writing the SessionId in place into the already built ClientHello.
- `vendor/rustls-reality-patch/src/server/{server_conn,hs}.rs` — server-side
  additions (needed only by the REALITY test server inside
  `reality_full_stack.rs`, not used by the client in production, but still
  part of the diff from upstream).

Specific questions for the reviewer (not just "check everything"):
1. Nonce reuse: `AES-256-GCM` for the SessionId uses
   `client_hello_random[20..32]` as the nonce — 12 bytes, together with the
   AuthKey, which itself depends on `client_hello_random[..20]`. Is nonce
   reuse under the same AuthKey across connections really ruled out (the
   ephemeral X25519 secret and `random` are generated anew for every
   connection — but it is worth independently confirming that this is
   exactly what guarantees uniqueness, and not something subtler).
2. The `mlkem || ecdh` byte order for `X25519MLKEM768` — checked against the
   Go stdlib and against the native implementation of the same group in the
   rustls used by the project (see PLAN.md, Stage 5), but that is a solo
   check of two sources by the same person — an independent third check
   would not hurt exactly here, because a byte-order mistake would not break
   the handshake loudly but would quietly weaken the secret.
3. Side channels: secret material is wrapped in `zeroize::Zeroizing` on
   `Drop` — but it has NOT been checked for timing side channels
   (constant-time comparisons, etc.) beyond what
   `x25519-dalek`/`ml-kem`/`aes-gcm` provide out of the box.
4. The rustls patch — whether it is embedded correctly in
   `emit_client_hello_for_retry` as a whole (not only the REALITY changes
   themselves, but also that the rest of the rustls logic around them is not
   broken — three very narrow but not isolated changes in shared code).

## 2. Interop test against a live REALITY server

All current tests (`reality_full_stack.rs`, `reality_handshake.rs`) run test
servers started INSIDE the test itself and implemented by hand (not real
Xray-core). This proves the client is self-consistent with the protocol as
it is DOCUMENTED/read from the sources — which is not the same as real
compatibility with someone else's process.

Steps:

```sh
# 1. Start a real Xray-core server with REALITY (see the official Xray-core
#    documentation for an example reality inbound config)
xray run -c server-config.json

# 2. Build this client in release mode
cargo build --release -p reality-client

# 3. Connect with a real vless link (pbk=/sid= from the server in step 1)
./target/release/reality-client \
    --server 'vless://UUID@host:443?encryption=none&security=reality&sni=host&pbk=...&sid=...' \
    --listen 127.0.0.1:1080

# 4. Send traffic through SOCKS5 and make sure it gets through
curl --socks5 127.0.0.1:1080 https://example.com -v

# 5. Additionally — capture and compare the fingerprint against THIS
#    particular server (this also checks minClientVer/maxClientVer live, if
#    the server uses them — see PLAN.md, Stage 5)
cargo run -p fpcheck -- --server 'vless://UUID@host:443?security=reality&sni=host&pbk=...&sid=...'
```

If step 4 fails — narrow it down: set `Show: true` in the Xray-core server
config (it then prints `AuthKey`/`ClientVer`/`ClientShortId` to its logs, see
`tls.go` in `XTLS/reality`) and compare with what `fpcheck`/the client itself
prints — that way the difference is visible immediately, not just as "did
not connect".
