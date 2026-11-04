# Stage 5 — checklist: third-party crypto review and an interop test against a live server

[Русский](stage5-crypto-review-and-interop.md) | **English**

An independent third-party review remains a useful additional assurance
layer, but on 2026-11-04 the user accepted reviews by three separate Codex
subagents for the first-release gate. Their report and limitations are in
[RU](reviews/2026-11-04-reality-internal-review.md) / [EN](reviews/2026-11-04-reality-internal-review.en.md).
That internal AI review is not an external audit. This file preserves the
checklist for any third-party expert and must not be read as evidence that such
an audit has happened.

## 1. Third-party crypto review

The original plan required external review before work started. By user
decision, the internal subagent review was accepted for the first-release
gate; this does not change the public fact that no external review has taken
place. If an external audit is commissioned later, this checklist defines its
scope and questions.

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
   rustls used by the project (see PLAN.en.md, Stage 5), but that is a solo
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

5. ML-KEM shared secret — is the returned `SharedKey` itself wiped on drop,
   rather than only a copy; does the selected `Zeroizing` wrapper cover the
   internal `hybrid-array` buffer?
6. Temporary AuthKey copies in `RealityHook::auth_key()` and certificate
   verification — can they be avoided or kept in zeroizing wrappers?
7. TLS group policy — does accepting classical X25519 in an authenticated
   REALITY session match the project policy, or is hybrid-only enforcement
   required? Explicitly assess HRR and the transcript used for `pqv=` too.

### How to record and close the review

Until the review is done, do not use the client where a compromised
connection would have serious consequences. The review is closed when the
repository has a report (for example, `docs/reviews/<date>-reality.md`) and
all its findings are fixed or knowingly accepted. The report contains:

- **what was reviewed:** the commit (`git rev-parse HEAD`), the rustls
  version under the patch (currently 0.23.46,
  `vendor/rustls-reality-patch/Cargo.toml`) and the SHA-256 of
  `vendor/rustls-reality-patch.diff`; the list of files from the list
  above and which of them were not looked at;
- **who reviewed** and when;
- **findings** — a table: number, file and line, description, severity,
  status (fixed — by which commit; accepted — why);
- answers to the four questions above.

After the fixes — a note in the report on which commit closed each
finding, and a line in `CHANGELOG.md`.

## 2. Interop test against a live REALITY server

> Done: `scripts/interop_xray.sh` (23 tests against real Xray-core,
> including REALITY, Vision, ML-DSA-65) and `scripts/interop_go_reality.sh`
> (the `XTLS/REALITY` Go library) run in CI on every push. The steps below
> are for checking against your own server.

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
#    the server uses them — see PLAN.en.md, Stage 5)
cargo run -p fpcheck -- --server 'vless://UUID@host:443?security=reality&sni=host&pbk=...&sid=...'
```

If step 4 fails — narrow it down: set `Show: true` in the Xray-core server
config (it then prints `AuthKey`/`ClientVer`/`ClientShortId` to its logs, see
`tls.go` in `XTLS/reality`) and compare with what `fpcheck`/the client itself
prints — that way the difference is visible immediately, not just as "did
not connect".
