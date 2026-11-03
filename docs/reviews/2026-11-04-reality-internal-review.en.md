# REALITY internal read-only review — 2026-11-04

> This was an internal review by three separate Codex subagents. It is not a third-party audit, a formal side-channel assessment, or a security guarantee.

## Review target

- Repository: `ERGFT/vpn-core`.
- Source commit reviewed: `2810fe351a4a07c9ddd1ae24656acbbb4af2a354`.
- Reviewers: `review_nonce_kdf`, `review_pq_handshake`, `review_sidechannels_rustls`; read-only, no file changes.
- Scope: `core/src/reality/auth.rs`, `hook.rs`, `verifier.rs`, `core/src/vless/uri.rs`, transport integration and `vendor/rustls-reality-patch`; nonce/KDF/AEAD/HMAC, X25519MLKEM768, ML-DSA-65, secret lifetime, and Rustls ClientHello/HRR hooks.

## Findings and status

| ID | Severity | Finding | Resolution / disposition |
|---|---|---|---|
| R1 | P2 | Public `RealityAuth` exposed `auth_key` through `Debug`. | Fixed in `c4d168da63f11d4a2afb24845dd18c08f5cd5c15`: custom redacted `Debug` plus a regression test. |
| R2 | P2 | ML-KEM `SharedKey` was copied into `Zeroizing`, while the original temporary buffer was dropped without wiping. | Fixed in `c4d168da63f11d4a2afb24845dd18c08f5cd5`: `Zeroizing` now wraps the original `SharedKey` before Drop. |
| R3 | P3 | `RealityHook::auth_key()` and `AuthKeySource::get()` created ordinary stack copies of AuthKey. | Fixed in PR #61, squash commit `56c397cdface8814c6ebc26d5987fd3007008a1e`: the hook returns a borrow; the verifier stores fixed keys in `Zeroizing` and uses a borrowed key. PR passed 8/8 checks. |
| R4 | Policy | An authenticated REALITY session can negotiate classical X25519 even when the client offers the hybrid group. | Accepted for first-release compatibility; RU/EN FEATURES state that post-quantum TLS is not guaranteed. No hybrid-only mode is implemented. |
| R5 | Coverage | Transcript semantics for `pqv=` after HelloRetryRequest are not confirmed by a test. | No confirmed defect or bypass was found. Recorded as a coverage limitation; the usual offered key shares are expected to avoid HRR. External or additional verification remains useful. |

## Review conclusions

- **Nonce and KDF:** HKDF-SHA256 uses `ClientHello.random`; AES-256-GCM uses a 12-byte nonce from its last bytes and ClientHello as AAD. Transport creates a new `RealityHook` per connection; no confirmed repeat seal using the same key/nonce pair was found in reviewed paths.
- **Hybrid TLS:** `mlkem || ecdh` order matches the Go TLS implementation and Xray interop. ML-KEM length validation, contributory X25519 checks, and rejection of an invalid ML-DSA key were found in implementation/tests.
- **TLS trust:** REALITY replaces ordinary PKI validation with HMAC/optional ML-DSA verification; Rustls continues to verify TLS transcript signatures.
- **Rustls patch:** ClientHello and ServerHello hook integration was inspected; no confirmed validation bypass, ALPN issue, or HRR bypass was found. `pqv=` with HRR remains untested.

## Limitations

This was a static review. It did not include a formal constant-time proof, an independent third-party review of the Rustls patch, fuzzing as part of this review, or full verification of primitive implementations. The user accepted this internal review for the first-release plan gate; the fact that REALITY has not received an external audit remains unchanged.
