# Shadowsocks implementation plan

[Русский](SHADOWSOCKS_IMPLEMENTATION_PLAN.md) | **English**

This document tracks roadmap stages 3.2 and 3.3. Classic Shadowsocks AEAD and
Shadowsocks 2022 are separate modes; support for one does not imply support for
the other.

## Current state: classic AEAD

The implementation is in [PR #204](https://github.com/ERGFT/vpn-core/pull/204)
from branch `codex/shadowsocks-aead-outbound`. CI is running; see the PR for its
results and implementation limits. The table describes PR code, not completed
or released support.

| Area | Branch implementation | Verification/limit |
|---|---|---|
| Protocol | Official Rust crate `shadowsocks-rust`; only `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | Link validation rejects stream ciphers and Shadowsocks 2022 |
| TCP | Shared resolver and protected TCP dialer | Independent Xray TCP echo test added, awaiting CI |
| UDP | Native Shadowsocks UDP through an adapter for the protected UDP socket; bounded queues | Independent Xray UDP echo test added, awaiting CI; drops on queue overflow are intentional |
| Configuration | `ss://`, sing-box fields, one Xray record; common outbound and factory | Plugins, UDP-over-TCP, network restrictions, detour, and unsupported transport-security settings are rejected |
| Subscriptions | SIP002, sing-box JSON, Clash YAML Shadowsocks nodes | Unrepresentable records are skipped and included in counters |
| Secrets | Uses `SecretSource`; settings debug output redacts the link | Redaction checks are included in unit tests |

## Classic AEAD exit criteria

- `cargo fmt --check`, `scripts/ci.sh --quick`, full CI, and Xray interop pass on
  all relevant platforms.
- TCP and UDP echo are verified against independent Xray, including repeated
  and parallel UDP datagrams and session-close behavior.
- Manual config and subscription formats either construct this outbound or
  explicitly reject/count unsupported entries; failures never fall back to
  direct.
- RU/EN README, CONFIG, FEATURES, ARCHITECTURE, TESTING, and this plan agree on
  supported formats, methods, transports, and limitations.

## Next substage: Shadowsocks 2022 / SIP022 — in progress

The [SIP022 specification](https://shadowsocks.org/doc/sip022.html) has been
checked against the pinned official `shadowsocks-rust` 1.24.0 crate. It
requires AES-128/256-GCM, fixed 16/32-byte base64 PSKs, separate TCP stream
salts/chunks, and UDP session/packet IDs with sliding-window replay protection.
The core does not duplicate cryptography or protocol codecs; it uses this
crate's client TCP/UDP paths.

Implementation has started in a separate worktree based on PR #204 for
`2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`. The official
`shadowsocks-rust` AEAD-2022 feature is enabled; separate method validation,
PSK validation through `ServerConfig`, and URI/factory/import unit tests have
been added. This is not verified support yet: TCP/UDP interoperability, full
CI, and review of all input formats remain required. The local build is
currently blocked by the missing MSVC `link.exe`.

Do not add 2022 to the classic validator/decoder. Next, satisfy these criteria:

1. Method names, key format, and minimum PSK length for each targeted
   `2022-blake3-*` variant.
2. TCP framing, salt/chunk lengths, nonce handling, and frame authentication.
3. UDP nonce and replay filter with bounded memory/time and per-association
   state.
4. SIP002 URI variants and sing-box/Xray/subscription fields without changing
   classic-link semantics.
5. Interop against an independent implementation over TCP and UDP, protocol
   vectors, malformed/replayed frames, and secret handling.

Do not claim Shadowsocks 2022 support until these criteria pass and bilingual
documentation is reviewed separately. SIP003 plugins and other transport
plugins remain a separate design decision: process lifecycle, platform support,
UDP, and secret delivery need explicit design first.
