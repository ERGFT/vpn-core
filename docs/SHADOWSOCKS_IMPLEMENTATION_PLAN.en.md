# Shadowsocks implementation plan

[Русский](SHADOWSOCKS_IMPLEMENTATION_PLAN.md) | **English**

This document tracks roadmap stages 3.2 and 3.3. Classic Shadowsocks AEAD and
Shadowsocks 2022 are separate modes; support for one does not imply support for
the other.

## Current state: classic AEAD

The classic outbound was merged into `main` through
[PR #204](https://github.com/ERGFT/vpn-core/pull/204). Required CI passed;
implementation limits are listed below and in the feature matrix.

| Area | Branch implementation | Verification/limit |
|---|---|---|
| Protocol | Official Rust crate `shadowsocks-rust`; only `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | Link validation rejects stream ciphers and Shadowsocks 2022 |
| TCP | Shared resolver and protected TCP dialer | Xray TCP echo passed in CI |
| UDP | Native Shadowsocks UDP through an adapter for the protected UDP socket; bounded queues | Xray UDP echo passed in CI; drops on queue overflow are intentional |
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

Classic AEAD exit criteria are met: PR #204 was merged after CI passed; Xray
verified TCP/UDP echo. Plugin and additional transport limits remain intentional
and are documented above.

## Shadowsocks 2022 / SIP022 — implementation and interop verified

The [SIP022 specification](https://shadowsocks.org/doc/sip022.html) has been
checked against the pinned official `shadowsocks-rust` 1.24.0 crate. It
requires AES-128/256-GCM, fixed 16/32-byte base64 PSKs, separate TCP stream
salts/chunks, and UDP session/packet IDs with sliding-window replay protection.
The core does not duplicate cryptography or protocol codecs; it uses this
crate's client TCP/UDP paths.

The implementation is in a separate branch based on the classic outbound for
`2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`. The official
`shadowsocks-rust` AEAD-2022 feature is enabled; separate method validation,
PSK validation through `ServerConfig`, and URI/factory/import unit tests have
been added. The UDP adapter assigns a
random client session ID and monotonic packet IDs, validates response session
IDs, and retains bounded replay windows for the current and previous server
sessions for 60 seconds. Xray TCP/UDP interop covers both methods and concurrent
repeated datagrams. On exact head `2c0d14e`, GitHub CI completed all 16
non-publish jobs successfully (the publish job is skipped for PRs); Linux CI ran
28 Xray interop tests, including `shadowsocks_2022_tcp_udp_against_xray`. Local
Rust tests and interop were not run because MSVC `link.exe` is absent.

Do not add 2022 to the classic validator/decoder. Verified coverage:

1. Tests check both method names, base64 PSKs, and invalid key lengths through
   `ServerConfig`.
2. TCP framing, salts/chunks, nonce handling, and AEAD remain in the official
   crate; Xray TCP echo interop passed for both methods.
3. Unit tests cover session IDs, replays, packet-ID ordering, the bounded replay
   window, and server-session TTL; Xray checks UDP echo and concurrent identical
   datagrams.
4. Config and subscription tests cover sing-box and Xray fields, SIP002 URIs,
   and Clash YAML while preserving classic methods and restrictions.
5. Secret redaction is covered by shared secret-handling tests; full CI and all
   28 Xray interop tests passed on the head recorded above.

The implementation criteria and bilingual documentation have been reviewed;
green CI for the PR targeting `main` is still required before merging. SIP003
plugins and other transport plugins remain a separate design decision: process
lifecycle, platform support, UDP, and secret delivery need explicit design
first.
