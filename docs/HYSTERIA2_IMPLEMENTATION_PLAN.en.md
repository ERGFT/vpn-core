# Hysteria 2 Integration Plan

**Status:** Stages 1–2 are complete (PRs #187 and #188); Stage 3 is PR #189; Stage 4 (TCP relay) is PR #190; Stage 5 (UDP relay) is PR #192; Stage 6.1 (Salamander) is PR #193. All listed PRs are merged into `main`; PR #193 landed as merge commit [`a776d7c`](https://github.com/ERGFT/vpn-core/commit/a776d7cb2ba635b50e392fce9f4e64c69509efcc). On head `32ef01a`, CI #757 passed 8/8 jobs and Release #124 passed 7/7 jobs; GitHub reported 15 successful and 1 skipped check. Stage 6.2 (selecting BBR for Hysteria 2) is implemented on the current work branch and awaits CI. Reference interoperability has not been verified, and the production outbound is not wired.
**Code snapshot:** `main` after PR #193, merge commit `a776d7c`.
**Scope:** client proxy outbound in the existing core only.

## Architectural decision

Hysteria 2 is a QUIC protocol with TCP streams and UDP datagrams. It fits the current `Outbound` contract: `connect()` opens a TCP destination stream and `udp()` returns a `UdpSession` association. A dedicated `Hysteria2Outbound` should own a shared QUIC endpoint/connection and its HTTP/3 control/auth state. Do not create another router or a dynamic registry.

`core/src/transport/quic.rs` already builds QUIC with `quinn`, creates protected UDP sockets through `net_protect`, supports QUIC over `UdpSession`, and bounds internal queues. `core/src/transport/xhttp.rs` already has an HTTP/3 client using `h3` + `h3-quinn`. These modules provide code examples and infrastructure, but they are not a ready Hysteria transport: Hysteria needs its own ALPN/auth headers, stream messages, UDP framing/fragmentation, congestion/rate settings, and port-hopping behavior.

Keep outbound construction in `app/outbound_factory.rs`; typed configuration and strict combination checks belong in `app/config/outbound.rs`. Add explicit parsing for applicable `hysteria2://` links, subscriptions, and supported sing-box input. Do not invent Xray Hysteria support where that outbound type does not exist.

## Protocol requirements and first complete implementation boundary

The official [Hysteria 2 protocol](https://v2.hysteria.network/docs/developers/Protocol/) specifies these required mechanisms:

- HTTP/3 `POST /auth`, `Hysteria-Auth`, and `Hysteria-CC-RX`; authentication succeeds only with status `233`. Any other result must close the connection and return an error.
- A new QUIC bidirectional stream for each TCP destination, with TCPRequest/TCPResponse validation before exposing the stream to callers.
- UDP over QUIC unreliable datagrams, with a unique session ID per UDP association, packet IDs, and protocol fragmentation/reassembly. Loss of any fragment discards the whole datagram.
- RX-rate negotiation from the auth response; `0` and `auto` have distinct meanings. Local bandwidth limits and server negotiation must not be conflated or silently ignored.
- Optional Salamander wraps QUIC packets with salted BLAKE2b-256 obfuscation. Generate a salt per packet and discard invalid packets. For reference compatibility, the PSK must be at least 4 UTF-8 bytes.

Settings should follow the current [official client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/): server/port and SNI, certificate verification, custom CA, fingerprint pinning, mTLS, ECH, Salamander, port hopping, bandwidth, and congestion controller. Verify the supported fields and limitations against current URI and sing-box formats during implementation. If an option is unsupported in the first release, reject it clearly; never accept and ignore it.

Out of scope for `vpn-core`: Hysteria's local SOCKS/HTTP listeners, server-side forwarding, NAT hole punching/Realms, Hysteria's own system TUN interface, and server-side `mimic`/XDP mode. UDP routing and TUN belong to the shared core and must work through its existing session model.

## Small PR sequence

1. **Model and URI parsing.** Typed `Hysteria2Config`, secret redaction, strict validation of `hysteria2://`/`hy2://`, SNI/TLS, Salamander/Gecko, and multi-port addresses. This layer does not create a working connection and must not be presented as outbound support.
2. **Input formats.** Explicit conversion for applicable sing-box outbounds and URI subscriptions. Adapters preserve only fields representable in the URI and count entries with unsupported options separately; recognized Hysteria 2 entries are skipped with a separate exact count because runtime support is unavailable. Do not add the type to the production factory before the transport is ready.
3. **QUIC and authentication.** Shared endpoint/connection owner, ALPN, TLS validation (insecure disabled by default), HTTP/3 auth, status 233, rate negotiation, timeouts, and task cancellation. Do not change existing DNS/XHTTP `quinn`/`h3` behavior.
4. **TCP relay and shutdown.** Each TCP dial opens a dedicated bidirectional QUIC stream on the shared authenticated connection. Send QUIC-varint `0x401`, the length and `host:port` destination, and random padding; strictly parse bounded TCPResponse status/message/padding and expose the stream only after status 0. Verify concurrent streams, half-close, resets, cancellation, and timeouts. Do not add the outbound to the production factory before its separate integration stage.
5. **UDP relay.** Datagram codec, per-association IDs, packet-ID wrap handling, bounded-memory fragmentation/reassembly, queues, and idle cleanup. Never retain unbounded state based on server traffic.
6. **Transport options, split into substages.** 6.1 Salamander on the QUIC socket, accounting for its 8-byte overhead in UDP datagram limits. 6.2 Select and wire BBR for directions without a fixed bandwidth; apply a numeric server RX limit only together with a local bandwidth setting. Do not claim Brutal until pacing and loss compensation are implemented and tested: Quinn 0.11.12 exposes `Controller`/`ControllerFactory`, but `pacing_rate` is a metric, not a pacer-control interface. Full rate negotiation first needs a local bandwidth field in outbound config and a pacing backend; the current URI does not carry this setting. 6.3 Port hopping with correct DNS/IPv4/IPv6 and network-change handling. Gecko needs a separate assessment: it is officially experimental and should be implemented separately with bounds and interoperability.
7. **Integration and compatibility.** Groups, router, accounting, config reload, subscription formats, and C ABI; update Russian and English docs and the feature matrix together.

Each PR should remain small, carry focused tests, and update both languages. Do not combine separate steps into a claim of a completed protocol without the full verification set.

## Completion checks

Full Hysteria 2 status requires codec/config tests plus interop with a pinned version of the official Go client/server. Verify:

- valid/invalid password, certificate, SNI, CA, and fingerprint;
- TCP echo, concurrent streams, remote close, timeout, and core shutdown;
- IPv4/IPv6 UDP echo, multiple destinations per association, large datagrams, fragment loss/reordering, queue overflow, and session cleanup;
- configured and negotiated rates, and BBR/Reno/Brutal only for controllers actually implemented;
- Salamander with correct/incorrect passwords, port hopping, network changes, and reconnection;
- single link and subscription import, groups/failover, and configuration reload;
- regular CI: fmt, clippy, workspace tests, coverage, Linux interop/TUN, Windows, Android/iOS builds, MSRV, audit, and secrets; preserve Rust/C ABI compatibility.

## Current progress

PR #187 added the typed model and strict URI parser and was merged into `main` as [`aa8dab6`](https://github.com/ERGFT/vpn-core/commit/aa8dab644b19cd5e3641d53e62408c705e6c6b5a); all 8 CI groups passed. PR #188 added URI-subscription parsing and conservative sing-box conversion, updated the RU/EN documentation, and was merged as [`e43066b`](https://github.com/ERGFT/vpn-core/commit/e43066ba4fac86d21796e57a4237f9d28f4adafa) after GitHub checks completed (16 successful, one skipped). Entries can be parsed and validated, but subscriptions currently skip them with a separate count; a regular sing-box config returns the precise reason that runtime support is not ready. No working outbound is created.

Stage 3 is implemented and merged in PR #189: one QUIC endpoint/connection owner, HTTP/3 `POST /auth`, strict acceptance of status 233, and parsing of `Hysteria-UDP`/`Hysteria-CC-RX`. System certificate roots are used; unsupported insecure TLS, pinning, and ECH are rejected.

Stage 4 is implemented and merged in PR #190: TCPRequest with QUIC-varint ID `0x401`, bounded TCPResponse parsing, timeouts, and a bidirectional stream per destination. The code is not wired into `Outbound` or the production factory.

Stage 5 is implemented and merged in PR #192. It adds UDPMessage framing, QUIC unreliable datagrams, monotonically increasing Session IDs per QUIC connection, wrapping Packet IDs, fragmentation using `max_datagram_size`, reordered-fragment reassembly, and bounded state: at most 128 incomplete packets, 256 KiB of reassembly data, and a 5-second TTL. Each UDP association has a queue of up to 256 replies and a 120-second idle timeout; payloads are limited to 4096 bytes. Reference server/client interoperability remains outstanding. TCP and UDP are not available through the production outbound.

Stage 6.1 is implemented and merged in PR #193: a dedicated QUIC UDP socket adds a random 8-byte salt and a BLAKE2b-256(`key || salt`) XOR mask to every packet. UDPMessage framing reduces the available datagram budget by 8 bytes. PSKs shorter than 4 UTF-8 bytes are rejected to match the reference implementation; short and salt-only frames are discarded. The implementation uses Tokio UDP without GSO/ECN. Salamander is obfuscation, not authenticated encryption; QUIC discards packets produced with the wrong key. On head `32ef01a`, CI #757 passed 8/8 jobs and Release #124 passed 7/7 jobs; one separate publish check was skipped. Reference interoperability has not run. The production factory remains unwired.

Stage 6.2 has started: Hysteria receives its own Quinn BBR selection; existing DNS/XHTTP QUIC clients keep their default configuration. Quinn marks BBR experimental. The auth response still parses `auto`, `0`, and a numeric RX limit, but the numeric limit is not applied yet because the project has no local Hysteria bandwidth setting. Exact Brutal is also not implementable through this Quinn pacing API and must not be claimed as supported.

An external Android phone is not needed for parser/codec development or local interop. It will help with the final device-level Android VPN/TUN run, Wi-Fi↔cellular handover, and wake-from-sleep recovery; an Android cross-build alone does not prove that behavior.

## Sources

- [Hysteria 2 URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/)
- [Hysteria 2 protocol specification](https://v2.hysteria.network/docs/developers/Protocol/)
- [Hysteria 2 full client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria Brutal reference implementation](https://github.com/HyNetworks/hysteria/blob/core/v2.13.0/core/internal/congestion/brutal/brutal.go)
- [Hysteria 2 changelog](https://v2.hysteria.network/docs/Changelog/)
- [sing-box Hysteria2 outbound](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)
- [Quinn 0.11.12 congestion control API](https://docs.rs/quinn/0.11.12/quinn/congestion/index.html)
