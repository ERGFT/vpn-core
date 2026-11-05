# Plan: a VLESS (+ REALITY) core, with risk notes

This is an English translation of the historical engineering log in
[`PLAN.md`](PLAN.md). Its status marks and claims describe the work as recorded
at each date; they are not a substitute for the current implementation,
tests, or release artifacts. See the [feature matrix](docs/FEATURES.en.md) and
[release history](CHANGELOG.md) for the current public status.
The original plan's external-review requirement was later revised by the
user: the internal review by three Codex agents is accepted for the first
release gate. This does not mean an external audit occurred; see the
[REALITY review notes](docs/stage5-crypto-review-and-interop.en.md).

## 2026-10-17: UID and site rules in one TUN (experimental)

- Instead of trusting a substituted `package_name`, the core trusts only the
  UID supplied by the host application through a callback for the original
  TCP/UDP address pair. Internal DNS and proxy inbounds do not invent a UID.
- The first matching rule keeps priority. If a rule requires a UID and that
  UID is unknown, the connection is blocked instead of bypassing the rule via
  `direct`/`final`, including when `invert` is set.
- The resolver is called only for new TUN flows when UID rules are present.
- The C ABI change is additive; Rust `Metadata` gains a field. Android needs a
  separate JNI/adapter integration (API 29+), app capture in TUN, and handling
  for shared UIDs. Until then, the restriction on mixing client rules must
  remain in place.
- Real devices, API 24–28, DoH, and power consumption have not been tested.

Stage status (updated as work progresses):

| Stage | Work | Status |
|---|---|---|
| 0 | Measurement infrastructure | ✅ complete (`bench/`) |
| 1 | Minimal VLESS client (TCP+TLS, SOCKS5) | ✅ complete; since 2026-09-26 also real `security=none` without TLS, XTLS Vision, UDP, and SOCKS5 username/password |
| 2 | Buffer owned by each connection instead of a global pool | ✅ complete (memory check with Valgrind; see below) |
| 3 | TLS fingerprinting (uTLS equivalent) | ✅ ClientHello matches Chrome 133, including JA4, in REALITY; ordinary TLS intentionally omits legacy cipher suites and ALPS (see “2026-09-26 improvements”) |
| 4 | Transports (WebSocket, gRPC) | ✅ complete and checked against real Xray-core; since 2026-09-26 also HTTPUpgrade and XHTTP (all modes) |
| 5 | REALITY | ✅ works over TCP/WS/gRPC, X25519MLKEM768 with fallback to X25519, and ML-DSA-65 (`pqv=`); checked against XTLS/REALITY and Xray-core. No external crypto review has taken place |
| 6 | Zero-copy (`splice`, server side) | ✅ not applicable to this core — an architectural fact, not unfinished work (see below) |
| 7 | Allocator profiling | ✅ complete (the system allocator is a sensible default; `mimalloc` is optional) |
| 8 | Final comparison and publication | ✅ comparison with Xray-core completed (remeasured 2026-09-26 on 26.9.9); publication is the user's decision |

---

## Addendum: external TUN and C ABI observability (2026-10-16)

Experimental mobile integration does not change the protocols or rustls.
An externally supplied FD disables route management, but not the core resolver
or the system-DNS loop check. To avoid the recursion “proxy → DNS → same
proxy,” transport hostnames use only explicitly configured `dns.bootstrap`
(direct UDP DNS to an IP address). This is an extension, not a field compatible
with another client's schema; users must be told that transport server names
may be exposed directly. Defaults for the regular CLI do not change. For
applications, the first DNS rule selects both the server and strategy,
including fake-IP; bootstrap does not inherit an IPv6-only application's
address-family preference.

`rc_validate` builds the configuration without starting inbounds or passing a
TUN FD. Its result is only 0/1, and it may read files; success does not guarantee
that the core can start. `rc_is_alive` reads sticky errors from supervised
tasks; it does not perform a network ping. Polling does not consume the error
that `Running::wait` needs. Unwind panics reach the error channel, while
`panic=abort` and failures from unsupervised detached tasks remain limitations.
One C handle serializes calls from the host application. Real mobile networks,
sleep, and battery use need separate testing; Android/iOS remain experimental
as a whole.

## Development (since 2026-09-26): from a client to an Xray/sing-box-level core

The goal is to make the core a full replacement for an Xray or sing-box client
for personal use: system-wide VPN, split tunneling, its own DNS, multiple
servers from a subscription, browser fingerprints, and DPI countermeasures.
The decisions and outcome of each phase follow.

Out of scope: a graphical interface (a separate project built on the API), a
server component, ready-made Android and iOS apps (the core is a library for
them; see [`docs/LIBRARY.en.md`](docs/LIBRARY.en.md)), and Shadowsocks 2022.

### Phase 0 — “inbounds → router → outbounds” architecture ✅

- `core/src/app/` defines the `Outbound` trait (TCP `connect`, UDP `udp` →
  `UdpSession`) and inbounds that ask `Router` using `Metadata` (inbound,
  source, network, destination, port, and discovered domain). Outbounds are
  `vless` (XUDP or a stream to the destination), `direct`, and `block`.
- Configuration started as TOML (`--config`, `--check`; sing-box/Xray JSON
  was added in Phase 10). `deny_unknown_fields` turns a misspelled field into
  an error instead of silently ignoring it. CLI flags produce the same
  `Config`, so both input methods share validation.
- A UDP association keeps one session per selected outbound; replies from all
  sessions go back to the association that owns them.
- Security: `direct` does not let network clients connect to addresses on the
  local machine (`127.0.0.1`, `localhost`; the resolved address is checked).
  Otherwise, a proxy exposed to the network could expose services listening
  only on loopback.

### Phase 1 — HTTP/mixed, rules, sniffing, system proxy ✅

- Inbounds: `socks`, `http`, and `mixed` (detected from the first byte). HTTP
  supports CONNECT and regular requests. Regular request lines are converted
  to origin-form, proxy headers are removed, and `Connection: close` prevents
  a later request on the same connection from going to the wrong site;
  WebSocket's `Connection: Upgrade` is preserved. Passwords use
  `Proxy-Authorization: Basic` and share the SOCKS5 bad-password counter.
  A request without a password is not treated as an error because browsers
  first probe without credentials.
- Rules follow sing-box's shape: `(domain OR address) AND port AND network
  AND inbound`; the first match wins. Domains use exact and suffix matching
  (`HashSet` plus parent-domain iteration), substring matching, and
  `RegexSet`. Addresses are merged sorted ranges searched with binary search.
  With real v2fly databases (`category-ads-all` + `category-ru` +
  `geoip:ru,private`), debug load took 0.2 s and a rule check about 0.4 μs.
- `geosite.dat`/`geoip.dat` use a custom protobuf parser (varints and
  length-delimited fields); only requested categories are loaded. Corrupt
  input returns an error instead of panicking (including a garbage-input
  test). Individual geosite expressions unsupported by the regex crate's
  RE2 dialect are skipped.
- TLS SNI / HTTP Host sniffing is used only when the application supplied an
  IP address. The “connected” reply must be sent before opening the outbound,
  or the application will not send the bytes to sniff; any later error can
  therefore only be reported by closing the connection. The wait is capped
  at 300 ms for protocols where the server speaks first.
  `sniff_override_destination` passes the discovered domain to the outbound
  instead of the IP.
- Windows `--system-proxy` updates `ProxyEnable/ProxyServer/ProxyOverride`
  in HKCU and calls `InternetSetOption`. Prior values (including missing
  values) are restored on Ctrl+C, window close, or sign-out; use
  `--system-proxy-off` after a hard termination. Checked under Wine with a
  registry unit test and an end-to-end run interrupted by SIGINT.
- Not completed in this phase: QUIC sniffing (added in Phase 9; a QUIC
  Initial with Chrome ClientHello across two packets), sing-box `.srs` rule
  sets (added in Phase 9), and resolving names for IP rules
  (`IPIfNonMatch`, assigned to Phase 2/DNS).

### Phase 2 — DNS ✅

- `core/src/app/dns/` contains UDP/TCP/DoT/DoH/`local`/`fakeip` servers
  (`upstream.rs`), selection by domain rules and geosite (the same
  `DomainSet` used by routing), a size-limited TTL cache (`cache.rs`), and
  ring-allocated fake IPs persisted to a file (`fakeip.rs`).
  `hickory-proto` handles message formats only; transport is implemented here.
- DNS servers use outbounds (`detour`, defaulting to `route.final`): DoH over
  VLESS hides queried names from the access provider. UDP DNS over VLESS uses
  XUDP (smoke-checked against Xray). A reply is accepted only if its ID,
  response flag, question, and server address match. A truncated UDP reply
  (`TC`) is retried over TCP; a UDP reply to a client without EDNS is truncated
  and marked `TC`.
- Loop prevention: `direct` resolves DNS-module server names through the
  system resolver using the `dns-internal` marker. `detour` to the `dns`
  outbound is a configuration error. VLESS server names use the system
  resolver with a cache (120 s; on DNS failure, old addresses remain usable
  for up to an hour), closing an open DNS-cache audit item.
- There is a UDP+TCP `dns` inbound (up to 256 concurrent requests), a `dns`
  outbound (intercepts rules with `port = [53]`), and `direct` resolution
  through the module. `route.domain_strategy = "ip_if_non_match"` requires
  `[dns]`; otherwise names would bypass the tunnel through system DNS.
  The router maps fake IPs back to names; unknown fake IPs fail. UDP to a
  fake IP gets a dedicated address session, and replies use the fake IP.
- The DNS inbound refuses to start on a network address without `allow_ip`
  (to avoid an open resolver).
- `Error::Protocol` no longer labels every error “VLESS protocol error”:
  DNS, direct, and HTTP errors are not VLESS errors.
- Verification recorded: seven integration tests in
  `core/tests/app_dns.rs` (UDP/TCP, cache, TC, DoT, DoH, untrusted
  certificate, fake-IP over TCP and UDP, interception, `ip_if_non_match`,
  and configuration errors), plus an Xray smoke test. Public DoH/DoT could
  not be tested from the sandbox because its gateway substitutes certificates
  (which the client correctly rejects); they must be checked on a normal
  machine.
- Not completed: DNS over QUIC (added in Phase 9) and HTTP/3, ECS, and a
  separate per-server cache for identical names (not needed). DNS interception
  in TUN belonged to Phase 3.

### Phase 3 — TUN ✅ (Linux and Windows)

- The device uses `tun-rs` (`/dev/net/tun` on Linux; Wintun and a neighboring
  `wintun.dll` on Windows). The custom TCP/IP stack is smoltcp through
  `netstack-smoltcp` (initially `ipstack`; see below). UDP is split into flows
  by address pair (`tun/udp.rs`). TUN connections take the same path as
  SOCKS5: sniffing → router (fake IP → name) → outbound.
- `net_protect` prevents the loop “client → TUN → client”: on Linux, every
  outbound socket (VLESS, `direct`, DNS) gets `SO_MARK 0x7e2`; on Windows it
  is bound to a physical interface (`IP_UNICAST_IF`).
- Linux `auto_route` follows sing-box's approach: table 2022 has a default
  route through TUN, `fwmark → main`, `route_exclude → main`, and `everything
  else → 2022`; `strict_route` adds `unreachable` as a kill switch. If the
  client is killed, the interface disappears with its routes and the table
  empties, so networking works again (or remains blocked under `strict_route`
  until `--tun-cleanup`). Windows adds routes `0.0.0.0/1`, `128.0.0.0/1`
  (and IPv6) through `netsh`, sets interface DNS to the neighboring TUN
  address for interception, and uses metric 1.
- VLESS and DNS server names are resolved before routes are enabled and then
  served from cache (refreshed in the background). With TUN active, system
  DNS itself goes through the client, so waiting for it while establishing a
  connection would loop. `local` DNS with TUN is a configuration error.
- IPv6 defaults to `fdfe:dcba:9876::1/126` so IPv6 cannot bypass TUN. It is
  silently disabled when the system has no IPv6; an explicitly requested
  IPv6 setup then fails.
- The first stack was `ipstack` 1.0 (512 KiB window, no MSS in SYN-ACK —
  adding it dropped connections; segments were therefore 536 bytes, about
  85 MiB/s). GitHub Actions `tun_netns.sh` hung after packet loss: TCP stopped
  permanently. Reproduced locally (TUN `txqueuelen 50` or
  `iptables … statistic --probability 0.02 -j DROP`). An out-of-order segment
  could sit behind an ACK when the kernel retransmitted the gap in different
  chunks (`consume_unordered_packets` made no further progress). No duplicate
  ACK was sent for the out-of-order segment, so the sender detected loss only
  through exponentially growing timeouts. Patching those paths helped little
  (5/8 versus 4/8 at 2% loss). It was replaced with smoltcp
  (`netstack-smoltcp`, as in clash-rs and xray-rust): 8/8 at 2% loss, 4/4 at
  5%, and 4/4 with a 50-packet TUN queue and loss in both directions. MSS now
  follows MTU and the 256 KiB window reached about 200–270 MiB/s through
  TUN+VLESS instead of about 85 MiB/s.
- Verified by `scripts/tun_netns.sh` in an isolated network namespace with
  veth to a host running Xray, echo, and DNS: TCP, 32 MiB transfer, `direct`
  without a loop, `route_exclude`, UDP/XUDP, DNS interception to 8.8.8.8
  (real answer and fake-IP), fake-IP connection, Ctrl+C, `kill -9`, stale
  state from an earlier run, kill switch, and `--tun-cleanup`. Added to
  `scripts/ci.sh`.
- On a real Windows runner (`scripts/windows_live_test.ps1`), the first HTTPS
  attempt through TUN failed. The runner has no IPv6, but TUN captured `::/1`
  and `8000::/1`; an IPv6 `direct` socket without a physical-interface index
  remained unbound and went back into TUN. The loop exhausted the connection
  limit in a second. IPv6 is now enabled in TUN only when the physical
  interface has IPv6, and an unbound socket now reports “network
  unreachable.” The service also failed to stop within 10 s because the
  runtime waited for `spawn_blocking`; shutdown now uses
  `shutdown_timeout(2 s)`.
- Not completed: Windows kill switch and IPv6 exclusions; ICMP.

### Phase 4 — server groups and subscriptions ✅

- `group.rs`: `selector`, `urltest`, and `fallback` outbounds select a member.
  Health checks send HTTP/1.1 `GET url` through the member (the custom
  `http_client.rs` works over any outbound and uses TLS for HTTPS) and measure
  time to the response line. Checks run every `interval` with ±20% jitter
  (a perfectly regular rhythm can be a DPI signal), up to eight at once.
  `urltest` keeps the current member until it is worse than the best by more
  than `tolerance`. Passive tracking marks a member down until the next check
  when opening a connection fails, then tries the next one (up to three; not
  for `selector`, where the selected member remains selected). Groups may
  contain other groups; cycles are configuration errors.
- `subscription.rs` parses base64 (standard or URL-safe, padded or not), plain
  text, sing-box JSON, and Clash YAML (`yaml_serde`) into `vless://` links;
  duplicate names receive a number. Server tags are `<subscription>/<name>`.
  Links use the same validation as a `vless` outbound (`security=none` only
  with `allow_insecure`). `include`/`exclude` are regexes applied to names.
- Subscription security: the URL is a secret (prefer `url_file`) and is never
  written to logs or error messages, including parse errors. HTTPS with
  certificate verification is required; otherwise anyone on the path could
  replace the server list and therefore control all traffic. Verification also
  applies after redirects. Limits: response ≤ 4 MiB, ≤ 3 redirects, 30 s.
  The saved list is written to a temporary file and renamed, with mode 600.
- Downloads use `detour`, otherwise the subscription's group; if the list is
  empty, they connect directly. A fresh saved list means the panel is not
  contacted at startup. Errors retry after one minute while there is no list,
  or after five minutes otherwise.
- With TUN, subscriptions without a saved list are fetched and all group
  server names are resolved before routes are enabled. Later names use the
  core DNS (`Dns::lookup`, without fake-IP), not system DNS: system requests
  now traverse TUN and could return a fake IP. Background address refresh is
  limited to one lookup per name at a time (otherwise DNS through the same
  server could trigger another refresh).
- Verification recorded in `core/tests/app_groups.rs`: `urltest`/`fallback`/
  `selector` with live and dead members; HTTPS panel with a custom CA —
  download, cache, mode 600, startup without panel, 503, wrong certificate;
  and 18 configuration errors. `scripts/smoke_xray.sh` tests subscription →
  `urltest` → Xray server.
- Not completed: changing `selector` externally (Phase 8 API); subscription
  protocols other than VLESS (Phase 8); `vless+xhttp` from sing-box/Clash JSON
  is skipped (it works when carried in a base64 link).

### Phase 5 — multiplexing ✅ (without HTTP/3)

- `vless/mux.rs` implements Xray-compatible Mux.Cool for TCP: a VLESS stream
  with the Mux command, New/Keep/End/KeepAlive frames, session IDs starting
  at 1, data chunks of 8 KiB, no more than `concurrency` simultaneous
  connections and 128 over the stream's lifetime. An empty stream closes
  after 16 s. New streams open one at a time (no handshake thundering herd);
  a stream closed between selection and opening is retried. Mux.Cool has no
  flow-control window of its own, so a slow receiver stalls the stream as in
  Xray; queues are bounded.
- Enabled as `mux = N` on a VLESS outbound or subscription. It is a
  configuration error with Vision; subscription servers using Vision simply
  do not use mux.
- `transport/h2pool.rs` shares HTTP/2 connections following Xray's
  `XmuxManager`: invalid connections (closed, or at session/request/time
  limits) are removed. `maxConnections` opens new connections up to N;
  otherwise one with capacity is chosen at random using `maxConcurrency`.
  Connection limits are randomly selected from ranges. An idle connection
  closes after 90 s; if a pooled connection has closed, one retry is made on
  a new connection.
- gRPC sends all streams to a server through one connection (like Xray's
  `grpc.ClientConn`). For XHTTP over h2, `xmux` comes from `extra=`; without it,
  Xray defaults are used (16–32 sessions, 600–900 requests, 1800–3000 s), and
  each GET/POST request is counted.
- Checked against Xray-core with a TCP-connection-counting intermediary:
  20 Mux.Cool connections at `mux = 8` used three streams; 11 gRPC streams
  used one connection; eight XHTTP stream-one and packet-up sessions used
  one connection, while `maxConcurrency: 2` used four.
- Not completed: XHTTP over HTTP/3 (QUIC; added in Phase 9) was considered a
  separate large task (`quinn` + `h3`) and not a priority. `hKeepAlivePeriod`
  (HTTP/2 PING) is accepted but unused.

### Phase 6 — DPI countermeasures: fragment and noises ✅

- `transport/fragment.rs` follows Xray `freedom`'s `fragment`: `tlshello`
  splits the first record containing ClientHello into records of `length`.
  With `interval = 0`, the pieces are sent in one write; otherwise each is a
  separate TCP segment with a pause. A range like `"a-b"` splits records a
  through b of each connection into segments. Lengths and pauses are random
  per piece. After fragmentation, traffic is forwarded directly without
  extra overhead. It is integrated into `RawConn` (all server transports:
  TCP, WS, gRPC, XHTTP, HTTPUpgrade) and `FragmentStream` (`direct` outbound).
  Vector writes are disabled while splitting so the complete ClientHello
  reaches the fragmenter.
- `transport/noise.rs`: `noises` on `direct` sends `rand`/`str`/`base64`/
  `hex` packets with `delay` pauses before the first datagram to a new address
  within a UDP session. `apply_to` selects ip/ipv4/ipv6; port 53 is excluded.
- Verification: Xray REALITY server accepts ClientHello split into 1–3 byte
  records, TCP segments with pauses, and Vision. An intermediary confirms
  that the wire contains many records of the requested lengths.
  `app_obfs.rs` checks `direct` fragmentation (segments and payload remain
  intact), noise only before the first datagram, and configuration errors.
- Separate timing/padding work was not done: Vision and XHTTP have their own
  padding as in Xray, and pauses are provided by `fragment.interval`. Random
  delays on every packet would only slow connections without hiding the
  protocol.

### Phase 7 — browser fingerprints ✅

- `fingerprint/profiles.rs`: Firefox 148 and Safari 26.3 profiles based on
  utls `u_parrots.go` (as in Xray: `HelloFirefox_Auto` and
  `HelloSafari_Auto`). `ios` uses Safari 26 (Xray used iOS 14 without ML-KEM,
  from 2020); `edge` and `android` use Chrome (Xray used Edge 85 and Android
  11 OkHttp, the latter TLS 1.2 only and incompatible with REALITY). `random`
  selects one profile per process; `randomized` uses per-outbound random
  parameters (utls's random parameters do not resemble any browser).
- The rustls patch (`ChromeHello`) adds `no_grease`, `named_groups` (including
  declaring only P-521/ffdhe, where the server selects a group from the key
  shares), and `extension_order` (fixed order rather than random; GREASE, ECH,
  and PSK stay in their required positions). It also adds `no_psk_modes` and
  `extra_p256_share`: a real second P-256 key share through
  `ActiveKeyExchange::extra_share`/`complete_extra` and
  `KeyExchangeChoice::Extra`. A HelloRetryRequest for a group already offered
  is an error, as required. `ClientConfig::clear_ech` supports Safari, which
  has no ECH.
- Certificate compression: zlib (`miniz_oxide`) and zstd (`ruzstd`) use pure
  Rust and perform real decompression (tested with a server compressing both
  formats).
- WS/HTTPUpgrade/XHTTP HTTP headers and the site visit used when REALITY is
  diverted use the same browser identity: Firefox UA at the current version,
  without Client Hints; Safari UA 26.3. In XHTTP,
  `User-Agent: firefox` / `safari` / `chrome` in `extra.headers` explicitly
  selects the browser.
- Verification: `fingerprint_profiles.rs` compares each ClientHello field
  on the wire against reference values for REALITY and TLS. Chrome/Edge/
  Android use Chrome JA4; with a P-256-only server Firefox avoids HRR while
  Chrome and Safari use HRR. Xray REALITY interoperability was tested for all
  `fp` values over TCP, Vision, XHTTP, and gRPC.
  `check_chrome_fingerprint.sh` also monitors `HelloFirefox_Auto` and
  `HelloSafari_Auto`.
- Not completed: byte-for-byte Firefox ECH-GREASE length; `record_size_limit`
  is advertised but server record size is not enforced (Go, BoringSSL, and
  OpenSSL do not send it); 360/QQ profiles.

### Phase 8 (part 1) — API, config reload, presets ✅

- `app/stats.rs`: connection tracking (`Tracker`) counts TCP through a
  counter on the outbound stream and UDP by sessions; totals and per-outbound
  traffic are reported. Closing a connection uses a cancellation token read
  by the relay.
- `app/api.rs`: HTTP/1.1 + JSON; a token is required (constant-time compare,
  with a pause after 10 invalid tokens). The API checks `Host` against DNS
  rebinding, rejects requests with `Origin`, requires `allow_ip` for
  non-loopback access, and limits headers, body size, and connection count.
- Reload: inbounds get the current router from `RouterHandle` for each new
  connection (the DNS inbound and TUN also use its DNS module). `Controller`
  builds a new core (outbounds, groups, subscriptions, DNS, rules); on error,
  nothing changes. Inbounds are compared by settings: unchanged ones keep
  listening and changed ones restart. Fake-IP keeps its table when its
  settings have not changed. CLI supports SIGHUP.
- Rule presets use `route.presets`.
- Verification: `app_api.rs` covers API security, selector member choice,
  listing and closing connections, counters; reload preserves open
  connections, sends new ones under new rules, opens a new inbound, rejects
  invalid settings; reloads a file through the API; and applies presets.
- Trojan (`trojan.rs`, `app/trojan_out.rs`) uses a SHA-224 header and SOCKS5
  address, plus UDP packets. Through `transport::open` it uses the same
  TLS/REALITY and WS/gRPC/HTTPUpgrade/XHTTP transports as VLESS;
  `security=none` requires `allow_insecure`. Subscriptions parse `trojan://`
  links and Trojan entries in sing-box/Clash. Checked against Xray over
  TCP+TLS, WS+TLS, REALITY, TCP, and UDP.
- Not completed in Phase 8: Shadowsocks 2022; Windows service/auto-start was
  implemented in Phase 9.

### Phase 9 — remaining work that did not require the user (2026-09-27)

- sing-box rule sets (`app/ruleset.rs`): `[[route.rule_set]]` accepts `.srs`
  versions 1–3 or source `.json`. `rule_set = [...]` in routing and DNS
  rules appends the set's domains and addresses before compilation. `.srs`
  follows sing-box's source format: zlib (256 MiB cap), compressed LOUDS
  domain trie (strings reversed by character), and addresses converted from
  ranges to CIDRs. Every length is checked against remaining bytes so a bad
  file returns an error without panicking or huge allocation. Conditions
  that cannot be represented as domains/addresses (port, process, `and`/`or`,
  `invert`) are rejected. An empty set in a rule is rejected because the
  remaining conditions could otherwise make it match everything. Only used
  sets are loaded. Checked by compiling with `sing-box rule-set compile` and
  comparing our parse → `rule-set decompile` byte-for-byte (versions 1–3,
  3000+ domains, IDN, dotted/non-dotted suffixes, IPv4/IPv6 ranges), plus five
  real SagerNet and MetaCubeX sets (geosite ads/ru/geolocation-cn, geoip-ru,
  youtube; up to 10,870 entries). Routing and configuration errors are in
  `app_ruleset.rs`.
- QUIC sniffing (`app/sniff_quic.rs`) in TUN inbounds: QUIC v1/v2 Initial
  packets; keys derived from DCID (HKDF, RFC 9001/9369 salts), header
  protection removed (AES-ECB), AES-128-GCM, CRYPTO frames assembled by
  offset from multiple datagrams and coalesced packets (Chrome's ML-KEM
  ClientHello spans two packets with interleaved frames). ClientHello uses
  the same parser as TCP. Limits: 16 KiB CRYPTO, eight datagrams, 300 ms.
  Datagrams are forwarded unchanged. Verified with RFC 9001/9369 key vectors,
  RFC 9001 Appendix A.2 packet, locally packed packets (reordering,
  overlaps, coalescing), 3000 malformed packets without panic, and real
  Chromium 140 datagrams (`scripts/capture_chrome_quic.sh`), which reveal the
  domain after the second packet. `tun_netns.sh` sends Chromium packets through
  TUN to `direct` by a domain rule. SOCKS5 UDP does not parse QUIC because it
  selects a route for each datagram.
- QUIC client (`transport/quic.rs`, quinn 0.11 on the same rustls/aws-lc,
  TLS 1.3 only): connects over a real UDP socket marked with `net_protect` or
  over any outbound's UDP session (`SessionSocket`, with 256-packet queues
  in each direction; overflow drops packets as a network would; tasks stop
  with the socket).
- DNS over QUIC (`quic://`, RFC 9250): `doq` ALPN, request ID 0, one stream
  per request, one connection for all requests (one reconnect/retry if it
  closes). Checked against a local quinn server (20 requests on one
  connection; wrong certificate gives SERVFAIL) and over VLESS (REALITY +
  Vision → XUDP) against Xray-core.
- XHTTP over HTTP/3 (`alpn=h3`, `security=tls` only, as in Xray): h3 +
  h3-quinn, all three modes; connections use the shared `xmux` pool (shared
  between h2 and h3 through the `Sender` trait). Checked against Xray inbound
  with `alpn = ["h3"]`: packet-up, stream-up, and stream-one with eight
  sessions each use one QUIC connection; a wrong certificate gives a clear
  error. `fp=` has no effect on QUIC (same as Xray's quic-go).
- Auto-start. Windows service (`windows-service`): `--service-install` copies
  settings, referenced files (only from the settings directory, via
  `Config::input_files`), the executable, and `wintun.dll` to
  `%ProgramData%\RealityClient` with
  `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`. The folder is created with these
  permissions (`CreateDirectoryW`); an existing folder is accepted only if
  owned by Administrators or SYSTEM. Files are recopied (an existing file or
  planted symlink is removed), so a SYSTEM service never executes or reads
  user-replaceable content. The service starts automatically and restarts
  after failures (5 s/30 s/2 min); Stop and Shutdown restore routes and proxy
  settings. `--autostart-install` writes HKCU\...\Run without a window (for
  `--system-proxy`). Both support `--log-file`. Linux has
  `examples/reality-client.service` (CAP_NET_ADMIN only; `ExecReload` sends
  SIGHUP). Checked under Wine (`cross_windows.sh`): install, settings copy,
  open port, uninstall, clean shutdown, and registry auto-start. Folder ACLs
  on real Windows were not checked (Wine does not enforce them).

### Phase 10 — sing-box and Xray configuration formats (2026-09-28) ✅

- Custom TOML was removed (there had been no releases, so nothing depended on
  it). `--config` accepts sing-box JSON (1.11+: rule actions, DNS servers
  with `type`, and older forms) or Xray-core JSON. Format is detected from
  keys such as inbound/outbound `protocol`, `routing`, `fakedns`, and
  `observatory`. Comments and trailing commas (JSONC) are accepted, as in
  both cores.
- Both formats map into the same `Config` (`app/config/singbox.rs`,
  `xray.rs`); the rest of the code is unchanged. Outbounds are converted to
  `vless://`/`trojan://` links and validated by the same parser as subscription
  links.
- Instead of `deny_unknown_fields`, an `Obj` walk tracks consumed keys.
  Extra keys fail with a path (`outbounds[2].multiplex`); unsupported
  features (other protocols, `detour` chains, sing-box multiplexing, Xray
  `kcp`) return an explanation rather than being ignored.
- Features absent from those formats are exposed as extensions with the same
  syntax (`link`/`link_file`, VLESS `mux` and `fragment`, `fallback`,
  subscriptions, `presets`, `allow_ip`, etc.). `clash_api` holds the API
  address and secret.
- Verification: all tests were rewritten for sing-box JSON;
  `smoke_xray.sh` sends traffic to real Xray using both configuration formats;
  `tun_netns.sh` tests TUN using sing-box settings.

### Phase 15 — library mode (2026-09-28) ✅

- The `ffi/` crate (`reality-ffi`, `libreality`: cdylib + staticlib) exposes
  a C ABI and `ffi/include/reality.h`; see [`docs/LIBRARY.en.md`](docs/LIBRARY.en.md).
  C ABI was chosen over UniFFI and similar options because any language can
  call it (JNI, Swift, cgo, P/Invoke) without code generators in the build.
- `rc_request` exposes the entire HTTP API as a function call
  (`Api::embedded`, `Api::local`), reusing the same path parsing and server
  responses instead of duplicating them. Streams use callbacks
  (`rc_set_event_callback`, `rc_set_log_callback`); subscriptions are
  established before return so events are not lost.
- Mobile: `InboundConfig::tun_fd` (programmatic only) →
  `AsyncDevice::from_fd`; the OS owns routes and kill switch.
  `net_protect::set_callback` runs for each new socket (Android:
  `VpnService.protect`).
- Verification recorded: `scripts/ffi_smoke.sh` builds a C program against
  `libreality.so`, sends traffic through the core's SOCKS5 inbound, controls
  it through `rc_request`, receives events, checks socket protection,
  `rc_reload` and `rc_stop`, and (as root) starts with an existing TUN FD.
  `cargo test -p reality-ffi` exercises the same calls from Rust and in
  Windows CI. Android/iOS builds were not checked at that point (NDK and
  Xcode were required); build steps were documented.

### Phase 14 — Windows kill switch (2026-09-28)

- Windows `strict_route` uses persistent WFP filters (`tun/wfp.rs`), modeled
  on WireGuard “block untunneled traffic” and Mullvad. A custom sublayer has
  highest weight at ALE connect/recv-accept for IPv4/IPv6. It allows only the
  client executable (app ID), loopback, TUN interface (LUID),
  `route_exclude`, DHCP, and for IPv6 ICMPv6/DHCPv6/link-local; everything
  else is blocked. `FWPM_FILTER_FLAG_PERSISTENT` survives crashes and
  reboots. Stable GUID keys allow removal without process state
  (`RouteGuard`, next launch, `--tun-cleanup`).
- Verified only on real Windows (Wine does not implement WFP):
  `scripts/windows_live_test.ps1` installs a service with `strict_route`,
  checks HTTPS through TUN, kills the process (`Stop-Process -Force`) and
  verifies an IP connection cannot bypass the tunnel, confirms SCM restarts
  the service (5 s) and traffic again goes through TUN, then removes the
  service and checks that filters were removed and direct networking works.
- Limitation (also on Linux): after a crash, system DNS is blocked too.
  On restart, the server name can be resolved only via its own DNS (server
  IP with `detour: direct`) or by configuring the server as an IP address.

### Phase 13 — change settings through the API (2026-09-28) ✅

- `GET /config` returns the settings file (path, format, and text as-is,
  including comments). `PUT /config` replaces all settings (sing-box or
  Xray): `?check=1` only builds (`App::build`); otherwise it reloads
  (`Controller::reload`) and writes the file atomically (temporary file →
  `rename`, previous file → `.bak`, permissions preserved). `?save=0` skips
  writing. `PUT /configs` with Clash `payload` applies without saving.
- Order is “apply, then save”: a build error changes neither runtime nor file.
  If saving fails, new settings remain active and `notes` reports the issue.
- Paths supplied through the API must stay within the settings directory
  (`Config::check_paths_confined`: relative, no `..`). Otherwise the API token
  could read arbitrary files as the service (SYSTEM); `link_file` parse
  errors can echo parts of the content (for example, `type=`). A single
  `Config::for_each_path` traversal is used both to bind paths to the settings
  directory (`parse_at`) and to validate them.
- API request body limit increased from 64 KiB to 1 MiB for configurations
  with large rule lists.

### Phase 12 — Clash API compatibility (2026-09-28) ✅

- Reference was real sing-box 1.12 with the same configuration. Responses
  were captured for `/`, `/version`, `/configs`, `/proxies`, `/group`,
  `/rules`, `/connections`, `/providers/*`, `/dns/query`, CORS and errors
  (`{"message"}`), plus WebSocket with `?token=`. Our responses match its
  fields; `core/tests/app_clash_api.rs` keeps their formats covered.
- Checked with real panels: latest metacubexd and yacd 0.3.8 opened in
  headless Chromium (Playwright) from `external_ui`. Tested proxies, groups,
  click-to-select server (`PUT /proxies`), group delay checks, connections,
  rules, logs, UI mode (`PATCH /configs`), and all four WebSocket streams.
  Found and fixed one incompatibility: Clash `GET /` works without a token
  because yacd uses it to check the server.
- rule/global/direct modes (`Tracker::mode`) survive reload. `GLOBAL` selects
  among all outbounds. DNS interception continues to work in global/direct
  modes. Group selections now survive reload (previously reset to `default`).
- `/connections` uses Clash format (chain, rule, RFC 3339 `start`). `Metadata`
  gained inbound type and rule description (`rules::describe`, before rule
  set expansion) for this. Project-specific `/stats`, `/groups`, `/events`,
  and `/reload` remain.
- Security: browser requests are accepted only from the panel itself and
  sites in `access_control_allow_origin` (previously browsers were always
  blocked). Without a token, only panel static files and the greeting are
  available. Panel files must remain inside its directory (`..`, `\`, and
  `:` are rejected; path is checked after `canonicalize`).
  `external_ui_download_url` is an error: the client will not download and
  unpack code from the internet.
- Not completed: `PUT /configs` with `payload`/`path` (new settings through
  API were the next item), changing log level and ports via `PATCH /configs`
  (400 with explanation), and metacubexd `/api/control/*` (not part of Clash
  API).

### Phase 11 — control: API event streams (2026-09-28) ✅

- `GET /events`, `/traffic`, `/memory`, `/logs` return streams: one JSON
  object per line (chunked) or WebSocket (`Upgrade: websocket`, same port;
  server uses async-tungstenite, already a dependency for WS transport).
  `/traffic`, `/memory`, and `/logs` use Clash API formats (a step toward
  panel compatibility, completed in the next phase).
- The event bus (`app/events.rs`) is one per app, lives in `Tracker`, and
  survives reload. `emit` takes a closure and constructs an event only if
  there are listeners. A custom listener count uses an atomic read instead
  of locking inside broadcast; with no listeners, the connection path pays
  for one atomic read on open and close.
- Logging uses a `tracing` layer (`LogLayer`) above the global filter and
  sees only what is already logged. No dynamic filter runs on every
  `trace!` call (that would affect smoltcp/rustls hot paths).
- Slow listeners do not stall the app: broadcast capacity is 1024 events
  and lagging listeners receive `lagged`. At most 16 streams are allowed;
  a client-closed stream is detected by EOF while reading.
- Also fixed: an unselected `selector` now reports its first member as
  current (previously `null`, although the first member was active).

## Improvements (2026-09-26): everything that was left open

Request: “analyze the project, understand what is unfinished, and finish it.”
The user selected all items: XTLS Vision, Chrome-like ClientHello, UDP and
SOCKS5 login, and ML-DSA-65; asked to “add” brotli; and approved legacy cipher
suites “for REALITY only.”

### Key step: real Xray-core as the test server

Xray release downloads from GitHub and `proxy.golang.org` were blocked in
that environment, but GitHub `git` access worked. Go 1.27.1 and Xray-core
26.9.9 were built from source, including about 55 Git dependencies
(`scripts/build_xray_from_source.sh`). This became the test setup for
`core/tests/interop_xray.rs` (11 tests) and `scripts/smoke_xray.sh`. Instead
of testing an implementation against itself, the client could be checked
against the server it is intended to use. It immediately exposed four serious
bugs missed by all earlier tests (listed below).

### Bugs found and fixed, each with a test

1. **`security=none` actually enabled TLS.** `connect_tls_by_security`
   combined `None` and `Tls` in one branch, so servers without TLS could not
   be used. It now uses plain TCP (`SecureStream::Plain`).
2. **gRPC hung with every real Xray server.** The client waited for HTTP/2
   response headers before sending the VLESS header, but grpc-go sends them
   only with the first message. The local test h2 server replied immediately
   and had hidden the issue.
3. **REALITY failed with decoy sites without ML-KEM.** The key share held
   only the hybrid share, which ordinary OpenSSL before 3.5 cannot select;
   the server returned “target sent incorrect server hello.” As in Chrome,
   the X25519 part of the hybrid is now also sent as a separate share.
4. **gRPC buffered without a limit** when the server was slow (`send_data`
   ignored the HTTP/2 window). It now uses `reserve_capacity`/
   `poll_capacity`.
5. Smaller fixes: unknown `type=`/`security=` used to silently become
   tcp/none (now an error); the relay could omit a tail when the socket was
   busy and the app went silent (flush added); `cargo fmt --check` failed,
   breaking CI on its first step; stale comments in `lib.rs`, `grpc.rs`, and
   `fingerprint/` were corrected.

### XTLS Vision

`core/src/vless/vision.rs` ports Xray-core `proxy/proxy.go` while preserving
decision order: padding (UUID in the first block, long padding to 900+ bytes
for short packets), first-eight-packet filter (ClientHello/ServerHello,
TLS 1.3 and cipher), Continue/End/Direct commands, per-direction transition
to direct forwarding, and VLESS header sent with initial data or after
500 ms of silence.

Two findings were needed for reliable Vision:

- **rustls reads ahead.** After a `Direct` block, the server writes raw inner
  TLS records to TCP. Go reads one outer TLS record at a time, but rustls
  reads as much as the socket provides and decrypts it all. In Vision mode,
  `transport/raw.rs` now gives rustls exactly one record and retains the rest
  itself, like Go's `rawInput`.
- **tokio-rustls also reads ahead.** Its `poll_read` fills available buffer
  space with later records, swallowing raw bytes after `Direct` and even
  sending an alert into the stream. An interop test caught this as an
  intermittent DecryptError (one failure in three to five runs). Vision now
  reads through `poll_fill_buf` (exactly one record); the test then passed
  20/20 times.

A third issue found by smoke testing: the relay buffer was exactly 16 KiB,
but a full TLS record is 16 KiB plus a header. For large sends, Vision never
saw a complete record and never switched to direct forwarding. The buffer
was increased to 17 KiB.

Limitations follow Xray: only `type=tcp` with `tls`/`reality`; UDP works
without Vision (Xray server permits this even for a Vision account); no
Mux/XUDP.

### ClientHello like Chrome 133

The rustls patch adds `ClientConfig::chrome_hello` (`ChromeHello`) and raw
extensions in `ClientExtensions` (shuffled with the others).
`fingerprint::apply_chrome_extensions` configures `renegotiation_info`
instead of SCSV; Chrome's eight `signature_algorithms` (the REALITY server's
Ed25519 signature is accepted by the verifier, as in utls); SCT; brotli
`compress_certificate` with real decompression (`brotli-decompressor`; the
rustls `brotli` feature added a compressor and 1.3 MiB, while a custom
decompressor added 0.4 MiB); ECH GREASE; and, for REALITY, `session_ticket`,
TLS 1.2 in `supported_versions`, six legacy suites, and ALPS.

Result (`core/tests/fingerprint_chrome_full.rs`): REALITY JA4 is
`t13d1516h2_8daaf6152771_d8a2da3f94cd`, as in Chrome 131+; ordinary TLS is
`t13d0915h2_…`. Two ordinary-TLS differences were intentionally retained:
legacy suites (per the user's decision) and ALPS. If a BoringSSL server/CDN
negotiates ALPS, the client must send its settings in encrypted extensions,
which rustls cannot do. This is not expected in REALITY: the Go server does
not negotiate ALPS and the decoy site does not complete its handshake with
the client. `scripts/check_chrome_fingerprint.sh` now also compares the
extension set and `signature_algorithms` against utls.

### ML-DSA-65, UDP, SOCKS5

- `pqv=`: ML-DSA-65 signature over HMAC-SHA512(AuthKey; certificate key ||
  ClientHello || ServerHello), as in `reality.go`. Verification uses aws-lc
  already in the project; no new crypto library. The rustls patch exposes
  raw ServerHello to the hook. Checked against Xray with `mldsa65Seed`,
  including rejection of a wrong key.
- UDP: SOCKS5 UDP ASSOCIATE (`socks5/udp.rs`) → VLESS UDP command, one stream
  per destination, packets with a 2-byte length; closes after 120 s idle;
  datagrams are accepted only from the association owner's IP.
- SOCKS5 username/password (RFC 1929, constant-time comparison without early
  exit). Without `--auth`, the client refuses to listen off loopback.
- `--ca` for self-signed servers, and `alpn=`/`host=` from the link.

### Memory check

No new `unsafe` code. Valgrind/memcheck (as in Stage 2) ran 59 unit tests and
all 11 Xray-core interop tests (Vision direct forwarding, UDP, gRPC, ML-DSA)
with **zero invalid memory accesses**.

### Items open after part one (closed in part two below)

- ~~Mux/XUDP, `xhttp`/`httpupgrade`/`kcp`/`quic` transports.~~ XUDP,
  HTTPUpgrade, and XHTTP were implemented; TCP Mux and KCP were not (see why
  below).
- ~~Windows build~~ — it builds and is checked under Wine.
- Human crypto review (Stage 5).

## Improvements, part 2 (2026-09-26): transports, XUDP, Windows

Request: “keep working” and close the remaining items above.

### HTTPUpgrade

`core/src/transport/httpupgrade.rs` sends an Xray-like Upgrade request
(Go-compatible header order, `Connection: Upgrade`, `Upgrade: websocket`),
strictly checks status 101, then treats remaining bytes as raw data. Shared
`browser_headers.rs` ports Xray `common/utils/browser.go`: Chrome headers
(date-derived User-Agent version, Sec-CH-UA, Sec-Fetch-*) are now also used
for WS. The `?ed=2048` early-data Xray path is discarded.
`VlessConfig::validate()` rejects REALITY with WS/HTTPUpgrade because Xray
does not accept it (“REALITY only supports RAW, XHTTP and gRPC”).

### XHTTP (SplitHTTP)

`core/src/transport/xhttp.rs`, based on
`transport/internet/splithttp` sources:

- Modes: `packet-up` (GET down + POSTs with `seq`), `stream-up` (GET down +
  streaming POST), and `stream-one` (one POST in both directions). `auto`
  follows Xray: REALITY → stream-one, otherwise packet-up.
- HTTP version follows Xray: REALITY → h2, no TLS → HTTP/1.1, TLS → h2, and
  `alpn=http/1.1` → HTTP/1.1 (packet-up only; custom chunked parser,
  consecutive POSTs over keep-alive without waiting for responses, separate
  response-check task, and reconnect if server closes the connection).
- Camouflage uses `Referer` with `x_padding` (server checks its length),
  Chrome “fetch” headers, and `Content-Type: application/grpc` on streaming
  POSTs.
- In `extra=` (JSON), supported keys are parsed; keys that change request
  format fail clearly at startup (`validate()`); server-side and harmless
  keys are ignored.
- Server errors (404 for path/host, 400 for padding/mode) reach the app as
  text instead of just “connection closed.”
- h2 uses Chrome SETTINGS/window values (6 MiB stream, 15 MiB connection),
  also avoiding the 64 KiB default bottleneck.

Interop against Xray-core: HTTP/1.1 without TLS (1 MiB, small POSTs with
`scMaxEachPostBytes`, 6 s pause mid-session), h2 over TLS in all three modes,
HTTP/1.1 over TLS, and every mode over REALITY; 404s (path, host) and 400s
(padding outside range, also proving the server checks our `Referer`). The
first run exposed a race in the test itself (the rejection could arrive in
`dial`); after fixing it, 15 consecutive runs passed.

Not completed: `xmux` (connection reuse between sessions), HTTP/3,
`downloadSettings`, `xPaddingObfsMode`, and placing session/seq/data outside
the path/body.

As of 2026-11-03: `downloadSettings` is implemented in a documented subset
(see the [feature matrix](docs/FEATURES.en.md) and [link format](docs/LINK.en.md));
supported modes and HTTP/1.1, h2, h3 were checked against Xray-core in CI
for PR #47.

### XUDP

`core/src/vless/xudp.rs` + `socks5::udp::serve_associate_xudp`. Source review
showed that Xray clients always send UDP through XUDP (`Mux` command,
`v1.mux.cool:666`, Mux.Cool frames for one session with an address in each
packet) when Vision is enabled, and do so by default otherwise. An Xray server
rejects the UDP command with Vision flow; the client previously worked around
this by sending UDP without flow. UDP now uses XUDP by default, including
with Vision, as in Xray: one connection per SOCKS5 association instead of
one per destination and Full Cone NAT. The interop test checks that two
different destinations see the same server port. `--no-xudp` retains the old
method.

TCP Mux.Cool was deliberately not implemented: an Xray Vision account resets
Mux connections carrying TCP, and Xray offers XHTTP as its replacement for
multiplexing.

### Transports that are not available

Xray-core itself removed `quic` and `h2`/`http`; links using them now fail
with a suggestion to use XHTTP. KCP (mKCP), a custom reliable protocol over
UDP with its own congestion control (about 2,500 lines in Xray), was not
implemented: it is a rare, conspicuous transport and the work is
disproportionate to its benefit.

### Windows

`scripts/cross_windows.sh` uses `x86_64-pc-windows-gnu` through mingw-w64.
The Rust standard library for the Windows target could not be downloaded from
`static.rust-lang.org` in that environment, so it was built from source
(`-Zbuild-std`; matching `library/` sources came from GitHub). Under Wine 9,
all 92 workspace tests and smoke against Xray-core with the same `.exe`
(REALITY + Vision direct forwarding, XUDP) passed. The `.exe` depends only
on system DLLs. This step was added to `scripts/ci.sh`. It had not yet run on
real Windows at the time of this entry.

## Security audit (2026-09-26)

Request: “review everything, say what the key weaknesses and risks are, then
fix them.” The review was manual and included three independent passes:
REALITY/TLS and the rustls patch against rustls 0.23.45 and Xray sources,
the SOCKS5/UDP local attack surface, and parsing server input.

No critical issue was found in that review: the UUID is never sent on a
connection that has not passed REALITY verification (VLESS data is written
only after the full handshake); there is no WebPKI fallback; site DNS names
are not resolved locally; TLS 1.2 is impossible in REALITY mode.

Found and fixed:

| Severity | Finding | Fix |
|---|---|---|
| High | gRPC server `u32` message length was unbounded; buffer could grow to 4 GiB and crash the process | 4 MiB limit (like grpc-go), with test |
| High | SOCKS5 had no greeting timeout or connection limit; silent clients could exhaust file descriptors before authentication | 10 s greeting timeout, `--max-conns` (512), greeting failures at debug; smoke check |
| Medium | Relay idle timeout was absent; silent server or dropped network could hold a connection forever | 300 s idle, 30 s after half-close (modeled on Xray policy), virtual-time tests |
| Medium | REALITY could be identified: when a server was replaced by a real site, handshake stopped immediately after the certificate | As in Xray, verify the site's X.509 certificate, finish handshake, issue a browser-like GET for `/`, and return an error to caller. Hook has a `verified` flag and the only REALITY connection creation point checks it; strict public `reality_client_config` does not use fallback. Test confirms site receives Chrome-header GET and no UUID |
| Medium | UDP ASSOCIATE checked only IP; another local process could send through tunnel and intercept replies (including DNS) | Check requested port when supplied; pin first sender by IP+port; test |
| Medium | UUID and password visible in process list | `--server-file`, `--auth-file`, `REALITY_SERVER`, `REALITY_SOCKS_AUTH` (values hidden from `--help`); smoke launches client this way |
| Medium | Every site's address was logged at default level | Moved to debug |
| Medium | gRPC tasks did not stop when stream closed | `GrpcStream` cancellation on drop; 30 s response timeout |
| Medium | `--no-xudp` UDP queues were nearly unbounded (up to ~1 GiB per association) | Shared 4 MiB budget per association |
| Low | Degenerate `pbk=` (small-order point) made AuthKey computable by anyone | Rejected while parsing link and in hook; hybrid-share contribution checked |
| Low | TLS session resumption was not disabled for REALITY | `Resumption::disabled()` (does not affect ClientHello) |
| Low | REALITY certificate key checked only by length | Ed25519 OID check |
| Low | WebSocket message limit was 64 MiB | Reduced to 1 MiB |
| Low | XHTTP background tasks survived an aborted setup | Cancellation guard |
| Low | One UDP datagram error (WSAECONNRESET on Windows) ended the whole association | Ignore that datagram error |
| Low | No delay after wrong password; lengths compared through `as u8`; empty/non-UTF-8 domain got no reply | 0.5 s delay; compare as `usize`; reply “address type not supported”; tests |

Deliberately not done: TCP keepalive (idle timeout already closes connections),
DNS cache for server names, and per-IP connection limits.

## Threat model: attacker on the same Wi-Fi (2026-09-26)

Request: “put yourself in the place of an attacker on my Wi-Fi: what could
they get, and how can it be fixed?” The review followed code without a
separate attack toolkit; tests checked protections.

Cannot do (tested):

- intercept or replace a connection to a server using `reality`/`tls`: a
  wrong certificate aborts the handshake before UUID is sent
  (`reality_browser_fallback.rs`: REALITY with an untrusted certificate,
  REALITY against a real website — browser-like visit without UUID, TLS with
  an untrusted certificate); TLS 1.2 and session resumption are excluded for
  REALITY;
- connect to the proxy by default (loopback `127.0.0.1` only; UDP association
  socket binds to the same address).

Could do; fixed:

- `security=none`: UUID and traffic are plaintext, and DNS/ARP spoofing allows
  interception → client refuses the link without `--allow-insecure` (smoke
  checked).
- Attack a network-exposed proxy by guessing passwords (previously up to 512
  concurrent attempts with a 0.5 s delay) → block address after five failures
  for 60 s, doubling up to an hour; memory capped at 4096 addresses; minimum
  password length 12; `--allow-ip` for addresses/subnets; startup warning
  (`bin/client/src/access.rs`, unit tests; block tested in smoke).
- Secret file readable by other Unix users → warning.

Cannot be fixed by the client (documented in README): SOCKS5 itself does not
encrypt the password, addresses, or data between device and computer; an
observer sees the server IP, traffic volume, and timing; applications without
a configured proxy and browser DNS without “DNS through SOCKS” bypass the
tunnel.

### Remeasured comparison with Xray-core

Xray-core 26.9.9, three runs, 8 × 16 MiB: idle memory 6.3 MiB vs 30.4 MiB,
peak 8.9 vs 35.3 MiB; throughput 625 vs 572 MiB/s and time to first byte
25.4 vs 35.8 ms. Both performance results were within run-to-run variation,
so considered a tie. Absolute throughput was below the prior measurement for
both clients because the sandbox ran on a different machine.

## Result (2026-09-23): a complete working version

In response to “make at least a rough but complete project,” the project was
brought to a state that could be built, run, and checked with one command,
with limitations described honestly (see `README.md`).

**What worked and how it was verified:**

- `reality-client`: `vless://` link → local SOCKS5; `security=none/tls/reality`,
  `type=tcp/ws/grpc`.
- REALITY over TCP was checked against an **independent** server implementation,
  Go library `XTLS/REALITY` (`scripts/interop_go_reality.sh`, four tests).
- **End-to-end smoke test of the built binary** (`scripts/smoke_e2e.sh`):
  client starts as a user would run it, Python “app” uses SOCKS5 → REALITY →
  VLESS to a Go server and back, and 64 KiB random data returns unchanged.
  A link with `flow=xtls-rprx-vision` is rejected at startup with a clear error.
- `scripts/ci.sh` runs everything in one command: fmt, clippy with
  `-D warnings`, 58 tests, release build, interop, smoke, fingerprint reference
  check (optional steps honestly report SKIP without Go ≥ 1.27 or network).
  All seven steps passed.
- Windows code is portable (no `std::os::unix`/`libc`/`/proc` outside
  `bench/memwatch`); `docs/WINDOWS.md` and `scripts/build_windows.ps1` exist.
  The script uses UTF-8 with BOM and CRLF because Windows PowerShell 5.1
  otherwise reads it as cp1251 and turns `—` into `вЂ”`, where `”` is parsed
  as a quote. It had **not been built on Windows** because the target std
  could not be downloaded from the sandbox.

**Found and fixed while finishing:** if `RUST_LOG` was unset, the client
printed nothing — on Windows it looked like a blank console. Default level
is now `info`, logs go to stderr, colors are used only in a real terminal and
not on Windows, and the log reports the actual port (with `--listen ...:0`
it previously printed `:0`).

**Not implemented at that time** (listed in README under “What's still open”):
XTLS Vision, ML-DSA-65 (`pqv=`), Chrome-like ClientHello extension set, WS/gRPC
interop against real Xray-core, UDP; Stages 2 (miri), 5 (human review), and 8
(publication) required instructions outside the development environment.

## Connection-establishment robustness (2026-09-25)

A code audit for missing client behavior found and fixed four ordinary network
reliability gaps:

1. **There were no timeouts.** A server that accepted TCP and stayed silent
   (typical of a blocked or hung node) could hold the connection, task, and
   buffers forever. Added 5 s for name resolution, 10 s for TCP connect,
   15 s for TLS/REALITY handshake, and a 30 s total connection-open limit.
   A separate handshake timeout is needed because TCP is already established
   and its timeout no longer applies — a test caught the first fix still
   hanging without it.
2. **Only the first resolved address was used.** A domain often returns both
   IPv6 and IPv4; if IPv6 is unavailable (common), the client failed despite
   a usable IPv4 address in the same answer. It now tries every address in
   turn.
3. **Name resolution blocked** (`to_socket_addrs`) inside async code. Tokio
   has as many worker threads as CPU cores (two on a small machine), so one
   slow DNS response could stop all connections. Replaced with async
   `tokio::net::lookup_host`.
4. The local socket to the app lacked `TCP_NODELAY` (the outbound socket
   already had it).

Errors are now clearer: an unresolvable name reports “could not resolve
<name>: …” instead of an English system message. New
`core/tests/connect_robustness.rs` (three tests) checks that a silent server
is cut off in 15 s instead of waiting forever, a dead port returns an error,
and an unresolvable name appears in a helpful error. Total tests: 61.

## Stages 2 and 8 closed (2026-09-25)

### Stage 2 — memory safety check (Valgrind instead of Miri)

`cargo miri` requires nightly Rust, unavailable in that environment.
Valgrind/memcheck on stable was used instead. It cannot detect Rust rule
violations (aliasing, UB without an actual invalid access) that Miri catches,
but it can catch real invalid accesses across the whole process, including
the TLS crypto C code in `aws-lc`, which Miri cannot inspect.

Memcheck results: 44 unit tests — **0 invalid accesses**; 14 integration
tests (real TLS/REALITY/WS/gRPC on loopback) — **0**; four Go REALITY-server
interop tests — **0**; release binary on live traffic, 20 consecutive
SOCKS5 → REALITY → VLESS connections and 1.25 MiB — **0 invalid accesses,
0 “definitely lost.”**

There was no per-connection leak: “possibly lost” was the same for one and
20 connections (1,279 bytes in 18 blocks), one-time allocations at startup
(Tokio pools, aws-lc initialization), not growth per connection.
`scripts/smoke_e2e.sh` gained a wrapper:
`CLIENT_WRAPPER="valgrind ..." SMOKE_CONNECTIONS=20 scripts/smoke_e2e.sh`.

### Stage 8 — comparison against real Xray-core

Previously considered impossible because Xray could not be installed from
that environment. The official GitHub release binary was downloadable
(`scripts/fetch_xray.sh`), and the Stage 5 REALITY test server already existed.
As an extra check, a real Xray client successfully connected through the Go
test server, confirming it behaved as a real server too.

`scripts/stage8_compare_with_xray.sh` automates a fair comparison: both
clients connect to the same server with the same link; the same
`scripts/stage8_loadgen.py` generates load.

Initial result (8 connections × 16 MiB, loopback, two cores, Xray-core
26.3.27; values below were **before** the fix discussed below):

| Metric | reality-core | Xray-core | Result |
|---|---:|---:|---|
| Idle RSS | **5.5 MiB** | 29.2 MiB | 5.3× lower |
| Peak RSS under load | **8.6 MiB** | 33.7 MiB | 3.9× lower |
| Throughput | 801 MiB/s | **995 MiB/s** | 19% slower |
| Handshake median | 34–70 ms | **1.6–7 ms** | **6–21× slower** |

Honest caveat: Xray-core is a general platform with dozens of protocols,
while this client did one job; this asks “how much process memory for the
same work,” not “whose code is better.” Loopback on one machine does not
reproduce real network latency or loss (see Stage 0 warning).

### Slow handshake: cause found and fixed

The first measurement showed a 6–21× connection-time gap. Analysis showed:

1. **It was not the cost of every connection.** Fifty consecutive connects
   took 88 ms (1.8 ms each); the first alone took 36 ms and later ones
   1.6–3 ms. The cost was one-time initialization.
2. **It was not our code.** Client CPU time for connects after the first was
   below measurement threshold (0 ms across 50 connections).
3. **The cause was aws-lc random-number-generator seeding.**
   `bench/src/bin/warmup_probe.rs` (run in separate processes because the
   cost is one-time) measured:

   | Operation | Time |
   |---|---:|
   | Install rustls crypto provider | 0.00 ms |
   | **First key-exchange key generation** | **26–32 ms** |
   | Later generations (mean of 20) | 0.02 ms |

   X25519, secp256r1, and X25519MLKEM768 all had the same cost, so it was not
   the post-quantum group. In a decisive test, requesting random bytes first
   moved the cost there: **random bytes 28.08 ms, key generation 0.08 ms.**
   aws-lc lazily seeds its RNG on first random-byte request (collecting
   entropy from CPU timing jitter), costing ~28 ms once per process.

**Fix** (`transport::tcp_tls::ensure_crypto_provider` plus a call on startup
in `bin/client/src/main.rs`): request random bytes once during initialization,
before accepting connections. The bytes are discarded; only the seeding side
effect matters. The one-time delay moved from the user's first connection to
process startup.

Before/after (8 connections × 16 MiB, same setup):

| Metric | Before | After | Xray-core |
|---|---:|---:|---:|
| Median handshake | 70 ms | **15.8 ms** | 5.3 ms |
| First connection | 36 ms | **5.7–8.7 ms** | — |
| Throughput | 801 MiB/s | **965 MiB/s** | 1020 MiB/s |

### ⚠️→✅ Correction: the “handshake gap” was a measurement error

The effort to “catch Xray's connection time” revealed that the measurements
compared **different things**. It measured time to a SOCKS5 CONNECT response.
Xray-core replies to CONNECT optimistically before its server connection is
established. Directly verified by pointing Xray at a port with no server: it
still returned “success” in 2.8 ms. This client responds only after a real
TCP + TLS + REALITY + VLESS handshake, and therefore reports an unavailable
server as a failure.

The fair metric is **time to the first byte of data through the tunnel**,
which includes the complete path for both. Across 30 sequential connections:

| Client | Time to SOCKS5 reply | Time to first data byte |
|---|---:|---:|
| reality-core | 1.74 ms | **1.93 ms** |
| Xray-core | 0.17 ms | 2.56 ms |

There was no “3× slower” result; with the same metric this client was
slightly faster. `scripts/stage8_loadgen.py` was corrected to measure time to
first byte, and labels CONNECT response time as not comparable between
clients. The behavior difference is real and deliberate: an optimistic reply
looks faster but makes the app believe a connection exists when the server
is unreachable; this client reports the error immediately.

### Final comparison over three runs (fair metric)

One run was misleading: run-to-run variation was comparable to the difference
between clients. Three runs, 8 connections × 16 MiB:

| Metric | reality-core | Xray-core | Conclusion |
|---|---:|---:|---|
| Idle memory, MiB | **5.9** | 29.5 | 5.0× lower; real difference |
| Peak memory, MiB | **8.7** | 34.3 | 3.9× lower; real difference |
| Time to first data byte, ms | 17.1 | 22.6 | Tie (difference within variation) |
| Throughput, MiB/s | 985 | 966 | Tie (difference within variation) |

**Conclusion at that time: the client did not trail Xray-core on any
measured metric** — two memory wins and two ties. Both earlier claims (“19%
slower” and “3× slower to connect”) were measurement artifacts: one-run
noise and comparing unlike metrics.

Remaining real difference: the first connection after startup took ~6 ms
versus ~2 ms for later ones, from warming handshake code. This was small
compared with the earlier 36 ms and barely noticeable on a real network,
where round-trip time to the server is usually tens of milliseconds.

An incidental finding: this client used **less** CPU time for handshakes than
Xray (0.70 ms vs 0.95 ms), measured from `/proc/<pid>/stat` across 200
sequential connections.

## Follow-up plan (written 2026-09-23)

Prepared after GREASE was completed, in response to “make a plan for what to
do next.” Before writing it, the current client ClientHello was captured on
loopback and compared with utls `HelloChrome_133`; Xray source
(`proxy/vless/inbound/inbound.go`, `transport/internet/reality/reality.go`)
and `XTLS/REALITY` source (`tls.go`, `handshake_server_tls13.go`) were reread
from `raw.githubusercontent.com`, and network access from the environment
was checked. Two findings changed priorities and were put first.

### Finding 1 (critical): `flow=xtls-rprx-vision` was unsupported and silently ignored

`vless/uri.rs` read `flow=` but nothing used it: VLESS requests always sent
empty addons. Xray source (`inbound.go`, around line 593) showed that an
account with `flow = xtls-rprx-vision` rejects TCP with empty flow:
“rejected since the client flow is empty.” VLESS + Vision + REALITY over TCP
is the configuration recommended in Xray docs and common in real links. The
client therefore would not connect to a typical server, without a helpful
reason in its log. This was a missing implementation item, not a deliberate
decision.

### Finding 2 (promising): interop with a real server might be possible here

`proxy.golang.org` and `static.rust-lang.org` returned 403, but GitHub Git
worked and the environment had Go 1.24.7. `XTLS/REALITY` is a Go library,
not only part of Xray-core, and nearly all its dependencies are on GitHub.
`golang.org/x/*` could be sourced from `github.com/golang/{crypto,sys,...}`
using local `replace` directives. REALITY's `go.mod` required Go 1.27, so it
was necessary to test lowering the directive or building Go 1.27 from
`github.com/golang/go` with 1.24 as bootstrap. If that worked, Stage 5 would
no longer be fully blocked: a small `reality.Server` with an echo after
handshake could provide an independent REALITY server for AuthKey/SessionId,
X25519MLKEM768, HMAC certificate, and GREASE. It would not replace human
review, but would replace checking the client only against its own server
implementation.

### Execution log

- ✅ **Step 1** — `flow=` is parsed into `vless::Flow`. Unknown values fail
  parsing; `xtls-rprx-vision` gets an explicit “not supported” error at
  client startup and before each connection
  (`VlessConfig::ensure_flow_supported`). No more silently empty flow.
- ✅ **Step 1b (found during work; critical)** — deadlock with current Xray.
  The server (`inbound.go`: `EncodeResponseHeader` + `SetFlushNext`) sends a
  VLESS response header only together with the target's first data, while the
  client waited for that header before sending anything. HTTPS/HTTP, where
  the client speaks first, deadlocked every connection. Test servers had
  replied with the header immediately and missed it. Replaced
  `vless_handshake` with `vless_connect`: send request immediately and read
  response header lazily on first `VlessStream` read. Regression test mimics
  `SetFlushNext`. 58 tests; clippy clean.
- ✅ **Step 2 — interop test setup works.** Go 1.27.1 was built from source
  (`github.com/golang/go`, bootstrapped from installed 1.24.7);
  `github.com/xtls/reality` was cloned via Git and `golang.org/x/*` came from
  `github.com/golang/*` mirrors. Server: `interop/go-reality-server/main.go`,
  using real REALITY, Go `crypto/tls` as a decoy site, and “VLESS-lite” (parse
  request and echo; response only with data, like Xray `SetFlushNext`).
  `core/tests/interop_go_reality.rs` has four ignored tests; run with
  `scripts/interop_go_reality.sh`, bootstrap in the sandbox with
  `scripts/interop_sandbox_bootstrap.sh`:
  - full REALITY handshake + VLESS echo **passed against an independently
    written server on the first run**. Server logs (`-show`) decrypted exactly
    what the client sealed: version 26.9.9, current time, ShortId;
  - wrong ShortId and wrong `pbk`: server falls back to the decoy; client
    rejects its certificate (P-256 rather than REALITY Ed25519);
  - `minClientVer`/`maxClientVer`: four ranges, accepted/rejected at the
    expected boundaries.

  This is not a human review or full Xray-core (TCP only; gRPC/WS and Vision
  were not covered by this harness at that time), but it was the first
  server-side check against an implementation not written by us.
- ✅ **Step 9 — automatic Chrome fingerprint reference check.**
  `scripts/check_chrome_fingerprint.sh` downloads utls `u_common.go`/
  `u_parrots.go`, finds the profile selected by `HelloChrome_Auto`, extracts
  its cipher suites, and compares them with the reference in the script (also
  used by `chrome_profile.rs`). Any mismatch returns nonzero. Both paths were
  tested: pointing `HelloChrome_Auto` to another version and changing one
  suite each returned `exit 1`. Suitable for manual or scheduled runs. At
  that date there was no mismatch (`HelloChrome_Auto` = `HelloChrome_133`).
- ✅ **Steps 3–8 completed on 2026-09-26** — see “Improvements
  (2026-09-26)” above. The following is a historical note on why they were
  not done in the earlier session.
- ⛔ **Steps 3, 4, 5, 6, 7 were not done in that session.** Work on XTLS
  Vision, ML-DSA-65, and Chrome ClientHello/extensions had been stopped by an
  environment security review while inspecting Xray/REALITY protocol
  internals. This was an external mechanism, not a code-correctness finding;
  the review was not bypassed by searching for supposedly “safe” fragments.
  Links with `flow=xtls-rprx-vision` still produced an explicit unsupported
  mode error (Step 1) rather than failing silently.

### Original ordered work items

| # | Work | Reason | Verification | Size | User decision? |
|---|---|---|---|---|---|
| 1 | Explicit error for non-empty `flow=` instead of ignoring it | Until Vision exists, users should see why connection fails, not just “connection closed” | Link parser unit test + CLI test | Small | No |
| 2 | Interop harness: minimal Go server using `XTLS/REALITY` (Finding 2) | First check against another server implementation; Stage 5 and GREASE had only been tested against our test server | Existing `reality_full_stack.rs` scenarios against Go server | Medium, may not build | No; if build fails, record cause and return to runbook |
| 3 | Client-side XTLS Vision (`flow=xtls-rprx-vision`) | Without it, client is incompatible with typical servers (Finding 1) | VLESS protobuf addons with flow; first-packet padding; detect inner TLS and switch to direct; compare with Xray `proxy/proxy.go`; main check against Xray server from Step 2 (requires VLESS inbound, not only REALITY) | Large, comparable to REALITY | No; largest plan item |
| 4 | REALITY ML-DSA-65 (`pqv=`, `mldsa65Verify`) | With `Mldsa65Key`, server sends a different `signedCertMldsa65` template with ML-DSA-65 signature. Verify HMAC accepts it and verify signature when `pqv` is set | Step 2 harness with ML-DSA; RustCrypto `ml-dsa` crate, same family as `ml-kem` | Medium | No |
| 5 | Cheap ClientHello fixes: Chrome's `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (0x00ff) → `renegotiation_info` extension (0xff01); default TCP ALPN `h2,http/1.1` (currently absent, anomalous for Chrome-like hello); read `alpn=` from link; accept `fp=chrome`, warn for others | Captured ClientHello: 11 extensions vs Chrome's 16, 00ff instead of ff01, no ALPN on TCP | On-wire tests like GREASE | Small–medium | No |
| 6 | Set `signature_algorithms` to Chrome's eight schemes in order (currently 13, including Ed25519 and ML-DSA) | Difference appears in JA4_c | **Source-based risk:** after authentication the REALITY server always signs CertificateVerify with Ed25519 (`hs.sigAlg = Ed25519`), but rustls rejects a signature using an undeclared scheme. For REALITY, separate what is advertised (Chrome-like) from what is accepted (+Ed25519) in the patch, not config. Real utls Chrome (Xray default client) omits Ed25519 and works in production, so this is compatible; verify with Step 2 harness | Medium | No |
| 7 | Missing extensions: `compress_certificate` (brotli), SCT (0x0012), ALPS (0x44cd), ECH-GREASE (0xfe0d) | Remaining extension-set difference from Chrome | ECH-GREASE via rustls `EchMode::Grease`; empty SCT as with GREASE extensions; ALPS requires patch so negotiated server ALPS is not treated as unsolicited (otherwise rustls aborts); brotli adds dependency, so first measure binary size and RSS | Medium | **Yes for brotli:** add dependency for fingerprint or preserve resource-saving principle? |
| 8 | Strategic choice: advertise Chrome's six legacy RSA/CBC suites and TLS 1.2 in REALITY without implementing them | After Steps 5–7, our JA4 remains `t13d09…`, Chrome's is `t13d1516…`, due to six intentionally omitted unsafe suites. They could be advertised as “unknown code points,” like GREASE; unsafe crypto would not enter the client, and a server selecting one would fail clearly. REALITY is TLS 1.3 only, so cannot select them; ordinary TLS fallback to 1.2 makes selection unlikely but possible | Compare JA4 before/after | Small | **Yes:** “advertise what you cannot do.” Technically safe, but changes principle recorded in `chrome_profile.rs` |
| 9 | Automatically compare fingerprint with reference | Chrome changes fingerprint several times a year (Stage 3 warning) | Download `u_parrots.go`, find `HelloChrome_Auto` profile, compare; signal on mismatch; can schedule | Small | No |
| 10 | Stage 2 (Miri/ASan), human crypto review (Stage 5), Stage 8 | No change: nightly unavailable, no reviewer or publication decision | Existing runbooks: `scripts/stage2_miri_asan.sh`, `docs/stage5-crypto-review-and-interop.md`, `scripts/stage8_compare_with_xray.sh`. If Step 2 works, also try Stage 8 memory comparison against Xray | — | User |

Chosen order: Step 1 cheaply closes a silent failure; Step 2 precedes Vision
because otherwise Vision would be tested against our own server implementation,
which is a self-confirming test this project had already avoided several
times. ClientHello changes (5–8) also benefit from the external harness, so
come afterward. User decisions for Steps 7 (brotli) and 8 (legacy suites)
are needed before reaching them. Everything else can proceed without user
input.

## Earlier roadmap to completion (version preceding the plan above)

Written at the user's request to “make a plan to close all these items and
act on it,” after choosing a summary of open items. This was more than a list:
it separated work possible in the sandbox (done in that session) from work
requiring network access, hardware, or people outside it, for which a
copyable runbook was supplied.

### Completed in that session

- **Stage 3, partly, over three consecutive sessions:**
  `core/src/fingerprint/chrome_profile.rs` orders cipher suites like Chrome
  133 using `refraction-networking/utls` `HelloChrome_133` as reference;
  GREASE cipher suite comes first (narrow patch in
  `vendor/rustls-reality-patch/src/client/hs.rs`, not affecting REALITY
  key_share/named_groups/HRR). Wired into all TCP transports through
  `transport::tcp_tls`. Experiments established that rustls already
  randomizes TLS extension order, so the earlier claim “stable, but not
  browser-like” was corrected; no patch was needed for that behavior.
  GREASE (RFC 8701) was then completed across cipher suite, supported_groups,
  key_share, supported_versions, and two GREASE extensions, on all paths
  including REALITY. An earlier bug that sent two key_share entries after
  HelloRetryRequest was found and fixed. Workspace tests grew from 48 to 54;
  clippy passed.
- **Stale documentation was corrected:** the status table at the top of
  this file (Stages 3/5/6/7 had been outdated) and `README.md`, including
  test count.

### Work then requiring action outside the sandbox

| Stage | Needed work | Runbook/reference |
|---|---|---|
| 2 | `cargo miri`/ASan; nightly could not be installed because crates.io network was restricted | `scripts/stage2_miri_asan.sh` |
| 3, remaining | Line-by-line comparison of ClientHello extensions/values (signature_algorithms, ALPN, certificate compression, ALPS, SCT, ECH-GREASE, etc.) against Chrome 133 | Separate session; reference `u_parrots.go` (`HelloChrome_133`), tools `fpcheck` and `core/src/fingerprint/client_hello.rs` |
| 5 | Third-party crypto review and interop against a live Xray-core server | `docs/stage5-crypto-review-and-interop.md` checklist and steps |
| 8 | Compare against installed Xray-core under the same load and decide about publication | `scripts/stage8_compare_with_xray.sh` |

These four items could not then be closed from the environment because of
structural constraints, not lack of effort: unavailable nightly/Xray network,
no external reviewer, and no live REALITY server. Results from those runbooks
(especially reviewer findings and interop issues) were explicitly identified
as reasons to revisit this plan rather than silently treating it as complete.

### Stage 0 — measurement infrastructure

Set up benchmark harness and RSS/PSS, throughput, latency, and allocation
metrics. **Harness limitation:** local benchmarks do not reproduce real DPI
conditions; good local results do not guarantee operation against a live
provider block. This caveat applies to all later measurements.
Implemented `bench/benches/throughput.rs` (Criterion for VLESS header
encoding and relay on in-memory duplex streams) and
`bench/src/bin/memwatch.rs` (external RSS/PSS sampler by PID from `/proc`).

### Stage 1 — minimal VLESS client

Link parser, TCP+TLS, SOCKS5 proxy; test with ten concurrent connections was
deferred to Stage 2. Implemented in `core/src/vless/uri.rs` (`vless://`),
`protocol.rs` (request encoding/response parsing), `transport/tcp_tls.rs`
(rustls TCP+TLS, without ClientHello camouflage at that time),
`socks5/mod.rs` (local SOCKS5 CONNECT), `relay.rs` (bidirectional relay),
and `bin/client/` (CLI composition).

### Stage 2 — memory use under concurrency

Each connection owns its buffer rather than a packet buffer or global shared
pool. Risk note: if buffer code touches decrypted traffic (Stage 5+), a
use-after-free or reuse with another session's data could leak data, not just
crash; Miri/sanitizers should be part of this stage's tests rather than
deferred to the end. Implemented in `core/src/relay.rs`: each copy direction
gets one `Vec<u8>` for the connection lifetime via
`copy_bidirectional_with_buffer_size`, with no global pool or per-packet
allocation; split via Tokio's `tokio::io::split`, not a custom poll state
machine.

Miri was not available in the sandbox because nightly downloads from
`static.rust-lang.org` were blocked. The proposed local commands were
`rustup toolchain install nightly --component miri` then
`cargo +nightly miri test -p reality-core --lib` (covering in-memory
`relay::tests`, `socks5::tests`, `vless::protocol::tests`). Real TCP/TLS test
`core/tests/tls_loopback.rs` cannot run under Miri; it should instead use
nightly ASan/TSan, e.g.
`RUSTFLAGS="-Z sanitizer=address" cargo +nightly test -p reality-core --test tls_loopback`.
Neither was run on the user's behalf in that earlier entry. A later entry in
this plan records the Valgrind alternative and its limits.

### Stage 3 — TLS fingerprinting (uTLS equivalent)

Goal: emulate browser ClientHello and compare JA3/JA4. This is ongoing, not a
one-time task: browsers change fingerprints several times a year, and DPI can
learn to distinguish a fingerprint by timing/TCP behavior later. Revisit and
refresh captures regularly.

Implemented `core/src/fingerprint/`: raw ClientHello parser, JA3, JA4, and
capture of raw ClientHello bytes from the socket because rustls does not
expose them. Formulas were checked against published examples and an
independent Python calculation. `cargo run -p fpcheck -- --server
'<vless-link>'` prints JA3/JA4 and fields for a real connection.

The prior claim that rustls cannot control cipher-suite/extension order was
empirically disproved and explicitly corrected. Cipher suites are a public
ordered `CryptoProvider::cipher_suites` vector. The Chrome 133 reference
contains 16 suites (GREASE, three TLS 1.3, six TLS 1.2 ECDHE, six legacy RSA/
CBC); `aws-lc-rs` implements the first nine. Unsafe CBC/plain-RSA suites were
deliberately not reimplemented just to match a fingerprint. The available
nine now follow Chrome's relative order across TCP, WS, and gRPC in REALITY
and ordinary TLS; wire bytes were checked by tests.

TLS extension order is randomized by rustls on each connection, like modern
Chrome's `ShuffleChromeTLSExtensions`; three loopback handshakes produced
three orders. This is also why JA4 sorts extensions while JA3 is order
sensitive. No rustls patch was needed for extension-order randomization.

GREASE was then extended to every Chrome location and path (including
REALITY): five independent values per connection — first cipher suite;
first supported group and first key_share (body `[0]`); first
supported_version; and two distinct GREASE extensions (first with empty body,
last with `[0]`, before `pre_shared_key`). One set is generated per
ClientHello input so retry after HRR uses the same values. The encoder was
patched directly; no macro or raw-byte ClientHello rewrite was needed.
`collect_used()` does not treat GREASE as a server-answered extension.

An HRR regression was fixed: RFC 8446 requires exactly one key_share entry in
the second ClientHello. The first patch sent `[GREASE, secp256r1]`; rustls's
test server tolerated it, but Go `crypto/tls` (and REALITY) rejects it. A test
forcing HRR on a secp256r1-only server parses both on-wire ClientHellos and
guards the fix. Source review also confirmed REALITY servers ignore unknown
GREASE groups and Xray's own default client sends GREASE in all five places.
The real group remains X25519MLKEM768, so no extra HRR is introduced.

At that point the remaining fingerprint gaps were the exact extension set
and values (signature_algorithms, ALPN, certificate compression, ALPS, SCT,
ECH-GREASE) and a byte-exact Firefox ECH-GREASE length; other remaining
items are recorded in the dated phase notes above. Possible last-resort
alternatives (`craftls` or BoringSSL FFI) were not chosen: maturity and API
risks had not been established, and a small rustls patch remained preferable.

### Stage 4 — transports (WebSocket, gRPC)

Prefer established libraries (`tokio-tungstenite`, `h2`); write custom code
only if profiling proves the overhead matters. Rationale: a self-written
framer bug would have only one developer to find it, unlike Xray's large
deployment base; do not trade memory for risky custom protocol code.

Implemented WS over TLS with `async-tungstenite` + `ws_stream_tungstenite`
(no custom WS framer), checked by TCP+TLS+WS loopback test. gRPC uses a single
bidirectional Xray/V2Ray “gun” stream (no multiplexing) via `h2`; only a thin
protobuf-varint/gRPC frame layer is custom (`/{serviceName}/Tun`, 1-byte
compression flag + 4-byte big-endian length + protobuf `Hunk{bytes data=1}`).
The format was checked against two independent technical sources. A loopback
TCP+TLS(ALPN h2)+HTTP/2 test found and fixed a real deadlock: the test server
was not polling `h2::server::Connection` in the background, so
`RecvStream::data().await` waited forever. CLI selects TCP/WS/gRPC from
link `type=`.

At that point, real Xray/V2Ray server interop was still unverified and was
explicitly required before production use. The early gRPC send flow used
`send_data` without `reserve_capacity`/`poll_capacity`, risking unbounded h2
buffering with a truly slow peer; a later dated entry records that fix and
real Xray interop.

### Stage 5 — REALITY

Planned: X25519, hand-built ClientHello fields, fuzz tests, local debug
server, and compatibility matrix against real Xray-server versions. Risk
warning: crypto bugs can silently weaken privacy instead of simply breaking
functionality. The plan called for a cryptography-experienced external
reviewer. It also called for legal assessment before implementing/publishing
active-probing circumvention. The owner said they had assessed the legal side;
that was their assessment, not independently verified here. **At this point
the plan still said no external crypto review had taken place**; source and
test-vector checks were not a substitute. Later entries document more tests,
but continue to distinguish those from an independent review.

The initial `core/src/reality/` work implemented X25519 ECDH
(`x25519-dalek`), HKDF-SHA256 AuthKey (salt `ClientHello.random[..20]`, info
`REALITY`), AES-256-GCM SessionId sealing (nonce `random[20..32]`, entire
ClientHello as AAD), and HMAC-SHA512 certificate verification
(`verify_ed25519_hmac`). Values were compared byte-for-byte against two
independent sources: Xray's client `Seal` and XTLS/REALITY's server `Open`.
The plaintext before AEAD is 16 bytes — version(3)+reserved(1)+timestamp(4)+
short_id(8) — not 24; the 16-byte GCM tag completes the 32-byte SessionId.
Tests included RFC 7748 §6.1 X25519 vectors independently checked in Python,
seal/open round-trip with independent decryption, AAD-tampering rejection,
and positive/negative HMAC cases.

`verifier.rs` implements rustls `ServerCertVerifier`: REALITY replaces X.509
chain trust with the protocol's HMAC check, as Xray `VerifyPeerCertificate`
does, while TLS 1.3 `Certificate`/`CertificateVerify` signatures are still
verified by `rustls::crypto::verify_tls13_signature`. Only key trust changes;
TLS is not disabled. `rcgen` certificates with a manually replaced signature
tested valid HMAC acceptance and wrong-key/ordinary Ed25519 rejection.
`VlessConfig::reality_params()` parses server `pbk=` and `sid=`.

The plan corrected an earlier mistaken claim that Xray's
`refraction-networking/utls` used BoringSSL FFI: it is a fork of Go's
`crypto/tls` with direct access to ClientHello fields. Three independent Rust
REALITY projects had patched rustls rather than using BoringSSL. BoringSSL is
a production-proven alternative for browser HTTP fingerprinting, but does
not expose arbitrary `legacy_session_id` either; patching C BoringSSL was
more work than a small Rust patch.

An initial spike used public rustls `ClientSessionStore` to inject a desired
TLS 1.2 `SessionId` into ClientHello while limiting supported versions to
TLS 1.3. It proved the ID reached the wire and TLS 1.3 remained negotiated;
it also caught an unwanted `session_ticket` extension when TLS 1.2 was
allowed. But source review showed the store was called before
`ClientHello.random` existed and did not control key_share, so it could not
implement REALITY. The spike remains only as a test; the live mechanism is a
small rustls patch, not a wholesale crypto-backend change.

The live `RealityClientHook` patch adds an optional hook (default `None`, so
normal rustls behavior is unchanged). During ClientHello construction it:

1. substitutes a `RealityKeyExchange` that shares the ephemeral secret with
   REALITY;
2. after serializing ClientHello (including ECH handling), calls
   `seal_session_id(random, aad)` using actual serialized handshake bytes
   with SessionId zeroed at the protocol offset, then installs the sealed
   value in both the outgoing message and retry state;
3. completes ordinary TLS ECDH with the same secret when the server's real
   key_share arrives.

`RealityHook` holds the static ephemeral secret intentionally for both uses
and stores AuthKey in `OnceLock` for the certificate verifier. On the first
loopback handshake, rustls sent an HRR because `named_groups` listed every
provider group but key_share offered only X25519. For REALITY, the first
ClientHello was limited to the offered group. A separate independent AEAD
test initially used more bytes than the actual TLS record in AAD; it was
corrected to use precisely the record length from the header.

`reality_handshake.rs` independently implements HKDF/AES-GCM in the test and
confirmed a full TLS 1.3 handshake and bidirectional application data, opens
the on-wire SessionId using server-derived AuthKey, and recovers the
configured ShortId and fresh timestamp. The transport entry point
`connect_tls_reality_with_alpn` builds the hook/verifier and is used by TCP,
WS, and gRPC. A test proves WS/gRPC reach the REALITY verifier (not ordinary
TLS fallback); a separate full-stack test server computes AuthKey and signs
HMAC certificates, and exercised production TCP/WS/gRPC connection paths
with bidirectional data. That test also exposed and fixed a missing 2-byte
VLESS response header in its own gRPC fixture; before then the full gRPC
handshake path had no runtime coverage.

Memory handling was later strengthened with `zeroize` for ephemeral X25519
and shared ECDH secrets on drop. A fresh comparison against current upstream
REALITY then found that Xray-core 26.9.8+ requires hybrid
`X25519MLKEM768` before optional X25519. The plan records implementation of
ML-KEM-768 using the RustCrypto `ml-kem` crate: client share is 1184-byte
encapsulation key + 32-byte X25519; server share is 1088-byte ciphertext +
32-byte X25519; decapsulation and ECDH secrets are concatenated
`mlkem || ecdh` (64 bytes). Byte layout was independently checked against
Go's `crypto/tls`/`crypto/mlkem` and the project's rustls/aws-lc hybrid
implementation. Rustls's hook and independent ClientHello parser were
updated; tests exercised TCP/WS/gRPC through the real verifier and a separate
AEAD check without changing their validation logic.

REALITY `pqv=` adds ML-DSA-65 signing over HMAC-SHA512(AuthKey; certificate
key || ClientHello || ServerHello), as in `reality.go`; aws-lc was used
without adding a crypto library, and wrong-key behavior was tested against
Xray. The plan also investigated `minClientVer`/`maxClientVer`. An initially
ambiguous 3x-ui issue ([#5922](https://github.com/MHSanaei/3x-ui/issues/5922))
was followed by a line-by-line check of the live `main` branch of
`XTLS/REALITY`, in `tls.go`. At the time of the check, this file matched
[upstream commit `83f6217`](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/tls.go#L272-L277)
(14 October 2026). The relevant upstream condition was:

```go
if (config.MinClientVer == nil || Value(hs.c.ClientVer[:]...) >= Value(config.MinClientVer...)) &&
    (config.MaxClientVer == nil || Value(hs.c.ClientVer[:]...) <= Value(config.MaxClientVer...)) &&
    (config.MaxTimeDiff == 0 || time.Since(hs.c.ClientTime).Abs() <= config.MaxTimeDiff) &&
    (config.ShortIds[hs.c.ClientShortId]) {
    hs.c.conn = conn
}
```

This confirms an active three-byte client-version check alongside ShortId and
time validation. The version bounds are optional: when either configured bound
is nil, that side of the comparison is disabled. On a failed comparison the
server does not send a TLS alert; `hs.c.conn` remains unset and traffic is
silently proxied to the cover site. `Value()` packs the bytes as a big-endian
integer. The project therefore added a fixed `CLIENT_VERSION = [26, 9, 9]` to
REALITY plaintext with a regression test. This value was not auto-synchronized
and could become stale; it was a plausible version rather than `0.0.0`, not a
protocol feature claim.

The plan emphasizes that upstream REALITY and DPI behavior evolve: fingerprints
and client version need periodic verification. It closes with a continuing
warning: expanding the rustls patch and crypto surface increases the value of
independent review. Full-stack tests and two-source checks **do not** replace
an external audit. The later first-release gate decision is documented in
[`docs/stage5-crypto-review-and-interop.en.md`](docs/stage5-crypto-review-and-interop.en.md).

### Stage 6 — zero-copy optimization

`splice` applies on a server side (server ↔ destination), not the client
SOCKS5 scenario. **Status: not applicable to this core, not deferred work —
an architectural fact.** This repository implements only the client
(SOCKS5 → VLESS); it has no server and none is planned. `splice(2)` avoids
copying only when bytes move between file descriptors without userspace, so
at least one relay side must not need in-process encryption/decryption. A
VLESS server can sometimes use it on server ↔ destination for a plaintext
socket. In this client, both relay sides pass through userspace TLS
(`rustls`, without kernel TLS/ktls): one is the app's local SOCKS5 socket,
the other is VLESS over TLS/WS/gRPC. Bytes must enter userspace so rustls can
encrypt/decrypt them; `splice` alone cannot help. Per-connection buffers
from Stage 2 are the relevant copy optimization. Revisit only if this project
adds a server component.

### Stage 7 — profiling

Compare alternative allocators under idle and load, selectable by build
feature. Caveat: profiling on one machine does not represent a real VPS with
another OS/kernel/memory profile; repeat on a typical deployment host.

**Status: complete within the sandbox's limits.** `bin/client` and `bench`
have optional `mimalloc` feature (`mimalloc = "0.1"` and
`#[global_allocator]` behind `#[cfg(feature = "mimalloc")]`); default remains
system allocator (glibc malloc on Linux). In this sandbox, two comparisons:

- **Idle:** `reality-client` had a valid link and listening SOCKS5 but no
  real connections; external RSS/PSS sample ran 5 s. System allocator:
  ~4.5 MB RSS / ~2.9 MB PSS, stable. mimalloc: ~11.2 MB RSS / ~9.5 MB PSS,
  also stable, about 2.5× higher because it reserves larger segments up
  front — a common throughput/fragmentation tradeoff that increases baseline
  footprint for a client that typically waits for network I/O.
- **Load:** `cargo bench -p bench --bench throughput -- --quick` ran twice
  with defaults and `--features mimalloc`. VLESS header encoding (`Vec<u8>`
  per call) showed directional improvement (~31 → ~18.5 ns), but Criterion's
  quick sample reported “no change in performance detected” (p ≈ 0.06 >
  0.05). Relay results at 4/64/1024 KiB varied both directions without
  statistical significance. Longer container runs were not considered useful
  because the host was not a typical VPS; these numbers are order-of-magnitude
  only, not a final decision.

Conclusion at the time: for this client, where waiting on network I/O
dominates rather than allocation-heavy hot paths, the system allocator is a
sensible default. The repeatable 2.5× idle RSS difference is real; a load
speedup was not statistically confirmed. `--features mimalloc` remains an
option for users who profile their own deployment and find allocation to be
a bottleneck; it is not the default.

### Stage 8 — final comparison

The original item was to publish configs and benchmark script for independent
verification. It warned that even sound results do not automatically build
community trust: no track record, public audit, or ready-made GUI/panels, and
technical results and community adoption are separate outcomes.

**Status in this older roadmap: not done for the user and not possible from
that sandbox.** Xray-core was not installed and could not be built there
(proxy allowed crates.io only; no `go install` or `XTLS/Xray-core` clone).
Stage 0/7 numbers were internal before/after baselines, not comparison with
a real alternative. Publishing “our core vs Xray” without actually running
Xray beside it would falsely present an unverified result as verified. The
workspace was not a Git repository and the process had neither credentials
nor permission to publish in the user's name; publication also required the
user's legal judgment and an unresolved Stage 5 review at that time.

The user's runbook was: install Xray locally or on the deployment VPS; run an
equivalent realistic workload for both clients using
`bench/src/bin/memwatch.rs` (which can sample any PID including Xray without
instrumentation); compare on a typical VPS rather than a development host;
resolve the crypto-review item before publication; then decide whether to
publish in light of the user's own legal assessment. Later entries in this
document record that real Xray comparisons were performed. Their methods and
limits are summarized above; do not read this older status as current.

## Overall note

⚠️ **Main strategic risk — time versus benefit.** The whole roadmap could
realistically take one developer many months, including ongoing maintenance
(Stage 3's DPI race). Before starting Stage 1, the plan advised weighing the
expected benefit (an illustrative “0.5–2 MB RSS saved per connection”) against
the time and legal/crypto-error risk of building a core, compared with using
or patching an existing core for the intended task.
