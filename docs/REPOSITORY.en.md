# Repository map

[Русский](REPOSITORY.md) | **English**

Where things are in the repository. How the core works inside — [ARCHITECTURE.en.md](ARCHITECTURE.en.md).

```
bin/client/            reality-client: CLI (flags or --config), sysproxy.rs,
                       winservice.rs (Windows service and autostart)
core/src/
  app/                 application: inbounds -> router -> outbounds;
                       config/ (sing-box, Xray → one model), proxy_in.rs + http_in.rs
                       (socks/http/mixed inbounds), sniff.rs + sniff_quic.rs, router.rs + rules.rs +
                       geo.rs (rules, geosite/geoip), ruleset.rs
                       (sing-box .srs/.json rule sets), outbound.rs
                       (direct, block, dns), vless_out.rs, access.rs,
                       dns/ (upstream.rs: UDP/TCP/DoT/DoH/DoQ, cache.rs,
                       fakeip.rs), dns_in.rs (DNS inbound), tun/ (TUN inbound
                       on smoltcp + tun-rs, udp.rs: UDP flows,
                       route.rs: auto_route)
  net_protect.rs       marking outgoing sockets (bypassing TUN)
  vless/               vless:// parsing (uri.rs), VLESS protocol (protocol.rs),
                       XTLS Vision (vision.rs), UDP packets (udp.rs), XUDP (xudp.rs)
  transport/           tcp_tls.rs (TCP, TLS, REALITY), raw.rs (a socket that yields
                       one TLS record at a time for Vision), ws.rs, grpc.rs,
                       httpupgrade.rs, xhttp.rs, quic.rs (quinn: DoQ, HTTP/3),
                       browser_headers.rs (Chrome headers)
  reality/             REALITY: keys and SessionId (auth.rs), ClientHello hook
                       (hook.rs), certificate verification: HMAC and ML-DSA-65 (verifier.rs)
  fingerprint/         Chrome-like ClientHello (chrome_profile.rs), parsing, JA3/JA4
  socks5/              SOCKS5 protocol: greeting, username/password, UDP headers
  relay.rs             bidirectional relay, one buffer per direction
core/tests/            integration tests (loopback) + interop_xray.rs, interop_go_reality.rs
vendor/rustls-reality-patch/
                       rustls 0.23.45 with a patch: REALITY, GREASE, Chrome ClientHello
                       profile (wired in via [patch.crates-io])
interop/go-reality-server/
                       REALITY test server on the XTLS/REALITY library
bin/fpcheck/           JA3/JA4 capture
ffi/                   the core as a library: C ABI (reality.h), a C example
bench/                 benchmarks (criterion) and memory measurement (memwatch, Linux)
scripts/               ci, interop, smoke, Xray build, fingerprint check,
                       Windows build, instructions for Stages 2 and 8
docs/                  ARCHITECTURE.md (how the core works), LIBRARY.md
                       (the core in an app), WINDOWS.md,
                       crypto review checklist (Stage 5)
examples/              example configs: sing-box.json, xray.json, systemd
PLAN.md                stage plan, decision history, open risks (in Russian)
```
