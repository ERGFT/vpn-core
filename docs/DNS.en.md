# DNS

[Русский](DNS.md) | **English**

The client's own DNS instead of the system one: servers, rules, cache, fake-IP. Set in the [config file](CONFIG.en.md).

The `dns` section — own DNS instead of the system one:

```json
"inbounds": [
  { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 53 }   // DNS server for the system
],
"route": { "rules": [{ "inbound": ["dns-in"], "action": "hijack-dns" }] },
"dns": {
  "servers": [
    { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },
    { "type": "https", "tag": "local", "server": "common.dot.dns.yandex.net", "detour": "direct" }
  ],
  "rules": [{ "geosite": ["category-ru"], "server": "local" }],
  "final": "remote"
}
```

In Xray: `"dns": {"servers": ["https://1.1.1.1/dns-query",
{"address": "https+local://…", "domains": ["geosite:category-ru"]}]}` —
`domains` become rules, `+local` — queries go directly.

- Servers: `udp`, `tcp`, `tls` (DNS over TLS, port 853), `https` (DNS over
  HTTPS, `path` defaults to `/dns-query`), `quic` (DNS over QUIC, RFC 9250,
  UDP port 853 — goes over XUDP through a VLESS outbound), `local` (system
  resolver), `fakeip`. The legacy sing-box form —
  `"address": "https://1.1.1.1/dns-query"` — is understood too. `udp` and
  `tcp` need an IP: there is nothing to resolve the DNS server's own name
  with. DoT/DoH/DoQ certificates are verified (own roots —
  `tls.certificate_path`).
- `detour` — which outbound to use to reach the server; defaults to
  `route.final`, i.e. usually through the VLESS server: this way neither
  your ISP nor your Wi-Fi neighbours see which names you look up.
- Who uses the module: the DNS inbound (set `127.0.0.1` as DNS in the network
  settings — then all programs' queries go through it); the `hijack-dns`
  rule (programs' DNS queries going through the proxy or TUN); the `direct`
  outbound (resolves names with it rather than with the system);
  `route.domain_strategy` `ip_if_non_match` (IP rules for names).
- Cache: by answer TTL (at most an hour; negative — at most a minute), up to
  4096 answers (`cache_capacity`; `disable_cache` — no cache).
- Fake-IP (a `"type": "fakeip"` server): the program immediately gets an
  address from `198.18.0.0/15` (and `fc00::/18`), and when connecting to it
  through the proxy it reaches the real site — the server resolves the name.
  Only makes sense with TUN or for programs that use this proxy: otherwise
  the program goes to 198.18.x.x directly and gets nowhere. The table can be
  kept across restarts (`cache_file` — extension).
- A DNS inbound open to the network requires `allow_ip`: otherwise it is an
  "open resolver" used for DDoS attacks.
