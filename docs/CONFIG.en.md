# Config file

[Русский](CONFIG.md) | **English**

The config file in sing-box or Xray-core format: inbounds, outbounds, routing, server groups, subscriptions, `fragment` and `noises`. See also: [DNS](DNS.en.md), [TUN](TUN.en.md), [application routing](APPLICATION_ROUTING.en.md), [API](API.en.md), [link parameters](LINK.en.md).

For multiple inbounds and outbounds, use a config file instead of flags, in
the **sing-box** or **Xray-core** format (JSON, comments allowed); the format
is detected automatically. Annotated examples:
[`examples/sing-box.json`](../examples/sing-box.json) and
[`examples/xray.json`](../examples/xray.json).

```sh
reality-client --config config.json --check   # validate only
reality-client --config config.json
```

sing-box and Xray files can be used as a starting point, but vpn-core accepts
only the parts of those formats that it supports. The format name does not
guarantee compatibility with every config from v2rayN or a panel, or behavior
that fully matches upstream. Check the table below and the [features
matrix](FEATURES.en.md). Many unknown or unsupported keys produce an error
with the key path; some explicitly handled fields may be ignored. For example,
an unsupported `multiplex` setting produces
`outbounds[2].multiplex: не поддерживается` (not supported).

The `--check` command parses the file and builds the application, then exits
before `app.start`. It reports configuration errors but does not test a
connection to a server.

```json
{
  "inbounds": [
    { "type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": 1080 }
  ],
  "outbounds": [
    { "type": "vless", "tag": "proxy", "server": "server.example.com", "server_port": 443,
      "uuid": "…", "flow": "xtls-rprx-vision",
      "tls": { "enabled": true, "server_name": "www.example.com",
               "utls": { "enabled": true, "fingerprint": "chrome" },
               "reality": { "enabled": true, "public_key": "…", "short_id": "…" } } },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [
      { "action": "sniff" },                              // domain from SNI/Host if the app sent an IP
      { "geosite": ["category-ads-all"], "outbound": "block" },
      { "ip_is_private": true, "outbound": "direct" },
      { "domain_suffix": ["ru", "su"], "geoip": ["ru"], "outbound": "direct" }
    ],
    "final": "proxy"                                      // where everything not matched by rules goes
  }
}
```

What each format supports:

| | sing-box | Xray-core |
|---|---|---|
| Inbounds | `socks`, `http`, `mixed`, `tun`; `direct` + a `hijack-dns` rule — DNS server | `socks`, `http`, `mixed`, `tun`; `dokodemo-door` (or `tunnel`, only in the DNS-server role) routed to a `dns` outbound |
| Outbounds | `vless`, `trojan`, TCP `socks` and `http` (HTTP CONNECT), `direct`, `block`, `dns`, `selector`, `urltest`; `fallback` is a vpn-core extension | `vless`, `trojan`, `freedom` (with `fragment`, `noises`), `blackhole`, `dns`; `balancers` with `leastPing`/`leastLoad` are converted to `urltest` (checks from `observatory`) |
| Transport and TLS | `tls` (`reality`, `utls`, `alpn`, `certificate_path`), `transport`: `ws`, `grpc`, `httpupgrade`; core extension `type: xhttp` with the supported part of `extra` | `streamSettings`: `raw`/`tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` (legacy alias: `splithttp`), including the supported part of `extra.downloadSettings`; `tls`/`reality`; `mux` (Mux.Cool) |
| Rules | `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `geosite`, `geoip`, `ip_cidr`, `ip_is_private`, `port`, `port_range`, `network`, `inbound`, `rule_set`, `user_id`, `invert`, `protocol: dns`; actions `route`, `reject`, `sniff`, `hijack-dns` | `domain` (`geosite:`, `domain:`, `full:`, `regexp:`, `keyword:`, plain substring), `ip` (`geoip:`, addresses), `port`, `network`, `inboundTag`, `outboundTag`/`balancerTag`; `domainStrategy` `AsIs`/`IPIfNonMatch` |
| DNS | `servers` (with `type`, and the legacy form with `address`), `rules`, `final`, `strategy`, `fakeip` | `servers` (strings and objects with `domains`; `+local` — direct), `queryStrategy`, `fakedns` |
| API | `experimental.clash_api`: `external_controller`, `secret` | the same `experimental.clash_api` extension |

Xray `leastLoad` does not retain its original semantics: both balancer types
are converted to the same latency-based `urltest` group, and
`strategy.settings` is ignored. The probe URL and interval come from
`observatory` or `burstObservatory`; other parameters in these sections do
not imply full Xray routing compatibility.

For XHTTP, the Xray parser accepts `downloadSettings` in `xhttpSettings` (or
`splithttpSettings`) and passes it to the limited `extra` parser. The sing-box
`transport.type: xhttp` extension uses the same XHTTP parser. The supported
fields, limits, and a separate download-channel example are documented in the
[link and XHTTP guide](LINK.en.md); this does not mean that all Xray options
are supported.

Rules are checked in order; the first match wins. Within one rule the
"where" conditions (domains, `geosite`, addresses, `geoip`) are combined with
"or", and with port, network and inbound — with "and" (as in sing-box). An IP
rule only matches if the app sent an IP; a domain rule — if it sent a name or
the name was found by sniffing. The `geosite.dat` (`dlc.dat` from
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/releases))
and `geoip.dat` ([v2fly/geoip](https://github.com/v2fly/geoip/releases))
databases are in the Xray format, sing-box configs included; they are looked
up next to the config file, and only the needed categories are read (both
full databases — ~0.2 s).

sing-box rule sets — `.srs` (e.g. from
[SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite/tree/rule-set),
[sing-geoip](https://github.com/SagerNet/sing-geoip/tree/rule-set) or
MetaCubeX/meta-rules-dat) and source `.json`, `type: local` only:

```json
"route": {
  "rule_set": [{ "type": "local", "tag": "ru", "format": "binary", "path": "geosite-category-ru.srs" }],
  "rules": [{ "rule_set": ["ru"], "outbound": "direct" }]
}
```

`rule_set` can also be used in DNS rules (domains are taken). Only rule sets
referenced by rules are loaded, and they are reloaded on config reload. Rule
sets with other conditions (port, process, logical `and`/`or`, `invert`) are
rejected with an error: silently simplifying them would route differently
from what was intended. The client does not download rule sets by URL — put
the file next to the config.

**Extensions of this core** — keys that are not part of the formats
themselves (sing-box and Xray will not accept them):

- on `vless`/`trojan` outbounds: `link` or `link_file` — a
  `vless://`/`trojan://` link instead of fields (the secret can live in a
  separate file); `allow_insecure` — explicitly allow `security=none` for
  VLESS or Trojan. The connection to the server is unencrypted in this mode;
  a Trojan password is also sent in plaintext. This field does not disable
  TLS certificate verification; keys for that purpose are unsupported;
  `mux` — Mux.Cool (in sing-box: `"mux": 8`); `fragment`;
- on `direct` (sing-box): `fragment`, `noises` — as on `freedom` in Xray;
- the `fallback` outbound (first working) and `subscriptions` on groups;
- at the root: `subscriptions` — panel subscriptions;
- on inbounds: `allow_ip`, `max_conns`; on `transport` (sing-box): `type: xhttp`;
- in `route` (sing-box): `presets`, `geosite_file`, `geoip_file`,
  `domain_strategy`; on `fakeip`: `cache_file`.

Command-line flags are a shortcut for one `mixed` inbound and one `proxy`
outbound. The `direct` outbound does not let network clients reach services
of this computer (`127.0.0.1`, `localhost`); the `block` outbound replies with
SOCKS5 code 0x02 or HTTP 403.

## SOCKS5 and HTTP CONNECT TCP chains

The sing-box `detour` field can be set on `socks` or `http` outbounds. It uses
the specified TCP outbound to connect to the proxy server. Multiple SOCKS5/HTTP
CONNECT hops can be nested; `direct`, VLESS, or Trojan can be the base outbound:

```json
"outbounds": [
  { "type": "socks", "tag": "entry", "server": "entry.example", "server_port": 1080, "network": "tcp" },
  { "type": "http", "tag": "exit", "server": "exit.example", "server_port": 8080, "detour": "entry" }
],
"route": { "final": "exit" }
```

Groups, `block`, and `dns` are not valid detours. Missing tags and cycles are
rejected. A failure at any hop is returned to the caller without falling back
to `direct`. Only TCP chains are supported.

### SOCKS5 and HTTP CONNECT authentication

In sing-box `socks` and `http` outbounds, set credentials as a pair:
`username` and `password`. SOCKS5 uses RFC 1929 authentication; each field
must be 1–255 bytes. HTTP CONNECT uses Basic authentication; the username
cannot contain a colon. Both fields are required together, must be non-empty,
and can be up to 4096 bytes; control characters are rejected. The
`password_file` core extension supplies the password instead of `password`:
the first non-empty line is used with surrounding whitespace trimmed. Choose
only one password source.

The SOCKS5 outbound supports TCP only and does not support TLS. HTTP CONNECT
uses TCP and HTTP/1.1. TLS is optional and is enabled with `tls.enabled`;
certificate verification is always required. `tls.server_name` defaults to
`server`; `ca_file` adds trusted roots without disabling certificate
verification. Without TLS or an encrypting
`detour`, credentials travel without protection: SOCKS5 does not encrypt its
authentication, and Basic encodes the password but does not encrypt it. A
`detour` can protect the path to the proxy if the selected outbound encrypts
the connection.

## Server groups and subscriptions

Several servers make a group; a group is itself an outbound, and its tag is
used in rules and `route.final`:

```json
"outbounds": [
  { "type": "urltest", "tag": "auto",            // fastest; "fallback" — first working;
    "outbounds": ["proxy"],                      // "selector" — selected (default or first)
    "subscriptions": ["my-panel"],               // + servers from the panel
    "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50 }
],
"subscriptions": [
  { "tag": "my-panel", "url_file": "subscription.txt",   // the subscription URL is a secret, like a UUID
    "update_interval": 43200, "detour": "direct", "include": "Germany|Finland" }
]
```

In the Xray format — the same via `routing.balancers` with the `leastPing`
strategy and `observatory` (check URL and interval).

- Health check — an HTTP request through each member every `interval` with
  ±20 % jitter; `urltest` does not switch while the current member is worse
  than the best by no more than `tolerance` ms. If a connection fails to
  open, the next member is tried (up to three), and the failed one is
  considered down until the next check. Switching does not drop open
  connections.
- Subscription: a base64 list of links (3x-ui, Marzban, Remnawave), plain
  text, sing-box JSON, Clash YAML — only VLESS and Trojan are taken, the rest
  is counted in the log. HTTPS only, with certificate verification
  (`ca_file` — for a panel's self-signed certificate); `security=none`
  servers are skipped without `allow_insecure`. Downloads go through the
  group, and while the list is empty — through `direct` (or `detour`). The
  last list is saved to `<tag>.subscription` next to the config. On Unix, the
  file is created with mode `0600`; on Windows, permissions are inherited from
  the directory. The service directory under `%ProgramData%` is not writable by
  regular users, but for a normal run access depends on the config directory's
  ACL. The file contains UUIDs, and the cache lets the client start without the
  panel. Only the panel's host name is logged, not the subscription URL. With
  TUN, a subscription without a saved list is
  downloaded before routes are enabled.

## Anti-DPI: fragment and noises

```json
{ "type": "direct", "tag": "direct",
  "fragment": { "packets": "tlshello", "length": "100-200", "interval": "10-20" },
  "noises": [{ "type": "rand", "packet": "10-20", "delay": "10-16" }] }
```

In Xray — the same fields in the `settings` of a `freedom` outbound.
`fragment` (on `vless` — towards the server, on `direct` — towards sites)
splits the first TLS record with the ClientHello into records of `length`
bytes; with `interval > 0` — also into separate TCP segments with delays
(ms). `packets = "1-3"` splits the 1st–3rd records of the connection instead.
It helps against DPI that looks for the site name in the first packet and
does not reassemble the stream; against DPI that reassembles, it does not,
and an unusual ClientHello is noticeable in itself. `noises` — dummy packets
(`rand`, `str`, `base64`, `hex`) before the first UDP datagram to an address;
not sent to port 53. Both are off by default; parameters are as in Xray's
`freedom`.
