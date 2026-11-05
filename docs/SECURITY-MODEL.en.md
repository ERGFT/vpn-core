# Security model

[Русский](SECURITY-MODEL.md) | **English**

Which security properties the client provides, the conditions under which they hold, and the remaining threats. How to report a vulnerability — [SECURITY.md](../SECURITY.md).

## Security

The history and scope of the internal review are documented in [PLAN.en.md, “Security audit (2026-09-26)”](../PLAN.en.md#security-audit-2026-09-26).

- **Who receives the UUID depends on `security`:**
  - `reality` — only a server that passed REALITY verification. VLESS data
    is sent after a full handshake with verification (certificate HMAC,
    ML-DSA-65 with `pqv=`). If REALITY verification fails, the client
    checks the certificate like an ordinary browser only to finish the
    handshake plausibly (see below): that connection is never handed to
    the app and the UUID is not sent over it. A degenerate `pbk=` is
    rejected.
  - `tls` — whoever presents a valid certificate for the `sni=` name (by
    the built-in root set or `--ca`): the same protection as HTTPS, the
    UUID goes to anyone holding a valid certificate for that name.
  - `none` — in plain text: the UUID and traffic are visible to anyone on
    the path to the server. The CLI requires `--allow-insecure`; in a
    sing-box config, set the core extension `allow_insecure: true` on the
    VLESS/Trojan outbound (see the [configuration guide](CONFIG.en.md)). The
    C ABI receives config from the host app, not CLI arguments (see the
    [SDK guide](LIBRARY.en.md)).
- **If a real site responds instead of the REALITY server:** after validating
  its certificate as ordinary TLS, the client starts one background `GET /`
  request with the selected browser profile's headers. The client returns the
  REALITY error immediately without waiting for that request; the background
  request can fail or time out. No VLESS header or UUID is sent over that
  connection. This is a simplified mimic: it makes one request and does not
  open a full browser. The Chrome profile is used when `fp=` is absent;
  supported `fp=` values select other profiles.
- **DNS for proxied traffic:** if the app passes the site name (SOCKS5 with a
  hostname, HTTP proxy, TUN with fake-IP), the name is resolved by the
  server and the local DNS does not see it. Visible to the local network may be:
  - the VLESS server's own name;
  - names the app resolved itself before connecting (for example, a
    browser with SOCKS5 without "Proxy DNS when using SOCKS v5");
  - names resolved for the `direct` outbound: when a `dns` section is
    configured, its selected DNS server resolves them; otherwise the system
    resolver does. A server without an explicit `detour` uses `route.final`,
    or the first outbound if `route.final` is unset (usually VLESS). With
    `detour: direct`, the local network sees the DNS
    server address; it sees query contents only for unencrypted UDP/TCP DNS.
    DoT, DoH, and DoQ encrypt DNS queries. `type: local` delegates resolution
    to the system resolver, whose visibility depends on OS settings;
  - names resolved by `domain_strategy: ip_if_non_match` for IP rules —
    through the selected DNS server and its `detour`. The local network sees
    the name when the query uses unencrypted DNS directly.
- **The local proxy does not hold on to "dead" connections:** 10 s for the
  SOCKS5/HTTP greeting, idle timeout (300 s; 30 s if one side has already
  closed), up to 512 concurrent connections per inbound by default; configure
  the limit with `max_conns`.
- **Some parsers limit input sizes, but this does not guarantee crash or DoS
  protection.** After reading the 5-byte header, the gRPC decoder rejects a
  message whose declared size exceeds 4 MiB without waiting for the complete
  message to be buffered; the
  `rejects_oversized_message_before_buffering_it` test covers this behavior.
  WebSocket configures 1 MiB frame and message limits in its parser.
  For XHTTP, the HTTP/2 client sets a 256 KiB header-list limit; this does not
  limit body size. These values describe specific settings and do not prove
  that all HTTP paths are safe or free of input-handling bugs.
- **A UDP association is used only by its owner** (IP and port), not by any
  process on the same machine.

## If an attacker is on the same Wi-Fi network

What they **cannot** do (with `security=reality` or `tls`):

- read or tamper with traffic to the server or learn the UUID — even if they
  intercept the connection (DNS spoofing, a rogue access point): without the
  server's key they fail REALITY verification, without a trusted certificate —
  TLS verification; the handshake is aborted before the UUID is sent;
- connect to the proxy: by default it listens on `127.0.0.1` only.

What they **can** do, and how it is mitigated:

| What | Protection |
|---|---|
| A link with `security=none`: the UUID and traffic are visible to everyone on the network, anyone can use the server | the CLI requires `--allow-insecure`; for sing-box/SDK config, see [`allow_insecure`](CONFIG.en.md) and the [SDK contract](LIBRARY.en.md) |
| The proxy is open to the network (`--listen 0.0.0.0`): password guessing | password of at least 12 UTF-8 bytes; after 5 wrong attempts an address is blocked for 60 seconds, and later blocks double up to 1 hour. IPv6 attempts are tracked by `/64` subnet; successful authentication clears the failure history. `--allow-ip` further restricts clients |
| The control API is reachable from the network: a token holder can change settings and control the client; `GET /config` exposes UUIDs and passwords | keep the API on loopback. Network access requires a token of at least 16 bytes and `allow_ip`; `Host` and browser `Origin` are checked. `allow_query_token` accepts `?token=` only for WebSocket requests; enable it only if a client needs it, because a URL containing the token may end up in proxy logs or browser history. Dashboard files and `GET /` are available without a token, but do not grant access to protected API routes |
| The proxy is open to the network: SOCKS5 and HTTP proxy do **not encrypt the client-to-proxy connection** — the password and destination names are visible on shared Wi-Fi; unencrypted application traffic is visible too. HTTPS protects its contents with TLS | that is how these protocols work, the client cannot fix it; it warns at startup. Open the proxy to the network only at home, for your own devices, with `--allow-ip` |
| The proxy is open to the network and there is a rule with the `direct` outbound: a device on the network acts "on behalf of" this computer — including on networks it cannot reach itself (work VPN, Docker, WSL) | for non-loopback clients, `direct` blocks loopback and unspecified addresses, as well as IPv4/IPv6 link-local addresses (including `169.254.169.254`); a local client may reach its own host. This restriction is not a general SSRF protection. Otherwise, let only your own devices use the proxy (password, `--allow-ip`) and do not route subnets they do not need to `direct` |
| Sees the server IP, the `sni=` name in ClientHello, and traffic volume and timing | A VPN does not hide this metadata. REALITY uses a ClientHello with the selected browser profile and `sni=`, but it does not hide the IP or the full traffic pattern, or turn the connection into a full browser session |
| DNS queries on the local network are visible and can be spoofed (plain DNS is not encrypted) | the `dns` section with DoH/DoT through the server and a DNS inbound (`direct` + a `hijack-dns` rule) as the system DNS; UDP answers are checked (ID, question, server address) |
| Traffic of programs **not** configured to use the proxy bypasses it | this is a proxy, not a system-wide VPN: configure programs or turn on `--system-proxy` (Windows; not all programs honour it); in a browser with SOCKS5, turn on "Proxy DNS when using SOCKS v5", otherwise site names go to the local network's DNS (with an HTTP proxy names go to the proxy anyway) |
