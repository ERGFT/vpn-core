# Security model

[Русский](SECURITY-MODEL.md) | **English**

What the client guarantees and what it protects against. How to report a vulnerability — [SECURITY.md](../SECURITY.md).

## Security

What the client guarantees and what it protects against (details and
history — `PLAN.md`, section "Аудит безопасности" / security audit):

- **Who receives the UUID depends on `security`:**
  - `reality` — only a server that passed REALITY verification. VLESS data
    is sent after a full handshake with verification (certificate HMAC,
    ML-DSA-65 with `pqv=`). There is no fallback to regular certificate
    verification; a degenerate `pbk=` is rejected.
  - `tls` — whoever presents a valid certificate for the `sni=` name (by
    the built-in root set or `--ca`): the same protection as HTTPS, the
    UUID goes to anyone holding a valid certificate for that name.
  - `none` — in plain text: the UUID and traffic are visible to anyone on
    the path to the server. That is why such a link does not run without
    `--allow-insecure`.
- **Replacing the server with a real site does not give the client away (REALITY):**
  like Xray, the client completes the handshake with the site, opens its home
  page like Chrome and only then reports an error — the UUID is not sent.
- **DNS for proxied traffic:** if the app passes the site name (SOCKS5 with a
  hostname, HTTP proxy, TUN with fake-IP), the name is resolved by the
  server and the local DNS does not see it. Visible to the local network may be:
  - the VLESS server's own name;
  - names the app resolved itself before connecting (for example, a
    browser with SOCKS5 without "Proxy DNS when using SOCKS v5");
  - names for the `direct` outbound — through the `dns` section or the
    system DNS;
  - queries to DNS servers with `"detour": "direct"` and to a
    `"type": "local"` server (the system resolver);
  - names that `domain_strategy: ip_if_non_match` resolves for IP rules —
    if the `dns` section's server for them goes direct (by default `dns`
    queries go through `route.final`, usually the VLESS server).
- **The local proxy does not hold on to "dead" connections:** 10 s for the
  SOCKS5/HTTP greeting, idle timeout (300 s; 30 s if one side has already
  closed), a limit on concurrent connections.
- **The server cannot crash the client** with an overlong gRPC, WebSocket or
  xhttp message: all parsers have limits.
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
| A link with `security=none`: the UUID and traffic are visible to everyone on the network, anyone can use the server | the client does not start such a link without `--allow-insecure` |
| The proxy is open to the network (`--listen 0.0.0.0`): password guessing | password of at least 12 characters, address blocked after 5 failures, `--allow-ip` |
| The proxy is open to the network: SOCKS5 and HTTP proxy are **not encrypted** — the password, site addresses and data between the phone and the computer are visible on shared Wi-Fi | that is how these protocols work, the client cannot fix it; it warns at startup. Open the proxy to the network only at home, for your own devices, with `--allow-ip` |
| The proxy is open to the network and there is a rule with the `direct` outbound: a device on the network acts "on behalf of" this computer — including on networks it cannot reach itself (work VPN, Docker, WSL) | `direct` does not let network clients reach the computer's own services (`127.0.0.1`, `localhost`); otherwise — let only your own devices use the proxy (password, `--allow-ip`) and do not route subnets they do not need to `direct` |
| Sees the very fact of a connection to the server's IP, and the volume and timing of traffic | no VPN hides this; REALITY only disguises it as a visit to an ordinary site |
| DNS queries on the local network are visible and can be spoofed (plain DNS is not encrypted) | the `dns` section with DoH/DoT through the server and a DNS inbound (`direct` + a `hijack-dns` rule) as the system DNS; UDP answers are checked (ID, question, server address) |
| Traffic of programs **not** configured to use the proxy bypasses it | this is a proxy, not a system-wide VPN: configure programs or turn on `--system-proxy` (Windows; not all programs honour it); in a browser with SOCKS5, turn on "Proxy DNS when using SOCKS v5", otherwise site names go to the local network's DNS (with an HTTP proxy names go to the proxy anyway) |
