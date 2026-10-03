# TUN — all of the computer's traffic

[Русский](TUN.md) | **English**

The `tun` inbound: the client works as a VPN for all programs. Set in the [config file](CONFIG.en.md), usually together with [DNS](DNS.en.md).

The `tun` inbound creates a virtual network interface, and the traffic of all
programs goes through the client, not only of those configured to use the
proxy:

```json
"inbounds": [
  { "type": "tun", "tag": "tun",
    "address": ["172.19.0.1/30"],               // default, plus fdfe:dcba:9876::1/126
    "auto_route": true,                         // all traffic into TUN (default)
    "strict_route": true,                       // kill switch
    "route_exclude_address": ["192.168.0.0/16"] }
],
"route": {
  "rules": [
    { "action": "sniff" },                       // domain from SNI/Host and from QUIC (HTTP/3)
    { "protocol": "dns", "action": "hijack-dns" } // DNS to port 53 of any address — dns section
  ]
}
```

In Xray — the `"protocol": "tun"` inbound (`settings.name`, `settings.MTU`);
DNS is hijacked by an `inboundTag` rule → a `dns` outbound.

- `sniff` in TUN also finds the domain of QUIC: the ClientHello is assembled
  from the first Initial packets (their keys are derived from the plaintext
  Connection ID), so domain rules work for HTTP/3 too. Non-QUIC — no delay;
  QUIC waits for the second packet for at most 300 ms.
- Requires administrator (Windows) or root (Linux) rights. On Windows,
  `wintun.dll` (from [wintun.net](https://www.wintun.net/), amd64) must be
  next to `reality-client.exe`.
- `auto_route` sends all traffic into TUN; the client's own connections (to
  the server, `direct`, DNS) bypass TUN: on Linux they are marked
  (`SO_MARK`), on Windows they are bound to the physical interface. There is
  no loop, and `direct` rules work as usual. If the computer has no IPv6,
  IPv6 is not routed into TUN.
- With a `hijack-dns` rule, DNS queries to port 53 of any address are
  answered by the `dns` section (without it — a config error). Fake-IP works
  fully with TUN: the program gets a 198.18.x.x address, and the client
  connects by name through the server.
- Exiting the client (Ctrl+C, closing the window) restores the routes. If
  the client is killed, the interface disappears together with its routes —
  the network works directly again. With `strict_route` — the opposite:
  the network stays closed (kill switch) until the client is started again
  or `reality-client --tun-cleanup` is run (only `route_exclude_address`
  and essentials stay open: DHCP, and NDP for IPv6). On Linux this is an
  `unreachable` rule, on Windows — persistent WFP filters (they survive
  even a reboot); the Windows service restarts itself after a crash. After
  a crash the system DNS is closed too: the server name resolves on restart
  if the server address is an IP or the `dns` section has a server by IP
  with `"detour": "direct"`. On Windows, for the first few seconds after
  the kill switch turns on, the system is still "identifying" the TUN
  interface and its DNS queries may fail; after a few seconds names
  resolve through the tunnel.
- `auto_route` is held by one instance per computer (on Linux — per
  network namespace): the routing table, rules and WFP filters are shared.
  A second instance with `auto_route` will not start ("auto_route уже
  держит другой запущенный экземпляр" — already held by another running
  instance), and `--tun-cleanup` touches nothing while one is running and
  exits with an error.
- A system DNS server (`"type": "local"`) together with TUN is a config
  error: system DNS itself goes through TUN (a loop).
- Limitations: ICMP (ping) does not pass through TUN; on Windows
  `route_exclude_address` is IPv4 only, and with the local network
  excluded Windows may query the router's DNS directly.
