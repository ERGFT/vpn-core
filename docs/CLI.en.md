# Command line and autostart

[Русский](CLI.md) | **English**

All `reality-client` options for running with a single link, and autostart setup. For several servers and rules — the [config file](CONFIG.en.md).

## Running

```sh
# the link on the first line of a file readable only by you
printf '%s\n' 'vless://UUID@host:443?encryption=none&security=reality&sni=site.example&pbk=KEY&sid=SHORTID&type=tcp&flow=xtls-rprx-vision' > server.txt
chmod 600 server.txt
reality-client --server-file server.txt --listen 127.0.0.1:1080
```

- `--server-file` — a file with the link (first non-empty line); the same
  via the `REALITY_SERVER` environment variable. There is also
  `--server 'vless://…'` (the whole link, in quotes: it contains `&`), but
  ⚠️ command-line arguments are visible to every user of the machine (the
  process list), and the link contains your UUID; the client then prints a
  warning.
- `--listen` — local proxy address, `127.0.0.1:1080` by default. The port
  serves both SOCKS5 and HTTP proxy (detected by the first byte).
- `--auth user:password` — require a SOCKS5 username and password. The client
  refuses to listen on anything other than `127.0.0.1` without a password.
  Without the command line: `--auth-file file` or `REALITY_SOCKS_AUTH`.
- `--allow-ip addresses` — who on the network may use the proxy (addresses
  or subnets, comma-separated: `192.168.1.23,192.168.1.40`). This computer is
  always allowed. After 5 wrong passwords in a row an address is blocked for
  a minute (then twice as long each time, up to an hour).
- `--allow-insecure` — allow a link with `security=none`. Without this flag
  the client will not start such a link: the UUID and all traffic would go in
  plain text.
- `--max-conns N` — how many connections to serve at once (512 by default);
  extra ones are closed immediately.
- `--ca file.pem` — custom root certificates for `security=tls` (a server
  with a self-signed certificate).
- `--sniff` — if an app sends an IP instead of a name, recover the name from
  the first bytes (TLS SNI, HTTP Host) and send the name to the server.
- `--system-proxy` (Windows) — turn on the system proxy while running:
  browsers and most programs go through the client with no setup. On exit
  (Ctrl+C, closing the window) the previous settings are restored; if the
  client was killed — `--system-proxy-off`.
- `--no-xudp` — UDP without XUDP (a separate stream per destination) — for
  servers that do not know XUDP.
- Log — to stderr, `info` level by default; `--log-file file` — to a file
  (over 10 MB the previous one is moved to `.old`). Visited site addresses
  are not logged at this level (only with `RUST_LOG=debug`).

## Autostart

**Windows, service** (starts at boot, before logon — needed for TUN; run as
administrator):

```bat
reality-client --service-install --config C:\path\config.json
reality-client --service-uninstall
```

The config file, the files it refers to (they must be in the same folder)
and `reality-client.exe` itself (with `wintun.dll`) are copied to
`%ProgramData%\RealityClient`, which only SYSTEM and administrators can write
to: the service runs as SYSTEM, and an exe or config writable by a regular
user would let any of that user's programs gain system rights. The installer
refuses a folder created beforehand by a non-administrator (delete it and try
again). The log is there too, `reality-client.log`. Changed the config? Run
`--service-install` again (the service is updated and restarted). After a
crash the service restarts itself (after 5 s, 30 s, 2 min).

**Windows, at user logon** (for `--system-proxy`: the system proxy is a
per-user setting):

```bat
reality-client --autostart-install --config C:\path\config.json --system-proxy
reality-client --autostart-uninstall
```

Starts without a window; the log is `reality-client.log` next to the config.

**Linux** — systemd: [`examples/reality-client.service`](../examples/reality-client.service)
(config in `/etc/reality-client`, the only root capability is `CAP_NET_ADMIN`
for TUN, `systemctl reload` rereads the config without dropping connections).

Checking that everything works:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

In a browser — set the SOCKS5 proxy to `127.0.0.1:1080` (in Firefox —
"Connection Settings", together with "Proxy DNS when using SOCKS v5").
