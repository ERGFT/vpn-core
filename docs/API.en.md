# API, web dashboards and config reload

[Русский](API.md) | **English**

The local API, compatible with the Clash API: control from web dashboards and your own programs. Enabled in the [config file](CONFIG.en.md).

The API is compatible with the **Clash API** (as in sing-box and mihomo):
ready-made web dashboards — [metacubexd](https://github.com/MetaCubeX/metacubexd),
[yacd](https://github.com/haishanh/yacd), zashboard — and clients that speak
the Clash API work with the core unchanged. metacubexd and yacd were tested
against the real core in a browser: groups, server selection, latency
tests, connections, rules, logs, mode.

```json
"experimental": {
  "clash_api": {
    "external_controller": "127.0.0.1:9090",
    "secret_file": "api-token.txt",
    "external_ui": "ui",
    "default_mode": "rule"
  }
},
"route": { "presets": ["block-ads", "private-direct", "ru-direct"] }
```

- `secret` — the token right in the config, `secret_file` (extension) — in
  a separate file; at least 16 characters.
- `external_ui` — a folder with dashboard files (e.g. metacubexd's unpacked
  `compressed-dist.tgz`); it opens at `http://127.0.0.1:9090/ui/`. The client
  does not download dashboards itself (`external_ui_download_url` is an
  error): put the files into the folder.
- `access_control_allow_origin` — dashboard sites allowed to call the API
  from a browser (`["https://metacubex.github.io"]` or `["*"]`); your own
  dashboard from `external_ui` is always allowed.
  `access_control_allow_private_network: true` — needed by Chrome for a
  dashboard hosted on the internet.
- `allow_query_token` (extension) — accept the token in a WebSocket URL
  (`?token=`), the way dashboards send it. By default only when the API
  listens on 127.0.0.1: a URL with the token ends up in proxy logs and
  browser history. An API on the network used from a browser dashboard
  needs `"allow_query_token": true`.
- `default_mode` — the mode at startup: `rule` (by rules), `global`
  (everything through the outbound selected in the `GLOBAL` group) or
  `direct` (everything direct). DNS hijacking works in every mode. The
  `GLOBAL` group (all outbounds, `route.final` by default) is created
  automatically, as in Clash.

Clash requests — the same paths and responses as sing-box:

```sh
T="Authorization: Bearer $(cat api-token.txt)"
curl -H "$T" http://127.0.0.1:9090/proxies                         # outbounds and groups
curl -H "$T" -X PUT -d '{"name":"my-panel/Finland"}' http://127.0.0.1:9090/proxies/proxy
curl -H "$T" "http://127.0.0.1:9090/proxies/proxy/delay?url=https://www.gstatic.com/generate_204&timeout=5000"
curl -H "$T" -X PATCH -d '{"mode":"global"}' http://127.0.0.1:9090/configs
curl -H "$T" http://127.0.0.1:9090/connections
curl -H "$T" -X DELETE http://127.0.0.1:9090/connections/42
curl -H "$T" "http://127.0.0.1:9090/dns/query?name=example.com&type=A"
```

| Request | What it does |
|---|---|
| `GET /configs`, `PATCH /configs` | inbound ports and the mode; change the mode (`mode`; ports and the rest — only in the config file) |
| `PUT /configs` | reread the config file; with `payload` — apply a new config (without writing the file, as in Clash) |
| `GET /proxies[/{name}]`, `PUT /proxies/{group}` | outbounds, groups (`now`, `all`), subscription servers; select a selector member |
| `GET /proxies/{name}/delay`, `GET /group/{name}/delay` | test the latency of an outbound or of all group members |
| `GET /connections`, `DELETE /connections[/{id}]` | open connections (outbound, chain, rule, traffic); close |
| `GET /rules` | rules in order and `route.final` |
| `GET /providers/proxies[/{name}]`, `PUT …/{name}`, `GET …/{name}/healthcheck` | subscriptions: servers, update, check |
| `GET /dns/query?name=&type=` | ask the client's DNS |

Own requests (not in the Clash API): `GET /stats` (traffic per outbound),
`GET /groups`, `PUT /groups/{tag}`, `POST /groups/{tag}/check`,
`POST /subscriptions/{tag}/update`, `POST /reload` (with notes in the
response).

**Changing the config via the API** — the client does not have to write the
file and restart the core itself:

```sh
curl -H "$T" http://127.0.0.1:9090/config               # {"path", "format", "text"}
curl -H "$T" -X PUT --data-binary @new.json "http://127.0.0.1:9090/config?check=1"   # validate only
curl -H "$T" -X PUT --data-binary @new.json http://127.0.0.1:9090/config             # apply and save
```

- The `PUT /config` body is the whole config, sing-box or Xray (the format
  is detected automatically). It is validated, applied without dropping
  connections (like a reload) and written to the config file atomically,
  the previous one kept as `<file>.bak`; `?save=0` applies without writing.
  An error is a 400 and nothing changes. Response:
  `{"applied", "saved", "notes"}` (`notes` — what takes effect only after a
  restart, e.g. the API address or the TUN inbound).
- Files in such a config (`link_file`, `rule_set`, databases,
  certificates…) must come from the config folder, as a relative path
  without `..` and not through a symlink leading outside (the file's real
  location is checked): otherwise anyone with the token could make the
  client (the Windows service — as SYSTEM) read any file on the computer.
- `GET /config` returns the whole file — including UUIDs and passwords, like
  the rest of the API: the token gives full control of the client.
- Works only if the client was started with a config file (`--config`).

Streams — the client learns about changes immediately, without polling. The
response does not end until the client closes the connection: one JSON
object per line or, with `Upgrade: websocket`, one WebSocket frame per
object.

```sh
curl -N -H "$T" http://127.0.0.1:9090/events            # events
curl -N -H "$T" http://127.0.0.1:9090/traffic           # speed every second
curl -N -H "$T" "http://127.0.0.1:9090/logs?level=warning"
```

| Stream | What it sends |
|---|---|
| `/events` | own events: `connection_open` (fields as in `/connections`), `connection_close` (traffic totals, duration), `group_switch` (a group changed its member: by itself or manually), `group_check` (delays after a check), `subscription_update` (server count or error), `reload`, `mode_change`; `lagged` — the client was too slow and some events were skipped (re-read `/connections`) |
| `/traffic` | every second: `up`, `down` — bytes per second, `upTotal`, `downTotal` — totals |
| `/memory` | every second: `inuse` — process memory, bytes |
| `/logs?level=info` | the log: `{"type": "warning", "payload": "…"}`; `level` — `debug`, `info`, `warning`, `error`; never more detailed than what is logged (`RUST_LOG`) |
| `/connections` (WebSocket only) | every `interval` ms (1000 by default) — the same as `GET /connections` |

While nobody listens to a stream, events are not even assembled. Up to 16
streams at a time.

- The token is always required (`Authorization: Bearer`; a WebSocket from a
  browser — `?token=`, see `allow_query_token`). 5 wrong tokens from an
  address (IPv6 — from a /64) block it for a minute and longer; 127.0.0.1
  is never blocked. Only dashboard files and the `GET /` greeting are
  served without it, as in Clash. `Host` must be the API address (DNS
  rebinding protection); browser requests are accepted only from your own
  dashboard and sites in `access_control_allow_origin`; listening on
  anything but 127.0.0.1 requires `allow_ip`. Site addresses in
  `/connections` are browsing history, so they are only in the API, not in
  the log.
- Reload (`PUT /configs`, `POST /reload`, on Linux also `kill -HUP`): if the
  file has an error, the previous config keeps working. New outbounds,
  rules, DNS, groups and subscriptions apply immediately to new
  connections, open ones keep the old ones; group selections and the mode
  are kept. Inbounds are restarted only if their settings changed; the TUN
  inbound and the API — after a program restart. The fake-IP table is kept.
- Presets (after your own rules, so your rules can override them):
  `block-ads` (geosite `category-ads-all` → the first `block`),
  `private-direct` (private addresses, `.local`, `.lan` → the first
  `direct`), `ru-direct`, `cn-direct`, `ir-direct` (country domains,
  geosite, geoip → `direct`).
