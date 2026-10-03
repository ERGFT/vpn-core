# vless:// link parameters

[Русский](LINK.md) | **English**

Which parameters of a `vless://…` link the client understands. The link is usually issued by the server panel (3x-ui, Marzban, Remnawave); you don't need to edit it by hand.

| Parameter | Value |
|---|---|
| `security` | `none`, `tls`, `reality`; anything else is an error |
| `type` | `tcp`/`raw` (default), `ws`, `grpc`, `httpupgrade`, `xhttp` (`splithttp`); anything else is an error |
| `sni` | server name for TLS/REALITY (defaults to host) |
| `pbk`, `sid` | REALITY public key and ShortId |
| `pqv` | the REALITY server's ML-DSA-65 key (optional) |
| `flow` | empty or `xtls-rprx-vision` (`-udp443` too); anything else is an error |
| `path`, `host` | path and Host header for ws, httpupgrade, xhttp (`?ed=` in the path is dropped) |
| `mode` | for xhttp: `auto` (default: REALITY — `stream-one`, otherwise `packet-up`), `packet-up`, `stream-up`, `stream-one` |
| `extra` | for xhttp: JSON as in Xray — `headers`, `xPaddingBytes`, `noGRPCHeader`, `scMaxEachPostBytes`, `scMinPostsIntervalMs`, `uplinkHTTPMethod`; settings that change the request format (`xPaddingObfsMode`, session/seq/data placed outside the path, `downloadSettings`) are an error |
| `serviceName` | gRPC service name |
| `alpn` | comma-separated ALPN list; default `h2,http/1.1` (like Chrome), `http/1.1` for ws and httpupgrade, always `h2` for gRPC; for xhttp `alpn=http/1.1` turns on HTTP/1.1, `alpn=h3` — HTTP/3 over QUIC (`security=tls` only) |
| `encryption` | `none` only |
| `headerType` | `none` only |
| `fp` | `chrome` (default), `firefox`, `safari`, `ios` (= Safari 26), `edge`, `android` (= Chrome), `random` (one browser per run), `randomized` (per outbound); anything else (`360`, `qq`) — Chrome and a warning |
