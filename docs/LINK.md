# Параметры ссылки vless://

**Русский** | [English](LINK.en.md)

Какие параметры ссылки `vless://…` понимает клиент. Ссылку обычно выдаёт панель сервера (3x-ui, Marzban, Remnawave) — менять её вручную не нужно.

| Параметр | Значение |
|---|---|
| `security` | `none`, `tls`, `reality`; другое — ошибка |
| `type` | `tcp`/`raw` (по умолчанию), `ws`, `grpc`, `httpupgrade`, `xhttp` (`splithttp`); другое — ошибка |
| `sni` | имя сервера для TLS/REALITY (по умолчанию — host) |
| `pbk`, `sid` | публичный ключ и ShortId REALITY |
| `pqv` | ключ ML-DSA-65 сервера REALITY (необязательно) |
| `flow` | пусто или `xtls-rprx-vision` (`-udp443` тоже); прочее — ошибка |
| `path`, `host` | путь и заголовок Host для ws, httpupgrade, xhttp (`?ed=` в пути отбрасывается) |
| `mode` | для xhttp: `auto` (по умолчанию: REALITY — `stream-one`, иначе `packet-up`), `packet-up`, `stream-up`, `stream-one` |
| `extra` | для xhttp: JSON как у Xray — `headers`, `xPaddingBytes`, `noGRPCHeader`, `scMaxEachPostBytes`, `scMinPostsIntervalMs`, `uplinkHTTPMethod`; настройки, меняющие формат запросов (`xPaddingObfsMode`, размещение session/seq/данных не в пути, `downloadSettings`), — ошибка |
| `serviceName` | имя gRPC-сервиса |
| `alpn` | список ALPN через запятую; по умолчанию `h2,http/1.1` (как Chrome), для ws и httpupgrade — `http/1.1`, для gRPC — всегда `h2`; для xhttp `alpn=http/1.1` включает HTTP/1.1, `alpn=h3` — HTTP/3 поверх QUIC (только `security=tls`) |
| `encryption` | только `none` |
| `headerType` | только `none` |
| `fp` | `chrome` (по умолчанию), `firefox`, `safari`, `ios` (= Safari 26), `edge`, `android` (= Chrome), `random` (один браузер на запуск), `randomized` (на каждый выход); прочее (`360`, `qq`) — Chrome и предупреждение |
