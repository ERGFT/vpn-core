# DNS

**Русский** | [English](DNS.en.md)

Свой DNS клиента вместо системного: серверы, правила, кеш, fake-IP. Задаётся в [файле настроек](CONFIG.md).

Раздел `dns` — свой DNS вместо системного:

```json
"inbounds": [
  { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 53 }   // DNS-сервер для системы
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

В Xray: `"dns": {"servers": ["https://1.1.1.1/dns-query",
{"address": "https+local://…", "domains": ["geosite:category-ru"]}]}` —
`domains` становятся правилами, `+local` — запросы напрямую.

- Серверы: `udp`, `tcp`, `tls` (DNS over TLS, порт 853), `https` (DNS over
  HTTPS, `path` по умолчанию `/dns-query`), `quic` (DNS over QUIC,
  RFC 9250, UDP-порт 853 — через выход VLESS идёт по XUDP), `local`
  (системный резолвер), `fakeip`. Старая форма sing-box —
  `"address": "https://1.1.1.1/dns-query"` — тоже понимается. Для `udp` и
  `tcp` нужен IP: имя самого DNS-сервера разрешить нечем. Сертификаты
  DoT/DoH/DoQ проверяются (свои корни — `tls.certificate_path`).
- `detour` — через какой выход ходить к серверу; по умолчанию
  `route.final`, то есть обычно через сервер VLESS: так ни провайдер, ни
  соседи по Wi-Fi не видят, какие имена вы спрашиваете.
- Кто пользуется модулем: DNS-вход (укажите `127.0.0.1` как DNS в
  настройках сети — тогда через него пойдут запросы всех программ);
  правило `hijack-dns` (DNS-запросы программ, идущие через прокси или
  TUN); выход `direct` (разрешает имена им, а не системой);
  `route.domain_strategy` `ip_if_non_match` (правила по IP для имён).
- Кеш: по TTL ответа (не дольше часа; отрицательные — не дольше минуты),
  до 4096 ответов (`cache_capacity`; `disable_cache` — без кеша).
- Fake-IP (сервер `"type": "fakeip"`): программа сразу получает адрес из
  `198.18.0.0/15` (и `fc00::/18`), а соединяясь с ним через прокси,
  получает настоящий сайт — имя разрешает сервер. Имеет смысл только
  вместе с TUN или для программ, которые ходят через этот прокси: без них
  программа пойдёт на адрес 198.18.x.x напрямую и никуда не попадёт.
  Таблицу можно сохранять между перезапусками (`cache_file` — расширение).
- DNS-вход, открытый в сеть, требует `allow_ip`: иначе это «открытый
  резолвер», которым пользуются для DDoS-атак.
