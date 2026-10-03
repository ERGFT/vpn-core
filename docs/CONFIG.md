# Файл настроек

**Русский** | [English](CONFIG.en.md)

Файл настроек в формате sing-box или Xray-core: входы, выходы, маршрутизация, группы серверов, подписки, `fragment` и `noises`. Отдельно: [DNS](DNS.md), [TUN](TUN.md), [API](API.md), [параметры ссылки](LINK.md).

Для нескольких входов и выходов вместо ключей — файл настроек в формате
**sing-box** или **Xray-core** (JSON, комментарии разрешены); формат
определяется сам. Примеры с пояснениями:
[`examples/sing-box.json`](../examples/sing-box.json) и
[`examples/xray.json`](../examples/xray.json).

```sh
reality-client --config config.json --check   # только проверить
reality-client --config config.json
```

Подходят и готовые настройки sing-box и Xray (из v2rayN, панелей и т.п.):
всё, что умеет ядро, работает как там. Чего ядро не умеет (другие
протоколы, цепочки выходов, мультиплексирование sing-box…), — ошибка при
запуске с путём до ключа, например `outbounds[2].multiplex: не
поддерживается`, а не молча пропущенная настройка. Опечатка в имени
ключа — тоже ошибка.

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
      { "action": "sniff" },                              // домен по SNI/Host, если приложение прислало IP
      { "geosite": ["category-ads-all"], "outbound": "block" },
      { "ip_is_private": true, "outbound": "direct" },
      { "domain_suffix": ["ru", "su"], "geoip": ["ru"], "outbound": "direct" }
    ],
    "final": "proxy"                                      // куда идёт всё, что не попало под правила
  }
}
```

Что понимается в каждом формате:

| | sing-box | Xray-core |
|---|---|---|
| Входы | `socks`, `http`, `mixed`, `tun`; `direct` + правило `hijack-dns` — DNS-сервер | `socks`, `http`, `mixed`, `tun`; `dokodemo-door`, отданный маршрутизацией выходу `dns`, — DNS-сервер |
| Выходы | `vless`, `trojan`, `direct`, `block`, `dns`, `selector`, `urltest` | `vless`, `trojan`, `freedom` (с `fragment`, `noises`), `blackhole`, `dns`; `balancers` с `leastPing`/`leastLoad` — группа `urltest` (проверка — из `observatory`) |
| Транспорт и TLS | `tls` (`reality`, `utls`, `alpn`, `certificate_path`), `transport`: `ws`, `grpc`, `httpupgrade` | `streamSettings`: `raw`/`tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`; `tls`/`reality`; `mux` (Mux.Cool) |
| Правила | `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `geosite`, `geoip`, `ip_cidr`, `ip_is_private`, `port`, `port_range`, `network`, `inbound`, `rule_set`, `protocol: dns`; действия `route`, `reject`, `sniff`, `hijack-dns` | `domain` (`geosite:`, `domain:`, `full:`, `regexp:`, `keyword:`, просто подстрока), `ip` (`geoip:`, адреса), `port`, `network`, `inboundTag`, `outboundTag`/`balancerTag`; `domainStrategy` `AsIs`/`IPIfNonMatch` |
| DNS | `servers` (с `type` и старые с `address`), `rules`, `final`, `strategy`, `fakeip` | `servers` (строки и объекты с `domains`; `+local` — напрямую), `queryStrategy`, `fakedns` |
| API | `experimental.clash_api`: `external_controller`, `secret` | то же расширение `experimental.clash_api` |

Правила проверяются по порядку, срабатывает первое подошедшее. В одном
правиле условия «куда» (домены, `geosite`, адреса, `geoip`) соединяются
через «или», а с портом, сетью и входом — через «и» (как у sing-box).
Правило по IP срабатывает, только если приложение прислало IP; правило по
домену — если прислало имя или имя найдено sniffing'ом. Базы
`geosite.dat` (`dlc.dat` из
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/releases))
и `geoip.dat` ([v2fly/geoip](https://github.com/v2fly/geoip/releases)) —
формат Xray, в том числе и для настроек sing-box; ищутся рядом с файлом
настроек, из них читаются только нужные категории (обе базы целиком —
~0,2 с).

Наборы правил sing-box — `.srs` (например, из
[SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite/tree/rule-set),
[sing-geoip](https://github.com/SagerNet/sing-geoip/tree/rule-set) или
MetaCubeX/meta-rules-dat) и исходный `.json`, только `type: local`:

```json
"route": {
  "rule_set": [{ "type": "local", "tag": "ru", "format": "binary", "path": "geosite-category-ru.srs" }],
  "rules": [{ "rule_set": ["ru"], "outbound": "direct" }]
}
```

`rule_set` можно указывать и в правилах DNS (берутся домены). Загружаются
только наборы, на которые ссылаются правила, и заново — при перечитывании
настроек. Наборы с другими условиями (порт, процесс, логические
`and`/`or`, `invert`) отвергаются с ошибкой: упростить их молча значило бы
маршрутизировать не так, как задумано. Скачивать наборы по URL клиент сам
не умеет — положите файл рядом с настройками.

**Расширения этого ядра** — ключи, которых нет в самих форматах (sing-box
и Xray их не примут):

- у выходов `vless`/`trojan`: `link` или `link_file` — ссылка
  `vless://`/`trojan://` вместо полей (секрет можно держать в отдельном
  файле); `allow_insecure` — разрешить сервер без шифрования; `mux` —
  Mux.Cool (в sing-box: `"mux": 8`); `fragment`;
- у `direct` (sing-box): `fragment`, `noises` — как у `freedom` в Xray;
- выход `fallback` (первый работающий) и `subscriptions` у групп;
- в корне: `subscriptions` — подписки с панели;
- у входов: `allow_ip`, `max_conns`; у `transport` (sing-box): `type: xhttp`;
- в `route` (sing-box): `presets`, `geosite_file`, `geoip_file`,
  `domain_strategy`; у `fakeip`: `cache_file`.

Ключи командной строки — сокращение для одного входа `mixed` и одного
выхода `proxy`. Выход `direct` не пускает клиентов из сети к службам этого
компьютера (`127.0.0.1`, `localhost`); выход `block` отвечает SOCKS5-кодом
0x02 или HTTP 403.

## Группы серверов и подписки

Несколько серверов — группа; группа сама выход, её tag пишут в правила и
`route.final`:

```json
"outbounds": [
  { "type": "urltest", "tag": "auto",            // самый быстрый; "fallback" — первый работающий;
    "outbounds": ["proxy"],                      // "selector" — выбранный (default или первый)
    "subscriptions": ["my-panel"],               // + серверы с панели
    "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50 }
],
"subscriptions": [
  { "tag": "my-panel", "url_file": "subscription.txt",   // адрес подписки — секрет, как UUID
    "update_interval": 43200, "detour": "direct", "include": "Germany|Finland" }
]
```

В формате Xray то же — `routing.balancers` со стратегией `leastPing` и
`observatory` (адрес и период проверки).

- Проверка — HTTP-запрос через каждого участника раз в `interval` с
  разбросом ±20 %; `urltest` не переключается, пока текущий хуже лучшего
  не больше чем на `tolerance` мс. Не открылось соединение — пробуется
  следующий участник (до трёх), неудачник считается упавшим до проверки.
  Переключение не рвёт открытых соединений.
- Подписка: base64-список ссылок (3x-ui, Marzban, Remnawave), обычный
  текст, JSON sing-box, YAML Clash — берутся только VLESS и Trojan,
  остальное в журнале счётчиком. Только https с проверкой сертификата
  (`ca_file` — для самоподписанного сертификата панели); серверы с
  `security=none` пропускаются без `allow_insecure`. Загрузка — через
  группу, а пока список пуст — через `direct` (или через `detour`).
  Последний список — в `<tag>.subscription` рядом с настройками (права
  600): клиент стартует без панели. В журнал попадает только имя сервера
  панели, не адрес подписки. С TUN подписка без сохранённого списка
  загружается до включения маршрутов.

## Против DPI: fragment и noises

```json
{ "type": "direct", "tag": "direct",
  "fragment": { "packets": "tlshello", "length": "100-200", "interval": "10-20" },
  "noises": [{ "type": "rand", "packet": "10-20", "delay": "10-16" }] }
```

В Xray — те же поля в `settings` выхода `freedom`. `fragment` (у `vless` —
к серверу, у `direct` — к сайтам) режет первый TLS-рекорд с ClientHello на
рекорды по `length` байт; с `interval > 0` — ещё и отдельными
TCP-сегментами с паузами (мс). `packets = "1-3"` — вместо этого режутся
1–3-я записи в соединение. Помогает против DPI, который ищет имя сайта в
первом пакете и не собирает поток; против DPI, который собирает, — нет, а
необычный ClientHello сам по себе заметен. `noises` — пакеты-пустышки
(`rand`, `str`, `base64`, `hex`) перед первой UDP-датаграммой к адресу; к
порту 53 не шлются. Оба выключены по умолчанию; параметры — как у
`freedom` в Xray.
