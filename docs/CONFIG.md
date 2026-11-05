# Файл настроек

**Русский** | [English](CONFIG.en.md)

Файл настроек с поддерживаемым подмножеством формата sing-box или Xray-core: входы, выходы, маршрутизация, группы серверов, подписки, `fragment` и `noises`. Отдельно: [DNS](DNS.md), [TUN](TUN.md), [привязка к приложениям](APPLICATION_ROUTING.md), [API](API.md), [параметры ссылки](LINK.md).

Для нескольких входов и выходов вместо ключей используйте файл настроек с
поддерживаемым подмножеством формата **sing-box** или **Xray-core** (JSON,
комментарии разрешены); формат
определяется сам. Примеры с пояснениями:
[`examples/sing-box.json`](../examples/sing-box.json) и
[`examples/xray.json`](../examples/xray.json).

```sh
reality-client --config config.json --check   # только проверить
reality-client --config config.json
```

Готовый конфиг sing-box или Xray можно взять за основу, но ядро поддерживает
только подмножество формата, перечисленное ниже. Совпадение формата не
означает полной совместимости с исходным приложением или одинаковой семантики
всех полей: у ядра есть собственные ограничения и расширения. После адаптации
проверьте файл командой `--check`. Она проверяет разбор и построение
конфигурации, но не подключение к серверу. Неизвестные и явно неподдерживаемые
поля, которые проверяет парсер, приводят к ошибке с путём до ключа; некоторые
служебные поля источника могут игнорироваться.

```jsonc
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
| Входы | `socks`, `http`, `mixed`, `tun`; `direct` + правило `hijack-dns` — DNS-сервер | `socks`, `http`, `mixed`, `tun`; `dokodemo-door` (или `tunnel`, только в роли DNS-сервера), отданный маршрутизацией выходу `dns` |
| Выходы | `vless`, `trojan`, TCP `socks` и `http` (HTTP CONNECT), `direct`, `block`, `dns`, `selector`, `urltest`; `fallback` — расширение vpn-core | `vless`, `trojan`, `freedom` (с `fragment`, `noises`), `blackhole`, `dns`; `balancers` с `leastPing`/`leastLoad` преобразуются в `urltest` (проверка — из `observatory`) |
| Транспорт и TLS | `tls` (`reality`, `utls`, `alpn`, `certificate_path`), `transport`: `ws`, `grpc`, `httpupgrade`; расширение ядра `type: xhttp` | `streamSettings`: `raw`/`tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` (также старое имя `splithttp`); `tls`/`reality`; `mux` (Mux.Cool) |
| Правила | `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `geosite`, `geoip`, `ip_cidr`, `ip_is_private`, `port`, `port_range`, `network`, `inbound`, `rule_set`, `user_id`, `invert`, `protocol: dns`; действия `route`, `reject`, `sniff`, `hijack-dns` | `domain` (`geosite:`, `domain:`, `full:`, `regexp:`, `keyword:`, просто подстрока), `ip` (`geoip:`, адреса), `port`, `network`, `inboundTag`, `outboundTag`/`balancerTag`; `domainStrategy` `AsIs`/`IPIfNonMatch` |
| DNS | `servers` (с `type` и старые с `address`), `rules`, `final`, `strategy`, `fakeip` | `servers` (строки и объекты с `domains`; `+local` — напрямую), `queryStrategy`, `fakedns` |
| API | `experimental.clash_api`: `external_controller`, `secret` | то же расширение `experimental.clash_api` |

В Xray `leastLoad` не сохраняет исходную семантику: оба типа balancer
преобразуются в одну latency-based группу `urltest`, а `strategy.settings`
игнорируются. Не рассчитывайте на полную совместимость Xray routing.

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

Ниже — частичный фрагмент раздела `route`, а не полный файл настроек.

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
  файле); `allow_insecure` — явно разрешить `security=none` для VLESS или
  Trojan. В этом режиме соединение с сервером не шифруется; пароль Trojan
  также передаётся открытым текстом. Это поле не отключает проверку
  сертификата TLS; ключи такого назначения не поддерживаются; `mux` —
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

## TCP-цепочки SOCKS5 и HTTP CONNECT

У outbound типа `socks` или `http` можно задать sing-box поле `detour`. Оно
использует указанный TCP outbound для соединения с сервером proxy. Несколько
SOCKS5/HTTP CONNECT звеньев можно вложить; базовым выходом может быть `direct`,
VLESS или Trojan:

Ниже показаны связанные разделы `outbounds` и `route`; это частичный фрагмент
конфигурации, а не полный файл.

```json
"outbounds": [
  { "type": "socks", "tag": "entry", "server": "entry.example", "server_port": 1080, "network": "tcp" },
  { "type": "http", "tag": "exit", "server": "exit.example", "server_port": 8080, "detour": "entry" }
],
"route": { "final": "exit" }
```

`detour` нельзя направлять на группу, `block` или `dns`; отсутствующий tag и
циклические цепочки отклоняются. Если звено недоступно, ошибка возвращается
вызывающему коду без перехода на `direct`. Поддерживаются только TCP-цепочки.

### Авторизация SOCKS5 и HTTP CONNECT

В sing-box-выходах `socks` и `http` учётные данные задаются парой
`username`/`password`. Для SOCKS5 это аутентификация RFC 1929; каждое поле
должно занимать 1–255 байт. Для HTTP CONNECT используется Basic auth;
имя не может содержать двоеточие. Оба поля обязательны вместе, не должны быть
пустыми и могут занимать до 4096 байт; управляющие символы запрещены.
Расширение ядра `password_file` задаёт пароль вместо `password`: берётся первая
непустая строка файла без пробелов по краям. Укажите только один из двух
источников пароля.

SOCKS5 outbound поддерживает только TCP и не поддерживает TLS. HTTP CONNECT
использует TCP и HTTP/1.1. TLS необязателен и включается через
`tls.enabled`; сертификат проверяется всегда. `tls.server_name` по умолчанию
равен `server`; `ca_file` задаёт дополнительные корни доверия, не отключая
проверку сертификата. Без TLS или шифрующего
`detour` учётные данные проходят по сети без защиты: SOCKS5 сам не шифрует
аутентификацию, а Basic кодирует, но не шифрует пароль. `detour` может
защитить путь до прокси, если выбранный выход шифрует соединение.

## Группы серверов и подписки

Несколько серверов — группа; группа сама выход, её tag пишут в правила и
`route.final`:

Следующий JSONC-фрагмент показывает только группу и подписку, а не полный файл
настроек.

```jsonc
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
  Последний список — в `<tag>.subscription` рядом с настройками: на Unix
  файл создаётся с режимом `0600`; на Windows права наследуются от каталога.
  Каталог службы в `%ProgramData%` закрыт для записи обычным пользователям,
  но для обычного запуска уровень доступа определяет ACL каталога настроек.
  Файл содержит UUID; с кешем клиент стартует без панели. В журнал попадает
  только имя сервера панели, не адрес подписки. С TUN подписка без
  сохранённого списка загружается до включения маршрутов.

## Против DPI: fragment и noises

Ниже — объект выхода `direct` для раздела `outbounds`, а не полный файл настроек.

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
