# reality-core

Собственное ядро клиента **VLESS (+REALITY, +XTLS Vision)** на Rust:
консольная программа `reality-client` принимает `vless://`-ссылку и
поднимает локальный **SOCKS5-прокси** (TCP и UDP). Трафик программ,
которым указан этот прокси, уходит на VLESS-сервер (Xray-core и
совместимые).

Проект написан с нуля по этапам — история, решения и риски по каждому
этапу в [`PLAN.md`](PLAN.md). Это учебно-исследовательский проект, а не
замена зрелым клиентам: ниже честно перечислено, что работает и чего нет.

## Что умеет и чего нет

| Возможность | Статус |
|---|---|
| `security=none` / `tls` / `reality` | ✅ все три проверены против настоящего Xray-core |
| Транспорт `type=tcp` (он же `raw`) | ✅ |
| Транспорты `type=ws` (`path=`, `host=`), `type=grpc` (`serviceName=`, режим «gun»), `type=httpupgrade` | ✅ проверены против настоящего Xray-core; HTTP-заголовки запроса — как у Chrome (как у Xray) |
| Транспорт `type=xhttp` (SplitHTTP): режимы `packet-up`, `stream-up`, `stream-one`, HTTP/2 и HTTP/1.1, `extra=` | ✅ все режимы проверены против Xray-core, в т.ч. поверх REALITY (см. ниже, что не поддерживается) |
| `flow=xtls-rprx-vision` (XTLS Vision) | ✅ padding, распознавание внутреннего TLS, прямая передача в обе стороны; проверено против Xray-core. Как и в Xray — только `type=tcp` с `tls`/`reality` |
| REALITY: X25519MLKEM768 (и откат на X25519 для сайтов без ML-KEM), ShortId, `minClientVer`/`maxClientVer`, HMAC-сертификат | ✅ |
| REALITY: ML-DSA-65 (`pqv=`) | ✅ |
| TLS-отпечаток как у Chrome 133 | ✅ REALITY — совпадает полностью, включая JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`; обычный TLS — без legacy cipher suite'ов и ALPS (см. ниже) |
| `fp=firefox` (Firefox 148), `safari`/`ios` (Safari 26.3), `edge`/`android` (как Chrome), `random`, `randomized` | ✅ cipher suites, расширения в порядке браузера, группы, доли ключа (у Firefox — настоящая P-256), подписи, сжатие сертификата (zlib, brotli, zstd — с распаковкой), GREASE — сверены с utls; HTTP-заголовки ws/httpupgrade/xhttp — того же браузера; проверено против REALITY-сервера Xray (tcp, Vision, xhttp, gRPC) |
| UDP (SOCKS5 UDP ASSOCIATE) через XUDP — как у клиента Xray: все назначения в одном потоке, Full Cone NAT | ✅ в том числе с Vision (другого способа UDP Vision-аккаунт у Xray не принимает); `--no-xudp` — поток на каждое назначение |
| Логин/пароль на SOCKS5 (`--auth`) | ✅ |
| Файл настроек (`--config`, TOML): несколько входов и выходов (`vless`, `direct`, `block`) | ✅ |
| Группы серверов `selector`, `urltest`, `fallback` (проверка по HTTP, переход к следующему при отказе); подписки: base64/текст/JSON sing-box/YAML Clash, кеш на диске | ✅ проверено с панелью на HTTPS и сервером Xray |
| Входы SOCKS5, HTTP-прокси (CONNECT и обычные запросы) и `mixed` — оба на одном порту | ✅ |
| Маршрутизация: домен (точно, суффикс, подстрока, regex), IP/подсеть, частные адреса, порт, сеть, вход, базы `geosite.dat`/`geoip.dat` (v2fly) | ✅ наборы правил sing-box (`.srs`) — нет |
| Sniffing: домен по TLS SNI и HTTP Host, когда приложение прислало IP | ✅ QUIC — нет |
| Системный прокси Windows (`--system-proxy`) | ✅ проверен под Wine |
| TUN — весь трафик компьютера (как VPN): свой TCP/IP-стек, `auto_route`, перехват DNS, fake-IP, `route_exclude`, kill switch `strict_route` | ✅ Linux — проверен против Xray в изолированном netns (TCP, UDP, DNS, fake-IP, ~85 МиБ/с); 🟡 Windows (Wintun) — собирается, на настоящей Windows не запускался; kill switch — только Linux |
| Свой DNS: серверы UDP, TCP, DoT, DoH, системный; выбор сервера по доменам и geosite; кеш; вход DNS-сервера; перехват DNS (выход `dns`); fake-IP; `domain_strategy = "ip_if_non_match"` | ✅ DoH/DoT проверены на своих серверах, UDP-DNS через Xray; DNS over QUIC — нет |
| Mux.Cool для TCP (`mux = 8` у выхода или подписки; не вместе с Vision) | ✅ проверен против Xray-core |
| Общие HTTP/2-соединения: gRPC — все потоки в одном соединении (как у Xray), xhttp — `xmux` (умолчания Xray: 16–32 сессии на соединение) | ✅ проверено против Xray-core (счёт соединений) |
| Против DPI: дробление ClientHello (`fragment`: TLS-рекорды и/или TCP-сегменты с паузами) у `vless` и `direct`, шум перед UDP (`noises`) у `direct` | ✅ дробление проверено против REALITY-сервера Xray (в т.ч. рекорды по 1–3 байта и Vision); по умолчанию выключено |
| Транспорт `kcp`, xhttp через HTTP/3 | ❌ не поддерживаются (почему — ниже); `quic`/`h2` удалены из самого Xray-core — ошибка подсказывает `xhttp` |
| Linux | ✅ собирается и проверен |
| Windows | 🟡 `.exe` собирается кросс-компиляцией и проходит все тесты и smoke против Xray-core под Wine ([`docs/WINDOWS.md`](docs/WINDOWS.md)); на настоящей Windows не запускался |

Стороннее крипто-ревью реализации REALITY не проводилось (подробности —
`PLAN.md`, Этап 5).

## Сборка

Нужен Rust (stable). На Linux:

```sh
cargo build --release -p reality-client
# -> target/release/reality-client  (~7 МБ)
```

На Windows — [`docs/WINDOWS.md`](docs/WINDOWS.md) или
`powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1`.

## Запуск

```sh
reality-client --server 'vless://UUID@host:443?encryption=none&security=reality&sni=site.example&pbk=KEY&sid=SHORTID&type=tcp&flow=xtls-rprx-vision' \
               --listen 127.0.0.1:1080
```

- `--server` — ссылка целиком, в кавычках (в ней есть `&`). ⚠️ Аргументы
  командной строки видны всем пользователям машины (список процессов), а в
  ссылке — ваш UUID. Надёжнее `--server-file файл` (ссылка в первой
  строке файла) или переменная окружения `REALITY_SERVER`.
- `--listen` — адрес локального прокси, по умолчанию `127.0.0.1:1080`.
  На этом порту и SOCKS5, и HTTP-прокси (вид определяется по первому байту).
- `--auth логин:пароль` — требовать логин и пароль на SOCKS5. Слушать не
  только на `127.0.0.1` без пароля клиент отказывается. То же без
  командной строки — `--auth-file файл` или `REALITY_SOCKS_AUTH`.
- `--allow-ip адреса` — кому из сети можно пользоваться прокси (адреса
  или подсети через запятую: `192.168.1.23,192.168.1.40`). Этот компьютер
  разрешён всегда. После 5 неверных паролей подряд адрес блокируется на
  минуту (дальше — вдвое дольше, до часа).
- `--allow-insecure` — разрешить ссылку с `security=none`. Без этого ключа
  клиент такую ссылку не запустит: UUID и весь трафик пошли бы открытым
  текстом.
- `--max-conns N` — сколько соединений обслуживать одновременно
  (по умолчанию 512); лишние сразу закрываются.
- `--ca файл.pem` — свои корневые сертификаты для `security=tls`
  (сервер с самоподписанным сертификатом).
- `--sniff` — если приложение присылает IP, а не имя, узнать имя по
  первым байтам (TLS SNI, HTTP Host) и отдать серверу имя.
- `--system-proxy` (Windows) — на время работы включить системный
  прокси: браузеры и большинство программ пойдут через клиент без
  настройки. При выходе (Ctrl+C, закрытие окна) прежние настройки
  возвращаются; если клиент был убит жёстко — `--system-proxy-off`.
- `--no-xudp` — UDP без XUDP (отдельный поток на каждое назначение) —
  для серверов, не знающих XUDP.
- Журнал — в stderr, уровень `info` по умолчанию. Адреса посещаемых
  сайтов на этом уровне не пишутся (только при `RUST_LOG=debug`).

Проверка, что всё работает:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

В браузере — указать SOCKS5-прокси `127.0.0.1:1080` (в Firefox —
«Параметры соединения», вместе с «DNS через SOCKS v5»).

### Файл настроек

Для нескольких входов и выходов вместо ключей — файл TOML
([`examples/client.toml`](examples/client.toml)):

```sh
reality-client --config client.toml --check   # только проверить
reality-client --config client.toml
```

```toml
[[inbounds]]
type = "mixed"             # SOCKS5 и HTTP на одном порту
listen = "127.0.0.1:1080"
sniff = true               # домен по SNI/Host, если приложение прислало IP

[[outbounds]]
tag = "proxy"
type = "vless"
link_file = "server.txt"   # ссылка — в отдельном файле

[[outbounds]]
tag = "direct"             # напрямую, без сервера
type = "direct"

[[outbounds]]
tag = "block"
type = "block"

[[route.rules]]
geosite = ["category-ads-all"]   # реклама
outbound = "block"

[[route.rules]]
ip_is_private = true             # локальная сеть
outbound = "direct"

[[route.rules]]
domain_suffix = ["ru", "su"]
geoip = ["ru"]                   # российский домен ИЛИ российский адрес
outbound = "direct"

[route]
final = "proxy"            # куда идёт всё, что не попало под правила
```

Правила проверяются по порядку, срабатывает первое подошедшее. В одном
правиле условия группы «куда» (`domain`, `domain_suffix`,
`domain_keyword`, `domain_regex`, `geosite`, `ip_cidr`, `ip_is_private`,
`geoip`) соединяются через «или», а с `port`, `network`, `inbound` —
через «и» (как у sing-box). Правило по IP срабатывает, только если
приложение прислало IP; правило по домену — если прислало имя или имя
найдено sniffing'ом. Базы `geosite.dat` (`dlc.dat` из
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/releases))
и `geoip.dat` ([v2fly/geoip](https://github.com/v2fly/geoip/releases))
ищутся рядом с файлом настроек; из них читаются только нужные категории
(обе базы целиком — ~0,2 с).

Ключи командной строки — сокращение для одного входа `mixed` и одного
выхода `proxy`. Опечатка в имени поля — ошибка при запуске. Выход
`direct` не пускает клиентов из сети к службам этого компьютера
(`127.0.0.1`, `localhost`); выход `block` отвечает SOCKS5-кодом 0x02 или
HTTP 403. Полный пример — [`examples/client.toml`](examples/client.toml).

### Группы серверов и подписки

Несколько серверов — группа; группа сама выход, её tag пишут в правила и
`route.final`:

```toml
[[outbounds]]
tag = "auto"
type = "urltest"                 # самый быстрый; "fallback" — первый работающий;
outbounds = ["proxy"]            # "selector" — выбранный (default или первый)
subscriptions = ["my-panel"]     # + серверы с панели
# url = "https://www.gstatic.com/generate_204"   interval = 180   tolerance = 50

[[subscriptions]]
tag = "my-panel"
url_file = "subscription.txt"    # адрес подписки — секрет, как UUID
# update_interval = 43200   detour = "direct"   include = "Germany|Finland"
```

- Проверка — HTTP-запрос через каждого участника раз в `interval` с
  разбросом ±20 %; `urltest` не переключается, пока текущий хуже лучшего
  не больше чем на `tolerance` мс. Не открылось соединение — пробуется
  следующий участник (до трёх), неудачник считается упавшим до проверки.
  Переключение не рвёт открытых соединений.
- Подписка: base64-список ссылок (3x-ui, Marzban, Remnawave), обычный
  текст, JSON sing-box, YAML Clash — берутся только VLESS, остальное в
  журнале счётчиком. Только https с проверкой сертификата (`ca_file` —
  для самоподписанного сертификата панели); серверы с `security=none`
  пропускаются без `allow_insecure`. Загрузка — через группу, а пока
  список пуст — через `direct` (или через `detour`). Последний список —
  в `<tag>.subscription` рядом с настройками (права 600): клиент стартует
  без панели. В журнал попадает только имя сервера панели, не адрес
  подписки. С TUN подписка без сохранённого списка загружается до
  включения маршрутов.

### Против DPI: fragment и noises

```toml
[[outbounds]]
tag = "direct"
type = "direct"
fragment = { packets = "tlshello", length = "100-200", interval = "10-20" }
noises = [{ type = "rand", packet = "10-20", delay = "10-16" }]
```

`fragment` (у `vless` — к серверу, у `direct` — к сайтам) режет первый
TLS-рекорд с ClientHello на рекорды по `length` байт; с `interval > 0` —
ещё и отдельными TCP-сегментами с паузами (мс). `packets = "1-3"` — вместо
этого режутся 1–3-я записи в соединение. Помогает против DPI, который
ищет имя сайта в первом пакете и не собирает поток; против DPI, который
собирает, — нет, а необычный ClientHello сам по себе заметен. `noises` —
пакеты-пустышки (`rand`, `str`, `base64`, `hex`) перед первой
UDP-датаграммой к адресу; к порту 53 не шлются. Оба выключены по
умолчанию; параметры — как у `freedom` в Xray.

### TUN — весь трафик компьютера

Вход `type = "tun"` создаёт виртуальный сетевой интерфейс, и через клиент
идёт трафик всех программ, а не только настроенных на прокси:

```toml
[[inbounds]]
type = "tun"
sniff = true
# strict_route = true            # kill switch (Linux)
# route_exclude = ["192.168.0.0/16"]
```

- Нужны права администратора (Windows) или root (Linux). На Windows
  рядом с `reality-client.exe` должен лежать `wintun.dll` (из
  [wintun.net](https://www.wintun.net/), архитектура amd64).
- `auto_route` (по умолчанию включён) направляет в TUN весь трафик;
  соединения самого клиента (к серверу, `direct`, DNS) идут мимо TUN:
  на Linux они помечаются (`SO_MARK`), на Windows привязаны к физическому
  интерфейсу. Петли нет, а правила `direct` работают как обычно.
- DNS-запросы на порт 53 любого адреса отвечает раздел `[dns]`
  (`dns_hijack`, по умолчанию включён; без `[dns]` — ошибка настроек).
  Fake-IP с TUN работает полностью: программа получает адрес
  198.18.x.x, а соединяется клиент уже с именем через сервер.
- Выход из клиента (Ctrl+C, закрытие окна) возвращает маршруты. Если
  клиент убит, интерфейс исчезает вместе со своими маршрутами — сеть
  снова работает напрямую. С `strict_route = true` (Linux) — наоборот:
  сеть остаётся закрытой (kill switch), пока клиент не запущен снова
  или не выполнено `reality-client --tun-cleanup`.
- Системный DNS-сервер (`address = "local"`) вместе с TUN — ошибка
  настроек: системный DNS сам идёт через TUN (петля).
- Ограничения: IPv6 включается, только если он есть в системе; ICMP
  (ping) через TUN не проходит; на Windows `route_exclude` — только
  IPv4, kill switch нет, а при исключённой локальной сети Windows может
  спрашивать DNS роутера напрямую.

### DNS

Раздел `[dns]` — свой DNS вместо системного (пример — в
[`examples/client.toml`](examples/client.toml)):

```toml
[[inbounds]]               # DNS-сервер для системы и программ
type = "dns"
listen = "127.0.0.1:53"

[dns]
final = "remote"

[[dns.servers]]
tag = "remote"
address = "https://1.1.1.1/dns-query"   # DoH
detour = "proxy"                        # через сервер VLESS

[[dns.servers]]
tag = "local"
address = "https://common.dot.dns.yandex.net/dns-query"
detour = "direct"

[[dns.rules]]
geosite = ["category-ru"]
server = "local"
```

- Адреса серверов: `1.1.1.1` или `udp://…` (UDP), `tcp://…`,
  `tls://…` (DNS over TLS, порт 853), `https://…/dns-query` (DNS over
  HTTPS), `local` (системный резолвер), `fakeip`. Для `udp://` и `tcp://`
  нужен IP: имя самого DNS-сервера разрешить нечем. Сертификаты DoT/DoH
  проверяются (свои корни — `ca_file`).
- `detour` — через какой выход ходить к серверу; по умолчанию
  `route.final`, то есть обычно через сервер VLESS: так ни провайдер, ни
  соседи по Wi-Fi не видят, какие имена вы спрашиваете.
- Кто пользуется модулем: вход `type = "dns"` (укажите `127.0.0.1` как
  DNS в настройках сети — тогда через него пойдут запросы всех программ);
  выход `type = "dns"` с правилом `port = [53]` (DNS-запросы программ,
  идущие через прокси); выход `direct` (разрешает имена им, а не
  системой); `route.domain_strategy = "ip_if_non_match"` (правила по IP
  для имён).
- Кеш: по TTL ответа (не дольше часа; отрицательные — не дольше минуты),
  до 4096 ответов (`cache_size`).
- Fake-IP (`address = "fakeip"`): программа сразу получает адрес из
  `198.18.0.0/15` (и `fc00::/18`), а соединяясь с ним через прокси,
  получает настоящий сайт — имя разрешает сервер. Имеет смысл только
  вместе с TUN или для программ, которые ходят через этот прокси: без них
  программа пойдёт на адрес 198.18.x.x напрямую и никуда не попадёт.
  Таблицу можно сохранять между перезапусками (`[dns.fakeip] cache_file`).
- DNS-вход, открытый в сеть, требует `allow_ip`: иначе это «открытый
  резолвер», которым пользуются для DDoS-атак.

### Какие параметры ссылки понимает

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
| `alpn` | список ALPN через запятую; по умолчанию `h2,http/1.1` (как Chrome), для ws и httpupgrade — `http/1.1`, для gRPC — всегда `h2`; для xhttp `alpn=http/1.1` включает HTTP/1.1, `h3` — ошибка |
| `encryption` | только `none` |
| `headerType` | только `none` |
| `fp` | `chrome` (по умолчанию), `firefox`, `safari`, `ios` (= Safari 26), `edge`, `android` (= Chrome), `random` (один браузер на запуск), `randomized` (на каждый выход); прочее (`360`, `qq`) — Chrome и предупреждение |

## Безопасность

Что клиент гарантирует и от чего защищён (подробности и история —
`PLAN.md`, раздел «Аудит безопасности»):

- **UUID не уходит никому, кроме настоящего REALITY-сервера.** Данные
  VLESS отправляются только после полного рукопожатия с проверкой
  REALITY (HMAC сертификата, ML-DSA-65 при `pqv=`). Отката на обычную
  проверку сертификата нет; вырожденный `pbk=` отвергается.
- **Подмена сервера настоящим сайтом не выдаёт клиента:** как и Xray,
  клиент доводит рукопожатие с сайтом до конца, открывает главную
  страницу как Chrome и только потом сообщает об ошибке — UUID при этом
  не отправляется.
- **Нет DNS-утечек:** имена сайтов разрешает сервер; локально
  разрешается только имя самого VLESS-сервера.
- **Локальный прокси не держится за «мёртвые» соединения:** 10 с на
  приветствие SOCKS5/HTTP, закрытие по простою (300 с; 30 с, если одна сторона
  уже закрылась), предел одновременных соединений.
- **Сервер не может «уронить» клиента** слишком длинным сообщением gRPC,
  WebSocket или xhttp: у всех разборщиков есть пределы.
- **UDP-ассоциацией пользуется только её владелец** (IP и порт), а не
  любой процесс на той же машине.

### Если злоумышленник в той же Wi-Fi сети

Что он **не** может (при `security=reality` или `tls`):

- прочитать или подменить трафик до сервера и узнать UUID — даже если
  перехватит соединение (подмена DNS, поддельная точка доступа): без
  ключа сервера он не пройдёт проверку REALITY, без доверенного
  сертификата — проверку TLS; рукопожатие обрывается до отправки UUID;
- подключиться к прокси: по умолчанию он слушает только `127.0.0.1`.

Что он **может**, и как это закрыто:

| Что | Защита |
|---|---|
| Ссылка с `security=none`: UUID и трафик видны всем в сети, сервером может пользоваться кто угодно | клиент не запускает такую ссылку без `--allow-insecure` |
| Прокси открыт в сеть (`--listen 0.0.0.0`): подбор пароля | пароль не короче 12 символов, блокировка адреса после 5 ошибок, `--allow-ip` |
| Прокси открыт в сеть: SOCKS5 и HTTP-прокси **не шифруются** — пароль, адреса сайтов и данные между телефоном и компьютером видны в общей Wi-Fi | так устроены сами эти протоколы, клиент это исправить не может; клиент предупреждает при запуске. Открывайте прокси в сеть только дома, для своих устройств, с `--allow-ip` |
| Прокси открыт в сеть, и есть правило с выходом `direct`: устройство из сети ходит «от имени» этого компьютера — в том числе в сети, куда оно само не достаёт (рабочий VPN, Docker, WSL) | к службам самого компьютера (`127.0.0.1`, `localhost`) `direct` клиентов из сети не пускает; остальное — пускайте в прокси только свои устройства (пароль, `--allow-ip`) и не направляйте в `direct` подсети, которые им не нужны |
| Видит сам факт соединения с IP сервера, объём и время трафика | не скрывается никаким VPN; REALITY лишь маскирует его под обращение к обычному сайту |
| DNS-запросы в локальной сети видны и подменяемы (обычный DNS не шифруется) | `[dns]` с DoH/DoT через сервер и вход `type = "dns"` как системный DNS; ответы UDP проверяются (номер, вопрос, адрес сервера) |
| Трафик программ, которым **не** указан прокси, идёт мимо него | это прокси, а не системный VPN: настраивайте программы или включите `--system-proxy` (Windows; его слушаются не все программы); в браузере с SOCKS5 включите «DNS через SOCKS v5», иначе имена сайтов уходят в DNS локальной сети (с HTTP-прокси имена и так уходят прокси) |

## Проверка проекта

Одной командой — всё, что доступно на этой машине:

```sh
scripts/ci.sh          # fmt, clippy (без предупреждений), тесты, release-сборка,
                       # + интероп и smoke с Go-стендом и с Xray-core, сверка отпечатка
scripts/ci.sh --quick  # только fmt, clippy, тесты
```

Отдельно:

| Скрипт | Что проверяет |
|---|---|
| `cargo test --workspace` | 187 тестов (131 unit + 56 интеграционных), всё на loopback; с `GEO_DIR=…` и `--ignored` — ещё проверка на настоящих базах geosite/geoip |
| `scripts/interop_xray.sh` | 20 тестов против **настоящего Xray-core**: REALITY (в т.ч. с сайтом без ML-KEM), Vision (padding и переход на прямую передачу), ML-DSA-65 (и отказ при чужом ключе), WebSocket и httpupgrade без TLS и с TLS + `--ca`, gRPC поверх REALITY, xhttp во всех режимах (HTTP/1.1, h2, поверх REALITY; отказы 404/400 с понятной ошибкой), UDP и XUDP (Full Cone), отказ Vision-аккаунта клиенту без flow, Mux.Cool (20 соединений — 3 потока), общие HTTP/2-соединения gRPC и xhttp (`xmux`), раздробленный ClientHello (`fragment`), отпечатки `fp=firefox/safari/…` |
| `scripts/smoke_xray.sh` | собранный бинарник как у пользователя против Xray-core: SOCKS5 с паролем → REALITY → Vision → VLESS, 1 МиБ внутреннего TLS туда-обратно с переходом на прямую передачу, 20 UDP-датаграмм через XUDP; файл настроек: `--check`, опечатки, вход `mixed` (SOCKS5 и HTTP CONNECT), правило `block`, DNS-вход с запросом через Xray |
| `scripts/tun_netns.sh` | TUN с `auto_route` в изолированном сетевом пространстве (root) против Xray-core: TCP (32 МиБ туда-обратно), `direct` без петли, `route_exclude`, UDP/XUDP, перехват DNS к 8.8.8.8, fake-IP, возврат маршрутов по Ctrl+C, сеть после `kill -9`, kill switch `strict_route` и `--tun-cleanup` |
| `scripts/cross_windows.sh` | `.exe` под Windows (mingw-w64) + все тесты и smoke против Xray-core под Wine, `--system-proxy`: запись в реестр и возврат по Ctrl+C |
| `scripts/interop_go_reality.sh` | 4 теста против REALITY-сервера на Go-библиотеке `XTLS/REALITY` (нужен Go ≥ 1.27) |
| `scripts/smoke_e2e.sh` | бинарник против Go-стенда; несовместимая ссылка отклоняется при старте |
| `scripts/check_chrome_fingerprint.sh` | не устарел ли эталон Chrome в utls: cipher suites, набор расширений, `signature_algorithms` (стоит запускать раз в месяц-два) |
| `cargo run -p fpcheck -- --server 'vless://...'` | JA3/JA4 реального ClientHello этого клиента |

Xray-core для тестов: `scripts/fetch_xray.sh` (скачать релиз) или
`scripts/build_xray_from_source.sh` (собрать из исходников по git — для
сред без доступа к релизам и `proxy.golang.org`). В такой же среде
Go-стенд готовит `scripts/interop_sandbox_bootstrap.sh`.

## Устройство

```
bin/client/            reality-client: CLI (ключи или --config), sysproxy.rs
core/src/
  app/                 приложение: входы -> маршрутизатор -> выходы;
                       config.rs (TOML), proxy_in.rs + http_in.rs (входы
                       socks/http/mixed), sniff.rs, router.rs + rules.rs +
                       geo.rs (правила, geosite/geoip), outbound.rs
                       (direct, block, dns), vless_out.rs, access.rs,
                       dns/ (upstream.rs: UDP/TCP/DoT/DoH, cache.rs,
                       fakeip.rs), dns_in.rs (вход DNS), tun/ (вход TUN
                       на ipstack + tun-rs, route.rs: auto_route)
  net_protect.rs       метка исходящих сокетов (мимо TUN)
  vless/               разбор vless:// (uri.rs), протокол VLESS (protocol.rs),
                       XTLS Vision (vision.rs), UDP-пакеты (udp.rs), XUDP (xudp.rs)
  transport/           tcp_tls.rs (TCP, TLS, REALITY), raw.rs (сокет с выдачей
                       по одному TLS-рекорду для Vision), ws.rs, grpc.rs,
                       httpupgrade.rs, xhttp.rs, browser_headers.rs (заголовки Chrome)
  reality/             REALITY: ключи и SessionId (auth.rs), хук в ClientHello
                       (hook.rs), проверка сертификата: HMAC и ML-DSA-65 (verifier.rs)
  fingerprint/         ClientHello как у Chrome (chrome_profile.rs), разбор, JA3/JA4
  socks5/              протокол SOCKS5: приветствие, логин/пароль, UDP-заголовки
  relay.rs             двусторонний релей, один буфер на направление
core/tests/            интеграционные тесты (loopback) + interop_xray.rs, interop_go_reality.rs
vendor/rustls-reality-patch/
                       rustls 0.23.45 с патчем: REALITY, GREASE, профиль ClientHello
                       Chrome (подключён через [patch.crates-io])
interop/go-reality-server/
                       тестовый REALITY-сервер на библиотеке XTLS/REALITY
bin/fpcheck/           снятие JA3/JA4
bench/                 бенчмарки (criterion) и замер памяти (memwatch, Linux)
scripts/               ci, интероп, smoke, сборка Xray, сверка отпечатка,
                       сборка под Windows, инструкции для Этапов 2 и 8
docs/                  WINDOWS.md, чек-лист крипто-ревью (Этап 5)
examples/client.toml   пример файла настроек
PLAN.md                план по этапам, история решений, открытые риски
```

## Сравнение с Xray-core

`scripts/stage8_compare_with_xray.sh` — автоматическое сравнение с
настоящим Xray-core на одинаковой нагрузке (оба клиента ходят на один
тестовый REALITY-сервер, нагрузку даёт один и тот же код). Три прогона,
8 соединений x 16 МиБ, loopback, 2 ядра, Xray-core 26.9.9:

| показатель | reality-core | Xray-core 26.9.9 |
|---|---|---|
| память на холостом ходу | **6,3 МиБ** | 30,4 МиБ |
| пик памяти под нагрузкой | **8,9 МиБ** | 35,3 МиБ |
| до первого байта данных | 25,4 мс | 35,8 мс (ничья — разброс сопоставим) |
| пропускная способность | 625 МиБ/с | 572 МиБ/с (ничья — разброс сопоставим) |

Выигрыш по памяти — во многом цена универсальности: Xray-core несёт
десятки протоколов и роутинг, этот клиент умеет одно.

⚠️ Время до **первого байта данных**, а не до ответа на SOCKS5 CONNECT:
Xray отвечает на CONNECT авансом, не дожидаясь соединения с сервером
(отвечает «успех», даже если сервера нет), поэтому его ответ на CONNECT
с нашим сравнивать нельзя. Подробности — `PLAN.md`, Этап 8.

## Производительность и память

Бенчмарки и выбор аллокатора — `PLAN.md`, Этапы 0 и 7. Кратко: один буфер
(17 КиБ — чтобы вмещался целый TLS-рекорд, это важно для Vision) на
направление соединения, без глобального пула; системный аллокатор по
умолчанию (`--features mimalloc` — опционально, в замерах давал больший
idle RSS).

```sh
cargo bench -p bench
cargo run -p bench --bin memwatch -- --pid <PID> --duration-secs 30 --csv rss.csv   # Linux
```

## Что осталось открытым

- Mux.Cool — только без Vision (Xray-сервер рвёт Vision-потоки с TCP
  внутри); полузакрытие соединения через Mux.Cool не передаётся (как у
  Xray). UDP идёт через XUDP отдельным потоком.
- `kcp` (mKCP — свой надёжный протокол поверх UDP, ~2,5 тыс. строк в Xray)
  не сделан: редкий и заметный для DPI транспорт.
- xhttp: нет HTTP/3 и `downloadSettings`; через HTTP/1.1 соединения не
  переиспользуются между сессиями (только h2 — `xmux`).
- Обычный TLS (`security=tls`) отличается от Chrome двумя вещами — осознанно:
  не заявляются 6 legacy cipher suite'ов (сервер с откатом на TLS 1.2 мог бы
  выбрать такой) и ALPS (если CDN на BoringSSL его согласует, клиент обязан
  ответить, а rustls этого не умеет). В REALITY совпадение полное.
- Под настоящей Windows не запускалось — только под Wine.
- Стороннее крипто-ревью (Этап 5) и решение о публикации (Этап 8) —
  за людьми: `docs/stage5-crypto-review-and-interop.md`.
