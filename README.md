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
| UDP (SOCKS5 UDP ASSOCIATE) через XUDP — как у клиента Xray: все назначения в одном потоке, Full Cone NAT | ✅ в том числе с Vision (другого способа UDP Vision-аккаунт у Xray не принимает); `--no-xudp` — поток на каждое назначение |
| Логин/пароль на SOCKS5 (`--auth`) | ✅ |
| Файл настроек (`--config`, TOML): несколько входов и выходов (`vless`, `direct`, `block`) | ✅ |
| Входы SOCKS5, HTTP-прокси (CONNECT и обычные запросы) и `mixed` — оба на одном порту | ✅ |
| Маршрутизация: домен (точно, суффикс, подстрока, regex), IP/подсеть, частные адреса, порт, сеть, вход, базы `geosite.dat`/`geoip.dat` (v2fly) | ✅ наборы правил sing-box (`.srs`) — нет |
| Sniffing: домен по TLS SNI и HTTP Host, когда приложение прислало IP | ✅ QUIC — нет |
| Системный прокси Windows (`--system-proxy`) | ✅ проверен под Wine |
| Mux.Cool для TCP, транспорт `kcp` | ❌ не поддерживаются (почему — ниже); `quic`/`h2` удалены из самого Xray-core — ошибка подсказывает `xhttp` |
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
| `fp` | читается; отпечаток всегда Chrome-подобный, другое значение — предупреждение в журнале |

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
| `cargo test --workspace` | 137 тестов (103 unit + 34 интеграционных), всё на loopback; с `GEO_DIR=…` и `--ignored` — ещё проверка на настоящих базах geosite/geoip |
| `scripts/interop_xray.sh` | 15 тестов против **настоящего Xray-core**: REALITY (в т.ч. с сайтом без ML-KEM), Vision (padding и переход на прямую передачу), ML-DSA-65 (и отказ при чужом ключе), WebSocket и httpupgrade без TLS и с TLS + `--ca`, gRPC поверх REALITY, xhttp во всех режимах (HTTP/1.1, h2, поверх REALITY; отказы 404/400 с понятной ошибкой), UDP и XUDP (Full Cone), отказ Vision-аккаунта клиенту без flow |
| `scripts/smoke_xray.sh` | собранный бинарник как у пользователя против Xray-core: SOCKS5 с паролем → REALITY → Vision → VLESS, 1 МиБ внутреннего TLS туда-обратно с переходом на прямую передачу, 20 UDP-датаграмм через XUDP; файл настроек: `--check`, опечатки, вход `mixed` (SOCKS5 и HTTP CONNECT), правило `block` |
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
                       (direct, block), vless_out.rs, access.rs
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

- Mux.Cool для TCP не сделан сознательно: Vision-аккаунт у Xray рвёт
  Mux-соединения с TCP внутри, а сам Xray для мультиплексирования теперь
  предлагает xhttp. UDP идёт через XUDP (тот же Mux.Cool, одна сессия).
- `kcp` (mKCP — свой надёжный протокол поверх UDP, ~2,5 тыс. строк в Xray)
  не сделан: редкий и заметный для DPI транспорт.
- xhttp: нет переиспользования соединений между сессиями (`xmux`) — каждая
  VLESS-сессия открывает своё; нет HTTP/3 и `downloadSettings`.
- Обычный TLS (`security=tls`) отличается от Chrome двумя вещами — осознанно:
  не заявляются 6 legacy cipher suite'ов (сервер с откатом на TLS 1.2 мог бы
  выбрать такой) и ALPS (если CDN на BoringSSL его согласует, клиент обязан
  ответить, а rustls этого не умеет). В REALITY совпадение полное.
- Под настоящей Windows не запускалось — только под Wine.
- Стороннее крипто-ревью (Этап 5) и решение о публикации (Этап 8) —
  за людьми: `docs/stage5-crypto-review-and-interop.md`.
