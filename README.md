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
| Транспорты `type=ws` (`path=`, `host=`), `type=grpc` (`serviceName=`, режим «gun») | ✅ проверены против настоящего Xray-core |
| `flow=xtls-rprx-vision` (XTLS Vision) | ✅ padding, распознавание внутреннего TLS, прямая передача в обе стороны; проверено против Xray-core. Как и в Xray — только `type=tcp` с `tls`/`reality` |
| REALITY: X25519MLKEM768 (и откат на X25519 для сайтов без ML-KEM), ShortId, `minClientVer`/`maxClientVer`, HMAC-сертификат | ✅ |
| REALITY: ML-DSA-65 (`pqv=`) | ✅ |
| TLS-отпечаток как у Chrome 133 | ✅ REALITY — совпадает полностью, включая JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`; обычный TLS — без legacy cipher suite'ов и ALPS (см. ниже) |
| UDP (SOCKS5 UDP ASSOCIATE → VLESS UDP) | ✅ в том числе с Vision-аккаунтом |
| Логин/пароль на SOCKS5 (`--auth`) | ✅ |
| Mux, XUDP, `xhttp`/`httpupgrade`/`kcp`/`quic` | ❌ не поддерживаются — неизвестный `type=` даёт понятную ошибку |
| Linux | ✅ собирается и проверен |
| Windows | 🟡 код переносимый, инструкция и скрипт есть ([`docs/WINDOWS.md`](docs/WINDOWS.md)), но реально под Windows не собирался |

Стороннее крипто-ревью реализации REALITY не проводилось (подробности —
`PLAN.md`, Этап 5).

## Сборка

Нужен Rust (stable). На Linux:

```sh
cargo build --release -p reality-client
# -> target/release/reality-client  (~6,4 МБ)
```

На Windows — [`docs/WINDOWS.md`](docs/WINDOWS.md) или
`powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1`.

## Запуск

```sh
reality-client --server 'vless://UUID@host:443?encryption=none&security=reality&sni=site.example&pbk=KEY&sid=SHORTID&type=tcp&flow=xtls-rprx-vision' \
               --listen 127.0.0.1:1080
```

- `--server` — ссылка целиком, в кавычках (в ней есть `&`).
- `--listen` — адрес локального SOCKS5, по умолчанию `127.0.0.1:1080`.
- `--auth логин:пароль` — требовать логин и пароль на SOCKS5. Слушать не
  только на `127.0.0.1` без пароля клиент отказывается.
- `--ca файл.pem` — свои корневые сертификаты для `security=tls`
  (сервер с самоподписанным сертификатом).
- Журнал — в stderr, уровень `info` по умолчанию; подробнее —
  `RUST_LOG=debug`.

Проверка, что всё работает:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

В браузере — указать SOCKS5-прокси `127.0.0.1:1080` (в Firefox —
«Параметры соединения», вместе с «DNS через SOCKS v5»).

### Какие параметры ссылки понимает

| Параметр | Значение |
|---|---|
| `security` | `none`, `tls`, `reality`; другое — ошибка |
| `type` | `tcp`/`raw` (по умолчанию), `ws`, `grpc`; другое — ошибка |
| `sni` | имя сервера для TLS/REALITY (по умолчанию — host) |
| `pbk`, `sid` | публичный ключ и ShortId REALITY |
| `pqv` | ключ ML-DSA-65 сервера REALITY (необязательно) |
| `flow` | пусто или `xtls-rprx-vision` (`-udp443` тоже); прочее — ошибка |
| `path`, `host` | путь и заголовок Host для WebSocket |
| `serviceName` | имя gRPC-сервиса |
| `alpn` | список ALPN через запятую; по умолчанию `h2,http/1.1` (как Chrome), для ws — `http/1.1`, для gRPC — всегда `h2` |
| `encryption` | только `none` |
| `headerType` | только `none` |
| `fp` | читается; отпечаток всегда Chrome-подобный, другое значение — предупреждение в журнале |

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
| `cargo test --workspace` | 80 тестов (59 unit + 21 интеграционный), всё на loopback |
| `scripts/interop_xray.sh` | 11 тестов против **настоящего Xray-core**: REALITY (в т.ч. с сайтом без ML-KEM), Vision (padding и переход на прямую передачу), ML-DSA-65 (и отказ при чужом ключе), WebSocket без TLS и с TLS + `--ca`, gRPC поверх REALITY, UDP, отказ Vision-аккаунта клиенту без flow |
| `scripts/smoke_xray.sh` | собранный бинарник как у пользователя против Xray-core: SOCKS5 с паролем → REALITY → Vision → VLESS, 1 МиБ внутреннего TLS туда-обратно с переходом на прямую передачу, 20 UDP-датаграмм |
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
bin/client/            reality-client: CLI, SOCKS5 -> VLESS
core/src/
  vless/               разбор vless:// (uri.rs), протокол VLESS (protocol.rs),
                       XTLS Vision (vision.rs), UDP-пакеты (udp.rs)
  transport/           tcp_tls.rs (TCP, TLS, REALITY), raw.rs (сокет с выдачей
                       по одному TLS-рекорду для Vision), ws.rs, grpc.rs
  reality/             REALITY: ключи и SessionId (auth.rs), хук в ClientHello
                       (hook.rs), проверка сертификата: HMAC и ML-DSA-65 (verifier.rs)
  fingerprint/         ClientHello как у Chrome (chrome_profile.rs), разбор, JA3/JA4
  socks5/              локальный SOCKS5: CONNECT, UDP ASSOCIATE (udp.rs), логин/пароль
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

- Mux/XUDP и транспорты `xhttp`, `httpupgrade`, `kcp`, `quic` — не
  реализованы.
- Обычный TLS (`security=tls`) отличается от Chrome двумя вещами — осознанно:
  не заявляются 6 legacy cipher suite'ов (сервер с откатом на TLS 1.2 мог бы
  выбрать такой) и ALPS (если CDN на BoringSSL его согласует, клиент обязан
  ответить, а rustls этого не умеет). В REALITY совпадение полное.
- Под Windows не собиралось (нет доступа к Windows-цели Rust из среды
  разработки).
- Стороннее крипто-ревью (Этап 5) и решение о публикации (Этап 8) —
  за людьми: `docs/stage5-crypto-review-and-interop.md`.
