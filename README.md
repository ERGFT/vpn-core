# reality-core

Собственное ядро клиента **VLESS (+REALITY)** на Rust: консольная программа
`reality-client` принимает `vless://`-ссылку и поднимает локальный
**SOCKS5-прокси**. Трафик программ, которым указан этот прокси, уходит на
VLESS-сервер (Xray-core и совместимые).

Проект написан с нуля по этапам — история, решения и риски по каждому
этапу в [`PLAN.md`](PLAN.md). Это учебно-исследовательский проект, а не
замена зрелым клиентам: ниже честно перечислено, что работает и чего нет.

## Что умеет и чего нет

| Возможность | Статус |
|---|---|
| `security=none` / `tls` / `reality` | ✅ |
| Транспорт `type=tcp` | ✅ проверен против настоящего REALITY-сервера (библиотека `XTLS/REALITY`) |
| Транспорты `type=ws` (`path=`), `type=grpc` (`serviceName=`, режим «gun») | ✅ проверены против собственных тестовых серверов; против настоящего Xray-core — нет |
| REALITY: X25519MLKEM768, ShortId, `minClientVer`/`maxClientVer`, проверка HMAC-сертификата | ✅ |
| TLS-отпечаток: порядок cipher suites как у Chrome 133, GREASE | ✅ частично — набор расширений ещё не как у браузера |
| `flow=xtls-rprx-vision` (XTLS Vision) | ❌ не поддерживается — клиент сразу завершается с понятной ошибкой |
| `pqv=` (ML-DSA-65 у REALITY) | ❌ не поддерживается |
| UDP (SOCKS5 UDP ASSOCIATE), Mux | ❌ |
| Логин/пароль на SOCKS5 | ❌ — слушать только на `127.0.0.1` |
| Linux | ✅ собирается и проверен |
| Windows | 🟡 код переносимый, инструкция и скрипт есть ([`docs/WINDOWS.md`](docs/WINDOWS.md)), но реально под Windows не собирался |

**Важно:** XTLS Vision — самая распространённая серверная настройка для
REALITY. Если в ссылке `flow=xtls-rprx-vision`, этот клиент с таким
сервером работать не будет. Стороннее крипто-ревью реализации REALITY не
проводилось (подробности — `PLAN.md`, Этап 5).

## Сборка

Нужен Rust (stable). На Linux:

```sh
cargo build --release -p reality-client
# -> target/release/reality-client  (~6 МБ)
```

На Windows — [`docs/WINDOWS.md`](docs/WINDOWS.md) или
`powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1`.

## Запуск

```sh
reality-client --server 'vless://UUID@host:443?encryption=none&security=reality&sni=site.example&pbk=KEY&sid=SHORTID&type=tcp' \
               --listen 127.0.0.1:1080
```

- `--server` — ссылка целиком, в кавычках (в ней есть `&`).
- `--listen` — адрес локального SOCKS5, по умолчанию `127.0.0.1:1080`.
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
| `security` | `none`, `tls`, `reality` |
| `type` | `tcp` (по умолчанию), `ws`, `grpc` |
| `sni` | имя сервера для TLS/REALITY (по умолчанию — host) |
| `pbk`, `sid` | публичный ключ и ShortId REALITY |
| `path` | путь WebSocket |
| `serviceName` | имя gRPC-сервиса |
| `flow` | пусто — да; `xtls-rprx-vision` — явная ошибка «не поддерживается»; прочее — ошибка разбора |
| `encryption` | только `none` |
| `fp` | читается, но отпечаток всегда один (Chrome-подобный) |

## Проверка проекта

Одной командой — всё, что доступно на этой машине:

```sh
scripts/ci.sh          # fmt, clippy (без предупреждений), тесты, release-сборка,
                       # + интероп, smoke и сверка отпечатка, если есть Go/сеть
scripts/ci.sh --quick  # только fmt, clippy, тесты
```

Отдельно:

| Скрипт | Что проверяет |
|---|---|
| `cargo test --workspace` | 61 тест (44 unit + 17 интеграционных), всё на loopback |
| `scripts/interop_go_reality.sh` | 4 теста против настоящего REALITY-сервера на Go-библиотеке `XTLS/REALITY`: рукопожатие + данные, чужой ключ, чужой ShortId, `minClientVer`/`maxClientVer`. Нужен Go ≥ 1.27 |
| `scripts/smoke_e2e.sh` | собранный бинарник как у пользователя: SOCKS5 → REALITY → VLESS до Go-сервера и обратно, 64 КиБ без искажений; ссылка с Vision отклоняется при старте |
| `scripts/check_chrome_fingerprint.sh` | не устарел ли эталон отпечатка Chrome относительно utls (стоит запускать раз в месяц-два) |
| `cargo run -p fpcheck -- --server 'vless://...'` | JA3/JA4 реального ClientHello этого клиента |

В среде без доступа к `proxy.golang.org` Go-стенд готовит
`scripts/interop_sandbox_bootstrap.sh` (собирает Go 1.27 из исходников и
тянет зависимости через git).

## Устройство

```
bin/client/            reality-client: CLI, SOCKS5 -> VLESS
core/src/
  vless/               разбор vless:// (uri.rs), протокол VLESS (protocol.rs)
  transport/           tcp_tls.rs (TLS и REALITY), ws.rs, grpc.rs
  reality/             REALITY: ключи и SessionId (auth.rs), хук в ClientHello
                       (hook.rs), проверка сертификата сервера (verifier.rs)
  fingerprint/         разбор ClientHello, JA3/JA4, профиль Chrome
  socks5/              локальный SOCKS5 (CONNECT, без аутентификации)
  relay.rs             двусторонний релей, один буфер на соединение
core/tests/            интеграционные тесты (loopback) + interop_go_reality.rs
vendor/rustls-reality-patch/
                       rustls 0.23.45 с патчем для REALITY и GREASE
                       (подключён через [patch.crates-io])
interop/go-reality-server/
                       тестовый REALITY-сервер на библиотеке XTLS/REALITY
bin/fpcheck/           снятие JA3/JA4
bench/                 бенчмарки (criterion) и замер памяти (memwatch, Linux)
scripts/               ci, интероп, smoke, сверка отпечатка, сборка под Windows,
                       инструкции для Этапов 2 и 8
docs/                  WINDOWS.md, чек-лист крипто-ревью (Этап 5)
PLAN.md                план по этапам, история решений, открытые риски
```

## Сравнение с Xray-core

`scripts/stage8_compare_with_xray.sh` — автоматическое сравнение с
настоящим Xray-core на одинаковой нагрузке (оба клиента ходят на один
тестовый REALITY-сервер, нагрузку даёт один и тот же код). Три прогона,
8 соединений x 16 МиБ, loopback:

| показатель | reality-core | Xray-core 26.3.27 |
|---|---|---|
| память на холостом ходу | **5,9 МиБ** | 29,5 МиБ |
| пик памяти под нагрузкой | **8,7 МиБ** | 34,3 МиБ |
| до первого байта данных | 17,1 мс | 22,6 мс (ничья) |
| пропускная способность | 985 МиБ/с | 966 МиБ/с (ничья) |

Выигрыш по памяти — во многом цена универсальности: Xray-core несёт
десятки протоколов и роутинг, этот клиент умеет одно.

⚠️ Время до **первого байта данных**, а не до ответа на SOCKS5 CONNECT:
Xray отвечает на CONNECT авансом, не дожидаясь соединения с сервером
(отвечает «успех», даже если сервера нет), поэтому его ответ на CONNECT
с нашим сравнивать нельзя. Подробности — `PLAN.md`, Этап 8.

## Производительность и память

Бенчмарки и выбор аллокатора — `PLAN.md`, Этапы 0 и 7. Кратко: один буфер
на направление соединения, без глобального пула; системный аллокатор по
умолчанию (`--features mimalloc` — опционально, в замерах давал больший
idle RSS).

```sh
cargo bench -p bench
cargo run -p bench --bin memwatch -- --pid <PID> --duration-secs 30 --csv rss.csv   # Linux
```

## Что осталось открытым

- XTLS Vision и ML-DSA-65 — не реализованы (см. таблицу выше).
- Набор расширений ClientHello пока отличается от Chrome.
- Интероп WS/gRPC с настоящим Xray-core не проверялся.
- `cargo miri`/ASan (Этап 2), стороннее крипто-ревью (Этап 5), сравнение
  с Xray-core и публикация (Этап 8) — требуют ресурсов вне среды
  разработки; готовые инструкции: `scripts/stage2_miri_asan.sh`,
  `docs/stage5-crypto-review-and-interop.md`,
  `scripts/stage8_compare_with_xray.sh`.
