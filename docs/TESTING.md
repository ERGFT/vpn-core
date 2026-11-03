# Проверка, сравнение и производительность

**Русский** | [English](TESTING.en.md)

Как проверяется проект, сравнение с Xray-core, замеры памяти и скорости.

## Проверка проекта

Одной командой — всё, что доступно на этой машине:

```sh
scripts/ci.sh          # fmt, SPDX-метки, clippy (без предупреждений), тесты, release-сборка,
                       # + интероп и smoke с Go-стендом и с Xray-core, сверка отпечатка
scripts/ci.sh --quick  # только fmt, SPDX-метки, ссылки в документации, clippy, тесты
```

Отдельно:

| Скрипт | Что проверяет |
|---|---|
| `cargo test --workspace` | все тесты (unit и интеграционные), всё на loopback; с `GEO_DIR=…` и `--ignored` — ещё проверка на настоящих базах geosite/geoip |
| `scripts/fetch_sing_box.sh` + `ci.sh` | разбор `.srs` против настоящего sing-box: наборы версий 1–3, собранные `sing-box rule-set compile` (3000+ доменов, IDN, суффиксы, IPv4/IPv6-диапазоны), и 5 настоящих наборов geosite/geoip — совпадение с `rule-set decompile` запись в запись |
| `scripts/interop_xray.sh` | 23 теста против **настоящего Xray-core**: REALITY (в т.ч. с сайтом без ML-KEM), Vision (padding и переход на прямую передачу), ML-DSA-65 (и отказ при чужом ключе), WebSocket и httpupgrade без TLS и с TLS + `--ca`, gRPC поверх REALITY, xhttp во всех режимах (HTTP/1.1, h2, HTTP/3, поверх REALITY; отказы 404/400 с понятной ошибкой), DNS over QUIC через VLESS, UDP и XUDP (Full Cone), отказ Vision-аккаунта клиенту без flow, Mux.Cool (20 соединений — 3 потока), общие HTTP/2-соединения gRPC и xhttp (`xmux`), раздробленный ClientHello (`fragment`), отпечатки `fp=firefox/safari/…` |
| `scripts/smoke_xray.sh` | собранный бинарник как у пользователя против Xray-core: SOCKS5 с паролем → REALITY → Vision → VLESS, 1 МиБ внутреннего TLS туда-обратно с переходом на прямую передачу, 20 UDP-датаграмм через XUDP; файл настроек: `--check`, опечатки, вход `mixed` (SOCKS5 и HTTP CONNECT), правило `block`, DNS-вход с запросом через Xray |
| `scripts/tun_netns.sh` | TUN с `auto_route` в изолированном сетевом пространстве (root) против Xray-core: TCP (32 МиБ туда-обратно), `direct` без петли, `route_exclude`, UDP/XUDP, sniffing QUIC на пакетах Chromium, перехват DNS к 8.8.8.8, fake-IP, возврат маршрутов по Ctrl+C, сеть после `kill -9`, kill switch `strict_route` и `--tun-cleanup` |
| `scripts/cross_windows.sh` | `.exe` под Windows (mingw-w64) + все тесты и smoke против Xray-core под Wine, `--system-proxy`: запись в реестр и возврат по Ctrl+C; служба: установка (копия настроек в ProgramData), запуск, штатная остановка и удаление; автозапуск при входе |
| `scripts/interop_go_reality.sh` | 4 теста против REALITY-сервера на Go-библиотеке `XTLS/REALITY` (нужен Go ≥ 1.27) |
| `scripts/smoke_e2e.sh` | бинарник против Go-стенда; несовместимая ссылка отклоняется при старте |
| `scripts/check_chrome_fingerprint.sh` | не устарел ли эталон Chrome в utls: cipher suites, набор расширений, `signature_algorithms` (стоит запускать раз в месяц-два) |
| `scripts/check_license_headers.sh` | у каждого своего исходника есть метка `SPDX-License-Identifier` |
| `scripts/check_doc_links.py` | у ссылок между документами есть файл и заголовок для `#якоря` (как на GitHub) |
| `scripts/third_party_licenses.sh` | `THIRD-PARTY-LICENSES.html` из `Cargo.lock` (cargo-about); ошибка, если у зависимости лицензия не из `about.toml` |
| `cargo run -p fpcheck -- --server 'vless://...'` | JA3/JA4 реального ClientHello этого клиента |

Unit-тесты `core/src/transport/tcp_tls.rs` используют виртуальные часы для
проверки чередования IPv4/IPv6, быстрого перехода ко второму семейству,
повторной попытки после отказа, лимита одновременных сокетов и общего срока
подключения — без зависимости от внешней сети и DNS.

Unit-тесты `core/src/transport/tcp_tls.rs` используют виртуальные часы для
проверки чередования IPv4/IPv6, быстрого перехода ко второму семейству,
повторной попытки после отказа и ограничения числа адресов — без зависимости
от внешней сети и DNS.

На GitHub то же самое делает сама платформа (`.github/workflows/ci.yml`) на
каждый push в `main` и каждый pull request: на Linux — весь `scripts/ci.sh`
(включая интероп с Go-сервером REALITY и Xray-core), TUN в netns и список
лицензий зависимостей; на
**настоящей Windows** — тесты, сборка `.exe` (его можно скачать со
страницы запуска, «Artifacts») и `scripts/windows_live_test.ps1`: служба,
права её папки и TUN с настоящим трафиком. Выпуск —
`git tag v0.1.0 && git push origin v0.1.0`: `.github/workflows/release.yml`
собирает бинарники для Windows и Linux с SHA-256, `LICENSE`,
`THIRD-PARTY-LICENSES.html` и SBOM (`reality-client.sbom.cdx.json`,
CycloneDX) в черновик релиза; происхождение бинарников подписано
(GitHub attestation) — проверка:
`gh attestation verify reality-client-linux-x86_64 --repo ERGFT/vpn-core`.

Каждый versioned tag `v*` собирается в обычный опубликованный релиз. К CLI
прикладываются SDK C ABI: Linux x86_64, Windows x86_64, macOS arm64,
Android arm64-v8a и iOS arm64. В каждом SDK есть готовая библиотека,
`reality.h`, минимальный пример на C и руководства по встраиванию/API.
Публикация запускается только после успешной сборки всех SDK-целей и
CLI-артефактов.

Xray-core для тестов: `scripts/fetch_xray.sh` (скачать релиз) или
`scripts/build_xray_from_source.sh` (собрать из исходников по git — для
сред без доступа к релизам и `proxy.golang.org`). В такой же среде
Go-стенд готовит `scripts/interop_sandbox_bootstrap.sh`.

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

## Сравнение с xray-rust

Для нового сравнения используйте отдельный сценарий, не старую таблицу выше:

```sh
scripts/fetch_xray.sh
scripts/stage6_compare_with_xray_rust.sh
```

Сценарий закрепляет `xray-rust` на теге `v0.8.0` (коммит
[`fcce4be`](https://github.com/aimalygin/xray-rust/tree/fcce4be2771c1fb3f11e9503741d39a4d8df314e))
и использует Xray-core `v26.9.9` как общий сервер VLESS + REALITY + Vision.
Оба клиента запускаются на одной машине с одинаковыми параметрами, Chrome
fingerprint, восемью одновременными потоками и внутренним TLS 1.3 echo.
Порядок клиентов чередуется между пятью прогонами. По каждому прогону
сохраняются JSON и CSV RSS/PSS; итоговый manifest фиксирует коммиты,
версии бинарников, SHA-256, ОС и модель CPU. Метрики: пропускная способность,
время до первых прикладных данных после TLS handshake, idle/peak RSS/PSS,
миллисекунды CPU на переданный GiB и восстановление прикладного запроса.

Настройки можно менять через `RUNS`, `CONNS`, `MIB`, `OUTDIR`. Результаты
появляются в `target/stage6-xray-rust/`; по умолчанию каждый из пяти прогонов
передаёт 8 × 64 МиБ в каждую сторону для каждого ядра. Затем общий сервер
останавливается на `OUTAGE_SECS` (по умолчанию 2 секунды) и запускается снова;
процесс клиента остаётся запущенным. `stage6_recovery_probe.py` повторяет SOCKS5
CONNECT и внутренний TLS 1.3 echo до первого успешного запроса. Результат от
TCP-готовности сервера до успешного echo записывается отдельно в
`*.recovery.json`; `RECOVERY_POLL_MS` задаёт интервал опроса, а
`RECOVERY_TIMEOUT_SECS` — предел ожидания. Сохраняйте параметры вместе с
сырыми JSON/CSV и не сводите вывод к одной лучшей попытке. Это loopback-сценарий
отказа и восстановления сервера, а не физического сетевого интерфейса: он не
моделирует WAN-потери, энергопотребление или обработку host-сигнала
`rc_network_changed`. Выводы появятся только после успешного полного прогона.

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
