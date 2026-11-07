# Карта репозитория

**Русский** | [English](REPOSITORY.en.md)

Где искать код, проверки и материалы для встраивания. Архитектура описана в
[ARCHITECTURE.md](ARCHITECTURE.md), полный каталог руководств — в
[README.md](README.md).

## Основные компоненты

| Путь | Назначение |
|---|---|
| `core/` | Rust-библиотека `reality-core`: входы, маршрутизация, DNS, TUN, прокси-выходы VLESS/Trojan/Hysteria 2, транспорты и REALITY |
| `bin/client/` | `reality-client`: CLI, запуск ядра, службы Windows и системный прокси |
| `bin/fpcheck/` | инструмент для захвата и анализа JA3/JA4 ClientHello |
| `ffi/` | `reality-ffi`: C ABI, `reality.h`, примеры и эталон ABI для интеграции приложений |
| `bench/` | Criterion-замеры и утилиты `memwatch`/`warmup_probe` |
| `fuzz/` | fuzz targets для разборщиков, сетевых заголовков и подписок |
| `interop/go-reality-server/` | Go-сервер REALITY для межоперационных проверок |
| `vendor/rustls-reality-patch/` | патченная копия rustls; область изменений и перенос патчей описаны в [RUSTLS_PATCH.md](RUSTLS_PATCH.md) |
| `vendor/smoltcp-window-patch.md`, `vendor/smoltcp-window-patch/` | пояснения проекта к патчу окна smoltcp; исходники и лицензии upstream сохраняются отдельно |

## Внутри `core/src/`

| Каталог/файл | Назначение |
|---|---|
| `app/` | жизненный цикл ядра, конфигурация, входы SOCKS5/HTTP/mixed/DNS/TUN, правила и маршрутизатор, DNS, группы, подписки и локальное API |
| `app/config/` | модель конфигурации и разбор собственных файлов, ссылок и поддерживаемых подмножеств форматов sing-box/Xray |
| `app/access.rs` | списки разрешённых IP/подсетей и временная блокировка после ошибок авторизации |
| `app/dns_in.rs`, `app/dns/` | DNS-вход UDP/TCP, upstream-серверы, кеш и fake-IP |
| `app/rules.rs`, `app/ruleset.rs`, `app/geo.rs` | предикаты маршрутизации, локальные наборы правил и geosite/geoip-базы |
| `app/sniff.rs`, `app/sniff_quic.rs` | определение домена из поддерживаемых TCP-протоколов и пакетов QUIC Initial |
| `app/group.rs`, `app/subscription.rs`, `app/http_client.rs` | группы выходов, обновление подписок и HTTP-запросы для подписок/проверки узлов |
| `app/stats.rs`, `app/events.rs` | учёт соединений и трафика, шина событий для API |
| `app/api.rs`, `app/clash.rs` | локальный API управления и наблюдения; отдельные ответы, совместимые с Clash API |
| `app/socks_out.rs`, `app/http_connect_out.rs` | TCP-выходы SOCKS5 и HTTP CONNECT, включая `detour`-цепочки |
| `app/vless_out.rs`, `app/trojan_out.rs`, `app/outbound.rs` | создание прокси-выходов и общие интерфейсы TCP/UDP |
| `app/tun/` | TUN-потоки, маршруты, UDP и платформенная реализация WFP |
| `connection_owner.rs` | доверенные метаданные владельца соединения от приложения-хоста |
| `vless/`, `trojan.rs` | форматы ссылок и протоколов VLESS/Trojan, Vision, UDP, XUDP и Mux.Cool |
| `transport/` | независимая `TransportConfig`; TCP/TLS/REALITY, WebSocket, gRPC, HTTPUpgrade, XHTTP, QUIC/DoQ/HTTP/3, пулы HTTP/2, фрагментация и имитация браузера |
| `reality/`, `fingerprint/` | рукопожатие и проверка REALITY; профили ClientHello, захват, JA3/JA4 |
| `socks5/`, `relay.rs`, `http1.rs` | протокольный framing, двусторонний relay и разбор ответов HTTP/1.1 |
| `net_protect.rs`, `hostname.rs`, `fsutil.rs`, `redact.rs` | обход TUN для собственных сокетов и общие сетевые/файловые помощники с очисткой секретов |

## Проверки и интеграция

| Путь | Назначение |
|---|---|
| `core/tests/` | интеграционные тесты ядра, включая interop с Xray-core и Go REALITY-сервером |
| `scripts/ci.sh`, `.github/workflows/ci.yml` | локальные и GitHub CI-проверки; workflow включает Linux, настоящую Windows, MSRV, покрытие, аудит зависимостей и advisory mobile cross-build |
| `scripts/package_ffi_sdk.py`, `scripts/ffi_sdk_metadata.py`, `scripts/check_ffi_sdk.py` | упаковка SDK-архивов, CMake/pkg-config metadata и проверка содержимого/manifest |
| `scripts/sdk-consumer/`, `scripts/test_ffi_sdk_consumer.py` | независимые C/C++ consumers из распакованного SDK; выполняются на поддерживаемых desktop runners, Android/iOS только компонуются |
| `.github/workflows/release.yml` | предварительная сборка по ручному запуску и публикация при отправке version tag |
| `.github/workflows/fuzz.yml`, `benchmark-xray-rust.yml` | fuzz-прогоны и сравнительные benchmark workflow |
| `scripts/interop_*.sh`, `smoke_*.sh`, `tun_netns.sh` | интероп, CLI smoke и TUN-проверки; точное покрытие перечислено в [TESTING.md](TESTING.md) |
| `examples/` | примеры конфигураций sing-box/Xray и unit-файл systemd |

## Публичные материалы

- `docs/` — технические руководства на русском и английском, собранные в
  [каталоге документации](README.md).
- `README.md`, `README.en.md`, `CHANGELOG.md` — обзор проекта и история
  опубликованных и будущих изменений.
- `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `CODE_OF_CONDUCT.md` — правила
  участия, сообщения об уязвимостях, поддержка и нормы сообщества.
- `.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md` — шаблоны
  обращений и pull request.
- `PLAN.md` и `PLAN.en.md` — исторический журнал решений на русском и его
  английский перевод; они не являются источниками текущего состояния.
  Фактические возможности и ограничения описаны в `docs/FEATURES.md` и
  `docs/FEATURES.en.md`.
