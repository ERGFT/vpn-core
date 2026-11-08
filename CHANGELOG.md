[Русский](#журнал-изменений) | [English](#changelog)

# Журнал изменений

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии —
[SemVer](https://semver.org/lang/ru/). Подробная история решений по
этапам — [PLAN.md](PLAN.md).

## [Не выпущено]

### Shadowsocks
- Добавлен классический Shadowsocks AEAD outbound для TCP и нативного UDP;
  поддерживаются `aes-128-gcm`, `aes-256-gcm` и
  `chacha20-ietf-poly1305`. Импортируются ссылки SIP002 и записи sing-box,
  Xray и Clash YAML. В отдельной ветке добавлены SIP022/2022 AES-128/256-GCM
  через TCP и нативный UDP с защитой от повторов; полный CI и Xray interop
  прошли на head `2c0d14e`, включение в main ожидает PR. SIP003 plugins,
  UDP-over-TCP и legacy stream ciphers не поддерживаются.

### Hysteria 2
- TCP/UDP runtime подключён к outbound factory, sing-box config и URI-подпискам; один outbound переиспользует аутентифицированное QUIC-соединение. Поддерживаемые поля sing-box преобразуются через URI-модель, неподдерживаемые опции отклоняются. Официальный сервер v2.13.0 подтвердил TCP/UDP echo, включая IPv4/IPv6 и UDP payload 4096 байт, в ограниченном loopback interop. `rc_network_changed` уведомляет выходы; Hysteria 2 сбрасывает общий QUIC-сеанс, а interop сценарий покрывает повторные TCP/UDP запросы после сигнала. Реальный переход между интерфейсами и production readiness не подтверждены; функция остаётся экспериментальной.
- Добавлен `ca_file` для пользовательского PEM-набора корневых сертификатов Hysteria 2 в основной конфигурации. Проверка сертификата остаётся включённой; подписка не может хранить локальный путь и пропускает такую запись как неподдерживаемую.

### SDK и C ABI
- Добавлены manifest архива с SHA-256 каждого файла и сведениями о сборке,
  переносимые CMake/pkg-config metadata и native link arguments для статической
  библиотеки.
- Добавлены независимые C/C++ проверки SDK из распакованного архива и контроль
  совместимости экспортируемого C ABI.
- Уточнены контракты callbacks и владения памятью; проверены ожидание завершения
  callbacks, адаптер C++ и валидация внешнего TUN-дескриптора.

Проверки SDK подтверждают запуск consumer-приложений на поддерживаемых CI
раннерах; Android/iOS проверяются сборкой и линковкой, а не запуском VPN на
устройстве.

## [0.1.0] - 2026-11-04

### Выходы
- Добавлен SOCKS5 outbound для TCP CONNECT (`network: "tcp"`) в формате sing-box; поддерживаются
  RFC 1929 и чтение пароля из `password_file`. Также добавлен HTTP CONNECT outbound (`type: "http"`):
  HTTP/1.1, Basic auth, пароль из `password_file`, опциональный TLS с обязательной проверкой сертификата.
  Оба выхода поддерживают только TCP; TLS для самого SOCKS5 proxy не поддерживается. Добавлен
  `detour` для SOCKS5/HTTP CONNECT: вложенные TCP-цепочки, проверка циклов и отказ без direct fallback.

- Экспериментально: route.rules.user_id и invert; доверенный resolver владельца
  нового TUN-потока через Rust/C ABI, fail-closed для неизвестного нужного UID.
  Сайты и приложения сохраняют first-match; Android JNI/адаптер требует интеграции.

### Встраивание и DNS
- `rc_validate`: предварительная проверка без запуска входов/TUN и без текста
  ошибки; `rc_is_alive`: неблокирующий sticky-статус терминальной ошибки задач.
- C ABI: `rc_last_error_code` и `rc_last_error_message` дают стабильную
  категорию и безопасное краткое описание терминальной ошибки без значений
  конфигурации, адресов и учётных данных.
- Добавлен `rc_network_changed`: host сообщает о смене сети; ядро сбрасывает
  DNS/server-address кеши и отменяет tracked-соединения, сохраняя слушатели и
  конфигурацию. Автоматического повтора прикладного трафика нет.
- Внешний TUN сохраняет резолвер ядра и проверку петли системного DNS.
  Имена транспорта разрешаются только явно выбранным `dns.bootstrap`
  (расширение vpn-core: прямой UDP-сервер с IP, без неявного отката).
- `dns.rules[].strategy`: фильтрация A/AAAA и порядок адресов для конкретного
  правила, включая fake-IP; прежняя общая стратегия остаётся по умолчанию.

### Транспорты
- XHTTP: `downloadSettings` открывает отдельный канал скачивания с независимым
  адресом, портом и настройками HTTP/защиты; неподдерживаемые поля отклоняются.

### Соединения
- TCP dialer чередует IPv4/IPv6 адреса: альтернативное семейство начинает
  подключение через 250 мс, одновременно работает не более двух попыток,
  общий предел — 10 с и 8 адресов.

### Производительность
- Добавлен повторяемый Linux-бенчмарк `vpn-core` против закреплённого `xray-rust v0.8.0`:
  общий Xray-core VLESS + REALITY + Vision сервер, внутренний TLS echo,
  чередование пяти прогонов, сохранение JSON/CSV метрик и параметров среды,
  а также замер восстановления после краткой остановки тестового сервера.
  Первые пять парных прогонов на `ubuntu-24.04` опубликованы в [документации
  методики](docs/TESTING.md): медианная пропускная способность составила
  24,280 против 23,967 МиБ/с, пиковый PSS — 11 405 против 14 641 КиБ;
  `xray-rust` быстрее восстановил запрос после перезапуска сервера
  (45,939 против 86,230 мс). Это только baseline одного loopback-сценария.

### Исправления
- Патченный `rustls` обновлён до 0.23.46 (RUSTSEC-2026-0348, RUSTSEC-2026-0349
  и ещё две); патч REALITY перенесён без изменения объёма — 13 файлов,
  +807/−93 строки.
- Зависимости: `ctutils` 0.4.7, `rustls-webpki` 0.103.16, `ruzstd` 0.9.1,
  `tokio` 1.54.1, `webpki-roots` 1.0.11 — закрыты RUSTSEC-2026-0344,
  RUSTSEC-2026-0381, RUSTSEC-2026-0382, RUSTSEC-2026-0385 и
  RUSTSEC-2026-0386.
- HTTP/1.1-транспорты (`httpupgrade`, xhttp): `path=`/`host=` из ссылки
  проверяются на управляющие символы — percent-encoded `%0d%0a` больше не
  может подменить запрос.
- VLESS: домен длиннее 255 байт режется по границе UTF-8, а не «оборачивает»
  длину по модулю 256 (иначе сдвигались порт и данные).
- API: ошибка `accept` (например, кончились дескрипторы) больше не
  останавливает всё ядро.
- Перечитывание настроек: смена пароля входа (в том числе через
  `auth_file`) теперь перезапускает вход, а не оставляет работать старый.
- Старт ядра: при ошибке после запуска части входов их задачи отменяются
  (важно для встраивания через C ABI).
- Длительности в настройках с переполнением отвергаются, а не роняют
  процесс.
- fake-IP: подсети шире `/8` отвергаются.
- Xray-формат TUN: перехват DNS по умолчанию выключен; включается
  `settings.dns_hijack: true`. В sing-box-формате добавлено расширение
  `dns_hijack`.
- Глобальное правило `sniff` не ставит sniffing DNS-входу.
- API на `0.0.0.0`: панель в сети больше не получает 421 при обращении по
  адресу интерфейса (домен по-прежнему отвергается).
- Подписка: не больше 4096 серверов.

Выпуск `v0.1.0` включает CLI и C ABI SDK для встраивания ядра.

### Артефакты
- CLI для Linux x86_64 и Windows x86_64.
- SDK ZIP для Linux x86_64, Windows x86_64, macOS arm64,
  Android arm64-v8a и iOS arm64; для каждого ZIP приложен SHA-256.
- Лицензии зависимостей и CycloneDX SBOM опубликованы как файлы релиза;
  GitHub build provenance опубликовано как GitHub-hosted attestation, а не как
  скачиваемый asset.

### Протокол и транспорты
- VLESS с `security=none`/`tls`/`reality`; REALITY с X25519MLKEM768
  (откат на X25519), ShortId, `minClientVer`/`maxClientVer`, ML-DSA-65
  (`pqv=`); XTLS Vision.
- Транспорты `tcp`/`raw`, `ws`, `grpc`, `httpupgrade`, `xhttp` (все
  режимы, HTTP/1.1, HTTP/2, HTTP/3); Mux.Cool, общие HTTP/2-соединения
  (`xmux`).
- UDP через XUDP (Full Cone NAT); выход `trojan`.
- TLS-отпечатки Chrome 133, Firefox 148, Safari 26.3 и др. (`fp=`).

### Приложение
- Входы SOCKS5, HTTP, `mixed`, DNS, TUN (`auto_route`, fake-IP, kill
  switch на Linux); маршрутизация по доменам, IP, geosite/geoip и наборам
  правил sing-box; sniffing TLS, HTTP и QUIC.
- Свой DNS: UDP, TCP, DoT, DoH, DoQ, кеш, fake-IP.
- Группы `selector`/`urltest`/`fallback`, подписки (base64, sing-box,
  Clash); локальное API; перечитывание настроек без разрыва соединений.
- Потоки API: `/events` (соединения, группы, подписки, перечитывание),
  `/traffic`, `/memory`, `/logs` — построчный JSON или WebSocket.
- API совместимо с Clash API (как у sing-box и mihomo): веб-панели
  metacubexd, yacd, zashboard; режимы rule/global/direct и группа
  `GLOBAL`; проверка задержки; своя панель из папки (`external_ui`), CORS
  для панелей из интернета. Выбор в группах переживает перечитывание
  настроек.
- Смена настроек через API: `GET /config`, `PUT /config` — проверить,
  применить без разрыва соединений, сохранить (с `.bak`).
- Kill switch (`strict_route`) на Windows — стойкие фильтры WFP: если
  клиент упал, сеть закрыта до нового запуска или `--tun-cleanup`.
- Ядро как библиотека (`libreality`, C ABI, `reality.h`): запуск,
  API вызовом функции, события и журнал обратными вызовами; для Android и
  iOS — готовый дескриптор TUN и защита сокетов (`VpnService.protect`).
- Файл настроек в форматах sing-box и Xray-core (JSON, формат
  определяется сам); неподдерживаемое — ошибка с путём до ключа. Свой
  формат TOML убран.
- Против DPI: `fragment`, `noises`.
- Windows: системный прокси, служба, автозапуск при входе; Linux: systemd.

### Безопасность
- Встраивание (`libreality`): дескриптор TUN, переданный в `rc_start`,
  закрывается ядром при любой ошибке разбора настроек и запуска (раньше
  при ошибке разбора оставался открытым); живому устройству отдаётся его
  собственный дубликат. Системный TUN (Android, iOS) не берёт блокировку
  `auto_route`, а имена серверов по-прежнему разрешает DNS ядра.
- `auto_route` — один владелец на компьютер: второй экземпляр и
  `--tun-cleanup` больше не снимают маршруты и kill switch работающего.
- `auto_route` на Linux не трогает чужие правила и маршруты: свои
  помечены протоколом 202 и снимаются только они, а если приоритеты
  9000–9002 или таблица 2022 заняты другой программой, `auto_route` не
  включается с понятной ошибкой (раньше при запуске и в `--tun-cleanup`
  удалялось всё на этих приоритетах и вся таблица).
- Токен API сравнивается с проверкой длины (раньше токен длиннее на
  256·k байт с правильным началом проходил).
- Пути в настройках через API проверяются и после разрешения
  символических ссылок, включая кеш подписки по умолчанию.
- Общий секрет TLS не оставляет незатёртой копии в памяти.
- REALITY: `auth_key` скрыт в `Debug`; ключ хранится в `Zeroizing`, а hook и
  verifier заимствуют его вместо создания обычных копий. Это меняет Rust API
  `RealityAuth.auth_key` и `RealityHook::auth_key()`; C ABI не меняется.
- Внутреннее статическое REALITY-review трёх Codex-субагентов и его
  ограничения опубликованы в [отчёте](docs/reviews/2026-11-04-reality-internal-review.md).
  Оно принято для первого release gate по решению владельца проекта, но не
  является внешним аудитом; вопросы `pqv=` + HRR остаются непокрытыми тестом.
- Выпуск: сборка без права записи, публикация — отдельным шагом; actions
  закреплены на коммитах.
- Патч rustls описан честно: `vendor/rustls-reality-patch.diff` и
  `docs/RUSTLS_PATCH.md` с порядком переноса обновлений.
- API: подбор токена блокирует адрес (5 неверных; IPv6 — по подсети
  /64; 127.0.0.1 — никогда); `?token=` для WebSocket по умолчанию только
  при API на loopback, в сеть — с `clash_api.allow_query_token`.
- `direct`: клиентам из сети закрыты и link-local адреса (облачный
  metadata 169.254.169.254, fe80::/10), отказ — до подключения.
- Windows: блокировка `auto_route` — в папке службы
  `%ProgramData%\RealityClient` (права только у SYSTEM и
  администраторов), а не в общем `%ProgramData%`; в режиме библиотеки —
  `rc_set_lock_dir`.
- Настройки, кеш подписок и fake-IP пишутся сразу с правами 0600, без
  перехода по подложенным ссылкам; `.srs` — не больше 2 млн подсетей и
  32 МиБ после распаковки; внешние команды (`ip`, `netsh`) — по
  абсолютным путям; сервер или пароль в командной строке — предупреждение.
- Паника больше не роняет приложение-хост в режиме библиотеки
  (`panic = "unwind"`); `libreality` собирается под Android и iOS.
- Имена хоста в старой числовой записи IPv4 (`2130706433`, `0x7f000001`,
  `0177.0.0.1`, `127.1`) отклоняются на входах, в маршрутизаторе и перед
  разрешением имени: системный резолвер читал их как IP, и они обходили
  правила по IP. Имена с управляющими символами из SOCKS5 и подписок
  отклоняются или очищаются.
- Журнал: на уровне `info` нет адресов посещаемых сайтов (они — только в
  `debug`); `--log-file` создаётся с правами 0600 и ротируется при 10 МБ
  во время работы (раньше — только при запуске), запись не блокирует
  работу.
- Токен API, UUID, пароли, ссылки и адреса подписок не выводятся в
  отладочном представлении настроек (`***`).
- Загрузка подписки не следует перенаправлению панели из интернета на
  адрес этого компьютера или локальной сети.
- Интероп-стенд (`scripts/interop_sandbox_bootstrap.sh`): зависимости
  клонируются ровно на закреплённых коммитах.

### Проект
- Лицензия GPL-3.0-or-later (раньше — MIT); SPDX-метки в исходниках;
  лицензии зависимостей в каждом релизе.
- CI на Linux и настоящей Windows; интероп-тесты против Xray-core.
- TUN: стек smoltcp вместо ipstack — соединения не встают после потери
  пакетов, ~200 МиБ/с; на Windows TUN и служба проверены на настоящей
  машине, без IPv6 у компьютера нет петли через TUN.
- TUN: данные сверх объявленного окна TCP больше не роняют стек smoltcp
  паникой («attempt to subtract sequence numbers with underflow») —
  бэкпорт исправления из smoltcp 0.13 (`vendor/smoltcp-window-patch`).
- TUN: соединение больше не встаёт навсегда, когда окно приёма у
  приложения было нулевым и сообщение о его открытии потерялось — стек
  шлёт пробы нулевого окна (бэкпорт из smoltcp 0.13, туда же).
- Документация на русском и английском; CONTRIBUTING, SECURITY,
  CODE_OF_CONDUCT, SUPPORT, шаблоны issue и PR; описание устройства ядра
  (`docs/ARCHITECTURE.md`).
- Зависимости: webpki-roots 1.0, base64 0.23, x509-parser 0.18,
  brotli-decompressor 6, criterion 0.8 (бенчмарки).
- Криптография — новое поколение RustCrypto: sha2/md-5 0.11, hkdf/hmac
  0.13, aes-gcm 0.11, x25519-dalek 3, rand 0.10; проверено интероп-тестами
  против Xray-core. Минимальная версия Rust — 1.89 (её требует aes 0.9).
- README перестроен для нового пользователя (названия, статус, быстрый
  старт для Linux и Windows); справочник — в `docs/` (`CLI`, `CONFIG`,
  `DNS`, `TUN`, `API`, `LINK`, `FEATURES`, оглавление `docs/README.md`).

### Ограничения и незакрытые проверки
- Android/iOS SDK собирается и проверяется кросс-компоновкой; запуск на
  реальных устройствах не подтверждён. Интеграцию выполняет приложение-хост.
- Системный прокси Windows, автозапуск при входе и interop с Xray-core
  проверялись под Wine; это не следует считать runtime-проверкой на Windows.
- Для первого release gate принято внутреннее статическое review REALITY
  тремя Codex-субагентами ([отчёт](docs/reviews/2026-11-04-reality-internal-review.md)).
  Независимого стороннего аудита не проводилось; сценарий `pqv=` + HRR не
  покрыт тестом ([чек-лист](docs/stage5-crypto-review-and-interop.md)).

[Не выпущено]: https://github.com/ERGFT/vpn-core/commits/main
[0.1.0]: https://github.com/ERGFT/vpn-core/releases/tag/v0.1.0

---


# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [SemVer](https://semver.org/). The detailed
stage-by-stage decision history is in [PLAN.md](PLAN.md) (in Russian).

## [Unreleased]

### Shadowsocks
- Added a classic Shadowsocks AEAD outbound for TCP and native UDP, supporting
  `aes-128-gcm`, `aes-256-gcm`, and `chacha20-ietf-poly1305`. SIP002 links and
  sing-box, Xray, and Clash YAML records are imported. SIP003 plugins,
  UDP-over-TCP, and legacy stream ciphers are unsupported. A separate branch
  adds SIP022/2022 AES-128/256-GCM over TCP and native UDP with replay
  protection; full CI and Xray interop passed on head `2c0d14e`, and inclusion
  in main awaits the target PR.

### Hysteria 2
- The TCP/UDP runtime is wired into the outbound factory, sing-box config, and URI subscriptions; each outbound reuses an authenticated QUIC connection. Supported sing-box fields are converted through the URI model and unsupported options are rejected. The official v2.13.0 server passed limited loopback TCP/UDP echo interoperability, including IPv4/IPv6 and a 4096-byte UDP payload. `rc_network_changed` now notifies outbounds; Hysteria 2 drops its shared QUIC session, and the interop scenario covers fresh TCP/UDP requests after the signal. A real interface transition and production readiness remain unverified, so the feature stays experimental.
- Added `ca_file` for a custom PEM trust-root set on Hysteria 2 outbounds in the main config. Certificate verification stays enabled; subscriptions cannot store a local path and skip such records as unsupported.

### SDK and C ABI
- SDK archives now include a per-file SHA-256 manifest and build metadata,
  relocatable CMake/pkg-config metadata, and native link arguments for static
  libraries.
- Added independent C/C++ consumers that build from extracted SDK archives
  and a compatibility guard for exported C ABI symbols.
- Clarified callback and memory-ownership contracts; added checks for callback
  completion, the C++ adapter, and external TUN descriptor validation.

SDK checks confirm consumer execution on supported CI runners. Android/iOS
checks cover compilation and linking, not VPN execution on a device.

## [0.1.0] - 2026-11-04

### Outbounds
- Added a sing-box SOCKS5 outbound for TCP CONNECT (`network: "tcp"`), with RFC 1929 and an optional
  `password_file` extension. Also added an HTTP CONNECT outbound (`type: "http"`): HTTP/1.1,
  Basic auth, `password_file`, and optional TLS with mandatory certificate verification. Both
  outbounds support TCP only; TLS to a SOCKS5 proxy is not supported. Added `detour` for
  SOCKS5/HTTP CONNECT: nested TCP chains, cycle detection, and no direct fallback on failure.

- Experimental route.rules.user_id/invert and trusted Rust/C ABI TUN flow-owner
  resolver; unknown required UIDs fail closed. Site/app first-match order is
  preserved; Android JNI/adapter integration is still required.

### Embedding and DNS
- `rc_validate`: preflight without starting listeners/TUN or returning error text;
  `rc_is_alive`: nonblocking sticky terminal task-error status.
- Added `rc_network_changed`: the host reports a network transition; the core
  clears DNS/server-address caches and cancels tracked sessions while keeping
  listeners and config alive. Application traffic is not retried automatically.
- External TUN retains the core resolver and system-DNS-loop validation.
  Transport hostnames use only an explicit `dns.bootstrap` (vpn-core extension:
  direct IP-literal UDP server, no implicit fallback).
- `dns.rules[].strategy`: per-rule A/AAAA filtering and address ordering,
  including fake-IP; the existing global strategy remains the default.

### Transports
- XHTTP: `downloadSettings` opens a separate download channel with its own
  address, port, HTTP version and transport security; unsupported fields fail.

### Connections
- The TCP dialer interleaves IPv4/IPv6 candidates: the alternative family
  starts after 250 ms, at most two attempts run concurrently, with a 10 s
  total deadline and an eight-address limit.

### Performance
- Added a repeatable Linux benchmark for `vpn-core` versus pinned `xray-rust v0.8.0`:
  a shared Xray-core VLESS + REALITY + Vision server, inner TLS echo, alternating
  five-run order, JSON/CSV output with metrics and environment details, and a
  recovery measurement after briefly stopping the test server.
  The first five paired runs on `ubuntu-24.04` are documented in the
  [benchmark methodology](docs/TESTING.en.md): median throughput was 24.280
  versus 23.967 MiB/s, peak PSS was 11,405 versus 14,641 KiB, and `xray-rust`
  recovered the request faster after server restart (45.939 versus 86.230 ms).
  This is a baseline from one loopback scenario only.

Release `v0.1.0` includes the CLI and C ABI SDKs for embedding the core.

### Release artifacts
- CLI binaries for Linux x86_64 and Windows x86_64.
- SDK ZIPs for Linux x86_64, Windows x86_64, macOS arm64,
  Android arm64-v8a, and iOS arm64; each ZIP has a SHA-256 checksum.
- Dependency licenses and a CycloneDX SBOM are published as release files;
  GitHub build provenance is published as a GitHub-hosted attestation, not a
  downloadable asset.

### Protocol and transports
- VLESS with `security=none`/`tls`/`reality`; REALITY with X25519MLKEM768
  (fallback to X25519), ShortId, `minClientVer`/`maxClientVer`, ML-DSA-65
  (`pqv=`); XTLS Vision.
- Transports `tcp`/`raw`, `ws`, `grpc`, `httpupgrade`, `xhttp` (all modes,
  HTTP/1.1, HTTP/2, HTTP/3); Mux.Cool, shared HTTP/2 connections (`xmux`).
- UDP over XUDP (Full Cone NAT); `trojan` outbound.
- TLS fingerprints of Chrome 133, Firefox 148, Safari 26.3 and others (`fp=`).

### Application
- SOCKS5, HTTP, `mixed`, DNS and TUN inbounds (`auto_route`, fake-IP, kill
  switch on Linux); routing by domain, IP, geosite/geoip and sing-box rule
  sets; TLS, HTTP and QUIC sniffing.
- Own DNS: UDP, TCP, DoT, DoH, DoQ, cache, fake-IP.
- `selector`/`urltest`/`fallback` groups, subscriptions (base64, sing-box,
  Clash); local API; config reload without dropping connections.
- API streams: `/events` (connections, groups, subscriptions, reload),
  `/traffic`, `/memory`, `/logs` — JSON lines or WebSocket.
- The API is compatible with the Clash API (as in sing-box and mihomo):
  the metacubexd, yacd and zashboard dashboards; rule/global/direct modes
  and the `GLOBAL` group; latency tests; your own dashboard from a folder
  (`external_ui`), CORS for dashboards hosted online. Group selections
  survive config reloads.
- Changing the config via the API: `GET /config`, `PUT /config` — validate,
  apply without dropping connections, save (with `.bak`).
- Kill switch (`strict_route`) on Windows — persistent WFP filters: if the
  client crashes, the network stays closed until it restarts or
  `--tun-cleanup` is run.
- The core as a library (`libreality`, C ABI, `reality.h`): start, the API
  as a function call, events and log via callbacks; for Android and iOS — a
  ready TUN descriptor and socket protection (`VpnService.protect`).
- Config file in the sing-box and Xray-core formats (JSON, detected
  automatically); anything unsupported is an error with the path to the
  key. The own TOML format has been removed.
- Anti-DPI: `fragment`, `noises`.
- Windows: system proxy, service, autostart at logon; Linux: systemd.

### Security
- Embedding (`libreality`): the TUN descriptor passed to `rc_start` is closed
  by the core on every config-parse and startup error (it used to stay open
  after a parse error); the live device gets its own duplicate. A system-owned
  TUN (Android, iOS) does not take the `auto_route` lock, and server names are
  still resolved by the core's DNS.
- `auto_route` has one owner per computer: a second instance and
  `--tun-cleanup` no longer remove the routes and kill switch of a running
  one.
- `auto_route` on Linux leaves other programs' rules and routes alone: its
  own are marked with protocol 202 and only those are removed; if
  priorities 9000–9002 or table 2022 are taken by another program,
  `auto_route` is not enabled and a clear error is shown (previously
  everything at those priorities and the whole table were deleted on start
  and in `--tun-cleanup`).
- The API token is compared with a length check (a token 256·k bytes
  longer with the right prefix used to pass).
- Paths in a config sent through the API are also checked after resolving
  symlinks, including the default subscription cache.
- The TLS shared secret leaves no unwiped copy in memory.
- REALITY: `auth_key` is redacted from `Debug`, stored in `Zeroizing`, and
  borrowed by the hook and verifier to avoid ordinary copies. This changes
  the Rust API of `RealityAuth.auth_key` and `RealityHook::auth_key()`; the C ABI is unchanged.
- The [report](docs/reviews/2026-11-04-reality-internal-review.en.md) records
  a static review by three Codex subagents and its limits. The project owner
  accepted it for the first-release gate; it is not an external audit, and
  `pqv=` with HRR remains untested.
- Release: the build has no write access, publishing is a separate step;
  actions are pinned to commits.
- The rustls patch is described honestly: `vendor/rustls-reality-patch.diff`
  and `docs/RUSTLS_PATCH.en.md` with the procedure for porting updates.
- API: token guessing blocks the address (5 wrong tokens; IPv6 — per /64;
  127.0.0.1 — never); `?token=` for WebSocket only for an API on loopback
  by default, on the network — with `clash_api.allow_query_token`.
- `direct`: link-local addresses (cloud metadata 169.254.169.254,
  fe80::/10) are closed to network clients too, refused before connecting.
- Windows: the `auto_route` lock lives in the service folder
  `%ProgramData%\RealityClient` (writable only by SYSTEM and
  administrators), not in the shared `%ProgramData%`; in library mode —
  `rc_set_lock_dir`.
- The config, subscription cache and fake-IP table are written with 0600
  from the start, without following planted links; `.srs` — at most 2
  million subnets and 32 MiB unpacked; external commands (`ip`, `netsh`) —
  by absolute paths; a server or password on the command line — a warning.
- A panic no longer brings down the host app in library mode
  (`panic = "unwind"`); `libreality` builds for Android and iOS.
- Host names in the legacy numeric IPv4 notation (`2130706433`,
  `0x7f000001`, `0177.0.0.1`, `127.1`) are rejected at inbounds, in the
  router and before name resolution: the system resolver read them as IPs
  and they bypassed IP rules. Names with control characters from SOCKS5
  and subscriptions are rejected or cleaned.
- Log: at the `info` level there are no addresses of visited sites (only
  at `debug`); `--log-file` is created with mode 0600 and rotated at 10 MB
  while running (previously only on start), and writing does not block.
- The API token, UUID, passwords, links and subscription URLs are not
  shown in the debug representation of the config (`***`).
- Subscription downloads do not follow a redirect from a panel on the
  internet to an address of this computer or the local network.
- Interop test bench (`scripts/interop_sandbox_bootstrap.sh`): dependencies
  are cloned at exactly the pinned commits.

### Project
- License GPL-3.0-or-later (previously MIT); SPDX headers in sources;
  dependency licenses shipped with every release.
- CI on Linux and real Windows; interop tests against Xray-core.
- TUN: smoltcp stack instead of ipstack — connections no longer stall after
  packet loss, ~200 MiB/s; on Windows TUN and the service are checked on a
  real machine, no loop through TUN without IPv6 on the computer.
- TUN: data beyond the advertised TCP window no longer crashes the smoltcp
  stack with a panic ("attempt to subtract sequence numbers with
  underflow") — a backport of the fix from smoltcp 0.13
  (`vendor/smoltcp-window-patch`).
- TUN: a connection no longer stalls forever when the application's receive
  window was zero and the update reopening it got lost — the stack sends
  zero-window probes (backported from smoltcp 0.13, same place).
- Documentation in Russian and English; CONTRIBUTING, SECURITY,
  CODE_OF_CONDUCT, SUPPORT, issue and PR templates; a description of how the
  core works (`docs/ARCHITECTURE.en.md`).
- Dependencies: webpki-roots 1.0, base64 0.23, x509-parser 0.18,
  brotli-decompressor 6, criterion 0.8 (benchmarks).
- Cryptography moved to the new RustCrypto generation: sha2/md-5 0.11,
  hkdf/hmac 0.13, aes-gcm 0.11, x25519-dalek 3, rand 0.10; checked by
  interop tests against Xray-core. Minimum Rust version is now 1.89 (aes 0.9
  requires it).
- The README is restructured for new users (names, status, quick start for
  Linux and Windows); the reference moved to `docs/` (`CLI`, `CONFIG`,
  `DNS`, `TUN`, `API`, `LINK`, `FEATURES`, index `docs/README.en.md`).

### Limitations and outstanding checks
- Android/iOS SDKs are built and cross-linked; runtime on real devices is not
  confirmed. Integration belongs to the host application.
- The Windows system proxy, autostart at logon, and Xray-core interop have been
  tested under Wine; this is not a runtime check on Windows.
- An internal static REALITY review by three Codex subagents was accepted for
  the first-release gate ([report](docs/reviews/2026-11-04-reality-internal-review.en.md)).
  No independent third-party audit has taken place; `pqv=` with HRR is not
  covered by a test ([checklist](docs/stage5-crypto-review-and-interop.en.md)).

[Unreleased]: https://github.com/ERGFT/vpn-core/commits/main
