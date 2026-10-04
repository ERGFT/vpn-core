[Русский](#журнал-изменений) | [English](#changelog)

# Журнал изменений

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии —
[SemVer](https://semver.org/lang/ru/). Подробная история решений по
этапам — [PLAN.md](PLAN.md).

## [Не выпущено]

Первый выпуск ещё не сделан (`git tag v0.1.0 && git push origin v0.1.0`).
В него войдёт:

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

### Планируется
Это намерения, а не обещания сроков.
- Первый выпуск `v0.1.0` с готовыми сборками для Linux и Windows в
  [Releases](https://github.com/ERGFT/vpn-core/releases) — и инструкции по
  установке, обновлению и удалению в README.
- Проверить на настоящей Windows то, что пока проверено только под Wine:
  системный прокси, автозапуск при входе, интероп с Xray-core.
- xhttp: `downloadSettings`.
- Стороннее крипто-ревью REALITY — нужен независимый специалист
  ([чек-лист](docs/stage5-crypto-review-and-interop.md)).

[Не выпущено]: https://github.com/ERGFT/vpn-core/commits/main

---


# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [SemVer](https://semver.org/). The detailed
stage-by-stage decision history is in [PLAN.md](PLAN.md) (in Russian).

## [Unreleased]

No release has been made yet (`git tag v0.1.0 && git push origin v0.1.0`).
It will include:

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

### Planned
These are intentions, not promised dates.
- The first release `v0.1.0` with prebuilt binaries for Linux and Windows in
  [Releases](https://github.com/ERGFT/vpn-core/releases) — and installation,
  update and removal instructions in the README.
- Test on real Windows what has only been tested under Wine so far: the
  system proxy, autostart at logon, interop with Xray-core.
- xhttp: `downloadSettings`.
- A third-party crypto review of REALITY — needs an independent expert
  ([checklist](docs/stage5-crypto-review-and-interop.en.md)).

[Unreleased]: https://github.com/ERGFT/vpn-core/commits/main
