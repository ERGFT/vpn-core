# Возможности и ограничения

**Русский** | [English](FEATURES.en.md)

Полный список: что умеет `reality-client` и как каждая возможность проверена. Коротко — в [README](../README.md#возможности).

## Что умеет и чего нет

Статусы:

- **готово** — работает и проверено тестами (где сказано — против настоящего Xray-core);
- **экспериментально** — работает, но проверено мало или результат зависит от сети;
- **не поддерживается** — нет и не планируется в ближайшее время;
- **не проверено на этой платформе** — код есть, но на этой ОС не проверялся по-настоящему.

| Возможность | Статус | Как проверено |
|---|---|---|
| `security=none` / `tls` / `reality` | готово | все три проверены против настоящего Xray-core |
| Транспорт `type=tcp` (он же `raw`) | готово | интероп с Xray-core |
| Транспорты `type=ws` (`path=`, `host=`), `type=grpc` (`serviceName=`, режим «gun»), `type=httpupgrade` | готово | проверены против настоящего Xray-core; HTTP-заголовки запроса — как у Chrome (как у Xray) |
| Транспорт `type=xhttp` (SplitHTTP): режимы `packet-up`, `stream-up`, `stream-one`, HTTP/2, HTTP/1.1 и HTTP/3 (`alpn=h3`, QUIC), `extra=` | готово | все режимы проверены против Xray-core, в т.ч. поверх REALITY (см. ниже, что не поддерживается) |
| `flow=xtls-rprx-vision` (XTLS Vision) | готово | padding, распознавание внутреннего TLS, прямая передача в обе стороны; проверено против Xray-core. Как и в Xray — только `type=tcp` с `tls`/`reality` |
| REALITY: X25519MLKEM768 (и откат на X25519 для сайтов без ML-KEM), ShortId, `minClientVer`/`maxClientVer`, HMAC-сертификат | готово | против Xray-core и Go-библиотеки XTLS/REALITY; стороннего крипто-ревью не было |
| REALITY: ML-DSA-65 (`pqv=`) | готово | против Xray-core, в т.ч. отказ при чужом ключе |
| TLS-отпечаток как у Chrome 133 | готово | REALITY — совпадает полностью, включая JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`; обычный TLS — без legacy cipher suite'ов и ALPS (см. ниже) |
| `fp=firefox` (Firefox 148), `safari`/`ios` (Safari 26.3), `edge`/`android` (как Chrome), `random`, `randomized` | готово | cipher suites, расширения в порядке браузера, группы, доли ключа (у Firefox — настоящая P-256), подписи, сжатие сертификата (zlib, brotli, zstd — с распаковкой), GREASE — сверены с utls; HTTP-заголовки ws/httpupgrade/xhttp — того же браузера; проверено против REALITY-сервера Xray (tcp, Vision, xhttp, gRPC) |
| UDP (SOCKS5 UDP ASSOCIATE) через XUDP — как у клиента Xray: все назначения в одном потоке, Full Cone NAT | готово | в том числе с Vision (другого способа UDP Vision-аккаунт у Xray не принимает); `--no-xudp` — поток на каждое назначение |
| Логин/пароль на SOCKS5 (`--auth`) | готово | smoke-тест бинарника против Xray-core |
| Файл настроек (`--config`) в формате **sing-box или Xray-core** (JSON, формат определяется сам): несколько входов и выходов | готово | неподдерживаемое — ошибка с путём до ключа, а не молчание |
| Группы серверов `selector`, `urltest`, `fallback` (проверка по HTTP, переход к следующему при отказе); подписки: base64/текст/JSON sing-box/YAML Clash, кеш на диске | готово | проверено с панелью на HTTPS и сервером Xray |
| Входы SOCKS5, HTTP-прокси (CONNECT и обычные запросы) и `mixed` — оба на одном порту | готово | smoke-тест: SOCKS5 и HTTP CONNECT на одном порту |
| Маршрутизация: домен (точно, суффикс, подстрока, regex), IP/подсеть, частные адреса, порт, сеть, вход, базы `geosite.dat`/`geoip.dat` (v2fly), наборы правил sing-box (`.srs` и `.json`) | готово | разбор `.srs` сверен с `sing-box rule-set decompile` на настоящих наборах SagerNet и MetaCubeX; в наборах — только домены и адреса |
| Sniffing: домен по TLS SNI и HTTP Host, когда приложение прислало IP; в TUN — и по QUIC (HTTP/3, v1 и v2) | готово | QUIC проверен на векторах RFC 9001/9369 и настоящих пакетах Chromium (ClientHello на два пакета, перемешанные CRYPTO-кадры) |
| Системный прокси Windows (`--system-proxy`) | не проверено на этой платформе | проверен под Wine |
| Автозапуск: служба Windows (`--service-install`, настройки в закрытой папке ProgramData), запуск при входе (`--autostart-install`), systemd на Linux | готово | служба — на настоящей Windows (CI: установка, права папки ProgramData, остановка и запуск, удаление); автозапуск при входе — под Wine |
| TUN — весь трафик компьютера (как VPN): свой TCP/IP-стек, `auto_route`, перехват DNS, fake-IP, `route_exclude`, kill switch `strict_route` | готово | Linux — проверен против Xray в изолированном netns (TCP, UDP, DNS, fake-IP, ~200 МиБ/с, устойчив к потерям пакетов); Windows (Wintun) — на настоящей Windows (CI: служба, `auto_route`, HTTPS через TUN, kill switch: процесс убит — сеть закрыта) |
| Свой DNS: серверы UDP, TCP, DoT, DoH, DNS over QUIC (`quic://`), системный; выбор сервера по доменам и geosite; кеш; вход DNS-сервера; перехват DNS (`hijack-dns`); fake-IP; `domain_strategy`: `ip_if_non_match` | готово | DoH/DoT/DoQ проверены на своих серверах, UDP-DNS и DoQ — через Xray (XUDP) |
| Mux.Cool для TCP (`"mux": 8` у выхода или подписки; не вместе с Vision) | готово | проверен против Xray-core |
| Общие HTTP/2-соединения: gRPC — все потоки в одном соединении (как у Xray), xhttp — `xmux` (умолчания Xray: 16–32 сессии на соединение; и для HTTP/2, и для HTTP/3) | готово | проверено против Xray-core (счёт соединений) |
| Против DPI: дробление ClientHello (`fragment`: TLS-рекорды и/или TCP-сегменты с паузами) у `vless` и `direct`, шум перед UDP (`noises`) у `direct` | экспериментально | дробление проверено против REALITY-сервера Xray (в т.ч. рекорды по 1–3 байта и Vision); по умолчанию выключено |
| Локальное API, совместимое с Clash API (127.0.0.1 + токен): выходы и группы, выбор сервера, проверка задержки, соединения и их закрытие, правила, подписки, режимы rule/global/direct, DNS-запрос; потоки событий, трафика, памяти и журнала (WebSocket); веб-панель из папки (`external_ui`); перечитывание настроек без разрыва соединений (API, SIGHUP); пресеты правил | готово | ответы сверены с sing-box 1.12; metacubexd и yacd проверены в браузере |
| Выход `trojan` (ссылка `trojan://`, TLS или REALITY, все транспорты VLESS, TCP и UDP); серверы Trojan в подписках | готово | проверен против Xray-core (tcp, ws, REALITY, UDP) |
| Транспорт `kcp` | не поддерживается | не поддерживается (почему — ниже); `quic`/`h2` удалены из самого Xray-core — ошибка подсказывает `xhttp` |
| Linux | готово | собирается и проверен |
| Windows | готово | CI на настоящей Windows: все тесты, сборка `.exe`, служба и TUN с настоящим трафиком; smoke против Xray-core — под Wine ([`docs/WINDOWS.md`](WINDOWS.md)) |
| Режим библиотеки (C ABI): Android, iOS, десктоп — [LIBRARY.md](LIBRARY.md) | экспериментально | в CI собирается под Android и iOS; пример на C запускается на Linux; на телефонах не проверялся |
| ICMP (ping) через TUN | не поддерживается | — |
| macOS | не проверено на этой платформе | собирается библиотека под iOS/macOS; программа `reality-client` на macOS не проверялась |

Стороннее крипто-ревью реализации REALITY не проводилось (подробности —
`PLAN.md`, Этап 5).

## Что осталось открытым

- Mux.Cool — только без Vision (Xray-сервер рвёт Vision-потоки с TCP
  внутри); полузакрытие соединения через Mux.Cool не передаётся (как у
  Xray). UDP идёт через XUDP отдельным потоком.
- `kcp` (mKCP — свой надёжный протокол поверх UDP, ~2,5 тыс. строк в Xray)
  не сделан: редкий и заметный для DPI транспорт.
- xhttp: нет `downloadSettings`; через HTTP/1.1 соединения не
  переиспользуются между сессиями (h2 и h3 — `xmux`). ClientHello внутри
  QUIC (HTTP/3, DoQ) — от rustls, не как у Chrome (у Xray — quic-go, тоже
  не Chrome); `fp=` на QUIC не действует.
- Обычный TLS (`security=tls`) отличается от Chrome двумя вещами — осознанно:
  не заявляются 6 legacy cipher suite'ов (сервер с откатом на TLS 1.2 мог бы
  выбрать такой) и ALPS (если CDN на BoringSSL его согласует, клиент обязан
  ответить, а rustls этого не умеет). В REALITY совпадение полное.
- На настоящей Windows (CI) проверены тесты, служба и TUN; системный прокси, автозапуск при входе и интероп с Xray-core — пока только под Wine.
- Стороннее крипто-ревью (Этап 5) и решение о публикации (Этап 8) —
  за людьми: `docs/stage5-crypto-review-and-interop.md`.
