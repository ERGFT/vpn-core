# План интеграции Hysteria 2

**Статус:** этапы 1–2 завершены (PR #187 и #188); этап 3 реализован в PR #189; этап 4 (TCP relay) реализован в PR #190; этап 5 (UDP relay и unit tests) реализован в PR #192. Все 8 CI jobs PR #192 прошли на commit `f0c8456`; PR остаётся открытым поверх #190. Подэтап 6.1 (Salamander) реализуется в PR #193 из `codex/hysteria2-salamander`, поверх #192. Head `c2c41a1` прошёл все 15 CI checks, кроме штатно пропущенного publish; follow-up, добавляющий проверку минимальной длины PSK, отправлен и ожидает CI. Reference interop не проводился. Production outbound и reference interop ещё не готовы.
**Срез кода:** `main`, commit `e43066b` (PR #188).
**Область:** только клиентский прокси-выход в существующем ядре.

## Решение по архитектуре

Hysteria 2 — QUIC-протокол с TCP-потоками и UDP datagrams. Он подходит к текущему контракту `Outbound`: `connect()` открывает направленный TCP-поток, `udp()` возвращает ассоциацию `UdpSession`. Нужен отдельный `Hysteria2Outbound`, который владеет общим QUIC endpoint/connection и HTTP/3 control/auth состоянием. Не создавать новый router или динамический реестр.

Существующий `core/src/transport/quic.rs` уже строит QUIC поверх `quinn`, создаёт защищённый UDP-сокет через `net_protect`, работает поверх `UdpSession` и ограничивает внутренние очереди. `core/src/transport/xhttp.rs` уже содержит рабочий клиент HTTP/3 через `h3` + `h3-quinn`. Эти модули дают кодовые примеры и части инфраструктуры, но не являются готовым Hysteria транспортом: Hysteria требует своих ALPN/auth-заголовков, потоковых сообщений, UDP формата/фрагментации, congestion/rate настроек и поведения порт-хоппинга.

Сборка выхода должна остаться в `app/outbound_factory.rs`; типизированная конфигурация и строгая проверка сочетаний — в `app/config/outbound.rs`. Далее нужен явный разбор применимых `hysteria2://` ссылок в подписках и поддерживаемых входных форматах sing-box. Не добавлять фиктивную поддержку Hysteria в Xray, где такой outbound-тип отсутствует.

## Требования протокола и границы первой полной реализации

Официальный [протокол Hysteria 2](https://v2.hysteria.network/docs/developers/Protocol/) задаёт следующие обязательные механизмы:

- HTTP/3 `POST /auth`, `Hysteria-Auth`, `Hysteria-CC-RX`; успешная аутентификация — только статус `233`. Иное состояние должно закрыть соединение и вернуть ошибку.
- Для каждого TCP назначения — новый QUIC bidirectional stream с TCPRequest и проверкой TCPResponse до выдачи потока вызывающему коду.
- Для UDP — QUIC unreliable datagrams с отдельным session ID на UDP-ассоциацию, последовательными packet IDs и протокольной фрагментацией/сборкой. Утеря любого фрагмента отбрасывает всю датаграмму.
- Согласование RX rate из auth-ответа; `0` и `auto` имеют разные значения. Локальный bandwidth limit и серверное согласование нельзя смешивать или молча игнорировать.
- Опциональный Salamander оборачивает QUIC-пакеты salted BLAKE2b-256 маскировкой. Соль генерируется для каждого пакета; неверный пакет отбрасывается; PSK для совместимости с официальной реализацией должен содержать не менее 4 UTF-8 байт.

Настройки должны следовать текущей [официальной клиентской конфигурации](https://v2.hysteria.network/docs/advanced/Full-Client-Config/): адрес/порт и SNI, проверка сертификата, пользовательский CA, fingerprint pinning, mTLS, ECH, Salamander, port hopping, bandwidth и congestion controller. Поддерживаемые поля и ограничения надо сверить с актуальными URI и sing-box форматами при реализации. Если опция не поддерживается в первой версии, парсер должен отклонить её с понятной ошибкой; нельзя принять и проигнорировать её.

В `vpn-core` остаются вне области задачи локальные SOCKS/HTTP listeners Hysteria-клиента, server-side forwarding, NAT hole punching/Realms, системный интерфейс TUN самого Hysteria и `mimic`/XDP серверный режим. UDP routing и TUN уже принадлежат общему ядру и должны работать через существующую модель сессий.

## План небольших PR

1. **Модель и разбор URI.** Типизированный `Hysteria2Config`, маскирование секретов, строгая валидация `hysteria2://`/`hy2://`, SNI/TLS, Salamander/Gecko и multi-port. Этот слой не создаёт рабочее соединение и не должен заявляться как поддержка outbound.
2. **Входные форматы.** Явное преобразование применимых sing-box outbound и URI-подписок. Адаптеры сохраняют только URI-представимые поля и считают записи с неподдержанными опциями отдельно; распознанные Hysteria 2 записи пропускаются с отдельным точным счётчиком, поскольку runtime отсутствует. Не включать тип в производственный factory до готовности транспорта.
3. **QUIC и аутентификация.** Общий owner endpoint/connection, ALPN, TLS validation (без insecure по умолчанию), HTTP/3 auth, статус 233, rate negotiation, timeout и отмена задач. Не менять поведение уже существующих DNS/XHTTP клиентов `quinn`/`h3`.
4. **TCP relay и закрытие.** Каждый TCP dial открывает отдельный bidirectional QUIC stream на общей аутентифицированной connection. Отправить QUIC-varint `0x401`, длину и строку назначения `host:port`, случайный padding; строго разобрать ограниченные TCPResponse status/message/padding и отдавать поток приложению только после status 0. Проверить параллельные потоки, half-close, сбросы, отмену и таймауты. Не включать outbound в factory до отдельного этапа интеграции.
5. **UDP relay.** Datagram codec, per-association IDs, packet ID wrap handling, фрагментация/сборка с пределами памяти, очереди и idle cleanup. Никакого неограниченного состояния на данных сервера.
6. **Опции транспорта — отдельными подэтапами.** 6.1 Salamander на сокете QUIC с учётом 8-byte overhead в UDP datagram limit. 6.2 rate negotiation и congestion controller: проверить API `quinn`; BBR/Brutal нельзя заявлять, пока выбранный алгоритм действительно не подключён и не протестирован. 6.3 port hopping с корректными DNS/IPv4/IPv6 и сменой сети. Gecko требует отдельной оценки: он официально experimental и должен разрабатываться отдельно с лимитами и interop.
7. **Интеграция и совместимость.** Группы, router, учёт, обновление конфигурации, subscription formats и C ABI; синхронное обновление русской и английской документации и feature matrix.

Каждый PR должен оставаться небольшим, иметь адресные тесты и обновлять обе версии документов. Не объединять отдельные этапы в одно изменение «готового протокола» без полного набора проверок.

## Проверки завершения

Для полного статуса Hysteria 2 нужны автоматические тесты codec/config плюс interop с зафиксированной версией официального Go client/server. Проверить:

- валидный/невалидный пароль, сертификат, SNI, CA и fingerprint;
- TCP echo, параллельные потоки, удалённое закрытие, таймаут и остановку ядра;
- UDP echo IPv4/IPv6, несколько назначений в ассоциации, большие датаграммы, потери/перестановку фрагментов, переполнение очереди и завершение сессии;
- лимиты и negotiated скорости, BBR/Reno/Brutal только для реально реализованных контроллеров;
- Salamander с правильным/неверным паролем, port hopping, смену сети и повторное соединение;
- одиночную ссылку и подписку, группу/переключение, конфигурационный reload;
- обычные CI: fmt, clippy, workspace tests, coverage, Linux interop/TUN, Windows, Android/iOS build, MSRV, audit и secrets; Rust/C ABI остаётся совместимым.

## Текущее продвижение

PR #187 добавил типизированную модель и строгий URI parser и объединён в `main` как [`aa8dab6`](https://github.com/ERGFT/vpn-core/commit/aa8dab644b19cd5e3641d53e62408c705e6c6b5a); все 8 групп CI прошли. PR #188 добавил URI-подписки и консервативное преобразование sing-box, обновил RU/EN документацию и слит как [`e43066b`](https://github.com/ERGFT/vpn-core/commit/e43066ba4fac86d21796e57a4237f9d28f4adafa) после завершения проверок GitHub (16 успешных, одна пропущена). Записи можно разобрать и проверить, но подписка пока пропускает их с отдельным счётчиком; обычный sing-box конфиг сообщает точную причину, что runtime ещё не готов. Рабочий выход не создаётся.

Этап 3 реализован в PR #189: единый QUIC endpoint/connection owner, HTTP/3 `POST /auth`, строгая проверка статуса 233 и разбор `Hysteria-UDP`/`Hysteria-CC-RX`. Все 8 CI jobs для commit `cc388b5` прошли; PR остаётся открытым до отдельного разрешения на слияние. Используются системные корни сертификатов; неподдержанные insecure TLS, pinning, ECH, obfuscation и port hopping отклоняются.

Этап 4 реализован в PR #190 (`codex/hysteria2-tcp-relay`), stacked on #189: TCPRequest с QUIC-varint ID `0x401`, ограниченный TCPResponse, таймауты и bidirectional stream на назначение. В последней попытке CI все 8 jobs прошли; первый coverage запуск упал на интеграционном тесте `app_groups`, его повтор прошёл. Код пока не подключён к `Outbound`/production factory.

Этап 5 реализован в PR #192 (`codex/hysteria2-udp-relay`), stacked on #190. Добавлены UDPMessage, QUIC unreliable datagrams, возрастающие Session ID на QUIC connection, wrapping Packet ID, фрагментация по `max_datagram_size`, сборка переставленных фрагментов и пределы состояния: до 128 незавершённых пакетов, до 256 KiB буфера сборки и TTL 5 секунд. UDP association имеет очередь до 256 ответов и idle timeout 120 секунд; payload ограничен 4096 байтами. Все 8 CI jobs прошли на `f0c8456`, включая workspace tests, coverage и платформенные проверки. Эталонная server/client interop ещё не выполнена; PR остаётся открытым. TCP и UDP не доступны через production outbound.

Подэтап 6.1 реализуется в PR #193 из `codex/hysteria2-salamander`, stacked on #192: отдельный QUIC UDP socket добавляет к каждому пакету случайную 8-byte соль и XOR-маску BLAKE2b-256(`key || salt`), а UDPMessage framing уменьшает доступный datagram budget на 8 байт. PSK короче 4 UTF-8 байт отклоняется согласно официальной реализации. Реализация использует Tokio UDP без GSO/ECN. Это не аутентифицированное шифрование: неверный ключ приводит к пакетам, которые QUIC отбросит. На head `c2c41a1` прошли все 15 CI checks, кроме штатно пропущенного publish; follow-up с проверкой границы PSK отправлен и ожидает CI. Reference interop ещё не проводился. Factory по-прежнему не подключена.

Внешний Android-телефон не требуется для разработки parser/codec и локального interop. Он станет полезен для финального device-level прогона Android VPN/TUN, Wi-Fi↔cellular handover и восстановления после sleep; одна Android cross-build этого поведения не доказывает.

## Источники

- [Hysteria 2 URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/)
- [Hysteria 2 protocol specification](https://v2.hysteria.network/docs/developers/Protocol/)
- [Hysteria 2 full client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria 2 changelog](https://v2.hysteria.network/docs/Changelog/)
- [sing-box Hysteria2 outbound](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)
- [Quinn congestion control API](https://docs.rs/quinn/latest/quinn/congestion/index.html)
