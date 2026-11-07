# План интеграции Hysteria 2

**Статус:** этапы 1–2 завершены (PR #187 и #188), этапы 3–5 слиты в `main` (PR #189, #190, #192). Подэтапы 6.1–6.3 слиты (PR #193, #196, #197, #198); CI этих этапов прошёл. Интеграция outbound этапа 7 слита в PR #199; CI прошёл 16 проверок, 1 проверка пропущена. Реальная совместимость с официальным сервером, смена сети и восстановление соединения не подтверждены, поэтому Hysteria 2 остаётся экспериментальной.
**Срез кода:** `main` после PR #199 (`8ec829c`).
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
2. **Входные форматы (состояние после PR #188).** На том этапе применимые URI и sing-box subscription records разбирались, но пропускались при применении подписки с отдельным счётчиком; production config и factory ещё не включали Hysteria 2. Текущая интеграция описана ниже.
3. **QUIC и аутентификация.** Общий owner endpoint/connection, ALPN, TLS validation (без insecure по умолчанию), HTTP/3 auth, статус 233, rate negotiation, timeout и отмена задач. Не менять поведение уже существующих DNS/XHTTP клиентов `quinn`/`h3`.
4. **TCP relay и закрытие.** Каждый TCP dial открывает отдельный bidirectional QUIC stream на общей аутентифицированной connection. Отправить QUIC-varint `0x401`, длину и строку назначения `host:port`, случайный padding; строго разобрать ограниченные TCPResponse status/message/padding и отдавать поток приложению только после status 0. Проверить параллельные потоки, half-close, сбросы, отмену и таймауты. Не включать outbound в factory до отдельного этапа интеграции.
5. **UDP relay.** Datagram codec, per-association IDs, packet ID wrap handling, фрагментация/сборка с пределами памяти, очереди и idle cleanup. Никакого неограниченного состояния на данных сервера.
6. **Опции транспорта — отдельными подэтапами.** 6.1 Salamander на сокете QUIC с учётом 8-byte overhead в UDP datagram limit. 6.2 выбрать и подключить BBR для направлений без фиксированного bandwidth; числовой серверный RX limit должен применяться только вместе с локальной bandwidth-настройкой. Brutal нельзя заявлять, пока pacing и loss compensation не реализованы и не проверены: Quinn 0.11.12 открывает `Controller`/`ControllerFactory`, но его `pacing_rate` является метрикой, а не интерфейсом управления pacer. Для полного rate negotiation сначала нужно добавить локальный bandwidth в outbound config и определить pacing backend; текущий URI такой настройки не несёт. 6.3 port hopping с корректными DNS/IPv4/IPv6 и сменой сети. Gecko требует отдельной оценки: он официально experimental и должен разрабатываться отдельно с лимитами и interop.
7. **Интеграция и совместимость.** Подключить outbound factory, groups/router, учёт, reload, subscription formats и C ABI; проверить shutdown и смену сети; синхронно обновить русскую и английскую документацию и feature matrix. Нужны адресные тесты и reference interop до объявления поддержки готовой.

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

PR #187 добавил типизированную модель и строгий URI parser и объединён в `main` как [`aa8dab6`](https://github.com/ERGFT/vpn-core/commit/aa8dab644b19cd5e3641d53e62408c705e6c6b5a); все 8 групп CI прошли. PR #188 добавил URI-подписки и консервативное преобразование sing-box, обновил RU/EN документацию и слит как [`e43066b`](https://github.com/ERGFT/vpn-core/commit/e43066ba4fac86d21796e57a4237f9d28f4adafa) после завершения проверок GitHub (16 успешных, одна пропущена). На тот момент записи разбирались, но подписка пропускала их с отдельным счётчиком; production sing-box config не создавал рабочий выход.

Этап 3 реализован и слит в PR #189: единый QUIC endpoint/connection owner, HTTP/3 `POST /auth`, строгая проверка статуса 233 и разбор `Hysteria-UDP`/`Hysteria-CC-RX`. Используются системные корни сертификатов; неподдержанные insecure TLS, pinning и ECH отклоняются.

Этап 4 реализован и слит в PR #190: TCPRequest с QUIC-varint ID `0x401`, ограниченный TCPResponse, таймауты и bidirectional stream на назначение. Код пока не подключён к `Outbound`/production factory.

Этап 5 реализован и слит в PR #192. Добавлены UDPMessage, QUIC unreliable datagrams, возрастающие Session ID на QUIC connection, wrapping Packet ID, фрагментация по `max_datagram_size`, сборка переставленных фрагментов и пределы состояния: до 128 незавершённых пакетов, до 256 KiB буфера сборки и TTL 5 секунд. UDP association имеет очередь до 256 ответов и idle timeout 120 секунд; payload ограничен 4096 байтами. Эталонная server/client interop ещё не выполнена; TCP и UDP не доступны через production outbound.

Подэтап 6.1 реализован и слит в PR #193: отдельный QUIC UDP socket добавляет к каждому пакету случайную 8-byte соль и XOR-маску BLAKE2b-256(`key || salt`), а UDPMessage framing уменьшает доступный datagram budget на 8 байт. PSK короче 4 UTF-8 байт отклоняется согласно официальной реализации; короткие и salt-only кадры отбрасываются. Реализация использует Tokio UDP без GSO/ECN. Это не аутентифицированное шифрование: неверный ключ приводит к пакетам, которые QUIC отбросит. На head `32ef01a` CI #757 прошёл 8/8 jobs, Release #124 — 7/7 jobs; один отдельный publish check был пропущен. Reference interop ещё не проводился. Factory по-прежнему не подключена.

Подэтап 6.2 реализован и слит через PR #196: Hysteria использует отдельный Quinn BBR controller, а существующие DNS/XHTTP QUIC-клиенты сохраняют Cubic. CI #759 прошёл 8/8 jobs. В Quinn BBR помечен experimental. Auth-ответ продолжает разбирать `auto`, `0` и числовой RX limit, но числовой лимит пока не применяется: в проекте нет локальной bandwidth-настройки Hysteria. Точный Brutal также пока не реализуем через этот Quinn pacing API; его нельзя считать поддержанным.

Подэтап 6.3 реализован и слит через PR #197: начальный серверный порт случайно выбирается из настроенных диапазонов; через 30 секунд после успешной аутентификации запускается периодическая смена порта. При переходе создаётся новый защищённый UDP socket, а предыдущий остаётся доступен для входящих пакетов ещё 2 секунды. CI #761 прошёл 8/8 jobs для head `37620742be9e1d9f9f83c5bdb22f810c6ebeeb0b`. Локальный focused test не запустился из-за отсутствующего MSVC `link.exe`; CI выполнил проверку на поддерживаемых runners. Совместимость с эталонным сервером, смена сетевого интерфейса и восстановление соединения не проверялись.

Этап 7 подключает `Hysteria2Outbound` с ленивым общим QUIC connection для TCP/UDP и повторным подключением после закрытия; фабрика принимает sing-box outbound и `link`/`link_file`, URI-подписки создают выходы, доступные группам. Интеграция слита в PR #199; CI завершился с 16 успешными и 1 пропущенной проверкой. Статус CI подтверждает сборки и автоматические тесты, но не совместимость с официальным сервером. Требуются практические проверки TCP/UDP interoperability, reload/shutdown, сетевого переключения и восстановления. Hysteria 2 остаётся экспериментальной до прохождения этих проверок.

Внешний Android-телефон не требуется для разработки parser/codec и локального interop. Он станет полезен для финального device-level прогона Android VPN/TUN, Wi-Fi↔cellular handover и восстановления после sleep; одна Android cross-build этого поведения не доказывает.

## Источники

- [Hysteria 2 URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/)
- [Hysteria 2 protocol specification](https://v2.hysteria.network/docs/developers/Protocol/)
- [Hysteria 2 full client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria Brutal reference implementation](https://github.com/HyNetworks/hysteria/blob/core/v2.13.0/core/internal/congestion/brutal/brutal.go)
- [Hysteria 2 changelog](https://v2.hysteria.network/docs/Changelog/)
- [sing-box Hysteria2 outbound](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)
- [Quinn 0.11.12 congestion control API](https://docs.rs/quinn/0.11.12/quinn/congestion/index.html)
