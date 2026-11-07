# План интеграции Hysteria 2

**Статус:** подготовка к реализации; поддержка в `vpn-core` отсутствует.
**Срез кода:** `main`, commit `53ec432` (PR #185).
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
- Опциональный Salamander оборачивает QUIC-пакеты salted BLAKE2b-256 маскировкой. Соль генерируется для каждого пакета; неверный пакет отбрасывается.

Настройки должны следовать текущей [официальной клиентской конфигурации](https://v2.hysteria.network/docs/advanced/Full-Client-Config/): адрес/порт и SNI, проверка сертификата, пользовательский CA, fingerprint pinning, mTLS, ECH, Salamander, port hopping, bandwidth и congestion controller. Поддерживаемые поля и ограничения надо сверить с актуальными URI и sing-box форматами при реализации. Если опция не поддерживается в первой версии, парсер должен отклонить её с понятной ошибкой; нельзя принять и проигнорировать её.

В `vpn-core` остаются вне области задачи локальные SOCKS/HTTP listeners Hysteria-клиента, server-side forwarding, NAT hole punching/Realms, системный интерфейс TUN самого Hysteria и `mimic`/XDP серверный режим. UDP routing и TUN уже принадлежат общему ядру и должны работать через существующую модель сессий.

## План небольших PR

1. **Модель и входные форматы.** Типизированный `Hysteria2Config`, редактирование/маскирование секретов, строгая валидация; sing-box outbound и `hysteria2://` link/subscription parser. Пока не включать тип в производственный factory до готовности транспорта либо выдавать чёткую ошибку, не обещающую рабочий протокол.
2. **QUIC и аутентификация.** Общий owner endpoint/connection, ALPN, TLS validation (без insecure по умолчанию), HTTP/3 auth, статус 233, rate negotiation, timeout и отмена задач. Не менять поведение уже существующих DNS/XHTTP клиентов `quinn`/`h3`.
3. **TCP relay и закрытие.** TCPRequest/Response codec, передача потока, одновременные потоки, отмена при закрытии стороны и при остановке `Running`.
4. **UDP relay.** Datagram codec, per-association IDs, packet ID wrap handling, фрагментация/сборка с пределами памяти, очереди и idle cleanup. Никакого неограниченного состояния на данных сервера.
5. **Опции транспорта.** Salamander; алгоритмы congestion/rate, порт-хоппинг с корректной DNS/IPv4/IPv6 и сменой сети. Проверить доступность QUIC congestion-controller интерфейсов `quinn`; BBR/Brutal нельзя заявлять, пока контроллер действительно не подключён и не протестирован. Gecko — отдельная оценка: официально experimental, включать только отдельным этапом с лимитами и совместимостью.
6. **Интеграция и совместимость.** Группы, router, учёт, обновление конфигурации, subscription formats и C ABI; синхронное обновление русской и английской документации и feature matrix.

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

Внешний Android-телефон не требуется для разработки parser/codec и локального interop. Он станет полезен для финального device-level прогона Android VPN/TUN, Wi-Fi↔cellular handover и восстановления после sleep; одна Android cross-build этого поведения не доказывает.

## Источники

- [Hysteria 2 protocol specification](https://v2.hysteria.network/docs/developers/Protocol/)
- [Hysteria 2 full client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria 2 changelog](https://v2.hysteria.network/docs/Changelog/)
- [Quinn congestion control API](https://docs.rs/quinn/latest/quinn/congestion/index.html)
