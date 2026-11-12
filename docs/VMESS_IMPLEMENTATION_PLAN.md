<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# VMess: план реализации

## Статус

Этап VMess начат, но поддержка исходящих соединений ещё не реализована. В `core::vmess` добавлен проверяемый разбор современных `vmess://` ссылок: base64 JSON, UUID, `aid=0`, современные варианты аутентифицированного шифрования с ассоциированными данными (AEAD) и общие параметры транспорта. Значения `alterId` и шифры без AEAD отвергаются явно. В `core::vmess::aead` добавлены nested-HMAC KDF, производный command key, AuthID и двухслойное AES-128-GCM шифрование заголовка. `core::vmess::header` кодирует/разбирает plaintext request header, адреса, padding и FNV-1a checksum; проверки этих модулей прошли в GitHub CI, но независимые wire-векторы Xray/V2Ray ещё не добавлены.

Добавлены разбор входящего AEAD request-header payload, получение ключей ответа из случайных request-body key/IV и аутентифицированное открытие двухслойного AEAD response header с точным числом прочитанных байтов. Они проверяются в отдельном loopback interop-тесте с Xray; полноценной интеграции в runtime outbound пока нет.

`core::vmess::response` теперь разбирает plaintext response-header payload: проверяет ожидаемый response marker, сохраняет option byte, проверяет границы command frame и возвращает точную длину разобранной части. Командные данные пока остаются непрозрачными; этот модуль не реализует управление динамическим портом или соединением.

`core::vmess::body` содержит направленный codec AEAD-чанков для AES-128-GCM и ChaCha20-Poly1305, двухбайтового размера, optional authenticated length с `auth_len`, проверки границ (размер зашифрованного чанка не более 2^14 байт, согласно спецификации Project X) и последовательного nonce. Счётчик nonce ограничен 65 536 чанками и завершается ошибкой вместо повторного использования nonce; способ безопасного rollover должен быть определён до подключения к длительным TCP-сессиям. Codec пока не включён в приложение как полноценный VMess outbound и проверен против Xray только для AES-128-GCM без authenticated length.

Добавлена первая сквозная проверка против настоящего Xray: тест строит modern VMess AEAD по raw TCP с AES-128-GCM, AuthID, зашифрованным request header, body chunks и зашифрованными response header/body; он проверяет двусторонний обмен через loopback echo. Результат проверки для каждого коммита отображается в GitHub CI. Тест покрывает только этот профиль; UDP, ChaCha20-Poly1305, authenticated length, другие transports и V2Ray не подтверждаются. Response header parser теперь требует полный четырёхбайтовый fixed prefix Xray и не считает последующие байты частью заголовка.

Framing и derivation ключа `auth_len` сверены с [Xray `EncodeRequestBody`](https://github.com/XTLS/Xray-core/blob/main/proxy/vmess/encoding/client.go), [Xray chunk parser](https://github.com/XTLS/Xray-core/blob/main/common/crypto/chunk.go) и [V2Ray `EncodeRequestBody`](https://github.com/v2fly/v2ray-core/blob/master/proxy/vmess/encoding/client.go). Сверка исходников не заменяет независимый golden vector или сетевой interop.

Формат полей сверяется с [описанием VMess от Project X](https://xtls.github.io/en/development/protocols/vmess.html) и [Xray `DecodeResponseHeader`](https://github.com/XTLS/Xray-core/blob/main/proxy/vmess/encoding/client.go#L1061-L1169). Это проверка структуры по первичному источнику, а не результат сетевого interop-теста.

Парсер использует общий `TransportConfig` и его проверку. Сам по себе он **не** создаёт подключение, не выполняет VMess-аутентификацию и не означает поддержку VMess в файлах конфигурации или подписках. Не добавляйте протокол в фабрику выходов и импортёры до появления работающего протокольного клиента.

## Оставшаяся работа

1. Расширить interop с Xray на ChaCha20-Poly1305 и authenticated length; добавить отдельную проверку V2Ray и стабильные wire-векторы для AuthID/request header.
2. Подключить AEAD-чанки к потокам TCP и packet-семантике UDP; проверить варианты chunk masking, global padding, EOF/ошибки и nonce exhaustion на независимых wire-векторах.
3. Подключить TCP и UDP семантику, используя общие TCP/TLS/REALITY и поддерживаемые транспорты проекта без дублирования транспортного слоя.
4. Подключить типизированную конфигурацию к factory, Xray/sing-box importers, URI/subscription flow и добавить отрицательные тесты для неподдерживаемых параметров.
5. Проверить совместимость с Xray и V2Ray в воспроизводимом interop-наборе, обновить таблицы возможностей, примеры и переводы RU/EN.

## Условия завершения

- TCP и UDP проходят двусторонние проверки с актуальными Xray и V2Ray.
- Поддержанные шифры, транспорты и форматы импорта задокументированы; старые alterId/неподдерживаемые шифры дают ясную ошибку.
- Присутствуют эталонные тесты заголовков/AEAD, сетевые интеграционные тесты, отрицательные тесты и обязательные CI проверки.
- Русская и английская документация сообщают одинаковый фактический статус и не заявляют неподтверждённую поддержку.
