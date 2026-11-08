# План реализации Shadowsocks

**Русский** | [English](SHADOWSOCKS_IMPLEMENTATION_PLAN.en.md)

Документ отслеживает этапы 3.2 и 3.3 утверждённой дорожной карты. Классический
Shadowsocks AEAD и Shadowsocks 2022 — разные режимы; поддержка одного не
означает поддержку другого.

## Текущее состояние: классический AEAD

Классический outbound влит в `main` через PR
[#204](https://github.com/ERGFT/vpn-core/pull/204). Требуемый CI завершился
успешно; ограничения реализации перечислены ниже и в матрице возможностей.

| Область | Реализация ветки | Проверка/ограничение |
|---|---|---|
| Протокол | Официальный Rust crate `shadowsocks-rust`; только `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | Проверка ссылок отклоняет stream ciphers и Shadowsocks 2022 |
| TCP | Подключение через общий resolver и защищённый TCP dialer | Xray TCP echo прошёл в CI |
| UDP | Нативный Shadowsocks UDP через адаптер защищённого UDP-сокета; очереди ограничены | Xray UDP echo прошёл в CI; потери при переполнении очереди намеренные |
| Конфигурация | `ss://`, поля sing-box, одна запись Xray; общий outbound и factory | Plugin, UDP-over-TCP, network restriction, detour и неподдерживаемые transport security параметры отклоняются |
| Подписки | SIP002, sing-box JSON, Clash YAML Shadowsocks nodes | Непредставимые записи пропускаются и отражаются в счётчиках |
| Секреты | Используется `SecretSource`, debug-вывод настроек маскирует ссылку | Проверки redaction включены в unit tests |

## Выходные критерии classic AEAD

- `cargo fmt --check`, `scripts/ci.sh --quick`, полный CI и Xray interop на всех
  релевантных платформах проходят.
- Проверены TCP и UDP echo с независимым Xray, в том числе повторные и
  параллельные UDP datagrams и корректная обработка закрытия сессии.
- Форматы ручного конфига и подписок либо строят этот outbound, либо явно
  отклоняются/учитываются как пропущенные; нет перехода на direct при ошибке.
- RU/EN README, CONFIG, FEATURES, ARCHITECTURE, TESTING и этот план совпадают
  по поддержанным форматам, методам, транспорту и ограничениям.

Критерии выхода classic AEAD выполнены: PR #204 влит после успешного CI, а
Xray подтвердил TCP/UDP echo. Ограничения плагинов и дополнительных транспортов
остаются намеренными и описаны выше.

## Shadowsocks 2022 / SIP022 — реализация и interop проверены

Спецификация [SIP022](https://shadowsocks.org/doc/sip022.html) сверена с
закреплённым официальным crate `shadowsocks-rust` 1.24.0. В ней обязательны
AES-128/256-GCM, фиксированные base64 PSK в 16/32 байта, отдельные TCP stream
salts/chunks и UDP session/packet IDs со sliding-window replay protection.
Криптографию и протокольный codec не дублируем в ядре: используем клиентские
TCP/UDP пути этого crate.

В отдельной ветке от классического outbound реализованы методы
`2022-blake3-aes-128-gcm` и `2022-blake3-aes-256-gcm`. Включён AEAD-2022
feature официального `shadowsocks-rust`; добавлены раздельная allowlist
методов, валидация PSK через `ServerConfig` и покрытие URI/factory/import
unit-тестами. UDP-адаптер назначает случайный client session ID, монотонный
packet ID, проверяет ID ответной сессии и держит bounded replay window вместе
с текущей/предыдущей server session в течение 60 секунд. Добавлен Xray TCP/UDP
interop для обоих методов и параллельных повторяющихся датаграмм. На точном
head `2c0d14e` GitHub CI завершил все 16 непубликационных jobs успешно
(публикационный job пропущен для PR); Linux прогон выполнил 28 Xray interop
тестов, включая `shadowsocks_2022_tcp_udp_against_xray`. Локальные Rust tests и
interop здесь не запускались: Windows-среде недостаёт MSVC `link.exe`.

Не включать 2022 в классический validator/decoder. Проверенное покрытие:

1. Тесты проверяют оба имени метода, base64 PSK и неверную длину ключа через
   `ServerConfig`.
2. Реализация передаёт TCP framing, salts/chunks, nonce и AEAD официальному
   crate; Xray TCP echo interop прошёл для обоих методов.
3. Unit tests проверяют session IDs, повторы, порядок packet IDs, ограниченное
   replay window и срок жизни server sessions; Xray проверяет UDP echo и
   параллельные одинаковые датаграммы.
4. Тесты конфигурации и subscription import проверяют sing-box и Xray поля,
   SIP002 URI и Clash YAML, сохраняя классические методы и ограничения.
5. Redaction покрыта общими secret-handling тестами; полный CI и все 28 Xray
   interop tests прошли на указанном head.

Кодовые критерии этой реализации выполнены. PR
[#206](https://github.com/ERGFT/vpn-core/pull/206) слит в `main` через merge
commit [`226b735`](https://github.com/ERGFT/vpn-core/commit/226b735). Для PR
прошли все 16 непубликационных CI jobs, а зафиксированный implementation head
`2c0d14e` прошёл 28 Xray interop тестов. SIP003 plugins и другие transport
plugins остаются отдельным решением: их жизненный цикл процесса, platform
support, UDP и безопасная передача секретов должны быть спроектированы заранее.
