# Внутренний read-only review REALITY — 2026-11-04

> Это внутреннее ревью, выполненное тремя отдельными Codex-субагентами. Оно не является сторонним аудитом, формальной оценкой побочных каналов или гарантией безопасности.

## Объект проверки

- Репозиторий: `ERGFT/vpn-core`.
- Проверенный исходный commit: `2810fe351a4a07c9ddd1ae24656acbbb4af2a354`.
- Проверяющие: `review_nonce_kdf`, `review_pq_handshake`, `review_sidechannels_rustls`; read-only, без изменений файлов.
- Область: `core/src/reality/auth.rs`, `hook.rs`, `verifier.rs`, `core/src/vless/uri.rs`, transport integration и `vendor/rustls-reality-patch`; nonce/KDF/AEAD/HMAC, X25519MLKEM768, ML-DSA-65, secret lifetime, Rustls ClientHello/HRR hooks.

## Findings и статус

| ID | Severity | Finding | Resolution / disposition |
|---|---|---|---|
| R1 | P2 | Публичный `RealityAuth` выводил `auth_key` через `Debug`. | Исправлено в `c4d168da63f11d4a2afb24845dd18c08f5cd5c15`: ручной `Debug` redacts key и добавлен regression test. |
| R2 | P2 | ML-KEM `SharedKey` копировался в `Zeroizing`, а исходный временный буфер удалялся без очистки. | Исправлено в `c4d168da63f11d4a2afb24845dd18c08f5cd5c15`: `Zeroizing` оборачивает исходный объект `SharedKey` до Drop. |
| R3 | P3 | `RealityHook::auth_key()` и `AuthKeySource::get()` создавали обычные stack-копии AuthKey. | Исправлено PR #61, squash-коммит `56c397cdface8814c6ebc26d5987fd3007008a1e`: hook возвращает borrow; verifier хранит fixed key в `Zeroizing` и использует borrowed key. PR прошёл 8/8 checks. |
| R4 | Policy | Аутентифицированная REALITY-сессия может согласовать классический X25519, даже если клиент предлагает гибридную группу. | Принято как совместимое поведение для первого выпуска; RU/EN FEATURES прямо говорят, что post-quantum TLS не гарантируется. Hybrid-only mode отсутствует. |
| R5 | Coverage | Transcript semantics для `pqv=` при HelloRetryRequest не подтверждены тестом. | Подтверждённого дефекта/обхода не найдено. Зафиксировано как ограничение покрытия; стандартный набор предлагаемых key shares рассчитан на отсутствие HRR. Внешняя или дополнительная проверка остаётся желательной. |

## Итоги проверенных вопросов

- **Nonce и KDF:** HKDF-SHA256 использует `ClientHello.random`; AES-256-GCM использует 12-байтовый nonce из его последних байт и ClientHello как AAD. Транспорт создаёт новый `RealityHook` на каждое соединение; в исследованных путях подтверждённого повторного seal с той же парой key/nonce не обнаружено.
- **Гибридный TLS:** порядок секрета `mlkem || ecdh` совпадает с Go TLS implementation и Xray interop. Валидация длины ML-KEM, contributory X25519 и отказ при неверном ML-DSA ключе найдены в реализации/тестах.
- **TLS trust:** REALITY заменяет обычную проверку PKI на HMAC/опциональную ML-DSA-проверку; TLS transcript signature продолжает проверяться Rustls.
- **Rustls patch:** просмотрен hook вокруг ClientHello и ServerHello; подтверждённого обхода проверки, нарушения ALPN или HRR bypass не найдено. `pqv=` + HRR остаётся непроверенным сценарием.

## Ограничения

Ревью было статическим. Не выполнялись формальное доказательство constant-time, независимый анализ Rustls patch сторонним экспертом, fuzzing этого аудита или полная проверка реализации примитивов. По решению пользователя внутреннее review принято для планового gate первого релиза; это не меняет факта, что внешнего аудита REALITY не было.
