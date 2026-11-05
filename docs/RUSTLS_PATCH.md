[English](RUSTLS_PATCH.en.md) | Русский

# Патч rustls

`vendor/rustls-reality-patch/` — полная копия rustls 0.23.46 с правками
для REALITY и отпечатка браузера. Через `[patch.crates-io]` в корневом
`Cargo.toml` она подменяет rustls во всём графе зависимостей, включая
tokio-rustls. Это **код, критичный для безопасности**: здесь собирается
ClientHello, ведётся обмен ключами TLS 1.3 и разбирается ответ сервера.

Весь объём правок — в `vendor/rustls-reality-patch.diff` (разница с
архивом rustls той же версии с crates.io). Пересоздаёт и сверяет его
`scripts/rustls_patch.sh`, полный `scripts/ci.sh` проверяет, что файл не
устарел. На момент записи — 13 файлов, около +800/−90 строк.

## Что изменено

| Файл | Что и зачем |
|---|---|
| `client/client_conn.rs` | `RealityClientHook` — крючок REALITY: своя гибридная доля ключа X25519MLKEM768, AEAD-печать `session_id` (AuthKey), завершение ECDH, сырой ServerHello. `ChromeHello` — профиль ClientHello браузера (подписи, наборы шифров, GREASE, порядок и сырые расширения, P-256 как у Firefox). Поля `reality`, `chrome_hello` у `ClientConfig`; `set_ech_grease`, `clear_ech`. |
| `client/hs.rs` | Основная логика: сборка ClientHello по `ChromeHello`, GREASE (RFC 8701) по раскладке Chrome, `session_id` из 32 нулей с последующей печатью хуком, подмена `key_share` долей хука (только в первом ClientHello), отдельная запись X25519-части гибрида, `RealityKeyExchange` и доля P-256. |
| `client/common.rs` | `GreaseValues` — GREASE-значения соединения (одни и те же после HelloRetryRequest). |
| `client/tls13.rs` | Выбор дополнительной доли ключа (P-256), если сервер выбрал её. |
| `crypto/mod.rs` | `ActiveKeyExchange::extra_share` / `complete_extra` — дополнительная доля (по умолчанию нет). |
| `msgs/handshake.rs` | Кодирование расширений в заданном порядке и сырых расширений, GREASE-записи; `SessionId::from_bytes_public`, `pub` у `SessionId` и `CertificateChain`. |
| `msgs/persist.rs`, `lib.rs` | `Tls12ClientSessionValue::new` и нужные типы — публичные; реэкспорт новых типов. |
| `client/builder.rs` | Значения по умолчанию для новых полей. |
| `server/hs.rs`, `server/server_conn.rs`, `server/test.rs` | Резолверу сертификата сервера открыты `ClientHello.random` и X25519-часть доли клиента — нужно только тестовому серверу REALITY в тестах ядра. |
| `Cargo.toml` | Пустой `[workspace]`, чтобы крейт собирался отдельно. |

Патч добавляет GREASE (RFC 8701) в наборы шифров, группы, доли ключа,
версии и расширения каждого ClientHello этого rustls, если для профиля не
задано `no_grease`. Ядро задаёт `no_grease` для профиля Firefox. Этот
переключатель не управляет ECH GREASE: оно задаётся отдельно через
`EchMode`; профиль Chrome и Firefox включает его, а Safari очищает. Поэтому
параметры GREASE различаются по профилям и настройкам, а утверждение о том,
что все разновидности GREASE присутствуют во всех TLS-соединениях, было бы
неточным. Поскольку патч подменяет rustls во всём графе зависимостей,
изменённая логика ClientHello применима и к другим TLS-соединениям ядра,
включая DoH/DoT и загрузку подписок; конкретный профиль определяет, какие
GREASE-поля будут отправлены. Серверы обязаны пропускать стандартные GREASE
значения, но это всё равно меняет поведение rustls в процессе.

## Обновление rustls

rustls закреплён на версии патча (dependabot его не трогает), а
`cargo audit`/`cargo deny` его не видят: в `Cargo.lock` у него нет
источника. Поэтому версию патча с базой RustSec сверяет отдельный шаг
CI — `scripts/rustls_advisories.sh` (job `audit`, в том числе раз в
неделю). Выход новой версии — особенно с исправлением уязвимости — значит
перенос патча:

1. Прочитать примечания к выпуску и рекомендации по безопасности rustls
   ([GitHub](https://github.com/rustls/rustls/releases),
   [RustSec](https://rustsec.org/packages/rustls.html)): затронуты ли
   файлы из таблицы выше.
2. Взять новую версию с crates.io в `vendor/rustls-reality-patch/`
   (тот же путь) и наложить `vendor/rustls-reality-patch.diff`:
   `patch -p1 -d vendor/rustls-reality-patch < vendor/rustls-reality-patch.diff`.
   Конфликты разбирать по смыслу: в `client/hs.rs` правки идут в самой
   сборке ClientHello.
3. Поменять версию в `Cargo.lock` (`cargo update -p rustls`), пересоздать
   `.diff` (`scripts/rustls_patch.sh`) и просмотреть его целиком —
   вошло только задуманное.
4. Полный `scripts/ci.sh`: тесты REALITY (`reality_full_stack`,
   `reality_handshake`), интероп с настоящим Xray-core, сверка отпечатка
   Chrome (`scripts/check_chrome_fingerprint.sh`), живой тест Windows в CI.
5. В CHANGELOG — новая версия rustls и что пришлось менять в патче.

Исправление безопасности в rustls, которое приходится на изменённые
места, переносится руками — и в первую очередь.
