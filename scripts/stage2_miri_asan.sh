#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Этап 2 — runbook, который нельзя выполнить в песочнице (нет сети к
# static.rust-lang.org, откуда качается nightly-канал) — см. PLAN.md,
# Этап 2, и раздел "Дорожная карта до финала". Запускать у себя, из
# корня репозитория (там, где этот файл лежит в scripts/../Cargo.toml).
#
# Что делает: ставит nightly + miri (если ещё не стоит), гоняет под miri
# все юнит-тесты reality-core, которые работают на чистом in-memory
# tokio::io::duplex (relay/socks5/vless::protocol) — именно они могут
# поймать use-after-free/переиспользование буфера с чужими данными,
# самый опасный класс ошибок, если такое случится в буферном коде,
# через который однажды пойдёт расшифрованный трафик (см. предупреждение
# Этапа 2 в PLAN.md). Отдельно — ASan на tls_loopback.rs (настоящие
# сокеты, miri их не поддерживает).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> rustup toolchain install nightly --component miri"
rustup toolchain install nightly --component miri

echo "==> cargo +nightly miri test -p reality-core --lib"
echo "    (relay::tests, socks5::tests, vless::protocol::tests — все на tokio::io::duplex)"
cargo +nightly miri test -p reality-core --lib

echo
echo "==> ASan для core/tests/tls_loopback.rs (настоящие TCP-сокеты, miri сюда не годится)"
echo "    Если host-таргет не подхватится сам — подставить явно, например:"
echo "    RUSTFLAGS=\"-Z sanitizer=address\" cargo +nightly test -p reality-core --test tls_loopback --target x86_64-unknown-linux-gnu"
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test -p reality-core --test tls_loopback

echo
echo "Готово. Любой FAIL здесь — реальная находка, разбирать до того, как"
echo "касаться буферного кода Этапа 5+, где через relay.rs пойдёт уже"
echo "расшифрованный трафик пользователя."
