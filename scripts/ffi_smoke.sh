#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Проверка режима библиотеки: C-программа (ffi/examples/smoke.c) собирается
# с libreality и управляет ядром через C ABI — запуск, rc_request, события,
# защита сокетов, перечитывание, остановка; трафик через SOCKS5-вход ядра.
#
#   scripts/ffi_smoke.sh            — отладочная сборка
#   PROFILE=release scripts/ffi_smoke.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROFILE="${PROFILE:-debug}"
CC="${CC:-cc}"
if [[ "$PROFILE" == release ]]; then
    cargo build --release -p reality-ffi
else
    cargo build -p reality-ffi
fi
LIB="$ROOT/target/$PROFILE"
OUT="$ROOT/target/ffi-smoke"
"$CC" -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE -I ffi/include \
    ffi/examples/smoke.c -L "$LIB" -lreality -lpthread -o "$OUT"
LD_LIBRARY_PATH="$LIB" DYLD_LIBRARY_PATH="$LIB" "$OUT"
