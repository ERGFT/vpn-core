#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Интероп-тесты против настоящего Xray-core (core/tests/interop_xray.rs):
# REALITY, XTLS Vision (с проверкой перехода на прямую передачу),
# ML-DSA-65, WebSocket (без TLS и с TLS), gRPC, UDP.
#
# Бинарник Xray: $XRAY_BIN, иначе target/xray/xray. Получить его:
#   scripts/fetch_xray.sh               — скачать официальный релиз;
#   scripts/build_xray_from_source.sh   — собрать из исходников (без
#                                          доступа к релизам/proxy.golang.org).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
XRAY_BIN="${XRAY_BIN:-$ROOT/target/xray/xray}"
[[ -x "$XRAY_BIN" ]] || { echo "нет Xray: $XRAY_BIN (scripts/fetch_xray.sh или scripts/build_xray_from_source.sh)" >&2; exit 2; }
{ "$XRAY_BIN" version || true; } | head -1 || true  # head закрывает канал раньше: без || true pipefail ронял скрипт
XRAY_BIN="$XRAY_BIN" cargo test -p reality-core --test interop_xray -- --ignored --test-threads=2 "$@"
