#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Интероп-тест клиента против настоящего REALITY-сервера на библиотеке
# github.com/xtls/reality (PLAN.md, "План дальнейших действий", шаг 2).
#
# Требуется: Go >= 1.27 (библиотека использует crypto/mldsa и crypto/hpke
# из стандартной библиотеки 1.27) и обычный доступ к proxy.golang.org.
#
# В песочнице без proxy.golang.org — сначала scripts/interop_sandbox_bootstrap.sh,
# затем этот скрипт с GO_MODFILE, который тот напечатает.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$ROOT/interop/go-reality-server"
OUT="$ROOT/target/go-reality-server"

go version
cd "$SRV"
if [[ -n "${GO_MODFILE:-}" ]]; then
    GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -modfile="$GO_MODFILE" -o "$OUT" .
else
    go mod tidy
    go build -o "$OUT" .
fi
echo "собран: $OUT"

cd "$ROOT"
REALITY_GO_SERVER="$OUT" cargo test -p reality-core --test interop_go_reality -- --ignored "$@"
