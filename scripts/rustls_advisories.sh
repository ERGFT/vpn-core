#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Уязвимости RustSec для патченного rustls (vendor/rustls-reality-patch).
#
# cargo audit / cargo deny сверяют Cargo.lock с базой по имени, версии и
# источнику, а у rustls из vendor/ источника нет (path-зависимость) —
# сканеры его молча пропускают (проверено: с заведомо уязвимой версией
# отчёт пуст). Поэтому здесь — отдельный Cargo.lock из одного rustls той
# же версии, как будто из crates.io.
#
#   scripts/rustls_advisories.sh   — код возврата 1, если версия уязвима
#
# Нужно: cargo-audit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/vendor/rustls-reality-patch/Cargo.toml" | head -1)"
[[ -n "$VER" ]] || { echo "не найдена версия rustls в vendor/rustls-reality-patch/Cargo.toml"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/Cargo.lock" <<EOF
version = 4

[[package]]
name = "rustls"
version = "$VER"
source = "registry+https://github.com/rust-lang/crates.io-index"
EOF
echo "rustls $VER (vendor/rustls-reality-patch) против RustSec:"
cargo audit --file "$TMP/Cargo.lock"
