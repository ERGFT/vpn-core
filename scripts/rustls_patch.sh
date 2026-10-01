#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Разница между vendor/rustls-reality-patch и исходным rustls той же
# версии с crates.io — vendor/rustls-reality-patch.diff. По нему видно
# весь объём патча, и с него начинается перенос на новую версию rustls
# (docs/RUSTLS_PATCH.md).
#
#   scripts/rustls_patch.sh          — пересоздать .diff
#   scripts/rustls_patch.sh --check  — .diff совпадает с vendor/ (для ci.sh)
#
# Архив rustls сверяется с контрольной суммой из индекса crates.io.
# Нужно: curl, tar, diff, sha256sum, python3.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor/rustls-reality-patch"
OUT="$ROOT/vendor/rustls-reality-patch.diff"

VER="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$VENDOR/Cargo.toml" | head -1)"
[[ -n "$VER" ]] || { echo "не найдена версия rustls в $VENDOR/Cargo.toml"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

WANT="$(curl -fsS https://index.crates.io/ru/st/rustls | python3 -c '
import json, sys
ver = sys.argv[1]
for line in sys.stdin:
    e = json.loads(line)
    if e["vers"] == ver:
        print(e["cksum"])
' "$VER")"
[[ -n "$WANT" ]] || { echo "rustls $VER не найден в индексе crates.io"; exit 1; }
curl -fsSL -o "$TMP/rustls.crate" "https://static.crates.io/crates/rustls/rustls-$VER.crate"
echo "$WANT  $TMP/rustls.crate" | sha256sum -c --quiet -
tar xzf "$TMP/rustls.crate" -C "$TMP"

# Пути — относительно корня крейта, без дат: .diff воспроизводим.
mkdir -p "$TMP/a" "$TMP/b"
cp -r "$TMP/rustls-$VER/." "$TMP/a/"
cp -r "$VENDOR/." "$TMP/b/"
rm -f "$TMP/a/.cargo-ok" "$TMP/b/.cargo-ok"
(cd "$TMP" && diff -ruN a b || true) |
    sed -E 's/^(---|\+\+\+) ([^\t]*)\t.*/\1 \2/' > "$TMP/new.diff"

if [[ "${1:-}" == "--check" ]]; then
    if ! cmp -s "$TMP/new.diff" "$OUT"; then
        echo "vendor/rustls-reality-patch.diff устарел — scripts/rustls_patch.sh"
        diff -u "$OUT" "$TMP/new.diff" | head -40 || true
        exit 1
    fi
    echo "патч rustls $VER: .diff совпадает с vendor/ ($(grep -c '^diff ' "$OUT") файлов)"
else
    cp "$TMP/new.diff" "$OUT"
    echo "записан $OUT: rustls $VER, $(grep -c '^diff ' "$OUT") файлов, \
+$(grep -c '^+[^+]' "$OUT") −$(grep -c '^-[^-]' "$OUT") строк"
fi
