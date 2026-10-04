#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Разница между пропатченным крейтом в vendor/ и исходным крейтом той же
# версии с crates.io — vendor/<каталог>.diff. По нему виден весь объём
# патча, и с него начинается перенос на новую версию крейта.
#
#   scripts/vendor_patch.sh <крейт>          — пересоздать .diff
#   scripts/vendor_patch.sh <крейт> --check  — .diff совпадает с vendor/ (для ci.sh)
#
# Крейты: rustls (vendor/rustls-reality-patch, docs/RUSTLS_PATCH.md),
# smoltcp (vendor/smoltcp-window-patch, vendor/smoltcp-window-patch.md).
# Архив сверяется с контрольной суммой из индекса crates.io.
# Нужно: curl, tar, diff, sha256sum, python3.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE="${1:?крейт: rustls или smoltcp}"
case "$CRATE" in
    rustls) DIR=rustls-reality-patch ;;
    smoltcp) DIR=smoltcp-window-patch ;;
    *) echo "неизвестный крейт $CRATE (rustls, smoltcp)" >&2; exit 2 ;;
esac
VENDOR="$ROOT/vendor/$DIR"
OUT="$ROOT/vendor/$DIR.diff"

VER="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$VENDOR/Cargo.toml" | head -1)"
[[ -n "$VER" ]] || { echo "не найдена версия $CRATE в $VENDOR/Cargo.toml"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Путь в индексе: две первые буквы / две следующие / имя (для имён от 4 букв).
WANT="$(curl -fsS "https://index.crates.io/${CRATE:0:2}/${CRATE:2:2}/$CRATE" | python3 -c '
import json, sys
ver = sys.argv[1]
for line in sys.stdin:
    e = json.loads(line)
    if e["vers"] == ver:
        print(e["cksum"])
' "$VER")"
[[ -n "$WANT" ]] || { echo "$CRATE $VER не найден в индексе crates.io"; exit 1; }
curl -fsSL -o "$TMP/crate.tar.gz" "https://static.crates.io/crates/$CRATE/$CRATE-$VER.crate"
echo "$WANT  $TMP/crate.tar.gz" | sha256sum -c --quiet -
tar xzf "$TMP/crate.tar.gz" -C "$TMP"

# Пути — относительно корня крейта, без дат: .diff воспроизводим.
mkdir -p "$TMP/a" "$TMP/b"
cp -r "$TMP/$CRATE-$VER/." "$TMP/a/"
cp -r "$VENDOR/." "$TMP/b/"
rm -f "$TMP/a/.cargo-ok" "$TMP/b/.cargo-ok"
(cd "$TMP" && diff -ruN a b || true) |
    sed -E 's/^(---|\+\+\+) ([^\t]*)\t.*/\1 \2/' > "$TMP/new.diff"

if [[ "${2:-}" == "--check" ]]; then
    if ! cmp -s "$TMP/new.diff" "$OUT"; then
        echo "vendor/$DIR.diff устарел — scripts/vendor_patch.sh $CRATE"
        diff -u "$OUT" "$TMP/new.diff" | head -40 || true
        exit 1
    fi
    echo "патч $CRATE $VER: .diff совпадает с vendor/ ($(grep -c '^diff ' "$OUT") файлов)"
else
    cp "$TMP/new.diff" "$OUT"
    echo "записан $OUT: $CRATE $VER, $(grep -c '^diff ' "$OUT") файлов, \
+$(grep -c '^+[^+]' "$OUT") −$(grep -c '^-[^-]' "$OUT") строк"
fi
