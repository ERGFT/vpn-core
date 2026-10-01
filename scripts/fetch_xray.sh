#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Скачать официальный бинарник Xray-core для сравнения (Этап 8).
# Кладёт его в target/xray/, откуда его сам находит
# scripts/stage8_compare_with_xray.sh. В репозиторий ничего не
# коммитится — это внешний инструмент для замеров, не зависимость.
#
# Версия закреплена (XRAY_VERSION — другая), архив сверяется с
# scripts/checksums.txt: CI запускает этот бинарник рядом с нашим кодом.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/target/xray"
mkdir -p "$DEST"

case "$(uname -m)" in
    x86_64|amd64) ASSET="Xray-linux-64.zip" ;;
    aarch64|arm64) ASSET="Xray-linux-arm64-v8a.zip" ;;
    *) echo "неизвестная архитектура $(uname -m) — скачайте вручную с https://github.com/XTLS/Xray-core/releases" >&2; exit 2 ;;
esac

VER="${XRAY_VERSION:-v26.9.9}"
URL="https://github.com/XTLS/Xray-core/releases/download/$VER/$ASSET"

echo "==> $URL"
curl -fsSL --max-time 300 -o "$DEST/xray.zip" "$URL"
# Сумма — из scripts/checksums.txt (строка «<sha256>  <версия>/<файл>»).
WANT="$(awk -v k="$VER/$ASSET" '$2 == k {print $1}' "$ROOT/scripts/checksums.txt")"
GOT="$(sha256sum "$DEST/xray.zip" | cut -d' ' -f1)"
if [[ -z "$WANT" ]]; then
    # Новая версия: напечатать сумму скачанного и официальную (.dgst) —
    # их сверяют и вносят в checksums.txt руками.
    DGST="$(curl -fsSL --max-time 60 "$URL.dgst" | sed -n 's/^SHA2-256= *//p' || true)"
    echo "нет суммы для $VER/$ASSET в scripts/checksums.txt" >&2
    echo "  скачано: $GOT" >&2
    echo "  .dgst:   ${DGST:-не получен}" >&2
    rm -f "$DEST/xray.zip"
    exit 1
fi
if [[ "$GOT" != "$WANT" ]]; then
    echo "$VER/$ASSET: сумма $GOT, ожидалась $WANT — файл не используется" >&2
    rm -f "$DEST/xray.zip"
    exit 1
fi
# Бинарник и лицензия; geo-файлы не нужны (в конфиге сравнения нет роутинга).
unzip -o -q "$DEST/xray.zip" -d "$DEST" xray LICENSE
chmod +x "$DEST/xray"
rm -f "$DEST/xray.zip"
{ "$DEST/xray" version || true; } | head -1 || true
echo "готово: $DEST/xray"
