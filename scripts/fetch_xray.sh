#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Скачать официальный бинарник Xray-core для сравнения (Этап 8).
# Кладёт его в target/xray/, откуда его сам находит
# scripts/stage8_compare_with_xray.sh. В репозиторий ничего не
# коммитится — это внешний инструмент для замеров, не зависимость.
#
# Версия по умолчанию — последняя; можно задать: XRAY_VERSION=v26.3.27
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/target/xray"
mkdir -p "$DEST"

case "$(uname -m)" in
    x86_64|amd64) ASSET="Xray-linux-64.zip" ;;
    aarch64|arm64) ASSET="Xray-linux-arm64-v8a.zip" ;;
    *) echo "неизвестная архитектура $(uname -m) — скачайте вручную с https://github.com/XTLS/Xray-core/releases" >&2; exit 2 ;;
esac

VER="${XRAY_VERSION:-latest}"
if [[ "$VER" == "latest" ]]; then
    URL="https://github.com/XTLS/Xray-core/releases/latest/download/$ASSET"
else
    URL="https://github.com/XTLS/Xray-core/releases/download/$VER/$ASSET"
fi

echo "==> $URL"
curl -fsSL --max-time 300 -o "$DEST/xray.zip" "$URL"
# Бинарник и лицензия; geo-файлы не нужны (в конфиге сравнения нет роутинга).
unzip -o -q "$DEST/xray.zip" -d "$DEST" xray LICENSE
chmod +x "$DEST/xray"
rm -f "$DEST/xray.zip"
{ "$DEST/xray" version || true; } | head -1 || true
echo "готово: $DEST/xray"
