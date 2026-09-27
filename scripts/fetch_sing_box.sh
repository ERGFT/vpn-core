#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Скачать официальный sing-box и несколько настоящих наборов .srs — для
# сверки нашего разбора наборов правил (tests/app_ruleset.rs). Кладёт всё
# в target/sing-box/; в репозиторий ничего не попадает.
#
# Версия: SING_BOX_VERSION=1.12.8 (по умолчанию).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/target/sing-box"
mkdir -p "$DEST/samples"

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "неизвестная архитектура $(uname -m)" >&2; exit 2 ;;
esac
VER="${SING_BOX_VERSION:-1.12.8}"
NAME="sing-box-$VER-linux-$ARCH"
URL="https://github.com/SagerNet/sing-box/releases/download/v$VER/$NAME.tar.gz"
echo "==> $URL"
curl -fsSL --max-time 300 -o "$DEST/sb.tgz" "$URL"
tar xzf "$DEST/sb.tgz" -C "$DEST" "$NAME/sing-box"
mv -f "$DEST/$NAME/sing-box" "$DEST/sing-box"
rmdir "$DEST/$NAME"
rm -f "$DEST/sb.tgz"
"$DEST/sing-box" version | head -1

RAW=https://raw.githubusercontent.com
for f in \
    "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs" \
    "SagerNet/sing-geosite/rule-set/geosite-category-ru.srs" \
    "SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs" \
    "SagerNet/sing-geoip/rule-set/geoip-ru.srs" \
    "MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs"; do
    out="$DEST/samples/$(echo "$f" | cut -d/ -f1)-$(basename "$f")"
    curl -fsSL --max-time 60 -o "$out" "$RAW/$f" || echo "не скачался $f (пропуск)"
done
echo "готово: $DEST/sing-box, наборы — $DEST/samples"
