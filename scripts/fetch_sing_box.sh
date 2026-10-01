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
# Сумма — из scripts/checksums.txt (строка «<sha256>  <файл>»).
WANT="$(awk -v k="$NAME.tar.gz" '$2 == k {print $1}' "$ROOT/scripts/checksums.txt")"
GOT="$(sha256sum "$DEST/sb.tgz" | cut -d' ' -f1)"
if [[ -z "$WANT" ]]; then
    # Новая версия: сумма скачанного и та, что публикует GitHub для файла
    # релиза, — их сверяют и вносят в checksums.txt руками.
    API="$(curl -fsSL --max-time 60 "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v$VER" |
        python3 -c 'import json,sys; n=sys.argv[1]; print(next((a.get("digest") or "" for a in json.load(sys.stdin)["assets"] if a["name"] == n), ""))' "$NAME.tar.gz" || true)"
    echo "нет суммы для $NAME.tar.gz в scripts/checksums.txt" >&2
    echo "  скачано:    $GOT" >&2
    echo "  GitHub API: ${API:-не получена}" >&2
    rm -f "$DEST/sb.tgz"
    exit 1
fi
if [[ "$GOT" != "$WANT" ]]; then
    echo "$NAME.tar.gz: сумма $GOT, ожидалась $WANT — файл не используется" >&2
    rm -f "$DEST/sb.tgz"
    exit 1
fi
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
