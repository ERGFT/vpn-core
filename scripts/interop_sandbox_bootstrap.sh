#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Подготовка интероп-стенда в окружении, где proxy.golang.org и
# golang.org закрыты, но git по https://github.com работает (так было в
# песочнице, где писался этот проект). Делает три вещи:
#   1. собирает Go 1.27.1 из исходников (github.com/golang/go), используя
#      уже установленный Go >= 1.24.6 как bootstrap;
#   2. клонирует зависимости github.com/xtls/reality по git (golang.org/x/*
#      — из зеркал github.com/golang/*);
#   3. пишет отдельный go.mod с replace на локальные клоны (сам
#      interop/go-reality-server/go.mod не трогается).
# В конце печатает, как запустить scripts/interop_go_reality.sh.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$HOME/interop}"
mkdir -p "$WORK/deps"
cd "$WORK"

# Клон ровно на коммите SHA (тег или ветку можно переписать): каталог
# <куда>, репозиторий github.com/<откуда>. Уже готовый клон тоже сверяется.
fetch_at() { # <откуда> <куда> <SHA>
    if [[ ! -d "$2/.git" ]]; then
        git init -q "$2"
        git -C "$2" fetch -q --depth 1 "https://github.com/$1" "$3"
        git -C "$2" checkout -q FETCH_HEAD
    fi
    local got
    got="$(git -C "$2" rev-parse HEAD)"
    if [[ "$got" != "$3" ]]; then
        echo "$2: коммит $got, ожидался $3 — удалите каталог или обновите SHA" >&2
        exit 1
    fi
}

if [[ ! -x "$WORK/go127/bin/go" ]]; then
    fetch_at golang/go go127 862c888e612ac346c7c4d99c9392bdfd265f33b0 # go1.27.1
    (cd go127/src && GOROOT_BOOTSTRAP="$(go env GOROOT)" GOTOOLCHAIN=local ./make.bash)
fi

# SHA — коммиты тегов из комментариев (на момент закрепления). REALITY —
# коммит из interop/go-reality-server/go.mod.
clone() { fetch_at "$1" "deps/$2" "$3"; }
REALITY_SHA=3c98159dee388c2914a2b9e73ea57bc10023f9d3
grep -q "github.com/xtls/reality v0.0.0-[0-9]*-${REALITY_SHA:0:12}" \
    "$REPO/interop/go-reality-server/go.mod" || {
    echo "REALITY в go.mod не $REALITY_SHA — обновите SHA здесь" >&2
    exit 1
}
clone XTLS/REALITY reality "$REALITY_SHA"
clone cloudflare/circl circl cfa7c70defd831ffb0792ab2af560bfef43d60ca              # v1.6.5
clone juju/ratelimit ratelimit f60b32039441cd828005f82f3a54aafd00bc9882            # v1.0.2
clone pires/go-proxyproto go-proxyproto bd986c0a99dccc91fea506d5a6b8c14c5e0cda7c   # v0.15.0
clone refraction-networking/utls utls 8fe0b08e9a0e7e2d08b268f451f2c79962e6acd0     # v1.8.2
clone golang/crypto xcrypto 3f62bf119e84c6e35e8518a2958089ade622d1a3               # v0.57.0
clone golang/sys xsys 613e2570718ecde85c04e69ebd5585c3881c442c                     # v0.48.0
clone golang/net xnet acc78e0d2b2c855c0c4fbdcfe5f42a9e3d0f9778                     # v0.58.0
clone golang/text xtext fafe4a06967e06550e69ee42787d9902845d2a3f                   # v0.42.0
clone golang/term xterm 6226200ed12cba417a9d9e799c2a7179d3fc0e27                   # v0.46.0
clone andybalholm/brotli brotli 6b8aef6ece266fa87b925ce3a913bc30dc4b7b70           # v1.2.3
clone klauspost/compress compress 9d8ccb1d9567304420eb55a88b6f63a2067a8da4         # v1.20.0
clone bwesterb/go-ristretto go-ristretto bbce5cc6c48525049a6edd0988dca78aa2b81f51  # v1.2.4
clone xyproto/randomstring randomstring fe387a090302592331fbb4090741d5f898765e38   # v1.0.5
clone go-check/check check 10cb98267c6cb43ea9cd6793f29ff4089c306974                # ветка v1
# У двух модулей нет go.mod (старые репозитории) — replace на каталог его требует.
[[ -f deps/ratelimit/go.mod ]] || echo "module github.com/juju/ratelimit" > deps/ratelimit/go.mod
[[ -f deps/check/go.mod ]] || echo "module gopkg.in/check.v1" > deps/check/go.mod

REV="$(TZ=UTC git -C deps/reality log -1 --format='%cd-%h' --date=format-local:'%Y%m%d%H%M%S' --abbrev=12)"
D="$WORK/deps"
cat > go.sandbox.mod <<MOD
module reality-core/interop/go-reality-server

go 1.27

require github.com/xtls/reality v0.0.0-$REV

replace (
	github.com/xtls/reality => $D/reality
	github.com/cloudflare/circl => $D/circl
	github.com/juju/ratelimit => $D/ratelimit
	github.com/pires/go-proxyproto => $D/go-proxyproto
	github.com/refraction-networking/utls => $D/utls
	golang.org/x/crypto => $D/xcrypto
	golang.org/x/sys => $D/xsys
	golang.org/x/net => $D/xnet
	golang.org/x/text => $D/xtext
	golang.org/x/term => $D/xterm
	github.com/andybalholm/brotli => $D/brotli
	github.com/klauspost/compress => $D/compress
	gopkg.in/check.v1 => $D/check
	github.com/bwesterb/go-ristretto => $D/go-ristretto
	github.com/xyproto/randomstring => $D/randomstring
)
MOD
touch go.sandbox.sum

echo
echo "Готово. Запуск:"
echo "  PATH=$WORK/go127/bin:\$PATH GOTOOLCHAIN=local GO_MODFILE=$WORK/go.sandbox.mod scripts/interop_go_reality.sh"
