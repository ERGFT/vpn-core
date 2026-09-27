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
WORK="${WORK:-$HOME/interop}"
mkdir -p "$WORK/deps"
cd "$WORK"

if [[ ! -x "$WORK/go127/bin/go" ]]; then
    git clone -q --depth 1 --branch go1.27.1 https://github.com/golang/go go127
    (cd go127/src && GOROOT_BOOTSTRAP="$(go env GOROOT)" GOTOOLCHAIN=local ./make.bash)
fi

clone() { [[ -d "deps/$2" ]] || git clone -q --depth 1 ${3:+--branch "$3"} "https://github.com/$1" "deps/$2"; }
clone XTLS/REALITY reality
clone cloudflare/circl circl v1.6.5
clone juju/ratelimit ratelimit v1.0.2
clone pires/go-proxyproto go-proxyproto v0.15.0
clone refraction-networking/utls utls v1.8.2
clone golang/crypto xcrypto v0.57.0
clone golang/sys xsys v0.48.0
clone golang/net xnet v0.58.0
clone golang/text xtext v0.42.0
clone golang/term xterm v0.46.0
clone andybalholm/brotli brotli v1.2.3
clone klauspost/compress compress v1.20.0
clone bwesterb/go-ristretto go-ristretto v1.2.4
clone xyproto/randomstring randomstring v1.0.5
clone go-check/check check v1
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
