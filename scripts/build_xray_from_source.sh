#!/usr/bin/env bash
# Собрать Xray-core из исходников — для сред, где релизы с GitHub и
# proxy.golang.org недоступны, а `git` по https://github.com работает
# (так было в песочнице, где писался этот проект). Там, где релиз
# скачивается, проще scripts/fetch_xray.sh.
#
# Что делает:
#   1. Go 1.27.1 из исходников (github.com/golang/go), bootstrap —
#      установленный Go >= 1.24.6 (пропускается, если GO127 уже собран);
#   2. Xray-core нужной версии и все его зависимости — по git (модули
#      golang.org/x/*, google.golang.org/*, gvisor.dev и т.п. — из их
#      зеркал на GitHub); модули, нужные только Windows или тестам, —
#      заглушки с одним go.mod;
#   3. go.mod с replace на локальные клоны и сборка ./main.
# Результат: target/xray/xray (там же его ищут интероп-тесты и Этап 8).
#
#   XRAY_VERSION=v26.9.9 scripts/build_xray_from_source.sh
# Версии зависимостей ниже соответствуют go.mod Xray-core v26.9.9; для
# другой версии их нужно сверить с её go.mod.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$HOME/xray-build}"
XRAY_VERSION="${XRAY_VERSION:-v26.9.9}"
DEST="$ROOT/target/xray"
mkdir -p "$WORK/deps" "$DEST"
cd "$WORK"

GO127="$WORK/go127/bin/go"
if [[ ! -x "$GO127" ]]; then
    git clone -q --depth 1 --branch go1.27.1 https://github.com/golang/go go127
    (cd go127/src && GOROOT_BOOTSTRAP="$(go env GOROOT)" GOTOOLCHAIN=local ./make.bash)
fi

[[ -d xray ]] || git -c advice.detachedHead=false clone -q --depth 1 --branch "$XRAY_VERSION" https://github.com/XTLS/Xray-core xray

# <модуль> <репозиторий на GitHub или "-" для заглушки> <тег или короткий sha>
fetch() {
    local mod="$1" repo="$2" ref="$3" dir
    dir="$WORK/deps/$(echo "$mod" | tr '/.' '__')"
    [[ -d "$dir" ]] && return 0
    if [[ "$repo" == "-" ]]; then
        mkdir -p "$dir"; echo "module $mod" > "$dir/go.mod"; return 0
    fi
    if [[ "$ref" =~ ^v[0-9] ]]; then
        git clone -q --depth 1 --branch "$ref" "https://github.com/$repo" "$dir"
    else
        git clone -q --filter=tree:0 --no-checkout "https://github.com/$repo" "$dir"
        git -C "$dir" -c advice.detachedHead=false checkout -q "$ref"
    fi
    # Старые репозитории без go.mod — replace на каталог его требует.
    [[ -f "$dir/go.mod" ]] || echo "module $mod" > "$dir/go.mod"
}

while read -r mod repo ref; do
    [[ -z "$mod" || "$mod" == \#* ]] && continue
    fetch "$mod" "$repo" "$ref" &
    while (( $(jobs -r | wc -l) >= 6 )); do sleep 0.5; done
done <<'LIST'
github.com/apernet/quic-go apernet/quic-go 184d081eef3e
github.com/cloudflare/circl cloudflare/circl v1.6.5
github.com/ghodss/yaml ghodss/yaml d8423dcdf344
github.com/golang/mock golang/mock v1.7.0-rc.1
github.com/google/go-cmp google/go-cmp v0.7.0
github.com/google/uuid google/uuid v1.6.0
github.com/gorilla/websocket gorilla/websocket v1.5.3
github.com/klauspost/cpuid/v2 klauspost/cpuid v2.4.0
github.com/libp2p/go-nat libp2p/go-nat 01afc089f138
github.com/miekg/dns miekg/dns v1.1.73
github.com/pelletier/go-toml pelletier/go-toml v1.9.5
github.com/pion/stun/v3 pion/stun v3.1.7
github.com/pires/go-proxyproto pires/go-proxyproto v0.15.0
github.com/refraction-networking/utls refraction-networking/utls aa6edf4b11af
github.com/robfig/cron/v3 robfig/cron v3.0.1
github.com/sagernet/sing sagernet/sing v0.5.1
github.com/sagernet/sing-shadowsocks sagernet/sing-shadowsocks v0.2.7
github.com/stretchr/testify - -
github.com/vishvananda/netlink vishvananda/netlink v1.3.1
github.com/xtls/reality XTLS/REALITY 8cdf7bf9c7f0
go4.org/netipx go4org/netipx fdeea329fbba
golang.org/x/crypto golang/crypto v0.55.0
golang.org/x/exp golang/exp 9bf2ced13842
golang.org/x/net golang/net v0.58.0
golang.org/x/sync golang/sync v0.22.0
golang.org/x/sys golang/sys v0.47.0
golang.zx2c4.com/wintun - -
golang.zx2c4.com/wireguard WireGuard/wireguard-go f333402bd9cb
golang.zx2c4.com/wireguard/windows - -
google.golang.org/grpc grpc/grpc-go v1.83.2
google.golang.org/protobuf protocolbuffers/protobuf-go v1.36.12
gvisor.dev/gvisor google/gvisor 89a5d21be8f0
h12.io/socks h12w/socks v1.0.3
lukechampine.com/blake3 lukechampine/blake3 v1.4.1
mvdan.cc/gofumpt - -
github.com/andybalholm/brotli andybalholm/brotli v1.0.6
github.com/google/btree google/btree v1.1.2
github.com/google/gopacket google/gopacket v1.1.19
github.com/huin/goupnp huin/goupnp v1.2.0
github.com/jackpal/go-nat-pmp jackpal/go-nat-pmp v1.0.2
github.com/juju/ratelimit juju/ratelimit v1.0.2
github.com/klauspost/compress klauspost/compress v1.17.4
github.com/koron/go-ssdp koron/go-ssdp v0.0.4
github.com/libp2p/go-netroute libp2p/go-netroute v0.2.1
github.com/pion/dtls/v3 pion/dtls v3.1.5
github.com/pion/logging pion/logging v0.2.4
github.com/pion/transport/v4 pion/transport v4.1.0
github.com/quic-go/qpack quic-go/qpack v0.6.0
github.com/vishvananda/netns vishvananda/netns v0.0.5
github.com/wlynxg/anet wlynxg/anet v0.0.5
go.yaml.in/yaml/v3 yaml/go-yaml v3.0.5
golang.org/x/text golang/text v0.41.0
golang.org/x/time golang/time v0.14.0
golang.org/x/tools - -
google.golang.org/genproto/googleapis/rpc googleapis/go-genproto 3dc84a4a5aaa
gopkg.in/yaml.v2 go-yaml/yaml v2.4.0
LIST
wait

cd xray
{
    cat go.mod
    echo
    echo "replace ("
    for d in "$WORK"/deps/*/; do
        d="${d%/}"
        mod="$(awk '/^module /{print $2; exit}' "$d/go.mod")"
        if [[ "$mod" == google.golang.org/genproto* ]]; then
            mod=google.golang.org/genproto/googleapis/rpc
            d="$d/googleapis/rpc"
        fi
        echo "	$mod => $d"
    done
    echo ")"
} > go.sandbox.mod
cp go.sum go.sandbox.sum

PATH="$(dirname "$GO127"):$PATH" GOTOOLCHAIN=local GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off \
    go build -modfile=go.sandbox.mod -trimpath -ldflags "-s -w" -o "$DEST/xray" ./main
"$DEST/xray" version | head -1
echo "готово: $DEST/xray"
