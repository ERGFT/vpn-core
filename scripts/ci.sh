#!/usr/bin/env bash
# Полная проверка проекта одной командой. Обязательные шаги — всё, что
# работает без внешних зависимостей; необязательные включаются сами,
# если для них есть инструменты, и честно пишут SKIP, если нет.
#
#   scripts/ci.sh            — всё, что можно на этой машине
#   scripts/ci.sh --quick    — только fmt, clippy и cargo test
#
# Шаги:
#   1. cargo fmt --check                         (обязательно)
#   2. cargo clippy --workspace --all-targets    (обязательно, без предупреждений)
#   3. cargo test --workspace                    (обязательно)
#   4. cargo build --release                     (обязательно, кроме --quick)
#   5. интероп с Go REALITY-сервером             (если есть Go >= 1.27)
#   6. сквозной smoke-тест бинарника             (если собран Go-стенд)
#   7. интероп с настоящим Xray-core             (если есть Xray: $XRAY_BIN
#      или target/xray/xray — scripts/fetch_xray.sh или
#      scripts/build_xray_from_source.sh)
#   8. сквозной smoke бинарника против Xray      (REALITY + Vision +
#      SOCKS5 с паролем + UDP; если есть Xray)
#   9. сверка эталона Chrome-отпечатка с utls    (если есть сеть)
#  10. сборка .exe под Windows и проверка под Wine (если есть mingw-w64;
#      тесты и smoke — если есть wine64)
#  11. сверка разбора наборов .srs с sing-box      (если есть sing-box:
#      $SING_BOX_BIN или target/sing-box/sing-box — scripts/fetch_sing_box.sh)
#
# Код возврата ненулевой, если упал любой обязательный шаг или любой
# необязательный, который был запущен.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

QUICK=0
[[ "${1:-}" == "--quick" ]] && QUICK=1

declare -a RESULTS=()
FAILED=0
step() {  # step <название> <команда...>
    local name="$1"; shift
    echo
    echo "==> $name"
    if "$@"; then
        RESULTS+=("PASS  $name")
    else
        RESULTS+=("FAIL  $name")
        FAILED=1
    fi
}
skip() { RESULTS+=("SKIP  $1 — $2"); echo; echo "==> $1: SKIP ($2)"; }

step "cargo fmt --check" cargo fmt --check
step "cargo clippy (без предупреждений)" \
    cargo clippy --workspace --all-targets -- -D warnings
step "cargo test --workspace" cargo test --workspace

if [[ $QUICK -eq 0 ]]; then
    step "cargo build --release" cargo build --release --workspace

    # Интероп и smoke нужен Go >= 1.27 (crypto/mldsa, crypto/hpke в stdlib).
    go_ok=0
    if command -v go >/dev/null 2>&1; then
        gv="$(go env GOVERSION 2>/dev/null | sed -E 's/^go([0-9]+)\.([0-9]+).*/\1 \2/')"
        read -r gmaj gmin <<<"${gv:-0 0}"
        if (( gmaj > 1 || (gmaj == 1 && gmin >= 27) )); then go_ok=1; fi
    fi
    if [[ $go_ok -eq 1 ]]; then
        step "интероп с Go REALITY-сервером" bash scripts/interop_go_reality.sh
        if [[ -x "$ROOT/target/go-reality-server" ]]; then
            step "сквозной smoke-тест бинарника" bash scripts/smoke_e2e.sh
        else
            skip "сквозной smoke-тест бинарника" "Go-стенд не собрался"
        fi
    else
        skip "интероп с Go REALITY-сервером" "нужен Go >= 1.27 в PATH"
        skip "сквозной smoke-тест бинарника" "нужен Go-стенд"
    fi

    XRAY="${XRAY_BIN:-$ROOT/target/xray/xray}"
    if [[ -x "$XRAY" ]]; then
        export XRAY_BIN="$XRAY"
        step "интероп с Xray-core" bash scripts/interop_xray.sh
        step "сквозной smoke против Xray-core" bash scripts/smoke_xray.sh
        if [[ $(id -u) == 0 ]] && command -v ip >/dev/null && [[ -e /dev/net/tun ]]; then
            step "TUN с auto_route в netns против Xray-core" bash scripts/tun_netns.sh
        else
            skip "TUN в netns" "нужны root, iproute2 и /dev/net/tun"
        fi
    else
        skip "интероп с Xray-core" "нет бинарника Xray ($XRAY)"
        skip "сквозной smoke против Xray-core" "нет бинарника Xray"
        skip "TUN в netns" "нет бинарника Xray"
    fi

    SB="${SING_BOX_BIN:-$ROOT/target/sing-box/sing-box}"
    if [[ -x "$SB" ]]; then
        step "наборы правил .srs против sing-box" env SING_BOX_BIN="$SB" \
            SING_BOX_SRS_SAMPLES="$ROOT/target/sing-box/samples" \
            cargo test -q -p reality-core --test app_ruleset -- --nocapture
    else
        skip "наборы правил .srs против sing-box" "нет sing-box ($SB) — scripts/fetch_sing_box.sh"
    fi

    if curl -fsS --max-time 10 -o /dev/null \
        https://raw.githubusercontent.com/refraction-networking/utls/master/u_common.go 2>/dev/null; then
        step "сверка эталона Chrome-отпечатка" bash scripts/check_chrome_fingerprint.sh
    else
        skip "сверка эталона Chrome-отпечатка" "нет доступа к raw.githubusercontent.com"
    fi
fi

if [[ $QUICK -eq 0 ]]; then
    if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
        step "сборка под Windows (+ проверка под Wine)" bash scripts/cross_windows.sh
    else
        skip "сборка под Windows" "нет mingw-w64"
    fi
fi

echo
echo "================ ИТОГ ================"
printf '%s\n' "${RESULTS[@]}"
exit $FAILED
