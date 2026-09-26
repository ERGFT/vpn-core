#!/usr/bin/env bash
# Сборка reality-client.exe под Windows (x86_64-pc-windows-gnu) на Linux
# и проверка его под Wine: все тесты workspace'а и smoke против настоящего
# Xray-core (REALITY + Vision + XUDP) — тем самым .exe, что пойдёт
# пользователю.
#
# Нужно: mingw-w64 (x86_64-w64-mingw32-gcc), для проверки — wine64.
# Стандартная библиотека Rust для Windows-цели:
#   - если `rustup target add x86_64-pc-windows-gnu` доступен — обычная
#     сборка;
#   - иначе (нет доступа к static.rust-lang.org) — сборка std из исходников
#     (`-Zbuild-std`): исходники library/ той же версии rustc нужно положить
#     в $(rustc --print sysroot)/lib/rustlib/src/rust/library (скрипт
#     скачает их через git, если их нет).
#
# Ключи: --no-test — только сборка; SMOKE=0 — без smoke с Xray.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TARGET=x86_64-pc-windows-gnu
RUN_TESTS=1
[[ "${1:-}" == "--no-test" ]] && RUN_TESTS=0

command -v x86_64-w64-mingw32-gcc >/dev/null \
    || { echo "нет x86_64-w64-mingw32-gcc: apt-get install mingw-w64" >&2; exit 2; }
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

BUILD_STD=()
BUILD_STD_TEST=()
if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    if ! rustup target add "$TARGET" 2>/dev/null; then
        SYSROOT="$(rustc --print sysroot)"
        SRC="$SYSROOT/lib/rustlib/src/rust/library"
        if [[ ! -f "$SRC/std/Cargo.toml" ]]; then
            VER="$(rustc --version | awk '{print $2}')"
            DIR="${RUST_SRC_DIR:-$HOME/.cache/rust-src-$VER}"
            if [[ ! -f "$DIR/library/std/Cargo.toml" ]]; then
                echo "== исходники std $VER (git, только library/)"
                rm -rf "$DIR"
                git clone -q --depth 1 --filter=blob:none --sparse --branch "$VER" \
                    https://github.com/rust-lang/rust "$DIR"
                git -C "$DIR" sparse-checkout set library
                git -C "$DIR" submodule update --init --depth 1 library/backtrace
            fi
            mkdir -p "$(dirname "$SRC")"
            ln -sfn "$DIR/library" "$SRC"
        fi
        echo "== std для $TARGET собирается из исходников (-Zbuild-std)"
        export RUSTC_BOOTSTRAP=1
        # release собирается с panic=abort — ему нужен и panic_abort.
        BUILD_STD=(-Zbuild-std=std,panic_abort)
        BUILD_STD_TEST=(-Zbuild-std)
    fi
fi

echo "== сборка reality-client.exe"
cargo build --release -p reality-client --target "$TARGET" "${BUILD_STD[@]}"
EXE="$ROOT/target/$TARGET/release/reality-client.exe"
ls -l "$EXE"
x86_64-w64-mingw32-objdump -p "$EXE" | awk '/DLL Name/{print "   зависит от", $3}' | sort -u

[[ $RUN_TESTS == 1 ]] || exit 0
WINE="$(command -v wine64 || true)"
[[ -z "$WINE" && -x /usr/lib/wine/wine64 ]] && WINE=/usr/lib/wine/wine64
[[ -n "$WINE" ]] || { echo "нет wine64 — проверка под Windows пропущена"; exit 0; }
export WINEDEBUG=-all
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-reality}"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER="$WINE"

echo "== тесты под Wine"
# Без отладочной информации: иначе тестовые .exe занимают гигабайты.
export CARGO_PROFILE_DEV_DEBUG=0
cargo test --workspace --target "$TARGET" "${BUILD_STD_TEST[@]}" \
    || { echo "ТЕСТЫ ПОД WINE УПАЛИ"; exit 1; }

if [[ "${SMOKE:-1}" == 1 ]]; then
    XRAY_BIN="${XRAY_BIN:-$ROOT/target/xray/xray}"
    if [[ -x "$XRAY_BIN" ]]; then
        echo "== smoke: reality-client.exe под Wine против Xray-core"
        CLIENT_BIN="$EXE" CLIENT_RUNNER="$WINE" XRAY_BIN="$XRAY_BIN" bash scripts/smoke_xray.sh
    else
        echo "нет Xray ($XRAY_BIN) — smoke пропущен"
    fi
fi
# Системный прокси: включается в реестре на время работы и возвращается
# при Ctrl+C (Wine переводит SIGINT в CTRL_C_EVENT).
echo "== --system-proxy под Wine"
KEY='HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
reg_val() { { "$WINE" reg query "$KEY" /v "$1" 2>/dev/null || true; } | tr -d '\r' | awk -v n="$1" '$1==n{print $3}'; }
BEFORE="$(reg_val ProxyEnable)"
PBK="$(python3 -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')"
SP_LINK="vless://11111111-2222-3333-4444-555555555555@127.0.0.1:9?security=reality&sni=a.test&pbk=$PBK&sid=01&type=tcp"
SP_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
SP_LOG="$(mktemp)"
"$WINE" "$EXE" --server "$SP_LINK" --listen "127.0.0.1:$SP_PORT" --system-proxy > "$SP_LOG" 2>&1 &
SP_PID=$!
for _ in $(seq 1 100); do grep -q 'системный прокси Windows включён' "$SP_LOG" && break; sleep 0.1; done
[[ "$(reg_val ProxyServer)" == "127.0.0.1:$SP_PORT" && "$(reg_val ProxyEnable)" == 0x1 ]] \
    || { echo "системный прокси не включился:"; cat "$SP_LOG"; kill "$SP_PID"; exit 1; }
kill -INT "$SP_PID"
for _ in $(seq 1 100); do kill -0 "$SP_PID" 2>/dev/null || break; sleep 0.1; done
grep -q 'прежние настройки возвращены' "$SP_LOG" \
    || { echo "настройки не возвращены:"; cat "$SP_LOG"; exit 1; }
[[ "$(reg_val ProxyEnable)" == "$BEFORE" ]] || { echo "ProxyEnable не вернулся"; exit 1; }
rm -f "$SP_LOG"
echo "OK: системный прокси включён и возвращён при Ctrl+C"
echo "WINDOWS CROSS-BUILD PASSED"
