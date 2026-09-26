#!/usr/bin/env bash
# Этап 8 — сравнение этого клиента с настоящим Xray-core на ОДИНАКОВОЙ
# нагрузке: память (RSS/PSS) и пропускная способность.
#
# Оба клиента поднимают локальный SOCKS5 и ходят на один и тот же
# тестовый REALITY-сервер (interop/go-reality-server, библиотека
# XTLS/REALITY — та же, что внутри Xray-core), с одинаковой ссылкой и
# одинаковыми параметрами. Нагрузку даёт scripts/stage8_loadgen.py —
# буквально один и тот же код для обоих.
#
# Что нужно:
#   - Xray-core: путь в XRAY=..., либо `xray` в PATH, либо
#     target/xray/xray (скачать: scripts/fetch_xray.sh);
#   - собранный Go-стенд: scripts/interop_go_reality.sh (нужен Go >= 1.27);
#   - python3, openssl.
#
# ⚠️ Честная оговорка к цифрам: Xray-core — универсальная платформа с
# десятками протоколов и роутингом, этот клиент умеет одно. Сравнение
# показывает "сколько ест процесс, делающий ту же работу", а не
# "чей код лучше". И то и другое меряется на loopback в одной машине:
# реальная сеть, задержки и потери здесь не воспроизводятся
# (см. предупреждение Этапа 0 в PLAN.md).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONNS="${CONNS:-8}"          # одновременных соединений
MIB="${MIB:-16}"             # МиБ в каждое соединение (в одну сторону)
OUTDIR="${OUTDIR:-$ROOT/target/stage8}"

XRAY_BIN="${XRAY:-}"
[[ -z "$XRAY_BIN" ]] && command -v xray >/dev/null 2>&1 && XRAY_BIN="$(command -v xray)"
[[ -z "$XRAY_BIN" && -x "$ROOT/target/xray/xray" ]] && XRAY_BIN="$ROOT/target/xray/xray"
if [[ -z "$XRAY_BIN" || ! -x "$XRAY_BIN" ]]; then
    echo "Xray-core не найден. Скачать: scripts/fetch_xray.sh   (или XRAY=/путь/к/xray $0)" >&2
    exit 2
fi
SERVER_BIN="${REALITY_GO_SERVER:-$ROOT/target/go-reality-server}"
[[ -x "$SERVER_BIN" ]] || { echo "нет Go-стенда: $SERVER_BIN (сначала scripts/interop_go_reality.sh)" >&2; exit 2; }

mkdir -p "$OUTDIR"
echo "==> сборка release-версии клиента"
cargo build --release -q -p reality-client || exit 1
cargo build --release -q -p bench --bin memwatch || exit 1
CLIENT_BIN="$ROOT/target/release/reality-client"
MEMWATCH="$ROOT/target/release/memwatch"

TMP="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

# --- тестовый REALITY-сервер ---
openssl genpkey -algorithm X25519 -out "$TMP/k.pem" 2>/dev/null
PRIV="$(openssl pkey -in "$TMP/k.pem" -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')"
PBK="$(openssl pkey -in "$TMP/k.pem" -pubout -outform DER | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SID="0123abcd"

"$SERVER_BIN" -private-key "$PRIV" -short-id "$SID" -uuid "$UUID" -sni example.com > "$TMP/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 300); do grep -q '^READY ' "$TMP/server.log" && break; sleep 0.1; done
SRV_PORT="$(grep -m1 '^READY ' "$TMP/server.log" | cut -d' ' -f2)"
[[ -n "$SRV_PORT" ]] || { echo "Go-стенд не стартовал:"; cat "$TMP/server.log"; exit 1; }
echo "==> тестовый REALITY-сервер на порту $SRV_PORT"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

# run_case <имя> <файл-результата> <команда запуска клиента...>
run_case() {
    local name="$1"; local tag="$2"; shift 2
    local port; port="$(free_port)"
    echo
    echo "=== $name ==="
    "$@" "$port" > "$TMP/$tag.log" 2>&1 &
    local pid=$!
    PIDS+=($pid)
    # ждём, пока порт начнёт слушать
    local ready=0
    for _ in $(seq 1 300); do
        if python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$port))==0 else 1)" 2>/dev/null; then ready=1; break; fi
        sleep 0.1
    done
    [[ $ready -eq 1 ]] || { echo "клиент не начал слушать порт $port:"; cat "$TMP/$tag.log"; return 1; }
    sleep 2   # дать процессу устояться до замера "на холостом ходу"

    local idle_rss
    idle_rss="$(awk '/^VmRSS:/{print $2}' /proc/$pid/status)"

    "$MEMWATCH" --pid "$pid" --interval-ms 100 --duration-secs 3600 --csv "$OUTDIR/$tag.rss.csv" > /dev/null 2>&1 &
    local mw=$!
    PIDS+=($mw)

    local json
    json="$(python3 scripts/stage8_loadgen.py "$port" "$CONNS" "$MIB")" || {
        echo "нагрузка не прошла"; kill $mw 2>/dev/null; return 1; }
    kill $mw 2>/dev/null; wait $mw 2>/dev/null

    local peak_rss peak_pss
    peak_rss="$(awk -F, 'NR>1 && $2>m {m=$2} END{print m+0}' "$OUTDIR/$tag.rss.csv")"
    peak_pss="$(awk -F, 'NR>1 && $3!="" && $3+0>m {m=$3+0} END{print m+0}' "$OUTDIR/$tag.rss.csv")"

    python3 - "$tag" "$name" "$idle_rss" "$peak_rss" "$peak_pss" "$json" "$OUTDIR/$tag.json" << 'PY'
import json, sys
tag, name, idle, peak, peakpss, loadjson, out = sys.argv[1:8]
d = json.loads(loadjson)
d.update({"name": name, "idle_rss_kb": int(idle), "peak_rss_kb": int(peak), "peak_pss_kb": int(peakpss)})
open(out, "w").write(json.dumps(d, ensure_ascii=False, indent=2))
print(f"  холостой RSS: {int(idle)/1024:.1f} МиБ   пик RSS: {int(peak)/1024:.1f} МиБ"
      + (f"   пик PSS: {int(peakpss)/1024:.1f} МиБ" if int(peakpss) else ""))
print(f"  {d['conns']} соединений x {d['mib_each']} МиБ: {d['elapsed_s']} с, "
      f"{d['throughput_mib_s']} МиБ/с (в обе стороны)")
print(f"  до первого байта данных:    медиана {d['first_byte_ms_median']} мс, макс {d['first_byte_ms_max']} мс")
print(f"  (ответ на SOCKS5 CONNECT:   медиана {d['connect_ms_median']} мс — НЕ сравнимо между клиентами, см. ниже)")
PY
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    sleep 1
}

start_reality_core() {
    local port="$1"
    exec "$CLIENT_BIN" \
        --server "vless://$UUID@127.0.0.1:$SRV_PORT?encryption=none&security=reality&sni=example.com&pbk=$PBK&sid=$SID&type=tcp&fp=chrome" \
        --listen "127.0.0.1:$port"
}

start_xray() {
    local port="$1"
    python3 - "$port" "$SRV_PORT" "$UUID" "$PBK" "$SID" "$TMP/xray.json" << 'PY'
import json, sys
port, srv, uuid, pbk, sid, out = sys.argv[1:7]
json.dump({
    "log": {"loglevel": "warning"},
    "inbounds": [{"listen": "127.0.0.1", "port": int(port), "protocol": "socks",
                  "settings": {"auth": "noauth", "udp": False}}],
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "127.0.0.1", "port": int(srv),
                                "users": [{"id": uuid, "encryption": "none"}]}]},
        "streamSettings": {"network": "tcp", "security": "reality",
                           "realitySettings": {"serverName": "example.com", "publicKey": pbk,
                                               "shortId": sid, "fingerprint": "chrome"}},
    }],
}, open(out, "w"), indent=2)
PY
    exec "$XRAY_BIN" run -c "$TMP/xray.json"
}

echo "==> нагрузка: $CONNS соединений x $MIB МиБ"
run_case "reality-core (этот клиент)" reality-core start_reality_core || exit 1
run_case "Xray-core $("$XRAY_BIN" version 2>/dev/null | head -1 | awk '{print $2}')" xray start_xray || exit 1

echo
echo "================= СРАВНЕНИЕ ================="
python3 - "$OUTDIR/reality-core.json" "$OUTDIR/xray.json" << 'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
rows = [
    ("холостой RSS, МиБ", "idle_rss_kb", 1 / 1024, "меньше лучше"),
    ("пик RSS, МиБ", "peak_rss_kb", 1 / 1024, "меньше лучше"),
    ("пропускная, МиБ/с", "throughput_mib_s", 1, "больше лучше"),
    ("до первого байта, мс", "first_byte_ms_median", 1, "меньше лучше"),
]
w = max(len(r[0]) for r in rows) + 1
print(f"{'':{w}} {a['name'][:22]:>22} {b['name'][:22]:>22}   отношение")
for label, key, mul, hint in rows:
    x, y = a[key] * mul, b[key] * mul
    ratio = f"{x / y:.2f}x" if y else "—"
    print(f"{label:{w}} {x:>22.1f} {y:>22.1f}   {ratio} ({hint})")
print("\nВремя до первого байта данных — единственный честный показатель задержки:")
print("Xray-core отвечает на SOCKS5 CONNECT авансом, не дожидаясь соединения с")
print("сервером (отвечает 'успех' даже когда сервера нет), этот клиент — после")
print("настоящего рукопожатия. Поэтому 'ответ на CONNECT' между ними не сравним.")
print("\nCSV с таймлайном памяти и JSON с цифрами — в target/stage8/")
PY
echo
echo "Публиковать результаты наружу — отдельное решение (PLAN.md, Этап 8)."
