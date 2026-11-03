#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Repeatable same-host VLESS + REALITY + Vision comparison.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="${OUTDIR:-$ROOT/target/stage6-xray-rust}"
RUNS="${RUNS:-5}"
CONNS="${CONNS:-8}"
MIB="${MIB:-64}"
OUTAGE_SECS="${OUTAGE_SECS:-2}"
RECOVERY_TIMEOUT_SECS="${RECOVERY_TIMEOUT_SECS:-60}"
RECOVERY_POLL_MS="${RECOVERY_POLL_MS:-50}"
XRAY_VERSION="${XRAY_VERSION:-v26.9.9}"
XRAY_BIN="${XRAY_BIN:-$ROOT/target/xray/xray}"
XRAY_RUST_COMMIT="fcce4be2771c1fb3f11e9503741d39a4d8df314e" # v0.8.0 peeled commit
XRAY_RUST_SRC="${XRAY_RUST_SRC:-$ROOT/target/xray-rust-$XRAY_RUST_COMMIT}"
XRAY_RUST_BIN="$XRAY_RUST_SRC/target/release/xray-rust"

for value in "$RUNS" "$CONNS" "$MIB"; do
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || { echo "RUNS, CONNS and MIB must be positive integers" >&2; exit 2; }
done
[[ "$OUTAGE_SECS" =~ ^[0-9]+$ ]] || { echo "OUTAGE_SECS must be a non-negative integer" >&2; exit 2; }
for value in "$RECOVERY_TIMEOUT_SECS" "$RECOVERY_POLL_MS"; do
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || { echo "RECOVERY_TIMEOUT_SECS and RECOVERY_POLL_MS must be positive integers" >&2; exit 2; }
done
export OUTAGE_SECS RECOVERY_TIMEOUT_SECS RECOVERY_POLL_MS
for tool in cargo git openssl python3; do
    command -v "$tool" >/dev/null || { echo "required tool not found: $tool" >&2; exit 2; }
done
[[ -r /proc/self/status ]] || { echo "this benchmark requires Linux /proc" >&2; exit 2; }

if [[ ! -x "$XRAY_BIN" ]]; then
    echo "Xray-core missing; run scripts/fetch_xray.sh first" >&2
    exit 2
fi
XRAY_VERSION_LINE="$("$XRAY_BIN" version 2>/dev/null | head -n1)"
[[ "$XRAY_VERSION_LINE" == *"${XRAY_VERSION#v}"* ]] || {
    echo "Xray binary version mismatch: expected $XRAY_VERSION, got ${XRAY_VERSION_LINE:-unknown}" >&2
    exit 2
}
if [[ ! -d "$XRAY_RUST_SRC/.git" ]]; then
    git clone --filter=blob:none --no-checkout --depth 1 \
        https://github.com/aimalygin/xray-rust.git "$XRAY_RUST_SRC"
fi
if [[ "$(git -C "$XRAY_RUST_SRC" rev-parse HEAD 2>/dev/null || true)" != "$XRAY_RUST_COMMIT" ]]; then
    git -C "$XRAY_RUST_SRC" fetch --depth 1 origin "$XRAY_RUST_COMMIT"
    git -C "$XRAY_RUST_SRC" checkout --detach "$XRAY_RUST_COMMIT"
fi
[[ "$(git -C "$XRAY_RUST_SRC" rev-parse HEAD)" == "$XRAY_RUST_COMMIT" ]] || {
    echo "xray-rust checkout does not match pinned commit" >&2; exit 1;
}
cargo build --locked --release --manifest-path "$XRAY_RUST_SRC/crates/xray-cli/Cargo.toml"
[[ -x "$XRAY_RUST_BIN" ]] || { echo "xray-rust binary missing: $XRAY_RUST_BIN" >&2; exit 2; }

cd "$ROOT"
cargo build --locked --release -p reality-client
cargo build --locked --release -p bench --bin memwatch
CLIENT_BIN="$ROOT/target/release/reality-client"
MEMWATCH="$ROOT/target/release/memwatch"
mkdir -p "$OUTDIR/runs"

TMP="$(mktemp -d)"
ACTIVE_PID=""
ACTIVE_SAMPLER=""
ECHO_PID=""
XRAY_SERVER_PID=""
cleanup() {
    local status=$?
    trap - EXIT
    if (( status != 0 )); then
        mkdir -p "$OUTDIR/diagnostics"
        for log in "$TMP"/*.log; do
            [[ -f "$log" ]] || continue
            cp "$log" "$OUTDIR/diagnostics/$(basename "$log")" 2>/dev/null || true
        done
    fi
    [[ -z "$ACTIVE_SAMPLER" ]] || kill "$ACTIVE_SAMPLER" 2>/dev/null || true
    [[ -z "$ACTIVE_PID" ]] || kill "$ACTIVE_PID" 2>/dev/null || true
    [[ -z "$ECHO_PID" ]] || kill "$ECHO_PID" 2>/dev/null || true
    [[ -z "$XRAY_SERVER_PID" ]] || kill "$XRAY_SERVER_PID" 2>/dev/null || true
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
DECOY_PORT="$(free_port)"
ECHO_PORT="$(free_port)"
SERVER_PORT="$(free_port)"
SOCKS_PORT=""

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -subj "/CN=inner.test" \
    -addext "subjectAltName=DNS:inner.test,DNS:decoy.test" 2>/dev/null
cat > "$TMP/servers.py" <<'PY'
import socket, ssl, sys, threading
decoy, echo, path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
def serve(port, do_echo):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(path + "/cert.pem", path + "/key.pem")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sock = socket.socket(); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port)); sock.listen(64)
    while True:
        raw, _ = sock.accept()
        def handle(conn, listener_port, echo_enabled):
            received = 0
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    while True:
                        data = tls.recv(65536)
                        if not data: break
                        received += len(data)
                        if echo_enabled: tls.sendall(data)
                print(f"TLS peer closed listener={listener_port} echo={echo_enabled} received={received}", flush=True)
            except (OSError, ssl.SSLError) as exc:
                print(f"TLS peer failed listener={listener_port} echo={echo_enabled} received={received} error={type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        threading.Thread(target=handle, args=(raw, port, do_echo), daemon=True).start()
threading.Thread(target=serve, args=(decoy, False), daemon=True).start()
serve(echo, True)
PY
python3 "$TMP/servers.py" "$DECOY_PORT" "$ECHO_PORT" "$TMP" >"$TMP/servers.log" 2>&1 &
ECHO_PID=$!
KEYS="$("$XRAY_BIN" x25519)"
PRIVATE_KEY="$(awk -F': ' '/PrivateKey/{print $2}' <<<"$KEYS")"
PUBLIC_KEY="$(awk -F': ' '/Password|PublicKey/{print $2; exit}' <<<"$(grep -v PrivateKey <<<"$KEYS")")"
UUID="$("$XRAY_BIN" uuid)"
SHORT_ID="0123abcd"
cat > "$TMP/xray-server.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$SERVER_PORT,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"raw","security":"reality",
     "realitySettings":{"target":"127.0.0.1:$DECOY_PORT","serverNames":["decoy.test"],
       "privateKey":"$PRIVATE_KEY","shortIds":["$SHORT_ID"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
JSON
"$XRAY_BIN" run -c "$TMP/xray-server.json" >"$TMP/xray-server.log" 2>&1 &
XRAY_SERVER_PID=$!
server_ready=0
for _ in $(seq 1 300); do
    if python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$SERVER_PORT))==0 else 1)" 2>/dev/null; then server_ready=1; break; fi
    sleep 0.1
done
[[ "$server_ready" == 1 ]] || { cat "$TMP/xray-server.log" >&2; exit 1; }

run_vpn_core() {
    exec "$CLIENT_BIN" --server "vless://$UUID@127.0.0.1:$SERVER_PORT?encryption=none&security=reality&sni=decoy.test&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp&fp=chrome&flow=xtls-rprx-vision" --listen "127.0.0.1:$1"
}
run_xray_rust() {
    local config="$TMP/xray-rust.json"
    python3 - "$1" "$SERVER_PORT" "$UUID" "$PUBLIC_KEY" "$SHORT_ID" "$config" <<'PY'
import json, sys
port, server, uuid, public_key, short_id, path = sys.argv[1:]
config = {"log": {"loglevel": "warning"},
 "inbounds": [{"listen": "127.0.0.1", "port": int(port), "protocol": "socks",
               "settings": {"auth": "noauth", "udp": False}}],
 "outbounds": [{"protocol": "vless", "settings": {
     "vnext": [{"address": "127.0.0.1", "port": int(server),
                "users": [{"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
     "streamSettings": {"network": "raw", "security": "reality",
        "realitySettings": {"serverName": "decoy.test", "publicKey": public_key,
                            "shortId": short_id, "fingerprint": "chrome"}}}]}
with open(path, "w", encoding="utf-8") as stream: json.dump(config, stream, indent=2)
PY
    exec "$XRAY_RUST_BIN" run -config "$config"
}

wait_for_server() {
    local ready=0
    for _ in $(seq 1 300); do
        if python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$SERVER_PORT))==0 else 1)" 2>/dev/null; then ready=1; break; fi
        sleep 0.1
    done
    [[ "$ready" == 1 ]] || { cat "$TMP/xray-server-recovery.log" >&2; return 1; }
}

measure_recovery() {
    local output="$1" result
    # Stop the shared VLESS server, keep the client core alive, and restore the
    # same endpoint before timing the first successful application-level flow.
    kill "$XRAY_SERVER_PID" 2>/dev/null || true
    wait "$XRAY_SERVER_PID" 2>/dev/null || true
    XRAY_SERVER_PID=""
    sleep "$OUTAGE_SECS"
    "$XRAY_BIN" run -c "$TMP/xray-server.json" >"$TMP/xray-server-recovery.log" 2>&1 &
    XRAY_SERVER_PID=$!
    wait_for_server
    result="$(python3 scripts/stage6_recovery_probe.py "$SOCKS_PORT" "$ECHO_PORT" "$RECOVERY_TIMEOUT_SECS" "$RECOVERY_POLL_MS")"
    python3 - "$output.recovery.json" "$result" <<'PY'
import json, sys
path, raw = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump(json.loads(raw), stream, ensure_ascii=False, indent=2)
PY
}

run_case() {
    local engine="$1" output="$2" launcher="$3" ready=0 before after sample
    SOCKS_PORT="$(free_port)"
    "$launcher" "$SOCKS_PORT" >"$TMP/$engine.log" 2>&1 &
    ACTIVE_PID=$!
    for _ in $(seq 1 300); do
        if python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$SOCKS_PORT))==0 else 1)" 2>/dev/null; then ready=1; break; fi
        sleep 0.1
    done
    [[ "$ready" == 1 ]] || { cat "$TMP/$engine.log" >&2; return 1; }
    sleep 2
    local idle_rss cpu_ticks_before cpu_ticks_after
    idle_rss="$(awk '/^VmRSS:/{print $2}' "/proc/$ACTIVE_PID/status")"
    cpu_ticks_before="$(python3 -c 'import sys; f=open(sys.argv[1]).read(); p=f.rsplit(") ",1)[1].split(); print(int(p[11])+int(p[12]))' "/proc/$ACTIVE_PID/stat")"
    "$MEMWATCH" --pid "$ACTIVE_PID" --interval-ms 100 --duration-secs 3600 --csv "$output.rss.csv" >/dev/null 2>&1 &
    ACTIVE_SAMPLER=$!
    if ! sample="$(python3 scripts/stage6_loadgen.py "$SOCKS_PORT" "$CONNS" "$MIB" "$ECHO_PORT")"; then
        echo "load generator failed for $engine; server/client diagnostics are included in the artifact" >&2
        return 1
    fi
    cpu_ticks_after="$(python3 -c 'import sys; f=open(sys.argv[1]).read(); p=f.rsplit(") ",1)[1].split(); print(int(p[11])+int(p[12]))' "/proc/$ACTIVE_PID/stat")"
    kill "$ACTIVE_SAMPLER" 2>/dev/null || true; wait "$ACTIVE_SAMPLER" 2>/dev/null || true; ACTIVE_SAMPLER=""
    python3 - "$engine" "$idle_rss" "$cpu_ticks_before" "$cpu_ticks_after" "$(getconf CLK_TCK)" "$CONNS" "$MIB" "$sample" "$output.json" "$output.rss.csv" <<'PY'
import csv, json, sys
engine, idle, before, after, hz, conns, mib, raw, path, csv_path = sys.argv[1:]
d = json.loads(raw)
cpu_seconds = max(0, int(after) - int(before)) / int(hz)
gib = int(conns) * int(mib) * 2 / 1024
with open(csv_path, newline="", encoding="utf-8") as f: rows = list(csv.DictReader(f))
rss = [int(row["rss_kb"]) for row in rows if row["rss_kb"]]
pss = [int(row["pss_kb"]) for row in rows if row["pss_kb"]]
d.update({"engine": engine, "idle_rss_kb": int(idle),
          "peak_rss_kb": max(rss) if rss else None,
          "peak_pss_kb": max(pss) if pss else None,
          "cpu_ms_per_gib": round(cpu_seconds * 1000 / gib, 2)})
with open(path, "w", encoding="utf-8") as f: json.dump(d, f, ensure_ascii=False, indent=2)
PY
    measure_recovery "$output"
    kill "$ACTIVE_PID" 2>/dev/null || true; wait "$ACTIVE_PID" 2>/dev/null || true; ACTIVE_PID=""
}

for ((run=1; run<=RUNS; run++)); do
    dir="$OUTDIR/runs/run-$(printf '%03d' "$run")"; mkdir -p "$dir"
    if (( run % 2 )); then
        run_case vpn-core "$dir/vpn-core" run_vpn_core
        run_case xray-rust "$dir/xray-rust" run_xray_rust
    else
        run_case xray-rust "$dir/xray-rust" run_xray_rust
        run_case vpn-core "$dir/vpn-core" run_vpn_core
    fi
done

python3 - "$OUTDIR" "$ROOT" "$XRAY_BIN" "$XRAY_RUST_BIN" "$XRAY_RUST_SRC" "$XRAY_RUST_COMMIT" "$XRAY_VERSION" "$RUNS" "$CONNS" "$MIB" <<'PY'
import hashlib, json, os, platform, statistics, subprocess, sys
from pathlib import Path
out, root, xray, xray_rust, source, commit, version, runs, conns, mib = sys.argv[1:]
out, root = Path(out), Path(root)
def sha(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()
def version_line(*cmd): return subprocess.check_output(cmd,text=True,stderr=subprocess.STDOUT).splitlines()[0]
data={engine:[] for engine in ("vpn-core","xray-rust")}
for n in range(1,int(runs)+1):
    folder=out/"runs"/f"run-{n:03d}"
    for engine in data:
        with open(folder/f"{engine}.json",encoding="utf-8") as f: data[engine].append(json.load(f))
metrics=("elapsed_s","throughput_mib_s","first_byte_ms_median","idle_rss_kb","peak_rss_kb","peak_pss_kb","cpu_ms_per_gib")
summary={}
for engine,rows in data.items():
    summary[engine]={}
    for metric in metrics:
        values=[row[metric] for row in rows if row[metric] is not None]
        summary[engine][metric]=({"median":statistics.median(values),"min":min(values),"max":max(values),"samples":values} if values else None)
    recovery=[]
    for n in range(1,int(runs)+1):
        with open(out/"runs"/f"run-{n:03d}"/f"{engine}.recovery.json",encoding="utf-8") as f:
            recovery.append(json.load(f)["recovery_ms"])
    summary[engine]["recovery_ms"]={"median":statistics.median(recovery),"min":min(recovery),"max":max(recovery),"samples":recovery}
cpu=next((line.split(":",1)[1].strip() for line in open("/proc/cpuinfo",encoding="utf-8") if line.startswith("model name")),"unknown")
manifest={"status":"complete","runs":int(runs),"connections":int(conns),"mib_each_direction_per_connection":int(mib),
 "profile":"VLESS + REALITY + XTLS Vision over TCP; Chrome ClientHello; inner TLS 1.3 echo",
 "configuration":{"client_transport":"TCP/raw","reality_sni":"decoy.test","fingerprint":"chrome","vision_flow":"xtls-rprx-vision","server_target":"127.0.0.1 TLS 1.3 echo","payload":"random bytes"},
 "build_profile":"release, locked dependencies; vpn-core reality-client and xray-rust xray-cli",
 "vpn_core_commit":subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip(),
 "xray_rust_commit":commit,"xray_rust_tag":"v0.8.0","xray_core_server_version":version,
 "xray_core_server_binary_sha256":sha(xray),"xray_rust_binary_sha256":sha(xray_rust),
 "os":platform.platform(),"machine":platform.machine(),"cpu_model":cpu,"logical_cpus":os.cpu_count(),
 "rustc_vpn_core":version_line("rustc","--version"),"rustc_xray_rust":subprocess.check_output(["rustc","--version"],cwd=source,text=True).strip(),
 "run_order":[["vpn-core","xray-rust"] if n % 2 else ["xray-rust","vpn-core"] for n in range(1,int(runs)+1)],"summary":summary,
 "recovery_scenario":{"outage":"stop the shared VLESS server process for OUTAGE_SECS, then restart it on the same loopback address and port","metric":"time from server TCP readiness until the first successful SOCKS5 CONNECT plus inner TLS 1.3 echo","poll_interval_ms":int(os.environ["RECOVERY_POLL_MS"]),"outage_secs":int(os.environ["OUTAGE_SECS"]),"timeout_secs":int(os.environ["RECOVERY_TIMEOUT_SECS"]),"client_process_kept_alive":True},
 "limitations":["loopback only; WAN latency, packet loss, energy, and host network-change callback behavior are not measured","recovery is measured after the server becomes TCP-ready and includes polling quantization; it is not full outage duration","CPU metric is client process CPU time per GiB transferred","the Xray-core server and echo service are shared and not included in client RSS/CPU"]}
with open(out/"manifest.json","w",encoding="utf-8") as f: json.dump(manifest,f,ensure_ascii=False,indent=2)
print(json.dumps(summary,ensure_ascii=False,indent=2)); print(f"Raw results and manifest: {out}")
PY
