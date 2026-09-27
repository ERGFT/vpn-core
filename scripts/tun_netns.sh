#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Проверка входа TUN с auto_route в изолированном сетевом пространстве
# (Linux, root). Хост-система не затрагивается: всё происходит в netns.
#
#   [netns rtun: приложение → reality-client (TUN)] ──veth── [хост: Xray, эхо, DNS]
#            10.99.0.2                                          10.99.0.1
#
# Проверяется:
#   1. TCP к IP идёт через TUN → VLESS (Xray) — эхо видит адрес Xray;
#   2. правило direct — напрямую, мимо TUN (метка сокета), без петли;
#   3. UDP через TUN → XUDP;
#   4. DNS на любой адрес (8.8.8.8) перехвачен: настоящий ответ через
#      сервер и fake-IP;
#   5. соединение с fake-IP доходит до сайта по имени;
#   6. после Ctrl+C правила маршрутизации убраны, интерфейса нет;
#   7. после kill -9 сеть работает (таблица TUN пуста);
#   8. route_exclude — мимо TUN;
#   9. strict_route (kill switch): после kill -9 сеть закрыта, после
#      --tun-cleanup — открыта;
#  10. sniffing QUIC: настоящие Initial-пакеты Chromium к IP — домен
#      найден, правило по домену отправляет их direct.
#
# Нужно: root, iproute2, python3, Xray (XRAY_BIN).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ $(id -u) == 0 ]] || { echo "нужен root" >&2; exit 2; }
command -v ip >/dev/null || { echo "нужен iproute2 (ip)" >&2; exit 2; }
XRAY_BIN="${XRAY_BIN:-$ROOT/target/xray/xray}"
[[ -x "$XRAY_BIN" ]] || { echo "нет Xray: $XRAY_BIN" >&2; exit 2; }
if [[ -z "${CLIENT_BIN:-}" ]]; then
    cargo build --release -q -p reality-client
    CLIENT_BIN="$ROOT/target/release/reality-client"
fi

NS=rtun$$
HOST_IP=10.99.0.1
NS_IP=10.99.0.2
TMP="$(mktemp -d)"
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    ip netns del "$NS" 2>/dev/null || true
    ip link del "veth$$" 2>/dev/null || true
    [[ -n "${KEEP_LOGS:-}" ]] && cp "$TMP"/*.log /tmp/ 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT
nsx() { ip netns exec "$NS" "$@"; }

ip netns add "$NS"
ip link add "veth$$" type veth peer name vpeer$$
ip link set "vpeer$$" netns "$NS"
ip addr add "$HOST_IP/24" dev "veth$$"
ip addr add "10.99.0.3/24" dev "veth$$"
ip link set "veth$$" up
nsx ip link set lo up
nsx ip addr add "$NS_IP/24" dev "vpeer$$"
nsx ip link set "vpeer$$" up
nsx ip route add default via "$HOST_IP"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("0.0.0.0",0)); print(s.getsockname()[1])'; }
ECHO=$(free_port); DIRECT_ECHO=$(free_port); EXCL_ECHO=$(free_port); UDPE=$(free_port); DNSUP=$(free_port)
SRV=$(free_port); DECOY=$(free_port)

# Эхо отвечает строкой «PEER <адрес>» — видно, кто соединился: Xray
# (адрес хоста) или клиент напрямую (адрес netns).
cat > "$TMP/hosts.py" <<'PY'
import socket, ssl, struct, sys, threading, subprocess
host, echo, direct_echo, udpe, dnsup, decoy, d, excl = sys.argv[1], *map(int, sys.argv[2:7]), sys.argv[7], int(sys.argv[8])
def tcp_echo(port, bind=None):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind or host, port)); s.listen(64)
    def h(c, a):
        c.sendall(f"PEER {a[0]}\n".encode())
        while True:
            b = c.recv(65536)
            if not b: break
            c.sendall(b)
    while True:
        c, a = s.accept(); threading.Thread(target=h, args=(c, a), daemon=True).start()
def udp_echo():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((host, udpe))
    while True:
        b, a = u.recvfrom(65536); u.sendto(f"PEER {a[0]} ".encode() + b, a)
def dns():
    # На любое имя: A 10.99.0.1.
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((host, dnsup))
    while True:
        q, a = u.recvfrom(4096)
        i = 12
        while q[i] != 0: i += 1 + q[i]
        qend = i + 5
        ans = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">I", 60) + b"\x00\x04" + socket.inet_aton(host)
        u.sendto(q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:qend] + ans, a)
def decoy_tls():
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-days", "1", "-keyout", d + "/k.pem", "-out", d + "/c.pem", "-subj", "/CN=decoy.test",
        "-addext", "subjectAltName=DNS:decoy.test"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(d + "/c.pem", d + "/k.pem")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", decoy)); s.listen(16)
    while True:
        c, _ = s.accept()
        try: ctx.wrap_socket(c, server_side=True).close()
        except Exception: pass
for f, a in [(tcp_echo, (echo,)), (tcp_echo, (direct_echo,)), (tcp_echo, (excl, "10.99.0.3")), (udp_echo, ()), (dns, ()), (decoy_tls, ())]:
    threading.Thread(target=f, args=a, daemon=True).start()
threading.Event().wait()
PY
python3 "$TMP/hosts.py" "$HOST_IP" "$ECHO" "$DIRECT_ECHO" "$UDPE" "$DNSUP" "$DECOY" "$TMP" "$EXCL_ECHO" &
PIDS+=($!)

KEYS="$("$XRAY_BIN" x25519)"
PRIV="$(awk -F': ' '/PrivateKey/{print $2}' <<<"$KEYS")"
PBK="$(awk -F': ' '/Password|PublicKey/{print $2; exit}' <<<"$(grep -v PrivateKey <<<"$KEYS")")"
UUID="$("$XRAY_BIN" uuid)"
SID="0123abcd"
cat > "$TMP/server.json" <<JSON
{"log":{"loglevel":"warning"},
 "dns":{"hosts":{"fake-site.test":"$HOST_IP"}},
 "inbounds":[{"listen":"$HOST_IP","port":$SRV,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"raw","security":"reality",
     "realitySettings":{"target":"127.0.0.1:$DECOY","serverNames":["decoy.test"],
       "privateKey":"$PRIV","shortIds":["$SID"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4",
   "finalRules":[{"action":"allow","ip":["10.99.0.0/24","127.0.0.0/8"]}]}}]}
JSON
"$XRAY_BIN" run -c "$TMP/server.json" > "$TMP/xray.log" 2>&1 &
PIDS+=($!)
sleep 1

LINK="vless://$UUID@$HOST_IP:$SRV?encryption=none&security=reality&sni=decoy.test&fp=chrome&pbk=$PBK&sid=$SID&type=tcp&flow=xtls-rprx-vision"
cat > "$TMP/client.toml" <<TOML
[[inbounds]]
type = "tun"
tag = "tun"
interface_name = "rtun0"
route_exclude = ["10.99.0.3/32"]
sniff = true

[[outbounds]]
tag = "proxy"
type = "vless"
link = "$LINK"

[[outbounds]]
tag = "direct"
type = "direct"

[[route.rules]]
port = [$DIRECT_ECHO]
outbound = "direct"

[[route.rules]]                # QUIC к www.example.test — найден по ClientHello
domain = ["www.example.test"]
network = "udp"
outbound = "direct"

[route]
final = "proxy"

[dns]
final = "fake"

[[dns.servers]]
tag = "fake"
address = "fakeip"

[[dns.servers]]
tag = "remote"
address = "udp://$HOST_IP:$DNSUP"
detour = "proxy"

[[dns.rules]]
domain_suffix = ["real.test"]
server = "remote"
TOML

start_client() {
    # Без функции-обёртки: $! должен быть самим клиентом (ip netns exec
    # заменяет себя им), иначе сигнал уйдёт подоболочке.
    ip netns exec "$NS" "$CLIENT_BIN" --config "$TMP/client.toml" > "$TMP/client.log" 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    for _ in $(seq 1 100); do grep -q 'весь трафик направлен в TUN' "$TMP/client.log" && return; sleep 0.1; done
    echo "клиент не поднял TUN:"; cat "$TMP/client.log"; exit 1
}
start_client

QUIC_HEX="$ROOT/core/src/app/testdata/chromium140_quic_initial.hex"
nsx python3 - "$HOST_IP" "$ECHO" "$DIRECT_ECHO" "$UDPE" "$EXCL_ECHO" "$QUIC_HEX" <<'PY' || { cat "$TMP/client.log"; exit 1; }
import os, socket, struct, sys
host, echo, direct_echo, udpe, excl = sys.argv[1], *map(int, sys.argv[2:6])
quic = [bytes.fromhex(l.strip()) for l in open(sys.argv[6]) if l.strip()]
def tcp(addr, port, data=b"hello over tun"):
    s = socket.create_connection((addr, port), timeout=15)
    f = s.makefile("rb"); peer = f.readline().decode().split()[1]
    s.sendall(data); got = b""
    while len(got) < len(data):
        b = s.recv(65536); assert b; got += b
    assert got == data; s.close(); return peer

peer = tcp(host, echo)
assert peer == host, f"TCP должен идти через Xray (эхо видит {peer})"
print("OK: TCP через TUN → VLESS (Xray)")
big = os.urandom(2 * 1024 * 1024)
assert tcp(host, echo, big) == host
print("OK: 2 МиБ через TUN без искажений")
import time
data = os.urandom(32 * 1024 * 1024)
s = socket.create_connection((host, echo), timeout=60); s.makefile("rb").readline()
t0 = time.time()
import threading
def w(): s.sendall(data)
th = threading.Thread(target=w); th.start()
got = 0
while got < len(data):
    b = s.recv(1 << 20); assert b; got += len(b)
th.join(); dt = time.time() - t0
print(f"OK: 32 МиБ туда и обратно через TUN + VLESS за {dt:.1f} с ({2*32/dt:.0f} МиБ/с)")
assert dt < 60

peer = tcp(host, direct_echo)
assert peer == "10.99.0.2", f"direct должен идти напрямую (эхо видит {peer})"
print("OK: правило direct — напрямую, мимо TUN, без петли")
peer = tcp("10.99.0.3", excl)
assert peer == "10.99.0.2", f"route_exclude должен идти мимо TUN (эхо видит {peer})"
print("OK: route_exclude — мимо TUN")

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(15)
for i in range(5):
    u.sendto(b"udp-%d" % i, (host, udpe))
    b, _ = u.recvfrom(4096)
    assert b.startswith(f"PEER {host} ".encode()) and b.endswith(b"udp-%d" % i), b
print("OK: UDP через TUN → XUDP (Xray)")

q = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); q.settimeout(15)
for d in quic[:2]:
    q.sendto(d, (host, udpe))
for d in quic[:2]:
    b, _ = q.recvfrom(4096)
    assert b.startswith(b"PEER 10.99.0.2 "), f"QUIC к www.example.test должен идти direct: {b[:40]}"
print("OK: sniffing QUIC — домен из ClientHello Chromium, правило direct")

def dns(name, server="8.8.8.8"):
    q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); d.settimeout(15)
    d.sendto(q, (server, 53)); a, _ = d.recvfrom(4096)
    assert a[:2] == b"\xab\xcd" and a[3] & 15 == 0, a
    return socket.inet_ntoa(a[-4:])
ip = dns("www.real.test")
assert ip == host, ip
print("OK: DNS к 8.8.8.8 перехвачен, настоящий ответ — через сервер")
fake = dns("fake-site.test", "1.2.3.4")
assert fake.startswith("198.18."), fake
print(f"OK: fake-IP {fake}")
assert tcp(fake, echo) == host
print("OK: соединение с fake-IP дошло до сайта по имени (через Xray)")
PY

# 6. Ctrl+C: правила и интерфейс убраны.
kill -INT "$CLIENT_PID"
for _ in $(seq 1 50); do kill -0 "$CLIENT_PID" 2>/dev/null || break; sleep 0.1; done
grep -q 'маршруты возвращены' "$TMP/client.log" || { cat "$TMP/client.log"; exit 1; }
if nsx ip rule | grep -q 'lookup 2022'; then echo "правила TUN остались"; nsx ip rule; exit 1; fi
if nsx ip link show rtun0 >/dev/null 2>&1; then echo "интерфейс остался"; exit 1; fi
nsx python3 -c "import socket; s=socket.create_connection(('$HOST_IP',$ECHO),5); assert s.recv(64).startswith(b'PEER 10.99.0.2')"
echo "OK: после Ctrl+C маршруты убраны, сеть напрямую"

# 7. kill -9: интерфейс исчезает, таблица пустеет — сеть работает.
start_client
kill -9 "$CLIENT_PID"; wait "$CLIENT_PID" 2>/dev/null || true; sleep 0.3
nsx python3 -c "import socket; s=socket.create_connection(('$HOST_IP',$ECHO),5); assert s.recv(64).startswith(b'PEER 10.99.0.2')"
echo "OK: после kill -9 сеть работает (таблица TUN пуста)"
# Следующий запуск убирает остатки правил сам.
start_client
kill -INT "$CLIENT_PID"; sleep 1
if nsx ip rule | grep -q 'lookup 2022'; then echo "остатки правил не убраны"; nsx ip rule; exit 1; fi
echo "OK: остатки прошлого запуска убраны"

# 9. strict_route: kill switch.
sed -i 's/^route_exclude = .*/strict_route = true/' "$TMP/client.toml"
start_client
nsx python3 -c "import socket; s=socket.create_connection(('$HOST_IP',$ECHO),5); assert s.recv(64).startswith(b'PEER $HOST_IP')"
kill -9 "$CLIENT_PID"; wait "$CLIENT_PID" 2>/dev/null || true; sleep 0.3
if nsx python3 -c "import socket; socket.create_connection(('$HOST_IP',$ECHO),3)" 2>/dev/null; then
    echo "strict_route: после kill -9 трафик пошёл мимо туннеля"; exit 1
fi
echo "OK: strict_route — после kill -9 сеть закрыта"
nsx "$CLIENT_BIN" --tun-cleanup
nsx python3 -c "import socket; s=socket.create_connection(('$HOST_IP',$ECHO),5); assert s.recv(64).startswith(b'PEER 10.99.0.2')"
echo "OK: --tun-cleanup открыл сеть"
echo "TUN (netns) PASSED"
