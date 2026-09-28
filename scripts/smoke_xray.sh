#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Сквозной smoke-тест готового бинарника против НАСТОЯЩЕГО Xray-core в
# самой распространённой боевой конфигурации: VLESS + REALITY + XTLS
# Vision. Всё как у пользователя: `reality-client` получает vless://-ссылку
# и поднимает SOCKS5 с логином/паролем, а «приложение» на Python:
#   1. проходит аутентификацию SOCKS5 (RFC 1929), неверный пароль отвергается;
#   2. открывает CONNECT и делает внутри настоящий TLS 1.3 до эхо-сервера,
#      1 МиБ туда и обратно — это «TLS в TLS», на котором Vision
#      переключается на прямую передачу (проверяется по журналу клиента);
#   3. через UDP ASSOCIATE шлёт 20 датаграмм UDP-эхо-серверу (клиент
#      везёт их через XUDP — как клиент Xray, единственный способ UDP
#      для Vision-аккаунта).
#
# Нужно: Xray ($XRAY_BIN или target/xray/xray — scripts/fetch_xray.sh или
# scripts/build_xray_from_source.sh), openssl, python3.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
XRAY_BIN="${XRAY_BIN:-$ROOT/target/xray/xray}"
[[ -x "$XRAY_BIN" ]] || { echo "нет Xray: $XRAY_BIN" >&2; exit 2; }

# CLIENT_BIN — готовый бинарник (например, собранный под Windows), тогда
# сборка пропускается; CLIENT_RUNNER — чем его запускать (например, wine).
if [[ -z "${CLIENT_BIN:-}" ]]; then
    cargo build --release -q -p reality-client
    CLIENT_BIN="$ROOT/target/release/reality-client"
fi
CLIENT_RUNNER="${CLIENT_RUNNER:-}"

TMP="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
[[ -n "${KEEP_LOGS:-}" ]] && trap 'cp "$TMP"/*.log /tmp/ 2>/dev/null; cleanup' EXIT

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
DECOY_PORT="$(free_port)"; ECHO_PORT="$(free_port)"; UDP_PORT="$(free_port)"
SRV_PORT="$(free_port)"; SOCKS_PORT="$(free_port)"

# Сертификат для «сайта прикрытия» и внутреннего TLS-эхо-сервера.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -subj "/CN=inner.test" \
    -addext "subjectAltName=DNS:inner.test,DNS:decoy.test" 2>/dev/null

# Вспомогательные серверы: сайт прикрытия (TLS 1.3), TLS-эхо, UDP-эхо.
cat > "$TMP/servers.py" <<'PY'
import socket, ssl, sys, threading
decoy, echo, udp, d = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
def tls_server(port, do_echo):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d + "/cert.pem", d + "/key.pem")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(64)
    def handle(c):
        try:
            t = ctx.wrap_socket(c, server_side=True)
            while True:
                b = t.recv(65536)
                if not b: break
                if do_echo: t.sendall(b)
        except Exception:
            pass
    while True:
        c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
def udp_echo():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", udp))
    while True:
        b, a = u.recvfrom(65536); u.sendto(b, a)
threading.Thread(target=tls_server, args=(decoy, False), daemon=True).start()
threading.Thread(target=udp_echo, daemon=True).start()
tls_server(echo, True)
PY
python3 "$TMP/servers.py" "$DECOY_PORT" "$ECHO_PORT" "$UDP_PORT" "$TMP" &
PIDS+=($!)

KEYS="$("$XRAY_BIN" x25519)"
PRIV="$(awk -F': ' '/PrivateKey/{print $2}' <<<"$KEYS")"
PBK="$(awk -F': ' '/Password|PublicKey/{print $2; exit}' <<<"$(grep -v PrivateKey <<<"$KEYS")")"
UUID="$("$XRAY_BIN" uuid)"
SID="0123abcd"
cat > "$TMP/server.json" <<JSON
{"log":{"loglevel":"${XRAY_LOGLEVEL:-warning}"},
 "inbounds":[{"listen":"127.0.0.1","port":$SRV_PORT,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"raw","security":"reality",
     "realitySettings":{"target":"127.0.0.1:$DECOY_PORT","serverNames":["decoy.test"],
       "privateKey":"$PRIV","shortIds":["$SID"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
JSON
"$XRAY_BIN" run -c "$TMP/server.json" > "$TMP/xray.log" 2>&1 &
PIDS+=($!)

LINK="vless://$UUID@127.0.0.1:$SRV_PORT?encryption=none&security=reality&sni=decoy.test&fp=chrome&pbk=$PBK&sid=$SID&type=tcp&flow=xtls-rprx-vision#smoke"
# Отказы при запуске: ссылка без шифрования и прокси в сеть с коротким паролем.
NONE_LINK="vless://$UUID@127.0.0.1:$SRV_PORT?encryption=none&security=none&type=tcp"
if $CLIENT_RUNNER "$CLIENT_BIN" --server "$NONE_LINK" --listen 127.0.0.1:0 > "$TMP/none.log" 2>&1; then
    echo "ссылка security=none должна отвергаться без --allow-insecure"; exit 1
fi
grep -q 'allow-insecure' "$TMP/none.log" || { cat "$TMP/none.log"; exit 1; }
echo "OK: ссылка без шифрования отвергнута без --allow-insecure"
if $CLIENT_RUNNER "$CLIENT_BIN" --server "$LINK" --listen 0.0.0.0:0 --auth "u:short" > "$TMP/weak.log" 2>&1; then
    echo "прокси в сеть с коротким паролем должен отвергаться"; exit 1
fi
grep -q 'короче' "$TMP/weak.log" || { cat "$TMP/weak.log"; exit 1; }
echo "OK: прокси в сеть с коротким паролем не запускается"

# Ссылка и пароль — из файлов, а не из командной строки (там их видят
# все пользователи машины).
printf '%s\n' "$LINK" > "$TMP/link.txt"
printf 'smoke:s3cret\n' > "$TMP/auth.txt"
RUST_LOG="info,reality_core::vless::vision=debug" $CLIENT_RUNNER "$CLIENT_BIN" --server-file "$TMP/link.txt" \
    --listen "127.0.0.1:$SOCKS_PORT" --auth-file "$TMP/auth.txt" > "$TMP/client.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 300); do grep -q 'прокси слушает' "$TMP/client.log" && break; sleep 0.1; done
for _ in $(seq 1 100); do python3 -c "import socket; socket.create_connection(('127.0.0.1',$SRV_PORT),1)" 2>/dev/null && break; sleep 0.1; done

python3 - "$SOCKS_PORT" "$ECHO_PORT" "$UDP_PORT" "$TMP/cert.pem" <<'PY'
import os, socket, ssl, struct, sys
socks, echo, udp, ca = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]

def greet(user, pw):
    s = socket.create_connection(("127.0.0.1", socks), timeout=30)
    s.sendall(b"\x05\x01\x02")
    assert s.recv(2) == b"\x05\x02", "сервер должен требовать логин/пароль"
    s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
    return s, s.recv(2)

# Молчащий клиент не должен держать соединение вечно.
import time
idle = socket.create_connection(("127.0.0.1", socks), timeout=30)
t0 = time.time()
assert idle.recv(1) == b"", "молчащее соединение должно закрываться"
assert time.time() - t0 < 20, "таймаут приветствия SOCKS5 слишком длинный"
print(f"OK: молчащий клиент отключён через {time.time() - t0:.0f} с")

s, st = greet(b"smoke", b"wrong")
assert st == b"\x01\x01", f"неверный пароль должен отвергаться: {st!r}"
s.close()
print("OK: неверный пароль SOCKS5 отвергнут")

# Блокировка адреса после серии неверных паролей. Отдельный адрес
# источника (127.0.0.2), чтобы не заблокировать остальные проверки.
def greet_from(src, user, pw):
    c = socket.socket()
    c.settimeout(30)
    c.bind((src, 0))
    c.connect(("127.0.0.1", socks))
    try:
        c.sendall(b"\x05\x01\x02")
        if c.recv(2) != b"\x05\x02":
            return None
        c.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
        return c.recv(2)
    except OSError:
        return None
    finally:
        c.close()

for i in range(5):
    assert greet_from("127.0.0.2", b"smoke", b"guess%d" % i) == b"\x01\x01"
assert greet_from("127.0.0.2", b"smoke", b"s3cret") is None, \
    "после 5 неверных паролей адрес должен быть заблокирован даже для верного"
st = greet_from("127.0.0.1", b"smoke", b"s3cret")
assert st == b"\x01\x00", f"блокировка не должна задевать другие адреса: {st!r}"
print("OK: после 5 неверных паролей адрес заблокирован, другие адреса работают")

# CONNECT + внутренний TLS 1.3, 1 МиБ в обе стороны.
s, st = greet(b"smoke", b"s3cret")
assert st == b"\x01\x00", f"верный пароль должен приниматься: {st!r}"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo))
rep = s.recv(10)
assert rep[:2] == b"\x05\x00", f"CONNECT отклонён: {rep!r}"
ctx = ssl.create_default_context(cafile=ca)
t = ctx.wrap_socket(s, server_hostname="inner.test")
# Поочерёдно: кусок туда — кусок обратно (объект SSL в Python нельзя
# одновременно читать и писать из разных потоков).
data = os.urandom(1024 * 1024)
got = bytearray()
for off in range(0, len(data), 16384):
    chunk = data[off:off + 16384]
    t.sendall(chunk)
    need = len(got) + len(chunk)
    while len(got) < need:
        b = t.recv(65536)
        if not b: break
        got += b
    if len(got) < need: break
assert bytes(got) == data, f"эхо через Vision не совпало: {len(got)} из {len(data)} байт"
t.close()
print("OK: 1 МиБ внутреннего TLS прошли через SOCKS5 -> REALITY -> Vision -> VLESS и вернулись без искажений")

# UDP ASSOCIATE.
c, st = greet(b"smoke", b"s3cret")
assert st == b"\x01\x00"
c.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
rep = c.recv(10)
assert rep[:2] == b"\x05\x00", f"UDP ASSOCIATE отклонён: {rep!r}"
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(10)
hdr = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", udp)
for i in range(20):
    payload = os.urandom(50 + i * 60)
    u.sendto(hdr + payload, relay)
    back, _ = u.recvfrom(65536)
    assert back[:10] == hdr and back[10:] == payload, f"UDP-датаграмма {i} не совпала"
c.close()
print("OK: 20 UDP-датаграмм прошли через SOCKS5 UDP ASSOCIATE -> XUDP (Vision) и вернулись")
PY

grep -q 'UDP: XUDP-поток открыт' "$TMP/client.log" \
    || { echo "UDP шёл не через XUDP:"; cat "$TMP/client.log"; exit 1; }
echo "OK: UDP шёл через XUDP"

# Направления переключаются независимо. Приём переключается всегда
# (сервер отдаёт ответы целыми TLS-рекордами). Отправка — как и у
# клиента Xray — только если приложение записало целый рекорд
# прикладных данных одним куском; поочерёдная запись по 16 КиБ выше
# это обычно даёт, но гарантии нет — поэтому только сообщаем.
grep -q 'приём переключён на прямую передачу' "$TMP/client.log" \
    || { echo "Vision не переключил приём на прямую передачу:"; grep -v 'Vision: padding' "$TMP/client.log"; exit 1; }
echo "OK: Vision переключил приём на прямую передачу"
if grep -q 'отправка переключена на прямую передачу' "$TMP/client.log"; then
    echo "OK: Vision переключил и отправку на прямую передачу"
else
    echo "(отправка осталась с padding'ом — приложение не записало ни одного целого рекорда разом)"
fi
# Файл настроек вместо ключей: относительный путь к ссылке, проверка
# --check, опечатка в поле — ошибка, затем TLS-эхо через выход vless.
SOCKS2_PORT="$(free_port)"; DNS_IN_PORT="$(free_port)"; DNS_UP_PORT="$(free_port)"
# «DNS-сервер интернета» для проверки DNS через Xray: на любое имя A 10.20.30.40.
cat > "$TMP/dns_up.py" <<'PY'
import socket, struct, sys
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    q, a = u.recvfrom(4096)
    i = 12
    while q[i] != 0: i += 1 + q[i]
    qend = i + 5
    hdr = q[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    ans = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">I", 60) + b"\x00\x04" + bytes([10, 20, 30, 40])
    u.sendto(hdr + q[12:qend] + ans, a)
PY
python3 "$TMP/dns_up.py" "$DNS_UP_PORT" &
PIDS+=($!)
mkdir -p "$TMP/conf"
cp "$TMP/link.txt" "$TMP/conf/server.txt"
# Формат sing-box; сервер — ссылкой из файла (расширение link_file).
cat > "$TMP/conf/client.json" <<JSON
{
  "inbounds": [
    { "type": "mixed", "listen": "127.0.0.1", "listen_port": $SOCKS2_PORT },
    { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": $DNS_IN_PORT }
  ],
  "outbounds": [
    { "type": "vless", "tag": "proxy", "link_file": "server.txt" },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [
      { "inbound": ["dns-in"], "action": "hijack-dns" },
      { "domain_suffix": ["blocked.test"], "outbound": "block" }
    ],
    "final": "proxy"
  },
  // DNS: запросы уходят через сервер VLESS (XUDP через Xray).
  "dns": { "servers": [{ "type": "udp", "tag": "remote", "server": "127.0.0.1", "server_port": $DNS_UP_PORT, "detour": "proxy" }] }
}
JSON
$CLIENT_RUNNER "$CLIENT_BIN" --config "$TMP/conf/client.json" --check > "$TMP/check.log" 2>&1 \
    || { echo "--check отверг правильный файл настроек:"; cat "$TMP/check.log"; exit 1; }
sed 's/"link_file"/"link_fiel"/' "$TMP/conf/client.json" > "$TMP/conf/typo.json"
if $CLIENT_RUNNER "$CLIENT_BIN" --config "$TMP/conf/typo.json" --check > "$TMP/typo.log" 2>&1; then
    echo "опечатка в файле настроек должна быть ошибкой"; exit 1
fi
grep -q 'link_fiel' "$TMP/typo.log" || { cat "$TMP/typo.log"; exit 1; }
# Тот же сервер в формате Xray-core: полями, как пишут v2rayN и панели.
cat > "$TMP/conf/xray.json" <<JSON
{
  "inbounds": [{ "protocol": "socks", "listen": "127.0.0.1", "port": $SOCKS2_PORT }],
  "outbounds": [{
    "tag": "proxy", "protocol": "vless",
    "settings": { "vnext": [{ "address": "127.0.0.1", "port": $SRV_PORT,
                              "users": [{ "id": "$UUID", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
    "streamSettings": { "network": "raw", "security": "reality",
                        "realitySettings": { "serverName": "decoy.test", "fingerprint": "chrome",
                                             "publicKey": "$PBK", "shortId": "$SID" } }
  }]
}
JSON
$CLIENT_RUNNER "$CLIENT_BIN" --config "$TMP/conf/xray.json" --check > "$TMP/check-xray.log" 2>&1 \
    || { echo "--check отверг настройки Xray:"; cat "$TMP/check-xray.log"; exit 1; }
echo "OK: --check (sing-box и Xray) и опечатки в файле настроек"
$CLIENT_RUNNER "$CLIENT_BIN" --config "$TMP/conf/client.json" > "$TMP/client2.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 300); do grep -q 'прокси слушает' "$TMP/client2.log" && break; sleep 0.1; done
python3 - "$SOCKS2_PORT" "$ECHO_PORT" "$TMP/cert.pem" "$DNS_IN_PORT" <<'PY' || { cat "$TMP/client2.log"; exit 1; }
import os, socket, ssl, struct, sys
socks, echo, ca, dns_in = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4])

# DNS-вход: вопрос уходит «DNS-серверу интернета» через Xray.
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(20)
q = b"\xbe\xef\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x04test\x00" + b"\x00\x01\x00\x01"
u.sendto(q, ("127.0.0.1", dns_in))
a, _ = u.recvfrom(4096)
assert a[:2] == b"\xbe\xef" and a[3] & 0x0f == 0, a
assert a.endswith(bytes([10, 20, 30, 40])), a
print("OK: --config: DNS-вход, запрос через выход vless (XUDP через Xray)")
s = socket.create_connection(("127.0.0.1", socks), timeout=30)
s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo))
rep = s.recv(10); assert rep[:2] == b"\x05\x00", rep
ctx = ssl.create_default_context(cafile=ca)
t = ctx.wrap_socket(s, server_hostname="inner.test")
data = os.urandom(64 * 1024); t.sendall(data)
got = b""
while len(got) < len(data):
    b = t.recv(65536); assert b; got += b
assert got == data
print("OK: --config: 64 КиБ TLS-эха через выход vless")

# HTTP CONNECT на том же порту (mixed) — тоже через Xray.
s = socket.create_connection(("127.0.0.1", socks), timeout=30)
s.sendall(f"CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n".encode())
head = b""
while not head.endswith(b"\r\n\r\n"):
    b = s.recv(1); assert b; head += b
assert head.startswith(b"HTTP/1.1 200"), head
t = ctx.wrap_socket(s, server_hostname="inner.test")
t.sendall(b"http-connect"); assert t.recv(64) == b"http-connect"
print("OK: --config: HTTP CONNECT (mixed) через выход vless")

# Правило: домен под block — SOCKS5 отвечает 0x02, HTTP — 403.
s = socket.create_connection(("127.0.0.1", socks), timeout=30)
s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
name = b"ads.blocked.test"
s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", 443))
assert s.recv(10)[1] == 2
s = socket.create_connection(("127.0.0.1", socks), timeout=30)
s.sendall(b"CONNECT ads.blocked.test:443 HTTP/1.1\r\n\r\n")
assert s.recv(64).startswith(b"HTTP/1.1 403")
print("OK: --config: правило block для домена (SOCKS5 0x02, HTTP 403)")
PY
# Настройки в формате Xray-core — тот же трафик (REALITY + Vision) через Xray.
SOCKS4_PORT="$(free_port)"
sed "s/\"port\": $SOCKS2_PORT/\"port\": $SOCKS4_PORT/" "$TMP/conf/xray.json" > "$TMP/conf/xray-run.json"
$CLIENT_RUNNER "$CLIENT_BIN" --config "$TMP/conf/xray-run.json" > "$TMP/client-xray.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 300); do grep -q 'прокси слушает' "$TMP/client-xray.log" && break; sleep 0.1; done
python3 - "$SOCKS4_PORT" "$ECHO_PORT" "$TMP/cert.pem" <<'PY' || { cat "$TMP/client-xray.log"; exit 1; }
import os, socket, ssl, struct, sys
socks, echo, ca = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.create_connection(("127.0.0.1", socks), timeout=30)
s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo))
rep = s.recv(10); assert rep[:2] == b"\x05\x00", rep
t = ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="inner.test")
data = os.urandom(64 * 1024); t.sendall(data)
got = b""
while len(got) < len(data):
    b = t.recv(65536); assert b; got += b
assert got == data
print("OK: настройки Xray-core: 64 КиБ TLS-эха через REALITY + Vision")
PY
# Фаза 4: группа urltest из «мёртвого» сервера и сервера из подписки.
# Подписка — HTTPS-панель на 127.0.0.1 со своим сертификатом, в ответе
# base64 со ссылкой на Xray; проверка групп идёт через Xray к HTTP-серверу.
PANEL_PORT="$(free_port)"; PROBE_PORT="$(free_port)"; SOCKS3_PORT="$(free_port)"; DEAD_PORT="$(free_port)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -keyout "$TMP/panel-key.pem" -out "$TMP/conf/panel-ca.pem" -subj "/CN=panel" \
    -addext "subjectAltName=IP:127.0.0.1" -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null
cat > "$TMP/panel.py" <<'PY'
import base64, http.server, ssl, sys, threading
panel, probe, d, link = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
class Panel(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/sub/tok":
            self.send_response(404); self.end_headers(); return
        body = base64.b64encode((link + "\nvmess://e30=\n").encode())
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
class Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
p = http.server.ThreadingHTTPServer(("127.0.0.1", panel), Panel)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(d + "/conf/panel-ca.pem", d + "/panel-key.pem")
p.socket = ctx.wrap_socket(p.socket, server_side=True)
threading.Thread(target=p.serve_forever, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", probe), Probe).serve_forever()
PY
python3 "$TMP/panel.py" "$PANEL_PORT" "$PROBE_PORT" "$TMP" "${LINK%#*}#from-panel" &
PIDS+=($!)
echo "https://127.0.0.1:$PANEL_PORT/sub/tok" > "$TMP/conf/sub.txt"
cat > "$TMP/conf/groups.json" <<JSON
{
  "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": $SOCKS3_PORT }],
  "outbounds": [
    { "type": "urltest", "tag": "auto", "outbounds": ["dead"], "subscriptions": ["panel"],
      "url": "http://127.0.0.1:$PROBE_PORT/generate_204", "interval": "10s" },
    { "type": "vless", "tag": "dead", "server": "127.0.0.1", "server_port": $DEAD_PORT, "uuid": "$UUID",
      "tls": { "enabled": true, "server_name": "decoy.test",
               "reality": { "enabled": true, "public_key": "$PBK", "short_id": "$SID" } } },
    { "type": "direct", "tag": "direct" }
  ],
  "subscriptions": [{ "tag": "panel", "url_file": "sub.txt", "ca_file": "panel-ca.pem", "detour": "direct" }],
  "route": { "final": "auto" }
}
JSON
sleep 0.5
$CLIENT_RUNNER "$CLIENT_BIN" --config "$TMP/conf/groups.json" > "$TMP/client3.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 300); do grep -q 'группа: переключение' "$TMP/client3.log" && break; sleep 0.1; done
grep -q 'подписка обновлена' "$TMP/client3.log" || { echo "подписка не загрузилась:"; cat "$TMP/client3.log"; exit 1; }
grep -q 'member="\?panel/from-panel' "$TMP/client3.log" || { echo "urltest не выбрал сервер из подписки:"; cat "$TMP/client3.log"; exit 1; }
if grep -q 'sub/tok' "$TMP/client3.log"; then echo "адрес подписки попал в журнал"; exit 1; fi
[[ -f "$TMP/conf/panel.subscription" ]] || { echo "список подписки не сохранён"; exit 1; }
python3 - "$SOCKS3_PORT" "$ECHO_PORT" "$TMP/cert.pem" <<'PY' || { cat "$TMP/client3.log"; exit 1; }
import socket, ssl, struct, sys
socks, echo, ca = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.create_connection(("127.0.0.1", socks), timeout=30)
s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo))
rep = s.recv(10); assert rep[:2] == b"\x05\x00", rep
t = ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="inner.test")
t.sendall(b"group"); assert t.recv(64) == b"group"
print("OK: подписка (HTTPS, base64) → urltest выбрал её сервер → TLS-эхо через Xray")
PY
echo "SMOKE (Xray) PASSED"
