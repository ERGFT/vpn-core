#!/usr/bin/env bash
# Сквозной smoke-тест готового продукта: собранный бинарник
# `reality-client` запускается так же, как его запускает пользователь
# (vless://-ссылка + локальный SOCKS5), а на той стороне — настоящий
# REALITY-сервер на библиотеке github.com/xtls/reality
# (interop/go-reality-server). Приложение-"браузер" изображает маленький
# SOCKS5-клиент на Python: CONNECT, отправка данных, проверка эха.
#
# В отличие от cargo-тестов, здесь проверяется всё вместе: разбор ссылки
# в CLI, SOCKS5-сервер, REALITY-рукопожатие, VLESS, релей — одним
# процессом, как в реальной работе.
#
# Нужно: собранный Go-стенд (scripts/interop_go_reality.sh собирает его в
# target/go-reality-server; путь можно переопределить через
# REALITY_GO_SERVER), openssl, python3.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SERVER_BIN="${REALITY_GO_SERVER:-$ROOT/target/go-reality-server}"
[[ -x "$SERVER_BIN" ]] || { echo "нет Go-стенда: $SERVER_BIN (сначала scripts/interop_go_reality.sh)" >&2; exit 2; }

cargo build --release -q -p reality-client
CLIENT_BIN="$ROOT/target/release/reality-client"

TMP="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

# Ключи сервера REALITY (X25519) и параметры ссылки.
openssl genpkey -algorithm X25519 -out "$TMP/k.pem" 2>/dev/null
PRIV_HEX="$(openssl pkey -in "$TMP/k.pem" -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')"
PBK="$(openssl pkey -in "$TMP/k.pem" -pubout -outform DER | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SID="0123abcd"

"$SERVER_BIN" -private-key "$PRIV_HEX" -short-id "$SID" -uuid "$UUID" -sni example.com > "$TMP/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 300); do grep -q '^READY ' "$TMP/server.log" && break; sleep 0.1; done
SRV_PORT="$(grep -m1 '^READY ' "$TMP/server.log" | cut -d' ' -f2)"
[[ -n "$SRV_PORT" ]] || { echo "Go-стенд не стартовал:"; cat "$TMP/server.log"; exit 1; }

SOCKS_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
LINK="vless://$UUID@127.0.0.1:$SRV_PORT?encryption=none&security=reality&sni=example.com&pbk=$PBK&sid=$SID&type=tcp&fp=chrome#smoke"

# CLIENT_WRAPPER — необязательная обёртка запуска клиента, например
#   CLIENT_WRAPPER="valgrind --error-exitcode=99 --log-file=/tmp/vg.log"
# (так проверяется release-бинарник под memcheck на живом трафике).
# SMOKE_CONNECTIONS — сколько соединений подряд (по умолчанию 1).
read -r -a WRAP <<< "${CLIENT_WRAPPER:-}"
"${WRAP[@]}" "$CLIENT_BIN" --server "$LINK" --listen "127.0.0.1:$SOCKS_PORT" > "$TMP/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=($CLIENT_PID)
for _ in $(seq 1 300); do grep -q 'прокси слушает' "$TMP/client.log" && break; sleep 0.1; done

python3 - "$SOCKS_PORT" "${SMOKE_CONNECTIONS:-1}" <<'PY'
import socket, sys, os
port, n = int(sys.argv[1]), int(sys.argv[2])
total = 0
for i in range(n):
    s = socket.create_connection(("127.0.0.1", port), timeout=60)
    s.sendall(b"\x05\x01\x00")                  # приветствие: без аутентификации
    assert s.recv(2) == b"\x05\x00", "SOCKS5: метод не принят"
    host = b"target.test"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (443).to_bytes(2, "big"))
    rep = s.recv(10)
    assert rep[:2] == b"\x05\x00", f"SOCKS5 CONNECT отклонён: {rep!r}"
    payload = os.urandom(64 * 1024)             # 64 КиБ случайных данных
    s.sendall(payload)
    got = b""
    while len(got) < len(payload):
        chunk = s.recv(65536)
        if not chunk:
            break
        got += chunk
    assert got == payload, f"соединение {i+1}: эхо не совпало, получено {len(got)} из {len(payload)} байт"
    s.close()
    total += len(payload)
print(f"OK: {n} соединени(е/й), {total} байт ушли через SOCKS5 -> REALITY -> VLESS и вернулись без искажений")
PY

grep -q '^EVENT reality-ok' "$TMP/server.log" || { echo "сервер не подтвердил REALITY:"; cat "$TMP/server.log"; exit 1; }
grep -q '^EVENT vless-ok cmd=1 target=target.test:443' "$TMP/server.log" || { echo "сервер не разобрал VLESS:"; cat "$TMP/server.log"; exit 1; }
echo "OK: сервер подтвердил REALITY-аутентификацию и VLESS-запрос к target.test:443"

# Ссылка, которую этот клиент выполнить не может (Vision поверх
# WebSocket — так не умеет и сам Xray-core), обязана отклоняться сразу
# при старте с понятной ошибкой, а не поднимать SOCKS5 и молча ломаться.
set +e
BAD_LINK="${LINK%%#*}"
BAD_LINK="${BAD_LINK/type=tcp/type=ws}&flow=xtls-rprx-vision#smoke"
timeout 10 "$CLIENT_BIN" --server "$BAD_LINK" --listen 127.0.0.1:0 > "$TMP/badlink.log" 2>&1
code=$?
set -e
if [[ $code -eq 0 ]] || ! grep -q 'xtls-rprx-vision' "$TMP/badlink.log"; then
    echo "ожидалась явная ошибка для Vision поверх ws, получено (код $code):"; cat "$TMP/badlink.log"; exit 1
fi
echo "OK: несовместимая ссылка (Vision поверх ws) отклонена при старте с понятной ошибкой"

# С обёрткой (valgrind) — корректно остановить клиент, чтобы обёртка
# успела записать итог, и вернуть её код.
if [[ ${#WRAP[@]} -gt 0 ]]; then
    kill -TERM "$CLIENT_PID" 2>/dev/null || true   # не INT: у фоновых процессов неинтерактивного bash SIGINT игнорируется
    set +e; wait "$CLIENT_PID"; wcode=$?; set -e
    echo "обёртка клиента завершилась с кодом $wcode"
    [[ $wcode -eq 99 ]] && { echo "обёртка сообщила об ошибках (код 99)"; exit 1; }
fi
echo "SMOKE PASSED"
