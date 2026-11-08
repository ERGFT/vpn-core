#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Interoperability with the official Hysteria 2 server, pinned by release and
# SHA-256. Requires Linux x86_64, curl, openssl, sha256sum, and Cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE_TAG="app%2Fv2.13.0"
SERVER_SHA256="907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
    echo "Hysteria 2 reference interop requires Linux x86_64" >&2
    exit 2
fi

SERVER_BIN="${HYSTERIA2_SERVER_BIN:-}"
if [[ -z "$SERVER_BIN" ]]; then
    SERVER_BIN="$WORK/hysteria"
    URL="https://github.com/HyNetworks/hysteria/releases/download/${RELEASE_TAG}/hysteria-linux-amd64"
    curl --fail --location --silent --show-error "$URL" --output "$SERVER_BIN"
    printf '%s  %s\n' "$SERVER_SHA256" "$SERVER_BIN" | sha256sum --check --status || {
        echo "SHA-256 mismatch for the official Hysteria server binary" >&2
        exit 1
    }
    chmod +x "$SERVER_BIN"
else
    [[ -x "$SERVER_BIN" ]] || { echo "HYSTERIA2_SERVER_BIN is not executable: $SERVER_BIN" >&2; exit 2; }
fi

PORT="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/ca.key" -out "$WORK/ca.crt" \
    -subj /CN=vpn-core-Hysteria-interop-CA \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
    -keyout "$WORK/server.key" -out "$WORK/server.csr" \
    -subj /CN=localhost >/dev/null 2>&1
cat >"$WORK/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EOF
openssl x509 -req -in "$WORK/server.csr" \
    -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
    -days 1 -extfile "$WORK/server.ext" -out "$WORK/server.crt" \
    >/dev/null 2>&1
openssl verify -CAfile "$WORK/ca.crt" -verify_hostname localhost \
    "$WORK/server.crt" >/dev/null
openssl verify -CAfile "$WORK/ca.crt" -verify_ip 127.0.0.1 \
    "$WORK/server.crt" >/dev/null

cat >"$WORK/server.yaml" <<EOF
listen: 127.0.0.1:$PORT
tls:
  cert: $WORK/server.crt
  key: $WORK/server.key
  sniGuard: disable
auth:
  type: password
  password: interop-password
EOF

"$SERVER_BIN" server -c "$WORK/server.yaml" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 60); do
    if grep -q 'server up and running' "$WORK/server.log"; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        cat "$WORK/server.log" >&2
        echo "official Hysteria server exited before becoming ready" >&2
        exit 1
    fi
    sleep 0.25
done
if ! grep -q 'server up and running' "$WORK/server.log"; then
    cat "$WORK/server.log" >&2
    echo "official Hysteria server did not become ready within 15 seconds" >&2
    exit 1
fi

cd "$ROOT"
if ! HYSTERIA2_PORT="$PORT" HYSTERIA2_CA_FILE="$WORK/ca.crt" \
    cargo test --locked -p reality-core --test interop_hysteria2 \
    -- --ignored --nocapture; then
    echo "official Hysteria server log:" >&2
    cat "$WORK/server.log" >&2
    exit 1
fi
