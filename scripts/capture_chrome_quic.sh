#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Снять первые QUIC-датаграммы настоящего Chromium (для теста sniffing
# QUIC — core/src/app/testdata/chromium*_quic_initial.hex). Никуда в сеть
# не ходит: имя www.example.test направляется на 127.0.0.1:443, где
# слушает скрипт на Python и ничего не отвечает. Нужны root (порт 443)
# и Chromium (по умолчанию — из Playwright).
#
#   scripts/capture_chrome_quic.sh [файл.hex]
set -euo pipefail
OUT="${1:-chrome_quic_initial.hex}"
CHROME="${CHROME_BIN:-$(ls -d /opt/pw-browsers/chromium-*/chrome-linux/chrome 2>/dev/null | head -1)}"
[[ -x "$CHROME" ]] || { echo "нет Chromium (CHROME_BIN)" >&2; exit 2; }
TMP="$(mktemp -d)"
trap 'kill $CH 2>/dev/null || true; rm -rf "$TMP"' EXIT
python3 - "$OUT" <<'PY' &
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 443))
s.settimeout(15)
out, t0 = [], time.time()
try:
    while len(out) < 6 and time.time() - t0 < 15:
        d, _ = s.recvfrom(65535)
        out.append(d)
except socket.timeout:
    pass
open(sys.argv[1], "w").write("".join(d.hex() + "\n" for d in out))
print(f"датаграмм: {len(out)}")
PY
CAP=$!
sleep 0.5
env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy -u ALL_PROXY -u all_proxy \
    "$CHROME" --headless=new --no-sandbox --disable-gpu --no-proxy-server \
    --enable-quic --origin-to-force-quic-on=www.example.test:443 \
    --host-resolver-rules="MAP * 127.0.0.1" --user-data-dir="$TMP/prof" \
    https://www.example.test/ >/dev/null 2>&1 &
CH=$!
wait $CAP
"$CHROME" --version
echo "готово: $OUT"
