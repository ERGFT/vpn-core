#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure time to the first successful SOCKS5 + TLS echo after an outage."""
import json
import socket
import ssl
import struct
import sys
import time

port, echo_port = map(int, sys.argv[1:3])
timeout_s = float(sys.argv[3]) if len(sys.argv) > 3 else 60.0
interval_s = float(sys.argv[4]) / 1000 if len(sys.argv) > 4 else 0.05
started = time.perf_counter()
attempts = 0
last_error = "no attempt completed"
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.minimum_version = ssl.TLSVersion.TLSv1_3
probe = b"recovery-probe-v1"


def recv_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise RuntimeError("peer closed the connection")
        result.extend(part)
    return bytes(result)


while time.perf_counter() - started < timeout_s:
    attempts += 1
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
            raw.settimeout(2)
            raw.sendall(b"\x05\x01\x00")
            if recv_exact(raw, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS5 rejected no-auth method")
            request = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
            raw.sendall(request + struct.pack(">H", echo_port))
            reply = recv_exact(raw, 4)
            if reply[:2] != b"\x05\x00":
                raise RuntimeError(f"SOCKS5 CONNECT failed: {reply!r}")
            address_size = {1: 4, 4: 16}.get(reply[3])
            if address_size is None:
                if reply[3] != 3:
                    raise RuntimeError(f"unknown SOCKS5 address type: {reply[3]}")
                address_size = recv_exact(raw, 1)[0]
            recv_exact(raw, address_size + 2)
            with context.wrap_socket(raw, server_hostname="inner.test") as tls:
                tls.settimeout(2)
                tls.sendall(probe)
                if recv_exact(tls, len(probe)) != probe:
                    raise RuntimeError("TLS echo returned unexpected bytes")
        print(json.dumps({
            "status": "recovered",
            "recovery_ms": round((time.perf_counter() - started) * 1000, 3),
            "attempts": attempts,
            "poll_interval_ms": round(interval_s * 1000, 3),
        }))
        raise SystemExit(0)
    except (OSError, ssl.SSLError, RuntimeError) as error:
        last_error = str(error)
        time.sleep(interval_s)

print(json.dumps({
    "status": "timeout",
    "timeout_s": timeout_s,
    "attempts": attempts,
    "last_error": last_error,
}), file=sys.stderr)
raise SystemExit(1)
