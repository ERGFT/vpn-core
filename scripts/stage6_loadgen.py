#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Same SOCKS5 + inner TLS echo workload for both client cores."""
import json
import os
import socket
import ssl
import statistics
import struct
import sys
import threading
import time

port, conns, mib, echo_port = map(int, sys.argv[1:5])
chunk = 64 * 1024
sent_total = 0
first_byte_ms = []
errors = []
lock = threading.Lock()
tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
tls_context.check_hostname = False
tls_context.verify_mode = ssl.CERT_NONE
tls_context.minimum_version = ssl.TLSVersion.TLSv1_3


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError(f"socket closed after {len(data)} of {size} bytes")
        data.extend(part)
    return bytes(data)


def one(index: int) -> None:
    global sent_total
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 no-auth method was rejected")
        request = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo_port)
        sock.sendall(request)
        head = recv_exact(sock, 4)
        if head[:2] != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 CONNECT failed: {head!r}")
        address_size = {1: 4, 4: 16}.get(head[3])
        if address_size is None:
            if head[3] != 3:
                raise RuntimeError(f"SOCKS5 returned unknown address type: {head[3]}")
            address_size = recv_exact(sock, 1)[0]
        recv_exact(sock, address_size + 2)
        tls = tls_context.wrap_socket(sock, server_hostname="inner.test")

        # First echoed application bytes after a real inner TLS 1.3 handshake.
        started = time.perf_counter()
        probe = b"first-byte-probe" * 4
        tls.sendall(probe)
        response = bytearray()
        while len(response) < len(probe):
            part = tls.recv(len(probe) - len(response))
            if not part:
                raise RuntimeError("TLS echo closed before the first response")
            response.extend(part)
        if response != probe:
            raise RuntimeError("TLS echo changed the first-byte probe")
        first_byte_ms.append((time.perf_counter() - started) * 1000)

        total = mib * 1024 * 1024
        payload = os.urandom(chunk)
        sent = 0
        while sent < total:
            size = min(chunk, total - sent)
            block = payload[:size]
            tls.sendall(block)
            if recv_exact(tls, size) != block:
                raise RuntimeError(f"TLS echo changed data after {sent} of {total} request bytes")
            sent += size
        tls.close()
        with lock:
            sent_total += total
    except Exception as exc:  # noqa: BLE001
        with lock:
            errors.append(f"connection {index}: {exc}")


started = time.perf_counter()
threads = [threading.Thread(target=one, args=(i,)) for i in range(conns)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
elapsed = time.perf_counter() - started

if errors:
    print(json.dumps({"errors": errors}, ensure_ascii=False), file=sys.stderr)
    raise SystemExit(1)

total_mib = sent_total * 2 / 1024 / 1024
print(json.dumps({
    "connections": conns,
    "mib_each_direction_per_connection": mib,
    "elapsed_s": round(elapsed, 4),
    "mib_total_both_ways": round(total_mib, 4),
    "throughput_mib_s": round(total_mib / elapsed, 3),
    "first_byte_ms_median": round(statistics.median(first_byte_ms), 3),
    "first_byte_ms_max": round(max(first_byte_ms), 3),
}, ensure_ascii=False))
