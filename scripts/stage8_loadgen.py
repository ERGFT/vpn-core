#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Нагрузка для Этапа 8 — одна и та же для обоих клиентов.

Через локальный SOCKS5 открывает N одновременных соединений, в каждое
шлёт M МиБ случайных данных и читает их обратно (тестовый сервер —
эхо). Печатает JSON: время рукопожатий (SOCKS5 CONNECT) и пропускную
способность. Ошибка в любом соединении — ненулевой код возврата.
"""
import json, os, socket, statistics, sys, threading, time

PORT = int(sys.argv[1])
CONNS = int(sys.argv[2])
MIB = int(sys.argv[3])
CHUNK = 64 * 1024
TARGET = b"target.test"

connect_ms, first_byte_ms, errors, sent_total = [], [], [], 0
lock = threading.Lock()


def one(idx: int) -> None:
    global sent_total
    try:
        t0 = time.perf_counter()
        s = socket.create_connection(("127.0.0.1", PORT), timeout=60)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5: метод не принят")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(TARGET)]) + TARGET + (443).to_bytes(2, "big"))
        rep = s.recv(10)
        if rep[:2] != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 CONNECT отклонён: {rep!r}")
        t1 = time.perf_counter()

        # Время до ПЕРВОГО БАЙТА ДАННЫХ, прошедшего через туннель. Это
        # единственный честный показатель: ответ на SOCKS5 CONNECT
        # сравнивать нельзя, потому что Xray-core отвечает на него
        # авансом, не дожидаясь соединения с сервером (проверено: он
        # отвечает "успех", даже когда сервера нет вообще), а этот
        # клиент отвечает после настоящего рукопожатия.
        s.sendall(b"x" * 64)
        probe = s.recv(64)
        if len(probe) != 64:
            raise RuntimeError(f"пробный байт не вернулся: {len(probe)}")
        t2 = time.perf_counter()

        payload = os.urandom(CHUNK)
        total = MIB * 1024 * 1024
        sent = got = 0

        def reader():
            nonlocal got
            while got < total:
                b = s.recv(CHUNK)
                if not b:
                    break
                got += len(b)

        th = threading.Thread(target=reader, daemon=True)
        th.start()
        while sent < total:
            n = min(CHUNK, total - sent)
            s.sendall(payload[:n])
            sent += n
        th.join(timeout=120)
        if got != total:
            raise RuntimeError(f"вернулось {got} из {total} байт")
        s.close()
        with lock:
            connect_ms.append((t1 - t0) * 1000)
            first_byte_ms.append((t2 - t0) * 1000)
            sent_total += total
    except Exception as e:  # noqa: BLE001
        with lock:
            errors.append(f"соединение {idx}: {e}")


start = time.perf_counter()
threads = [threading.Thread(target=one, args=(i,)) for i in range(CONNS)]
for t in threads:
    t.start()
for t in threads:
    t.join()
elapsed = time.perf_counter() - start

if errors:
    print(json.dumps({"errors": errors}, ensure_ascii=False), file=sys.stderr)
    sys.exit(1)

# Байты считаем в обе стороны: данные ушли и вернулись эхом.
mib = sent_total * 2 / 1024 / 1024
print(json.dumps({
    "conns": CONNS,
    "mib_each": MIB,
    "elapsed_s": round(elapsed, 3),
    "mib_total_both_ways": round(mib, 1),
    "throughput_mib_s": round(mib / elapsed, 1),
    "connect_ms_median": round(statistics.median(connect_ms), 1),
    "connect_ms_max": round(max(connect_ms), 1),
    "first_byte_ms_median": round(statistics.median(first_byte_ms), 1),
    "first_byte_ms_max": round(max(first_byte_ms), 1),
}, ensure_ascii=False))
