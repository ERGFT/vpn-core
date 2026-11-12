#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise tagged exits with real SOCKS handshakes over loopback."""
import argparse
import json
import os
import socket
import socketserver
import sys
import subprocess
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory


def read_exact(stream, length):
    value = stream.read(length)
    if len(value) != length:
        raise EOFError("Truncated SOCKS frame")
    return value


class Exit(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        if read_exact(self.rfile, 2) != b"\x05\x01":
            raise ValueError("Expected SOCKS5 with one authentication method")
        if read_exact(self.rfile, 1) != b"\x00":
            raise ValueError("Expected unauthenticated local fixture")
        self.wfile.write(b"\x05\x00")
        version, command, reserved, family = read_exact(self.rfile, 4)
        if (version, command, reserved) != (5, 1, 0):
            raise ValueError("Expected SOCKS CONNECT")
        if family == 3:
            target = read_exact(self.rfile, read_exact(self.rfile, 1)[0]).decode("ascii")
        elif family in (1, 4):
            target = socket.inet_ntop(socket.AF_INET if family == 1 else socket.AF_INET6,
                                      read_exact(self.rfile, 4 if family == 1 else 16))
        else:
            raise ValueError("Unsupported address family")
        port = int.from_bytes(read_exact(self.rfile, 2), "big")
        self.server.seen.append((target, port))
        self.wfile.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        while True:
            line = self.rfile.readline(4096)
            if not line:
                raise EOFError("Missing tunneled HTTP request")
            if line == b"\r\n":
                break
        body = self.server.label.encode("ascii")
        self.wfile.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                         + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)


def request(proxy_port, host):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
        sock.settimeout(5)
        with sock.makefile("rb") as stream:
            sock.sendall(f"CONNECT {host}:80 HTTP/1.1\r\nHost: {host}:80\r\n\r\n".encode("ascii"))
            status = stream.readline(4096)
            if b" 200 " not in status:
                raise OSError(f"CONNECT failed: {status!r}")
            while True:
                header = stream.readline(4096)
                if header == b"\r\n":
                    break
                if not header:
                    raise EOFError("Missing CONNECT response headers")
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
            response = stream.read()
            return response.split(b"\r\n\r\n", 1)[1].decode("ascii")


def run(core):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Exit) as primary, \
         socketserver.ThreadingTCPServer(("127.0.0.1", 0), Exit) as secondary, \
         TemporaryDirectory(prefix="dual-exit-", dir=Path.cwd()) as directory:
        primary.label, secondary.label = "vpn1", "vpn2"
        primary.seen, secondary.seen = [], []
        for server in (primary, secondary):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            proxy_port = reserve.getsockname()[1]
        config = {
            "inbounds": [{"type": "http", "tag": "test", "listen": "127.0.0.1", "listen_port": proxy_port}],
            "outbounds": [{"type": "socks", "tag": server.label, "server": "127.0.0.1",
                           "server_port": server.server_address[1], "version": "5", "network": "tcp"}
                          for server in (primary, secondary)],
            "route": {"rules": [{"domain": ["secondary.example.test"], "outbound": "vpn2"}], "final": "vpn1"},
        }
        config_path = Path(directory, "config.json")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        subprocess.run([core, "--config", str(config_path), "--check"], check=True, timeout=15)
        with Path(directory, "core.log").open("w+b") as log:
            process = subprocess.Popen([core, "--config", str(config_path), "--exit-on-stdin-eof"],
                                       stdin=subprocess.PIPE, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        log.seek(0)
                        raise RuntimeError(log.read().decode("utf-8", errors="replace"))
                    try:
                        with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                for host, expected in [("secondary.example.test", "vpn2"), ("default.example.test", "vpn1"),
                                       ("secondary.example.test", "vpn2")]:
                    assert request(proxy_port, host) == expected
                assert primary.seen == [("default.example.test", 80)]
                assert secondary.seen == [("secondary.example.test", 80)] * 2
                secondary.shutdown()
                secondary.server_close()
                try:
                    request(proxy_port, "secondary.example.test")
                except (OSError, EOFError):
                    pass
                else:
                    raise AssertionError("Unavailable VPN-2 unexpectedly succeeded")
                assert primary.seen == [("default.example.test", 80)]
                assert request(proxy_port, "default.example.test") == "vpn1"

            finally:
                process.stdin.close()
                try:
                    assert process.wait(timeout=5) == 0, "Core failed to stop cleanly"
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise AssertionError("Core did not stop after stdin closed")
                primary.shutdown()
                secondary.shutdown()
        print("PASS: domain and default select distinct exits, failed VPN-2 never falls back, stdin EOF stops core")


def run_windows_tun(core):
    if sys.platform != "win32":
        raise RuntimeError("The TUN fixture requires an isolated Windows runner")
    address = "192.0.2.42"
    # TCP dials under Windows TUN are pinned to the physical interface.
    # Select its local address without sending a packet to the synthetic target.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((address, 9))
        underlay = route.getsockname()[0]
    with socketserver.ThreadingTCPServer((underlay, 0), Exit) as primary, \
         socketserver.ThreadingTCPServer((underlay, 0), Exit) as secondary, \
         TemporaryDirectory(prefix="dual-tun-", dir=Path.cwd()) as directory:
        primary.label, secondary.label = "vpn1", "vpn2"
        primary.seen, secondary.seen = [], []
        for server in (primary, secondary):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        config = {
            "inbounds": [{"type": "tun", "tag": "tun", "interface_name": "reality-dual-test",
                          "address": ["172.23.61.1/30"], "auto_route": True}],
            "outbounds": [{"type": "socks", "tag": server.label, "server": underlay,
                           "server_port": server.server_address[1], "version": "5", "network": "tcp"}
                          for server in (primary, secondary)],
            "route": {
                "rules": [{"process_path": [sys.executable], "ip_cidr": [address + "/32"],
                           "outbound": "vpn2"}],
                "final": "vpn1",
            },
        }
        path = Path(directory, "config.json")
        path.write_text(json.dumps(config), encoding="utf-8")
        subprocess.run([core, "--check", "-c", str(path)], check=True, timeout=15)
        with Path(directory, "core.log").open("w+b") as log:
            process = subprocess.Popen([core, "-c", str(path), "--exit-on-stdin-eof"],
                                       stdin=subprocess.PIPE, stdout=log, stderr=log, cwd=Path(core).parent,
                                       env={**os.environ, "RUST_LOG": "info,reality_core::app=debug"})
            try:
                deadline = time.monotonic() + 45
                output = ""
                while process.poll() is None and time.monotonic() < deadline:
                    try:
                        with socket.create_connection((address, 80), timeout=1) as client:
                            client.sendall(b"GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
                            with client.makefile("rb") as response:
                                output = response.read().decode("ascii")
                            break
                    except OSError:
                        time.sleep(0.25)
                assert output.endswith("\r\n\r\nvpn2"), f"Python process did not select VPN-2: {output!r}, exits={primary.seen!r}/{secondary.seen!r}"
                assert not primary.seen and secondary.seen == [(address, 80)]
                alternate = subprocess.run(
                    ["curl.exe", "--noproxy", "*", "--max-time", "5", "--fail", "--silent",
                     "--show-error", f"http://{address}/"],
                    capture_output=True, text=True, check=True, timeout=10)
                assert alternate.stdout == "vpn1", f"Default application selected {alternate.stdout!r}"
                assert primary.seen == [(address, 80)] and secondary.seen == [(address, 80)]
            except Exception:
                log.seek(0)
                print(log.read().decode("utf-8", errors="replace"), file=sys.stderr)
                raise
            finally:
                process.stdin.close()
                try:
                    assert process.wait(timeout=15) == 0, "TUN core failed to stop cleanly"
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
                finally:
                    for server in (primary, secondary):
                        server.shutdown()
    print("PASS: two Windows executables reached different exits through Wintun")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("core", type=Path)
    parser.add_argument("--windows-tun", action="store_true")
    args = parser.parse_args()
    (run_windows_tun if args.windows_tun else run)(str(args.core.resolve()))
