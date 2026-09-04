"""Minimal proxies for the tests: HTTP CONNECT and SOCKS5.

They are needed to check that the traffic really goes through the proxy rather
than past it: each server counts the tunnels and records the requested addresses.
"""

from __future__ import annotations

import base64
import socket
import socketserver
import struct
import threading
from typing import Callable


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Pumps data one way until it closes."""
    try:
        while chunk := a.recv(65536):
            b.sendall(chunk)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
    t = threading.Thread(target=_pump, args=(upstream, client), daemon=True)
    t.start()
    _pump(client, upstream)
    t.join(timeout=1)


class _Base(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, handler: type, auth: tuple[str, str] | None = None):
        super().__init__(("127.0.0.1", 0), handler)
        self.auth = auth
        self.tunnels: list[str] = []
        self.rejected = 0
        self._thread: threading.Thread | None = None

    @property
    def url_host(self) -> str:
        host, port = self.server_address[:2]
        return f"{host}:{port}"

    def start(self) -> "_Base":
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


class _ConnectHandler(socketserver.BaseRequestHandler):
    server: "HTTPProxy"

    def handle(self) -> None:
        f = self.request.makefile("rb")
        line = f.readline().decode("latin-1").strip()
        if not line.startswith("CONNECT "):
            self.request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        target = line.split()[1]

        headers: dict[str, str] = {}
        while (raw := f.readline()) not in (b"\r\n", b"\n", b""):
            k, _, v = raw.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()

        if self.server.auth:
            user, password = self.server.auth
            want = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
            if headers.get("proxy-authorization") != want:
                self.server.rejected += 1
                self.request.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"test\"\r\n\r\n"
                )
                return

        host, _, port = target.rpartition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        self.server.tunnels.append(target)
        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        with upstream:
            _tunnel(self.request, upstream)


class HTTPProxy(_Base):
    """An HTTP proxy supporting CONNECT only."""

    def __init__(self, auth: tuple[str, str] | None = None):
        super().__init__(_ConnectHandler, auth)


class _Socks5Handler(socketserver.BaseRequestHandler):
    server: "Socks5Proxy"

    def handle(self) -> None:
        sock = self.request
        # The greeting: version, method count, methods
        head = sock.recv(2)
        if len(head) < 2 or head[0] != 0x05:
            return
        methods = sock.recv(head[1])

        need_auth = self.server.auth is not None
        if need_auth:
            if 0x02 not in methods:
                sock.sendall(b"\x05\xff")
                return
            sock.sendall(b"\x05\x02")
            if not self._authenticate(sock):
                self.server.rejected += 1
                return
        else:
            sock.sendall(b"\x05\x00")

        # The request: version, command, reserved, address type
        req = sock.recv(4)
        if len(req) < 4 or req[1] != 0x01:  # CONNECT only
            sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return

        atyp = req[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(sock.recv(4))
        elif atyp == 0x03:
            host = sock.recv(sock.recv(1)[0]).decode()
        else:
            sock.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = struct.unpack("!H", sock.recv(2))[0]

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            sock.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
            return

        self.server.tunnels.append(f"{host}:{port}")
        sock.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        with upstream:
            _tunnel(sock, upstream)

    def _authenticate(self, sock: socket.socket) -> bool:
        ver = sock.recv(1)
        if not ver or ver[0] != 0x01:
            return False
        user = sock.recv(sock.recv(1)[0]).decode()
        password = sock.recv(sock.recv(1)[0]).decode()
        ok = (user, password) == self.server.auth
        sock.sendall(b"\x01\x00" if ok else b"\x01\x01")
        return ok


class Socks5Proxy(_Base):
    """A SOCKS5 proxy with optional username and password authentication."""

    def __init__(self, auth: tuple[str, str] | None = None):
        super().__init__(_Socks5Handler, auth)
