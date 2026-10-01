"""A WebSocket client for the DevTools endpoint of a local browser, on the
standard library alone.

The package's own WebSocket goes out with a browser profile's handshake —
Origin included — and Chrome refuses a DevTools connection whose Origin it was
not told to allow. This one says nothing but what RFC 6455 requires, speaks to
127.0.0.1 only and carries text frames: all the DevTools protocol needs.
"""

from __future__ import annotations

import base64
import os
import socket
import struct
from urllib.parse import urlsplit

_OP_CONT, _OP_TEXT, _OP_BIN, _OP_CLOSE, _OP_PING, _OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class WSClosed(ConnectionError):
    """The browser closed the DevTools connection."""


class WS:
    def __init__(self, url: str, timeout: float = 10.0):
        u = urlsplit(url)
        if u.scheme != "ws" or u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(f"a DevTools endpoint is ws:// on this machine, got {url!r}")
        self._sock = socket.create_connection((u.hostname, u.port or 80), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = u.path + (f"?{u.query}" if u.query else "")
        self._sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
                            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise WSClosed("the browser closed the connection during the handshake")
            head += chunk
        head, self._buf = head.split(b"\r\n\r\n", 1)
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status + b" ":
            raise ConnectionError(f"DevTools refused the WebSocket: {status.decode(errors='replace')}")
        self._sock.settimeout(None)

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(max(65536, n - len(self._buf)))
            if not chunk:
                raise WSClosed("the browser closed the DevTools connection")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            head = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
        elif n < 1 << 16:
            head = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            head = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(head + mask + masked)

    def send(self, text: str) -> None:
        self._send_frame(_OP_TEXT, text.encode("utf-8"))

    def recv(self) -> str:
        """The next text message, whole; pings are answered on the way."""
        parts: list[bytes] = []
        while True:
            b0, b1 = self._read(2)
            opcode, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._read(8))[0]
            if b1 & 0x80:  # a server never masks; tolerated all the same
                mask = self._read(4)
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(self._read(n)))
            else:
                payload = self._read(n)
            if opcode == _OP_PING:
                self._send_frame(_OP_PONG, payload)
                continue
            if opcode == _OP_PONG:
                continue
            if opcode == _OP_CLOSE:
                raise WSClosed("the browser closed the DevTools connection")
            parts.append(payload)
            if b0 & 0x80:
                return b"".join(parts).decode("utf-8")

    def close(self) -> None:
        try:
            self._send_frame(_OP_CLOSE, struct.pack("!H", 1000))
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass
