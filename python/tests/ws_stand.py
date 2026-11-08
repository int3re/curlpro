"""A local WebSocket echo stand (RFC 6455) for the WebSocket tests.

``with WsStand() as st:`` — ``st.url`` is ``ws://127.0.0.1:PORT/``. Each
connection gets a greeting text frame first, as echo.websocket.org sends one;
then every text or binary message is sent back with its own opcode, a ping is
answered with a pong carrying its payload, and a close is returned. No
extension is accepted, so frames are plain whatever the client offers.
``st.handshakes`` holds every handshake's header lines, in order, as sent.

The tests used to talk to echo.websocket.org, which this machine's network
resets during TLS: an outage of someone else's server read as a failure here.
"""
from __future__ import annotations

import base64
import hashlib
import socket
import struct
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
GREETING = "hello from the stand"


def _read_exact(c: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = c.recv(n - len(out))
        if not chunk:
            raise ConnectionError("closed")
        out += chunk
    return out


def _frame(opcode: int, payload: bytes) -> bytes:
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack("!H", n)
    else:
        head += bytes([127]) + struct.pack("!Q", n)
    return head + payload


class WsStand:
    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.url = f"ws://127.0.0.1:{self.sock.getsockname()[1]}/"
        self.handshakes: list[list[str]] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def __enter__(self) -> "WsStand":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept(self) -> None:
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c: socket.socket) -> None:
        with c:
            try:
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = c.recv(4096)
                    if not chunk:
                        return
                    head += chunk
                lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
                self.handshakes.append(lines)
                key = next((ln.split(":", 1)[1].strip() for ln in lines[1:]
                            if ln.lower().startswith("sec-websocket-key:")), "")
                accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
                c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
                c.sendall(_frame(0x1, GREETING.encode()))
                message, kind = b"", 0
                while True:
                    b0, b1 = _read_exact(c, 2)
                    fin, opcode = b0 & 0x80, b0 & 0x0F
                    n = b1 & 0x7F
                    if n == 126:
                        n = struct.unpack("!H", _read_exact(c, 2))[0]
                    elif n == 127:
                        n = struct.unpack("!Q", _read_exact(c, 8))[0]
                    mask = _read_exact(c, 4) if b1 & 0x80 else b"\x00\x00\x00\x00"
                    data = bytes(x ^ mask[i % 4] for i, x in enumerate(_read_exact(c, n)))
                    if opcode == 0x8:
                        c.sendall(_frame(0x8, data[:2]))
                        return
                    if opcode == 0x9:
                        c.sendall(_frame(0xA, data))
                        continue
                    if opcode == 0xA:
                        continue
                    if opcode in (0x1, 0x2):
                        message, kind = data, opcode
                    else:  # a continuation
                        message += data
                    if fin:
                        c.sendall(_frame(kind, message))
                        message = b""
            except (ConnectionError, OSError):
                return
