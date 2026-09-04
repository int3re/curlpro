"""permessage-deflate with a window below 32 KiB.

Checking it with a server from the ``websockets`` package is pointless: it
accepts uncompressed frames silently, and the check would pass without any
compression. Here the server is our own — it looks at the RSV1 bit and inflates
with exactly the window it demanded: zlib with ``wbits=-9`` refuses a 32 KiB stream.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import ssl
import struct
import threading
import zlib
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]
CERT_DIR = REPO / "capture" / "certs"
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class DeflateWS:
    """A server that demands client_max_window_bits and reads one frame."""

    def __init__(self, bits: int):
        self.bits = bits
        self.rsv1: bool | None = None
        self.payload: bytes = b""
        self.error: str | None = None

        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def url(self) -> str:
        return f"wss://localhost:{self.port}/"

    def _serve(self) -> None:
        try:
            raw, _ = self._sock.accept()
        except OSError:
            return
        try:
            with self._ctx.wrap_socket(raw, server_side=True) as conn:
                self._handshake(conn)
                self._read_frame(conn)
                # The reply goes out uncompressed: RSV1 is set per message.
                conn.sendall(b"\x81\x02ok")
                # Wait for the close frame and answer with our own: otherwise the
                # client gets a TLS break instead of a clean close.
                self._read_frame(conn)
                conn.sendall(b"\x88\x00")
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"

    def _handshake(self, conn: ssl.SSLSocket) -> None:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                raise ConnectionError("the client sent no handshake")
            data += chunk
        key = ""
        for line in data.decode("latin-1").split("\r\n")[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "sec-websocket-key":
                key = value.strip()
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        conn.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n"
            b"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits="
            + str(self.bits).encode() + b"\r\n\r\n"
        )

    def _read_frame(self, conn: ssl.SSLSocket) -> None:
        def read(n: int) -> bytes:
            buf = b""
            while len(buf) < n:
                chunk = conn.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("the frame was cut short")
                buf += chunk
            return buf

        b0, b1 = read(2)
        if self.rsv1 is None:
            self.rsv1 = bool(b0 & 0x40)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", read(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", read(8))[0]
        mask = read(4) if b1 & 0x80 else b"\x00\x00\x00\x00"
        body = bytearray(read(length))
        for i in range(len(body)):
            body[i] ^= mask[i % 4]
        if not self.payload:
            self.payload = bytes(body)

    def __enter__(self) -> "DeflateWS":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._sock.close()
        self._thread.join(timeout=2)


# Distant repeats: with a 512-byte window a reference to the beginning is out of
# reach, and the compressor must account for that. With a 32 KiB window it would
# refer back, and zlib with wbits=-9 cannot read such a stream.
PAYLOAD = ("A" * 400 + "B" * 400) * 4 + "tail"


def test_small_client_window_is_compressed_within_window():
    with DeflateWS(bits=9) as srv:
        with curlpro.Session("chrome-151-windows", verify=False) as s:
            with s.websocket(srv.url, timeout=5) as ws:
                ws.send(PAYLOAD)
                assert ws.recv() == "ok"

    assert srv.error is None, srv.error
    assert srv.rsv1 is True, "the message went out uncompressed though the extension was negotiated"
    # The sender trims the stored-block tail (RFC 7692, 7.2.1) — we put it back.
    raw = zlib.decompressobj(-9).decompress(srv.payload + b"\x00\x00\xff\xff")
    assert raw.decode("utf-8") == PAYLOAD


def test_full_window_still_compressed():
    """The ordinary case — a 32 KiB window — is not broken by switching compressors."""
    with DeflateWS(bits=15) as srv:
        with curlpro.Session("chrome-151-windows", verify=False) as s:
            with s.websocket(srv.url, timeout=5) as ws:
                ws.send(PAYLOAD)
                assert ws.recv() == "ok"

    assert srv.error is None, srv.error
    assert srv.rsv1 is True
    raw = zlib.decompressobj(-15).decompress(srv.payload + b"\x00\x00\xff\xff")
    assert raw.decode("utf-8") == PAYLOAD
