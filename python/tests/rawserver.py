"""Минимальный TLS-сервер, возвращающий сырые заголовки запроса.

Публичные оракулы приводят имена заголовков к нижнему регистру, поэтому
проверить регистр на них нельзя. Этот сервер отдаёт строки запроса ровно
так, как они пришли на провод.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parents[2] / "capture" / "certs"


class RawHeaderServer:
    """Принимает одно HTTP/1.1-соединение и отвечает списком сырых заголовков."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, persistent: bool = False):
        # persistent=True держит соединение открытым и считает принятые:
        # так проверяется переиспользование. По умолчанию сервер отвечает
        # одним ответом и закрывает — этого ждут проверки регистра заголовков.
        self.persistent = persistent
        self.accepted = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        # Только HTTP/1.1: h2 запретил бы проверку регистра, там он всегда нижний.
        self._ctx.set_alpn_protocols(["http/1.1"])

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}/"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            self.accepted += 1
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as conn:
                    while self._handle(conn) and self.persistent:
                        pass
            except (ssl.SSLError, OSError):
                pass

    def _handle(self, conn: ssl.SSLSocket) -> bool:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                return False
            data += chunk

        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        body = json.dumps(
            {
                "request_line": lines[0],
                # Имена ровно как на проводе, без нормализации.
                "headers": [ln.split(":", 1)[0] for ln in lines[1:] if ":" in ln],
                "raw": lines[1:],
            },
            ensure_ascii=False,
        ).encode("utf-8")

        alive = b"keep-alive" if self.persistent else b"close"
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: " + alive + b"\r\n\r\n" + body
        )
        return True

    def __enter__(self) -> "RawHeaderServer":
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()
        if self._thread:
            self._thread.join(timeout=2)
