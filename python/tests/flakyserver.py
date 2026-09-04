"""A scripted TLS server for checking retries, timeouts and redirects.

External services will not do: the test must know exactly how many attempts
reached the server and what it answered. httpbin can do /status/503 but gives
no way to tell "the client retried" from "the client went once".
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from collections import defaultdict
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parents[2] / "capture" / "certs"


class FlakyServer:
    """An HTTPS server with scripted behaviour.

    Every path is described by a script: the list of responses the server hands
    out in turn. That makes it possible to check that the client retried exactly
    as many times as it should and then stopped.
    """

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        self._ctx.set_alpn_protocols(["http/1.1"])

        # path -> list of steps; a step is dict(status, body, delay, headers)
        self.scenarios: dict[str, list[dict]] = {}
        # path -> how many requests arrived: tells a retry from a single visit
        self.hits: dict[str, int] = defaultdict(int)
        self.requests: list[dict] = []

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def base(self) -> str:
        return f"https://localhost:{self.port}"

    def url(self, path: str) -> str:
        return f"{self.base}{path}"

    def scenario(self, path: str, steps: list[dict]) -> str:
        """Sets the response sequence for a path and returns its URL.

        The last step repeats when there are more attempts than steps.
        """
        self.scenarios[path] = steps
        return self.url(path)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(raw,), daemon=True).start()

    def _session(self, raw: socket.socket) -> None:
        try:
            with self._ctx.wrap_socket(raw, server_side=True) as conn:
                # keep-alive: the client may send several requests in a row
                while not self._stop.is_set():
                    if not self._handle(conn):
                        return
        except (ssl.SSLError, OSError):
            pass

    def _handle(self, conn: ssl.SSLSocket) -> bool:
        data = b""
        while b"\r\n\r\n" not in data:
            try:
                chunk = conn.recv(4096)
            except OSError:
                return False
            if not chunk:
                return False
            data += chunk

        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = (lines[0].split(" ") + ["", "", ""])[:3]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # Drain the body, or the next request on this connection
        # would start with its remainder.
        body_len = int(headers.get("content-length", 0) or 0)
        body = rest
        while len(body) < body_len:
            chunk = conn.recv(min(65536, body_len - len(body)))
            if not chunk:
                break
            body += chunk

        with self._lock:
            self.hits[path] += 1
            attempt = self.hits[path]
            self.requests.append(
                {"method": method, "path": path, "headers": headers, "body_len": len(body)}
            )
            steps = self.scenarios.get(path) or [{"status": 200}]
            step = steps[min(attempt - 1, len(steps) - 1)]

        if delay := step.get("delay"):
            time.sleep(delay)

        status = step.get("status", 200)
        payload = json.dumps(
            step.get("body", {"path": path, "attempt": attempt}), ensure_ascii=False
        ).encode("utf-8")

        extra = "".join(f"{k}: {v}\r\n" for k, v in (step.get("headers") or {}).items())
        reason = {200: "OK", 301: "Moved Permanently", 302: "Found", 429: "Too Many Requests",
                  500: "Internal Server Error", 502: "Bad Gateway",
                  503: "Service Unavailable"}.get(status, "Status")

        try:
            conn.sendall(
                f"HTTP/1.1 {status} {reason}\r\n".encode()
                + b"Content-Type: application/json\r\n"
                + extra.encode("latin-1")
                + f"Content-Length: {len(payload)}\r\n\r\n".encode()
                + payload
            )
        except OSError:
            return False
        return True

    def __enter__(self) -> "FlakyServer":
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()
        if self._thread:
            self._thread.join(timeout=2)
