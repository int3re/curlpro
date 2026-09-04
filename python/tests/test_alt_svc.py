"""The automatic HTTP/3 upgrade via Alt-Svc and the fallback when QUIC fails.

The live upgrade is checked by the cmd/hcapture stand (which brings up both TCP
and QUIC): the first request goes over HTTP/2, the second over HTTP/3. Here what
is checked is what can be checked without a QUIC server: an advertisement
without working QUIC must not break requests, and the option off disables it.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]
CERT_DIR = REPO / "capture" / "certs"


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class AltSvcServer:
    """Advertises HTTP/3 while nobody listens on UDP."""

    def __init__(self, advertise: bool = True):
        self.advertise = advertise
        self.requests = 0

        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        self._ctx.set_alpn_protocols(["http/1.1"])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}/"

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
                while self._handle(conn):
                    pass
        except (ssl.SSLError, OSError):
            pass

    def _handle(self, conn: ssl.SSLSocket) -> bool:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return False
            data += chunk
        self.requests += 1
        body = b"ok"
        extra = f'Alt-Svc: h3=":{self.port}"; ma=86400\r\n' if self.advertise else ""
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + extra.encode()
            + b"Connection: keep-alive\r\n\r\n"
            + body
        )
        return True

    def __enter__(self) -> "AltSvcServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)


def test_broken_quic_falls_back_to_tcp():
    """The site advertised HTTP/3 but QUIC does not answer: requests must go on."""
    with AltSvcServer() as srv:
        with curlpro.Session("chrome-151-windows", verify=False, timeout=20) as s:
            first = s.get(srv.url)
            second = s.get(srv.url)   # here the client tries QUIC and falls back
            third = s.get(srv.url)    # the address is already marked broken
    assert first.status == second.status == third.status == 200
    assert srv.requests == 3, f"{srv.requests} of three requests reached the server"


def test_second_attempt_is_not_repeated_every_time():
    """After a failure the client does not try QUIC again for a while: otherwise
    every request would pay for a handshake that will not happen."""
    with AltSvcServer() as srv:
        with curlpro.Session("chrome-151-windows", verify=False, timeout=20) as s:
            s.get(srv.url)
            start = time.perf_counter()
            s.get(srv.url)
            with_attempt = time.perf_counter() - start

            start = time.perf_counter()
            s.get(srv.url)
            after_broken = time.perf_counter() - start
    assert after_broken < with_attempt, (
        f"the repeat QUIC attempt took {after_broken:.2f} s against {with_attempt:.2f} s"
    )


def test_disabled_option_skips_quic_entirely():
    with AltSvcServer() as srv:
        with curlpro.Session("chrome-151-windows", verify=False,
                             alt_svc=False, timeout=20) as s:
            start = time.perf_counter()
            s.get(srv.url)
            s.get(srv.url)
            spent = time.perf_counter() - start
    # Without a QUIC attempt two requests fit into a fraction of a second.
    assert spent < 2, f"two requests took {spent:.2f} s — that looks like a QUIC attempt"


def test_without_announcement_nothing_changes():
    with AltSvcServer(advertise=False) as srv:
        with curlpro.Session("chrome-151-windows", verify=False, timeout=20) as s:
            start = time.perf_counter()
            for _ in range(3):
                assert s.get(srv.url).status == 200
            spent = time.perf_counter() - start
    assert spent < 2, "without an advertisement the client must not try QUIC"
