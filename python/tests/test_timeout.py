"""A separate limit on establishing the connection: timeout=(connect, total)."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import curlpro
import pytest
from curlpro.timeouts import split_timeout as _split_timeout

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class StalledServer:
    """Accepts a TCP connection and stays silent: the TLS handshake never starts.

    A dead address will not do for the check: the kernel answers it differently
    and on Windows often refuses at once. A silent socket gives the same
    "not connected yet" phase, but identically on every system.
    """

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._held: list[socket.socket] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}/"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            # The socket is held open: closing it would return an error to the
            # client too early and leave the limit unchecked.
            self._held.append(raw)

    def __enter__(self) -> "StalledServer":
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()
        for raw in self._held:
            raw.close()


@pytest.fixture
def stalled():
    with StalledServer() as srv:
        yield srv


def test_pair_splits_connect_and_total():
    assert _split_timeout(None) == (None, None)
    assert _split_timeout(5) == (None, 5.0)
    assert _split_timeout((3, 30)) == (3.0, 30.0)
    with pytest.raises(ValueError):
        _split_timeout((1, 2, 3))


def test_connect_timeout_fires_before_total(stalled):
    """A silent host must fail on the first limit rather than on the total one."""
    with curlpro.Session(verify=False) as s:
        started = time.monotonic()
        with pytest.raises(curlpro.Timeout):
            s.get(stalled.url, timeout=(0.4, 30))
        spent = time.monotonic() - started
    assert spent < 5, f"waited {spent:.1f} s — that looks like the total limit"


def test_session_connect_timeout_applies(stalled):
    """The limit from the constructor applies without a per-request override."""
    with curlpro.Session(verify=False, timeout=(0.4, 30)) as s:
        started = time.monotonic()
        with pytest.raises(curlpro.Timeout):
            s.get(stalled.url)
        spent = time.monotonic() - started
    assert spent < 5, f"waited {spent:.1f} s"


def test_connect_timeout_does_not_limit_reading():
    """The response is awaited under the total limit: a slow server must not fail."""
    with RawHeaderServer(delay=1.0) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            assert s.get(srv.url, timeout=(0.5, 10)).status == 200


def test_total_timeout_still_cuts_slow_response():
    """The total limit still works when a separate connect limit is set."""
    with RawHeaderServer(delay=2.0) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            with pytest.raises(curlpro.Timeout):
                s.get(srv.url, timeout=(0.5, 0.7))


def test_websocket_connect_timeout(stalled):
    """The socket handshake is the same connecting phase as a request's."""
    with curlpro.Session("chrome-151-windows", verify=False) as s:
        started = time.monotonic()
        with pytest.raises(curlpro.CurlProError):
            s.websocket(stalled.url.replace("https://", "wss://"), timeout=(0.4, 30))
        spent = time.monotonic() - started
    assert spent < 5, f"waited {spent:.1f} s"


# --- response_timeout: the wait for the headers -----------------------------

def test_response_timeout_fires_when_the_headers_are_late():
    """A server that accepts and then thinks is past the connecting limit and
    inside the total one; this is the limit for that silence."""
    with RawHeaderServer(delay=2.0) as srv, curlpro.Session(verify=False, force_http1=True) as s:
        started = time.monotonic()
        with pytest.raises(curlpro.Timeout, match="response headers"):
            s.get(srv.url, response_timeout=0.4, timeout=10)
        assert time.monotonic() - started < 1.5


def test_response_timeout_spares_a_slow_body():
    """Once the headers are in the timer is off: a body that trickles for a
    second after a 0.4 s headers limit still arrives whole."""
    with RawHeaderServer(body_delay=1.0) as srv, curlpro.Session(verify=False, force_http1=True) as s:
        r = s.get(srv.url, response_timeout=0.4, timeout=10)
        assert r.status == 200 and r.json()["request_line"].startswith("GET")


def test_session_response_timeout_applies():
    with RawHeaderServer(delay=2.0) as srv:
        with curlpro.Session(verify=False, force_http1=True, response_timeout=0.4) as s:
            with pytest.raises(curlpro.Timeout, match="response headers"):
                s.get(srv.url)


def test_named_connect_timeout_wins_over_the_pair(stalled):
    """connect_timeout= is the more specific statement; it overrides the
    pair's first element rather than being ignored beside it."""
    with curlpro.Session(verify=False) as s:
        started = time.monotonic()
        with pytest.raises(curlpro.CurlProError):
            s.get(stalled.url, timeout=(30, 30), connect_timeout=0.4)
        assert time.monotonic() - started < 5


def test_response_timeout_must_be_positive():
    """Zero is refused by name on the native side, as timeout=0 is — "leave it
    unset for no limit"; a bool is refused before it can turn into a second."""
    with curlpro.Session(verify=False) as s:
        with pytest.raises(curlpro.CurlProError, match="response timeout must be positive"):
            s.get("https://example.com/", response_timeout=0)
        with pytest.raises(TypeError, match="response_timeout"):
            s.get("https://example.com/", response_timeout=True)
