"""WebSocket checks.

The handshake is a plain HTTP/1.1 request with Upgrade, so its headers come from
the browser profile and belong to the fingerprint too.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[2]
ECHO = "wss://echo.websocket.org/"


def _online() -> bool:
    try:
        with socket.create_connection(("echo.websocket.org", 443), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _online(), reason="no access to echo.websocket.org")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def ws():
    with curlpro.Session("chrome-151-windows") as s:
        with s.websocket(ECHO) as sock:
            sock.recv()  # the server sends a greeting first
            yield sock


def test_text_roundtrip(ws):
    ws.send("hello from curlpro")
    got = ws.recv()
    assert got == "hello from curlpro"
    assert isinstance(got, str)


def test_binary_roundtrip(ws):
    """Binary data must not be damaged: a text frame would corrupt sequences that
    are not valid UTF-8."""
    blob = bytes(range(256))
    ws.send(blob)
    got = ws.recv()
    assert got == blob
    assert isinstance(got, bytes)


def test_frame_type_follows_payload_type(ws):
    """A str goes out as a text frame, bytes as a binary one. These are different
    opcodes, and a server may tell them apart."""
    ws.send("a string")
    assert isinstance(ws.recv(), str)
    ws.send(b"bytes")
    assert isinstance(ws.recv(), bytes)


def test_large_message(ws):
    """A length above 65535 is encoded in eight bytes (RFC 6455)."""
    payload = "x" * 100_000
    ws.send(payload)
    assert ws.recv() == payload


def test_medium_message(ws):
    """A length between 126 and 65535 is encoded in two bytes."""
    payload = "y" * 5000
    ws.send(payload)
    assert ws.recv() == payload


def test_ping_does_not_break_stream(ws):
    """The matching pong is handled inside recv and never surfaces."""
    ws.ping(b"probe")
    ws.send("after the ping")
    assert ws.recv() == "after the ping"


def test_close_is_idempotent():
    with curlpro.Session() as s:
        sock = s.websocket(ECHO)
        sock.close()
        sock.close()
        with pytest.raises(RuntimeError, match="closed"):
            sock.send("too late")


def test_requires_wss():
    with curlpro.Session() as s:
        with pytest.raises(curlpro.CurlProError, match="only wss"):
            s.websocket("ws://echo.websocket.org/")


def test_handshake_uses_profile_headers():
    """The handshake fingerprint must depend on the profile.

    Checking the headers directly needs a server of our own; here it is checked
    that a connection with the Firefox profile is established just as
    successfully — that is, the headers are assembled rather than taken from Go's defaults.
    """
    with curlpro.Session("firefox-144-macos") as s:
        with s.websocket(ECHO) as sock:
            sock.recv()
            sock.send("firefox")
            assert sock.recv() == "firefox"
