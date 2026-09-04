"""Checking the binding against a local fingerproxy echo-server.

The stand is started separately (see docs/CAPTURE.md):

    tools/echo-server_windows_amd64.exe -listen-addr localhost:8443 \
        -cert-filename capture/certs/tls.crt -certkey-filename capture/certs/tls.key

Without it the tests skip rather than fail.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

import curlpro

STAND = "https://localhost:8443/json"
REPO = Path(__file__).resolve().parents[2]
REFERENCE = REPO / "reference" / "chrome-151-windows.json"


def _stand_up() -> bool:
    try:
        with socket.create_connection(("localhost", 8443), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _stand_up(), reason="no echo-server on :8443")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    names = curlpro.load_profiles(REPO / "profiles")
    assert "chrome-151-windows" in names
    return names


def _fetch(profile: str) -> dict:
    with curlpro.Session(profile, verify=False) as s:
        return s.get(STAND).json()


def test_fingerprint_matches_reference():
    """JA4 must match the baseline captured from a real Chrome 151."""
    want = json.loads(REFERENCE.read_text(encoding="utf-8"))["captured"]["ja4"][0]
    assert _fetch("chrome-151-windows")["ja4"] == want


def test_ja3_varies_between_connections():
    """Chrome >= 110 shuffles extensions: a constant JA3 is a trait in itself."""
    seen = set()
    for _ in range(5):
        # Every session is a new TLS connection and a new extension permutation.
        with curlpro.Session("chrome-151-windows", verify=False) as s:
            seen.add(s.get(STAND).json()["ja3"])
    assert len(seen) > 1, f"JA3 does not change between connections: {seen}"


def test_profiles_differ():
    """Different browsers must produce different fingerprints on every layer."""
    chrome = _fetch("chrome-151-windows")
    firefox = _fetch("firefox-144-macos")
    assert chrome["ja4"] != firefox["ja4"]
    # Firefox differs at the HTTP/2 level too: its own window and pseudo-header order.
    assert chrome["http2"] != firefox["http2"]
    assert firefox["http2"].endswith("m,p,a,s")


def test_register_profile_at_runtime():
    """A profile added at runtime is immediately usable for requests."""
    base = json.loads((REPO / "profiles" / "chrome-151-windows.json").read_text(encoding="utf-8"))
    delta = {
        "name": "chrome-152-test",
        "based_on": "chrome-151-windows",
        "headers": {"user_agent": base["headers"]["user_agent"].replace("151", "152")},
    }
    assert "chrome-152-test" in curlpro.register_profile(delta)

    with curlpro.Session("chrome-152-test", verify=False) as s:
        body = s.get(STAND).json()
    # The TLS fingerprint is inherited from the parent — only the User-Agent changed.
    assert body["ja4"] == _fetch("chrome-151-windows")["ja4"]


def test_error_surfaces_from_native():
    with pytest.raises(curlpro.CurlProError, match="not found"):
        curlpro.Session("no-such-profile")
