"""HTTP/3 checks.

The fingerprint is compared with real Chrome: quic.browserleaks.com returns
h3_text, which for Chrome 144 looks exactly like CHROME_H3.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[2]
ORACLE = "https://quic.browserleaks.com/fp"

# The baseline captured from a real Chrome 144.
CHROME_H3 = "1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p"


def _quic_reachable() -> bool:
    # Check the TCP port: if the host is unreachable, UDP certainly is.
    try:
        with socket.create_connection(("quic.browserleaks.com", 443), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _quic_reachable(), reason="no access to quic.browserleaks.com")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_http3_negotiated():
    with curlpro.Session(http3=True) as s:
        r = s.get(ORACLE)
    assert r.status == 200
    assert r.proto.startswith("HTTP/3")


def test_http3_fingerprint_matches_chrome():
    with curlpro.Session(http3=True) as s:
        body = s.get(ORACLE).json()
    assert body["h3_text"] == CHROME_H3


def test_http3_fingerprint_is_stable():
    """The fingerprint must not change from request to request.

    Catches two races that have already happened: the control stream going out in
    parallel with the request, and PRIORITY_UPDATE sent once instead of per
    request.
    """
    with curlpro.Session(http3=True) as s:
        seen = {s.get(ORACLE).json()["h3_text"] for _ in range(4)}
    assert seen == {CHROME_H3}, f"the fingerprint is unstable: {seen}"


def test_ja4_marks_quic_transport():
    """JA4 over QUIC starts with 'q', over TCP with 't'."""
    with curlpro.Session(http3=True) as s:
        quic_ja4 = s.get(ORACLE).json()["ja4"]
    assert quic_ja4.startswith("q13d"), quic_ja4


def test_http3_requires_profile_support():
    """A profile without an http3 section must not quietly fall back to TCP."""
    with pytest.raises(curlpro.CurlProError, match="no http3 section"):
        curlpro.Session("firefox-144-macos", http3=True)


def test_brotli_response_is_decompressed():
    """The profile advertises br and zstd — so the response must be decodable.

    Before decompression existed this request returned compressed bytes and JSON
    parsing failed on the first character.
    """
    with curlpro.Session(http3=True) as s:
        r = s.get(ORACLE)
    assert r.json()["h3_text"]  # it parsed, so it was decompressed
