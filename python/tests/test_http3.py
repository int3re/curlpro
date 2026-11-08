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
    # The TCP port first: if the host is unreachable, UDP certainly is. Then
    # QUIC itself: a network that passes TCP and drops UDP (this machine's)
    # used to time every test out instead of skipping them.
    try:
        with socket.create_connection(("quic.browserleaks.com", 443), timeout=5):
            pass
    except OSError:
        return False
    try:
        with curlpro.Session(http3=True, trust_env=False, timeout=8) as s:
            return s.get(ORACLE).proto.startswith("HTTP/3")
    except curlpro.CurlProError:
        return False


# Goes to the internet: the network marker keeps these out of the main
# run, so an outage of someone else's service does not read as a bug here.
pytestmark = pytest.mark.network


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


# Probed once, and only when these tests run: a module-level skipif probed at
# collection, in every run, the network ones deselected or not.
@pytest.fixture(scope="module", autouse=True)
def _quic(_profiles):
    if not _quic_reachable():
        pytest.skip("no QUIC to quic.browserleaks.com from here")


# The sessions here ignore the environment's proxy (trust_env=False): HTTP/3
# cannot go through an http:// one, and a machine with HTTPS_PROXY set failed
# the whole module on configuration rather than on anything about QUIC.


def test_http3_negotiated():
    with curlpro.Session(http3=True, trust_env=False) as s:
        r = s.get(ORACLE)
    assert r.status == 200
    assert r.proto.startswith("HTTP/3")


def test_http3_fingerprint_matches_chrome():
    with curlpro.Session(http3=True, trust_env=False) as s:
        body = s.get(ORACLE).json()
    assert body["h3_text"] == CHROME_H3


def test_http3_fingerprint_is_stable():
    """The fingerprint must not change from request to request.

    Catches two races that have already happened: the control stream going out in
    parallel with the request, and PRIORITY_UPDATE sent once instead of per
    request.
    """
    seen = set()
    with curlpro.Session(http3=True, trust_env=False) as s:
        for i in range(4):
            try:
                seen.add(s.get(ORACLE).json()["h3_text"])
            except curlpro.Timeout as e:
                # A connection that goes silent after its first answers is the
                # network's doing (this machine's drops QUIC mid-connection);
                # what came before is still checked.
                if i == 0:
                    raise
                assert seen == {CHROME_H3}, f"the fingerprint is unstable: {seen}"
                pytest.skip(f"QUIC to the oracle went silent after {i} requests: {e}")
    assert seen == {CHROME_H3}, f"the fingerprint is unstable: {seen}"


def test_ja4_marks_quic_transport():
    """JA4 over QUIC starts with 'q', over TCP with 't'."""
    with curlpro.Session(http3=True, trust_env=False) as s:
        quic_ja4 = s.get(ORACLE).json()["ja4"]
    assert quic_ja4.startswith("q13d"), quic_ja4


def test_http3_requires_profile_support():
    """A profile without an http3 section must not quietly fall back to TCP."""
    with pytest.raises(curlpro.CurlProError, match="no http3 section"):
        curlpro.Session("firefox-144-macos", http3=True, trust_env=False)


def test_brotli_response_is_decompressed():
    """The profile advertises br and zstd — so the response must be decodable.

    Before decompression existed this request returned compressed bytes and JSON
    parsing failed on the first character.
    """
    with curlpro.Session(http3=True, trust_env=False) as s:
        r = s.get(ORACLE)
    assert r.json()["h3_text"]  # it parsed, so it was decompressed
