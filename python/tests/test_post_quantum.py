"""post_quantum=False and the raw ClientHello.

A field report measured the hello with a socket server of its own — 1873 bytes
for Firefox 155, of which 1216 are the X25519MLKEM768 key share — and asked
for two things: the bytes without the socket server, and a knob to send the
hello of a browser with post-quantum key agreement off, to A/B a path that
mangles anything spanning two TCP segments.
"""

from __future__ import annotations

from pathlib import Path

import curlpro
import pytest

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_the_raw_hello_is_the_message_the_fingerprint_came_from():
    with curlpro.Session("firefox-155-windows") as s:
        fp = s.fingerprint()
    raw = fp.client_hello
    assert isinstance(raw, bytes) and raw[0] == 1, "a ClientHello handshake message"
    assert len(raw) > 1460, "with the post-quantum share the hello spans two segments — as Firefox's does"


@pytest.mark.parametrize("profile", ["chrome-152-windows", "firefox-155-windows"])
def test_post_quantum_off_drops_the_share_and_keeps_ja4(profile):
    with curlpro.Session(profile) as a, curlpro.Session(profile, post_quantum=False) as b:
        fa, fb = a.fingerprint(), b.fingerprint()
    assert fa.ja4 == fb.ja4, "the groups are not part of JA4"
    assert fa.ja3n != fb.ja3n, "JA3 hashes the groups, so it moves"
    assert "11ec" in fa.curves and "11ec" not in fb.curves
    # As sets: Chrome shuffles its extensions per connection, which is why JA4 sorts them.
    assert sorted(fa.extensions) == sorted(fb.extensions)
    assert len(fb.client_hello) < 1000 < 1460 < len(fa.client_hello)


def test_post_quantum_off_still_handshakes():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session("firefox-155-windows", verify=False, force_http1=True,
                             post_quantum=False) as s:
            assert s.get(srv.url).status == 200


def test_two_sessions_of_one_profile_still_compare_equal():
    """The raw bytes carry fresh key shares and GREASE: not part of diff()."""
    with curlpro.Session("chrome-152-windows") as a, curlpro.Session("chrome-152-windows") as b:
        fa, fb = a.fingerprint(), b.fingerprint()
    assert fa.client_hello != fb.client_hello
    assert fa.diff(fb) == {}
