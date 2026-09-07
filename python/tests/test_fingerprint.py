"""The fingerprint of a session, computed without asking anyone.

The value of this is not only convenience. Until it existed, every check of
"does our TLS look like Chrome" needed tls.browserleaks.com to be up — and on
the day this was written it was not, twice. A local answer turns a network
question into an offline one.

The arithmetic itself is checked in Go against 47 captures
(internal/fingerprint/baseline_test.go); here the concern is the Python surface.
"""

from __future__ import annotations

from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_fingerprint_needs_no_network():
    with curlpro.Session("chrome-151-windows") as s:
        fp = s.fingerprint()

    assert fp.profile == "chrome-151-windows"
    assert fp.ja4.startswith("t13d"), fp.ja4
    assert fp.ja3n and len(fp.ja3n) == 32
    assert fp.akamai.count("|") == 3, fp.akamai
    assert fp.headers, "no header order"
    assert "Chrome/151" in fp.user_agent


def test_the_value_matches_the_captured_reference():
    """The one number this whole feature stands on.

    reference/baselines holds what tls.browserleaks.com actually answered for
    this profile. If the local computation ever drifts from it, everything else
    here is decoration.
    """
    import json

    baseline = json.loads(
        (REPO / "reference" / "baselines" / "chrome-151-windows.json").read_text("utf-8"))
    with curlpro.Session("chrome-151-windows") as s:
        fp = s.fingerprint()

    assert fp.ja4 in baseline["ja4"], f"{fp.ja4} not in {baseline['ja4']}"
    assert fp.akamai == baseline["akamai"]


def test_the_host_does_not_move_it():
    """JA4 is stable across domains — that independence is why it replaced JA3."""
    with curlpro.Session("chrome-151-windows") as s:
        a = s.fingerprint("https://example.com/")
        b = s.fingerprint("https://a-much-longer-name.example.org/path?q=1")
    assert a.ja4 == b.ja4
    assert a.ja3n == b.ja3n


def test_force_http1_changes_alpn_and_therefore_ja4():
    """ALPN is two characters of JA4_a, so restricting it changes the value.

    Legitimately: a browser without h2 does look different. Reporting the
    unrestricted fingerprint would describe a session other than this one.
    """
    with curlpro.Session("chrome-151-windows") as h2, \
         curlpro.Session("chrome-151-windows", force_http1=True) as h1:
        a, b = h2.fingerprint(), h1.fingerprint()

    assert a.ja4[:10].endswith("h2"), a.ja4
    assert b.ja4[:10].endswith("h1"), b.ja4
    assert a.ja4 != b.ja4


def test_plain_ja3_moves_while_ja4_does_not():
    """Chrome ≥110 shuffles its extensions, and JA3 keeps the send order.

    So JA3 differs between connections and JA4 does not. This is documented
    behaviour rather than a defect: a frozen order is itself an anomaly.
    """
    seen_ja3, seen_ja4 = set(), set()
    for _ in range(10):
        with curlpro.Session("chrome-151-windows") as s:
            fp = s.fingerprint()
            seen_ja3.add(fp.ja3)
            seen_ja4.add(fp.ja4)
    assert len(seen_ja4) == 1, f"JA4 moved: {seen_ja4}"
    assert len(seen_ja3) > 1, "the extensions are not being shuffled"


def test_diff_names_what_changed_between_two_chromes():
    """The question a profile edit actually raises: did a server notice?"""
    with curlpro.Session("chrome-151-windows") as a, \
         curlpro.Session("chrome-152-windows") as b:
        d = a.fingerprint().diff(b.fingerprint())

    assert "ja4" in d, "two Chrome versions must differ somewhere"
    # Chrome 152 brought trust_anchors (0xCA34); the diff should say so rather
    # than merely reporting that the hashes are unequal.
    before, after = d["extensions"]
    assert "ca34" in set(after) - set(before), d["extensions"]


def test_two_sessions_of_one_profile_compare_equal():
    with curlpro.Session("chrome-151-windows") as a, \
         curlpro.Session("chrome-151-windows") as b:
        assert a.fingerprint() == b.fingerprint()


def test_a_closed_session_says_so():
    s = curlpro.Session("chrome-151-windows")
    s.close()
    with pytest.raises(RuntimeError, match="session is closed"):
        s.fingerprint()


def test_the_dict_form_is_serialisable():
    import json

    with curlpro.Session("chrome-151-windows") as s:
        data = s.fingerprint().to_dict()
    json.dumps(data)  # storable next to a scraper's own state
    assert data["ja4"] and data["akamai"]
