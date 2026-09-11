"""The fingerprint of a session, computed without asking anyone.

The value of this is not only convenience. Until it existed, every check of
"does our TLS look like Chrome" needed tls.browserleaks.com to be up — and on
the day this was written it was not, twice. A local answer turns a network
question into an offline one.

The arithmetic itself is checked in Go against 50 captures
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


# --- JA4H -----------------------------------------------------------------
#
# Skipped when the library was built with -tags nofoxio: there the
# FoxIO-licensed code is not compiled in and both JA4H fields are empty by
# design. Asserting on them would turn a supported build into a test failure.

def _skip_without_ja4h():
    """Asked at call time, not at import: the profiles are loaded by a fixture,
    and a session built during collection would fail before they exist."""
    with curlpro.Session() as s:
        if not s.fingerprint("https://example.com").ja4h_available:
            pytest.skip("built with -tags nofoxio: JA4H is not compiled in")

#
# Licensed differently from the rest: FoxIO License 1.1, patent-pending. Free
# for internal and academic use; commercial monetisation needs an OEM licence.
# Said here as well as in the code, because a test file is where someone looks
# to find out what a feature actually does.

def test_ja4h_describes_the_request():
    _skip_without_ja4h()
    with curlpro.Session("chrome-151-windows") as s:
        fp = s.fingerprint()

    parts = fp.ja4h.split("_")
    assert len(parts) == 4, fp.ja4h
    assert parts[0].startswith("ge20"), parts[0]      # GET over HTTP/2
    # No cookies on a bare session: both cookie hashes are the zero form rather
    # than the hash of an empty string.
    assert parts[2] == parts[3] == "000000000000", fp.ja4h


def test_ja4h_follows_the_protocol_and_its_header_set():
    """The version and the header list move together.

    Chrome drops priority over HTTP/1.1 and gains Connection, so a session
    forced to HTTP/1.1 has a different count and a different name hash. Taking
    the version from one transport and the headers from the other would
    describe a request nobody makes — which is exactly the bug this test was
    written after.
    """
    _skip_without_ja4h()
    with curlpro.Session("chrome-151-windows") as h2, \
         curlpro.Session("chrome-151-windows", force_http1=True) as h1:
        a, b = h2.fingerprint(), h1.fingerprint()

    assert a.ja4h.startswith("ge20"), a.ja4h
    assert b.ja4h.startswith("ge11"), b.ja4h
    assert a.ja4h.split("_")[1] != b.ja4h.split("_")[1], "the name hashes did not move"


def test_ja4h_separates_the_profiles():
    """Different browsers send different header sets, and JA4H must show it."""
    _skip_without_ja4h()
    seen = {}
    for name in ("chrome-151-windows", "firefox-133-macos", "safari-18.4-macos"):
        with curlpro.Session(name) as s:
            seen[name] = s.fingerprint().ja4h
    assert len(set(seen.values())) == 3, seen


def test_ja4h_is_stable_across_sessions():
    values = set()
    for _ in range(5):
        with curlpro.Session("chrome-151-windows") as s:
            values.add(s.fingerprint().ja4h)
    assert len(values) == 1, values


# --- TLS session resumption -----------------------------------------------

def test_resume_does_not_change_the_first_handshake():
    """The fingerprint of a first connection must be untouched.

    The resuming ClientHello carries pre_shared_key; the first one cannot,
    since there is nothing to resume with. If enabling resumption moved the
    fingerprint, every stored baseline would be wrong for every session that
    uses it — so this is the check that makes the option safe to turn on.
    """
    with curlpro.Session("chrome-151-windows") as plain, \
         curlpro.Session("chrome-151-windows", resume=True) as resuming:
        assert plain.fingerprint().ja4 == resuming.fingerprint().ja4
        assert plain.fingerprint().ja3n == resuming.fingerprint().ja3n


def test_fingerprints_are_hashable_and_hash_like_they_compare():
    """A set of fingerprints used to raise TypeError: __eq__ was defined and
    __hash__ was not. Equal ones must land in the same bucket."""
    with curlpro.Session("chrome-151-windows") as a, curlpro.Session("chrome-151-windows") as b:
        x, y = a.fingerprint(), b.fingerprint()
    assert x == y
    assert hash(x) == hash(y)
    assert len({x, y}) == 1
    with curlpro.Session("firefox-144-macos") as c:
        z = c.fingerprint()
    assert len({x, z}) == 2

