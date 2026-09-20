"""Every browser profile carries the sets a capture does not measure.

A raw capture sees TLS and HTTP/2. The HTTP/1.1 order and case, the fetch set
and the WebSocket handshake are measured once per family and carried by every
profile of it — and the one profile that lacked them, Firefox 155, sent
TE: trailers and no Connection: keep-alive over HTTP/1.1, and the navigation
set under mode="fetch": sec-fetch-user: ?1 beside the caller's
sec-fetch-mode: cors. The host that found it speaks HTTP/1.1 only.
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


@pytest.fixture
def server():
    with RawHeaderServer(persistent=True) as srv:
        yield srv


def wire(response) -> list[tuple[str, str]]:
    """(lowercase name, value) pairs as they reached the wire, in order."""
    out = []
    for line in response.json()["raw"]:
        if ":" in line:
            k, v = line.split(":", 1)
            out.append((k.strip().lower(), v.strip()))
    return out


def test_firefox_155_sends_the_fetch_set_under_mode_fetch(server):
    with curlpro.Session("firefox-155-windows", verify=False, force_http1=True) as s:
        got = dict(wire(s.post(server.url, json_body={"a": 1}, mode="fetch")))
    assert "sec-fetch-user" not in got and "upgrade-insecure-requests" not in got
    assert got["accept"] == "*/*"
    assert got["sec-fetch-mode"] == "cors" and got["sec-fetch-dest"] == "empty"
    assert got["priority"] == "u=4", "Firefox's fetch priority, measured"
    assert got["connection"] == "keep-alive"
    assert "te" not in got, "Firefox sends TE over HTTP/2 only"


def test_firefox_155_navigation_over_http1_is_the_measured_set(server):
    """The transport the SmartCaptcha host speaks — and where the profile was wrong."""
    with curlpro.Session("firefox-155-windows", verify=False, force_http1=True) as s:
        pairs = wire(s.get(server.url))
    names = [n for n, _ in pairs]
    got = dict(pairs)
    assert got["connection"] == "keep-alive"
    assert "te" not in got
    assert names[:5] == ["host", "user-agent", "accept", "accept-language", "accept-encoding"]
    assert names.index("connection") < names.index("upgrade-insecure-requests")
    assert names[-1] == "priority"


@pytest.mark.parametrize("profile", ["firefox-155-windows", "chrome-152-windows"])
def test_fetch_metadata_values_switch_the_set_by_themselves(server, profile):
    """The reproduction from the report, without mode=: the names are known to
    the navigation set, so only the values can say this is a fetch."""
    with curlpro.Session(profile, verify=False, force_http1=True) as s:
        got = dict(wire(s.get(server.url, headers={"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"})))
    assert "sec-fetch-user" not in got and "upgrade-insecure-requests" not in got
    assert got["accept"] == "*/*"
    assert got["sec-fetch-mode"] == "cors"


def test_an_explicit_fetch_on_a_profile_without_a_set_is_refused(server):
    """Refused with the reason, not quietly navigational.

    okhttp is the example since 0.9.0: it is a library, it has no fetch
    concept at all, while the Safari profiles carry a derived set.
    """
    with pytest.raises(curlpro.ProfileCapabilityError, match="no fetch header set"):
        curlpro.Session("okhttp-5.5-jvm", mode="fetch")
    with curlpro.Session("okhttp-5.5-jvm", verify=False, force_http1=True) as s:
        with pytest.raises(curlpro.ProfileCapabilityError, match="no fetch header set"):
            s.get(server.url, mode="fetch")
        # Auto mode still works: the navigation set is the only one there is.
        assert s.get(server.url).status == 200


def test_every_browser_profile_has_an_http1_set():
    """A profile without http1.order sends its HTTP/2 set over HTTP/1.1 with
    the case approximated and no Connection header — the gap Firefox 155 had."""
    missing = []
    for name in curlpro.list_profiles():
        if name.startswith("okhttp"):
            continue  # a library, measured over HTTP/2 only
        with curlpro.Session(name) as s:
            h1 = [n.lower() for n in s.fingerprint().headers_http1]
        if "connection" not in h1:
            missing.append(name)
    assert missing == [], f"no HTTP/1.1 set: {missing}"


def test_firefox_family_drops_te_over_http1_and_keeps_it_over_http2():
    for name in ("firefox-133-macos", "firefox-144-macos", "firefox-155-windows", "tor-14-macos"):
        with curlpro.Session(name) as s:
            fp = s.fingerprint()
        assert "te" in [n.lower() for n in fp.headers], name
        assert "te" not in [n.lower() for n in fp.headers_http1], name


def test_every_browser_profile_accepts_mode_fetch():
    families = ("chrome-", "edge-", "firefox-", "tor-", "yandex-", "safari-")
    for name in curlpro.list_profiles():
        if name.startswith(families):
            with curlpro.Session(name, mode="fetch") as s:
                assert s.impersonate == name
