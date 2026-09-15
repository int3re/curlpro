"""A header given as None is removed; one given as "" is sent empty.

Both used to go out as an empty header, and the only way to lose one profile
header was default_headers=False — which loses the User-Agent and the order
with it. The case that found it: a client that never navigates and does not
want sec-fetch-user, on a profile whose fetch set did not exist yet.
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


def wire(response) -> dict[str, str]:
    """Header names (lowercase) and values as they reached the wire."""
    out = {}
    for line in response.json()["raw"]:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def session(**kw):
    kw.setdefault("verify", False)
    kw.setdefault("force_http1", True)
    return curlpro.Session("firefox-155-windows", **kw)


def test_none_removes_a_profile_header_and_leaves_the_rest(server):
    with session() as s:
        got = wire(s.get(server.url, headers={"Sec-Fetch-User": None}))
    assert "sec-fetch-user" not in got
    # The neighbours stay: this is not default_headers=False.
    assert got["upgrade-insecure-requests"] == "1"
    assert "Firefox/155" in got["user-agent"]


def test_an_empty_string_is_sent_as_an_empty_header(server):
    """A browser's fetch() sends an empty header when told to; so does this."""
    with session() as s:
        got = wire(s.get(server.url, headers={"Sec-Fetch-User": "", "X-Empty": ""}))
    assert got["sec-fetch-user"] == ""
    assert got["x-empty"] == ""


def test_a_session_level_none_applies_to_every_request(server):
    with session() as s:
        s.headers["Sec-Fetch-User"] = None
        assert s.headers.suppressed == ["Sec-Fetch-User"]
        assert "Sec-Fetch-User" not in s.headers, "a removal is not a value"
        assert "sec-fetch-user" not in [n.lower() for n in s.fingerprint().headers]
        for _ in range(2):
            assert "sec-fetch-user" not in wire(s.get(server.url))

        # The request's own value beats the session's removal.
        assert wire(s.get(server.url, headers={"Sec-Fetch-User": "?1"}))["sec-fetch-user"] == "?1"

        # del lifts a removal the same way it drops a value.
        del s.headers["Sec-Fetch-User"]
        assert s.headers.suppressed == []
        assert wire(s.get(server.url))["sec-fetch-user"] == "?1"

        # And a value set later lifts it too.
        s.headers["Sec-Fetch-User"] = None
        s.headers["Sec-Fetch-User"] = "?1"
        assert s.headers.suppressed == []


def test_clear_lifts_removals_as_well(server):
    with session() as s:
        s.headers["X-Api-Key"] = "k"
        s.headers["Sec-Fetch-User"] = None
        assert s.headers.clear() == 2
        assert s.headers.suppressed == []
        assert wire(s.get(server.url))["sec-fetch-user"] == "?1"


def test_a_value_that_is_neither_string_nor_none_is_refused_by_name(server):
    with session() as s:
        with pytest.raises(TypeError, match="X-Count"):
            s.get(server.url, headers={"X-Count": 5})
        with pytest.raises(TypeError, match="string"):
            s.headers["X-Count"] = 5


def test_a_persona_carries_a_removal(server, tmp_path):
    """The identity file says which header is gone, and the next run honours it."""
    p = curlpro.Persona.new("firefox-155-windows", headers={"Sec-Fetch-User": None})
    path = p.save(tmp_path / "acc.json")
    again = curlpro.Persona.load(path)
    with again.session(verify=False, force_http1=True) as s:
        assert "sec-fetch-user" not in wire(s.get(server.url))
