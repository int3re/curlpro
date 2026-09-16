"""header_order as a pattern: the browser's order with edits, not a restatement.

A partial list used to put the listed names in one place and the rest
somewhere that depended on the profile's anchor, so "put X-Api-Key after
Accept" meant writing the whole order out and keeping it in step with the
profile. Now ``...`` stands for the profile's own order, and a pattern edits it
in place — on the profile's headers and the caller's alike.
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


def names(response) -> list[str]:
    return [line.split(":", 1)[0].lower() for line in response.json()["raw"] if ":" in line]


def session(profile="chrome-152-windows", **kw):
    kw.setdefault("verify", False)
    kw.setdefault("force_http1", True)
    return curlpro.Session(profile, **kw)


def test_a_custom_header_lands_after_its_neighbour(server):
    with session() as s:
        plain = names(s.get(server.url))
        got = names(s.get(server.url, headers={"X-Api-Key": "k"}, mode="navigate",
                          header_order=[..., "accept", "x-api-key", ...]))
    assert got.index("x-api-key") == got.index("accept") + 1
    # Everything else is exactly the browser's order.
    assert [n for n in got if n != "x-api-key"] == plain


def test_first_and_last(server):
    with session() as s:
        first = names(s.get(server.url, headers={"X-Api-Key": "k"}, mode="navigate",
                            header_order=["x-api-key", ...]))
        last = names(s.get(server.url, headers={"X-Api-Key": "k"}, mode="navigate",
                           header_order=[..., "x-api-key"]))
    assert first[0] == "x-api-key" and first[1] == "host"
    assert last[-1] == "x-api-key"


def test_two_profile_headers_can_be_swapped(server):
    """The same pattern edits the default headers, not only the custom ones."""
    with session("firefox-155-windows") as s:
        plain = names(s.get(server.url))
        got = names(s.get(server.url, header_order=[..., "accept-encoding", "accept-language", ...]))
    assert plain.index("accept-language") < plain.index("accept-encoding")
    assert got.index("accept-encoding") < got.index("accept-language")
    assert sorted(got) == sorted(plain)


def test_several_slots_keep_unlisted_headers_beside_their_neighbours(server):
    with session() as s:
        got = names(s.get(server.url, headers={"X-A": "1", "X-B": "2"}, mode="navigate",
                          header_order=[..., "user-agent", "x-a", ..., "sec-fetch-dest", "x-b", ...]))
    assert got.index("x-a") == got.index("user-agent") + 1
    assert got.index("x-b") == got.index("sec-fetch-dest") + 1
    assert got.index("accept") < got.index("sec-fetch-site") < got.index("x-b") < got.index("accept-encoding")


def test_a_session_pattern_applies_to_every_request_and_shows_in_the_fingerprint(server):
    with session(header_order=[..., "accept", "x-api-key", ...]) as s:
        s.headers["X-Api-Key"] = "k"
        fp = [n.lower() for n in s.fingerprint().headers_http1]
        assert fp.index("x-api-key") == fp.index("accept") + 1
        for _ in range(2):
            got = names(s.get(server.url, mode="navigate"))
            assert got.index("x-api-key") == got.index("accept") + 1


def test_a_list_without_ellipsis_is_the_list_then_the_rest(server):
    with session() as s:
        plain = names(s.get(server.url))
        got = names(s.get(server.url, header_order=["accept", "user-agent"]))
    assert got[:2] == ["accept", "user-agent"]
    assert got[2:] == [n for n in plain if n not in ("accept", "user-agent")]


def test_names_the_request_does_not_carry_are_skipped(server):
    with session() as s:
        got = names(s.get(server.url, header_order=[..., "accept", "x-not-sent", ...]))
    assert "x-not-sent" not in got


def test_a_bad_pattern_is_refused_by_name(server):
    with session() as s:
        with pytest.raises(curlpro.CurlProError, match="twice"):
            s.get(server.url, header_order=["accept", "Accept"])
        with pytest.raises(TypeError, match="header_order"):
            s.get(server.url, header_order=["accept", 5])
    with pytest.raises(curlpro.CurlProError, match="twice"):
        curlpro.Session("chrome-152-windows", header_order=["accept", "accept"])
