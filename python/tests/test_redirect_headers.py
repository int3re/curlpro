"""Every redirect hop carries the headers the server answered it with.

A chain used to hand back only where each hop pointed. What a hop *said* — a
`Set-Cookie` the jar swallowed, an anti-bot's mark on a 302, a `Retry-After` —
was gone by the time the last response arrived.
"""

from __future__ import annotations

import asyncio

import curlpro
import pytest
from echo_stand import EchoStand


def chain(st: EchoStand) -> str:
    """Three hops: /a -> /b -> /c -> 200, each saying something of its own."""
    st.routes["/a"] = (302, [("Location", st.url + "/b"),
                             ("Set-Cookie", "first=1; path=/"),
                             ("X-Hop", "a")], b"")
    st.routes["/b"] = (301, [("Location", st.url + "/c"),
                             ("Set-Cookie", "second=2; path=/"),
                             ("X-Hop", "b"),
                             ("Retry-After", "7")], b"")
    st.routes["/c"] = (200, [("X-Hop", "c")], b"{}")
    return st.url + "/a"


def test_each_hop_keeps_its_own_headers():
    with EchoStand() as st, curlpro.Session("chrome-154-windows") as s:
        r = s.get(chain(st))
    assert r.status == 200 and len(r.history) == 2
    first, second = r.history
    assert (first.status, second.status) == (302, 301)
    assert first.header("x-hop") == "a" and second.header("x-hop") == "b"
    # The hop's own Set-Cookie, which only the jar used to remember.
    assert first.header("set-cookie").startswith("first=1")
    assert second.header("set-cookie").startswith("second=2")
    # A header one hop sent and the other did not.
    assert second.header("retry-after") == "7" and first.header("retry-after") is None
    # The final response's headers are its own, not a hop's.
    assert r.header("x-hop") == "c"


def test_the_headers_are_a_Headers_mapping():
    with EchoStand() as st, curlpro.Session("chrome-154-windows") as s:
        hop = s.get(chain(st)).history[0]
    assert isinstance(hop.headers, curlpro.Headers)
    assert hop.headers.get("X-HOP") == "a"          # any case, string-like
    assert hop.headers.get_list("x-hop") == ["a"]
    assert hop.headers.first("nothing") is None


def test_a_response_without_redirects_has_an_empty_history():
    with EchoStand() as st, curlpro.Session("chrome-154-windows") as s:
        assert s.get(st.url + "/plain").history == []


def test_a_stream_and_an_async_session_carry_them_too():
    with EchoStand() as st:
        url = chain(st)
        with curlpro.Session("chrome-154-windows") as s, s.stream("GET", url) as r:
            assert r.history[0].header("x-hop") == "a"

        async def go():
            async with curlpro.AsyncSession("chrome-154-windows") as s:
                return (await s.get(url)).history
        hops = asyncio.run(go())
        assert [h.header("x-hop") for h in hops] == ["a", "b"]


def test_a_hop_that_said_nothing_of_its_own_still_has_headers():
    # The native side leaves the field out when a hop had no headers at all
    # (json omitempty); the Python side must still give a usable mapping.
    hop = curlpro.session.Redirect(302, "https://a.test/", "https://b.test/")
    assert isinstance(hop.headers, curlpro.Headers)
    assert hop.headers.first("anything") is None
    with pytest.raises(AttributeError):
        hop.nothing_like_this = 1          # __slots__, as the other response types
