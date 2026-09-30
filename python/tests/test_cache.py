"""The HTTP cache (0.14): what the session keeps and what it asks the network.

The freshness rules, the validators' positions and the partitioning by the
top-level site were measured on the hcapture -cache stand (Chrome 154,
Firefox 156) and are replayed on the Go side; these check that the Python
arguments reach it and that what comes back says how the cache served it.
The stand is cleartext and local: a cache is about which requests go out,
and that does not depend on the transport.
"""
from __future__ import annotations

import asyncio

import curlpro
import curlpro.requests as requests_compat
import pytest
from echo_stand import EchoStand

LAST_MODIFIED = "Fri, 25 Sep 2026 12:00:00 GMT"

PAGE = b"""<!doctype html><html><head><meta charset=utf-8>
<link rel=stylesheet href="/style.css">
</head><body><p>page</body></html>"""


def conditional(etag: str | None, cache_control: str, body: bytes, content_type: str = "text/plain"):
    """A route that answers 304 to its own validator, as a server does."""

    def route(rec: dict):
        headers = [("Cache-Control", cache_control), ("Content-Type", content_type)]
        if etag:
            headers.append(("ETag", etag))
        else:
            headers.append(("Last-Modified", LAST_MODIFIED))
        if (etag and rec.get("if-none-match") == etag) or (
                not etag and rec.get("if-modified-since") == LAST_MODIFIED):
            return 304, headers, b""
        return 200, headers, body

    return route


@pytest.fixture
def stand():
    with EchoStand() as st:
        st.routes["/fresh"] = conditional('"f1"', "max-age=3600", b"fresh body")
        st.routes["/nocache"] = conditional('"n1"', "no-cache", b"nocache body")
        st.routes["/lastmod"] = conditional(None, "no-cache", b"lastmod body")
        st.routes["/nostore"] = (200, [("Cache-Control", "no-store"), ("ETag", '"x1"')], b"nostore body")
        st.routes["/"] = conditional('"d1"', "no-cache", PAGE, "text/html")
        st.routes["/style.css"] = (200, [("Cache-Control", "max-age=3600"), ("Content-Type", "text/css")],
                                   b"p{color:red}")
        yield st


def asked(st: EchoStand, path: str) -> list[dict]:
    """The requests for one path that reached the server."""
    return [r for r in st.seen if r["path"].split("?", 1)[0] == path]


# --- what the cache keeps ---------------------------------------------------

def test_a_fresh_response_comes_back_with_no_request(stand):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        first = s.get(stand.url + "/fresh")
        second = s.get(stand.url + "/fresh")
    assert first.cache == "miss" and not first.from_cache
    assert second.cache == "hit" and second.from_cache
    assert second.status == 200 and second.content == first.content == b"fresh body"
    assert second.header("etag") == '"f1"', "the stored headers come back with the body"
    assert len(asked(stand, "/fresh")) == 1


def test_no_cache_is_revalidated_with_the_etag(stand):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        first = s.get(stand.url + "/nocache")
        second = s.get(stand.url + "/nocache")
    assert first.cache == "miss" and second.cache == "revalidated" and second.from_cache
    # The server answered 304; the caller sees the stored 200 and its body.
    assert second.status == 200 and second.content == b"nocache body"
    seen = asked(stand, "/nocache")
    assert len(seen) == 2
    assert "if-none-match" not in seen[0]
    assert seen[1]["if-none-match"] == '"n1"'
    # A revalidation the server asked for is not a reload: no cache-control.
    assert "cache-control" not in seen[1]


def test_last_modified_is_the_validator_without_an_etag(stand):
    with curlpro.Session("firefox-156-windows", cache=True) as s:
        s.get(stand.url + "/lastmod")
        again = s.get(stand.url + "/lastmod")
    assert again.cache == "revalidated" and again.content == b"lastmod body"
    assert asked(stand, "/lastmod")[1]["if-modified-since"] == LAST_MODIFIED


def test_no_store_is_never_kept(stand):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        outcomes = [s.get(stand.url + "/nostore").cache for _ in range(2)]
        info = s.cache_info()
    assert outcomes == ["miss", "miss"]
    assert len(asked(stand, "/nostore")) == 2
    assert info["entries"] == 0 and info["stored"] == 0


def test_a_post_does_not_touch_the_cache(stand):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        r = s.post(stand.url + "/fresh", data=b"x")
    assert r.cache is None and not r.from_cache


def test_a_session_without_a_cache_says_so(stand):
    with curlpro.Session("chrome-154-windows") as s:
        r = s.get(stand.url + "/fresh")
        again = s.get(stand.url + "/fresh")
        info = s.cache_info()
    assert r.cache is None and again.cache is None
    assert len(asked(stand, "/fresh")) == 2
    assert info == {"enabled": False, "dir": "", "entries": 0, "bytes": 0, "max_bytes": 0,
                    "hits": 0, "revalidated": 0, "misses": 0, "stored": 0}


# --- a request's cache mode -----------------------------------------------

def test_the_cache_modes(stand):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        s.get(stand.url + "/fresh")
        s.get(stand.url + "/nocache")
        before = len(stand.seen)
        # Anything stored answers, stale or not, with no request at all.
        assert s.get(stand.url + "/nocache", cache="force-cache").cache == "hit"
        assert s.get(stand.url + "/nocache", cache="only-if-cached").cache == "hit"
        missing = s.get(stand.url + "/never", cache="only-if-cached")
        assert len(stand.seen) == before, "force-cache and only-if-cached went to the network"
        assert missing.status == 504 and not missing.from_cache
        # no-store neither reads nor writes.
        bypass = s.get(stand.url + "/fresh", cache="no-store")
        assert bypass.cache is None and len(asked(stand, "/fresh")) == 2
        # no-cache revalidates even a fresh entry: a reload.
        reload = s.get(stand.url + "/fresh", cache="no-cache")
        assert reload.cache == "revalidated" and reload.content == b"fresh body"
        assert asked(stand, "/fresh")[-1]["if-none-match"] == '"f1"'


@pytest.mark.parametrize("profile,header", [("chrome-154-windows", "max-age=0"),
                                            ("firefox-156-windows", None)])
def test_a_reload_says_so_where_the_browser_does(stand, profile, header):
    with curlpro.Session(profile, cache=True) as s:
        s.get(stand.url + "/nocache")
        r = s.get(stand.url + "/nocache", cache="no-cache")
        assert r.cache == "revalidated"
        wire = asked(stand, "/nocache")[-1]
        assert wire.get("cache-control") == header
        assert wire["if-none-match"] == '"n1"'
        # The preview shows the reload's header; the validators depend on
        # what is stored when the request goes, and are not previewed.
        preview = s.headers_for("GET", "https://www.example.test/", mode="navigate", cache="no-cache")
        assert {k.lower(): v for k, v in preview.items()}.get("cache-control") == header
        plain = s.headers_for("GET", "https://www.example.test/", mode="navigate")
        assert "cache-control" not in {k.lower() for k in plain}


def test_the_reload_header_goes_out_without_a_cache(stand):
    # Nothing to revalidate, but the reload button says so all the same.
    with curlpro.Session("chrome-154-windows") as s:
        r = s.get(stand.url + "/fresh", cache="no-cache")
    assert r.cache is None
    assert stand.last()["cache-control"] == "max-age=0"


# --- keyed by the top-level site -------------------------------------------

def test_partitioned_by_the_top_level_site(stand):
    url = stand.url + "/fresh"
    with curlpro.Session("firefox-156-windows", cache=True) as s:
        under = [s.get(url, resource="image", page=page).cache for page in (
            "https://www.a.example/", "https://shop.a.example/other",
            "https://b.example/", "https://www.a.example/again")]
        # A frame of b under a: the top level names a's partition.
        framed = s.get(url, resource="image", page="https://b.example/frame",
                       top_level="https://a.example/").cache
        # The session's top level does the same for every request.
        s.page, s.top_level = "https://b.example/frame", "https://www.a.example/"
        session_wide = s.get(url, resource="image").cache
        # False takes the page for the top level again: b's partition.
        own = s.get(url, resource="image", top_level=False).cache
    assert under == ["miss", "hit", "miss", "hit"]
    assert framed == "hit" and session_wide == "hit" and own == "hit"
    assert len(asked(stand, "/fresh")) == 2, "once per site"


# --- on disk, counted, cleared ---------------------------------------------

def test_a_disk_cache_outlives_its_session(stand, tmp_path):
    where = tmp_path / "http-cache"
    with curlpro.Session("chrome-154-windows", cache=where) as s:
        assert s.get(stand.url + "/fresh").cache == "miss"
        assert s.cache_info()["dir"] == str(where)
    # The next run starts as a returning visitor.
    with curlpro.Session("chrome-154-windows", cache=str(where)) as s:
        r = s.get(stand.url + "/fresh")
        assert r.cache == "hit" and r.content == b"fresh body"
        assert len(asked(stand, "/fresh")) == 1
        assert list(where.glob("*.curlpro-cache"))
        s.clear_cache()
        assert not list(where.glob("*.curlpro-cache")), "clear_cache left files on disk"
        assert s.get(stand.url + "/fresh").cache == "miss"


def test_cache_info_counts_and_clear_cache_empties(stand):
    with curlpro.Session("chrome-154-windows", cache=True, cache_size=1 << 20) as s:
        s.get(stand.url + "/fresh")
        s.get(stand.url + "/fresh")
        s.get(stand.url + "/nocache")
        s.get(stand.url + "/nocache")
        info = s.cache_info()
        assert info["enabled"] and info["dir"] == "" and info["max_bytes"] == 1 << 20
        assert (info["hits"], info["revalidated"], info["misses"], info["stored"]) == (1, 1, 2, 2)
        assert info["entries"] == 2 and info["bytes"] > 0
        s.clear_cache()
        after = s.cache_info()
        assert after["entries"] == 0 and after["bytes"] == 0
        assert after["hits"] == 1, "the counters describe the session, and stay"
        assert s.get(stand.url + "/fresh").cache == "miss"


def test_the_default_sizes(stand, tmp_path):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        assert s.cache_info()["max_bytes"] == 64 << 20
    with curlpro.Session("chrome-154-windows", cache=tmp_path) as s:
        assert s.cache_info()["max_bytes"] == 256 << 20


def test_a_stream_reports_the_cache(stand):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        with s.stream("GET", stand.url + "/fresh") as first:
            assert first.cache == "miss" and not first.from_cache
            # Stored as it is read, once it is read to the end.
            assert first.read() == b"fresh body"
        with s.stream("GET", stand.url + "/fresh") as second:
            assert second.cache == "hit" and second.from_cache
            assert second.read() == b"fresh body"
    assert len(asked(stand, "/fresh")) == 1


# --- a page reload -----------------------------------------------------------

def test_load_page_reload_revalidates_the_document_alone(stand):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        first = s.load_page(stand.url + "/", favicon=False)
        assert first.document.cache == "miss"
        assert [r.response.cache for r in first.resources] == ["miss"]
        again = s.load_page(stand.url + "/", favicon=False)
        reload = s.load_page(stand.url + "/", favicon=False, reload=True)
    # A plain visit: the no-cache document is revalidated, as the server
    # asked, and says nothing of a reload; the fresh stylesheet is a hit.
    assert again.document.cache == "revalidated"
    assert [r.response.cache for r in again.resources] == ["hit"]
    # The reload: the document with the reload's header, the stylesheet still
    # out of the cache — a reload revalidates the document alone.
    assert reload.document.cache == "revalidated" and reload.document.text == PAGE.decode()
    assert [r.response.cache for r in reload.resources] == ["hit"]
    docs = asked(stand, "/")
    assert [d.get("cache-control") for d in docs] == [None, None, "max-age=0"]
    assert docs[-1]["if-none-match"] == '"d1"'
    assert len(asked(stand, "/style.css")) == 1


def test_load_page_reload_and_a_contradicting_cache_mode(stand):
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        with pytest.raises(ValueError, match="reload"):
            s.load_page(stand.url + "/", reload=True, cache="force-cache")
        # The same mode twice is no contradiction.
        page = s.load_page(stand.url + "/", reload=True, cache="no-cache", favicon=False)
    assert page.document.status == 200


# --- the arguments ---------------------------------------------------------

def test_the_arguments_are_checked():
    with pytest.raises(ValueError, match="cache_size needs the cache"):
        curlpro.Session("chrome-154-windows", cache_size=1 << 20)
    with pytest.raises(ValueError, match="positive"):
        curlpro.Session("chrome-154-windows", cache=True, cache_size=0)
    with pytest.raises(ValueError, match="cache_size cannot be negative"):
        curlpro.Session("chrome-154-windows", cache=True, cache_size=-1)
    with pytest.raises(TypeError, match="cache_size must be an int"):
        curlpro.Session("chrome-154-windows", cache=True, cache_size="1M")  # type: ignore[arg-type]
    # A request's mode given to the session would make a directory of that name.
    with pytest.raises(ValueError, match="request's cache mode"):
        curlpro.Session("chrome-154-windows", cache="no-cache")
    with pytest.raises(ValueError, match="names no directory"):
        curlpro.Session("chrome-154-windows", cache="")
    with pytest.raises(TypeError, match="cache must be"):
        curlpro.Session("chrome-154-windows", cache=64)  # type: ignore[arg-type]
    with curlpro.Session("chrome-154-windows", cache=True) as s:
        # The session's switch passed to a request, refused by name.
        with pytest.raises(TypeError, match="Session\\(cache=True\\)"):
            s.get("http://127.0.0.1:1/", cache=True)  # type: ignore[arg-type]
        # The names are checked natively, where mode and credentials are.
        with pytest.raises(curlpro.ConfigurationError, match="only-if-cached"):
            s.get("http://127.0.0.1:1/", cache="sometimes")
        with pytest.raises(curlpro.ConfigurationError):
            s.headers_for("GET", "https://example.com/", cache="reload")
    s.close()
    with pytest.raises(RuntimeError, match="closed"):
        s.cache_info()
    with pytest.raises(RuntimeError, match="closed"):
        s.clear_cache()


# --- the other faces ---------------------------------------------------------

def test_async_hit_and_revalidation(stand):
    async def run() -> tuple:
        async with curlpro.AsyncSession("firefox-156-windows", cache=True) as s:
            fresh = [await s.get(stand.url + "/fresh") for _ in range(2)]
            nocache = [await s.get(stand.url + "/nocache") for _ in range(2)]
            async with s.stream("GET", stand.url + "/fresh") as st:
                streamed = (st.cache, st.from_cache, await st.read())
            info = s.cache_info()
            s.clear_cache()
            return fresh, nocache, streamed, info, s.cache_info()

    fresh, nocache, streamed, info, cleared = asyncio.run(run())
    assert [r.cache for r in fresh] == ["miss", "hit"] and fresh[1].from_cache
    assert [r.cache for r in nocache] == ["miss", "revalidated"]
    assert nocache[1].content == b"nocache body" and nocache[1].status == 200
    assert asked(stand, "/nocache")[1]["if-none-match"] == '"n1"'
    assert streamed == ("hit", True, b"fresh body")
    assert info["hits"] == 2 and info["revalidated"] == 1
    assert cleared["entries"] == 0
    assert len(asked(stand, "/fresh")) == 1


def test_the_requests_face_reads_from_cache(stand):
    # from_cache is what requests-cache calls it.
    with requests_compat.Session("chrome-154-windows", cache=True) as s:
        first = s.get(stand.url + "/fresh")
        second = s.get(stand.url + "/fresh")
    assert first.cache == "miss" and not first.from_cache
    assert second.cache == "hit" and second.from_cache


def test_the_one_off_request_takes_a_cache_mode(stand):
    r = curlpro.get(stand.url + "/fresh", impersonate="chrome-154-windows", cache="no-cache")
    assert r.cache is None and stand.last()["cache-control"] == "max-age=0"
