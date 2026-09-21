"""The page a request is made from: Referer, Origin and sec-fetch-site.

Measured on Chrome 153 and Firefox 156 (cmd/hcapture -origins, 2026-09-19),
where the two agreed on every value: the Referer is the page's URL to its own
origin and the page's origin elsewhere; the Origin is the page's origin, on
every cross-origin fetch and on any request with a body; sec-fetch-site is the
relation between the page and the URL. Before this a fetch to an API on
another origin went out with the API's own origin in Origin, no Referer and
sec-fetch-site: same-origin — three headers a browser never sends together.
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
    out = {}
    for line in response.json()["raw"]:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def order(response) -> list[str]:
    return [line.split(":", 1)[0].lower() for line in response.json()["raw"] if ":" in line]


def session(**kw):
    kw.setdefault("verify", False)
    kw.setdefault("force_http1", True)
    return curlpro.Session("chrome-152-windows", **kw)


def test_a_fetch_from_a_page_on_another_site(server):
    page = "https://www.example.test/app/index.html?tab=1"
    # A JSON POST to another site is preceded by a CORS preflight since 0.10
    # (test_preflight.py); the raw stand answers none, and the question here
    # is the request's own headers.
    with session(page=page, preflight=False) as s:
        got = wire(s.post(server.url + "api/v1", json_body={"a": 1}))
    assert got["origin"] == "https://www.example.test"
    assert got["referer"] == "https://www.example.test/"
    assert got["sec-fetch-site"] == "cross-site"
    assert got["sec-fetch-mode"] == "cors"


def test_a_fetch_from_a_page_on_the_same_origin(server):
    page = server.url + "app/index.html?tab=1"
    with session(page=page) as s:
        get = wire(s.get(server.url + "so-get", headers={"X-Api-Key": "k"}))
        post = wire(s.post(server.url + "so-post", json_body={"a": 1}))
    assert "origin" not in get, "a same-origin GET fetch carries no Origin"
    assert get["referer"] == page, "the full URL, query included, to its own origin"
    assert get["sec-fetch-site"] == "same-origin"
    assert post["origin"] == server.url.rstrip("/")
    assert post["sec-fetch-site"] == "same-origin"


def test_a_navigation_from_a_page(server):
    with session(page="https://www.example.test/app") as s:
        got = wire(s.get(server.url + "cs-nav"))
        names = order(s.get(server.url + "cs-nav"))
    assert got["sec-fetch-mode"] == "navigate"
    assert got["sec-fetch-site"] == "cross-site"
    assert got["referer"] == "https://www.example.test/"
    assert got["sec-fetch-user"] == "?1", "a navigation from a page is a click"
    assert "origin" not in got
    # Chromium puts the Referer right after Sec-Fetch-Dest.
    assert names.index("referer") == names.index("sec-fetch-dest") + 1


def test_the_page_moves_with_the_scraper(server):
    with session() as s:
        first = wire(s.get(server.url + "app"))
        assert "referer" not in first and first["sec-fetch-site"] == "none"
        s.page = server.url + "app"
        assert s.page == server.url + "app"
        second = wire(s.get(server.url + "next"))
        assert second["referer"] == server.url + "app"
        assert second["sec-fetch-site"] == "same-origin"
        s.page = None
        assert s.page is None
        third = wire(s.get(server.url + "later"))
        assert "referer" not in third and third["sec-fetch-site"] == "none"


def test_a_request_s_page_wins_and_false_means_none(server):
    with session(page="https://www.example.test/app") as s:
        own = wire(s.get(server.url + "x", page=server.url + "home"))
        none = wire(s.get(server.url + "x", page=False))
        default = wire(s.get(server.url + "x"))
    assert own["referer"] == server.url + "home" and own["sec-fetch-site"] == "same-origin"
    assert "referer" not in none and none["sec-fetch-site"] == "none"
    assert default["sec-fetch-site"] == "cross-site"


def test_a_page_that_is_not_an_absolute_url_is_refused(server):
    with pytest.raises(curlpro.CurlProError, match="absolute http"):
        curlpro.Session("chrome-152-windows", page="example.test/app")
    with session() as s:
        with pytest.raises(curlpro.CurlProError, match="absolute http"):
            s.page = "/relative"
        with pytest.raises(curlpro.CurlProError, match="absolute http"):
            s.get(server.url, page="ftp://x/")
        with pytest.raises(TypeError, match="page"):
            s.get(server.url, page=5)


def test_the_fingerprint_shows_the_page_s_headers():
    with curlpro.Session("firefox-155-windows", page="https://www.example.test/app") as s:
        fp = s.fingerprint("https://api.example.test/v1")
    values = {h["name"].lower(): h["value"] for h in fp.to_dict()["header_values"]}
    assert values["referer"] == "https://www.example.test/"
    assert values["sec-fetch-site"] == "same-site"
    assert fp.to_dict()["url"] == "https://api.example.test/v1"
    names = [n.lower() for n in fp.headers]
    # Firefox: Referer before upgrade-insecure-requests, where it was measured.
    assert names.index("referer") < names.index("upgrade-insecure-requests")


def test_the_websocket_origin_is_the_page_s():
    with curlpro.Session("chrome-152-windows", page="https://www.example.test/app") as s:
        assert s.page == "https://www.example.test/app"


# --- the audit -------------------------------------------------------------

def test_a_hand_written_referer_next_to_none_is_a_finding():
    with curlpro.Session("chrome-152-windows") as s:
        s.headers["Referer"] = "https://www.example.test/app"
        found = s.audit()
    assert ("referer_site", "high") in [(f.code, f.level) for f in found]
    assert "page=" in next(f for f in found if f.code == "referer_site").fix


def test_a_page_is_silent_in_the_audit():
    for profile in ("chrome-152-windows", "firefox-155-windows"):
        with curlpro.Session(profile, page="https://www.example.test/app") as s:
            assert "referer_site" not in {f.code for f in s.audit()}, profile


def test_referer_and_origin_from_different_pages_is_a_finding():
    with curlpro.Session("chrome-152-windows", page="https://www.example.test/app") as s:
        s.headers["Origin"] = "https://other.test"
        assert "referer_site" in {f.code for f in s.audit()}
