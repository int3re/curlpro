"""The visitor beyond the browser — country, time zone, languages — and the
session moved into its browser and back.

The identity itself and the session's header run against the local stand;
the browser's time zone and the handoff start the Chrome installed here and
are skipped where there is none, and on CI.
"""

from __future__ import annotations

import os
import sys
import time

import pytest

import curlpro
from curlpro.browser import find_chrome
from curlpro.browser.chrome import to_devtools, to_record
from curlpro.identity import accept_language

sys.path.insert(0, os.path.dirname(__file__))
from challenge_stand import Stand  # noqa: E402


@pytest.fixture()
def stand():
    s = Stand()
    yield s
    s.close()


browser = pytest.mark.skipif(
    find_chrome() is None or bool(os.environ.get("CI")),
    reason="needs the Chrome installed on this machine, and a screen for its window")


def test_the_header_chrome_writes_for_a_list_of_languages():
    # As this machine's Chrome 154 wrote it for ru-RU, ru, en-US, en.
    assert accept_language(("ru-RU", "ru", "en-US", "en")) == "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
    assert accept_language(("en-US", "en")) == "en-US,en;q=0.9"


def test_an_identity_for_a_country():
    de = curlpro.Identity.for_country("de")
    assert (de.country, de.timezone, de.languages) == ("DE", "Europe/Berlin", ("de-DE", "de", "en-US", "en"))
    us = curlpro.Identity.for_country("US")
    assert us.languages == ("en-US", "en") and us.timezone == "America/New_York"
    own = curlpro.Identity.for_country("US", timezone="America/Los_Angeles")
    assert own.timezone == "America/Los_Angeles"
    with pytest.raises(ValueError):
        curlpro.Identity.for_country("XX")
    odd = curlpro.Identity.for_country("XX", timezone="UTC", languages=["en"])
    assert odd.languages == ("en",)


def test_a_lookup_reads_the_service(stand):
    ident = curlpro.Identity.lookup(url=stand.base + "/geo", impersonate="chrome-154-windows")
    assert ident == curlpro.Identity("DE", "Europe/Berlin", ("de-DE", "de", "en-US", "en"), "203.0.113.7")


def test_the_session_speaks_the_identity_s_languages(stand):
    ident = curlpro.Identity.for_country("FR")
    with curlpro.Session("chrome-154-windows") as plain, \
            curlpro.Session("chrome-154-windows", identity=ident) as s:
        before = list(plain.headers_for("GET", "https://example.com/"))
        sent = s.headers_for("GET", "https://example.com/")
        assert sent["accept-language"] == "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
        # In the profile's place for the header, not appended.
        assert list(sent) == before
        assert s.identity is ident
    with pytest.raises(TypeError):
        curlpro.Session("chrome-154-windows", identity={"country": "FR"})


def test_a_cookie_goes_to_the_browser_as_it_was():
    host = {"name": "a", "value": "1", "domain": "shop.test", "path": "/", "secure": True,
            "http_only": True, "same_site": "lax", "host_only": True, "expires": 1900000000}
    assert to_devtools(host) == {"name": "a", "value": "1", "path": "/", "secure": True, "httpOnly": True,
                                 "url": "https://shop.test/", "sameSite": "Lax", "expires": 1900000000}
    dom = {"name": "b", "value": "2", "domain": "shop.test", "path": "/x", "partition": "https://top.test"}
    d = to_devtools(dom)
    assert d["domain"] == ".shop.test" and "url" not in d
    assert d["partitionKey"] == {"topLevelSite": "https://top.test", "hasCrossSiteAncestor": False}


@pytest.mark.browser
@browser
def test_the_browser_keeps_the_identity_s_zone_everywhere(stand):
    # The page, a dedicated, a shared and a service worker: all in the
    # identity's zone and languages — a zone set on the page alone would be
    # a mismatch the workers give away.
    solver = curlpro.BrowserSolver()
    ident = curlpro.Identity.for_country("US", timezone="America/Chicago")
    with curlpro.Session(**solver.session_options(), identity=ident) as s:
        with s.browser(stand.base + "/zones"):
            for _ in range(200):
                if stand.zones:
                    break
                time.sleep(0.05)
    want = "America/Chicago|en-US,en"
    assert stand.zones and stand.zones[0] == {"page": want, "dedicated": want, "shared": want,
                                              "service": want}, stand.zones


@pytest.mark.browser
@browser
@pytest.mark.parametrize("keep_open", [False, True])
def test_the_solver_s_browser_is_the_same_visitor(stand, keep_open):
    # The check page measures the visitor the requests describe: the
    # identity's zone and languages, in a browser of its own or a context
    # of a kept-open one.
    ident = curlpro.Identity.for_country("JP")
    with curlpro.BrowserSolver(keep_open=keep_open) as solver:
        with curlpro.Session(**solver.session_options(), identity=ident, solver=solver) as s:
            assert s.get(stand.base + "/gate").status == 200
    page = stand.reports[0]
    assert (page["tz"], page["langs"]) == ("Asia/Tokyo", "ja-JP,ja,en-US,en"), page


@pytest.mark.browser
@browser
def test_the_session_goes_into_its_browser_and_back(stand):
    solver = curlpro.BrowserSolver()
    with curlpro.Session(**solver.session_options()) as s:
        s.cookies.set("from_session", "1", domain="127.0.0.1")
        with s.browser(stand.base + "/storage") as b:
            for _ in range(200):
                if stand.storage_done:
                    break
                time.sleep(0.05)
            # The page's first request carried the session's cookie.
            assert "from_session=1" in stand.storage_cookies[0]
            assert b.local_storage(stand.base)["token"] == "abc123"
        # Back in the session: the cookie the page set by script.
        echo = s.get(stand.base + "/echo-cookies").json()["cookie"]
        assert "js_cookie=1" in echo and "from_session=1" in echo
    records = [to_record(c) for c in [{"name": "x", "value": "1", "domain": "127.0.0.1", "path": "/",
                                       "expires": -1, "session": True}]]
    assert records[0]["host_only"]
