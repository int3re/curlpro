"""Checking the HTTP/1.1 fingerprint.

In HTTP/2 header names must be lowercase, while in HTTP/1.1 the case is free —
and browsers use it. Public oracles normalise the names, so the check runs
against a local server that returns the raw lines.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import curlpro
from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]

# The order and case of a navigational HTTP/1.1 request.
#
# Chrome 152 and Firefox 154 measured (docs/STAGE15-RESULTS.md): over HTTP/1.1
# Chrome does not send priority and Firefox does not send TE, though HTTP/2 has
# both. That is why http1.order defines the set as well as the order.
CHROME_H1 = [
    "Host", "Connection",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "Upgrade-Insecure-Requests", "User-Agent", "Accept",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
    "Accept-Encoding", "Accept-Language",
]

FIREFOX_H1 = [
    "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
    "Connection", "Upgrade-Insecure-Requests",
    "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
    "Priority",
]

# The cluster Chrome puts the custom headers of a fetch/XHR request into.
CHROME_FETCH_H1 = [
    "Host", "Connection", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua",
    "X-Api-Key", "sec-ch-ua-mobile", "Accept",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
    "Accept-Encoding", "Accept-Language",
]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def raw():
    with RawHeaderServer() as srv:
        yield srv


def fetch(srv, profile: str, **kw) -> dict:
    with curlpro.Session(profile, force_http1=True, verify=False, **kw) as s:
        return s.get(srv.url).json()


def test_chrome_header_order_and_case(raw):
    assert fetch(raw, "chrome-151-windows")["headers"] == CHROME_H1


def test_firefox_header_order_and_case(raw):
    assert fetch(raw, "firefox-144-macos")["headers"] == FIREFOX_H1


def test_case_is_not_canonicalized(raw):
    """sec-ch-* stay lowercase, though Go canonicalises names by default."""
    names = fetch(raw, "chrome-151-windows")["headers"]
    assert "sec-ch-ua" in names and "Sec-Ch-Ua" not in names
    assert "sec-ch-ua-platform" in names and "Sec-Ch-Ua-Platform" not in names
    # These, on the contrary, must be in Title-Case.
    assert "User-Agent" in names and "user-agent" not in names


def test_host_and_connection_present(raw):
    """HTTP/2 has neither, but over HTTP/1.1 a browser sends both, Host first."""
    d = fetch(raw, "chrome-151-windows")
    assert d["headers"][0] == "Host"
    assert d["headers"][1] == "Connection"
    assert any(line.startswith("Connection: keep-alive") for line in d["raw"])


def test_request_line(raw):
    assert fetch(raw, "chrome-151-windows")["request_line"] == "GET / HTTP/1.1"


def test_profiles_differ(raw):
    chrome = fetch(raw, "chrome-151-windows")["headers"]
    firefox = fetch(raw, "firefox-144-macos")["headers"]
    assert chrome != firefox
    # Firefox has Priority, Chrome over HTTP/1.1 does not have it at all.
    assert "Priority" in firefox and not any(h.lower() == "priority" for h in chrome)
    # sec-ch-* belong to Chromium only.
    assert "sec-ch-ua" in chrome and "sec-ch-ua" not in firefox


def test_custom_header_switches_to_fetch_set(raw):
    """A custom header only appears on fetch/XHR, and their set is different.

    The navigation set plus X-Api-Key is anomalous with any anchor: fetch has no
    upgrade-insecure-requests and no sec-fetch-user, its accept is */*, and the
    sec-ch-* live in the renderer cluster (measured on Chrome 152).
    """
    with curlpro.Session("chrome-151-windows", force_http1=True, verify=False) as s:
        s.headers["X-Api-Key"] = "secret"
        d = s.get(raw.url).json()
    assert d["headers"] == CHROME_FETCH_H1
    assert any(line.startswith("Accept: */*") for line in d["raw"])


def test_mode_navigate_keeps_navigation_set(raw):
    """An explicit navigate mode keeps the navigation set."""
    with curlpro.Session("chrome-151-windows", force_http1=True, verify=False,
                         mode="navigate") as s:
        s.headers["X-Api-Key"] = "secret"
        names = s.get(raw.url).json()["headers"]
    assert [h for h in names if h != "X-Api-Key"] == CHROME_H1
    assert names.index("X-Api-Key") == names.index("Accept") - 1
