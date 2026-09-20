"""headers_for: what will go out, without sending it.

Seeing the outgoing headers used to need a server of one's own — a field
report stood up an HTTP echo to answer "does this request carry a Referer".
fingerprint() shows a plain GET in the session's own mode; this shows the
request the caller is about to make, and the test that matters is that the two
agree with the wire rather than with a second implementation of the rules.
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
    return {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip()
            for line in response.json()["raw"] if ":" in line}


@pytest.mark.parametrize("profile", ["chrome-152-windows", "firefox-155-windows"])
def test_the_preview_is_what_the_wire_gets(server, profile):
    page = "https://www.example.test/app"
    with curlpro.Session(profile, verify=False, force_http1=True, page=page) as s:
        s.headers["X-Api-Key"] = "k"
        for kw in ({"mode": "fetch"}, {"mode": "navigate"}, {}):
            preview = s.headers_for("GET", server.url + "x", protocol="http1", **kw)
            sent = wire(s.get(server.url + "x", **kw))
            assert list(preview) == [n for n in sent if n != "host"] or list(preview) == list(sent), \
                f"{kw}: {list(preview)} vs {list(sent)}"
            for name, value in preview.items():
                assert sent.get(name) == value, f"{kw}: {name}"


def test_the_preview_takes_the_request_s_own_mode_and_page(server):
    with curlpro.Session("chrome-152-windows") as s:
        nav = s.headers_for(url="https://a.test/", mode="navigate")
        fetch = s.headers_for(url="https://a.test/", mode="fetch")
        assert nav["accept"].startswith("text/html") and fetch["accept"] == "*/*"
        assert "sec-fetch-user" in nav and "sec-fetch-user" not in fetch
        with_page = s.headers_for(url="https://b.test/api", mode="fetch",
                                  page="https://a.test/app")
        assert with_page["referer"] == "https://a.test/"
        assert with_page["sec-fetch-site"] == "cross-site"


def test_the_preview_follows_the_transport(server):
    with curlpro.Session("firefox-155-windows") as s:
        h1 = s.headers_for(url="https://a.test/", protocol="http1")
        h2 = s.headers_for(url="https://a.test/", protocol="h2")
    assert "host" in h1 and "connection" in h1, "HTTP/1.1 adds both"
    assert "host" not in h2 and "connection" not in h2
    assert "te" in h2 and "te" not in h1, "Firefox sends TE over HTTP/2 only"


def test_the_preview_refuses_what_the_request_would_refuse():
    with curlpro.Session("safari-26.0-macos") as s:
        # Safari's fetch set is derived, so it is allowed — and marked.
        assert s.headers_for(mode="fetch")["accept"] == "*/*"
    with curlpro.Session("okhttp-5.5-jvm") as s:
        with pytest.raises(curlpro.ProfileCapabilityError):
            s.headers_for(mode="fetch")
    with curlpro.Session("chrome-152-windows") as s:
        with pytest.raises(curlpro.ConfigurationError, match="twice"):
            s.headers_for(header_order=["accept", "Accept"])
        with pytest.raises(curlpro.ConfigurationError, match="absolute http"):
            s.headers_for(page="nope")


def test_removals_and_order_show_in_the_preview(server):
    with curlpro.Session("chrome-152-windows", verify=False, force_http1=True) as s:
        h = s.headers_for(url=server.url, headers={"Sec-Fetch-User": None, "X-Api-Key": "k"},
                          header_order=[..., "accept", "x-api-key", ...], protocol="http1")
        names = list(h)
        assert "sec-fetch-user" not in names
        assert names.index("x-api-key") == names.index("accept") + 1
        sent = wire(s.get(server.url, headers={"Sec-Fetch-User": None, "X-Api-Key": "k"},
                          header_order=[..., "accept", "x-api-key", ...]))
        assert list(sent) == names
