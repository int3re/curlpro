"""The requests-shaped face.

The point is adoption: existing code changes one import and starts looking like
a browser. So the tests are written the way requests code is written, and what
this module cannot honour must fail loudly — a silently dropped verify= or
proxies= looks like it worked until the moment it matters.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import curlpro.requests as requests
import pytest

import curlpro
from flakyserver import FlakyServer
from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_the_familiar_names_are_there():
    with RawHeaderServer(persistent=True) as srv:
        with requests.Session(verify=False, force_http1=True) as s:
            r = s.get(srv.url)

    assert r.status_code == 200
    assert r.ok and bool(r) is True
    assert isinstance(r.content, bytes)
    assert isinstance(r.text, str)
    assert r.json()["raw"]
    assert r.url.startswith("https://")
    assert isinstance(r.elapsed, datetime.timedelta)
    assert r.reason == "OK"
    assert repr(r) == "<Response [200]>"


def test_headers_are_case_insensitive():
    with FlakyServer() as srv:
        url = srv.scenario("/h", [{"status": 200, "body": "ok",
                                   "headers": {"X-Thing": "yes"}}])
        with requests.Session(verify=False, force_http1=True) as s:
            r = s.get(url)

    assert r.headers["x-thing"] == "yes"
    assert r.headers["X-THING"] == "yes"
    with pytest.raises(KeyError):
        r.headers["absent"]


def test_json_keyword_is_translated():
    """requests spells it json=, curlpro spells it json_body=."""
    with RawHeaderServer(persistent=True) as srv:
        with requests.Session(verify=False, force_http1=True) as s:
            r = s.post(srv.url, json={"a": 1})
    assert r.status_code == 200
    assert any("content-type: application/json" in line.lower()
               for line in r.json()["raw"])


def test_proxies_dict_is_translated():
    """requests keys proxies by scheme; one connection has one proxy here."""
    from proxyserver import HTTPProxy

    with HTTPProxy() as proxy, RawHeaderServer(persistent=True) as srv:
        with requests.Session(verify=False, force_http1=True,
                              proxies={"https": f"http://{proxy.url_host}"}) as s:
            r = s.get(srv.url)
    assert r.status_code == 200
    assert proxy.tunnels, "the request did not go through the proxy"


def test_raise_for_status_raises_the_shared_class():
    """A caller catching requests.HTTPError must catch what curlpro raises.

    The names are mapped onto our classes rather than duplicated: two separate
    hierarchies would mean code that catches one and is hit by the other.
    """
    with FlakyServer() as srv:
        url = srv.scenario("/gone", [{"status": 404, "body": "no"}])
        with requests.Session(verify=False, force_http1=True) as s:
            r = s.get(url)

    assert requests.HTTPError is curlpro.HTTPError
    assert issubclass(requests.HTTPError, requests.RequestException)
    with pytest.raises(requests.HTTPError):
        r.raise_for_status()


def test_module_level_calls_work_like_requests():
    with RawHeaderServer(persistent=True) as srv:
        r = requests.get(srv.url, verify=False, force_http1=True)
    assert r.status_code == 200


def test_the_profile_is_choosable_and_is_the_whole_point():
    """The shim must not flatten the profiles into one shape.

    Client hints are the clean discriminator: sec-ch-ua is Chromium's, and
    Firefox sends nothing of the sort. If both profiles produced the same
    headers, this face would be shaping the traffic instead of the profile.
    """
    def names_for(profile: str) -> list[str]:
        with RawHeaderServer(persistent=True) as srv:
            with requests.Session(profile, verify=False, force_http1=True) as s:
                return [line.split(":", 1)[0].lower()
                        for line in s.get(srv.url).json()["raw"] if ":" in line]

    chrome = names_for("chrome-151-windows")
    firefox = names_for("firefox-133-macos")

    assert any(n.startswith("sec-ch-ua") for n in chrome), chrome
    assert not any(n.startswith("sec-ch-ua") for n in firefox), firefox


def test_unsupported_arguments_are_refused_loudly():
    """Silently dropping any of these changes what goes on the wire."""
    with RawHeaderServer(persistent=True) as srv:
        with requests.Session(verify=False, force_http1=True) as s:
            for bad, expect in (
                ({"stream": True}, "curlpro.Session.stream"),
                ({"hooks": {}}, "on_request"),
                ({"verify": False}, "TLS session"),
                ({"cert": ("a", "b")}, "TLS session"),
            ):
                with pytest.raises(TypeError, match=expect):
                    s.get(srv.url, **bad)


def test_the_session_underneath_is_reachable():
    """Everything this face does not cover stays one attribute away."""
    with requests.Session("chrome-151-windows") as s:
        assert isinstance(s.curlpro, curlpro.Session)
        assert s.curlpro.fingerprint().ja4.startswith("t13d")


def test_the_timeout_difference_is_documented():
    """The one argument that is honoured but means something else.

    requests reads (connect, read-silence); curlpro reads (connect, total).
    The difference is in the direction of strictness, so carrying a value over
    is safe — but the module whose promise is "your old code works" is exactly
    the one that has to say so.
    """
    doc = requests.__doc__ or ""
    assert "(connect, total)" in doc, "the timeout difference is not documented"
    assert "silence between bytes" in doc
