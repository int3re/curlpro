"""The session memory switched off per request: the jar and the session headers.

A scraper needs one request that carries nothing of the session — a probe, a
health check, a call to a third-party API from the same session — and it must
bring nothing back either.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import curlpro
import pytest
from curlpro import Expect, ExpectationFailed

from flakyserver import FlakyServer
from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def sent(response) -> list[str]:
    """The raw request lines the server saw."""
    return response.json()["raw"]


def header(response, name: str) -> str:
    lowered = name.lower() + ":"
    for line in sent(response):
        if line.lower().startswith(lowered):
            return line.split(":", 1)[1].strip()
    return ""


# --- cookies ------------------------------------------------------------------

def test_request_without_cookies_sends_none():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.cookies.set("sid", "abc", domain="localhost")
            assert header(s.get(srv.url), "cookie") == "sid=abc"
            assert header(s.get(srv.url, cookies=False), "cookie") == ""
            # The switch applies to one request, not to the session.
            assert header(s.get(srv.url), "cookie") == "sid=abc"


def test_isolated_request_does_not_fill_the_jar():
    with FlakyServer() as srv:
        url = srv.scenario("/set", [{
            "status": 200, "body": "ok", "headers": {"Set-Cookie": "probe=1; Path=/"},
        }])
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.get(url, cookies=False)
            assert len(s.cookies) == 0, "an isolated request wrote into the jar"
            s.get(url)
            assert s.cookies["probe"] == "1"


def test_cookies_true_without_a_jar_is_rejected():
    """Asking for a jar that does not exist is a mistake, not a no-op."""
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True, cookies=False) as s:
            with pytest.raises(curlpro.CurlProError, match="cookie jar"):
                s.get(srv.url, cookies=True)


# --- session headers ----------------------------------------------------------

def test_request_without_session_headers():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.headers["X-Api-Key"] = "secret"
            assert header(s.get(srv.url), "x-api-key") == "secret"

            lines = sent(s.get(srv.url, session_headers=False))
            names = [ln.split(":", 1)[0].lower() for ln in lines if ":" in ln]
            assert "x-api-key" not in names
            # The profile headers are a different switch and must stay.
            assert "sec-fetch-site" in names

            assert header(s.get(srv.url), "x-api-key") == "secret"


def test_request_headers_survive_without_session_headers():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.headers["X-Session"] = "from-session"
            r = s.get(srv.url, headers={"X-Request": "from-request"},
                      session_headers=False)
    assert header(r, "x-request") == "from-request"
    assert header(r, "x-session") == ""


def test_both_switches_together_leave_only_the_profile():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.headers["X-Api-Key"] = "secret"
            s.cookies.set("sid", "abc", domain="localhost")
            lines = sent(s.get(srv.url, cookies=False, session_headers=False))
    names = [ln.split(":", 1)[0].lower() for ln in lines if ":" in ln]
    assert "x-api-key" not in names and "cookie" not in names
    assert "user-agent" in names, "the profile headers must remain"


def test_stream_takes_the_switches_too():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.cookies.set("sid", "abc", domain="localhost")
            with s.stream("GET", srv.url, cookies=False) as r:
                body = r.read().decode()
    assert "Cookie" not in body


# --- the async session --------------------------------------------------------

def test_async_session_has_the_same_switches_and_expectations():
    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            s.cookies.set("sid", "abc", domain="localhost")
            with_jar = await s.get(srv.url)
            without = await s.get(srv.url, cookies=False)

            failures: list[BaseException] = []
            s.on_error(failures.append)
            with pytest.raises(ExpectationFailed):
                await s.get(srv.url, expect=Expect(status=404))
            return header(with_jar, "cookie"), header(without, "cookie"), failures

    with RawHeaderServer(persistent=True) as srv:
        with_jar, without, failures = asyncio.run(run(srv))
    assert with_jar == "sid=abc" and without == ""
    assert len(failures) == 1 and isinstance(failures[0], ExpectationFailed)


def test_async_rollback_undoes_a_failed_request():
    async def run(url):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            s.cookies.set("sid", "old", domain="localhost")
            with pytest.raises(ExpectationFailed):
                await s.get(url, expect=Expect(body="welcome"), rollback_cookies=True)
            return s.cookies["sid"]

    with FlakyServer() as srv:
        url = srv.scenario("/login", [{
            "status": 200, "body": "no", "headers": {"Set-Cookie": "sid=new; Path=/"},
        }])
        assert asyncio.run(run(url)) == "old"
