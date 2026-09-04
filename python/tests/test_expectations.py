"""Expectations, the error hook and the cookie transaction.

These four things are what a scraper writes by hand around every request:
check the status, look for a marker on the page, undo a half-finished login,
log the failure. Written by hand they are forgotten one by one.
"""

from __future__ import annotations

import json
from pathlib import Path

import curlpro
import pytest
from curlpro import Expect, ExpectationFailed
from curlpro.session import Response

from flakyserver import FlakyServer
from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def make(status: int = 200, body: bytes = b"", headers: dict | None = None) -> Response:
    return Response(status=status, proto="HTTP/1.1", headers=headers or {},
                    content=body, url="https://example.com/")


# --- the checks themselves ----------------------------------------------------

def test_status_one_of():
    Expect(status=200).check(make(200))
    Expect(status=[200, 204]).check(make(204))
    with pytest.raises(ExpectationFailed, match="status 403 is not among"):
        Expect(status=[200, 204]).check(make(403))


def test_forbidden_status():
    Expect(not_status=[500, 503]).check(make(200))
    with pytest.raises(ExpectationFailed, match="among the forbidden"):
        Expect(not_status=503).check(make(503))


def test_body_markers():
    page = "<h1>Welcome, user</h1>".encode()
    Expect(body="Welcome", not_body="captcha").check(make(body=page))

    with pytest.raises(ExpectationFailed, match="does not contain 'Logout'"):
        Expect(body="Logout").check(make(body=page))
    with pytest.raises(ExpectationFailed, match="forbidden 'Welcome'"):
        Expect(not_body="Welcome").check(make(body=page))


def test_all_markers_must_be_present():
    """Several body markers mean all of them: that is how such a check reads."""
    page = b"first second"
    Expect(body=["first", "second"]).check(make(body=page))
    with pytest.raises(ExpectationFailed, match="'third'"):
        Expect(body=["first", "third"]).check(make(body=page))


def test_body_is_matched_as_text():
    """The charset is known to the response, so the marker is a word, not bytes."""
    r = make(body="Привет".encode("cp1251"),
             headers={"Content-Type": ["text/html; charset=windows-1251"]})
    Expect(body="Привет").check(r)  # noqa: RUF001


def test_headers_are_searched_as_lines():
    r = make(headers={"Set-Cookie": ["sid=abc; Path=/"], "Server": ["nginx"]})
    Expect(headers="set-cookie").check(r)          # by name
    Expect(headers="sid=abc").check(r)             # by value
    Expect(not_headers="cf-mitigated").check(r)
    with pytest.raises(ExpectationFailed, match="do not contain 'x-token'"):
        Expect(headers="x-token").check(r)
    with pytest.raises(ExpectationFailed, match="forbidden 'nginx'"):
        Expect(not_headers="nginx").check(r)


def test_non_empty_and_json():
    with pytest.raises(ExpectationFailed, match="body is empty"):
        Expect(non_empty=True).check(make(body=b""))
    Expect(non_empty=True, json=True).check(make(body=b'{"ok": true}'))
    with pytest.raises(ExpectationFailed, match="does not parse as JSON"):
        Expect(json=True).check(make(body=b"<html>"))


def test_failure_names_the_response():
    """The message must say where it happened: a scraper walks many pages."""
    with pytest.raises(ExpectationFailed) as caught:
        Expect(status=200).check(make(503))
    assert "503 https://example.com/" in str(caught.value)
    assert caught.value.status == 503
    assert caught.value.response.content == b""
    assert caught.value.code == "expectation"


# --- against a live request ---------------------------------------------------

def test_expect_runs_on_the_request():
    with FlakyServer() as srv:
        url = srv.scenario("/page", [{"status": 200, "body": "blocked: captcha"}])
        with curlpro.Session(verify=False, force_http1=True) as s:
            with pytest.raises(ExpectationFailed, match="captcha"):
                s.get(url, expect=Expect(not_body="captcha"))
            # And the same response passes when it is expected.
            r = s.get(url, expect=Expect(status=200, body="captcha"))
    assert r.status == 200


def test_expect_is_checked_after_the_hooks():
    """A hook may replace the response, and the caller gets the replacement —
    so it is the replacement that must be checked."""
    with FlakyServer() as srv:
        url = srv.scenario("/page", [{"status": 200, "body": "original"}])
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.on_response(lambda r: make(200, b"replaced"))
            with pytest.raises(ExpectationFailed, match="'original'"):
                s.get(url, expect=Expect(body="original"))


# --- the error hook -----------------------------------------------------------

def test_error_hook_sees_every_failure():
    seen: list[BaseException] = []
    with FlakyServer() as srv:
        url = srv.scenario("/page", [{"status": 500, "body": "boom"}])
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.on_error(seen.append)
            with pytest.raises(ExpectationFailed):
                s.get(url, expect=Expect(status=200))
            with pytest.raises(curlpro.CurlProError):
                s.get("https://127.0.0.1:9/")
    assert len(seen) == 2, seen
    assert isinstance(seen[0], ExpectationFailed)


def test_error_hook_can_replace_the_exception():
    class MyError(RuntimeError):
        pass

    with curlpro.Session(verify=False, timeout=2) as s:
        s.on_error(lambda exc: MyError(f"wrapped: {exc}"))
        with pytest.raises(MyError, match="wrapped:"):
            s.get("https://127.0.0.1:9/")


def test_successful_request_does_not_call_the_error_hook():
    calls = []
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.on_error(calls.append)
            assert s.get(srv.url).status == 200
    assert calls == []


def test_unknown_hook_event_is_still_rejected():
    with pytest.raises(ValueError, match="request, response and error"):
        curlpro.Session(hooks={"whenever": [print]})


# --- the cookie transaction ---------------------------------------------------

def test_rollback_undoes_what_the_failed_request_wrote():
    with FlakyServer() as srv:
        url = srv.scenario("/login", [{
            "status": 200, "body": "no", "headers": {"Set-Cookie": "sid=new; Path=/"},
        }])
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.cookies.set("sid", "old", domain="localhost")
            with pytest.raises(ExpectationFailed):
                s.get(url, expect=Expect(body="welcome"), rollback_cookies=True)
            assert s.cookies["sid"] == "old", "the failed request kept its cookie"


def test_rollback_keeps_the_cookies_of_a_successful_request():
    with FlakyServer() as srv:
        url = srv.scenario("/login", [{
            "status": 200, "body": "welcome", "headers": {"Set-Cookie": "sid=new; Path=/"},
        }])
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.get(url, expect=Expect(body="welcome"), rollback_cookies=True)
            assert s.cookies["sid"] == "new"


def test_transaction_rolls_back_on_any_exception():
    with FlakyServer() as srv:
        url = srv.scenario("/login", [{
            "status": 200, "body": "ok", "headers": {"Set-Cookie": "sid=new; Path=/"},
        }])
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.cookies.set("sid", "old", domain="localhost")
            with pytest.raises(RuntimeError):
                with s.cookies.transaction():
                    s.get(url)
                    assert s.cookies["sid"] == "new"
                    raise RuntimeError("the caller changed its mind")
            assert s.cookies["sid"] == "old"


def test_transaction_keeps_changes_on_success():
    with FlakyServer() as srv:
        url = srv.scenario("/login", [{
            "status": 200, "body": "ok", "headers": {"Set-Cookie": "sid=new; Path=/"},
        }])
        with curlpro.Session(verify=False, force_http1=True) as s:
            with s.cookies.transaction():
                s.get(url)
            assert s.cookies["sid"] == "new"


def test_snapshot_is_a_plain_list_of_records():
    """The snapshot is ordinary data: it can be stored, logged and compared."""
    with curlpro.Session() as s:
        s.cookies.set("a", "1", domain="example.com")
        saved = s.cookies.snapshot()
        json.dumps(saved)  # serialisable, so it can be kept between runs
        s.cookies.clear()
        s.cookies.restore(saved)
        assert s.cookies["a"] == "1"


def test_a_failing_error_hook_does_not_replace_the_request_error():
    """A hook is for logging, and logging must not become the diagnosis.

    Raising from a hook used to replace the exception by accident: a typo in
    the caller's logging arrived instead of the network error. Replacing is
    what returning an exception is for, and that still works.
    """
    ran_after = []
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            @s.on_error
            def broken(exc):
                raise ValueError("the hook itself failed")

            @s.on_error
            def after(exc):
                ran_after.append(type(exc).__name__)

            with pytest.raises(ExpectationFailed) as caught:
                s.get(srv.url, expect=Expect(status=418))

    # One broken hook disables itself, not the ones behind it.
    assert ran_after == ["ExpectationFailed"]
    notes = getattr(caught.value, "__notes__", [])
    if notes:  # PEP 678, Python 3.11 and up
        assert "broken" in notes[0] and "the hook itself failed" in notes[0]


def test_an_error_hook_still_replaces_by_returning():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.on_error(lambda exc: LookupError("the caller's own error"))
            with pytest.raises(LookupError):
                s.get(srv.url, expect=Expect(status=418))
