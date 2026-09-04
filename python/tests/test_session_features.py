"""Retries, per-request overrides and session headers.

Checked against a local scripted server: the test must know exactly how many
attempts arrived, and public services do not show that.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

import curlpro
from flakyserver import FlakyServer
from proxyserver import HTTPProxy
from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def srv():
    with FlakyServer() as s:
        yield s


def session(**kw):
    kw.setdefault("verify", False)
    kw.setdefault("force_http1", True)
    return curlpro.Session(**kw)


# --- retries -------------------------------------------------------------


def test_retry_until_success(srv):
    url = srv.scenario("/flaky", [{"status": 503}, {"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01) as s:
        assert s.get(url).status == 200
    assert srv.hits["/flaky"] == 3, "there must be exactly three attempts"


def test_exhausted_retries_return_last_response(srv):
    """Once the attempts run out the client returns the last response, not an error.

    A server response is a result, not a client failure: curl and urllib3 behave
    the same way, and it fits raise_for_status being voluntary here.
    """
    url = srv.scenario("/always", [{"status": 500, "body": {"why": "busy"}}])
    with session(retries=2, retry_backoff=0.01) as s:
        r = s.get(url)
    assert r.status == 500
    assert r.json() == {"why": "busy"}, "the body of the last response was lost"
    assert srv.hits["/always"] == 3, "the first attempt plus two retries"


def test_post_not_retried_returns_response(srv):
    """A POST is not retried, but the server response still arrives."""
    url = srv.scenario("/post503", [{"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01) as s:
        r = s.post(url, data=b"x")
    assert r.status == 503
    assert srv.hits["/post503"] == 1


def test_no_retry_by_default(srv):
    url = srv.scenario("/once", [{"status": 503}, {"status": 200}])
    with session() as s:
        assert s.get(url).status == 503
    assert srv.hits["/once"] == 1


def test_retry_respects_retry_after(srv):
    url = srv.scenario(
        "/after",
        [{"status": 429, "headers": {"Retry-After": "1"}}, {"status": 200}],
    )
    with session(retries=2, retry_backoff=0.01) as s:
        start = time.perf_counter()
        assert s.get(url).status == 200
        elapsed = time.perf_counter() - start
    # The server asked for a second — the backoff formula would give 0.01 s.
    assert elapsed >= 0.9, f"Retry-After was ignored: {elapsed:.2f}s"


def test_post_not_retried_by_default(srv):
    """Repeating a POST may create a second order: the server may have processed
    the request and failed to answer in time, and the client cannot tell."""
    url = srv.scenario("/post", [{"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01) as s:
        assert s.post(url, data=b"x").status == 503
    assert srv.hits["/post"] == 1


def test_post_retried_when_allowed(srv):
    url = srv.scenario("/post-ok", [{"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01, retry_methods=["POST"]) as s:
        assert s.post(url, data=b"x").status == 200
    assert srv.hits["/post-ok"] == 2


def test_retry_status_list_is_configurable(srv):
    url = srv.scenario("/notfound", [{"status": 404}, {"status": 200}])
    with session(retries=2, retry_backoff=0.01, retry_statuses=[404]) as s:
        assert s.get(url).status == 200
    assert srv.hits["/notfound"] == 2


def test_per_request_retry_override(srv):
    url = srv.scenario("/req", [{"status": 503}, {"status": 200}])
    with session() as s:  # the session has no retries
        assert s.get(url, retries=2, retry_backoff=0.01).status == 200
    assert srv.hits["/req"] == 2


# --- per-request overrides -----------------------------------------------


def test_per_request_timeout(srv):
    url = srv.scenario("/slow", [{"status": 200, "delay": 3}])
    with session(timeout=30) as s:
        start = time.perf_counter()
        with pytest.raises(curlpro.CurlProError):
            s.get(url, timeout=0.6)
        assert time.perf_counter() - start < 1.5


def test_timeout_covers_whole_redirect_chain(srv):
    """One deadline covers the chain rather than each step.

    Otherwise four redirects would stretch into four timeouts.
    """
    for i in range(3):
        srv.scenario(f"/c{i}", [{"status": 302, "headers": {"Location": srv.url(f"/c{i+1}")}}])
    srv.scenario("/c3", [{"status": 200, "delay": 3}])

    with session() as s:
        start = time.perf_counter()
        with pytest.raises(curlpro.CurlProError):
            s.get(srv.url("/c0"), timeout=1.0)
        assert time.perf_counter() - start < 2.0


def test_zero_timeout_rejected(srv):
    with session() as s:
        with pytest.raises(curlpro.CurlProError, match="must be positive"):
            s.get(srv.url("/ok"), timeout=0)


def test_per_request_redirect_block(srv):
    srv.scenario("/redir", [{"status": 302, "headers": {"Location": srv.url("/dest")}}])
    srv.scenario("/dest", [{"status": 200}])
    with session(allow_redirects=True) as s:
        assert s.get(srv.url("/redir")).status == 200
        assert s.get(srv.url("/redir"), allow_redirects=False).status == 302


def test_body_survives_307_redirect(srv):
    """A 307 must keep the method and the body. BodyFile used to be lost when the
    request was copied, and an empty POST reached the server."""
    srv.scenario("/r307", [{"status": 307, "headers": {"Location": srv.url("/land")}}])
    srv.scenario("/land", [{"status": 200}])

    path = Path(tempfile.mkdtemp()) / "body.bin"
    path.write_bytes(b"A" * 4096)

    with session() as s:
        s.post(srv.url("/r307"), body_file=str(path))

    landed = [r for r in srv.requests if r["path"] == "/land"][0]
    assert landed["method"] == "POST"
    assert landed["body_len"] == 4096


def test_body_dropped_on_303(srv):
    """A 303 does the opposite: the method becomes GET and the body is dropped."""
    srv.scenario("/r303", [{"status": 303, "headers": {"Location": srv.url("/land303")}}])
    srv.scenario("/land303", [{"status": 200}])
    with session() as s:
        s.post(srv.url("/r303"), data=b"payload")
    landed = [r for r in srv.requests if r["path"] == "/land303"][0]
    assert landed["method"] == "GET"
    assert landed["body_len"] == 0


# --- proxies ---------------------------------------------------------------


def test_proxy_can_be_bypassed_per_request(srv):
    url = srv.scenario("/ok", [{"status": 200}])
    with HTTPProxy() as proxy:
        with session(proxy=f"http://{proxy.url_host}") as s:
            assert s.get(url).status == 200
            assert len(proxy.tunnels) == 1
            # proxy=False must go directly
            assert s.get(url, proxy=False).status == 200
            assert len(proxy.tunnels) == 1, "the request went through the proxy after all"


def test_proxy_can_be_overridden_per_request(srv):
    url = srv.scenario("/ok2", [{"status": 200}])
    with HTTPProxy() as first, HTTPProxy() as second:
        with session(proxy=f"http://{first.url_host}") as s:
            s.get(url, proxy=f"http://{second.url_host}")
            assert len(second.tunnels) == 1
            assert len(first.tunnels) == 0


def test_proxy_true_rejected():
    with session() as s:
        with pytest.raises(ValueError, match="meaningless"):
            s.get("https://example.com", proxy=True)


# --- session headers -------------------------------------------------------


@pytest.fixture
def raw():
    with RawHeaderServer() as srv:
        yield srv


def headers_of(srv, s) -> list[str]:
    return s.get(srv.url).json()["headers"]


def test_session_header_added_before_anchor(raw):
    """A custom header stands before the profile anchor rather than at the end.

    The browser appends its service tail (accept-encoding, cookie) last, so a
    header after it is a visible anomaly. The mode is set explicitly: without it
    a custom name switches the set to fetch (see test_http1.py).
    """
    with session(mode="navigate") as s:
        base = headers_of(raw, s)
        s.headers["X-Api-Key"] = "secret"
        after = headers_of(raw, s)

    assert "X-Api-Key" in after
    assert after.index("X-Api-Key") < after.index("Accept-Encoding")
    # The order of the profile headers did not change.
    assert [h for h in after if h != "X-Api-Key"] == base


def test_cookie_takes_profile_position(raw):
    """cookie is declared in the profile as a slot and takes its own position —
    after accept-language, not where the insertion order would put it.

    Over HTTP/1.1 Chrome does not send priority (measured on Chrome 152), so
    cookie comes last here; in HTTP/2 priority follows it.
    """
    with session(cookies=True) as s:
        s.headers["Cookie"] = "sid=abc"
        names = [h.lower() for h in headers_of(raw, s)]
    assert "cookie" in names
    assert names.index("accept-language") < names.index("cookie")
    assert names.index("cookie") == len(names) - 1


def test_session_header_removed_by_name(raw):
    with session(mode="navigate") as s:
        s.headers["X-One"] = "1"
        s.headers["X-Two"] = "2"
        del s.headers["X-One"]
        names = headers_of(raw, s)
        assert "X-Two" in names and "X-One" not in names


def test_removing_unknown_header_raises(raw):
    with session() as s:
        with pytest.raises(KeyError):
            del s.headers["X-Never-Set"]


def test_reset_keeps_profile_headers(raw):
    with session(mode="navigate") as s:
        base = headers_of(raw, s)
        s.headers["X-A"] = "1"
        s.headers["X-B"] = "2"
        assert s.headers.clear() == 2
        assert headers_of(raw, s) == base


def test_overriding_profile_header_keeps_its_position(raw):
    """The value changes while the position stays: moving it to the end would
    break the fingerprint."""
    with session(mode="navigate") as s:
        base = headers_of(raw, s)
        position = base.index("User-Agent")
        s.headers["User-Agent"] = "custom/1.0"
        after = s.get(raw.url).json()
        assert after["headers"].index("User-Agent") == position
        assert any(l == "User-Agent: custom/1.0" for l in after["raw"])


# --- added after the audit (STAGE14) ---------------------------------------


def test_per_request_zero_retries_overrides_session(srv):
    """retries=0 on a request switches the session retries off rather than inheriting them.

    Zero used to collapse into "not set", and switching retries off for one
    request was impossible.
    """
    url = srv.scenario("/zero", [{"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01) as s:
        assert s.get(url, retries=0).status == 503
    assert srv.hits["/zero"] == 1


def test_stream_accepts_request_overrides(srv):
    """stream() takes the same overrides as request()."""
    url = srv.scenario("/slow-stream", [{"status": 200, "delay": 3}])
    with session(timeout=30) as s:
        start = time.perf_counter()
        with pytest.raises(curlpro.CurlProError) as info:
            s.stream("GET", url, timeout=0.6)
        assert time.perf_counter() - start < 1.5
        assert info.value.code == "timeout"


def test_stream_early_close_keeps_session_usable(srv):
    """Closing a stream with the body unread does not spoil the next request."""
    srv.scenario("/big", [{"status": 200, "body": {"n": "z" * 200_000}}])
    srv.scenario("/after", [{"status": 200}])
    with session() as s:
        stream = s.stream("GET", srv.url("/big"))
        next(stream.iter_content(64))
        stream.close()
        assert s.get(srv.url("/after")).status == 200
