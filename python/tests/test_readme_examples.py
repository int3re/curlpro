"""The README examples, executed.

Documentation drifts away from the code silently: a renamed parameter keeps the
README looking right while every copied snippet stops working. Everything shown in
the README that can run offline runs here, against the raw-header stand.

Only the online examples are left out — HTTP/3, live oracles and echo.websocket.org
are covered by test_http3.py, test_smoke.py and test_websocket.py.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import curlpro
import pytest
from curlpro import Expect

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def server():
    with RawHeaderServer(persistent=True) as srv:
        yield srv


def names(response) -> list[str]:
    """Header names as they reached the wire."""
    return [line.split(":", 1)[0].lower()
            for line in response.json()["raw"] if ":" in line]


# --- Quickstart --------------------------------------------------------------

def test_module_level_request(server):
    r = curlpro.get(server.url, impersonate="firefox-144-macos", verify=False)
    assert r.status == 200


def test_session_header_and_json_body(server):
    with curlpro.Session("chrome-151-windows", verify=False, force_http1=True) as s:
        s.headers["X-Api-Key"] = "secret"
        r = s.post(server.url, json_body={"id": 7})
    assert r.status == 200 and r.json()["request_line"].startswith("POST")


# --- The option tables -------------------------------------------------------

def test_every_documented_session_option(server):
    """Each parameter of the Session table is accepted and the session works."""
    with curlpro.Session(
        "chrome-151-windows", verify=False, force_http1=True,
        timeout=(3, 30), trust_env=False, retries=1, retry_statuses=[503],
        retry_methods=["GET"], retry_backoff=0.1, retry_max_backoff=1.0,
        respect_retry_after=True, allow_redirects=True, max_redirects=20,
        cookies=True, default_headers=True, header_order=["host"], mode="auto",
        alt_svc=False, keep_alive=True, max_idle_conns=8, idle_conn_timeout=60.0,
        resolve={"example.test:443": "127.0.0.1"}, ip_version="4",
        max_response_size=10 << 20,
    ) as s:
        assert s.get(server.url).status == 200


def test_every_documented_request_option(server):
    with curlpro.Session("chrome-151-windows", verify=False, force_http1=True) as s:
        r = s.get(server.url, params={"page": 2}, auth=("user", "pw"),
                  headers={"X-One": "1"}, header_order=["host"],
                  timeout=(3, 30), protocol=1.1, cookies=False,
                  session_headers=False, default_headers=True, mode="navigate",
                  allow_redirects=True, max_redirects=5, retries=0, proxy=False)
    assert r.proto == "HTTP/1.1"


def test_documented_response_surface(server):
    with curlpro.Session(verify=False, force_http1=True) as s:
        r = s.get(server.url)
    assert (r.status, r.ok, r.proto) == (200, True, "HTTP/1.1")
    assert r.text and r.content and r.json()
    assert r.header("content-type") and r.headers
    assert r.cookies == {} and r.history == [] and r.elapsed >= 0
    r.raise_for_status()


# --- Session memory ----------------------------------------------------------

def test_memory_switches(server):
    with curlpro.Session(verify=False, force_http1=True) as s:
        s.headers["X-Api-Key"] = "secret"
        s.cookies.set("sid", "abc", domain="localhost")

        bare = names(s.get(server.url, cookies=False, session_headers=False))
        assert "cookie" not in bare and "x-api-key" not in bare

        full = names(s.get(server.url))
        assert "cookie" in full and "x-api-key" in full


# --- Expectations and rollback -----------------------------------------------

def test_expectation_fields(server):
    with curlpro.Session(verify=False, force_http1=True) as s:
        s.get(server.url, expect=Expect(status=200, body="request_line",
                                        not_body="captcha", non_empty=True,
                                        json=True, headers="content-type",
                                        not_headers="x-nope"))
        with pytest.raises(curlpro.ExpectationFailed) as exc:
            s.get(server.url, expect=Expect(body="Dashboard"))
    assert exc.value.response.status == 200
    assert exc.value.code == "expectation"


def test_rollback_and_transaction(server):
    with curlpro.Session(verify=False, force_http1=True) as s:
        s.cookies.set("before", "1", domain="localhost")

        with pytest.raises(curlpro.ExpectationFailed):
            s.get(server.url, expect=Expect(body="nothing like this"),
                  rollback_cookies=True)
        assert [c.name for c in s.cookies.all()] == ["before"]

        with pytest.raises(RuntimeError):
            with s.cookies.transaction():
                s.cookies.set("inside", "2", domain="localhost")
                raise RuntimeError("a failure in the middle of the block")
        assert [c.name for c in s.cookies.all()] == ["before"]


# --- Hooks -------------------------------------------------------------------

def test_three_hooks(server):
    seen: dict[str, object] = {}
    with curlpro.Session(verify=False, force_http1=True) as s:
        @s.on_request
        def sign(meta):
            meta.setdefault("headers", {})["X-Signature"] = "sig"

        @s.on_response
        def log(resp):
            seen["status"] = resp.status

        @s.on_error
        def alert(exc):
            seen["error"] = type(exc).__name__

        assert "x-signature" in names(s.get(server.url))
        assert seen["status"] == 200

        with pytest.raises(curlpro.ExpectationFailed):
            s.get(server.url, expect=Expect(status=999))
    assert seen["error"] == "ExpectationFailed"


# --- Streaming, cookies, profiles --------------------------------------------

def test_streaming_examples(server):
    with curlpro.Session(verify=False, force_http1=True) as s:
        with s.stream("GET", server.url, timeout=5) as r:
            assert b"".join(r.iter_content(64 * 1024))
        with s.stream("GET", server.url) as r:
            assert list(r.iter_lines())


def test_cookie_files(tmp_path):
    with curlpro.Session(verify=False) as s:
        s.cookies.set("sid", "abc", domain="example.com")
        s.cookies.save(tmp_path / "state.json")
        s.cookies.save_netscape(tmp_path / "cookies.txt")

    with curlpro.Session(verify=False) as s:
        s.cookies.load_file(tmp_path / "cookies.txt")
        assert s.cookies["sid"] == "abc"
        s.cookies.clear()
        s.cookies.load_file(tmp_path / "state.json")
        assert s.cookies["sid"] == "abc"


def test_profile_registration():
    curlpro.register_profile({
        "name": "chrome-153-readme",
        "based_on": "chrome-152-windows",
        "headers": {"user_agent": "...Chrome/153.0.0.0..."},
    })
    base = curlpro.Profile.from_file(REPO / "profiles" / "chrome-152-windows.json")
    base.derive("chrome-154-readme",
                headers={"user_agent": "...Chrome/154.0.0.0..."}).register()

    known = curlpro.list_profiles()
    assert {"chrome-153-readme", "chrome-154-readme"} <= set(known)


def test_mobile_profile_with_random_device(server):
    with curlpro.Session("chrome-152-android", device="random",
                         verify=False, force_http1=True) as s:
        assert s.get(server.url).status == 200


# --- Header sets and async ----------------------------------------------------

def test_navigate_and_fetch_sets(server):
    with curlpro.Session(verify=False, force_http1=True) as s:
        assert "upgrade-insecure-requests" in names(s.get(server.url))
        assert "upgrade-insecure-requests" not in names(
            s.get(server.url, headers={"X-Api-Key": "k"}))
        assert "upgrade-insecure-requests" in names(
            s.get(server.url, headers={"X-Api-Key": "k"}, mode="navigate"))


def test_async_examples(server):
    async def run():
        async with curlpro.AsyncSession("chrome-151-windows",
                                        verify=False, force_http1=True) as s:
            answers = await asyncio.gather(*(s.get(server.url) for _ in range(4)))
            assert all(r.status == 200 for r in answers)
            async with s.stream("GET", server.url) as r:
                assert b"".join([chunk async for chunk in r.iter_content()])

    asyncio.run(run())
