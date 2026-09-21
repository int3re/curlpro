"""The CORS preflight: sent when a browser sends one, checked, cached, exposed.

Measured on Chrome 153 and Firefox 156 (cmd/hcapture -origins, 2026-09-21).
"""
import asyncio

import pytest

import curlpro
from echo_stand import EchoStand

PAGE = "http://www.example.test/app"


def allowing(rec):
    return (204, [("Access-Control-Allow-Origin", rec.get("origin", "*")),
                  ("Access-Control-Allow-Credentials", "true"),
                  ("Access-Control-Allow-Methods", "GET, POST, DELETE"),
                  ("Access-Control-Allow-Headers", "content-type, x-api-key"),
                  ("Access-Control-Max-Age", "600")], b"")


def test_preflight_goes_before_a_json_post_from_a_page():
    with EchoStand() as st, curlpro.Session("chrome-151-windows", page=PAGE) as s:
        st.routes["/api"] = lambda rec: allowing(rec) if rec["method"] == "OPTIONS" else (200, [], b"{}")
        r = s.post(st.url + "/api", json_body={"a": 1}, mode="fetch", headers={"X-Api-Key": "k"})
        assert st.methods() == ["OPTIONS /api", "POST /api"]
        pf, real = st.seen
        assert pf["access-control-request-method"] == "POST"
        assert pf["access-control-request-headers"] == "content-type,x-api-key"
        assert pf["origin"] == "http://www.example.test"
        assert pf["accept"] == "*/*" and pf["sec-fetch-mode"] == "cors"
        # Neither the request's own headers nor cookies nor client hints ride on it.
        for absent in ("x-api-key", "content-type", "cookie", "sec-ch-ua"):
            assert absent not in pf
        assert real["x-api-key"] == "k"
        # The caller sees it on the response.
        assert r.preflight is not None and r.preflight.status == 204 and not r.preflight.cached
        assert r.preflights[0].headers.get("Access-Control-Max-Age") == ["600"]
        # Within Access-Control-Max-Age the answer is reused.
        r = s.post(st.url + "/api", json_body={"a": 2}, mode="fetch", headers={"X-Api-Key": "k"})
        assert st.methods() == ["OPTIONS /api", "POST /api", "POST /api"]
        assert r.preflight.cached


def test_preflight_order_on_http1_matches_the_profile_case():
    with EchoStand() as st, curlpro.Session("chrome-151-windows", page=PAGE) as s:
        st.routes["/api"] = lambda rec: allowing(rec) if rec["method"] == "OPTIONS" else (200, [], b"{}")
        s.delete(st.url + "/api", mode="fetch")
        pf = st.seen[0]
        assert pf["method"] == "OPTIONS"
        assert "access-control-request-headers" not in pf  # a DELETE names no headers
        order = [k for k in pf["_order"] if k.lower() not in ("host", "connection")]
        assert order[:4] == ["Accept", "Access-Control-Request-Method", "Origin", "User-Agent"]
        assert "Priority" not in order and "priority" not in order  # Chrome sends none over HTTP/1.1


def test_no_preflight_where_a_browser_sends_none():
    with EchoStand() as st, curlpro.Session("chrome-151-windows", page=PAGE) as s:
        s.get(st.url + "/x", mode="fetch")                                   # a plain GET
        s.post(st.url + "/x", data="a=1", mode="fetch",
               headers={"Content-Type": "application/x-www-form-urlencoded"})  # a form body
        s.post(st.url + "/x", json_body={"a": 1}, mode="navigate")            # a navigation
        s.post(st.url + "/x", json_body={"a": 1}, mode="fetch", page=st.url + "/app")  # same origin
        assert "OPTIONS" not in " ".join(st.methods())


def test_preflight_for_previews_without_sending():
    with curlpro.Session("firefox-155-windows", page=PAGE) as s:
        assert s.preflight_for("GET", "https://api.example.org/v1", mode="fetch") is None
        pf = s.preflight_for("POST", "https://api.example.org/v1", mode="fetch",
                             headers={"Content-Type": "application/json", "X-Api-Key": "k"})
        assert list(pf)[:6] == ["user-agent", "accept", "accept-language", "accept-encoding",
                                "access-control-request-method", "access-control-request-headers"]
        assert pf["access-control-request-headers"] == "content-type,x-api-key"
        assert pf["origin"] == "http://www.example.test" and pf["sec-fetch-site"] == "cross-site"

    async def on_the_async_session():
        async with curlpro.AsyncSession("firefox-155-windows", page=PAGE) as a:
            return a.preflight_for("DELETE", "https://api.example.org/v1", mode="fetch")
    assert asyncio.run(on_the_async_session()) is not None


def test_refusal_is_a_cors_error_and_the_request_is_not_sent():
    with EchoStand() as st, curlpro.Session("chrome-151-windows", page=PAGE, retries=2) as s:
        st.routes["/api"] = lambda rec: (200, [("Access-Control-Allow-Origin", "http://other.example.test")], b"") \
            if rec["method"] == "OPTIONS" else (200, [], b"{}")
        with pytest.raises(curlpro.CORSError) as ei:
            s.post(st.url + "/api", json_body={"a": 1}, mode="fetch")
        e = ei.value
        assert e.code == "cors" and e.status == 200 and e.method == "POST"
        assert "does not match" in e.reason and e.headers["Access-Control-Allow-Origin"]
        assert not isinstance(e, curlpro.PermanentError)
        assert st.methods() == ["OPTIONS /api"]  # not sent, not retried

        # A wildcard does not cover a credentialed request.
        st.routes["/api2"] = lambda rec: (204, [("Access-Control-Allow-Origin", "*"),
                                                ("Access-Control-Allow-Headers", "*")], b"") \
            if rec["method"] == "OPTIONS" else (200, [], b"{}")
        with pytest.raises(curlpro.CORSError, match="credentials"):
            s.post(st.url + "/api2", json_body={"a": 1}, mode="fetch", credentials="include")


def test_preflight_can_be_switched_off():
    with EchoStand() as st, curlpro.Session("chrome-151-windows", page=PAGE, preflight=False) as s:
        s.post(st.url + "/api", json_body={"a": 1}, mode="fetch")
        st.routes["/api"] = lambda rec: allowing(rec) if rec["method"] == "OPTIONS" else (200, [], b"{}")
        s.post(st.url + "/api", json_body={"a": 1}, mode="fetch", preflight=True)
        assert st.methods() == ["POST /api", "OPTIONS /api", "POST /api"]


def test_the_async_response_carries_the_preflight_and_the_history():
    # The third field report: the OPTIONS went out on AsyncSession too, but
    # its Response was built without preflights — and without history.
    async def go(st):
        async with curlpro.AsyncSession("chrome-151-windows", page=PAGE) as a:
            r = await a.get(st.url + "/api", mode="fetch", headers={"X-Api-Key": "k"})
            hop = await a.get(st.url + "/r", mode="navigate")
            return r, hop
    with EchoStand() as st:
        st.routes["/api"] = lambda rec: allowing(rec) if rec["method"] == "OPTIONS" else (200, [], b"{}")
        st.routes["/r"] = (302, [("Location", st.url + "/x")], b"")
        r, hop = asyncio.run(go(st))
    assert st.methods()[:2] == ["OPTIONS /api", "GET /api"]
    assert r.preflight is not None and r.preflight.status == 204
    assert [h.status for h in hop.history] == [302] and hop.elapsed > 0
