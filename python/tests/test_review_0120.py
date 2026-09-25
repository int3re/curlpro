"""The Python package's review of 2026-09-26: each finding reproduced, then fixed."""

from __future__ import annotations

import asyncio
import gc
import io
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import curlpro
import pytest
from curlpro import cookies as cookies_module
from curlpro import requests as rq
from echo_stand import EchoStand


class _Threaded:
    """A threading stand: routes map a path to a function(handler) -> (status, headers, body)."""

    def __init__(self):
        self.routes: dict = {}
        stand = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _any(self):
                n = int(self.headers.get("content-length") or 0)
                if n:
                    self.rfile.read(n)
                status, headers, body = stand.routes[self.path.split("?")[0]](self)
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _any

            def do_HEAD(self):
                status, headers, _ = stand.routes[self.path.split("?")[0]](self)
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *a):  # noqa: ANN002
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def close(self):
        self._srv.shutdown()
        self._srv.server_close()


def _slow_body_stand(parts: list[bytes], gap: float):
    """HTTP/1.1 over TCP: headers at once, then the body in parts, gap apart."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)

    def serve():
        c, _ = sock.accept()
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                data += c.recv(65536)
            body = b"".join(parts)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body))
            for part in parts:
                time.sleep(gap)
                c.sendall(part)
            time.sleep(0.5)
        except OSError:
            pass  # the client gave up first: that is what some tests are about
        finally:
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{sock.getsockname()[1]}/"


# --- C1, C2, C5: async cancellation and cleanup --------------------------

def test_a_timed_out_chunk_read_loses_nothing():
    parts = [b"AAAA", b"BBBB", b"CCCC", b"DDDD"]
    url = _slow_body_stand(parts, 0.3)

    async def main():
        got, timeouts = b"", 0
        async with curlpro.AsyncSession("chrome-153-windows", timeout=10) as s:
            async with s.stream("GET", url) as r:
                while True:
                    try:
                        chunk = await asyncio.wait_for(r.read_chunk(), 0.1)
                    except asyncio.TimeoutError:
                        timeouts += 1
                        continue
                    if not chunk:
                        break
                    got += chunk
        return got, timeouts

    got, timeouts = asyncio.run(main())
    assert got == b"".join(parts)
    assert timeouts > 0, "the stand was meant to be slower than the idle timeout"


def test_an_unclosed_async_stream_is_closed_when_collected():
    from curlpro import _ffi

    async def main():
        with EchoStand() as st:
            async with curlpro.AsyncSession("chrome-153-windows") as s:
                r = await s.stream("GET", st.url + "/x")
                sid = r._id
                del r
                gc.collect()
                with pytest.raises(curlpro.CurlProError, match="not found"):
                    _ffi._call("curlpro_stream_error", sid)

    asyncio.run(main())


# --- C3: where a request goes ---------------------------------------------

def test_an_explicit_session_proxy_beats_the_environment(monkeypatch):
    with EchoStand() as a, EchoStand() as b:
        monkeypatch.setenv("HTTP_PROXY", b.url)
        with curlpro.Session("chrome-153-windows", proxy=a.url, retries=0) as s:
            with pytest.raises(curlpro.ProxyError):   # the stand refuses the tunnel
                s.get("http://target.test/x")
        assert [r["method"] for r in a.seen] == ["CONNECT"] and b.seen == []


def test_a_stream_reads_the_environment(monkeypatch):
    with EchoStand() as proxy:
        monkeypatch.setenv("HTTP_PROXY", proxy.url)
        with curlpro.Session("chrome-153-windows", retries=0) as s:
            with pytest.raises(curlpro.ProxyError):   # the stand refuses the tunnel
                s.stream("GET", "http://target.test/x")
        assert [r["method"] for r in proxy.seen] == ["CONNECT"], "the stream went direct, from the real address"


def test_the_route_rule():
    with curlpro.Session("chrome-153-windows") as s:
        s._trust_env = False
        assert s._route("https://a.test/") is None
    with curlpro.Session("chrome-153-windows", proxy="http://p.test:1") as s:
        assert s._route("https://a.test/") is None          # the session's own, applied natively
        assert s._route("https://a.test/", False) is False  # the request's own wins


# --- C4: the caller's Content-Type ---------------------------------------

def test_json_body_keeps_the_caller_s_content_type():
    with EchoStand() as st, curlpro.Session("chrome-153-windows") as s:
        s.post(st.url + "/x", json_body={"a": 1}, headers={"Content-Type": "text/plain"})
        assert st.last()["content-type"] == "text/plain"
        s.post(st.url + "/x", json_body={"a": 1})
        assert st.last()["content-type"] == "application/json"


# --- C6: a failed stream read raises what it is ----------------------------

def test_a_stalled_stream_read_raises_a_timeout():
    url = _slow_body_stand([b"x" * 10, b"y" * 10], 2.5)
    with curlpro.Session("chrome-153-windows", timeout=1.0) as s:
        with pytest.raises(curlpro.Timeout):
            with s.stream("GET", url) as r:
                r.read()


# --- C7: the requests facade ------------------------------------------------

def test_the_requests_facade_maps_the_common_calls():
    with EchoStand() as st:
        st.routes["/r"] = (302, [("Location", "/final")], b"")
        st.routes["/j"] = (200, [], b'{"x": 1.5}')
        with rq.Session("chrome-153-windows") as s:
            s.post(st.url + "/form", data={"a": "1", "b": "two words"})
            rec = st.last()
            assert rec["content-type"] == "application/x-www-form-urlencoded"
            s.get(st.url + "/c", cookies={"sid": "abc"})
            assert "sid=abc" in st.last().get("cookie", "")
            s.get(st.url + "/p", params="a=1&b=2")
            assert st.last()["path"].endswith("/p?a=1&b=2")
            s.get(st.url + "/p", params={"k": b"v"})
            assert st.last()["path"].endswith("/p?k=v")
            assert s.get(st.url + "/j").json(parse_float=str) == {"x": "1.5"}
            s.post(st.url + "/up", files={"f": io.BytesIO(b"hello")}, data={"field": "x"})
            assert st.last()["content-type"].startswith("multipart/form-data")


def test_an_empty_proxies_mapping_is_not_set():
    with EchoStand() as proxy:
        with rq.Session("chrome-153-windows", proxy=proxy.url, retries=0) as s:
            with pytest.raises(curlpro.ProxyError):   # the stand refuses the tunnel
                s.get("http://target.test/x", proxies={})
        assert [r["method"] for r in proxy.seen] == ["CONNECT"], "proxies={} bypassed the session's proxy"


def test_the_requests_facade_head_does_not_follow():
    st = _Threaded()
    try:
        st.routes["/r"] = lambda h: (302, [("Location", "/final")], b"")
        st.routes["/final"] = lambda h: (200, [], b"")
        with rq.Session("chrome-153-windows") as s:
            assert s.head(st.url + "/r").status_code == 302
    finally:
        st.close()


# --- C8: host-only cookies survive a file ---------------------------------

def test_host_only_cookies_survive_a_netscape_round_trip():
    records = [
        {"name": "host", "value": "1", "domain": "example.test", "path": "/", "host_only": True},
        {"name": "dom", "value": "2", "domain": "example.test", "path": "/"},
    ]
    back = cookies_module.parse_netscape(cookies_module.format_netscape(records))
    by_name = {c["name"]: c for c in back}
    assert by_name["host"]["host_only"] is True
    assert by_name["dom"]["host_only"] is False


def test_a_host_only_cookie_is_exported_as_one():
    with EchoStand() as st, curlpro.Session("chrome-153-windows") as s:
        st.routes["/set"] = (200, [("Set-Cookie", "h=1; Path=/")], b"")
        s.get(st.url + "/set")
        (c,) = s.cookies.export()
        assert c.get("host_only") is True


# --- C9: a rollback touches only its own request's cookies ----------------

def test_rollback_leaves_other_requests_cookies_alone():
    st = _Threaded()
    try:
        release = threading.Event()

        def slow(h):
            release.wait(5)
            return 200, [("Set-Cookie", "half=login; Path=/")], b"not what was expected"

        st.routes["/login"] = slow
        st.routes["/csrf"] = lambda h: (200, [("Set-Cookie", "csrf=fresh; Path=/")], b"ok")
        with curlpro.Session("chrome-153-windows", timeout=10) as s:
            errors = []

            def a():
                try:
                    s.post(st.url + "/login", data=b"x", rollback_cookies=True,
                           expect=curlpro.Expect(body="welcome"))
                except curlpro.ExpectationFailed as e:
                    errors.append(e)

            t = threading.Thread(target=a)
            t.start()
            time.sleep(0.3)
            s.get(st.url + "/csrf")          # another request, in the middle of the first
            release.set()
            t.join()
            assert errors, "the expectation was meant to fail"
            names = {c["name"] for c in s.cookies.export()}
            assert "half" not in names, "the failed login was not rolled back"
            assert "csrf" in names, "the rollback erased another request's cookie"
    finally:
        st.close()


# --- C10: the BOM wins -------------------------------------------------------

def test_a_byte_order_mark_beats_the_header_charset():
    with EchoStand() as st, curlpro.Session("chrome-153-windows") as s:
        st.routes["/b"] = (200, [("Content-Type", "text/html; charset=windows-1251")],
                           "﻿<p>Привет</p>".encode("utf-8"))
        r = s.get(st.url + "/b")
        assert r.encoding == "utf-8" and r.text == "<p>Привет</p>"


# --- C11: a persona keeps its device ----------------------------------------

def test_a_persona_draws_its_device_once(tmp_path):
    p = curlpro.Persona("chrome-152-android", device="random")
    assert p.device in curlpro.capabilities("chrome-152-android")["devices"]
    path = tmp_path / "p.json"
    p.save(path)
    assert json.loads(path.read_text(encoding="utf-8"))["device"] == p.device


# --- C12: the retry parameters -----------------------------------------------

def test_retry_parameters_mean_what_they_say():
    with pytest.raises(ValueError):
        curlpro.Session("chrome-153-windows", retries=-1)
    with EchoStand() as st, curlpro.Session("chrome-153-windows", retries=3, retry_backoff=0) as s:
        st.routes["/busy"] = (503, [], b"")
        t0 = time.perf_counter()
        r = s.get(st.url + "/busy")
        assert r.status == 503 and len(st.seen) == 4
        assert time.perf_counter() - t0 < 0.5, "retry_backoff=0 slept anyway"
