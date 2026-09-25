"""The fixes of 0.12, from one field report (five complaints and a question).

1. ``response.headers`` was a plain dict: ``.get("retry-after")`` quietly
   returned ``None`` and a solver's ``Retry-After`` was never honoured.
2. ``devices`` changed meaning in 0.11 without a word: desktop profiles list
   builds there, not phones. ``device_kind`` now says which.
3. The exceptions were declared in the private ``curlpro._ffi``.
4. The verbs took ``**kw: Any``: mypy and editors checked nothing.
5. No default body limit.
6. Does a request survive a kept-alive connection the server has closed? It
   did not: over HTTP/1.1 the dead connection was handed out again.
"""

from __future__ import annotations

import importlib.util
import json
import pickle
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import curlpro
import pytest
from curlpro import session as session_module
from echo_stand import EchoStand

REPO = Path(__file__).resolve().parents[2]


# --- 1. headers ------------------------------------------------------------

def test_response_headers_are_found_by_any_case():
    with EchoStand() as st, curlpro.Session("chrome-153-windows") as s:
        st.routes["/r"] = (429, [("retry-after", "120"), ("Set-Cookie", "a=1"), ("set-cookie", "b=2")], b"{}")
        r = s.get(st.url + "/r")
    h = r.headers
    assert isinstance(h, dict) and isinstance(h, curlpro.Headers)
    assert h.get("retry-after") == ["120"] == h["RETRY-AFTER"] == h.get("Retry-After")
    assert "retry-after" in h and "x-absent" not in h and h.get("x-absent") is None
    assert h.first("retry-after") == "120" and r.header("retry-after") == "120"
    assert h.get("set-cookie") == ["a=1", "b=2"], "values stay lists, every one of them"
    # Iteration and equality are a dict's: the stored spelling is kept.
    assert "Retry-After" in list(h) and dict(h)["Retry-After"] == ["120"]
    assert json.loads(json.dumps(h))["Retry-After"] == ["120"]
    again = pickle.loads(pickle.dumps(h))
    assert isinstance(again, curlpro.Headers) and again.get("retry-after") == ["120"]


def test_headers_mutation_keeps_one_entry_per_name():
    h = curlpro.Headers({"Content-Type": ["text/html"]})
    h["content-type"] = ["application/json"]
    assert list(h) == ["Content-Type"] and h["CONTENT-TYPE"] == ["application/json"]
    h.update({"X-A": ["1"]}, x_b=["2"])
    del h["x-a"]
    assert "X-A" not in h and h.pop("x-missing", None) is None
    assert h.setdefault("content-type", ["other"]) == ["application/json"]
    copy = h.copy()
    assert isinstance(copy, curlpro.Headers) and copy is not h and copy == h


def test_every_response_shape_carries_headers():
    page = "https://www.example.test/app"
    with EchoStand() as st, curlpro.Session("chrome-153-windows", page=page) as s:
        st.routes["/api"] = lambda rec: (
            (204, [("Access-Control-Allow-Origin", rec.get("origin", "*")),
                   ("Access-Control-Allow-Headers", "content-type")], b"")
            if rec["method"] == "OPTIONS" else (200, [("x-stream", "yes")], b"{}"))
        r = s.post(st.url + "/api", json_body={"a": 1}, mode="fetch")
        assert r.preflight is not None
        assert r.preflight.headers.get("access-control-allow-origin")
        with s.stream("GET", st.url + "/api", mode="fetch") as sr:
            assert sr.headers.get("X-STREAM") == ["yes"]
        st.routes["/no"] = lambda rec: (200, [("x-why", "no")], b"")
        with pytest.raises(curlpro.CORSError) as info:
            s.post(st.url + "/no", json_body={"a": 1}, mode="fetch")
        assert isinstance(info.value.headers, curlpro.Headers)


def test_async_responses_carry_headers():
    import asyncio

    async def main():
        with EchoStand() as st:
            st.routes["/r"] = (200, [("retry-after", "5")], b"ok")
            async with curlpro.AsyncSession("chrome-153-windows") as s:
                r = await s.get(st.url + "/r")
                assert r.headers.get("retry-after") == ["5"]
                async with s.stream("GET", st.url + "/r") as sr:
                    assert sr.headers.get("RETRY-AFTER") == ["5"]

    asyncio.run(main())


# --- 2. device_kind --------------------------------------------------------

@pytest.mark.parametrize("name,kind", [
    ("chrome-152-android", "phone"),
    ("yandex-26.8-android", "phone"),
    ("chrome-153-windows", "desktop"),
    ("chrome-151-macos", "desktop"),
    ("safari-26-ios", "iphone"),
    ("firefox-150-linux", "distro"),
    ("chrome-150-macos", ""),
    ("edge-153-windows", ""),
    ("safari-18.0-macos", ""),
])
def test_device_kind_says_what_the_pool_is(name, kind):
    assert curlpro.capabilities(name)["device_kind"] == kind
    with curlpro.Session(name) as s:
        assert s.fingerprint().device_kind == kind
        assert s.fingerprint().to_dict()["device_kind"] == kind


def test_a_phone_filter_written_for_0_10_has_a_field_to_read():
    """The code the report described: "profiles with devices are phones"."""
    phones = [n for n in curlpro.list_profiles()
              if curlpro.capabilities(n)["device_kind"] == "phone"]
    assert sorted(phones) == ["chrome-152-android", "yandex-26.8-android"]


# --- 3. errors -------------------------------------------------------------

def test_exceptions_live_in_a_public_module():
    names = ("CurlProError", "Timeout", "HTTPError", "WebSocketClosed", "PermanentError",
             "ProfileCapabilityError", "ConfigurationError", "ProxyError", "ProxyAuthError", "CORSError")
    from curlpro import _ffi, errors
    for name in names:
        cls = getattr(curlpro, name)
        assert cls.__module__ == "curlpro.errors", name
        assert getattr(errors, name) is cls
        # Code written before 0.12 imported them from the private module.
        assert getattr(_ffi, name) is cls


def test_a_raised_error_names_the_public_module():
    with pytest.raises(curlpro.ConfigurationError) as info:
        curlpro.Session("netscape-4")
    assert type(info.value).__module__ == "curlpro.errors"


# --- 4. signatures ---------------------------------------------------------

def _kwonly(f):
    import inspect
    return {n for n, p in inspect.signature(f).parameters.items() if p.kind == p.KEYWORD_ONLY}


def test_typed_kwargs_match_the_real_signatures():
    from curlpro._kwargs import OneOffKwargs, StreamKwargs, _OneOffRest
    import inspect
    assert set(curlpro.RequestKwargs.__annotations__) == _kwonly(curlpro.Session.request)
    meta = set(inspect.signature(session_module._request_meta).parameters) - {"method", "url"}
    assert set(StreamKwargs.__annotations__) == meta
    one_off = _kwonly(session_module.request)
    assert set(OneOffKwargs.__annotations__) == set(_OneOffRest.__annotations__) | one_off
    for switch in ("force_http1", "http3", "post_quantum"):
        assert switch in _kwonly(curlpro.Session.__init__) | set(
            inspect.signature(curlpro.Session.__init__).parameters)


def test_every_verb_is_annotated():
    for owner, names in ((curlpro.Session, "get post put patch delete head options"),
                         (curlpro.AsyncSession, "request get post put patch delete head options stream")):
        for name in names.split():
            ann = getattr(owner, name).__annotations__["kw"]
            assert "Unpack[" in ann, (owner.__name__, name, ann)
    for name in "get post put patch delete head options".split():
        assert getattr(curlpro, name).__annotations__["kw"] == "Unpack[OneOffKwargs]"


@pytest.mark.skipif(importlib.util.find_spec("mypy") is None, reason="mypy is not installed")
def test_mypy_catches_a_misspelt_argument():
    out = subprocess.run([sys.executable, str(REPO / "scripts" / "check-typing.py")],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


# --- 5. the default body limit --------------------------------------------

def test_buffered_responses_are_capped_by_default(monkeypatch):
    assert curlpro.DEFAULT_MAX_RESPONSE_SIZE == 100 * 1024 * 1024
    # The default is read when a session is made; a small one stands in.
    monkeypatch.setattr(session_module, "DEFAULT_MAX_RESPONSE_SIZE", 1000)
    body = b"x" * 5000
    with EchoStand() as st:
        st.routes["/big"] = (200, [], body)
        with curlpro.Session("chrome-153-windows") as s:
            with pytest.raises(curlpro.CurlProError) as info:
                s.get(st.url + "/big")
            assert info.value.code == "too_large"
            assert "max_response_size" in str(info.value) and "0 means no limit" in str(info.value)
            # A stream is not bound by the default: that is how a large body
            # is meant to be read.
            with s.stream("GET", st.url + "/big") as sr:
                assert sr.read() == body
        with curlpro.Session("chrome-153-windows", max_response_size=0) as s:
            assert s.get(st.url + "/big").content == body
        # Given explicitly, the number binds both, as before.
        with curlpro.Session("chrome-153-windows", max_response_size=1000) as s:
            with s.stream("GET", st.url + "/big") as sr, pytest.raises(curlpro.CurlProError):
                sr.read()


# --- 6. a kept-alive connection the server has closed ---------------------

class _ClosingStand:
    """HTTP/1.1 over plain TCP: answers the first request with keep-alive,
    then closes the connection while it idles — a server's keep-alive timer."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        self.requests: list[str] = []
        self.connections = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(65536)
            if not chunk:
                c.close()
                return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length":
                length = int(v)
        while len(rest) < length:
            rest += c.recv(65536)
        self.requests.append(head.split(b"\r\n")[0].decode())
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
        time.sleep(0.2)
        c.close()

    def close(self):
        self.sock.close()


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_connection_the_server_closed_is_not_reused(method):
    st = _ClosingStand()
    try:
        with curlpro.Session("chrome-153-windows", timeout=5) as s:
            assert s.get(st.url + "/one").status == 200
            time.sleep(0.8)
            r = s.request(method, st.url + "/two", data=b"x=1" if method == "POST" else None)
        assert r.status == 200
        assert st.requests.count(f"{method} /two HTTP/1.1") == 1
        assert st.connections == 2
    finally:
        st.close()
