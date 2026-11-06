"""The C ABI a transparent proxy stands on (ABI 0.31): no-limit and idle
timeouts, response trailers, a request body written while the request is in
flight, and the raw connection after an upgrade.

Driven through ctypes the way a binding drives the library, against a raw
socket server that writes exactly what each case needs: chunked bodies with
trailers, a chunked upload read back, a 101 with bytes behind it.
"""
from __future__ import annotations

import ctypes
import json
import socket
import threading
import time
from pathlib import Path

import pytest

from curlpro import _ffi
from curlpro.errors import CurlProError

REPO = Path(__file__).resolve().parents[2]
lib = _ffi._lib


def _read_head(f) -> tuple[str, dict[str, str]]:
    line = f.readline().decode("latin-1").strip()
    headers: dict[str, str] = {}
    while True:
        h = f.readline().decode("latin-1")
        if h in ("\r\n", "\n", ""):
            break
        k, _, v = h.partition(":")
        headers[k.strip().lower()] = v.strip()
    return line, headers


def _read_chunked(f) -> tuple[bytes, dict[str, str]]:
    body = b""
    while True:
        size = int(f.readline().split(b";")[0].strip(), 16)
        if size == 0:
            break
        body += f.read(size)
        f.readline()
    trailers: dict[str, str] = {}
    while True:
        h = f.readline().decode("latin-1")
        if h in ("\r\n", "\n", ""):
            break
        k, _, v = h.partition(":")
        trailers[k.strip().lower()] = v.strip()
    return body, trailers


class RawStand:
    """One connection per request, answered by path."""

    def __init__(self) -> None:
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        self.seen: list[dict] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c: socket.socket) -> None:
        f = c.makefile("rb")
        try:
            line, h = _read_head(f)
            path = line.split(" ")[1]
            rec = {"path": path, "headers": h}
            self.seen.append(rec)
            if path == "/trailers":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\n"
                          b"Transfer-Encoding: chunked\r\nTrailer: grpc-status\r\n\r\n"
                          b"5\r\n\x00\x00\x00\x00\x00\r\n0\r\ngrpc-status: 5\r\ngrpc-message: not found\r\n\r\n")
            elif path == "/upload":
                body, trailers = _read_chunked(f)
                rec["body"], rec["trailers"] = body, trailers
                out = json.dumps({"body": body.decode(), "trailers": trailers}).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(out) + out)
            elif path == "/upgrade":
                c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\n"
                          b"Connection: Upgrade\r\n\r\nhello")
                while True:
                    data = c.recv(4096)
                    if not data:
                        break
                    c.sendall(data)
            elif path == "/refuse":
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\ngo away")
            elif path == "/trickle":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
                for _ in range(8):
                    c.sendall(b"x")
                    time.sleep(0.1)
            elif path == "/stall":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nstart")
                time.sleep(3)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def close(self) -> None:
        self.sock.close()


@pytest.fixture()
def stand():
    s = RawStand()
    yield s
    s.close()


@pytest.fixture()
def session():
    _ffi._call("curlpro_profiles_load_dir", str(REPO / "profiles").encode())
    sid = _ffi._call("curlpro_session_new", _ffi.encode({
        "profile": "chrome-156-windows", "default_headers": True, "follow_redirects": True,
        "max_redirects": 20, "cookies": True, "resume": True, "timeout_ms": 0,
    }))["session"]
    yield sid
    _ffi._call("curlpro_session_close", sid)


def _wait(rid: int, timeout: float = 10) -> tuple[dict, bytes]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        done = lib.curlpro_result_wait(200)
        if done == rid:
            out = ctypes.c_int(0)
            ptr = lib.curlpro_result_take(rid, ctypes.byref(out))
            try:
                return _ffi._take("curlpro_result_take", ptr, out.value)
            finally:
                lib.curlpro_free(ptr)
        assert done == 0, f"a stray result {done}"
    raise AssertionError(f"request {rid} did not finish")


def _read_all(stream: int) -> bytes:
    buf = ctypes.create_string_buffer(4096)
    out = b""
    while True:
        n = lib.curlpro_stream_read(stream, buf, 4096)
        if n == 0:
            return out
        if n < 0:
            _ffi._call("curlpro_stream_error", stream)
            raise AssertionError("read failed without an error")
        out += buf.raw[:n]


def test_response_trailers_in_the_response_and_on_a_stream(session, stand):
    data, body = _ffi.call_framed("curlpro_request", session, meta={"method": "POST", "url": stand.url + "/trailers"},
                                  body=b"\x00\x00\x00\x00\x00")
    assert data["trailers"]["Grpc-Status"] == ["5"]
    assert data["trailers"]["Grpc-Message"] == ["not found"]
    assert body == b"\x00\x00\x00\x00\x00"

    head, _ = _ffi.call_framed("curlpro_stream_open", session, meta={"method": "POST", "url": stand.url + "/trailers"})
    sid = head["stream"]
    try:
        assert _ffi._call("curlpro_stream_trailers", sid) == {"trailers": {}}
        assert _read_all(sid) == b"\x00\x00\x00\x00\x00"
        assert _ffi._call("curlpro_stream_trailers", sid)["trailers"]["Grpc-Status"] == ["5"]
    finally:
        _ffi._call("curlpro_stream_close", sid)


def test_a_streamed_body_with_trailers(session, stand):
    rid = _ffi.call_with_frame("curlpro_request_start", session,
                               meta={"method": "POST", "url": stand.url + "/upload", "body_stream": True})["request"]
    for chunk in (b"alpha-", b"beta-", b"gamma"):
        assert _ffi._call("curlpro_request_body_write", rid, chunk, len(chunk)) == {"written": len(chunk)}
    _ffi._call("curlpro_request_body_end", rid, json.dumps({"x-sum": "16"}).encode())
    data, body = _wait(rid)
    assert data["status"] == 200
    assert json.loads(body) == {"body": "alpha-beta-gamma", "trailers": {"x-sum": "16"}}
    assert stand.seen[-1]["headers"]["transfer-encoding"] == "chunked"
    # The body is gone with the request: a write now is told so.
    with pytest.raises(CurlProError) as e:
        _ffi._call("curlpro_request_body_write", rid, b"late", 4)
    assert e.value.code == "conn_closed"
    counts = _ffi._call("curlpro_debug_counts")
    assert counts["bodies"] == 0


def test_body_stream_is_refused_on_a_blocking_call(session, stand):
    for name in ("curlpro_request", "curlpro_stream_open", "curlpro_upgrade_open"):
        with pytest.raises(CurlProError) as e:
            _ffi.call_framed(name, session, meta={"method": "POST", "url": stand.url + "/upload", "body_stream": True})
        assert e.value.code == "configuration", name
    with pytest.raises(CurlProError) as e:
        _ffi.call_with_frame("curlpro_request_start", session, body=b"x",
                             meta={"method": "POST", "url": stand.url + "/upload", "body_stream": True})
    assert e.value.code == "configuration"


def test_upgrade_hands_back_the_raw_connection(session, stand):
    data, body = _ffi.call_framed("curlpro_upgrade_open", session, meta={
        "method": "GET", "url": stand.url + "/upgrade",
        "headers": {"connection": "Upgrade", "upgrade": "echo"}})
    assert data["status"] == 101 and body == b""
    cid = data["conn"]
    assert stand.seen[-1]["headers"]["connection"] == "Upgrade"
    try:
        buf = ctypes.create_string_buffer(64)
        got = b""
        while len(got) < 5:
            n = lib.curlpro_conn_read(cid, buf, 64)
            assert n > 0
            got += buf.raw[:n]
        assert got == b"hello"
        msg = b"\x81\x05frame"
        assert lib.curlpro_conn_write(cid, msg, len(msg)) == len(msg)
        echoed = b""
        while len(echoed) < len(msg):
            n = lib.curlpro_conn_read(cid, buf, 64)
            assert n > 0
            echoed += buf.raw[:n]
        assert echoed == msg
        # The asynchronous pair.
        rid = _ffi._call("curlpro_conn_write_start", cid, b"async", 5)["request"]
        assert _wait(rid)[0] == {"written": 5}
        rid = _ffi._call("curlpro_conn_read_start", cid, 64)["request"]
        assert _wait(rid) == ({"eof": False}, b"async")
    finally:
        _ffi._call("curlpro_conn_close", cid)
    assert lib.curlpro_conn_read(cid, ctypes.create_string_buffer(8), 8) == -1

    data, body = _ffi.call_framed("curlpro_upgrade_open", session, meta={
        "method": "GET", "url": stand.url + "/refuse", "headers": {"connection": "Upgrade", "upgrade": "echo"}})
    assert data["status"] == 403 and "conn" not in data and body == b"go away"
    assert _ffi._call("curlpro_debug_counts")["conns"] == 0


def test_zero_timeout_is_none_and_the_idle_limit_cuts_silence(stand):
    _ffi._call("curlpro_profiles_load_dir", str(REPO / "profiles").encode())
    sid = _ffi._call("curlpro_session_new", _ffi.encode({
        "profile": "chrome-156-windows", "default_headers": True, "timeout_ms": 300}))["session"]
    try:
        # The session's 300 ms would cut an 800 ms body; the request's 0 lifts it.
        data, body = _ffi.call_framed("curlpro_request", sid, meta={
            "method": "GET", "url": stand.url + "/trickle", "timeout_ms": 0})
        assert body == b"x" * 8
        with pytest.raises(CurlProError) as e:
            _ffi.call_framed("curlpro_request", sid, meta={"method": "GET", "url": stand.url + "/trickle"})
        assert e.value.code == "timeout"
        started = time.time()
        with pytest.raises(CurlProError) as e:
            _ffi.call_framed("curlpro_request", sid, meta={
                "method": "GET", "url": stand.url + "/stall", "timeout_ms": 0, "idle_timeout_ms": 400})
        assert e.value.code == "timeout" and "idle_timeout" in str(e.value)
        assert time.time() - started < 2.5
    finally:
        _ffi._call("curlpro_session_close", sid)
