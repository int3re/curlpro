"""The C ABI a transparent proxy stands on (ABI 0.31): no-limit and idle
timeouts, response trailers, a request body written while the request is in
flight, and the raw connection after an upgrade.

Driven through ctypes the way a binding drives the library, against a raw
socket server that writes exactly what each case needs: chunked bodies with
trailers, a chunked upload read back, a 101 with bytes behind it.
"""
from __future__ import annotations

import base64
import ctypes
import gzip
import http.server
import json
import random
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import pytest

from curlpro import _ffi
from curlpro.errors import CurlProError

REPO = Path(__file__).resolve().parents[2]
lib = _ffi._lib


def _read_head(f) -> tuple[str, dict[str, str], list[str]]:
    line = f.readline().decode("latin-1").strip()
    headers: dict[str, str] = {}
    lines: list[str] = []
    while True:
        h = f.readline().decode("latin-1")
        if h in ("\r\n", "\n", ""):
            break
        lines.append(h.rstrip("\r\n"))
        k, _, v = h.partition(":")
        headers[k.strip().lower()] = v.strip()
    return line, headers, lines


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
            line, h, lines = _read_head(f)
            path = line.split(" ")[1]
            rec = {"path": path, "headers": h, "lines": lines}
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
            elif path == "/raw":
                # The request's head back as the body; a header block in the
                # server's own case and order.
                head = json.dumps(rec["lines"]).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nX-Zeta: 1\r\nset-cookie: a=1\r\nCACHE-control: no\r\n"
                          b"Set-Cookie: b=2\r\nContent-Length: %d\r\n\r\n" % len(head) + head)
            elif path == "/cp1251":
                # A Set-Cookie in cp1251, as old Russian sites send it.
                head = json.dumps(rec["lines"]).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nSet-Cookie: city=\xcc\xee\xf1\xea\xe2\xe0\r\n"
                          b"Content-Length: %d\r\n\r\n" % len(head) + head)
            elif path.startswith("/x|"):
                # The target given whole (target_raw): recorded, answered empty.
                c.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
            elif path == "/hints-late":
                # A 103 at once, the final answer 0.6 s later.
                c.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n")
                time.sleep(0.6)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            elif path == "/gzip":
                body = gzip.compress(b"compressible " * 40)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            elif path == "/early":
                c.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"
                          b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
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
    # The block as it came (0.35): the server's case and order.
    assert data["trailers_raw"] == [["grpc-status", "5"], ["grpc-message", "not found"]]
    assert body == b"\x00\x00\x00\x00\x00"

    head, _ = _ffi.call_framed("curlpro_stream_open", session, meta={"method": "POST", "url": stand.url + "/trailers"})
    sid = head["stream"]
    try:
        assert _ffi._call("curlpro_stream_trailers", sid) == {"trailers": {}, "trailers_raw": []}
        assert _read_all(sid) == b"\x00\x00\x00\x00\x00"
        after = _ffi._call("curlpro_stream_trailers", sid)
        assert after["trailers"]["Grpc-Status"] == ["5"]
        assert after["trailers_raw"] == [["grpc-status", "5"], ["grpc-message", "not found"]]
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
    # The connection the answer came over, as a response's conn (0.35).
    info = data["info"]
    assert info["proto"] == "http/1.1" and info["id"] > 0 and info["remote"] == stand.url.split("//")[1]
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
    assert data["info"]["remote"] == stand.url.split("//")[1] and data["info"]["id"] != info["id"]
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


def test_raw_headers_both_ways_and_the_raw_body(session, stand):
    data, body = _ffi.call_framed("curlpro_request", session, meta={
        "method": "GET", "url": stand.url + "/raw",
        "headers_raw": [["X-B", "2"], ["accept", "a1"], ["accept", "a2"], ["Connection", "keep-alive"]]})
    sent = json.loads(body)
    assert sent[0].startswith("Host: 127.0.0.1:")
    assert sent[1:] == ["X-B: 2", "accept: a1", "accept: a2", "Connection: keep-alive"]
    assert data["headers_raw"] == [["X-Zeta", "1"], ["set-cookie", "a=1"], ["CACHE-control", "no"],
                                   ["Set-Cookie", "b=2"], ["Content-Length", str(len(body))]]
    raw, wire = _ffi.call_framed("curlpro_request", session, meta={
        "method": "GET", "url": stand.url + "/gzip", "decompress": False})
    assert wire[:2] == b"\x1f\x8b" and gzip.decompress(wire) == b"compressible " * 40
    assert raw["headers"]["Content-Encoding"] == ["gzip"]
    _, decoded = _ffi.call_framed("curlpro_request", session, meta={"method": "GET", "url": stand.url + "/gzip"})
    assert decoded == b"compressible " * 40


def test_interim_conn_and_codes(session, stand):
    data, body = _ffi.call_framed("curlpro_request", session, meta={"method": "GET", "url": stand.url + "/early"})
    assert body == b"ok"
    assert data["interim"] == [{"status": 103, "headers": {"Link": ["</a.css>; rel=preload"]}}]
    conn = data["conn"]
    assert conn["id"] > 0 and conn["proto"] == "http/1.1" and conn["remote"].startswith("127.0.0.1:")
    assert data["timing"]["wait_ms"] >= 0
    with pytest.raises(CurlProError) as e:
        _ffi.call_framed("curlpro_request", session, meta={"method": "GET", "url": "http://127.0.0.1:1/"})
    assert e.value.code == "connect_refused"


def test_a_profile_given_whole_and_unregistered():
    _ffi._call("curlpro_profiles_load_dir", str(REPO / "profiles").encode())
    inline = {"name": "live-one", "based_on": "chrome-156-windows", "headers": {"user_agent": "phone/1"}}
    sid = _ffi._call("curlpro_session_new", _ffi.encode({"profile": inline, "default_headers": True}))["session"]
    try:
        assert "live-one" not in _ffi._call("curlpro_profiles_list")["profiles"]
    finally:
        _ffi._call("curlpro_session_close", sid)
    _ffi._call("curlpro_profile_register", _ffi.encode({"name": "live-two", "based_on": "chrome-156-windows"}))
    left = _ffi._call("curlpro_profile_unregister", b"live-two")["profiles"]
    assert "live-two" not in left
    with pytest.raises(CurlProError) as e:
        _ffi._call("curlpro_profile_unregister", b"chrome-155-windows")  # chrome-156 stands on it
    assert e.value.code == "configuration"
    assert _ffi._call("curlpro_ticket_cache_drop", b"never-made") == {"dropped": False}


def test_tls_dial_for_another_protocol():
    _ffi._call("curlpro_profiles_load_dir", str(REPO / "profiles").encode())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(REPO / "capture" / "certs" / "tls.crt"), str(REPO / "capture" / "certs" / "tls.key"))
    ctx.set_alpn_protocols(["mqtt"])
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    seen = {}

    def serve():
        c, _ = srv.accept()
        with ctx.wrap_socket(c, server_side=True) as tc:
            seen["alpn"] = tc.selected_alpn_protocol()
            tc.sendall(tc.recv(64))

    threading.Thread(target=serve, daemon=True).start()
    insecure = _ffi._call("curlpro_session_new", _ffi.encode({
        "profile": "chrome-156-windows", "insecure_skip_verify": True}))["session"]
    try:
        out = _ffi._call("curlpro_tls_dial", insecure, _ffi.encode({"host": "127.0.0.1", "port": port, "alpn": ["mqtt"]}))
        cid = out["conn"]
        assert out["info"]["proto"] == "mqtt" and out["info"]["ja4"].startswith("t13i")
        assert lib.curlpro_conn_write(cid, b"\x10\x0cCONNECT", 9) == 9
        buf = ctypes.create_string_buffer(16)
        got = b""
        while len(got) < 9:
            n = lib.curlpro_conn_read(cid, buf, 16)
            assert n > 0
            got += buf.raw[:n]
        assert got == b"\x10\x0cCONNECT" and seen["alpn"] == "mqtt"
        _ffi._call("curlpro_conn_close", cid)
    finally:
        _ffi._call("curlpro_session_close", insecure)
        srv.close()


def test_header_values_that_are_not_utf8_go_as_base64(session, stand):
    moscow = "Москва".encode("cp1251")
    data, body = _ffi.call_framed("curlpro_request", session, meta={
        "method": "GET", "url": stand.url + "/cp1251",
        "headers_raw": [["X-City", base64.b64encode(moscow).decode(), "base64"], ["X-Plain", "1"]]})
    sent = json.loads(body)
    assert sent[1:] == ["X-City: " + moscow.decode("latin-1"), "X-Plain: 1"]
    assert data["headers_raw"][0] == ["Set-Cookie", base64.b64encode(b"city=" + moscow).decode(), "base64"]
    assert data["headers_raw"][1][:2] == ["Content-Length", str(len(body))]
    with pytest.raises(CurlProError):
        _ffi.call_framed("curlpro_request", session, meta={
            "method": "GET", "url": stand.url + "/cp1251", "headers_raw": [["X-City", "%%%", "base64"]]})


class _KeepAlive(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_a_request_names_its_connection(session):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _KeepAlive)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    try:
        def get(conn):
            return _ffi.call_framed("curlpro_request", session, meta={
                "method": "GET", "url": url, "connection": conn})[0]

        first, second = get("new"), get("new")
        assert first["conn"]["id"] != second["conn"]["id"]
        again = get(first["conn"]["id"])
        assert again["conn"]["id"] == first["conn"]["id"] and again["conn"]["reused"]
        with pytest.raises(CurlProError) as e:
            get(1 << 40)
        assert e.value.code == "conn_closed"
        with pytest.raises(CurlProError):
            get("old")
    finally:
        srv.shutdown()
        srv.server_close()


def test_a_failure_names_its_phase(session):
    raw = _ffi._lib.curlpro_request
    out_len = ctypes.c_int()
    meta = json.dumps({"method": "GET", "url": "http://127.0.0.1:1/"}).encode()
    frame = len(meta).to_bytes(4, "little") + meta
    ptr = raw(session, frame, len(frame), ctypes.byref(out_len))
    try:
        buf = ctypes.string_at(ptr, out_len.value)
    finally:
        _ffi._lib.curlpro_free(ptr)
    n = int.from_bytes(buf[:4], "little")
    env = json.loads(buf[4:4 + n])
    assert env["code"] == "connect_refused" and env["details"]["phase"] == "connect"


def test_the_ready_queue_has_a_handle():
    out = _ffi._call("curlpro_result_event")
    assert out["handle"] > 0
    assert out["kind"] == ("event" if sys.platform == "win32" else "fd")
    assert _ffi._call("curlpro_result_event") == out


def test_a_body_relayed_compressed_decodes_on_demand():
    plain = bytes(random.Random(7).choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(300000))
    raw = gzip.compress(plain)
    data, out = _ffi.call_framed("curlpro_decode", meta={"encoding": "gzip", "limit": 0}, body=raw)
    assert data["complete"] and out == plain
    data, out = _ffi.call_framed("curlpro_decode", meta={"encoding": "gzip", "limit": 0}, body=raw[:len(raw) // 2])
    assert not data["complete"] and data["error"] and out
    with pytest.raises(CurlProError) as e:
        _ffi.call_framed("curlpro_decode", meta={"encoding": "compress"}, body=raw)
    assert e.value.code == "configuration"


def test_interim_responses_come_before_the_final_one(session, stand):
    started = time.time()
    rid = _ffi.call_with_frame("curlpro_request_start", session, body=b"",
                               meta={"method": "GET", "url": stand.url + "/hints-late",
                                     "interim_events": True})["request"]
    first, _ = _wait(rid)
    first_at = time.time() - started
    assert first == {"interim": {"status": 103, "headers": {"Link": ["</a.css>; rel=preload"]}}}
    final, body = _wait(rid)
    final_at = time.time() - started
    assert body == b"ok" and final["status"] == 200 and final["interim"][0]["status"] == 103
    assert final_at - first_at > 0.4, (first_at, final_at)
    # Without the flag the call has one result, as before.
    rid = _ffi.call_with_frame("curlpro_request_start", session, body=b"",
                               meta={"method": "GET", "url": stand.url + "/hints-late"})["request"]
    only, body = _wait(rid)
    assert only["status"] == 200 and body == b"ok"


def test_the_target_as_given_and_resolve_by_the_proxy(session, stand):
    data, _ = _ffi.call_framed("curlpro_request", session, meta={
        "method": "GET", "url": stand.url + "/ignored", "target_raw": "/x|y^{z}`?q=%7e"})
    assert stand.seen[-1]["path"] == "/x|y^{z}`?q=%7e"
    assert data["conn"]["resolved_by"] == "local"
    with pytest.raises(CurlProError) as e:
        _ffi._call("curlpro_session_new", _ffi.encode({"profile": "chrome-156-windows", "resolve_via_proxy": "dns"}))
    assert e.value.code == "configuration"
