"""Cookies: recording, export, import, carrying a session between runs."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]
CERT_DIR = REPO / "capture" / "certs"


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class CookieServer:
    """Sets cookies and reports what came back."""

    def __init__(self, set_cookies: list[str]):
        self.set_cookies = set_cookies
        self.seen: list[str] = []

        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        self._ctx.set_alpn_protocols(["http/1.1"])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def url(self, path: str = "/") -> str:
        return f"https://localhost:{self.port}{path}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as conn:
                    while self._handle(conn):
                        pass
            except (ssl.SSLError, OSError):
                pass

    def _handle(self, conn: ssl.SSLSocket) -> bool:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return False
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        got = ""
        for ln in head[1:]:
            if ln.lower().startswith("cookie:"):
                got = ln.split(":", 1)[1].strip()
        self.seen.append(got)

        body = b"ok"
        extra = "".join(f"Set-Cookie: {c}\r\n" for c in self.set_cookies)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + extra.encode()
            + b"Connection: keep-alive\r\n\r\n"
            + body
        )
        return True

    def __enter__(self) -> "CookieServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)


def test_cookies_are_recorded_and_sent_back():
    with CookieServer(["sid=abc; Path=/; HttpOnly", "theme=dark; Path=/"]) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.get(srv.url())
            got = s.cookies.all()
            s.get(srv.url())
    names = {c.name: c.value for c in got}
    assert names == {"sid": "abc", "theme": "dark"}
    assert srv.seen[0] == "", "the first request carries no cookies yet"
    assert "sid=abc" in srv.seen[1] and "theme=dark" in srv.seen[1]


def test_export_keeps_domain_path_and_flags():
    with CookieServer(["sid=abc; Path=/api; Secure; HttpOnly; SameSite=Lax"]) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.get(srv.url("/api/list"))
            data = s.cookies.export()
    assert len(data) == 1
    c = data[0]
    assert c["name"] == "sid" and c["value"] == "abc"
    assert c["domain"] == "localhost" and c["path"] == "/api"
    assert c["secure"] is True and c["http_only"] is True
    assert c["same_site"] == "lax"


def test_session_survives_between_runs(tmp_path):
    """This is what it was all for: the login carries into a new run."""
    state = tmp_path / "cookies.json"
    with CookieServer(["sid=secret; Path=/"]) as srv:
        with curlpro.Session(verify=False, force_http1=True) as first:
            first.get(srv.url())
            first.cookies.save(state)

        # A new session is like a new run of the scraper.
        with curlpro.Session(verify=False, force_http1=True) as second:
            second.cookies.load_file(state)
            second.get(srv.url())
    assert "sid=secret" in srv.seen[-1], srv.seen


def test_missing_file_is_not_an_error(tmp_path):
    with curlpro.Session(verify=False) as s:
        s.cookies.load_file(tmp_path / "no-such-file.json")  # the first run
        assert len(s.cookies) == 0


def test_set_and_clear():
    with CookieServer([]) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.cookies.set("token", "xyz", domain="localhost")
            assert s.cookies["token"] == "xyz"
            s.get(srv.url())
            s.cookies.clear()
            assert len(s.cookies) == 0
            s.get(srv.url())
    assert "token=xyz" in srv.seen[0]
    assert srv.seen[1] == "", "after clear no cookies must go out"


def test_server_can_delete_a_cookie():
    with CookieServer(["sid=abc; Path=/"]) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.get(srv.url())
            assert "sid" in s.cookies
            srv.set_cookies = ["sid=; Path=/; Max-Age=0"]
            s.get(srv.url())
            assert "sid" not in s.cookies, "a cleared cookie must not stay in the export"


def test_expired_cookie_is_not_exported():
    past = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() - 3600))
    with CookieServer([f"old=1; Path=/; Expires={past}", "new=2; Path=/"]) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.get(srv.url())
            names = [c.name for c in s.cookies.all()]
    assert names == ["new"]


def test_cookies_file_is_plain_json(tmp_path):
    state = tmp_path / "c.json"
    with CookieServer(["sid=abc; Path=/"]) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            s.get(srv.url())
            s.cookies.save(state)
    data = json.loads(state.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data[0]["name"] == "sid"


def test_cookies_after_close_say_the_session_is_closed():
    """The jar dies with its session, and has to say so.

    It has no handle of its own, so it used to ask the native part about a
    session that was gone and pass on "session 7 not found" — a number the
    caller never chose, for a failure that is entirely predictable.
    """
    s = curlpro.Session(verify=False, force_http1=True)
    s.cookies.set("sid", "1", domain="example.com")
    saved = s.cookies.export()
    s.close()

    for call in (lambda: s.cookies.all(),
                 lambda: s.cookies.export(),
                 lambda: s.cookies["sid"],
                 lambda: s.cookies.set("a", "1", domain="example.com"),
                 lambda: s.cookies.clear(),
                 lambda: s.cookies.load([])):
        with pytest.raises(RuntimeError, match="session is closed"):
            call()

    # The way out named by the message: take the cookies out before closing.
    assert saved and saved[0]["name"] == "sid"
