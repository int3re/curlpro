"""Совместимость с requests и сетевые возможности.

Проверяется то, по чему библиотеку оценивают в первые пять минут: params,
auth, куки ответа, время запроса, цепочка редиректов, построчное чтение,
типизированные ошибки. И то, без чего клиент считают игрушечным: свой
корневой сертификат, прокси из окружения, предел размера ответа.
"""

from __future__ import annotations

import http.server
import os
import socketserver
import ssl
import threading
from pathlib import Path

import curlpro
import pytest

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]
CERT_DIR = REPO / "capture" / "certs"


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class SmallServer:
    """Сервер с редиректами, куками и большим телом."""

    def __init__(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):  # noqa: N802
                if self.path == "/a":
                    self.send_response(302)
                    self.send_header("Location", "/b")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif self.path == "/b":
                    self.send_response(301)
                    self.send_header("Location", "/c")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif self.path == "/cookies":
                    body = b"ok"
                    self.send_response(200)
                    self.send_header("Set-Cookie", "sid=abc; Path=/")
                    self.send_header("Set-Cookie", "theme=dark; Path=/")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/lines":
                    body = b'{"n":1}\n{"n":2}\n{"n":3}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/big":
                    body = b"x" * 100_000
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/notfound":
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    body = b"ok"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *a):  # noqa: ANN001, N802
                pass

        self._srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        self._srv.socket = ctx.wrap_socket(self._srv.socket, server_side=True)
        self.port = self._srv.server_address[1]
        outer._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def url(self, path: str = "/") -> str:
        return f"https://localhost:{self.port}{path}"

    def __enter__(self) -> "SmallServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._srv.shutdown()
        self._srv.server_close()


# --- совместимость -------------------------------------------------------------

def test_params_are_added_to_the_query():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            line = s.get(srv.url, params={"q": "привет", "page": 2,
                                          "tag": ["a", "b"], "skip": None}).json()["request_line"]
    assert "q=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82" in line
    assert "page=2" in line and "tag=a&tag=b" in line
    assert "skip" not in line, "None-параметры не отправляются"


def test_existing_query_is_kept():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            line = s.get(srv.url + "?lang=ru", params={"page": 2}).json()["request_line"]
    assert "lang=ru" in line and "page=2" in line


def test_basic_auth():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            raw = s.get(srv.url, auth=("user", "pw")).json()["raw"]
    assert "Authorization: Basic dXNlcjpwdw==" in raw


def test_response_cookies_are_only_this_response():
    with SmallServer() as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            first = s.get(srv.url("/cookies"))
            second = s.get(srv.url("/"))
    assert first.cookies == {"sid": "abc", "theme": "dark"}
    assert second.cookies == {}, "у ответа без Set-Cookie своих кук нет"


def test_elapsed_is_measured():
    with RawHeaderServer(persistent=True, delay=0.2) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            r = s.get(srv.url)
    assert r.elapsed >= 0.2


def test_redirect_history():
    with SmallServer() as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            r = s.get(srv.url("/a"))
    assert r.status == 200 and r.url.endswith("/c")
    assert [h.status for h in r.history] == [302, 301]
    assert r.history[0].location == "/b" and r.history[1].location == "/c"


def test_no_redirects_means_empty_history():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            assert s.get(srv.url).history == []


def test_iter_lines():
    with SmallServer() as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            with s.stream("GET", srv.url("/lines")) as r:
                lines = list(r.iter_lines())
    assert lines == [b'{"n":1}', b'{"n":2}', b'{"n":3}']


def test_raise_for_status_raises_typed_error():
    with SmallServer() as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            r = s.get(srv.url("/notfound"))
            with pytest.raises(curlpro.HTTPError) as info:
                r.raise_for_status()
    assert info.value.status == 404
    assert info.value.response is r
    assert isinstance(info.value, curlpro.CurlProError)


def test_timeout_has_its_own_class():
    with RawHeaderServer(persistent=True, delay=2.0) as srv:
        with curlpro.Session(verify=False, force_http1=True, timeout=0.3) as s:
            with pytest.raises(curlpro.Timeout) as info:
                s.get(srv.url)
    assert info.value.code == "timeout"


# --- сетевые возможности --------------------------------------------------------

def test_own_ca_is_trusted():
    """Сертификат стенда подписан сам собой: с указанным корнем проверка
    проходит, без него — падает."""
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=str(CERT_DIR / "tls.crt"), force_http1=True) as s:
            assert s.get(srv.url).status == 200

        with curlpro.Session(verify=True, force_http1=True, timeout=5) as s:
            with pytest.raises(curlpro.CurlProError):
                s.get(srv.url)


def test_missing_ca_file_fails_at_session_creation():
    with pytest.raises(curlpro.CurlProError, match="корневой сертификат"):
        curlpro.Session(verify="нет-такого-файла.pem")


def test_client_cert_requires_both_files():
    with pytest.raises(curlpro.CurlProError, match="mTLS"):
        curlpro.Session(verify=False, cert=("only-cert.pem", ""))


def test_max_response_size():
    with SmallServer() as srv:
        with curlpro.Session(verify=False, force_http1=True,
                             max_response_size=10_000) as s:
            with pytest.raises(curlpro.CurlProError, match="больше предела"):
                s.get(srv.url("/big"))

        with curlpro.Session(verify=False, force_http1=True,
                             max_response_size=200_000) as s:
            assert len(s.get(srv.url("/big")).content) == 100_000


def test_proxy_from_environment(monkeypatch):
    """Прокси из окружения используется, а NO_PROXY его отменяет."""
    with RawHeaderServer(persistent=True) as srv:
        # Заведомо мёртвый прокси: если его взяли, запрос упадёт.
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
        with curlpro.Session(verify=False, force_http1=True, timeout=5) as s:
            with pytest.raises(curlpro.CurlProError):
                s.get(srv.url)

        monkeypatch.setenv("NO_PROXY", "localhost")
        with curlpro.Session(verify=False, force_http1=True, timeout=5) as s:
            assert s.get(srv.url).status == 200


def test_trust_env_can_be_disabled(monkeypatch):
    with RawHeaderServer(persistent=True) as srv:
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
        with curlpro.Session(verify=False, force_http1=True,
                             trust_env=False, timeout=5) as s:
            assert s.get(srv.url).status == 200


def test_explicit_proxy_beats_environment(monkeypatch):
    with RawHeaderServer(persistent=True) as srv:
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
        # Пустая строка в запросе означает «идти напрямую».
        with curlpro.Session(verify=False, force_http1=True, timeout=5) as s:
            assert s.get(srv.url, proxy=False).status == 200
