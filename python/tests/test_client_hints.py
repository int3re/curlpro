"""Клиентские подсказки высокой энтропии и выбор устройства.

Chrome вырезал модель и версию системы из User-Agent: у любого телефона там
«Android 10; K». Разные телефоны различаются подсказками sec-ch-ua-model и
sec-ch-ua-platform-version, а браузер шлёт их только после Accept-CH.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]
CERT_DIR = REPO / "capture" / "certs"


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class HintServer:
    """Сервер, запрашивающий подсказки и записывающий сырые заголовки."""

    def __init__(self, accept_ch: str, critical: bool = False):
        self.accept_ch = accept_ch
        self.critical = critical
        self.requests: list[list[str]] = []

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

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}/"

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
        self.requests.append([ln for ln in head[1:] if ":" in ln])

        body = b"ok"
        extra = f"Accept-CH: {self.accept_ch}\r\n"
        if self.critical:
            extra += f"Critical-CH: {self.accept_ch}\r\n"
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + extra.encode()
            + b"Connection: keep-alive\r\n\r\n"
            + body
        )
        return True

    def names(self, i: int) -> list[str]:
        return [ln.split(":", 1)[0] for ln in self.requests[i]]

    def value(self, i: int, name: str) -> str | None:
        for ln in self.requests[i]:
            k, _, v = ln.partition(":")
            if k.strip().lower() == name:
                return v.strip()
        return None

    def __enter__(self) -> "HintServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)


ALL_HINTS = (
    "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-form-factors, "
    "sec-ch-ua-full-version, sec-ch-ua-full-version-list, sec-ch-ua-model, "
    "sec-ch-ua-platform-version, sec-ch-ua-wow64"
)


def test_hints_appear_only_after_accept_ch():
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Pixel 8") as s:
            s.get(srv.url)
            s.get(srv.url)
    assert srv.value(0, "sec-ch-ua-model") is None, "подсказка ушла до Accept-CH"
    assert srv.value(1, "sec-ch-ua-model") == '"Pixel 8"'
    assert srv.value(1, "sec-ch-ua-platform-version") == '"16.0.0"'


def test_critical_ch_makes_the_client_repeat_at_once():
    with HintServer("sec-ch-ua-model", critical=True) as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Pixel 7") as s:
            s.get(srv.url)
    assert len(srv.requests) == 2, "Critical-CH обязан вызвать немедленный повтор"
    assert srv.value(1, "sec-ch-ua-model") == '"Pixel 7"'


def test_only_requested_hints_are_sent():
    with HintServer("sec-ch-ua-model") as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Pixel 7") as s:
            s.get(srv.url)
            s.get(srv.url)
    names = [n.lower() for n in srv.names(1)]
    assert "sec-ch-ua-model" in names
    assert "sec-ch-ua-platform-version" not in names, "сайт этой подсказки не просил"
    assert "sec-ch-ua-full-version-list" not in names


def test_hint_order_matches_measured_template():
    """Порядок кластера с подсказками снят с Chrome 152 на Pixel 7."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Pixel 7") as s:
            s.get(srv.url)
            s.get(srv.url)
    got = [n for n in srv.names(1) if n.lower().startswith("sec-ch-ua")]
    assert got == [
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-full-version", "sec-ch-ua-arch",
        "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-model",
        "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-full-version-list",
        "sec-ch-ua-form-factors",
    ], got


def test_random_device_differs_between_sessions():
    seen = set()
    with HintServer("sec-ch-ua-model") as srv:
        for _ in range(12):
            with curlpro.Session("chrome-152-android", verify=False,
                                 force_http1=True, device="random") as s:
                s.get(srv.url)
                s.get(srv.url)
            seen.add(srv.value(len(srv.requests) - 1, "sec-ch-ua-model"))
    assert len(seen) > 1, f"за двенадцать сессий устройство не сменилось: {seen}"


def test_own_device_list_overrides_the_profile():
    devices = [{"name": "мой", "model": "SM-X999", "platform_version": "13.0.0"}]
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False, force_http1=True,
                             device="мой", devices=devices) as s:
            s.get(srv.url)
            s.get(srv.url)
    assert srv.value(1, "sec-ch-ua-model") == '"SM-X999"'
    assert srv.value(1, "sec-ch-ua-platform-version") == '"13.0.0"'


def test_unknown_device_is_an_error():
    with pytest.raises(curlpro.CurlProError, match="устройство"):
        curlpro.Session("chrome-152-android", device="Nokia 3310")


def test_user_agent_stays_frozen():
    """Модель в User-Agent не подставляется: у Chrome там заглушка для всех."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Galaxy S23") as s:
            s.get(srv.url)
            s.get(srv.url)
    ua = srv.value(1, "user-agent")
    assert "Android 10; K" in ua and "SM-S911B" not in ua, ua
    assert srv.value(1, "sec-ch-ua-model") == '"SM-S911B"'


def test_yandex_puts_the_device_into_the_user_agent():
    """У Яндекса модель и версия Android стоят в самой строке — подставляем там."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("yandex-26.8-android", verify=False,
                             force_http1=True, device="Galaxy S23") as s:
            s.get(srv.url)
            s.get(srv.url)
    ua = srv.value(1, "user-agent")
    assert "Android 15; SM-S911B" in ua, ua
    assert "Pixel 7" not in ua
    # Подсказка и строка обязаны говорить одно и то же.
    assert srv.value(1, "sec-ch-ua-model") == '"SM-S911B"'
    assert srv.value(1, "sec-ch-ua-platform-version") == '"15.0.0"'


def test_yandex_full_version_is_its_own():
    """Полная версия у Яндекса своя, не хромовская — замер телефона."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("yandex-26.8-android", verify=False,
                             force_http1=True, device="Pixel 7") as s:
            s.get(srv.url)
            s.get(srv.url)
    assert srv.value(1, "sec-ch-ua-full-version") == '"26.8.2.121"'
    assert "Yandex" in srv.value(1, "sec-ch-ua-full-version-list")


def test_without_device_nothing_is_substituted():
    """Без device профиль остаётся ровно таким, каким снят."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("yandex-26.8-android", verify=False, force_http1=True) as s:
            s.get(srv.url)
            s.get(srv.url)
    assert "Pixel 7" in srv.value(1, "user-agent")
    assert srv.value(1, "sec-ch-ua-model") is None, "модель без выбранного устройства не подставляется"
