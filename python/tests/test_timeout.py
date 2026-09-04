"""Отдельный предел на установку соединения: timeout=(соединение, всего)."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import curlpro
import pytest
from curlpro.timeouts import split_timeout as _split_timeout

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class StalledServer:
    """Принимает TCP-соединение и молчит: рукопожатие TLS не начинается.

    Мёртвый адрес для проверки не годится: ядро отвечает на него по-разному
    и на Windows часто сразу отказом. Молчащий сокет даёт ту же фазу
    «соединение ещё не установлено», но одинаково на всех системах.
    """

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._held: list[socket.socket] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}/"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            # Сокет держится открытым: закрытие вернуло бы клиенту ошибку
            # раньше срока, и предел остался бы непроверенным.
            self._held.append(raw)

    def __enter__(self) -> "StalledServer":
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()
        for raw in self._held:
            raw.close()


@pytest.fixture
def stalled():
    with StalledServer() as srv:
        yield srv


def test_pair_splits_connect_and_total():
    assert _split_timeout(None) == (None, None)
    assert _split_timeout(5) == (None, 5.0)
    assert _split_timeout((3, 30)) == (3.0, 30.0)
    with pytest.raises(ValueError):
        _split_timeout((1, 2, 3))


def test_connect_timeout_fires_before_total(stalled):
    """Молчащий узел обязан отвалиться по первому пределу, а не по общему."""
    with curlpro.Session(verify=False) as s:
        started = time.monotonic()
        with pytest.raises(curlpro.Timeout):
            s.get(stalled.url, timeout=(0.4, 30))
        spent = time.monotonic() - started
    assert spent < 5, f"ждали {spent:.1f} с — похоже, сработал общий предел"


def test_session_connect_timeout_applies(stalled):
    """Предел из конструктора действует без переопределения в запросе."""
    with curlpro.Session(verify=False, timeout=(0.4, 30)) as s:
        started = time.monotonic()
        with pytest.raises(curlpro.Timeout):
            s.get(stalled.url)
        spent = time.monotonic() - started
    assert spent < 5, f"ждали {spent:.1f} с"


def test_connect_timeout_does_not_limit_reading():
    """Ответ ждётся под общим пределом: медленный сервер не должен падать."""
    with RawHeaderServer(delay=1.0) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            assert s.get(srv.url, timeout=(0.5, 10)).status == 200


def test_total_timeout_still_cuts_slow_response():
    """Общий предел работает и когда задан отдельный предел на соединение."""
    with RawHeaderServer(delay=2.0) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            with pytest.raises(curlpro.Timeout):
                s.get(srv.url, timeout=(0.5, 0.7))


def test_websocket_connect_timeout(stalled):
    """Рукопожатие сокета — та же фаза установки, что и у запроса."""
    with curlpro.Session("chrome-151-windows", verify=False) as s:
        started = time.monotonic()
        with pytest.raises(curlpro.CurlProError):
            s.websocket(stalled.url.replace("https://", "wss://"), timeout=(0.4, 30))
        spent = time.monotonic() - started
    assert spent < 5, f"ждали {spent:.1f} с"
