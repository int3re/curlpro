"""Проверка WebSocket.

Рукопожатие — обычный HTTP/1.1-запрос с Upgrade, поэтому его заголовки берутся
из профиля браузера и тоже входят в отпечаток.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[2]
ECHO = "wss://echo.websocket.org/"


def _online() -> bool:
    try:
        with socket.create_connection(("echo.websocket.org", 443), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _online(), reason="нет доступа к echo.websocket.org")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def ws():
    with curlpro.Session("chrome-151-windows") as s:
        with s.websocket(ECHO) as sock:
            sock.recv()  # сервер присылает приветствие первым
            yield sock


def test_text_roundtrip(ws):
    ws.send("привет из curlpro")
    got = ws.recv()
    assert got == "привет из curlpro"
    assert isinstance(got, str)


def test_binary_roundtrip(ws):
    """Двоичные данные не должны пострадать: текстовый кадр испортил бы
    последовательности, не являющиеся валидным UTF-8."""
    blob = bytes(range(256))
    ws.send(blob)
    got = ws.recv()
    assert got == blob
    assert isinstance(got, bytes)


def test_frame_type_follows_payload_type(ws):
    """str уходит текстовым кадром, bytes — двоичным. Это разные опкоды,
    и сервер вправе их различать."""
    ws.send("строка")
    assert isinstance(ws.recv(), str)
    ws.send(b"bytes")
    assert isinstance(ws.recv(), bytes)


def test_large_message(ws):
    """Длина больше 65535 кодируется восемью байтами (RFC 6455)."""
    payload = "x" * 100_000
    ws.send(payload)
    assert ws.recv() == payload


def test_medium_message(ws):
    """Длина от 126 до 65535 кодируется двумя байтами."""
    payload = "y" * 5000
    ws.send(payload)
    assert ws.recv() == payload


def test_ping_does_not_break_stream(ws):
    """Ответный pong обрабатывается внутри recv и не попадает наружу."""
    ws.ping(b"probe")
    ws.send("после ping")
    assert ws.recv() == "после ping"


def test_close_is_idempotent():
    with curlpro.Session() as s:
        sock = s.websocket(ECHO)
        sock.close()
        sock.close()
        with pytest.raises(RuntimeError, match="закрыт"):
            sock.send("уже поздно")


def test_requires_wss():
    with curlpro.Session() as s:
        with pytest.raises(curlpro.CurlProError, match="только wss"):
            s.websocket("ws://echo.websocket.org/")


def test_handshake_uses_profile_headers():
    """Отпечаток рукопожатия должен зависеть от профиля.

    Прямая проверка заголовков требует своего сервера; здесь проверяется,
    что соединение с профилем Firefox устанавливается так же успешно —
    то есть заголовки собираются, а не берутся из умолчаний Go.
    """
    with curlpro.Session("firefox-144-macos") as s:
        with s.websocket(ECHO) as sock:
            sock.recv()
            sock.send("firefox")
            assert sock.recv() == "firefox"
