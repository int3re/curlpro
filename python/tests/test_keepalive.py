"""Переиспользование соединения между запросами."""

from __future__ import annotations

from pathlib import Path

import curlpro
import pytest

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def server():
    with RawHeaderServer(persistent=True) as srv:
        yield srv


def test_connection_is_reused_by_default(server):
    with curlpro.Session(verify=False, force_http1=True) as s:
        for _ in range(3):
            assert s.get(server.url).status == 200
    assert server.accepted == 1, "три запроса должны уложиться в одно соединение"


def test_keep_alive_false_opens_connection_per_request(server):
    with curlpro.Session(verify=False, force_http1=True, keep_alive=False) as s:
        for _ in range(3):
            assert s.get(server.url).status == 200
    assert server.accepted == 3, "keep_alive=False: соединение на запрос"


def test_keep_alive_false_keeps_browser_connection_header(server):
    """Connection: close не отправляется — браузер его не шлёт."""
    with curlpro.Session(verify=False, force_http1=True, keep_alive=False) as s:
        raw = s.get(server.url).json()["raw"]
    sent = [ln for ln in raw if ln.lower().startswith("connection:")]
    assert sent == ["Connection: keep-alive"], sent
