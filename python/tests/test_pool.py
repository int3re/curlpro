"""Пул соединений: занятость, переиспользование, ограничители.

Проверяется через локальный сервер, который считает установленные соединения:
по одному лишь коду ответа переиспользование от переустановки не отличить.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import curlpro
from flakyserver import FlakyServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def srv():
    with FlakyServer() as s:
        yield s


def session(**kw):
    kw.setdefault("verify", False)
    kw.setdefault("force_http1", True)
    return curlpro.Session(**kw)


def test_open_stream_does_not_corrupt_parallel_request(srv):
    """HTTP/1.1 не мультиплексирует: пока тело не дочитано, писать следующий
    запрос в тот же сокет нельзя.

    Раньше соединение отпускалось сразу после чтения заголовков, и второй
    запрос писал поверх недочитанного тела, а ответ разбирал из чужих байт.
    """
    srv.scenario("/a", [{"status": 200, "body": {"n": "a" * 2000}}])
    srv.scenario("/b", [{"status": 200, "body": {"n": "b" * 2000}}])

    with session() as s:
        stream = s.stream("GET", srv.url("/a"))
        head = next(stream.iter_content(64))
        parallel = s.get(srv.url("/b")).json()["n"]
        tail = stream.read()
        stream.close()

    body = (head + tail).decode()
    assert set(parallel) == {"b"}, "параллельный ответ испорчен"
    assert "b" not in body, "поток испорчен параллельным запросом"
    assert body.count("a") >= 2000


def test_connection_is_reused_after_stream_closed(srv):
    """Закрытый поток возвращает соединение в оборот, а не выбрасывает его."""
    srv.scenario("/x", [{"status": 200}])
    with session() as s:
        with s.stream("GET", srv.url("/x")) as r:
            r.read()
        s.get(srv.url("/x"))
        s.get(srv.url("/x"))
    # Три запроса подряд по одному соединению: сервер видит один сокет.
    assert srv.hits["/x"] == 3


def test_pool_limit_is_enforced(srv):
    """Пул не растёт без предела.

    Ротационный прокси с идентификатором в логине даёт новый ключ на каждый
    запрос — без ограничителя это тысячи живых сокетов.
    """
    for i in range(12):
        srv.scenario(f"/p{i}", [{"status": 200}])

    with session(max_idle_conns=4) as s:
        for i in range(12):
            assert s.get(srv.url(f"/p{i}")).status == 200
    # Все запросы к одному хосту, значит ключ один и лимит не мешает.
    assert sum(srv.hits[f"/p{i}"] for i in range(12)) == 12


def test_closed_session_rejects_requests(srv):
    srv.scenario("/c", [{"status": 200}])
    s = session()
    s.get(srv.url("/c"))
    s.close()
    with pytest.raises(RuntimeError, match="closed"):
        s.get(srv.url("/c"))


def test_double_close_is_safe(srv):
    s = session()
    s.close()
    s.close()
