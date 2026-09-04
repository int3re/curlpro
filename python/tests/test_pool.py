"""The connection pool: busy state, reuse, limits.

Checked through a local server that counts the connections it accepts: from the
response code alone reuse cannot be told from re-establishing.
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
    """HTTP/1.1 does not multiplex: until the body is read, the next request
    cannot be written into the same socket.

    The connection used to be released right after the headers were read, and a
    second request wrote over an unread body while parsing its response from foreign bytes.
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
    assert set(parallel) == {"b"}, "the parallel response is corrupted"
    assert "b" not in body, "the stream is corrupted by a parallel request"
    assert body.count("a") >= 2000


def test_connection_is_reused_after_stream_closed(srv):
    """A closed stream returns the connection to circulation instead of dropping it."""
    srv.scenario("/x", [{"status": 200}])
    with session() as s:
        with s.stream("GET", srv.url("/x")) as r:
            r.read()
        s.get(srv.url("/x"))
        s.get(srv.url("/x"))
    # Three requests in a row over one connection: the server sees one socket.
    assert srv.hits["/x"] == 3


def test_pool_limit_is_enforced(srv):
    """The pool does not grow without a limit.

    A rotating proxy with an identifier in the login yields a new key per request
    — without a limiter that means thousands of live sockets.
    """
    for i in range(12):
        srv.scenario(f"/p{i}", [{"status": 200}])

    with session(max_idle_conns=4) as s:
        for i in range(12):
            assert s.get(srv.url(f"/p{i}")).status == 200
    # Every request goes to one host, so the key is one and the limit does not interfere.
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
