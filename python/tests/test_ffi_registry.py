"""Handles on the FFI boundary: everything opened has to come back.

A leaked handle is invisible from Python — the object is gone, while the Go
side still holds a connection and a goroutine. It shows up only as memory that
never comes back down, which is a slow way to find out. ``curlpro_debug_counts``
reports every registry, so the same question is answered by measurement here.

The audit swept the boundary by hand (sessions, streams, sockets, async
cancellations, exceptions between open and close, bogus handles) and found
nothing; this file keeps it that way.
"""

from __future__ import annotations

import asyncio
import gc
from pathlib import Path

import curlpro
import pytest
from curlpro._ffi import _call

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def counts() -> dict:
    """The registry sizes, with the Python objects collected first.

    Without the collection an abandoned stream is still alive and its handle
    legitimately registered — the test would then measure the garbage
    collector, not the boundary.
    """
    gc.collect()
    return _call("curlpro_debug_counts")


@pytest.fixture
def baseline() -> dict:
    return counts()


def assert_back_to(base: dict, what: str) -> None:
    now = counts()
    for registry in ("sessions", "streams", "sockets", "pending"):
        assert now[registry] <= base[registry], (
            f"{what}: registry {registry} grew from {base[registry]} to "
            f"{now[registry]} — a handle stayed behind")


def test_debug_counts_reports_every_registry(baseline):
    for key in ("sessions", "streams", "sockets", "pending", "goroutines", "heap_kb"):
        assert key in baseline, f"no {key} in the report"
        assert isinstance(baseline[key], int)


def test_sessions_come_back(baseline):
    with RawHeaderServer(persistent=True) as srv:
        for _ in range(20):
            with curlpro.Session(verify=False, force_http1=True) as s:
                s.get(srv.url)
    assert_back_to(baseline, "sessions opened and closed")


def test_open_session_is_registered_and_released(baseline):
    with RawHeaderServer(persistent=True) as srv:
        held = [curlpro.Session(verify=False, force_http1=True) for _ in range(5)]
        for s in held:
            s.get(srv.url)
        assert counts()["sessions"] >= baseline["sessions"] + 5
        for s in held:
            s.close()
    assert_back_to(baseline, "five sessions held and then closed")


def test_streams_come_back(baseline):
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            for _ in range(20):
                with s.stream("GET", srv.url) as r:
                    r.read()
    assert_back_to(baseline, "streams through with")


def test_abandoned_stream_comes_back(baseline):
    """No close() at all: the handle rides on __del__, and that has to be enough."""
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            for _ in range(10):
                r = s.stream("GET", srv.url)
                r.read()
                del r
    assert_back_to(baseline, "streams abandoned without close")


def test_exception_between_open_and_close_leaks_nothing(baseline):
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            for _ in range(10):
                with pytest.raises(RuntimeError):
                    with s.stream("GET", srv.url):
                        raise RuntimeError("the caller failed mid-body")
    assert_back_to(baseline, "an exception inside with")


def test_cancelled_async_calls_come_back(baseline):
    async def run(url: str) -> None:
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            await asyncio.gather(*(s.get(url) for _ in range(20)))
            tasks = [asyncio.create_task(s.get(url)) for _ in range(10)]
            await asyncio.sleep(0.02)
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    with RawHeaderServer(persistent=True) as srv:
        asyncio.run(run(srv.url))
    # A cancelled call is dropped by the reaper, not by the waiter: give it the
    # moment it needs before deciding the registry kept something.
    for _ in range(20):
        if counts()["pending"] <= baseline["pending"]:
            break
        asyncio.run(asyncio.sleep(0.05))
    assert_back_to(baseline, "cancelled async requests")


def test_bogus_handles_do_not_register_anything(baseline):
    for _ in range(20):
        with pytest.raises(curlpro.CurlProError):
            _call("curlpro_session_close", 999_999)
        with pytest.raises(curlpro.CurlProError):
            _call("curlpro_stream_close", 999_999)
    assert_back_to(baseline, "calls against handles that never existed")


def test_goroutines_do_not_pile_up(baseline):
    """A leaked handle shows up as goroutines long before it shows as memory."""
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True) as s:
            for _ in range(100):
                s.get(srv.url).content
    gc.collect()
    now = counts()
    assert now["goroutines"] <= baseline["goroutines"] + 4, (
        f"goroutines grew from {baseline['goroutines']} to {now['goroutines']}")
