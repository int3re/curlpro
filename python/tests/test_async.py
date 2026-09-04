"""The async path: goroutines instead of a thread pool.

AsyncSession used to be a facade over a pool of thirty-two threads, and that
pool was the concurrency ceiling. Now a request becomes a goroutine and the
process keeps exactly one thread — the one waiting for completions.
"""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import curlpro
import pytest
from curlpro._ffi import _lib

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_concurrency_is_not_capped_by_threads():
    """A hundred and twenty-eight 0.3 s requests must not run in four waves."""
    n, delay = 128, 0.3

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            start = time.perf_counter()
            await asyncio.gather(*(s.get(srv.url) for _ in range(n)))
            return time.perf_counter() - start

    with RawHeaderServer(persistent=True, delay=delay) as srv:
        spent = asyncio.run(run(srv))

    # A pool of 32 threads would give at least four waves, that is 4x delay.
    assert spent < delay * 3, f"{n} requests took {spent:.2f} s — that looks like a queue"


def test_one_helper_thread_regardless_of_load():
    """Only our own threads are counted: the test server also starts a thread
    per connection, and a total count would measure it rather than the client."""
    import threading

    def ours() -> list[str]:
        return [t.name for t in threading.enumerate() if t.name.startswith("curlpro")]

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            tasks = [asyncio.create_task(s.get(srv.url)) for _ in range(64)]
            await asyncio.sleep(0.1)   # look while the requests are in flight
            names = ours()
            await asyncio.gather(*tasks)
            return names

    with RawHeaderServer(persistent=True, delay=0.3) as srv:
        names = asyncio.run(run(srv))
    assert names == ["curlpro-completions"], names


def test_responses_are_correct():
    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            r = await s.get(srv.url)
            assert r.status == 200 and r.proto.startswith("HTTP/1.1")
            body = r.json()
            assert body["request_line"].startswith("GET /")
            post = await s.post(srv.url, data="a=1")
            assert post.json()["request_line"].startswith("POST /")

    with RawHeaderServer(persistent=True) as srv:
        asyncio.run(run(srv))


def test_error_reaches_the_caller():
    async def run():
        async with curlpro.AsyncSession(verify=False, timeout=2) as s:
            with pytest.raises(curlpro.CurlProError):
                await s.get("https://127.0.0.1:9/")

    asyncio.run(run())


def test_cancelled_task_cancels_the_request():
    """A cancelled task must not leave a request in flight: it would hold a
    connection until its own timeout."""

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            task = asyncio.create_task(s.get(srv.url))
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # Give the native part time to reach the cancellation.
            await asyncio.sleep(0.5)

    with RawHeaderServer(persistent=True, delay=1.0) as srv:
        asyncio.run(run(srv))
    assert int(_lib.curlpro_async_pending()) == 0, "the request stayed registered"


def test_nothing_leaks_after_a_batch():
    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            await asyncio.gather(*(s.get(srv.url) for _ in range(32)))

    with RawHeaderServer(persistent=True) as srv:
        asyncio.run(run(srv))
    assert int(_lib.curlpro_async_pending()) == 0


def test_hooks_and_cookies_work_in_async():
    seen = []

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            s.on_response(lambda r: seen.append(r.status))
            s.cookies.set("token", "xyz", domain="localhost")
            await s.get(srv.url)
            assert s.cookies["token"] == "xyz"

    with RawHeaderServer(persistent=True) as srv:
        asyncio.run(run(srv))
    assert seen == [200]


def test_two_event_loops_in_a_row():
    """The collector exits with the last request and comes back up again."""

    async def once(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            return (await s.get(srv.url)).status

    with RawHeaderServer(persistent=True) as srv:
        assert asyncio.run(once(srv)) == 200
        time.sleep(0.4)  # the collector has time to exit on idle
        assert asyncio.run(once(srv)) == 200


def test_still_faster_than_the_old_thread_pool():
    """A direct comparison with the old scheme: a pool over the sync session."""
    n, delay = 64, 0.3

    def old_way(srv):
        with curlpro.Session(verify=False, force_http1=True) as s:
            with ThreadPoolExecutor(max_workers=32) as pool:
                start = time.perf_counter()
                list(pool.map(lambda _: s.get(srv.url), range(n)))
                return time.perf_counter() - start

    async def new_way(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            start = time.perf_counter()
            await asyncio.gather(*(s.get(srv.url) for _ in range(n)))
            return time.perf_counter() - start

    with RawHeaderServer(persistent=True, delay=delay) as srv:
        old = old_way(srv)
        new = asyncio.run(new_way(srv))
    assert new < old, f"the new path {new:.2f} s against the old {old:.2f} s"
