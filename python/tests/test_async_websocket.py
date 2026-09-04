"""WebSocket in the async session: handshake, receive and send without threads."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import curlpro
import pytest
from curlpro._ffi import _lib

websockets = pytest.importorskip("websockets")

from test_websocket_local import LocalWS  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def ours() -> list[str]:
    return [t.name for t in threading.enumerate() if t.name.startswith("curlpro")]


async def watch_threads(stop: asyncio.Event) -> list[list[str]]:
    """Samples the list of our threads until the work is over.

    One sample is not enough: the collector exits as soon as there is nothing to
    wait for, and between two pieces of work it may not exist at all. What
    matters is that there is never more than one.
    """
    seen: list[list[str]] = []
    while not stop.is_set():
        seen.append(ours())
        await asyncio.sleep(0.02)
    return seen


def check_threads(samples: list[list[str]]) -> None:
    biggest = max((len(s) for s in samples), default=0)
    assert biggest <= 1, f"our threads grew to {biggest}: {samples}"
    assert any(s == ["curlpro-completions"] for s in samples), (
        f"the collector was never seen: {samples}"
    )


def test_echo_text_and_binary():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    async def run(srv):
        async with curlpro.AsyncSession("chrome-151-windows", verify=False) as s:
            async with s.websocket(srv.url, timeout=5) as ws:
                await ws.send("hello")
                assert await ws.recv() == "hello"
                await ws.send(b"\x00\x01\x02")
                assert await ws.recv() == b"\x00\x01\x02"

    with LocalWS(handler) as srv:
        asyncio.run(run(srv))
    assert int(_lib.curlpro_async_pending()) == 0


def test_iteration_stops_on_close():
    async def handler(ws):
        await ws.send("one")
        await ws.send("two")
        await ws.close()

    async def run(srv):
        async with curlpro.AsyncSession("chrome-151-windows", verify=False) as s:
            async with s.websocket(srv.url, timeout=5) as ws:
                return [msg async for msg in ws]

    with LocalWS(handler) as srv:
        assert asyncio.run(run(srv)) == ["one", "two"]


def test_waiting_for_a_message_does_not_block_the_loop():
    """While there is no message, the event loop must handle other work."""
    ticks = 0

    async def handler(ws):
        await asyncio.sleep(0.4)
        await ws.send("at last")
        await asyncio.sleep(0.2)

    async def tick():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    async def run(srv):
        ticker = asyncio.create_task(tick())
        async with curlpro.AsyncSession("chrome-151-windows", verify=False) as s:
            async with s.websocket(srv.url, timeout=5) as ws:
                assert await ws.recv() == "at last"
        ticker.cancel()

    with LocalWS(handler, compression=None) as srv:
        asyncio.run(run(srv))
    assert ticks > 20, f"the event loop ticked {ticks} times — it looks stalled"


def test_many_sockets_share_one_helper_thread():
    n = 12

    async def handler(ws):
        async for msg in ws:
            await asyncio.sleep(0.1)
            await ws.send(f"echo:{msg}")

    async def one(s, url, i):
        async with s.websocket(url, timeout=5) as ws:
            await ws.send(f"number {i}")
            return await ws.recv()

    async def run(srv):
        stop = asyncio.Event()
        watcher = asyncio.create_task(watch_threads(stop))
        async with curlpro.AsyncSession("chrome-151-windows", verify=False) as s:
            answers = await asyncio.gather(*(one(s, srv.url, i) for i in range(n)))
        stop.set()
        return await watcher, answers

    with LocalWS(handler, compression=None) as srv:
        samples, answers = asyncio.run(run(srv))
    check_threads(samples)
    assert sorted(answers) == sorted(f"echo:number {i}" for i in range(n))


def test_handshake_headers_come_from_the_profile():
    """The async handshake takes the same path as the ordinary one: browser headers."""
    seen: dict[str, str] = {}

    async def handler(ws):
        seen.update({k.lower(): v for k, v in ws.request.headers.items()})
        await ws.send("ok")

    async def run(srv):
        async with curlpro.AsyncSession("chrome-151-windows", verify=False) as s:
            async with s.websocket(srv.url, timeout=5) as ws:
                assert await ws.recv() == "ok"

    with LocalWS(handler, compression=None) as srv:
        asyncio.run(run(srv))
    assert "chrome" in seen.get("user-agent", "").lower(), seen
    assert seen.get("sec-websocket-version") == "13", seen
