"""WebSocket against a local server: compression, closing, timeouts.

echo.websocket.org does not enable permessage-deflate and never closes the
connection itself, so those scenarios are checked against a server from the
``websockets`` package with the stand certificate. Without it they skip.
"""

from __future__ import annotations

import asyncio
import ssl
import threading
import time
from pathlib import Path

import pytest

import curlpro

websockets = pytest.importorskip("websockets")

REPO = Path(__file__).resolve().parents[2]
CERT_DIR = REPO / "capture" / "certs"


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class LocalWS:
    """A WSS server in its own thread. handler is a websockets coroutine."""

    def __init__(self, handler, compression="deflate"):
        self._handler = handler
        self._compression = compression
        self._port: int | None = None
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        async def main():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
            self._loop = asyncio.get_running_loop()
            async with websockets.serve(self._handler, "127.0.0.1", 0, ssl=ctx,
                                        compression=self._compression) as server:
                self._port = server.sockets[0].getsockname()[1]
                self._ready.set()
                await asyncio.Future()

        try:
            asyncio.run(main())
        except Exception:  # noqa: BLE001 — the server is stopped from outside
            pass

    def __enter__(self) -> "LocalWS":
        self._thread.start()
        self._ready.wait(5)
        return self

    def __exit__(self, *exc: object) -> None:
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

    @property
    def url(self) -> str:
        return f"wss://localhost:{self._port}/"


def test_compressed_messages_are_inflated():
    """The server accepts permessage-deflate and sends compressed frames; the
    client must inflate them rather than hand deflate bytes back as text."""

    async def handler(ws):
        await ws.send("hello, deflate " * 20)
        await ws.send("second message shares the window " * 5)
        got = await ws.recv()
        await ws.send(f"echo:{got}")
        await asyncio.sleep(1)

    with LocalWS(handler) as srv:
        with curlpro.Session("chrome-151-windows", verify=False) as s:
            with s.websocket(srv.url, timeout=5) as ws:
                assert ws.recv() == "hello, deflate " * 20
                assert ws.recv() == "second message shares the window " * 5
                ws.send("from client")
                assert ws.recv() == "echo:from client"


def test_iteration_stops_only_on_close():
    """A read timeout is an error with a code, not the end of the iteration."""

    async def handler(ws):
        await ws.send("one")
        await asyncio.sleep(3)

    with LocalWS(handler, compression=None) as srv:
        with curlpro.Session("chrome-151-windows", verify=False) as s:
            with s.websocket(srv.url, timeout=0.5) as ws:
                got = []
                start = time.perf_counter()
                with pytest.raises(curlpro.CurlProError) as info:
                    for m in ws:
                        got.append(m)
                assert got == ["one"]
                assert info.value.code == "timeout"
                assert time.perf_counter() - start < 2


def test_server_close_raises_websocket_closed():
    async def handler(ws):
        await ws.send("bye")
        await ws.close(code=4000, reason="done")

    with LocalWS(handler, compression=None) as srv:
        with curlpro.Session("chrome-151-windows", verify=False) as s:
            with s.websocket(srv.url, timeout=5) as ws:
                assert list(ws) == ["bye"]
                with pytest.raises(curlpro.WebSocketClosed):
                    ws.recv()


def test_message_limit_is_enforced():
    async def handler(ws):
        await ws.send("x" * 5000)
        await asyncio.sleep(1)

    with LocalWS(handler, compression=None) as srv:
        with curlpro.Session("chrome-151-windows", verify=False) as s:
            with s.websocket(srv.url, timeout=5, max_message_size=1024) as ws:
                with pytest.raises(curlpro.CurlProError) as info:
                    ws.recv()
                assert info.value.code == "ws_too_big"
