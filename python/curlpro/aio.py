"""The async facade.

Requests, streaming reads and WebSockets all go into the native part and run
there as goroutines: the event loop is never blocked waiting, and the number
of concurrent operations is bounded by connections and by the server, not by
the size of a thread pool. There used to be a pool of thirty-two threads
here, and it was the ceiling.

The only thing left off the event loop is closing a stream or a socket: it is
short but it touches the network, so it goes to the default executor.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Iterable, Mapping

from ._completions import settle
from ._ffi import CurlProError, WebSocketClosed, _call, call_with_frame, encode
from .proxies import proxy_for as env_proxy
from .session import DEFAULT_PROFILE, Response, Session, _request_meta
from .timeouts import split_timeout as _split_timeout
from .stream import DEFAULT_CHUNK, lines_from, too_large


class _Opener:
    """Opens a resource both with ``async with`` and with ``await``.

    Opening is a coroutine, but the result is usually wanted inside a block
    that closes it automatically, and ``async with await ...`` reads badly.
    aiohttp is built the same way, so the shape is familiar.
    """

    __slots__ = ("_coro", "_obj")

    def __init__(self, coro):  # noqa: ANN001 — the opening coroutine
        self._coro = coro
        self._obj: Any = None

    def __await__(self):  # noqa: ANN204
        return self._coro.__await__()

    async def __aenter__(self) -> Any:
        self._obj = await self._coro
        return self._obj

    async def __aexit__(self, *exc: object) -> None:
        await self._obj.close()


class AsyncStreamResponse:
    """A body read in chunks without tying up a thread.

        async with session.stream("GET", url) as r:
            async for chunk in r.iter_content():
                out.write(chunk)

    The stream holds its connection until closed — hence ``async with``.
    """

    __slots__ = ("status", "proto", "headers", "url", "_id", "_closed", "_max_size")

    def __init__(self, payload: dict, max_size: int = 0):
        self.status: int = payload["status"]
        self.proto: str = payload.get("proto", "")
        self.headers: dict[str, list[str]] = payload.get("headers") or {}
        self.url: str = payload.get("url", "")
        self._id: int = payload["stream"]
        self._closed = False
        # See StreamResponse: the limit binds read(), not iter_content().
        self._max_size = max_size

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, values in self.headers.items():
            if key.lower() == lowered and values:
                return values[0]
        return None

    async def read_chunk(self, size: int = DEFAULT_CHUNK) -> bytes:
        """Reads one chunk. An empty result means the body ended."""
        if self._closed:
            raise RuntimeError("stream is closed")
        if size <= 0:
            raise ValueError("chunk size must be positive")
        started = _call("curlpro_stream_read_start", self._id, size)
        _meta, data = await settle(started)
        return data

    async def iter_content(self, chunk_size: int = DEFAULT_CHUNK) -> AsyncIterator[bytes]:
        """Yields the body in chunks until it ends."""
        while True:
            chunk = await self.read_chunk(chunk_size)
            if not chunk:
                return
            yield chunk

    async def iter_lines(self, chunk_size: int = DEFAULT_CHUNK,
                         keepends: bool = False) -> AsyncIterator[bytes]:
        """The body line by line, without collecting it whole."""
        buffer = b""
        async for chunk in self.iter_content(chunk_size):
            buffer, lines = lines_from(buffer, chunk, keepends)
            for line in lines:
                yield line
        if buffer:
            yield buffer

    async def read(self) -> bytes:
        """Reads the rest of the body. Handy when the stream was opened in vain.

        Bounded by the session's ``max_response_size``, exactly as the
        synchronous reader is.
        """
        if not self._max_size:
            return b"".join([chunk async for chunk in self.iter_content()])
        parts: list[bytes] = []
        total = 0
        while total <= self._max_size:
            chunk = await self.read_chunk(min(DEFAULT_CHUNK, self._max_size + 1 - total))
            if not chunk:
                return b"".join(parts)
            parts.append(chunk)
            total += len(chunk)
        raise too_large(self._max_size)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _call, "curlpro_stream_close", self._id)

    def __repr__(self) -> str:
        return f"<AsyncStreamResponse {self.status} {self.proto} stream {self._id}>"


class AsyncWebSocket:
    """A WebSocket that ties up no thread, neither on receive nor on send."""

    __slots__ = ("_id", "_closed")

    def __init__(self, socket_id: int):
        self._id = socket_id
        self._closed = False

    async def send(self, data: str | bytes) -> None:
        """Sends a message. The frame type follows the type of the data."""
        binary = not isinstance(data, str)
        payload = data if binary else data.encode("utf-8")
        await self._send(payload, binary=binary, ping=False)

    async def ping(self, data: bytes = b"") -> None:
        """Sends a ping. The matching pong is handled inside recv."""
        await self._send(data, binary=True, ping=True)

    async def recv(self) -> str | bytes:
        """Reads the next message.

        Text frames come back as ``str`` and binary ones as ``bytes``: on the
        wire these are different opcodes, and a server may tell them apart.
        """
        self._check()
        started = _call("curlpro_ws_recv_start", self._id)
        meta, data = await settle(started)
        return data if (meta or {}).get("binary") else data.decode("utf-8")

    async def __aiter__(self) -> AsyncIterator[str | bytes]:
        """Reads messages until the connection closes."""
        while True:
            try:
                yield await self.recv()
            except WebSocketClosed:
                return

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, _call, "curlpro_ws_close", self._id, code, reason.encode("utf-8")
        )

    async def _send(self, payload: bytes, *, binary: bool, ping: bool) -> None:
        self._check()
        started = call_with_frame(
            "curlpro_ws_send_start", self._id,
            body=payload, meta={"binary": binary, "ping": ping},
        )
        await settle(started)

    def _check(self) -> None:
        if self._closed:
            raise RuntimeError("socket is closed")

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"<AsyncWebSocket {self._id} {state}>"


class AsyncSession:
    """An async session over the same native session as the sync one.

    Takes the same parameters as :class:`~curlpro.Session`.

    :param max_workers: unused. Kept so that calls written before the move to
        native async keep working: there is no thread pool any more, the
        waiting is done by goroutines.
    """

    def __init__(
        self,
        impersonate: str = DEFAULT_PROFILE,
        *,
        max_workers: int | None = None,
        **kwargs: Any,
    ):
        self._session = Session(impersonate, **kwargs)
        self.impersonate = impersonate

    @property
    def cookies(self):  # noqa: ANN201 — the type is declared in Session
        """The session cookies: the same ones the sync session sees."""
        return self._session.cookies

    @property
    def headers(self):  # noqa: ANN201
        return self._session.headers

    @property
    def hooks(self) -> dict[str, list[Any]]:
        return self._session.hooks

    def on_request(self, fn):  # noqa: ANN001, ANN201
        return self._session.on_request(fn)

    def on_response(self, fn):  # noqa: ANN001, ANN201
        return self._session.on_response(fn)

    def on_error(self, fn):  # noqa: ANN001, ANN201
        return self._session.on_error(fn)

    async def request(self, method: str, url: str, **kw: Any) -> Response:
        """Sends a request. Takes the same arguments as :meth:`Session.request`,
        including ``expect`` and ``rollback_cookies``."""
        if self._session._closed:
            raise RuntimeError("session is closed")

        expect = kw.pop("expect", None)
        rollback = kw.pop("rollback_cookies", False)
        # The snapshot is taken before sending: after a failure the jar has
        # already changed and there is nothing left to copy.
        saved = self._session.cookies.snapshot() if rollback else None

        if kw.get("proxy") is None and self._session._trust_env:
            kw["proxy"] = env_proxy(url)
        meta, body = _request_meta(method, url, **kw)
        for hook in self._session.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        try:
            started = call_with_frame(
                "curlpro_request_start", self._session._id, body=body, meta=meta
            )
            payload, content = await settle(started)
        except asyncio.CancelledError:
            # The rollback still applies — the request did not finish — but the
            # cancellation itself must reach the task loop untouched.
            if saved is not None:
                self._session.cookies.restore(saved)
            raise
        except BaseException as exc:
            raise self._session._failed(exc, saved) from None

        try:
            return self._session._after(Response(
                status=payload["status"],
                proto=payload.get("proto", ""),
                headers=payload.get("headers") or {},
                content=content,
                url=payload.get("url") or url,
            ), expect)
        except BaseException as exc:
            # A failed expectation is a request failure too: the caller was
            # promised a response of a certain shape and did not get it.
            raise self._session._failed(exc, saved) from None

    async def get(self, url: str, **kw: Any) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> Response:
        return await self.request("POST", url, **kw)

    async def put(self, url: str, **kw: Any) -> Response:
        return await self.request("PUT", url, **kw)

    async def patch(self, url: str, **kw: Any) -> Response:
        return await self.request("PATCH", url, **kw)

    async def delete(self, url: str, **kw: Any) -> Response:
        return await self.request("DELETE", url, **kw)

    async def head(self, url: str, **kw: Any) -> Response:
        return await self.request("HEAD", url, **kw)

    async def options(self, url: str, **kw: Any) -> Response:
        return await self.request("OPTIONS", url, **kw)

    def stream(self, method: str, url: str, **kw: Any) -> _Opener:
        """Opens a response for reading in chunks.

            async with session.stream("GET", url) as r:
                async for chunk in r.iter_content():
                    out.write(chunk)

        Takes the same arguments as :meth:`request`. The stream holds its
        connection until closed, so open it with ``async with`` — or close it
        by hand if you ``await`` it instead.
        """
        return _Opener(self._open_stream(method, url, **kw))

    def websocket(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        subprotocols: Iterable[str] | None = None,
        timeout: float | tuple[float, float] = 30.0,
        max_message_size: int = 0,
    ) -> _Opener:
        """Opens a WebSocket whose handshake headers come from the profile.

            async with session.websocket(url) as ws:
                await ws.send("hello")
                print(await ws.recv())
        """
        return _Opener(self._open_websocket(
            url, headers=headers, subprotocols=subprotocols,
            timeout=timeout, max_message_size=max_message_size,
        ))

    async def _open_stream(self, method: str, url: str, **kw: Any) -> AsyncStreamResponse:
        if self._session._closed:
            raise RuntimeError("session is closed")
        if kw.get("proxy") is None and self._session._trust_env:
            kw["proxy"] = env_proxy(url)
        meta, body = _request_meta(method, url, **kw)
        for hook in self._session.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        started = call_with_frame(
            "curlpro_stream_open_start", self._session._id, body=body, meta=meta
        )
        payload, _ = await settle(started)
        return AsyncStreamResponse(payload, self._session._max_response_size)

    async def _open_websocket(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None,
        subprotocols: Iterable[str] | None,
        timeout: float | tuple[float, float],
        max_message_size: int,
    ) -> AsyncWebSocket:
        if self._session._closed:
            raise RuntimeError("session is closed")
        connect_timeout, total = _split_timeout(timeout)
        started = _call(
            "curlpro_ws_connect_start",
            self._session._id,
            encode({
                "url": url,
                "headers": dict(headers or {}),
                "subprotocols": list(subprotocols or []),
                "timeout_ms": int(total * 1000) if total else 0,
                "connect_timeout_ms":
                    int(connect_timeout * 1000) if connect_timeout else 0,
                "max_message_size": int(max_message_size),
            }),
        )
        payload, _ = await settle(started)
        return AsyncWebSocket(payload["socket"])

    async def close(self) -> None:
        # Closing touches the network, so it goes off the event loop: the
        # session closes its connections, and on a slow link that shows.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._session.close)

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
