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
import time
import warnings
from typing import TYPE_CHECKING, Any, AsyncIterator, Iterable, Mapping

import weakref

from ._completions import settle
from ._ffi import _call, call_with_frame, encode
from ._headers import Headers
from .errors import WebSocketClosed
from .session import DEFAULT_PROFILE, Redirect, Response, Session, _preflights, _request_meta
from .timeouts import split_timeout as _split_timeout
from .stream import DEFAULT_CHUNK, lines_from, too_large
from .websocket import _proxy_field


if TYPE_CHECKING:
    from typing_extensions import Unpack

    from ._kwargs import RequestKwargs, StreamKwargs

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



def _quiet_call(name: str, *args: Any) -> None:
    """A native close from a finaliser or an orphan handler: never raises."""
    try:
        _call(name, *args)
    except Exception:  # noqa: BLE001 — already closed, or the session is gone
        pass


async def _await_pending(owner: Any) -> tuple[Any, bytes]:
    """Awaits owner._pending without cancelling it when the waiter is.

    The read or receive in flight stays in ``owner._pending`` across a
    cancelled wait; any other outcome, a result or an error, clears it.
    """
    task = owner._pending
    try:
        result = await asyncio.shield(task)
    except asyncio.CancelledError:
        if task.cancelled():
            owner._pending = None
        raise
    except BaseException:
        owner._pending = None
        raise
    owner._pending = None
    return result

class AsyncStreamResponse:
    """A body read in chunks without tying up a thread.

        async with session.stream("GET", url) as r:
            async for chunk in r.iter_content():
                out.write(chunk)

    The stream holds its connection until closed — hence ``async with``.
    """

    __slots__ = ("status", "proto", "headers", "url", "history", "preflights",
                 "_id", "_closed", "_max_size", "_pending", "_finalizer", "__weakref__")

    def __init__(self, payload: dict, max_size: int = 0):
        self._pending: asyncio.Task | None = None
        self.status: int = payload["status"]
        self.proto: str = payload.get("proto", "")
        self.headers = Headers(payload.get("headers"))
        self.url: str = payload.get("url", "")
        from .session import Redirect, _preflights
        #: The redirect hops before this response, first to last.
        self.history = [Redirect(h.get("status", 0), h.get("url", ""), h.get("location", ""))
                        for h in payload.get("history") or []]
        #: The CORS preflights sent before the request, in order.
        self.preflights = _preflights(payload.get("preflights"))
        self._id: int = payload["stream"]
        self._closed = False
        # See StreamResponse: the limit binds read(), not iter_content().
        self._max_size = max_size
        # A stream nobody closed is closed when collected: the sync one was,
        # the async one held its connection until the process ended.
        self._finalizer = weakref.finalize(self, _quiet_call, "curlpro_stream_close", self._id)

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
        # A read in flight survives a cancelled wait: wait_for(read_chunk(), t)
        # used as an idle timeout cancelled the wait while the native read went
        # on, and whatever it read was thrown away. The next call gets it.
        if self._pending is None:
            started = _call("curlpro_stream_read_start", self._id, size)
            self._pending = asyncio.ensure_future(settle(started))
        _meta, data = await _await_pending(self)
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
        self._finalizer.detach()
        if self._pending is not None:
            self._pending.cancel()
            self._pending = None
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _call, "curlpro_stream_close", self._id)

    def __repr__(self) -> str:
        return f"<AsyncStreamResponse {self.status} {self.proto} stream {self._id}>"


class AsyncWebSocket:
    """A WebSocket that ties up no thread, neither on receive nor on send."""

    __slots__ = ("_id", "_closed", "_pending", "_finalizer", "__weakref__")

    def __init__(self, socket_id: int):
        self._pending: asyncio.Task | None = None
        self._finalizer = weakref.finalize(self, _quiet_call, "curlpro_ws_close", socket_id, 1001, b"")
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
        # As with a stream read: a receive in flight survives a cancelled
        # wait, and the next recv() gets its message instead of losing it.
        if self._pending is None:
            started = _call("curlpro_ws_recv_start", self._id)
            self._pending = asyncio.ensure_future(settle(started))
        meta, data = await _await_pending(self)
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
        self._finalizer.detach()
        if self._pending is not None:
            self._pending.cancel()
            self._pending = None
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

    # __slots__ is the point, not the memory: without it this class is a bag
    # of attributes, and `s.page = url` for a property it had forgotten to
    # proxy went into that bag instead of reaching the session. No error, no
    # Referer on the wire, and a field report that found it only by standing
    # up an echo server. A missing name is now an AttributeError.
    __slots__ = ("_session", "impersonate")

    def __init__(
        self,
        impersonate: str = DEFAULT_PROFILE,
        *,
        max_workers: int | None = None,
        **kwargs: Any,
    ):
        if max_workers is not None:
            # The thread pool this sized was removed in 0.2.0: requests run as
            # goroutines and the process keeps one thread. Accepting the
            # argument in silence would let a caller believe it still limits
            # something. Warned now, removed in the next minor (VERSIONING.md).
            warnings.warn(
                "AsyncSession(max_workers=...) has no effect since 0.2.0 and "
                "will be removed; requests are not bounded by a thread pool",
                DeprecationWarning, stacklevel=2)
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
    def page(self) -> str | None:
        """The page the requests are made from. See :attr:`curlpro.Session.page`."""
        return self._session.page

    @page.setter
    def page(self, url: str | None) -> None:
        self._session.page = url

    @property
    def hooks(self) -> dict[str, list[Any]]:
        return self._session.hooks

    def fingerprint(self, url: str = "https://example.com/"):  # noqa: ANN201
        """What a server would see. Offline, like the sync session's."""
        return self._session.fingerprint(url)

    def audit(self, mode: str | None = None) -> list:
        """Contradictions in what this session would send."""
        return self._session.audit(mode)

    def headers_for(self, method: str = "GET", url: str = "https://example.com/", **kw: Any):  # noqa: ANN201
        """The headers a request would carry, without sending it."""
        return self._session.headers_for(method, url, **kw)

    def preflight_for(self, method: str = "GET", url: str = "https://example.com/", **kw: Any):  # noqa: ANN201
        """The CORS preflight a request would be preceded by, or None."""
        return self._session.preflight_for(method, url, **kw)

    def on_request(self, fn):  # noqa: ANN001, ANN201
        return self._session.on_request(fn)

    def on_response(self, fn):  # noqa: ANN001, ANN201
        return self._session.on_response(fn)

    def on_error(self, fn):  # noqa: ANN001, ANN201
        return self._session.on_error(fn)

    async def request(self, method: str, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        """Sends a request. Takes the same arguments as :meth:`Session.request`,
        including ``expect`` and ``rollback_cookies``."""
        if self._session._closed:
            raise RuntimeError("session is closed")

        expect = kw.pop("expect", None)
        rollback = kw.pop("rollback_cookies", False)

        kw["proxy"] = self._session._route(url, kw.get("proxy"))
        # expect and rollback_cookies were popped above.
        meta, body = _request_meta(method, url, **kw)  # type: ignore[misc]
        if rollback:
            meta["track_cookies"] = True
        for hook in self._session.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        t0 = time.perf_counter()
        try:
            started = call_with_frame(
                "curlpro_request_start", self._session._id, body=body, meta=meta
            )
            payload, content = await settle(started)
        except asyncio.CancelledError:
            # The native request fails with the cancellation and undoes its
            # own cookie changes there; the cancellation reaches the task loop
            # untouched.
            raise
        except BaseException as exc:
            raise self._session._failed(exc, None) from None

        try:
            # The same fields the synchronous path fills: a response built
            # here without history and preflights was the third field report
            # — `r.preflight` was None on every AsyncSession request while the
            # OPTIONS had gone out, and the redirect chain was invisible too.
            return self._session._after(Response(
                status=payload["status"],
                proto=payload.get("proto", ""),
                headers=payload.get("headers") or {},
                content=content,
                url=payload.get("url") or url,
                elapsed=time.perf_counter() - t0,
                history=[Redirect(h.get("status", 0), h.get("url", ""), h.get("location", ""))
                         for h in payload.get("history") or []],
                preflights=_preflights(payload.get("preflights")),
            ), expect)
        except BaseException as exc:
            # A failed expectation is a request failure too: the caller was
            # promised a response of a certain shape and did not get it.
            raise self._session._failed(exc, payload.get("cookie_changes") if rollback else None) from None

    async def get(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return await self.request("POST", url, **kw)

    async def put(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return await self.request("PUT", url, **kw)

    async def patch(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return await self.request("PATCH", url, **kw)

    async def delete(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return await self.request("DELETE", url, **kw)

    async def head(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return await self.request("HEAD", url, **kw)

    async def options(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return await self.request("OPTIONS", url, **kw)

    def stream(self, method: str, url: str, **kw: Unpack[StreamKwargs]) -> _Opener:
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
        kw["proxy"] = self._session._route(url, kw.get("proxy"))
        meta, body = _request_meta(method, url, **kw)
        for hook in self._session.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        started = call_with_frame(
            "curlpro_stream_open_start", self._session._id, body=body, meta=meta
        )
        payload, _ = await settle(started, on_orphan=lambda r: _quiet_call(
            "curlpro_stream_close", r[0]["stream"]))
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
                **_proxy_field(self._session._route(url)),
            }),
        )
        payload, _ = await settle(started, on_orphan=lambda r: _quiet_call(
            "curlpro_ws_close", r[0]["socket"], 1001, b""))
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
