"""Асинхронный фасад.

Запросы, потоковое чтение и WebSocket уходят в нативную часть и выполняются
там горутинами: цикл событий не занят ожиданием, а число одновременных
операций ограничено соединениями и сервером, а не размером пула потоков.
Раньше здесь был пул на тридцать два потока, и он же был потолком.

Единственное, что осталось за циклом событий, — закрытие потока и сокета:
оно короткое, но ходит в сеть, поэтому уходит в исполнитель по умолчанию.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Iterable, Mapping

from ._completions import settle
from ._ffi import WebSocketClosed, _call, call_with_frame, encode
from .proxies import proxy_for as env_proxy
from .session import DEFAULT_PROFILE, Response, Session, _request_meta
from .timeouts import split_timeout as _split_timeout
from .stream import DEFAULT_CHUNK, lines_from


class _Opener:
    """Открывает ресурс и по ``async with``, и по ``await``.

    Открытие — корутина, но чаще результат нужен в блоке с автоматическим
    закрытием, и ``async with await ...`` читается плохо. Так же устроен
    aiohttp, поэтому форма привычна.
    """

    __slots__ = ("_coro", "_obj")

    def __init__(self, coro):  # noqa: ANN001 — корутина открытия
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
    """Тело, читаемое частями, без занятого потока.

        async with session.stream("GET", url) as r:
            async for chunk in r.iter_content():
                out.write(chunk)

    Поток удерживает соединение до закрытия — отсюда ``async with``.
    """

    __slots__ = ("status", "proto", "headers", "url", "_id", "_closed")

    def __init__(self, payload: dict):
        self.status: int = payload["status"]
        self.proto: str = payload.get("proto", "")
        self.headers: dict[str, list[str]] = payload.get("headers") or {}
        self.url: str = payload.get("url", "")
        self._id: int = payload["stream"]
        self._closed = False

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
        """Читает одну часть. Пустой результат означает конец тела."""
        if self._closed:
            raise RuntimeError("поток закрыт")
        if size <= 0:
            raise ValueError("размер части должен быть положительным")
        started = _call("curlpro_stream_read_start", self._id, size)
        _meta, data = await settle(started)
        return data

    async def iter_content(self, chunk_size: int = DEFAULT_CHUNK) -> AsyncIterator[bytes]:
        """Отдаёт тело частями до конца."""
        while True:
            chunk = await self.read_chunk(chunk_size)
            if not chunk:
                return
            yield chunk

    async def iter_lines(self, chunk_size: int = DEFAULT_CHUNK,
                         keepends: bool = False) -> AsyncIterator[bytes]:
        """Тело построчно, не собирая его целиком."""
        buffer = b""
        async for chunk in self.iter_content(chunk_size):
            buffer, lines = lines_from(buffer, chunk, keepends)
            for line in lines:
                yield line
        if buffer:
            yield buffer

    async def read(self) -> bytes:
        """Дочитывает тело целиком. Удобно, когда поток открыт зря."""
        parts = [chunk async for chunk in self.iter_content()]
        return b"".join(parts)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _call, "curlpro_stream_close", self._id)

    def __repr__(self) -> str:
        return f"<AsyncStreamResponse {self.status} {self.proto} поток {self._id}>"


class AsyncWebSocket:
    """WebSocket, не занимающий поток ни на приёме, ни на отправке."""

    __slots__ = ("_id", "_closed")

    def __init__(self, socket_id: int):
        self._id = socket_id
        self._closed = False

    async def send(self, data: str | bytes) -> None:
        """Отправляет сообщение. Тип кадра выбирается по типу данных."""
        binary = not isinstance(data, str)
        payload = data if binary else data.encode("utf-8")
        await self._send(payload, binary=binary, ping=False)

    async def ping(self, data: bytes = b"") -> None:
        """Отправляет ping. Ответный pong обрабатывается внутри recv."""
        await self._send(data, binary=True, ping=True)

    async def recv(self) -> str | bytes:
        """Читает следующее сообщение.

        Текстовые кадры возвращаются как ``str``, двоичные — как ``bytes``:
        на проводе это разные опкоды, и сервер вправе их различать.
        """
        self._check()
        started = _call("curlpro_ws_recv_start", self._id)
        meta, data = await settle(started)
        return data if (meta or {}).get("binary") else data.decode("utf-8")

    async def __aiter__(self) -> AsyncIterator[str | bytes]:
        """Читает сообщения, пока соединение не закроется."""
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
            raise RuntimeError("сокет закрыт")

    def __repr__(self) -> str:
        state = "закрыт" if self._closed else "открыт"
        return f"<AsyncWebSocket {self._id} {state}>"


class AsyncSession:
    """Асинхронная сессия поверх той же нативной сессии, что и обычная.

    Принимает те же параметры, что и :class:`~curlpro.Session`.

    :param max_workers: не используется. Оставлен, чтобы не ломать вызовы,
        написанные до перехода на нативную асинхронность: пула потоков
        больше нет, ждут теперь горутины.
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
    def cookies(self):  # noqa: ANN201 — тип задан в Session
        """Куки сессии: те же, что у синхронной."""
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

    async def request(self, method: str, url: str, **kw: Any) -> Response:
        if self._session._closed:
            raise RuntimeError("сессия закрыта")

        if kw.get("proxy") is None and self._session._trust_env:
            kw["proxy"] = env_proxy(url)
        meta, body = _request_meta(method, url, **kw)
        for hook in self._session.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        started = call_with_frame(
            "curlpro_request_start", self._session._id, body=body, meta=meta
        )
        payload, content = await settle(started)

        return self._session._after(Response(
            status=payload["status"],
            proto=payload.get("proto", ""),
            headers=payload.get("headers") or {},
            content=content,
            url=payload.get("url") or url,
        ))

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
        """Открывает ответ для чтения по частям.

            async with session.stream("GET", url) as r:
                async for chunk in r.iter_content():
                    out.write(chunk)

        Принимает те же аргументы, что и :meth:`request`. Поток удерживает
        соединение до закрытия, поэтому открывать его следует через
        ``async with`` — или закрывать вручную, если ``await``.
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
        """Открывает WebSocket с заголовками рукопожатия из профиля.

            async with session.websocket(url) as ws:
                await ws.send("привет")
                print(await ws.recv())
        """
        return _Opener(self._open_websocket(
            url, headers=headers, subprotocols=subprotocols,
            timeout=timeout, max_message_size=max_message_size,
        ))

    async def _open_stream(self, method: str, url: str, **kw: Any) -> AsyncStreamResponse:
        if self._session._closed:
            raise RuntimeError("сессия закрыта")
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
        return AsyncStreamResponse(payload)

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
            raise RuntimeError("сессия закрыта")
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
        # Закрытие ходит в сеть — за пределы цикла событий: сессия закрывает
        # соединения, и на медленной сети это заметное ожидание.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._session.close)

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
