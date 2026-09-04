"""Асинхронный фасад.

Запросы уходят в нативную часть и выполняются там горутинами: цикл событий
не занят ожиданием, а число одновременных запросов ограничено соединениями
и сервером, а не размером пула потоков. Раньше здесь был пул на тридцать два
потока, и он же был потолком одновременности.

Потоковое чтение и WebSocket пока идут через пул: они держат соединение
открытым, и переносить их на ту же схему — отдельная работа.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ._completions import completions
from ._ffi import _call, call_with_frame
from .session import DEFAULT_PROFILE, Response, Session, _request_meta


class AsyncSession:
    """Асинхронная сессия поверх той же нативной сессии, что и обычная.

    :param max_workers: размер пула для потокового чтения и WebSocket.
        На обычные запросы он больше не влияет: они не занимают потоков.
    """

    def __init__(
        self,
        impersonate: str = DEFAULT_PROFILE,
        *,
        max_workers: int = 32,
        **kwargs: Any,
    ):
        self._session = Session(impersonate, **kwargs)
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="curlpro"
        )
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

        meta, body = _request_meta(method, url, **kw)
        for hook in self._session.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        started = call_with_frame(
            "curlpro_request_start", self._session._id, body=body, meta=meta
        )
        request_id = int(started["request"])

        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        completions.register(request_id, future)
        try:
            payload, content = await future
        except asyncio.CancelledError:
            # Задачу сняли: отменяем запрос в нативной части, иначе он
            # займёт соединение до своего таймаута.
            completions.forget(request_id)
            _call("curlpro_request_cancel", request_id)
            raise

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

    async def close(self) -> None:
        loop = asyncio.get_running_loop()
        # Сначала дожидаемся работы в пуле, потом закрываем сессию:
        # в обратном порядке она получала бы «сессия закрыта».
        await loop.run_in_executor(None, lambda: self._pool.shutdown(wait=True))
        await loop.run_in_executor(None, self._session.close)

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
