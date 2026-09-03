"""Асинхронная обёртка.

FFI-вызов блокирующий: пока Go выполняет запрос, поток стоит. Поэтому вызовы
уводятся в пул потоков — GIL при этом отпускается, так как ctypes освобождает
его на время нативного вызова. Настоящий параллелизм обеспечивает Go: сокеты
и горутины живут на его стороне, Python лишь ждёт результата.

    async with curlpro.AsyncSession("chrome-151-windows") as s:
        r = await s.get("https://example.com")

    # запросы идут одновременно, не по очереди
    results = await asyncio.gather(*(s.get(u) for u in urls))
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable

from .session import DEFAULT_PROFILE, Response, Session


class AsyncSession:
    """Асинхронный фасад над :class:`Session`.

    :param max_workers: размер пула потоков, то есть предел одновременных
        запросов этой сессии. Значение по умолчанию совпадает с тем, сколько
        соединений браузер держит к одному хосту.
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

    async def request(self, method: str, url: str, **kw: Any) -> Response:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._pool, lambda: self._session.request(method, url, **kw)
        )

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
        await loop.run_in_executor(self._pool, self._session.close)
        # Дожидаемся завершения задач, иначе поток может обратиться
        # к уже закрытой сессии.
        self._pool.shutdown(wait=True)

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


async def request(method: str, url: str, *, impersonate: str = DEFAULT_PROFILE,
                  **kw: Any) -> Response:
    """Одиночный асинхронный запрос. Для серии используйте AsyncSession."""
    session_kw = {
        k: kw.pop(k)
        for k in ("verify", "timeout", "proxy", "default_headers", "header_order",
                  "allow_redirects", "max_redirects", "cookies", "force_http1", "http3")
        if k in kw
    }
    async with AsyncSession(impersonate, **session_kw) as s:
        return await s.request(method, url, **kw)


async def get(url: str, **kw: Any) -> Response:
    return await request("GET", url, **kw)


async def post(url: str, **kw: Any) -> Response:
    return await request("POST", url, **kw)
