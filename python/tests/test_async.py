"""Асинхронный путь: горутины вместо пула потоков.

Раньше AsyncSession была фасадом над пулом из тридцати двух потоков, и он же
был потолком одновременности. Теперь запрос уходит в горутину, а поток на весь
процесс ровно один — тот, что ждёт завершений.
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
    """Сто двадцать восемь запросов по 0.3 с не должны идти четырьмя волнами."""
    n, delay = 128, 0.3

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            start = time.perf_counter()
            await asyncio.gather(*(s.get(srv.url) for _ in range(n)))
            return time.perf_counter() - start

    with RawHeaderServer(persistent=True, delay=delay) as srv:
        spent = asyncio.run(run(srv))

    # Пул из 32 потоков дал бы минимум четыре волны, то есть 4×delay.
    assert spent < delay * 3, f"{n} запросов заняли {spent:.2f} с — похоже на очередь"


def test_one_helper_thread_regardless_of_load():
    """Считаем только свои потоки: тестовый сервер тоже заводит поток
    на соединение, и общий счётчик мерил бы его, а не клиента."""
    import threading

    def ours() -> list[str]:
        return [t.name for t in threading.enumerate() if t.name.startswith("curlpro")]

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            tasks = [asyncio.create_task(s.get(srv.url)) for _ in range(64)]
            await asyncio.sleep(0.1)   # смотрим, пока запросы в полёте
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
    """Снятая задача не должна оставлять запрос в полёте: он занимал бы
    соединение до своего таймаута."""

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            task = asyncio.create_task(s.get(srv.url))
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # Даём нативной части дойти до отмены.
            await asyncio.sleep(0.5)

    with RawHeaderServer(persistent=True, delay=1.0) as srv:
        asyncio.run(run(srv))
    assert int(_lib.curlpro_async_pending()) == 0, "запрос остался в учёте"


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
    """Приёмник завершается вместе с последним запросом и поднимается снова."""

    async def once(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            return (await s.get(srv.url)).status

    with RawHeaderServer(persistent=True) as srv:
        assert asyncio.run(once(srv)) == 200
        time.sleep(0.4)  # приёмник успевает выйти по простою
        assert asyncio.run(once(srv)) == 200


def test_still_faster_than_the_old_thread_pool():
    """Прямое сравнение со схемой, которая была: пул поверх синхронной сессии."""
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
    assert new < old, f"новый путь {new:.2f} с против прежнего {old:.2f} с"
