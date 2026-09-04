"""Потоковое чтение и WebSocket в асинхронной сессии.

Раньше и то и другое ходило через пул потоков — потолок одновременности был
в его размере. Теперь ждут горутины, и поток у процесса по-прежнему один:
тот, что забирает завершения.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
import time
from pathlib import Path

import curlpro
import pytest
from curlpro._ffi import _lib

REPO = Path(__file__).resolve().parents[2]
CERT_DIR = REPO / "capture" / "certs"


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class BodyServer:
    """Отдаёт тело частями: так видно, что чтение идёт по кускам.

    :param chunks: список частей тела.
    :param gap: пауза между частями — на ней проверяется, что ожидание
        не занимает поток и не мешает другим задачам.
    :param head_delay: пауза до строки ответа: на ней ловится отмена
        ещё не открытого потока.
    """

    def __init__(self, chunks: list[bytes], gap: float = 0.0, head_delay: float = 0.0):
        self.chunks = chunks
        self.gap = gap
        self.head_delay = head_delay
        self.accepted = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self.port = self._sock.getsockname()[1]

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        self._ctx.set_alpn_protocols(["http/1.1"])

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}/"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._session, args=(raw,), daemon=True).start()

    def _session(self, raw: socket.socket) -> None:
        try:
            with self._ctx.wrap_socket(raw, server_side=True) as conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    part = conn.recv(4096)
                    if not part:
                        return
                    data += part
                if self.head_delay:
                    time.sleep(self.head_delay)
                total = sum(len(c) for c in self.chunks)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    b"Content-Length: " + str(total).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n"
                )
                for chunk in self.chunks:
                    conn.sendall(chunk)
                    if self.gap:
                        time.sleep(self.gap)
        except (ssl.SSLError, OSError):
            pass

    def __enter__(self) -> "BodyServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()


def ours() -> list[str]:
    """Только свои потоки: сервер в тестах тоже заводит поток на соединение."""
    return [t.name for t in threading.enumerate() if t.name.startswith("curlpro")]


async def watch_threads(stop: asyncio.Event) -> list[list[str]]:
    """Снимает список своих потоков, пока работа не кончится.

    Одной выборки мало: приёмник завершается, как только ждать нечего,
    и между двумя работами его может не быть вовсе. Важно другое — что
    их никогда не становится больше одного.
    """
    seen: list[list[str]] = []
    while not stop.is_set():
        seen.append(ours())
        await asyncio.sleep(0.02)
    return seen


def check_threads(samples: list[list[str]]) -> None:
    biggest = max((len(s) for s in samples), default=0)
    assert biggest <= 1, f"своих потоков стало {biggest}: {samples}"
    assert any(s == ["curlpro-completions"] for s in samples), (
        f"приёмник ни разу не попался на глаза: {samples}"
    )


def test_stream_reads_full_body():
    chunks = [b"x" * 8192] * 12

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            async with s.stream("GET", srv.url) as r:
                assert r.status == 200
                return b"".join([c async for c in r.iter_content(4096)])

    with BodyServer(chunks) as srv:
        body = asyncio.run(run(srv))
    assert len(body) == sum(len(c) for c in chunks)


def test_iter_lines_splits_ndjson():
    """Строка, разорванная границей части, должна собраться обратно."""
    chunks = [b'{"n":1}\n{"n":', b'2}\n{"n":3}']

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            async with s.stream("GET", srv.url) as r:
                return [line async for line in r.iter_lines(chunk_size=8)]

    with BodyServer(chunks) as srv:
        lines = asyncio.run(run(srv))
    assert lines == [b'{"n":1}', b'{"n":2}', b'{"n":3}']


def test_await_form_closes_by_hand():
    """Поток можно открыть и без ``async with`` — тогда закрывать вручную."""

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            r = await s.stream("GET", srv.url)
            try:
                assert await r.read() == b"hello"
            finally:
                await r.close()

    with BodyServer([b"hello"]) as srv:
        asyncio.run(run(srv))
    assert int(_lib.curlpro_async_pending()) == 0


def test_reading_does_not_block_the_loop():
    """Пока часть тела едет, цикл событий обязан заниматься другими делами."""
    ticks = 0

    async def tick():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    async def run(srv):
        ticker = asyncio.create_task(tick())
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            async with s.stream("GET", srv.url) as r:
                async for _ in r.iter_content(4096):
                    pass
        ticker.cancel()

    with BodyServer([b"y" * 1024] * 4, gap=0.1) as srv:
        asyncio.run(run(srv))
    assert ticks > 10, f"цикл событий тикнул {ticks} раз — похоже, он стоял"


def test_many_streams_share_one_helper_thread():
    n = 24

    async def one(s, url):
        async with s.stream("GET", url) as r:
            return len(await r.read())

    async def run(srv):
        stop = asyncio.Event()
        watcher = asyncio.create_task(watch_threads(stop))
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            sizes = await asyncio.gather(*(one(s, srv.url) for _ in range(n)))
        stop.set()
        return await watcher, sizes

    with BodyServer([b"z" * 4096] * 4, gap=0.05) as srv:
        samples, sizes = asyncio.run(run(srv))
    check_threads(samples)
    assert sizes == [4096 * 4] * n


def test_cancelled_open_leaves_nothing_behind():
    """Отмена во время открытия не должна оставлять поток на учёте.

    Если бы результат просто выбрасывался, соединение осталось бы занятым
    до конца жизни процесса: закрыть его снаружи уже нечем — номера потока
    вызывающий так и не увидел.
    """

    async def open_it(s, url):
        return await s.stream("GET", url)

    async def run(srv):
        async with curlpro.AsyncSession(verify=False, force_http1=True) as s:
            task = asyncio.create_task(open_it(s, srv.url))
            await asyncio.sleep(0.1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.sleep(0.6)  # даём нативной части убрать за собой

    with BodyServer([b"q" * 1024], head_delay=0.5) as srv:
        asyncio.run(run(srv))
    assert int(_lib.curlpro_async_pending()) == 0
