"""Приёмник завершившихся запросов.

Асинхронный запрос уходит в горутину, а Python узнаёт о его конце отсюда.
Поток ровно один на процесс, независимо от числа запросов в полёте: он ждёт
в нативной части, где ctypes отпускает GIL, поэтому цикл событий не стоит.

Забирает результат уже сам цикл событий — вызов быстрый, память копируется
и всё. Ходить в цикл из чужого потока можно только через call_soon_threadsafe,
им и будим фьючерс.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from ._ffi import _lib, call_framed_out

# Сколько ждать в одном обращении к нативной части. Пробуждение раз в четверть
# секунды при простое ничего не стоит, зато поток завершается почти сразу
# после того, как его перестают использовать.
_WAIT_MS = 250


class Completions:
    """Единый на процесс приёмник результатов."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._waiters: dict[int, tuple[asyncio.AbstractEventLoop, asyncio.Future]] = {}
        self._thread: threading.Thread | None = None
        self._stop = False

    def register(self, request_id: int, future: asyncio.Future) -> None:
        loop = asyncio.get_running_loop()
        with self._lock:
            self._waiters[request_id] = (loop, future)
            if self._thread is None or not self._thread.is_alive():
                self._stop = False
                self._thread = threading.Thread(
                    target=self._reap, name="curlpro-completions", daemon=True
                )
                self._thread.start()

    def forget(self, request_id: int) -> None:
        """Снимает ожидание: запрос отменён и результат никому не нужен."""
        with self._lock:
            self._waiters.pop(request_id, None)

    def _reap(self) -> None:
        while True:
            with self._lock:
                if self._stop or not self._waiters:
                    self._thread = None
                    return
            rid = int(_lib.curlpro_result_wait(_WAIT_MS))
            if rid == 0:
                continue
            with self._lock:
                entry = self._waiters.pop(rid, None)
            if entry is None:
                # Запрос отменили, пока он завершался: результат забираем
                # и выбрасываем, иначе он останется в учёте нативной части.
                _take(rid)
                continue
            loop, future = entry
            try:
                loop.call_soon_threadsafe(_settle, future, rid)
            except RuntimeError:
                # Цикл событий уже закрыт — забирать результат некому.
                _take(rid)


def _take(request_id: int) -> tuple[Any, bytes] | None:
    try:
        return call_framed_out("curlpro_result_take", request_id)
    except Exception:  # noqa: BLE001 — результат уже забрали или сессия закрыта
        return None


def _settle(future: asyncio.Future, request_id: int) -> None:
    """Выполняется в цикле событий: забирает результат и будит ожидающего."""
    if future.done():  # задачу сняли, пока результат ехал
        _take(request_id)
        return
    try:
        payload, content = call_framed_out("curlpro_result_take", request_id)
    except BaseException as exc:  # noqa: BLE001 — ошибку отдаём ожидающему
        future.set_exception(exc)
        return
    future.set_result((payload, content))


#: Один экземпляр на процесс: нативная очередь готовых тоже одна.
completions = Completions()
