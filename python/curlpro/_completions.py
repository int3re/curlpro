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

from ._ffi import _call, _lib, call_framed_out

# Сколько ждать в одном обращении к нативной части. Пробуждение раз в четверть
# секунды при простое ничего не стоит, зато поток завершается почти сразу
# после того, как его перестают использовать.
_WAIT_MS = 250


class Completions:
    """Единый на процесс приёмник результатов."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._waiters: dict[int, tuple[asyncio.AbstractEventLoop, asyncio.Future]] = {}
        # Результаты, пришедшие раньше своего ожидающего: работа успевает
        # закончиться между запуском и register — у чтения из потока это
        # обычное дело, оно занимает микросекунды.
        self._ready: dict[int, tuple[Any, bytes]] = {}
        self._thread: threading.Thread | None = None
        self._stop = False

    def register(self, request_id: int, future: asyncio.Future) -> None:
        loop = asyncio.get_running_loop()
        with self._lock:
            done = self._ready.pop(request_id, None)
            if done is not None:
                # Регистрируют из цикла событий, поэтому фьючерс можно
                # выполнить прямо здесь, без call_soon_threadsafe.
                future.set_result(done)
                return
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
            self._ready.pop(request_id, None)

    def _reap(self) -> None:
        while True:
            with self._lock:
                if self._stop or not (self._waiters or self._ready):
                    self._thread = None
                    return
            rid = int(_lib.curlpro_result_wait(_WAIT_MS))
            if rid == 0:
                continue
            with self._lock:
                entry = self._waiters.pop(rid, None)
                if entry is None:
                    # Ожидающего ещё нет. Работа стартует и регистрируется
                    # двумя шагами, и быстрая — чтение части тела — успевает
                    # закончиться между ними. Результат откладывается,
                    # его заберёт register.
                    #
                    # Раньше он здесь выбрасывался, и такой запрос повисал
                    # навсегда: 24 одновременных потоковых чтения теряли одно.
                    #
                    # Забираем под тем же замком: иначе register вклинивается
                    # между проверкой и откладыванием, и ожидающий с готовым
                    # результатом расходятся навсегда.
                    #
                    # Отменённый результат сюда не попадает: отмена снимает
                    # запрос с учёта в нативной части, и забрать его уже нечем.
                    done = _take(rid)
                    if done is not None:
                        self._ready[rid] = done
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


async def settle(started: dict) -> tuple[Any, bytes]:
    """Ждёт результат уже запущенной работы: запроса, чтения, приёма.

    Отмена задачи снимает ожидание и отменяет работу в нативной части.
    Для запроса это освобождает соединение сразу; для чтения из потока
    и приёма сообщения отменять нечего — то, что уже снято с провода,
    теряется, поэтому после отмены поток или сокет закрывают.
    """
    request_id = int(started["request"])
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    completions.register(request_id, future)
    try:
        return await future
    except asyncio.CancelledError:
        completions.forget(request_id)
        _call("curlpro_request_cancel", request_id)
        raise
