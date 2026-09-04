"""Collector of finished native calls.

An async request goes into a goroutine, and Python learns that it finished
from here. There is exactly one thread per process, no matter how many calls
are in flight: it waits inside the native part, where ctypes releases the
GIL, so the event loop keeps running.

The result itself is picked up by the event loop — that call is quick, just a
memory copy. Reaching into a loop from another thread is only allowed through
call_soon_threadsafe, and that is how the future is woken.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from ._ffi import _call, _lib, call_framed_out

# How long a single wait inside the native part lasts. Waking up four times a
# second while idle costs nothing, and the thread exits almost immediately
# once nobody uses it any more.
_WAIT_MS = 250


class Completions:
    """The single per-process collector of results."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._waiters: dict[int, tuple[asyncio.AbstractEventLoop, asyncio.Future]] = {}
        # Results that arrived before their waiter: the work can finish
        # between the start call and register — routine for a stream read,
        # which takes microseconds.
        self._ready: dict[int, tuple[Any, bytes]] = {}
        self._thread: threading.Thread | None = None
        self._stop = False

    def register(self, request_id: int, future: asyncio.Future) -> None:
        loop = asyncio.get_running_loop()
        with self._lock:
            done = self._ready.pop(request_id, None)
            if done is not None:
                # Registration happens on the event loop, so the future can
                # be completed right here, without call_soon_threadsafe.
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
        """Drops the wait: the call was cancelled and nobody needs its result."""
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
                    # No waiter yet. Work is started and registered in two
                    # steps, and a fast one — reading a chunk of the body —
                    # can finish in between. The result is set aside for
                    # register to pick up.
                    #
                    # It used to be thrown away here, and such a call hung
                    # forever: 24 concurrent stream reads lost one of them.
                    #
                    # It is taken under the same lock: otherwise register
                    # slips between the check and the hand-off, and the
                    # waiter and its ready result never meet again.
                    #
                    # A cancelled result never lands here: cancelling removes
                    # the call from the native registry, leaving nothing to take.
                    done = _take(rid)
                    if done is not None:
                        self._ready[rid] = done
                    continue
            loop, future = entry
            try:
                loop.call_soon_threadsafe(_settle, future, rid)
            except RuntimeError:
                # The event loop is already closed — nobody to hand it to.
                _take(rid)


def _take(request_id: int) -> tuple[Any, bytes] | None:
    try:
        return call_framed_out("curlpro_result_take", request_id)
    except Exception:  # noqa: BLE001 — already taken, or the session is closed
        return None


def _settle(future: asyncio.Future, request_id: int) -> None:
    """Runs on the event loop: takes the result and wakes the waiter."""
    if future.done():  # the task was cancelled while the result was on its way
        _take(request_id)
        return
    try:
        payload, content = call_framed_out("curlpro_result_take", request_id)
    except BaseException as exc:  # noqa: BLE001 — hand the error to the waiter
        future.set_exception(exc)
        return
    future.set_result((payload, content))


#: One instance per process: the native ready queue is single too.
completions = Completions()


async def settle(started: dict) -> tuple[Any, bytes]:
    """Awaits the result of work already started: a request, a read, a receive.

    Cancelling the task drops the wait and cancels the work natively. For a
    request that frees the connection at once; for a stream read or a message
    receive there is nothing to cancel — whatever was taken off the wire is
    lost, which is why the stream or socket is closed after a cancellation.
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
