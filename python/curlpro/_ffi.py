"""Loading the native library and calling it through ctypes.

Every export returns a char* holding a JSON envelope
``{"ok":…, "error":…, "code":…, "data":…}``. That string is allocated in C and
must be released with ``curlpro_free`` or it leaks. :func:`_call` does the
releasing, which is why no pointer ever escapes this module.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any


class CurlProError(RuntimeError):
    """An error raised by the native part.

    ``code`` is the machine-readable code when the native side knows one:
    ``timeout``, ``session_closed``, ``too_large``, ``ws_closed``,
    ``ws_too_big``, ``ws_protocol``. Never branch on the message text — it is
    for humans.
    """

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


class Timeout(CurlProError):
    """The request ran out of time.

    A class of its own because a timeout is the one outcome a scraper treats
    differently from other network errors: it retries it.
    """


class HTTPError(CurlProError):
    """A response with an error status; raised by :meth:`Response.raise_for_status`.

    That method used to raise a bare RuntimeError, indistinguishable from an
    internal failure. ``response`` stays attached: an error response usually
    carries a body, and that body is the reason to look at it.
    """

    def __init__(self, message: str, response=None, code: str | None = None):  # noqa: ANN001
        super().__init__(message, code)
        self.response = response
        self.status = getattr(response, "status", None)


class WebSocketClosed(CurlProError):
    """The WebSocket is closed: by the server's Close frame or by the caller.

    A class of its own so that ``for message in ws`` stops on a close only,
    while read timeouts and protocol errors reach the caller.
    """


def _raise(envelope: dict, name: str) -> None:
    code = envelope.get("code")
    message = envelope.get("error") or f"{name}: unknown error"
    if code == "ws_closed":
        raise WebSocketClosed(message, code)
    if code == "timeout":
        raise Timeout(message, code)
    raise CurlProError(message, code)


def _library_name() -> str:
    system = platform.system()
    if system == "Windows":
        return "curlpro.dll"
    if system == "Darwin":
        return "libcurlpro.dylib"
    return "libcurlpro.so"


def _candidates() -> list[Path]:
    """Where the library is looked for, from an explicit path to a source build."""
    name = _library_name()
    out: list[Path] = []
    if env := os.environ.get("CURLPRO_LIBRARY"):
        out.append(Path(env))
    here = Path(__file__).resolve().parent
    out.append(here / "lib" / name)          # packed into the wheel
    out.append(here.parent.parent / "dist" / name)  # a build from the repository
    return out


def _load() -> ctypes.CDLL:
    tried = []
    for path in _candidates():
        if path.is_file():
            return ctypes.CDLL(str(path))
        tried.append(str(path))
    raise CurlProError(
        "native library not found. Looked in:\n  "
        + "\n  ".join(tried)
        + "\nBuild it: go build -buildmode=c-shared -o dist/"
        + _library_name()
        + " ./lib\n"
        + "or point CURLPRO_LIBRARY at an existing build"
    )


_lib = _load()

_lib.curlpro_free.argtypes = [ctypes.c_void_p]
_lib.curlpro_free.restype = None

for _name, _args in (
    ("curlpro_version", []),
    ("curlpro_profiles_list", []),
    ("curlpro_profiles_load_dir", [ctypes.c_char_p]),
    ("curlpro_profile_register", [ctypes.c_char_p]),
    ("curlpro_session_new", [ctypes.c_char_p]),
    ("curlpro_session_close", [ctypes.c_longlong]),
    (
        "curlpro_request",
        [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)],
    ),
    (
        "curlpro_stream_open",
        [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)],
    ),
    ("curlpro_stream_close", [ctypes.c_longlong]),
    ("curlpro_ws_connect", [ctypes.c_longlong, ctypes.c_char_p]),
    (
        "curlpro_ws_send",
        [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)],
    ),
    ("curlpro_ws_recv", [ctypes.c_longlong, ctypes.POINTER(ctypes.c_int)]),
    ("curlpro_ws_close", [ctypes.c_longlong, ctypes.c_int, ctypes.c_char_p]),
    ("curlpro_session_set_header", [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_char_p]),
    ("curlpro_session_remove_header", [ctypes.c_longlong, ctypes.c_char_p]),
    ("curlpro_session_reset_headers", [ctypes.c_longlong]),
    ("curlpro_session_headers", [ctypes.c_longlong]),
    ("curlpro_session_cookies", [ctypes.c_longlong]),
    ("curlpro_session_set_cookies", [ctypes.c_longlong, ctypes.c_char_p]),
    ("curlpro_session_clear_cookies", [ctypes.c_longlong]),
    ("curlpro_request_start", [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int]),
    ("curlpro_stream_open_start", [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int]),
    ("curlpro_stream_read_start", [ctypes.c_longlong, ctypes.c_int]),
    ("curlpro_ws_connect_start", [ctypes.c_longlong, ctypes.c_char_p]),
    ("curlpro_ws_send_start", [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int]),
    ("curlpro_ws_recv_start", [ctypes.c_longlong]),
    ("curlpro_result_take", [ctypes.c_longlong, ctypes.POINTER(ctypes.c_int)]),
    ("curlpro_request_cancel", [ctypes.c_longlong]),
    ("curlpro_debug_counts", []),
):
    try:
        _fn = getattr(_lib, _name)
    except AttributeError:
        raise CurlProError(
            f"the library exports no {_name}: it was built from an older revision.\n"
            f"Rebuild it: .\\build.ps1 (writes to dist/)"
        ) from None
    _fn.argtypes = _args
    # c_void_p and not c_char_p: ctypes converts c_char_p into bytes and
    # loses the original pointer, which curlpro_free needs.
    _fn.restype = ctypes.c_void_p

# Waiting for completions and counting in-flight calls return numbers, not
# pointers. ctypes performs the blocking wait with the GIL released, and the
# async path stands on that: the collector thread waits without blocking the
# event loop.
_lib.curlpro_result_wait.argtypes = [ctypes.c_int]
_lib.curlpro_result_wait.restype = ctypes.c_longlong
_lib.curlpro_async_pending.argtypes = []
_lib.curlpro_async_pending.restype = ctypes.c_longlong

# read returns a byte count, not a pointer: the caller owns the buffer.
_lib.curlpro_stream_read.argtypes = [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int]
_lib.curlpro_stream_read.restype = ctypes.c_int


def stream_read(stream_id: int, size: int) -> bytes:
    """Reads up to size bytes. An empty result means the body ended."""
    buf = ctypes.create_string_buffer(size)
    n = _lib.curlpro_stream_read(stream_id, buf, size)
    if n < 0:
        raise CurlProError("stream read failed")
    return buf.raw[:n]


def _call(name: str, *args: Any) -> Any:
    """Calls an export, unwraps the envelope and frees the C string."""
    ptr = getattr(_lib, name)(*args)
    if not ptr:
        raise CurlProError(f"{name}: the native side returned NULL")
    try:
        raw = ctypes.string_at(ptr).decode("utf-8")
    finally:
        _lib.curlpro_free(ptr)

    envelope = json.loads(raw)
    if not envelope.get("ok"):
        _raise(envelope, name)
    return envelope.get("data")


# Minimum version of the native part: major and minor. Raise it together
# with lib/curlpro.go whenever Python starts depending on a new export or field.
REQUIRED_VERSION = (0, 12)


def _check_version() -> None:
    """Checks the library version against what this Python expects.

    Without the check a mismatch is silent: both sides tolerate unknown JSON
    fields, so an older library quietly ignores new options — the request
    goes out without them, and that looks like a logic bug rather than a
    stale build.
    """
    raw = _call("curlpro_version").get("version", "")
    try:
        got = tuple(int(p) for p in raw.split(".")[:2])
    except ValueError:
        raise CurlProError(f"the library reported an unreadable version {raw!r}") from None

    if got < REQUIRED_VERSION:
        want = ".".join(str(p) for p in REQUIRED_VERSION)
        raise CurlProError(
            f"library version {raw} is older than the required {want}.x, "
            f"so some options would be silently ignored.\n"
            f"Rebuild it: .\\build.ps1 (writes to dist/)"
        )


_check_version()


# Request and response bodies travel as binary, separate from the JSON.
#
# As a string inside JSON they were not merely copied one extra time:
# arbitrary bytes are not valid UTF-8, so the response was corrupted — 10,000
# random bytes came back as 18,502 after the round trip.
#
# Frame layout: [uint32 LE JSON length][JSON][raw body].
_HEADER = 4


def _frame(meta: Any, body: bytes = b"") -> bytes:
    js = encode(meta)
    return len(js).to_bytes(_HEADER, "little") + js + body


def _unframe(name: str, raw: bytes) -> tuple[Any, bytes]:
    if len(raw) < _HEADER:
        raise CurlProError(f"{name}: frame is shorter than its header ({len(raw)} bytes)")
    meta_len = int.from_bytes(raw[:_HEADER], "little")
    envelope = json.loads(raw[_HEADER : _HEADER + meta_len])
    if not envelope.get("ok"):
        _raise(envelope, name)
    return envelope.get("data"), raw[_HEADER + meta_len :]


def call_framed(name: str, *args: Any, body: bytes = b"", meta: Any) -> tuple[Any, bytes]:
    """Calls an export with frames and returns (data, body)."""
    payload = _frame(meta, body)
    out_len = ctypes.c_int(0)
    ptr = getattr(_lib, name)(*args, payload, len(payload), ctypes.byref(out_len))
    if not ptr:
        raise CurlProError(f"{name}: the native side returned NULL")
    try:
        raw = ctypes.string_at(ptr, out_len.value)
    finally:
        _lib.curlpro_free(ptr)
    return _unframe(name, raw)


def call_with_frame(name: str, *args: Any, body: bytes = b"", meta: Any) -> Any:
    """A frame going in, a plain JSON envelope coming back.

    This is how an async request starts: the body goes out as a frame, and
    all that returns is the request number — there is no response yet.
    """
    payload = _frame(meta, body)
    return _call(name, *args, payload, len(payload))


def call_framed_out(name: str, *args: Any) -> tuple[Any, bytes]:
    """Like call_framed but without an input frame — for recv-style calls."""
    out_len = ctypes.c_int(0)
    ptr = getattr(_lib, name)(*args, ctypes.byref(out_len))
    if not ptr:
        raise CurlProError(f"{name}: the native side returned NULL")
    try:
        raw = ctypes.string_at(ptr, out_len.value)
    finally:
        _lib.curlpro_free(ptr)
    return _unframe(name, raw)


def encode(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")
