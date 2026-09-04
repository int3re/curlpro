"""Загрузка нативной библиотеки и низкоуровневый вызов через ctypes.

Все экспорты возвращают char* с JSON-конвертом ``{"ok":…, "error":…, "code":…, "data":…}``.
Строка выделена в C и обязана быть освобождена через ``curlpro_free`` — иначе течь.
Освобождение делает :func:`_call`, поэтому наружу указатели не выдаются.
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
    """Ошибка, пришедшая из нативной части.

    ``code`` — машинный код, когда нативная часть его знает: ``timeout``,
    ``session_closed``, ``ws_closed``, ``ws_too_big``, ``ws_protocol``.
    По тексту ошибки исходы различать нельзя: он для человека.
    """

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


class Timeout(CurlProError):
    """Истёк предел на запрос.

    Отдельным классом, потому что таймаут — единственный исход, который
    в парсере обрабатывают иначе, чем прочие сетевые ошибки: его повторяют.
    """


class HTTPError(CurlProError):
    """Ответ со статусом ошибки; поднимает :meth:`Response.raise_for_status`.

    Раньше там поднимался голый RuntimeError, и отличить его от внутренней
    поломки было нельзя. ``response`` остаётся под рукой: у ответа с ошибкой
    обычно есть тело, ради которого его и разбирают.
    """

    def __init__(self, message: str, response=None, code: str | None = None):  # noqa: ANN001
        super().__init__(message, code)
        self.response = response
        self.status = getattr(response, "status", None)


class WebSocketClosed(CurlProError):
    """WebSocket закрыт: сервером кадром Close либо вызывающим.

    Отдельный класс, чтобы ``for message in ws`` останавливался только на
    закрытии, а таймаут чтения или ошибка протокола доходили до вызывающего.
    """


def _raise(envelope: dict, name: str) -> None:
    code = envelope.get("code")
    message = envelope.get("error") or f"{name}: неизвестная ошибка"
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
    """Пути поиска библиотеки, от явного указания к сборке из исходников."""
    name = _library_name()
    out: list[Path] = []
    if env := os.environ.get("CURLPRO_LIBRARY"):
        out.append(Path(env))
    here = Path(__file__).resolve().parent
    out.append(here / "lib" / name)          # уложена в wheel
    out.append(here.parent.parent / "dist" / name)  # сборка из репозитория
    return out


def _load() -> ctypes.CDLL:
    tried = []
    for path in _candidates():
        if path.is_file():
            return ctypes.CDLL(str(path))
        tried.append(str(path))
    raise CurlProError(
        "нативная библиотека не найдена. Искали:\n  "
        + "\n  ".join(tried)
        + "\nСоберите её: go build -buildmode=c-shared -o dist/"
        + _library_name()
        + " ./lib\n"
        + "или укажите путь в переменной окружения CURLPRO_LIBRARY"
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
    ("curlpro_result_take", [ctypes.c_longlong, ctypes.POINTER(ctypes.c_int)]),
    ("curlpro_request_cancel", [ctypes.c_longlong]),
):
    try:
        _fn = getattr(_lib, _name)
    except AttributeError:
        raise CurlProError(
            f"в библиотеке нет экспорта {_name}: она собрана из старой ревизии.\n"
            f"Пересоберите: .\\build.ps1 (кладёт в dist/)"
        ) from None
    _fn.argtypes = _args
    # Именно c_void_p, а не c_char_p: ctypes конвертирует c_char_p в bytes
    # и теряет исходный указатель, который нужен для curlpro_free.
    _fn.restype = ctypes.c_void_p

# Ожидание завершений и счётчик в полёте возвращают числа, а не указатели.
# Блокирующее ожидание ctypes выполняет с отпущенным GIL — на этом и стоит
# асинхронный путь: поток-приёмник ждёт, не мешая циклу событий.
_lib.curlpro_result_wait.argtypes = [ctypes.c_int]
_lib.curlpro_result_wait.restype = ctypes.c_longlong
_lib.curlpro_async_pending.argtypes = []
_lib.curlpro_async_pending.restype = ctypes.c_longlong

# read возвращает число байт, а не указатель: буфер выделяет вызывающий.
_lib.curlpro_stream_read.argtypes = [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int]
_lib.curlpro_stream_read.restype = ctypes.c_int


def stream_read(stream_id: int, size: int) -> bytes:
    """Читает до size байт. Пустой результат означает конец тела."""
    buf = ctypes.create_string_buffer(size)
    n = _lib.curlpro_stream_read(stream_id, buf, size)
    if n < 0:
        raise CurlProError("ошибка чтения потока")
    return buf.raw[:n]


def _call(name: str, *args: Any) -> Any:
    """Вызывает экспорт, разбирает конверт и освобождает C-строку."""
    ptr = getattr(_lib, name)(*args)
    if not ptr:
        raise CurlProError(f"{name}: нативная часть вернула NULL")
    try:
        raw = ctypes.string_at(ptr).decode("utf-8")
    finally:
        _lib.curlpro_free(ptr)

    envelope = json.loads(raw)
    if not envelope.get("ok"):
        _raise(envelope, name)
    return envelope.get("data")


# Минимальная версия нативной части: мажор и минор. Поднимать вместе
# с lib/curlpro.go, когда Python начинает зависеть от нового экспорта или поля.
REQUIRED_VERSION = (0, 8)


def _check_version() -> None:
    """Сверяет версию библиотеки с той, на которую рассчитан этот Python.

    Без проверки рассинхрон нем: обе стороны переживают незнакомые поля JSON,
    поэтому старая библиотека молча игнорирует новые опции — запрос уходит
    без них, и это выглядит как ошибка логики, а не как устаревшая сборка.
    """
    raw = _call("curlpro_version").get("version", "")
    try:
        got = tuple(int(p) for p in raw.split(".")[:2])
    except ValueError:
        raise CurlProError(f"библиотека вернула нечитаемую версию {raw!r}") from None

    if got < REQUIRED_VERSION:
        want = ".".join(str(p) for p in REQUIRED_VERSION)
        raise CurlProError(
            f"библиотека версии {raw} старее требуемой {want}.x — "
            f"часть опций она молча проигнорирует.\n"
            f"Пересоберите: .\\build.ps1 (кладёт в dist/)"
        )


_check_version()


# Тела запросов и ответов ходят бинарно, отдельно от JSON.
#
# Строкой внутри JSON они не только копировались лишний раз: произвольные байты
# не являются валидным UTF-8, поэтому ответ портился — 10 000 случайных байт
# возвращались как 18 502 после перекодировки.
#
# Формат кадра: [uint32 LE длина JSON][JSON][сырое тело].
_HEADER = 4


def _frame(meta: Any, body: bytes = b"") -> bytes:
    js = encode(meta)
    return len(js).to_bytes(_HEADER, "little") + js + body


def _unframe(name: str, raw: bytes) -> tuple[Any, bytes]:
    if len(raw) < _HEADER:
        raise CurlProError(f"{name}: кадр короче заголовка ({len(raw)} байт)")
    meta_len = int.from_bytes(raw[:_HEADER], "little")
    envelope = json.loads(raw[_HEADER : _HEADER + meta_len])
    if not envelope.get("ok"):
        _raise(envelope, name)
    return envelope.get("data"), raw[_HEADER + meta_len :]


def call_framed(name: str, *args: Any, body: bytes = b"", meta: Any) -> tuple[Any, bytes]:
    """Вызывает экспорт кадрами и возвращает (данные, тело)."""
    payload = _frame(meta, body)
    out_len = ctypes.c_int(0)
    ptr = getattr(_lib, name)(*args, payload, len(payload), ctypes.byref(out_len))
    if not ptr:
        raise CurlProError(f"{name}: нативная часть вернула NULL")
    try:
        raw = ctypes.string_at(ptr, out_len.value)
    finally:
        _lib.curlpro_free(ptr)
    return _unframe(name, raw)


def call_with_frame(name: str, *args: Any, body: bytes = b"", meta: Any) -> Any:
    """Кадр на входе, обычный конверт JSON на выходе.

    Так устроен запуск асинхронного запроса: тело уходит кадром, а обратно
    приходит только номер запроса — ответа ещё нет.
    """
    payload = _frame(meta, body)
    return _call(name, *args, payload, len(payload))


def call_framed_out(name: str, *args: Any) -> tuple[Any, bytes]:
    """Как call_framed, но без входного кадра — для вызовов вида recv."""
    out_len = ctypes.c_int(0)
    ptr = getattr(_lib, name)(*args, ctypes.byref(out_len))
    if not ptr:
        raise CurlProError(f"{name}: нативная часть вернула NULL")
    try:
        raw = ctypes.string_at(ptr, out_len.value)
    finally:
        _lib.curlpro_free(ptr)
    return _unframe(name, raw)


def encode(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")
