"""Загрузка нативной библиотеки и низкоуровневый вызов через ctypes.

Все экспорты возвращают char* с JSON-конвертом ``{"ok":…, "error":…, "data":…}``.
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
    """Ошибка, пришедшая из нативной части."""


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
):
    _fn = getattr(_lib, _name)
    _fn.argtypes = _args
    # Именно c_void_p, а не c_char_p: ctypes конвертирует c_char_p в bytes
    # и теряет исходный указатель, который нужен для curlpro_free.
    _fn.restype = ctypes.c_void_p

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
        raise CurlProError(envelope.get("error") or f"{name}: неизвестная ошибка")
    return envelope.get("data")


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

    if len(raw) < _HEADER:
        raise CurlProError(f"{name}: кадр короче заголовка ({len(raw)} байт)")
    meta_len = int.from_bytes(raw[:_HEADER], "little")
    envelope = json.loads(raw[_HEADER : _HEADER + meta_len])
    if not envelope.get("ok"):
        raise CurlProError(envelope.get("error") or f"{name}: неизвестная ошибка")
    return envelope.get("data"), raw[_HEADER + meta_len :]


def encode(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")
