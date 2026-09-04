"""Потоковое чтение тела ответа.

Обычный запрос материализует тело целиком; для больших загрузок это лишняя
память и задержка до первого байта. Поток отдаёт тело частями, но удерживает
соединение до закрытия — поэтому пользоваться им следует через ``with``.
"""

from __future__ import annotations

from typing import Iterator

from ._ffi import _call, stream_read

DEFAULT_CHUNK = 64 * 1024


def lines_from(buffer: bytes, chunk: bytes, keepends: bool) -> tuple[bytes, list[bytes]]:
    """Достаёт из накопленного готовые строки и возвращает остаток.

    Общая для обычного и асинхронного чтения: разойтись двум копиям здесь
    легко — например, на переводе строки, попавшем на границу частей.
    """
    buffer += chunk
    lines: list[bytes] = []
    while True:
        line, sep, rest = buffer.partition(b"\n")
        if not sep:
            return buffer, lines
        buffer = rest
        lines.append(line + sep if keepends else line.rstrip(b"\r"))


class StreamResponse:
    """Ответ с телом, читаемым по частям.

        with session.stream("GET", url) as r:
            for chunk in r.iter_content():
                out.write(chunk)
    """

    __slots__ = ("status", "proto", "headers", "url", "_id", "_closed")

    def __init__(self, payload: dict):
        self.status: int = payload["status"]
        self.proto: str = payload.get("proto", "")
        self.headers: dict[str, list[str]] = payload.get("headers") or {}
        self.url: str = payload.get("url", "")
        self._id: int = payload["stream"]
        self._closed = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def iter_lines(self, chunk_size: int = DEFAULT_CHUNK,
                   keepends: bool = False) -> Iterator[bytes]:
        """Тело построчно, не собирая его целиком.

        Нужно для потоков вида NDJSON, где ответ бесконечен по смыслу
        и материализовать его нельзя. Разделителем считается перевод
        строки; последняя строка отдаётся даже без него.
        """
        buffer = b""
        for chunk in self.iter_content(chunk_size):
            buffer, lines = lines_from(buffer, chunk, keepends)
            yield from lines
        if buffer:
            yield buffer

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, values in self.headers.items():
            if key.lower() == lowered and values:
                return values[0]
        return None

    def iter_content(self, chunk_size: int = DEFAULT_CHUNK) -> Iterator[bytes]:
        """Отдаёт тело частями до конца."""
        if chunk_size <= 0:
            raise ValueError("chunk_size должен быть положительным")
        while True:
            chunk = stream_read(self._id, chunk_size)
            if not chunk:
                return
            yield chunk

    def read(self) -> bytes:
        """Дочитывает тело целиком. Удобно, когда поток открыт зря."""
        return b"".join(self.iter_content())

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _call("curlpro_stream_close", self._id)

    def __enter__(self) -> "StreamResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Незакрытый поток удерживает соединение на стороне Go.
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"<StreamResponse {self.status} {self.proto} поток {self._id}>"
