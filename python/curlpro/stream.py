"""Streaming reads of the response body.

An ordinary request materialises the whole body; for large downloads that is
wasted memory and a delay before the first byte. A stream hands the body over
in chunks but holds the connection until it is closed — hence ``with``.
"""

from __future__ import annotations

from typing import Iterator

from ._ffi import _call, stream_read

DEFAULT_CHUNK = 64 * 1024


def lines_from(buffer: bytes, chunk: bytes, keepends: bool) -> tuple[bytes, list[bytes]]:
    """Pulls complete lines out of what has accumulated, returns the rest.

    Shared by the sync and async readers: two copies would drift apart
    easily — on a newline landing exactly on a chunk boundary, say.
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
    """A response whose body is read in chunks.

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
        """The body line by line, without collecting it whole.

        Needed for NDJSON-style streams, where the response is endless by
        design and cannot be materialised. The separator is the newline;
        the last line is yielded even without one.
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
        """Yields the body in chunks until it ends."""
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        while True:
            chunk = stream_read(self._id, chunk_size)
            if not chunk:
                return
            yield chunk

    def read(self) -> bytes:
        """Reads the rest of the body. Handy when the stream was opened in vain."""
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
        # An unclosed stream holds a connection on the Go side.
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"<StreamResponse {self.status} {self.proto} stream {self._id}>"
