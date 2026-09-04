"""WebSocket over the same kind of TLS connection as ordinary requests.

The handshake is a plain HTTP/1.1 request with Upgrade, so its headers are
part of the fingerprint too: they are built from the profile's ``websocket``
template rather than from the navigation set. The permessage-deflate
extension is advertised and supported: incoming messages are inflated and
outgoing ones are compressed when the server accepted the extension.

    with curlpro.Session("chrome-151-windows") as s:
        with s.websocket("wss://echo.websocket.org/") as ws:
            ws.send("hello")
            print(ws.recv())
"""

from __future__ import annotations

from typing import Iterable, Iterator, Mapping

from ._ffi import WebSocketClosed, _call, call_framed, call_framed_out, encode
from .timeouts import split_timeout as _split_timeout


class WebSocket:
    """An established WebSocket connection.

    The connection is held until it is closed, so use it through ``with``.
    """

    __slots__ = ("_id", "_closed")

    def __init__(self, socket_id: int):
        self._id = socket_id
        self._closed = False

    def send(self, data: str | bytes) -> None:
        """Sends a message. The frame type follows the type of the data."""
        self._check()
        binary = not isinstance(data, str)
        payload = data if binary else data.encode("utf-8")
        call_framed("curlpro_ws_send", self._id, body=payload,
                    meta={"binary": binary, "ping": False})

    def ping(self, data: bytes = b"") -> None:
        """Sends a ping. The matching pong is handled inside recv."""
        self._check()
        call_framed("curlpro_ws_send", self._id, body=data,
                    meta={"binary": True, "ping": True})

    def recv(self) -> str | bytes:
        """Reads the next message.

        Text frames come back as ``str`` and binary ones as ``bytes``: on
        the wire these are different opcodes, and a server is free to tell
        them apart.

        A close from the server raises :class:`WebSocketClosed`; a read
        timeout (``timeout`` seconds of silence) raises :class:`CurlProError`
        with ``code == "timeout"``, and the connection stays alive so
        reading can continue.
        """
        self._check()
        meta, data = call_framed_out("curlpro_ws_recv", self._id)
        return data if (meta or {}).get("binary") else data.decode("utf-8")

    def __iter__(self) -> Iterator[str | bytes]:
        """Reads messages until the connection closes.

        It stops on a close and nothing else. This used to swallow every
        failure, so thirty seconds of silence on a healthy connection looked
        like a normal end; now timeouts and protocol errors reach the caller.
        """
        while True:
            try:
                yield self.recv()
            except WebSocketClosed:
                return

    def close(self, code: int = 1000, reason: str = "") -> None:
        if not self._closed:
            self._closed = True
            _call("curlpro_ws_close", self._id, code, reason.encode("utf-8"))

    def _check(self) -> None:
        if self._closed:
            raise RuntimeError("socket is closed")

    def __enter__(self) -> "WebSocket":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # An unclosed socket holds a connection on the Go side.
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"<WebSocket {self._id} {state}>"


def connect(
    session_id: int,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    subprotocols: Iterable[str] | None = None,
    timeout: float | tuple[float, float] = 30.0,
    max_message_size: int = 0,
) -> WebSocket:
    connect_timeout, timeout = _split_timeout(timeout)
    data = _call(
        "curlpro_ws_connect",
        session_id,
        encode(
            {
                "url": url,
                "headers": dict(headers or {}),
                "subprotocols": list(subprotocols or []),
                "timeout_ms": int(timeout * 1000) if timeout else 0,
                "connect_timeout_ms":
                    int(connect_timeout * 1000) if connect_timeout else 0,
                # Zero means the native default (64 MiB). A limit is needed
                # because the frame length is whatever the server says.
                "max_message_size": int(max_message_size),
            }
        ),
    )
    return WebSocket(data["socket"])
