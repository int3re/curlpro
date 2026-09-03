"""WebSocket поверх того же TLS-соединения, что и обычные запросы.

Рукопожатие — обычный HTTP/1.1-запрос с Upgrade, поэтому его заголовки тоже
часть отпечатка: они собираются по шаблону профиля браузера (секция
``websocket``), а не из навигационного набора. Расширение permessage-deflate
объявляется и поддерживается: сжатые сообщения распаковываются, исходящие
сжимаются, если сервер расширение принял.

    with curlpro.Session("chrome-151-windows") as s:
        with s.websocket("wss://echo.websocket.org/") as ws:
            ws.send("привет")
            print(ws.recv())
"""

from __future__ import annotations

from typing import Iterable, Iterator, Mapping

from ._ffi import WebSocketClosed, _call, call_framed, call_framed_out, encode


class WebSocket:
    """Установленное WebSocket-соединение.

    Соединение держится до закрытия, поэтому пользоваться следует через ``with``.
    """

    __slots__ = ("_id", "_closed")

    def __init__(self, socket_id: int):
        self._id = socket_id
        self._closed = False

    def send(self, data: str | bytes) -> None:
        """Отправляет сообщение. Тип кадра выбирается по типу данных."""
        self._check()
        binary = not isinstance(data, str)
        payload = data if binary else data.encode("utf-8")
        call_framed("curlpro_ws_send", self._id, body=payload,
                    meta={"binary": binary, "ping": False})

    def ping(self, data: bytes = b"") -> None:
        """Отправляет ping. Ответный pong обрабатывается внутри recv."""
        self._check()
        call_framed("curlpro_ws_send", self._id, body=data,
                    meta={"binary": True, "ping": True})

    def recv(self) -> str | bytes:
        """Читает следующее сообщение.

        Текстовые кадры возвращаются как ``str``, двоичные — как ``bytes``:
        на проводе это разные опкоды, и сервер вправе их различать.

        Закрытие соединения сервером — :class:`WebSocketClosed`; таймаут
        чтения (``timeout`` секунд тишины) — :class:`CurlProError`
        с ``code == "timeout"``, соединение при этом живо и читать можно дальше.
        """
        self._check()
        meta, data = call_framed_out("curlpro_ws_recv", self._id)
        return data if (meta or {}).get("binary") else data.decode("utf-8")

    def __iter__(self) -> Iterator[str | bytes]:
        """Читает сообщения, пока соединение не закроется.

        Останавливается только на закрытии. Раньше здесь глотался любой сбой,
        и тридцать секунд тишины на живом соединении выглядели как штатный
        конец — теперь таймаут и ошибки протокола доходят до вызывающего.
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
            raise RuntimeError("сокет закрыт")

    def __enter__(self) -> "WebSocket":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Незакрытый сокет удерживает соединение на стороне Go.
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        state = "закрыт" if self._closed else "открыт"
        return f"<WebSocket {self._id} {state}>"


def connect(
    session_id: int,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    subprotocols: Iterable[str] | None = None,
    timeout: float = 30.0,
    max_message_size: int = 0,
) -> WebSocket:
    data = _call(
        "curlpro_ws_connect",
        session_id,
        encode(
            {
                "url": url,
                "headers": dict(headers or {}),
                "subprotocols": list(subprotocols or []),
                "timeout_ms": int(timeout * 1000),
                # Ноль — умолчание нативной части (64 МиБ). Предел нужен:
                # длину кадра называет сервер.
                "max_message_size": int(max_message_size),
            }
        ),
    )
    return WebSocket(data["socket"])
