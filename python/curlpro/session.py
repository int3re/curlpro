"""Сессия и функции уровня модуля в стиле requests."""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from ._ffi import _call, call_framed, encode
from .profiles import ensure_loaded
from .stream import StreamResponse

DEFAULT_PROFILE = "chrome-151-windows"


def _build_multipart(
    fields: Mapping[str, str] | None,
    files: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bytes]:
    """Готовит описание формы и склеенное содержимое файлов.

    Границу формы генерирует нативная часть в стиле профиля: её вид отличает
    Chrome от Firefox и потому относится к отпечатку, а не к деталям кодирования.

    Значение ``files`` — либо ``bytes``, либо кортеж
    ``(filename, content)`` / ``(filename, content, content_type)``.
    """
    fields = dict(fields or {})
    described: list[dict[str, str]] = []
    sizes: list[int] = []
    blob = bytearray()

    for field, value in (files or {}).items():
        content_type = ""
        if isinstance(value, (bytes, bytearray)):
            filename, content = field, bytes(value)
        elif isinstance(value, tuple):
            if len(value) == 2:
                filename, content = value
            elif len(value) == 3:
                filename, content, content_type = value
            else:
                raise ValueError(f"files[{field!r}]: ожидался кортеж из 2 или 3 элементов")
        else:
            raise TypeError(f"files[{field!r}]: ожидались bytes или кортеж")

        if isinstance(content, str):
            content = content.encode("utf-8")
        described.append(
            {"field": field, "filename": filename, "content_type": content_type}
        )
        sizes.append(len(content))
        blob += content

    meta = {
        "fields": fields,
        "order": list(fields),
        "files": described,
        "file_sizes": sizes,
    }
    return meta, bytes(blob)


class Response:
    """Ответ сервера."""

    __slots__ = ("status", "proto", "headers", "content", "url")

    def __init__(self, status: int, proto: str, headers: dict[str, list[str]],
                 content: bytes, url: str = ""):
        self.status = status
        self.proto = proto
        self.headers = headers
        self.content = content
        self.url = url

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.content)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def raise_for_status(self) -> "Response":
        if not self.ok:
            raise RuntimeError(f"HTTP {self.status} для {self.url}")
        return self

    def header(self, name: str) -> str | None:
        """Первое значение заголовка без учёта регистра."""
        lowered = name.lower()
        for key, values in self.headers.items():
            if key.lower() == lowered and values:
                return values[0]
        return None

    def __repr__(self) -> str:
        return f"<Response {self.status} {self.proto} {len(self.content)}b>"


class Session:
    """Сессия с одним профилем и переиспользованием соединений.

    :param impersonate: имя профиля
    :param verify: проверять сертификат сервера
    :param timeout: предел на запрос целиком, включая редиректы, в секундах
    :param proxy: ``http://``, ``https://`` или ``socks5://``, можно с user:pass
    :param default_headers: подставлять заголовки профиля. Выключите, чтобы
        полностью управлять набором и порядком самостоятельно — анти-боты
        смотрят и на порядок
    :param header_order: желаемый порядок заголовков; не перечисленные идут
        следом, сохраняя относительный порядок
    :param allow_redirects: переходить по 3xx
    :param max_redirects: предел длины цепочки
    :param cookies: включить cookie-jar, общий для запросов сессии
    :param force_http1: не предлагать h2, даже если профиль его содержит
    :param http3: отправлять запросы по QUIC вместо TCP. Профиль обязан
        описывать секцию ``http3``, иначе сессия не создастся. Это отдельный
        транспорт, а не вариант ALPN, поэтому выбирается явно
    """

    def __init__(
        self,
        impersonate: str = DEFAULT_PROFILE,
        *,
        verify: bool = True,
        timeout: float = 30.0,
        proxy: str | None = None,
        default_headers: bool = True,
        header_order: Iterable[str] | None = None,
        allow_redirects: bool = True,
        max_redirects: int = 20,
        cookies: bool = True,
        force_http1: bool = False,
        http3: bool = False,
    ):
        # Профили, вложенные в пакет, подгружаются при первом обращении:
        # после pip install библиотека должна работать без лишних шагов.
        ensure_loaded()
        self._id = _call(
            "curlpro_session_new",
            encode(
                {
                    "profile": impersonate,
                    "insecure_skip_verify": not verify,
                    "timeout_ms": int(timeout * 1000),
                    "proxy": proxy or "",
                    "default_headers": default_headers,
                    "header_order": list(header_order) if header_order else None,
                    "follow_redirects": allow_redirects,
                    "max_redirects": max_redirects,
                    "cookies": cookies,
                    "force_http1": force_http1,
                    "http3": http3,
                }
            ),
        )["session"]
        self.impersonate = impersonate
        self._closed = False

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: bytes | str | None = None,
        json_body: Any = None,
        files: Mapping[str, Any] | None = None,
        fields: Mapping[str, str] | None = None,
        header_order: Iterable[str] | None = None,
        default_headers: bool | None = None,
    ) -> Response:
        if self._closed:
            raise RuntimeError("сессия закрыта")

        hdrs = dict(headers or {})
        multipart = None

        if files or fields:
            if data is not None or json_body is not None:
                raise ValueError("multipart несовместим с data и json_body")
            multipart, data = _build_multipart(fields, files)
        elif json_body is not None:
            if data is not None:
                raise ValueError("укажите либо data, либо json_body, не оба")
            data = encode(json_body)
            hdrs.setdefault("content-type", "application/json")

        if isinstance(data, str):
            data = data.encode("utf-8")

        payload, body = call_framed(
            "curlpro_request",
            self._id,
            body=data or b"",
            meta={
                "method": method.upper(),
                "url": url,
                "headers": hdrs,
                "header_order": list(header_order) if header_order else None,
                "no_default_headers": default_headers is False,
                "multipart": multipart,
            },
        )
        return Response(
            status=payload["status"],
            proto=payload.get("proto", ""),
            headers=payload.get("headers") or {},
            content=body,
            url=payload.get("url") or url,
        )

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: bytes | str | None = None,
        json_body: Any = None,
        header_order: Iterable[str] | None = None,
        default_headers: bool | None = None,
    ) -> "StreamResponse":
        """Открывает ответ для чтения по частям.

        Поток удерживает соединение до закрытия, поэтому использовать его
        следует через ``with``.
        """
        if self._closed:
            raise RuntimeError("сессия закрыта")

        hdrs = dict(headers or {})
        if json_body is not None:
            if data is not None:
                raise ValueError("укажите либо data, либо json_body, не оба")
            data = encode(json_body)
            hdrs.setdefault("content-type", "application/json")
        if isinstance(data, str):
            data = data.encode("utf-8")

        payload, _ = call_framed(
            "curlpro_stream_open",
            self._id,
            body=data or b"",
            meta={
                "method": method.upper(),
                "url": url,
                "headers": hdrs,
                "header_order": list(header_order) if header_order else None,
                "no_default_headers": default_headers is False,
                "multipart": None,
            },
        )
        return StreamResponse(payload)

    def get(self, url: str, **kw: Any) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Response:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw: Any) -> Response:
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw: Any) -> Response:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Any) -> Response:
        return self.request("DELETE", url, **kw)

    def head(self, url: str, **kw: Any) -> Response:
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw: Any) -> Response:
        return self.request("OPTIONS", url, **kw)

    def close(self) -> None:
        if not self._closed:
            _call("curlpro_session_close", self._id)
            self._closed = True

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Сессия держит открытые сокеты на стороне Go: без закрытия они
        # переживут сборку Python-объекта.
        try:
            self.close()
        except Exception:
            pass


def request(method: str, url: str, *, impersonate: str = DEFAULT_PROFILE,
            verify: bool = True, timeout: float = 30.0, proxy: str | None = None,
            **kw: Any) -> Response:
    """Одиночный запрос. Для серии запросов используйте Session."""
    session_kw = {
        k: kw.pop(k)
        for k in ("default_headers", "header_order", "allow_redirects",
                  "max_redirects", "cookies", "force_http1", "http3")
        if k in kw
    }
    with Session(impersonate, verify=verify, timeout=timeout, proxy=proxy,
                 **session_kw) as s:
        return s.request(method, url, **kw)


def get(url: str, **kw: Any) -> Response:
    return request("GET", url, **kw)


def post(url: str, **kw: Any) -> Response:
    return request("POST", url, **kw)


def put(url: str, **kw: Any) -> Response:
    return request("PUT", url, **kw)


def patch(url: str, **kw: Any) -> Response:
    return request("PATCH", url, **kw)


def delete(url: str, **kw: Any) -> Response:
    return request("DELETE", url, **kw)


def head(url: str, **kw: Any) -> Response:
    return request("HEAD", url, **kw)


def options(url: str, **kw: Any) -> Response:
    return request("OPTIONS", url, **kw)
