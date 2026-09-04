"""curlpro — HTTP-клиент с сетевым отпечатком браузера.

    import curlpro

    curlpro.load_profiles("profiles")
    r = curlpro.get("https://example.com", impersonate="chrome-151-windows")
    print(r.status, r.text[:200])

Профиль можно добавить и в рантайме, не дожидаясь релиза библиотеки::

    curlpro.register_profile(json.load(open("chrome-152-windows.json")))

Библиотека воспроизводит сетевой слой: TLS ClientHello, кадры HTTP/2, порядок
и регистр заголовков. JS-отпечаток (canvas, WebGL, navigator) — уровень
браузера, здесь его нет.
"""

from __future__ import annotations

from ._ffi import HTTPError, Timeout, CurlProError, WebSocketClosed
from .aio import AsyncSession
from .cookies import Cookie, Cookies
from .session import Redirect, Response, Session, delete, get, head, options, patch, post, put
from .profiles import Profile, ensure_loaded, list_profiles, load_profiles, register_profile
from .stream import StreamResponse
from .websocket import WebSocket

__all__ = [
    "AsyncSession",
    "Cookie",
    "Cookies",
    "CurlProError",
    "HTTPError",
    "Redirect",
    "Timeout",
    "Profile",
    "Response",
    "Session",
    "StreamResponse",
    "WebSocket",
    "WebSocketClosed",
    "delete",
    "ensure_loaded",
    "get",
    "head",
    "list_profiles",
    "load_profiles",
    "options",
    "patch",
    "post",
    "put",
    "register_profile",
]

__version__ = "0.1.0"
