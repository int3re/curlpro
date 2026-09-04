"""curlpro — an HTTP client with a browser's network fingerprint.

    import curlpro

    curlpro.load_profiles("profiles")
    r = curlpro.get("https://example.com", impersonate="chrome-151-windows")
    print(r.status, r.text[:200])

A profile can also be added at runtime, without waiting for a library
release::

    curlpro.register_profile(json.load(open("chrome-152-windows.json")))

The library reproduces the network layer: the TLS ClientHello, HTTP/2 frames,
header order and case. The JavaScript fingerprint (canvas, WebGL, navigator)
belongs to the browser and is not covered here.
"""

from __future__ import annotations

from ._ffi import HTTPError, Timeout, CurlProError, WebSocketClosed
from .aio import AsyncSession, AsyncStreamResponse, AsyncWebSocket
from .cookies import Cookie, Cookies
from .session import Redirect, Response, Session, delete, get, head, options, patch, post, put
from .profiles import Profile, ensure_loaded, list_profiles, load_profiles, register_profile
from .stream import StreamResponse
from .websocket import WebSocket

__all__ = [
    "AsyncSession",
    "AsyncStreamResponse",
    "AsyncWebSocket",
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
