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

from ._ffi import (
    ConfigurationError,
    CORSError,
    CurlProError,
    HTTPError,
    PermanentError,
    ProfileCapabilityError,
    ProxyAuthError,
    ProxyError,
    Timeout,
    WebSocketClosed,
)
from .expect import Expect, ExpectationFailed
from .fingerprint import Fingerprint
from .audit import Finding, audit
from .persona import Persona, load_all
from .aio import AsyncSession, AsyncStreamResponse, AsyncWebSocket
from .cookies import Cookie, Cookies
from .session import Preflight, Redirect, Response, Session, delete, get, head, options, patch, post, put, request
from .profiles import (
    Profile,
    capabilities,
    ensure_loaded,
    get_profile,
    library_version,
    list_profiles,
    load_profiles,
    register_profile,
)
from .stream import StreamResponse
from .websocket import WebSocket

__all__ = [
    "AsyncSession",
    "AsyncStreamResponse",
    "AsyncWebSocket",
    "Cookie",
    "Cookies",
    "ConfigurationError",
    "CORSError",
    "CurlProError",
    "Expect",
    "Finding",
    "ExpectationFailed",
    "Fingerprint",
    "Persona",
    "PermanentError",
    "Preflight",
    "ProfileCapabilityError",
    "ProxyAuthError",
    "ProxyError",
    "HTTPError",
    "Redirect",
    "Timeout",
    "Profile",
    "Response",
    "Session",
    "StreamResponse",
    "WebSocket",
    "WebSocketClosed",
    "audit",
    "capabilities",
    "delete",
    "ensure_loaded",
    "get",
    "get_profile",
    "head",
    "library_version",
    "list_profiles",
    "load_all",
    "load_profiles",
    "options",
    "patch",
    "post",
    "put",
    "register_profile",
    "request",
]

__version__ = "0.10.1"

try:  # an installed distribution is the authority; a source checkout has none
    from importlib.metadata import version as _dist_version

    __version__ = _dist_version("curlpro")
except Exception:  # pragma: no cover - not installed, keep the literal above
    pass
