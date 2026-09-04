"""The session and the requests-style module-level functions."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlencode, urlsplit, urlunsplit

from ._ffi import HTTPError, _call, call_framed, encode
from .cookies import Cookies
from .encoding import detect as detect_encoding
from .headers import SessionHeaders
from .profiles import ensure_loaded
from .proxies import proxy_for as env_proxy
from .stream import StreamResponse
from .timeouts import split_timeout as _split_timeout
from .websocket import WebSocket, connect as ws_connect

DEFAULT_PROFILE = "chrome-151-windows"


def _proxy_override(proxy: str | bool | None) -> str | None:
    """Turns the proxy argument into what the native side expects.

    Three states, and they have to stay distinct: ``None`` inherits the
    session proxy, ``False`` goes directly, bypassing it, and a string uses
    the address given. One string cannot express that, because the empty
    string already means "directly".
    """
    if proxy is None:
        return None
    if proxy is False:
        return ""
    if proxy is True:
        raise ValueError("proxy=True is meaningless: pass an address or False")
    if not isinstance(proxy, str):
        raise TypeError(f"proxy must be a string, False or None, got {type(proxy).__name__}")
    return proxy


def _retry_config(
    retries: int | None,
    statuses: Iterable[int] | None,
    methods: Iterable[str] | None,
    backoff: float | None,
    max_backoff: float | None,
    respect_retry_after: bool,
) -> dict[str, Any] | None:
    """Builds the retry policy.

    ``None`` means "not set": for a session that is "no retries", for a
    request it is "take the session's". Zero is an explicit "no retries",
    which is how a request switches off the retries its session configured.
    Zero used to collapse into ``None``, and turning them off for one request
    was impossible.

    Only idempotent methods are retried by default: repeating a POST can
    create a second order, because the server may have processed the request
    and failed to answer in time. An explicit ``retry_methods`` list allows it.
    """
    if retries is None:
        return None
    return {
        "attempts": int(retries),
        "statuses": list(statuses) if statuses else None,
        "methods": list(methods) if methods else None,
        "backoff_ms": int((backoff or 0.2) * 1000),
        "max_backoff_ms": int((max_backoff or 10.0) * 1000),
        "respect_retry_after": respect_retry_after,
    }


def _build_multipart(
    fields: Mapping[str, str] | None,
    files: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bytes]:
    """Prepares the form description and the concatenated file contents.

    The multipart boundary is generated natively in the profile's style: its
    shape tells Chrome from Firefox, so it belongs to the fingerprint rather
    than to encoding details.

    A ``files`` value is either ``bytes`` or a tuple
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
                raise ValueError(f"files[{field!r}]: expected a tuple of 2 or 3 items")
        else:
            raise TypeError(f"files[{field!r}]: expected bytes or a tuple")

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


def _with_params(url: str, params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> str:
    """Appends query parameters to the URL.

    An existing query string is kept: requests behaves the same way, and a
    URL like "/search?lang=ru" does not lose its lang when params are added.
    """
    if not params:
        return url
    items: list[tuple[str, str]] = []
    pairs = params.items() if hasattr(params, "items") else params
    for key, value in pairs:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            items.extend((key, str(v)) for v in value if v is not None)
        elif isinstance(value, bool):
            items.append((key, "true" if value else "false"))
        else:
            items.append((key, str(value)))
    if not items:
        return url
    parts = urlsplit(url)
    query = urlencode(items, doseq=False)
    if parts.query:
        query = parts.query + "&" + query
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _auth_header(auth: tuple[str, str] | str | None) -> str | None:
    """Basic auth: a pair becomes a header, a string is passed through as is."""
    if auth is None:
        return None
    if isinstance(auth, str):
        return auth
    user, password = auth
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return "Basic " + token


#: What people call the protocols. The canonical value goes to the core.
_PROTOCOLS = {
    "http1": "http1", "http/1.1": "http1", "http1.1": "http1",
    "h1": "http1", "1.1": "http1", "1": "http1",
    "h2": "h2", "http2": "h2", "http/2": "h2", "2": "h2", "2.0": "h2",
    "h3": "h3", "http3": "h3", "http/3": "h3", "3": "h3", "3.0": "h3",
}


def _protocol(value: str | float | None) -> str:
    """Maps a protocol name onto what the core understands.

    Numbers are accepted too: ``protocol=2`` reads no worse than
    ``protocol="h2"``, and that is the form people ask for.
    """
    if value is None:
        return ""
    key = str(value).strip().lower()
    if key not in _PROTOCOLS:
        raise ValueError(
            f"protocol={value!r}: use http1 (1.1), h2 (2) or h3 (3)"
        )
    return _PROTOCOLS[key]


def _request_meta(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
    auth: tuple[str, str] | str | None = None,
    data: bytes | str | None = None,
    json_body: Any = None,
    files: Mapping[str, Any] | None = None,
    fields: Mapping[str, str] | None = None,
    body_file: str | Any = None,
    header_order: Iterable[str] | None = None,
    default_headers: bool | None = None,
    protocol: str | float | None = None,
    timeout: float | tuple[float, float] | None = None,
    allow_redirects: bool | None = None,
    max_redirects: int | None = None,
    retries: int | None = None,
    retry_statuses: Iterable[int] | None = None,
    retry_methods: Iterable[str] | None = None,
    retry_backoff: float | None = None,
    retry_max_backoff: float | None = None,
    respect_retry_after: bool = True,
    proxy: str | bool | None = None,
    mode: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    # params and auth are the familiar requests arguments; here they turn
    # into a URL with a query string and an ordinary header, nothing special.
    connect_timeout, timeout = _split_timeout(timeout)
    url = _with_params(url, params)
    if credentials := _auth_header(auth):
        headers = dict(headers or {})
        headers.setdefault("Authorization", credentials)
    """Builds the request frame. Shared by request() and stream(): the stream
    used to keep its own cut-down copy without timeout, proxy, retries or files."""
    hdrs = dict(headers or {})
    multipart = None

    if body_file is not None:
        if data is not None or json_body is not None or files or fields:
            raise ValueError("body_file cannot be combined with data, json_body or multipart")
        body_file = str(body_file)
    elif files or fields:
        if data is not None or json_body is not None:
            raise ValueError("multipart cannot be combined with data or json_body")
        multipart, data = _build_multipart(fields, files)
    elif json_body is not None:
        if data is not None:
            raise ValueError("pass either data or json_body, not both")
        data = encode(json_body)
        hdrs.setdefault("content-type", "application/json")

    if isinstance(data, str):
        data = data.encode("utf-8")

    meta = {
        "method": method.upper(),
        "url": url,
        "headers": hdrs,
        "header_order": list(header_order) if header_order else None,
        # None follows the session; True and False override it either way.
        "default_headers": default_headers,
        "protocol": _protocol(protocol),
        "multipart": multipart,
        "body_file": body_file or "",
        # None means "take the session's"; zero is a meaningful value, so
        # absence is what travels, not a substituted default.
        "timeout_ms": None if timeout is None else int(timeout * 1000),
        "connect_timeout_ms": None if connect_timeout is None else int(connect_timeout * 1000),
        "follow_redirects": allow_redirects,
        "max_redirects": max_redirects,
        "retry": _retry_config(
            retries, retry_statuses, retry_methods,
            retry_backoff, retry_max_backoff, respect_retry_after,
        ),
        # None takes the session's, False goes directly bypassing the
        # session proxy, a string uses the address given.
        "proxy": _proxy_override(proxy),
        # None is the session mode; "navigate" or "fetch" pick a header set.
        "mode": mode or "",
    }
    return meta, data or b""


class Redirect:
    """One hop of a redirect chain: where the server answered and with what status."""

    __slots__ = ("status", "url", "location")

    def __init__(self, status: int, url: str, location: str):
        self.status = status
        self.url = url
        self.location = location

    def __repr__(self) -> str:
        return f"<Redirect {self.status} {self.url} → {self.location}>"


class Response:
    """A server response."""

    __slots__ = ("status", "proto", "headers", "content", "url", "elapsed",
                 "history", "_encoding")

    def __init__(self, status: int, proto: str, headers: dict[str, list[str]],
                 content: bytes, url: str = "", elapsed: float = 0.0,
                 history: list | None = None):
        self.status = status
        self.proto = proto
        self.headers = headers
        self.content = content
        self.url = url
        #: Time of the whole request, redirects and retries included, in seconds.
        self.elapsed = elapsed
        #: The intermediate responses of a redirect chain, first to last.
        self.history: list[Redirect] = history or []
        self._encoding: str | None = None

    @property
    def cookies(self) -> dict[str, str]:
        """The cookies this response set.

        This response, not the whole session: the session has its own
        ``cookies``, which also holds cookies from earlier requests.
        """
        out: dict[str, str] = {}
        for name, values in self.headers.items():
            if name.lower() != "set-cookie":
                continue
            for v in values:
                pair = v.split(";", 1)[0]
                key, _, value = pair.partition("=")
                if key.strip():
                    out[key.strip()] = value.strip()
        return out

    @property
    def encoding(self) -> str:
        """Body charset: from Content-Type, then the BOM, then the document.

        Detected once and remembered. Assigning to it overrides the detected
        value — a site may declare the charset wrongly, and then the choice
        belongs to the caller.
        """
        if self._encoding is None:
            self._encoding = detect_encoding(self.content, self.header("content-type"))
        return self._encoding

    @encoding.setter
    def encoding(self, value: str) -> None:
        self._encoding = value

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding, errors="replace")

    def json(self) -> Any:
        """Parses the body as JSON.

        The bytes are handed over untouched: json.loads recognises UTF-8,
        UTF-16 and UTF-32 itself, per RFC 8259. The header charset is no help
        here — sites declare anything in it while the body is UTF-8 anyway.
        """
        return json.loads(self.content)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def raise_for_status(self) -> "Response":
        """Raises :class:`HTTPError` on a 4xx or 5xx status."""
        if not self.ok:
            raise HTTPError(f"HTTP {self.status} for {self.url}", response=self)
        return self

    def header(self, name: str) -> str | None:
        """The first value of a header, matched case-insensitively."""
        lowered = name.lower()
        for key, values in self.headers.items():
            if key.lower() == lowered and values:
                return values[0]
        return None

    def __repr__(self) -> str:
        return f"<Response {self.status} {self.proto} {len(self.content)}b>"


class Session:
    """A session with one profile and reused connections.

    :param impersonate: profile name
    :param verify: verify the server certificate. ``True`` uses the system
        roots, a path to a PEM file trusts only that root, ``False`` skips
        verification entirely
    :param cert: a ``(certificate, key)`` path pair for mutual TLS
    :param trust_env: take the proxy from the ``HTTPS_PROXY`` and
        ``ALL_PROXY`` environment variables, honouring ``NO_PROXY``. An
        explicit ``proxy`` always wins
    :param max_response_size: body size limit in bytes; 0 means no limit.
        Without one, a server with an endless response eats the process memory
    :param timeout: limit for the whole request including redirects, in
        seconds. A ``(connect, total)`` pair sets a separate limit on
        establishing the connection — name resolution, TCP and the TLS
        handshake. Here the second element caps the whole request rather than
        the silence between bytes as in requests: that is stricter, so the
        familiar value is safe to keep
    :param proxy: ``http://``, ``https://`` or ``socks5://``, user:pass allowed
    :param default_headers: send the profile's headers. Turn it off to control
        the set and the order yourself — anti-bot systems look at the order
        too. Without your own ``user-agent`` no such header is sent at all:
        the library will not substitute Go's default. An individual request
        overrides this either way
    :param header_order: the desired header order; anything not listed follows,
        keeping its relative order
    :param allow_redirects: follow 3xx responses
    :param max_redirects: limit on the length of a redirect chain
    :param cookies: enable the cookie jar shared by the session's requests
    :param force_http1: do not offer h2, even when the profile lists it
    :param http3: send requests over QUIC instead of TCP. The profile must
        describe an ``http3`` section or the session will not be created.
        This is a separate transport, not an ALPN variant, so it is explicit
    :param alt_svc: upgrade to HTTP/3 after seeing an ``Alt-Svc`` header in a
        response. That is what a browser does: the first request to a site
        always goes over TCP, and it moves to QUIC only after the
        advertisement. A failed attempt postpones the next one and falls back
        to TCP. Requires a profile with an ``http3`` section; does not apply
        through a proxy
    :param resolve: address override for a host:
        ``{"example.com:443": "10.0.0.7"}``. The name in SNI and in the Host
        header stays the same — only the socket destination changes. The
        equivalent of curl's ``--resolve``: it is how you reach one specific
        server behind a balancer. Does not apply through a proxy, which
        resolves names itself
    :param ip_version: restrict the address family: ``"4"`` or ``"6"``. Needed
        where a name has an AAAA record but there is no IPv6 route
    :param keep_alive: reuse the connection between requests. On by default:
        that is what a browser does, and the TLS handshake is not repeated per
        request. ``False`` closes the connection right after the response —
        useful when a balancer pins a client to one node. No
        ``Connection: close`` header is sent either way: a browser does not
        send one
    :param device: the phone the session pretends to be: a name from the
        profile's ``devices`` section, or ``"random"``. Modern Chrome cut the
        model out of ``User-Agent`` (everyone reports ``Android 10; K``), so
        the device is disclosed through the ``sec-ch-ua-model`` and
        ``sec-ch-ua-platform-version`` hints — and only after the site asked
        for them with ``Accept-CH``. Chosen once per session
    :param devices: your own device list instead of the profile's; each entry
        is ``{"name": ..., "model": ..., "platform_version": ...}``
    :param retries: how many retries to make after the first attempt
    :param mode: which header set to use: ``"navigate"`` for a page load,
        ``"fetch"`` for a fetch/XHR request from a page, ``"auto"`` to decide
        from the request itself (a method other than GET/HEAD/POST, a
        non-form body or a custom header mean fetch). The profile needs a
        ``fetch`` section
    """

    def __init__(
        self,
        impersonate: str = DEFAULT_PROFILE,
        *,
        verify: bool | str = True,
        cert: tuple[str, str] | None = None,
        trust_env: bool = True,
        max_response_size: int = 0,
        timeout: float | tuple[float, float] = 30.0,
        proxy: str | None = None,
        default_headers: bool = True,
        header_order: Iterable[str] | None = None,
        allow_redirects: bool = True,
        max_redirects: int = 20,
        cookies: bool = True,
        force_http1: bool = False,
        http3: bool = False,
        alt_svc: bool = True,
        resolve: Mapping[str, str] | None = None,
        ip_version: str | None = None,
        keep_alive: bool = True,
        hooks: Mapping[str, Iterable[Callable[..., Any]]] | None = None,
        device: str | None = None,
        devices: Iterable[Mapping[str, str]] | None = None,
        max_idle_conns: int = 0,
        idle_conn_timeout: float = 0.0,
        retries: int = 0,
        retry_statuses: Iterable[int] | None = None,
        retry_methods: Iterable[str] | None = None,
        retry_backoff: float = 0.2,
        retry_max_backoff: float = 10.0,
        respect_retry_after: bool = True,
        mode: str = "auto",
    ):
        # The bundled profiles are loaded on first use: after pip install
        # the library has to work without any extra steps.
        ensure_loaded()
        session_connect, session_total = _split_timeout(timeout)
        self._id = _call(
            "curlpro_session_new",
            encode(
                {
                    "profile": impersonate,
                    # verify=True uses the system roots, a string picks one
                    # root of your own, False skips verification entirely.
                    "insecure_skip_verify": verify is False,
                    "ca_cert": verify if isinstance(verify, str) else "",
                    "client_cert": cert[0] if cert else "",
                    "client_key": cert[1] if cert else "",
                    # Python reads the environment: on Linux the native part
                    # sees it as it was when the process started, so an
                    # os.environ change at runtime never reaches it.
                    "trust_env": False,
                    "max_response_size": int(max_response_size),
                    "timeout_ms": int(session_total * 1000) if session_total else 0,
                    "connect_timeout_ms":
                        int(session_connect * 1000) if session_connect else 0,
                    "proxy": proxy or "",
                    "default_headers": default_headers,
                    "header_order": list(header_order) if header_order else None,
                    "follow_redirects": allow_redirects,
                    "max_redirects": max_redirects,
                    "cookies": cookies,
                    "force_http1": force_http1,
                    "http3": http3,
                    "alt_svc": alt_svc,
                    "resolve": dict(resolve) if resolve else None,
                    "ip_version": ip_version or "",
                    "keep_alive": keep_alive,
                    "device": device or "",
                    "devices": [dict(d) for d in devices] if devices else None,
                    "max_idle_conns": max_idle_conns,
                    "idle_conn_timeout_ms": int(idle_conn_timeout * 1000),
                    "retry": _retry_config(
                        retries or None, retry_statuses, retry_methods,
                        retry_backoff, retry_max_backoff, respect_retry_after,
                    ),
                    "mode": "" if mode == "auto" else mode,
                }
            ),
        )["session"]
        self.impersonate = impersonate
        self._trust_env = trust_env
        self._closed = False
        #: Headers added to every request of the session. Kept apart from
        #: the profile's, so clear() restores the plain fingerprint.
        self.headers = SessionHeaders(self._id)
        #: Session cookies: reading, editing, saving and loading from a file.
        self.cookies = Cookies(self._id)
        #: Hooks: "request" runs before sending and receives the request
        #: description, "response" runs after with the finished response. Both
        #: may return a replacement; returning None changes nothing.
        self.hooks: dict[str, list[Callable[..., Any]]] = {"request": [], "response": []}
        for event, fns in (hooks or {}).items():
            if event not in self.hooks:
                raise ValueError(f"unknown hook event {event!r}: available events are request and response")
            self.hooks[event].extend(fns)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
        auth: tuple[str, str] | str | None = None,
        data: bytes | str | None = None,
        json_body: Any = None,
        files: Mapping[str, Any] | None = None,
        fields: Mapping[str, str] | None = None,
        body_file: str | Any = None,
        header_order: Iterable[str] | None = None,
        default_headers: bool | None = None,
        protocol: str | float | None = None,
        timeout: float | tuple[float, float] | None = None,
        allow_redirects: bool | None = None,
        max_redirects: int | None = None,
        retries: int | None = None,
        retry_statuses: Iterable[int] | None = None,
        retry_methods: Iterable[str] | None = None,
        retry_backoff: float | None = None,
        retry_max_backoff: float | None = None,
        respect_retry_after: bool = True,
        proxy: str | bool | None = None,
        mode: str | None = None,
    ) -> Response:
        if self._closed:
            raise RuntimeError("session is closed")

        if proxy is None and self._trust_env:
            # An explicit proxy beats the environment; False means "go
            # directly" and is not overridden either.
            proxy = env_proxy(url)

        meta, body = _request_meta(
            method, url, headers=headers, params=params, auth=auth,
            data=data, json_body=json_body,
            files=files, fields=fields, body_file=body_file,
            header_order=header_order, default_headers=default_headers,
            protocol=protocol, timeout=timeout, allow_redirects=allow_redirects,
            max_redirects=max_redirects, retries=retries,
            retry_statuses=retry_statuses, retry_methods=retry_methods,
            retry_backoff=retry_backoff, retry_max_backoff=retry_max_backoff,
            respect_retry_after=respect_retry_after, proxy=proxy, mode=mode,
        )
        for hook in self.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        started = time.perf_counter()
        payload, content = call_framed("curlpro_request", self._id, body=body, meta=meta)
        spent = time.perf_counter() - started
        return self._after(Response(
            status=payload["status"],
            proto=payload.get("proto", ""),
            headers=payload.get("headers") or {},
            content=content,
            url=payload.get("url") or url,
            elapsed=spent,
            history=[Redirect(h.get("status", 0), h.get("url", ""), h.get("location", ""))
                     for h in payload.get("history") or []],
        ))

    def _after(self, response: Response) -> Response:
        """Runs the response through the hooks."""
        for hook in self.hooks["response"]:
            replaced = hook(response)
            if replaced is not None:
                response = replaced
        return response

    def on_request(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Adds a request hook. Works as a decorator too."""
        self.hooks["request"].append(fn)
        return fn

    def on_response(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Adds a response hook. Works as a decorator too."""
        self.hooks["response"].append(fn)
        return fn

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: bytes | str | None = None,
        json_body: Any = None,
        files: Mapping[str, Any] | None = None,
        fields: Mapping[str, str] | None = None,
        body_file: str | Any = None,
        header_order: Iterable[str] | None = None,
        default_headers: bool | None = None,
        protocol: str | float | None = None,
        timeout: float | tuple[float, float] | None = None,
        allow_redirects: bool | None = None,
        max_redirects: int | None = None,
        retries: int | None = None,
        retry_statuses: Iterable[int] | None = None,
        retry_methods: Iterable[str] | None = None,
        retry_backoff: float | None = None,
        retry_max_backoff: float | None = None,
        respect_retry_after: bool = True,
        proxy: str | bool | None = None,
        mode: str | None = None,
    ) -> "StreamResponse":
        """Opens a response for reading in chunks.

        Takes the same arguments as :meth:`request`. The stream holds its
        connection until closed, so use it through ``with``. Closing a stream
        with the body unread drops the connection instead of draining the
        rest: reading a kilobyte and closing is cheap.
        """
        if self._closed:
            raise RuntimeError("session is closed")

        meta, body = _request_meta(
            method, url, headers=headers, data=data, json_body=json_body,
            files=files, fields=fields, body_file=body_file,
            header_order=header_order, default_headers=default_headers,
            protocol=protocol, timeout=timeout, allow_redirects=allow_redirects,
            max_redirects=max_redirects, retries=retries,
            retry_statuses=retry_statuses, retry_methods=retry_methods,
            retry_backoff=retry_backoff, retry_max_backoff=retry_max_backoff,
            respect_retry_after=respect_retry_after, proxy=proxy, mode=mode,
        )
        payload, _ = call_framed("curlpro_stream_open", self._id, body=body, meta=meta)
        return StreamResponse(payload)

    def websocket(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        subprotocols: Iterable[str] | None = None,
        timeout: float | tuple[float, float] = 30.0,
        max_message_size: int = 0,
    ) -> "WebSocket":
        """Opens a WebSocket whose handshake headers come from the profile.

        ``timeout`` caps the handshake and the wait for a single message; a
        ``(connect, total)`` pair caps establishing the connection separately,
        exactly as for an ordinary request. ``max_message_size`` limits an
        incoming message in bytes (zero means 64 MiB). The connection is held
        until closed — use ``with``.
        """
        if self._closed:
            raise RuntimeError("session is closed")
        return ws_connect(self._id, url, headers=headers, subprotocols=subprotocols,
                          timeout=timeout, max_message_size=max_message_size)

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
        # The session holds open sockets on the Go side: without closing
        # they outlive the Python object.
        try:
            self.close()
        except Exception:
            pass


def request(method: str, url: str, *, impersonate: str = DEFAULT_PROFILE,
            verify: bool = True, timeout: float | tuple[float, float] = 30.0, proxy: str | None = None,
            **kw: Any) -> Response:
    """A one-off request. For a series of them use Session."""
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
