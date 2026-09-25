"""The session and the requests-style module-level functions."""

from __future__ import annotations

import math
import base64
import json
import sys
import time
import traceback
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping
from urllib.parse import urlencode, urlsplit, urlunsplit

from ._ffi import _call, call_framed, encode
from ._headers import Headers
from .errors import HTTPError
from .cookies import Cookies
from .encoding import detect as detect_encoding, without_bom
from .expect import Expect
from .fingerprint import Fingerprint
from .headers import SessionHeaders
from .profiles import ensure_loaded
from .proxies import proxy_for as env_proxy
from .stream import StreamResponse
from .timeouts import split_timeout as _split_timeout
from .websocket import WebSocket, connect as ws_connect

DEFAULT_PROFILE = "chrome-151-windows"


def _ms(value: float | None, name: str) -> int | None:
    """Seconds to whole milliseconds, with the answers a float can smuggle in.

    ``int(nan * 1000)`` raised a bare ValueError and ``int(inf * 1000)`` an
    OverflowError, both from three frames deep with no mention of the option.
    NaN is not a duration and is refused by name; infinity is what "no limit"
    means and is passed down as None, which is how no limit is spelled at the
    boundary; a negative value is refused here with the same words the native
    side uses, so the message does not depend on which side sees it first.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError(f"{name} must be a number of seconds, not a bool")
    v = float(value)
    if math.isnan(v):
        raise ValueError(f"{name} must be a number of seconds, got nan")
    if math.isinf(v):
        if v < 0:
            raise ValueError(f"{name} cannot be negative, got {value}")
        return None
    if v < 0:
        raise ValueError(f"{name} cannot be negative, got {value}")
    return int(v * 1000)


if TYPE_CHECKING:
    from typing_extensions import Unpack

    from ._kwargs import OneOffKwargs, RequestKwargs, _OneOffRest

#: The body limit a buffered response gets when ``max_response_size`` is not
#: given: 100 MiB. Streams are not bound by it — reading in chunks is how a
#: large body is meant to be handled.
DEFAULT_MAX_RESPONSE_SIZE = 100 * 1024 * 1024


def _size(value: Any) -> int:
    """A byte limit: 0 means none, and the native side reads a signed 64-bit.

    A negative limit used to slip through as "no limit"; 2**63 came back as a
    JSON unmarshal error naming a Go struct field. Both are the caller's mistake
    and are named as such, here.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"max_response_size must be an int of bytes, got {value!r}")
    if value < 0:
        raise ValueError(f"max_response_size cannot be negative, got {value}")
    if value > 2**63 - 1:
        raise ValueError(f"max_response_size is too large, got {value}")
    return value


def _count(value: Any, name: str) -> Any:
    """A non-negative int, or None for "not set"."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {value!r}")
    if value < 0:
        raise ValueError(f"{name} cannot be negative, got {value}")
    return value


def _split_headers(
    headers: "Mapping[str, str | None] | None",
) -> tuple[dict[str, str], list[str]]:
    """Splits the caller's headers into values to send and names to remove.

    ``None`` removes a header the profile or the session would send — the way
    to drop one navigation-only name without ``default_headers=False``, which
    drops the User-Agent and the order with it. An empty string is a value and
    goes out as one, the way a browser's ``fetch()`` sends an empty header when
    told to. Both used to be sent empty, without a word.
    """
    values: dict[str, str] = {}
    suppress: list[str] = []
    for name, value in (headers or {}).items():
        if value is None:
            suppress.append(name)
        elif isinstance(value, str):
            values[name] = value
        else:
            raise TypeError(
                f"header {name!r}: the value must be a string, or None to remove "
                f"the header; got {type(value).__name__}")
    return values, suppress


def _page_override(page: str | bool | None) -> str | None:
    """The page argument as the native side expects it: ``None`` inherits the
    session's page, ``False`` means no initiator, a string names the page."""
    if page is None:
        return None
    if page is False:
        return ""
    if not isinstance(page, str):
        raise TypeError(f"page must be a URL, None or False, got {type(page).__name__}")
    return page


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
    if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
        raise ValueError(f"retries must be a non-negative int, got {retries!r}")
    for name, value in (("retry_backoff", backoff), ("retry_max_backoff", max_backoff)):
        if value is not None and value < 0:
            raise ValueError(f"{name} cannot be negative, got {value}")
    return {
        "attempts": int(retries),
        "statuses": list(statuses) if statuses else None,
        "methods": list(methods) if methods else None,
        # None keeps the native default; 0 is honoured as no pause (it used
        # to be read as "not given", and retry_backoff=0 slept 0.2 s).
        "backoff_ms": None if backoff is None else int(backoff * 1000),
        "max_backoff_ms": None if max_backoff is None else int(max_backoff * 1000),
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
    chunks: list[bytes] = []

    for field, value in (files or {}).items():
        content_type = ""
        if isinstance(value, (bytes, bytearray, memoryview)) or hasattr(value, "read"):
            filename, content = getattr(value, "name", None) or field, value
            if not isinstance(filename, str):
                filename = field
            else:
                filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        elif isinstance(value, tuple):
            if len(value) == 2:
                filename, content = value
            elif len(value) == 3:
                filename, content, content_type = value
            else:
                raise ValueError(f"files[{field!r}]: expected a tuple of 2 or 3 items")
        else:
            raise TypeError(f"files[{field!r}]: expected bytes, a file object or a tuple")

        # A file object (open(...), BytesIO) is read, as requests reads it.
        if hasattr(content, "read"):
            content = content.read()
        if isinstance(content, str):
            content = content.encode("utf-8")
        content = bytes(content)
        described.append(
            {"field": field, "filename": filename, "content_type": content_type}
        )
        sizes.append(len(content))
        chunks.append(content)

    meta = {
        "fields": fields,
        "order": list(fields),
        "files": described,
        "file_sizes": sizes,
    }
    return meta, b"".join(chunks)


def _with_params(url: str, params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> str:
    """Appends query parameters to the URL.

    An existing query string is kept: requests behaves the same way, and a
    URL like "/search?lang=ru" does not lose its lang when params are added.
    """
    if not params:
        return url
    if isinstance(params, (str, bytes)):
        # A ready query string, as requests takes it: appended as it is.
        raw = params.decode("utf-8") if isinstance(params, bytes) else params
        parts = urlsplit(url)
        query = parts.query + "&" + raw.lstrip("?&") if parts.query else raw.lstrip("?")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
    items: list[tuple[str, Any]] = []
    pairs = params.items() if hasattr(params, "items") else params
    for key, value in pairs:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            items.extend((key, v if isinstance(v, bytes) else str(v)) for v in value if v is not None)
        elif isinstance(value, bool):
            items.append((key, "true" if value else "false"))
        elif isinstance(value, bytes):
            # Percent-encoded as bytes; str() gave "b'v'".
            items.append((key, value))
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


def _order(header_order: Iterable[Any] | None) -> list[str] | None:
    """The header order as it travels: names as given, ``...`` as the string.

    ``...`` (the Ellipsis) marks where the profile's own order goes, so a
    pattern edits the browser's order instead of restating it.
    """
    if not header_order:
        return None
    out: list[str] = []
    for item in header_order:
        if item is Ellipsis:
            out.append("...")
        elif isinstance(item, str):
            out.append(item)
        else:
            raise TypeError(
                f"header_order: entries are header names or ..., got {type(item).__name__}")
    return out


def _request_meta(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str | None] | None = None,
    params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
    auth: tuple[str, str] | str | None = None,
    data: bytes | str | None = None,
    json_body: Any = None,
    files: Mapping[str, Any] | None = None,
    fields: Mapping[str, str] | None = None,
    body_file: str | Any = None,
    header_order: Iterable[Any] | None = None,
    default_headers: bool | None = None,
    cookies: bool | None = None,
    session_headers: bool | None = None,
    protocol: str | float | None = None,
    timeout: float | tuple[float, float] | None = None,
    connect_timeout: float | None = None,
    response_timeout: float | None = None,
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
    page: str | bool | None = None,
    credentials: str | None = None,
    preflight: bool | None = None,
) -> tuple[dict[str, Any], bytes]:
    # params and auth are the familiar requests arguments; here they turn
    # into a URL with a query string and an ordinary header, nothing special.
    pair_connect, timeout = _split_timeout(timeout)
    # The named limit wins over the pair's first element: it is the more
    # specific statement of the two, and a caller writing both meant it.
    if connect_timeout is None:
        connect_timeout = pair_connect
    url = _with_params(url, params)
    if basic := _auth_header(auth):
        headers = dict(headers or {})
        if not any(k.lower() == "authorization" for k in headers):
            headers["Authorization"] = basic
    """Builds the request frame. Shared by request() and stream(): the stream
    used to keep its own cut-down copy without timeout, proxy, retries or files."""
    hdrs, suppress = _split_headers(headers)
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
        # The caller's Content-Type in any spelling wins: "Content-Type:
        # text/plain" is how a page avoids a CORS preflight, and the default
        # used to overwrite it because it looked for the lowercase name only.
        if not any(k.lower() == "content-type" for k in hdrs):
            hdrs["content-type"] = "application/json"

    if isinstance(data, str):
        data = data.encode("utf-8")

    meta = {
        "method": method.upper(),
        "url": url,
        "headers": hdrs,
        "suppress_headers": suppress,
        "header_order": _order(header_order),
        # None follows the session; True and False override it either way.
        "default_headers": default_headers,
        # The session memory: the cookie jar and the session headers. False
        # isolates the request from them, and for cookies in both directions.
        "cookies": cookies,
        "session_headers": session_headers,
        "protocol": _protocol(protocol),
        "multipart": multipart,
        "body_file": body_file or "",
        # None means "take the session's"; zero is a meaningful value, so
        # absence is what travels, not a substituted default.
        "timeout_ms": _ms(timeout, "timeout"),
        "connect_timeout_ms": _ms(connect_timeout, "connect_timeout"),
        "response_timeout_ms": _ms(response_timeout, "response_timeout"),
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
        # None takes the session's page, False means no initiator for this
        # request, a URL names the page it is made from.
        "page": _page_override(page),
        # None takes the session's credentials mode; "same-origin", "include"
        # or "omit" set it for this fetch-mode request.
        "credentials": credentials or "",
        # None takes the session's; False sends a cross-origin fetch without
        # the OPTIONS a browser would send first, True sends it when needed.
        "preflight": preflight,
    }
    return meta, data or b""


class Preflight:
    """A CORS preflight the session sent before a request: the ``OPTIONS``
    and what the server answered. ``cached`` means no OPTIONS went out —
    an earlier answer, within its ``Access-Control-Max-Age``, still covered
    the method and the headers, which is how a browser avoids one per request."""

    __slots__ = ("url", "status", "headers", "cached")

    def __init__(self, url: str, status: int, headers: dict[str, list[str]], cached: bool = False):
        headers = Headers(headers)
        self.url = url
        self.status = status
        self.headers = headers
        self.cached = cached

    def __repr__(self) -> str:
        mark = " (cached)" if self.cached else ""
        return f"<Preflight {self.status} {self.url}{mark}>"


def _preflights(items: Any) -> list[Preflight]:
    return [Preflight(p.get("url", ""), p.get("status", 0), p.get("headers") or {}, bool(p.get("cached")))
            for p in items or []]


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
                 "history", "preflights", "_encoding")

    def __init__(self, status: int, proto: str, headers: dict[str, list[str]],
                 content: bytes, url: str = "", elapsed: float = 0.0,
                 history: list | None = None, preflights: list | None = None):
        self.status = status
        self.proto = proto
        #: Every header of the response; lookups ignore case (see Headers).
        self.headers = Headers(headers)
        self.content = content
        self.url = url
        #: Time of the whole request, redirects and retries included, in seconds.
        self.elapsed = elapsed
        #: The intermediate responses of a redirect chain, first to last.
        self.history: list[Redirect] = history or []
        #: The CORS preflights sent before the request and its hops, in
        #: order; empty when a browser would have sent none.
        self.preflights: list[Preflight] = preflights or []
        self._encoding: str | None = None

    @property
    def preflight(self) -> "Preflight | None":
        """The CORS preflight that preceded this request, or None."""
        return self.preflights[0] if self.preflights else None

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
        return without_bom(self.content, self.encoding).decode(self.encoding, errors="replace")

    def json(self, **kwargs: Any) -> Any:
        """Parses the body as JSON; keyword arguments go to :func:`json.loads`.

        The bytes are handed over untouched: json.loads recognises UTF-8,
        UTF-16 and UTF-32 itself, per RFC 8259. The header charset is no help
        here — sites declare anything in it while the body is UTF-8 anyway.
        """
        return json.loads(self.content, **kwargs)

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


def _note_hook_failure(exc: BaseException, hook: Any, hook_exc: BaseException) -> None:
    """Attaches an error hook's own failure to the exception that survives it.

    From Python 3.11 the remark rides along as a PEP 678 note and prints under
    the traceback. Older versions have nowhere to put it, so it goes to stderr
    the way an unraisable exception does — anything else would lose it.
    """
    name = getattr(hook, "__name__", None) or repr(hook)
    text = (f"on_error hook {name!r} itself failed with "
            f"{type(hook_exc).__name__}: {hook_exc}; the request error above is "
            f"what was raised")
    add_note = getattr(exc, "add_note", None)
    if add_note is not None:
        add_note(text)
        return
    print(text, file=sys.stderr)
    traceback.print_exception(type(hook_exc), hook_exc, hook_exc.__traceback__)


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
        Without one, a server with an endless response eats the process memory.
        Not given, a buffered response is capped at 100 MiB
        (:data:`DEFAULT_MAX_RESPONSE_SIZE`, since 0.12) and a stream is not
        capped; given, the number binds both, a stream's ``read()`` included
    :param timeout: limit for the whole request including redirects, in
        seconds. A ``(connect, total)`` pair sets a separate limit on
        establishing the connection — name resolution, TCP and the TLS
        handshake. Here the second element caps the whole request rather than
        the silence between bytes as in requests: that is stricter, so the
        familiar value is safe to keep
    :param connect_timeout: the connecting limit by name — name resolution,
        TCP and the TLS handshake. Wins over the pair's first element
    :param response_timeout: how long to wait for the response headers after
        the request went out. The gap the other two leave: a server that
        accepts the connection and then thinks for a minute is past the
        connecting limit and still inside the total one. The body is not
        bounded by it — once the headers are in, only ``timeout`` applies.
        Raises :class:`Timeout` with the words "response headers"
    :param proxy: ``http://``, ``https://``, ``socks5://`` or ``socks5h://``,
        with ``user:pass`` allowed. An address with no scheme is read as
        ``http://``: a bare one says nothing about SOCKS, and guessing wrong
        would open a connection speaking the wrong protocol. The first CONNECT
        carries no credentials and adds them after a 407, as a browser does; a
        proxy that hangs up instead of challenging, or answers the 407 and then
        closes without saying so, gets the CONNECT with them on a fresh
        connection
    :param default_headers: send the profile's headers. Turn it off to control
        the set and the order yourself — anti-bot systems look at the order
        too. Without your own ``user-agent`` no such header is sent at all:
        the library will not substitute Go's default. An individual request
        overrides this either way
    :param header_order: the send order as a pattern: names, with ``...`` for
        "the profile's own order here". ``[..., "accept", "x-api-key", ...]``
        puts a custom header right after Accept and leaves the rest as the
        browser sends it; ``["x-api-key", ...]`` puts it first, ``[...,
        "accept-language", "accept", ...]`` swaps two profile headers.
        Several ``...`` are allowed: an unlisted profile header stays beside
        the listed neighbour it follows in the profile. A list without
        ``...`` is the list followed by the rest of the profile. Names the
        request does not carry are skipped, so one pattern serves every
        request; a name listed twice is refused
    :param allow_redirects: follow 3xx responses
    :param max_redirects: limit on the length of a redirect chain
    :param cookies: enable the cookie jar shared by the session's requests
    :param force_http1: do not offer h2, even when the profile lists it
    :param post_quantum: ``False`` drops the X25519MLKEM768 group and its
        1216-byte key share from the ClientHello — the hello of a browser
        with post-quantum key agreement switched off by policy. JA4 is
        unchanged, JA3 and the size move: a ~1.9 KB hello that spans two TCP
        segments becomes one that fits in one. On by default, because the
        browser sends the share
    :param resume: reuse TLS session tickets, as a browser does. A browser
        talking to one host resumes constantly, and a client that never
        resumes is an observable anomaly that no fingerprint measures —
        JA3, JA4, JA4H and the Akamai string all come from the first
        handshake, while the tell lives in the second. On by default since
        the resuming hello was measured (Chrome 153 and Firefox 156,
        2026-09-19): it is the first hello plus ``pre_shared_key`` last,
        no early data, and for Firefox without ``session_ticket`` — which is
        what goes out here. The first hello of a session is untouched, so
        every fingerprint stays what it was
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
    :param page: the page the requests are made from — the initiator. Sets
        ``Referer``, ``Origin`` and ``sec-fetch-site`` the way a browser does
        for a request from that page; see :attr:`page`. Must be an absolute
        http(s) URL
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
        max_response_size: int | None = None,
        timeout: float | tuple[float, float] = 30.0,
        connect_timeout: float | None = None,
        response_timeout: float | None = None,
        proxy: str | None = None,
        default_headers: bool = True,
        header_order: Iterable[Any] | None = None,
        allow_redirects: bool = True,
        max_redirects: int = 20,
        cookies: bool = True,
        force_http1: bool = False,
        post_quantum: bool = True,
        resume: bool = True,
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
        page: str | None = None,
        credentials: str = "same-origin",
        samesite: bool = True,
        preflight: bool = True,
    ):
        # The bundled profiles are loaded on first use: after pip install
        # the library has to work without any extra steps.
        ensure_loaded()
        session_connect, session_total = _split_timeout(timeout)
        if connect_timeout is not None:
            session_connect = connect_timeout
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
                    "max_response_size": (DEFAULT_MAX_RESPONSE_SIZE if max_response_size is None
                                          else _size(max_response_size)),
                    "timeout_ms": _ms(session_total, "timeout") or 0,
                    "connect_timeout_ms": _ms(session_connect, "connect_timeout") or 0,
                    "response_timeout_ms": _ms(response_timeout, "response_timeout") or 0,
                    "proxy": proxy or "",
                    "default_headers": default_headers,
                    "header_order": _order(header_order),
                    "follow_redirects": allow_redirects,
                    "max_redirects": _count(max_redirects, "max_redirects"),
                    "cookies": cookies,
                    "force_http1": force_http1,
                    "post_quantum": post_quantum,
                    "resume": resume,
                    "http3": http3,
                    "alt_svc": alt_svc,
                    "resolve": dict(resolve) if resolve else None,
                    "ip_version": ip_version or "",
                    "keep_alive": keep_alive,
                    "device": device or "",
                    "devices": [dict(d) for d in devices] if devices else None,
                    "max_idle_conns": max_idle_conns,
                    "idle_conn_timeout_ms": _ms(idle_conn_timeout, "idle_conn_timeout") or 0,
                    "retry": _retry_config(
                        retries or None, retry_statuses, retry_methods,
                        retry_backoff, retry_max_backoff, respect_retry_after,
                    ),
                    "mode": "" if mode == "auto" else mode,
                    "page": page or "",
                    "credentials": credentials,
                    "samesite": samesite,
                    "preflight": preflight,
                }
            ),
        )["session"]
        self.impersonate = impersonate
        self._trust_env = trust_env
        #: The session's own proxy: it beats the environment (see _route).
        self._proxy = proxy or ""
        self._closed = False
        # Kept for the streaming path: the limit lives in the native part,
        # which never sees a stream read as a whole body. The default binds
        # buffered responses only.
        self._max_response_size = 0 if max_response_size is None else _size(max_response_size)
        #: Headers added to every request of the session. Kept apart from
        #: the profile's, so clear() restores the plain fingerprint.
        self.headers = SessionHeaders(self._id)
        #: The page the requests are made from; see :attr:`page`.
        self._page = page or ""
        #: Session cookies: reading, editing, saving and loading from a file.
        self.cookies = Cookies(self._id)
        #: Hooks: "request" runs before sending and receives the request
        #: description, "response" runs after with the finished response,
        #: "error" runs when the request fails and receives the exception.
        #: request and response hooks may return a replacement; an error hook
        #: may return another exception to raise instead. Returning None
        #: changes nothing.
        self.hooks: dict[str, list[Callable[..., Any]]] = {
            "request": [], "response": [], "error": [],
        }
        for event, fns in (hooks or {}).items():
            if event not in self.hooks:
                raise ValueError(f"unknown hook event {event!r}: available events are request, response and error")
            self.hooks[event].extend(fns)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str | None] | None = None,
        params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
        auth: tuple[str, str] | str | None = None,
        data: bytes | str | None = None,
        json_body: Any = None,
        files: Mapping[str, Any] | None = None,
        fields: Mapping[str, str] | None = None,
        body_file: str | Any = None,
        header_order: Iterable[Any] | None = None,
        default_headers: bool | None = None,
        cookies: bool | None = None,
        session_headers: bool | None = None,
        protocol: str | float | None = None,
        timeout: float | tuple[float, float] | None = None,
        connect_timeout: float | None = None,
        response_timeout: float | None = None,
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
        page: str | bool | None = None,
        credentials: str | None = None,
        preflight: bool | None = None,
        expect: "Expect | None" = None,
        rollback_cookies: bool = False,
    ) -> Response:
        """Sends a request and returns the response.

        Beyond the familiar requests arguments:

        :param headers: your own headers. A value of ``None`` removes a header
            the profile or the session would send — one navigation-only name
            gone, the rest of the set and its order intact; an empty string
            is sent as an empty header, the way a browser's ``fetch()`` sends
            one
        :param header_order: the send order for this request as a pattern —
            ``[..., "accept", "x-api-key", ...]`` puts a custom header right
            after Accept, the rest stays as the browser sends it; see
            :class:`Session` for the rules
        :param page: the page this request is made from, overriding the
            session's; ``False`` sends it with no initiator at all
        :param cookies: use the session jar for this request. ``False`` isolates
            the request in both directions: stored cookies are not sent and
            ``Set-Cookie`` from the response is not remembered
        :param session_headers: add the headers set on the session. ``False``
            leaves only the profile headers and the ones passed here
        :param default_headers: add the profile headers, overriding the session
            setting either way
        :param protocol: force the transport for this request: ``"http1"``,
            ``"h2"`` or ``"h3"`` (``1.1``, ``2`` and ``3`` also work)
        :param expect: an :class:`~curlpro.Expect` describing what the response
            must and must not contain; a mismatch raises
            :class:`~curlpro.ExpectationFailed`
        :param rollback_cookies: undo what this request wrote into the jar if it
            fails — including a failed expectation. A half-finished login is
            worse than none
        """
        if self._closed:
            raise RuntimeError("session is closed")

        proxy = self._route(url, proxy)

        meta, body = _request_meta(
            method, url, headers=headers, params=params, auth=auth,
            data=data, json_body=json_body,
            files=files, fields=fields, body_file=body_file,
            header_order=header_order, default_headers=default_headers,
            cookies=cookies, session_headers=session_headers,
            protocol=protocol, timeout=timeout, connect_timeout=connect_timeout,
            response_timeout=response_timeout, allow_redirects=allow_redirects,
            max_redirects=max_redirects, retries=retries,
            retry_statuses=retry_statuses, retry_methods=retry_methods,
            retry_backoff=retry_backoff, retry_max_backoff=retry_max_backoff,
            respect_retry_after=respect_retry_after, proxy=proxy, mode=mode, page=page, credentials=credentials,
            preflight=preflight,
        )
        if rollback_cookies:
            # The native side logs what this request changes in the jar and
            # undoes it itself when the request fails; the log comes back for
            # the failures only Python sees (an expectation, a hook).
            meta["track_cookies"] = True
        for hook in self.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        started = time.perf_counter()
        changes: list | None = None
        try:
            payload, content = call_framed("curlpro_request", self._id, body=body, meta=meta)
            changes = payload.get("cookie_changes")
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
                preflights=_preflights(payload.get("preflights")),
            ), expect)
        except BaseException as exc:
            raise self._failed(exc, changes if rollback_cookies else None) from None

    def _failed(self, exc: BaseException, changes: "list[dict[str, Any]] | None") -> BaseException:
        """Handles a failed request: rolls the cookies back and runs the hooks.

        The rollback comes first: an error hook may itself go to the network,
        and it must see the jar the request started with rather than the half
        of a login the failed request managed to write.

        Returns the exception to raise — a hook may replace it, which is how a
        library error is turned into one of the caller's own.
        """
        # A request that failed natively was undone there; a response that
        # failed here (an expectation, a hook) is undone from its own log.
        if changes:
            self.cookies._undo(changes)
        # Cancellation and Ctrl+C are not request failures but control flow:
        # a hook returning its own exception in their place would swallow the
        # cancellation, and the task would never stop.
        if not isinstance(exc, Exception):
            return exc
        for hook in self.hooks["error"]:
            try:
                replaced = hook(exc)
            except Exception as hook_exc:  # noqa: BLE001
                # A hook that fails must not hide why the request failed: the
                # caller acts on the network error, not on a typo in their own
                # logging. Replacing the exception is what returning one is
                # for; raising from a hook used to do it by accident. The
                # remaining hooks still run — one broken hook disables itself,
                # not the others.
                _note_hook_failure(exc, hook, hook_exc)
                continue
            if isinstance(replaced, BaseException):
                exc = replaced
        return exc

    def _after(self, response: Response, expect: "Expect | None" = None) -> Response:
        """Runs the response through the hooks and the expectations.

        The expectations come last: a hook may replace the response, and it is
        the replacement the caller receives — so it is the one to check.
        """
        for hook in self.hooks["response"]:
            replaced = hook(response)
            if replaced is not None:
                response = replaced
        if expect is not None:
            expect.check(response)
        return response

    def on_request(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Adds a request hook. Works as a decorator too."""
        self.hooks["request"].append(fn)
        return fn

    def on_error(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Adds an error hook. Works as a decorator too.

        Runs on every request failure: a network error, a timeout, a failed
        expectation. Handy for logging, metrics and rotating a proxy — and,
        by returning an exception, for turning a library error into one of
        the caller's own.
        """
        self.hooks["error"].append(fn)
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
        headers: Mapping[str, str | None] | None = None,
        params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
        auth: tuple[str, str] | str | None = None,
        data: bytes | str | None = None,
        json_body: Any = None,
        files: Mapping[str, Any] | None = None,
        fields: Mapping[str, str] | None = None,
        body_file: str | Any = None,
        header_order: Iterable[Any] | None = None,
        default_headers: bool | None = None,
        cookies: bool | None = None,
        session_headers: bool | None = None,
        protocol: str | float | None = None,
        timeout: float | tuple[float, float] | None = None,
        connect_timeout: float | None = None,
        response_timeout: float | None = None,
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
        page: str | bool | None = None,
        credentials: str | None = None,
        preflight: bool | None = None,
    ) -> "StreamResponse":
        """Opens a response for reading in chunks.

        Takes the same arguments as :meth:`request`. The stream holds its
        connection until closed, so use it through ``with``. Closing a stream
        with the body unread drops the connection instead of draining the
        rest: reading a kilobyte and closing is cheap.
        """
        if self._closed:
            raise RuntimeError("session is closed")

        proxy = self._route(url, proxy)
        meta, body = _request_meta(
            method, url, headers=headers, params=params, auth=auth, data=data, json_body=json_body,
            files=files, fields=fields, body_file=body_file,
            header_order=header_order, default_headers=default_headers,
            cookies=cookies, session_headers=session_headers,
            protocol=protocol, timeout=timeout, connect_timeout=connect_timeout,
            response_timeout=response_timeout, allow_redirects=allow_redirects,
            max_redirects=max_redirects, retries=retries,
            retry_statuses=retry_statuses, retry_methods=retry_methods,
            retry_backoff=retry_backoff, retry_max_backoff=retry_max_backoff,
            respect_retry_after=respect_retry_after, proxy=proxy, mode=mode, page=page, credentials=credentials,
            preflight=preflight,
        )
        # The request hooks see a stream's frame too, as they do on the async
        # side: a hook that adds a signature header must not miss downloads.
        for hook in self.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced
        payload, _ = call_framed("curlpro_stream_open", self._id, body=body, meta=meta)
        return StreamResponse(payload, self._max_response_size)

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
                          timeout=timeout, max_message_size=max_message_size,
                          proxy=self._route(url))

    def get(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return self.request("DELETE", url, **kw)

    def head(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw: Unpack[RequestKwargs]) -> Response:
        return self.request("OPTIONS", url, **kw)

    def _route(self, url: str, proxy: str | bool | None = None) -> str | bool | None:
        """The proxy a request, stream or socket to ``url`` goes through.

        The request's own ``proxy`` wins; ``None`` means "the session's". A
        session with a proxy of its own keeps it — the native side applies it
        when the request names none. Without one, ``trust_env`` reads the
        environment for this URL, ``NO_PROXY`` included. Until 0.12 the
        environment beat an explicit session proxy on requests, and streams
        and WebSockets never read it: they went direct, from the real address.
        """
        if proxy is not None or self._proxy:
            return proxy
        if not self._trust_env:
            return None
        scheme, sep, rest = url.partition("://")
        plain = {"ws": "http", "wss": "https"}.get(scheme.lower(), scheme) + sep + rest
        # "" is "go direct": NO_PROXY excluded the host, or nothing is set.
        return env_proxy(plain) or ""

    def fingerprint(self, url: str = "https://example.com/") -> "Fingerprint":
        """What a server would see from this session — without sending anything.

        The URL decides only the SNI and the Host header. It moves neither JA4
        nor JA3N — that independence is why JA4 replaced JA3 — but it does
        change the length of the ClientHello, so a name is used rather than
        nothing.

            with curlpro.Session("chrome-151-windows") as s:
                print(s.fingerprint().ja4)

        The session's own options are taken into account: ``force_http1``
        restricts ALPN, and ALPN is two characters of JA4. A fingerprint that
        ignored that would describe a different session.
        """
        if self._closed:
            raise RuntimeError("session is closed")
        return Fingerprint(_call("curlpro_session_fingerprint", self._id, url.encode("utf-8")))

    @property
    def page(self) -> str | None:
        """The page the session's requests are made from — the initiator.

        With a page set, three headers are derived the way a browser derives
        them (measured on Chrome 153 and Firefox 156, identical): ``Referer``
        is the page's URL to its own origin and the page's origin elsewhere;
        ``Origin`` is the page's origin, on every cross-origin fetch and on
        any request with a body; ``sec-fetch-site`` is the relation between
        the page and the URL — same-origin, same-site or cross-site — and
        degrades along a redirect chain. Without a page the profile's own
        values go out: a navigation typed into the bar and a fetch from the
        request's own origin.

        A scraper sets it as it moves::

            r = s.get("https://example.com/app")     # the navigation
            s.page = r.url                            # from here on, from that page
            s.post("https://api.example.com/v1/x", json_body=...)   # Origin, Referer, cross-site

        ``None`` clears it. A request's own ``page=`` argument wins for that
        request; ``page=False`` sends one request with no initiator.
        """
        return self._page or None

    @page.setter
    def page(self, url: str | None) -> None:
        if self._closed:
            raise RuntimeError("session is closed")
        value = url or ""
        if not isinstance(value, str):
            raise TypeError(f"page must be a URL or None, got {type(url).__name__}")
        _call("curlpro_session_set_page", self._id, value.encode("utf-8"))
        self._page = value

    def headers_for(
        self,
        method: str = "GET",
        url: str = "https://example.com/",
        *,
        headers: Mapping[str, str | None] | None = None,
        header_order: Iterable[Any] | None = None,
        mode: str | None = None,
        page: str | bool | None = None,
        credentials: str | None = None,
        protocol: str | float | None = None,
        default_headers: bool | None = None,
        session_headers: bool | None = None,
    ) -> dict[str, str]:
        """The headers this request would carry, without sending it.

            s.headers_for("POST", api_url, mode="fetch", page=page_url)
            # {'sec-ch-ua-platform': '"Windows"', ..., 'referer': ..., 'origin': ...}

        The same assembly the request itself runs — profile set, session
        headers, removals, order pattern, the page's ``Referer``, ``Origin``
        and ``sec-fetch-site`` — so the answer is what goes out, not a second
        implementation of the rules. Insertion order is send order.

        :meth:`fingerprint` answers the same question for a plain GET in the
        session's own mode; this one takes the request. The transport matters,
        so it follows ``protocol``: HTTP/1.1 adds ``Host`` and ``Connection``
        and uses the browser's letter case, HTTP/2 and HTTP/3 have neither.

        Refuses what the request would refuse: ``mode="fetch"`` on a profile
        without a fetch set raises :class:`~curlpro.ProfileCapabilityError`
        here too, which makes this the cheap way to ask before committing.
        """
        if self._closed:
            raise RuntimeError("session is closed")
        hdrs, suppress = _split_headers(headers)
        data = _call("curlpro_session_preview", self._id, encode({
            "method": method.upper(),
            "url": url,
            "headers": hdrs,
            "suppress_headers": suppress,
            "header_order": _order(header_order),
            "mode": mode or "",
            "page": _page_override(page),
            "credentials": credentials or "",
            "protocol": _protocol(protocol),
            "default_headers": default_headers,
            "session_headers": session_headers,
        }))
        return {h["name"]: h["value"] for h in data["headers"]}

    def preflight_for(
        self,
        method: str = "GET",
        url: str = "https://example.com/",
        *,
        headers: Mapping[str, str | None] | None = None,
        mode: str | None = None,
        page: str | bool | None = None,
        credentials: str | None = None,
        protocol: str | float | None = None,
        session_headers: bool | None = None,
    ) -> "dict[str, str] | None":
        """The CORS preflight this request would be preceded by, or None.

            s.preflight_for("POST", api_url, headers={"Content-Type": "application/json"}, page=page_url)
            # {'accept': '*/*', 'access-control-request-method': 'POST',
            #  'access-control-request-headers': 'content-type', 'origin': ..., ...}

        None means a browser would send the request straight out: it is not
        a fetch from a page to another origin, or it is a simple one — GET,
        HEAD or POST with nothing outside the CORS safelist. The same
        assembly the real preflight runs, so what this shows is what goes
        out — the request's own headers are not on it, only their names in
        ``access-control-request-headers``. The request is sent with the
        preflight automatically; this is for looking before sending.
        """
        if self._closed:
            raise RuntimeError("session is closed")
        hdrs, suppress = _split_headers(headers)
        data = _call("curlpro_session_preview", self._id, encode({
            "method": method.upper(),
            "url": url,
            "headers": hdrs,
            "suppress_headers": suppress,
            "mode": mode or "",
            "page": _page_override(page),
            "credentials": credentials or "",
            "protocol": _protocol(protocol),
            "session_headers": session_headers,
            "preflight": True,
        }))
        if not data.get("needed"):
            return None
        return {h["name"]: h["value"] for h in data["headers"]}

    def audit(self, mode: str | None = None) -> list:
        """Contradictions in what this session would send.

        The second question, after "does my fingerprint look right": does
        anything here disagree with anything else. See :mod:`curlpro.audit`.

        The session is judged by what it has actually sent — the header
        sets its requests went out with — as well as by how it was built;
        ``mode="fetch"`` asks about fetch requests before any has gone out.
        """
        from .audit import audit as _audit
        return _audit(self, mode)

    def close(self) -> None:
        if not self._closed:
            _call("curlpro_session_close", self._id)
            self._closed = True
            # The jar has no handle of its own: it reads the session that is
            # now gone, and has to say so rather than name a stale number.
            self.cookies._closed = True

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
            **kw: Unpack[_OneOffRest]) -> Response:
    """A one-off request. For a series of them use Session."""
    session_kw: dict[str, Any] = {
        k: kw.pop(k)  # type: ignore[misc]
        for k in ("default_headers", "header_order", "allow_redirects",
                  "max_redirects", "cookies", "force_http1", "http3", "post_quantum")
        if k in kw
    }
    with Session(impersonate, verify=verify, timeout=timeout, proxy=proxy,
                 **session_kw) as s:
        # The session switches were popped into session_kw above.
        return s.request(method, url, **kw)  # type: ignore[misc]


def get(url: str, **kw: Unpack[OneOffKwargs]) -> Response:
    return request("GET", url, **kw)


def post(url: str, **kw: Unpack[OneOffKwargs]) -> Response:
    return request("POST", url, **kw)


def put(url: str, **kw: Unpack[OneOffKwargs]) -> Response:
    return request("PUT", url, **kw)


def patch(url: str, **kw: Unpack[OneOffKwargs]) -> Response:
    return request("PATCH", url, **kw)


def delete(url: str, **kw: Unpack[OneOffKwargs]) -> Response:
    return request("DELETE", url, **kw)


def head(url: str, **kw: Unpack[OneOffKwargs]) -> Response:
    return request("HEAD", url, **kw)


def options(url: str, **kw: Unpack[OneOffKwargs]) -> Response:
    return request("OPTIONS", url, **kw)
