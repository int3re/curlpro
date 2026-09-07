"""A ``requests``-shaped face on curlpro.

Existing code changes one import:

    import curlpro.requests as requests

    r = requests.get("https://example.com/", timeout=10)
    print(r.status_code, r.text[:200])

and the traffic starts looking like Chrome. That is the whole point: the barrier
to trying a fingerprinting client is usually not the client, it is rewriting the
call sites.

**This is a subset, and it says so.** What is missing is missing loudly: an
argument this module does not honour raises rather than being ignored, because a
silently dropped ``verify=False`` or ``proxies=`` is the kind of thing that
looks like it worked until it matters. Not implemented, on purpose:

* transport adapters, ``PreparedRequest``, ``Request`` — the whole
  mount/adapter machinery has no equivalent here;
* ``requests.Session.hooks`` — curlpro has its own hooks with a different
  contract; use :meth:`curlpro.Session.on_response`;
* ``stream=True`` — use :meth:`curlpro.Session.stream`, which holds the
  connection properly;
* per-request ``verify``/``cert`` — they belong to the TLS session here, so
  they are session-level;
* authentication objects — only the ``(user, password)`` tuple and a bearer
  string are understood.

One argument is honoured but means something slightly different, and it is the
kind of difference that is worth knowing before it surprises you:

* ``timeout=(a, b)``. In requests the pair is *(connect, read)*, where the
  second number is how much **silence between bytes** is tolerated. Here it is
  *(connect, total)*: the second number caps the whole request. That is
  stricter rather than looser, so a value carried over from requests is safe —
  a request that used to be allowed 27 seconds of silence is now allowed 27
  seconds altogether. Code that relied on a slow drip continuing indefinitely
  will time out where it used to hang.

The profile is chosen the usual way, and defaults to the library's default:

    with requests.Session(impersonate="firefox-133-macos") as s:
        s.get("https://example.com/")
"""

from __future__ import annotations

import datetime
from typing import Any, Iterator, Mapping

from ._ffi import CurlProError, HTTPError, Timeout
from .session import Response as _Response
from .session import Session as _Session

__all__ = [
    "ConnectionError",
    "HTTPError",
    "RequestException",
    "Response",
    "Session",
    "Timeout",
    "delete",
    "exceptions",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
]


# --- exceptions -----------------------------------------------------------
#
# requests code catches by name. The names are mapped onto ours rather than
# duplicated: a caller who catches RequestException must also catch what
# curlpro raises, and the only way to guarantee that is to make them the same
# class.

RequestException = CurlProError
ConnectionError = CurlProError


class _Exceptions:
    """``requests.exceptions`` as far as it is meaningful here."""

    RequestException = RequestException
    ConnectionError = ConnectionError
    HTTPError = HTTPError
    Timeout = Timeout
    ConnectTimeout = Timeout
    ReadTimeout = Timeout


exceptions = _Exceptions


class _Headers(Mapping[str, str]):
    """Case-insensitive response headers, as requests has them."""

    __slots__ = ("_raw",)

    def __init__(self, raw: Mapping[str, list[str]]):
        self._raw = raw

    def __getitem__(self, key: str) -> str:
        lowered = key.lower()
        for name, values in self._raw.items():
            if name.lower() == lowered and values:
                return ", ".join(values)
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._raw)

    def __len__(self) -> int:
        return len(self._raw)

    def __repr__(self) -> str:
        return f"{dict(self)!r}"


class Response:
    """A response under the names requests uses."""

    __slots__ = ("_r", "headers")

    def __init__(self, r: _Response):
        self._r = r
        self.headers = _Headers(r.headers)

    @property
    def status_code(self) -> int:
        return self._r.status

    @property
    def content(self) -> bytes:
        return self._r.content

    @property
    def text(self) -> str:
        return self._r.text

    @property
    def encoding(self) -> str:
        return self._r.encoding

    @encoding.setter
    def encoding(self, value: str) -> None:
        self._r.encoding = value

    def json(self, **kw: Any) -> Any:
        return self._r.json(**kw)

    @property
    def url(self) -> str:
        return self._r.url

    @property
    def ok(self) -> bool:
        return self._r.ok

    @property
    def cookies(self) -> dict[str, str]:
        return self._r.cookies

    @property
    def elapsed(self) -> datetime.timedelta:
        """requests reports a timedelta; curlpro reports seconds."""
        return datetime.timedelta(seconds=self._r.elapsed)

    @property
    def history(self) -> list[Any]:
        return list(self._r.history or [])

    @property
    def reason(self) -> str:
        """The reason phrase.

        HTTP/2 and HTTP/3 have none — the field was removed from the protocol —
        so this is derived from the status rather than invented. Code that
        branches on it is reading something the wire no longer carries.
        """
        return _REASONS.get(self._r.status, "")

    @property
    def is_redirect(self) -> bool:
        return self._r.status in (301, 302, 303, 307, 308)

    def raise_for_status(self) -> "Response":
        self._r.raise_for_status()
        return self

    def iter_content(self, chunk_size: int = 8192, decode_unicode: bool = False) -> Iterator[Any]:
        """Walks the body that is already in memory.

        Not a stream: by the time a Response exists the body has been read.
        For a real stream use :meth:`curlpro.Session.stream`, which holds the
        connection instead of pretending to.
        """
        if decode_unicode:
            raise NotImplementedError(
                "decode_unicode is not supported; use .text, or "
                "curlpro.Session.stream() for a real stream")
        data = self._r.content
        if chunk_size is None or chunk_size <= 0:
            yield data
            return
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]

    def iter_lines(self, chunk_size: int = 8192, decode_unicode: bool = False) -> Iterator[bytes]:
        if decode_unicode:
            raise NotImplementedError("decode_unicode is not supported; use .text")
        for line in self._r.content.splitlines():
            yield line

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"


#: Reason phrases for the statuses that actually occur. Deliberately short:
#: the field does not exist in HTTP/2 or HTTP/3, and a long table would suggest
#: it carries information that it does not.
_REASONS = {
    200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other",
    304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 408: "Request Timeout", 409: "Conflict",
    410: "Gone", 418: "I'm a Teapot", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}


#: Arguments requests understands that this module cannot honour. Each one is
#: refused with the reason and the way round it: silently dropping any of them
#: changes what goes on the wire, and that is exactly what this library exists
#: to control.
_REFUSED = {
    "stream": "stream=True is not supported here; use curlpro.Session.stream(), "
              "which holds the connection instead of pretending to",
    "hooks": "requests hooks are not supported; curlpro has its own — "
             "Session.on_request, on_response and on_error",
    "cert": "cert belongs to the TLS session here: pass it to "
            "curlpro.requests.Session(cert=...)",
    "verify": "verify belongs to the TLS session here: pass it to "
              "curlpro.requests.Session(verify=...)",
}


def _translate(kw: dict[str, Any]) -> dict[str, Any]:
    """Renames requests keywords to ours. No refusals: both callers share this."""
    out = dict(kw)
    if "json" in out:
        out["json_body"] = out.pop("json")
    if "proxies" in out:
        proxies = out.pop("proxies")
        if isinstance(proxies, Mapping):
            # requests keys by scheme; one connection has one proxy here, and
            # https is the scheme this library is for.
            out["proxy"] = proxies.get("https") or proxies.get("http") or ""
        else:
            out["proxy"] = proxies
    return out


def _request_kw(kw: dict[str, Any]) -> dict[str, Any]:
    """The same, for a single request, refusing what cannot be honoured there.

    The refusals belong here and not in the constructor: verify and cert are
    perfectly good session arguments — they describe the TLS session — and only
    become meaningless per request, because one connection has one TLS
    configuration.
    """
    for name, why in _REFUSED.items():
        if name in kw:
            raise TypeError(why)
    return _translate(kw)


class Session:
    """``requests.Session`` as far as it maps.

    Takes every :class:`curlpro.Session` argument as well, so the profile,
    the proxy and the retry policy are set where they belong.
    """

    __slots__ = ("_s",)

    def __init__(self, impersonate: str | None = None, **kw: Any):
        # The profile is positional here as it is in curlpro.Session: the
        # shortest form of the only argument that matters.
        if impersonate is not None:
            kw["impersonate"] = impersonate
        self._s = _Session(**_translate(kw))

    # -- the requests surface ---------------------------------------------

    @property
    def headers(self) -> Any:
        return self._s.headers

    @property
    def cookies(self) -> Any:
        return self._s.cookies

    @property
    def curlpro(self) -> _Session:
        """The session underneath, for everything this face does not cover."""
        return self._s

    def request(self, method: str, url: str, **kw: Any) -> Response:
        return Response(self._s.request(method, url, **_request_kw(kw)))

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
        self._s.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<curlpro.requests.Session {self._s.impersonate}>"


def request(method: str, url: str, **kw: Any) -> Response:
    """One request in its own session, as the module-level requests calls are."""
    session_only = {}
    for name in ("impersonate", "verify", "cert", "proxy", "proxies", "http3",
                 "force_http1", "device", "trust_env"):
        if name in kw:
            session_only[name] = kw.pop(name)
    with Session(**session_only) as s:
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
