"""The exceptions curlpro raises.

Every one is also importable from ``curlpro`` itself. Until 0.12 they were
declared in the private ``curlpro._ffi``, so tracebacks and editors pointed
there and callers learnt to import from a module that promises nothing (a
field report); ``_ffi`` still re-exports them for that code.
"""

from __future__ import annotations

from ._headers import Headers


class CurlProError(RuntimeError):
    """An error raised by the native part.

    ``code`` is the machine-readable code when the native side knows one:
    ``timeout``, ``session_closed``, ``too_large``, ``ws_closed``,
    ``ws_too_big``, ``ws_protocol``. Never branch on the message text — it is
    for humans.
    """

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


class Timeout(CurlProError):
    """The request ran out of time.

    A class of its own because a timeout is the one outcome a scraper treats
    differently from other network errors: it retries it.
    """


class HTTPError(CurlProError):
    """A response with an error status; raised by :meth:`Response.raise_for_status`.

    That method used to raise a bare RuntimeError, indistinguishable from an
    internal failure. ``response`` stays attached: an error response usually
    carries a body, and that body is the reason to look at it.
    """

    def __init__(self, message: str, response=None, code: str | None = None):  # noqa: ANN001
        super().__init__(message, code)
        self.response = response
        self.status = getattr(response, "status", None)


class WebSocketClosed(CurlProError):
    """The WebSocket is closed: by the server's Close frame or by the caller.

    A class of its own so that ``for message in ws`` stops on a close only,
    while read timeouts and protocol errors reach the caller.
    """


class PermanentError(CurlProError):
    """A failure that will repeat: retrying it changes nothing.

    The two below are its kinds, and this is what a caller catches to mean
    "do not retry". Until it existed, a profile that could not serve
    ``mode="fetch"`` raised the same ``CurlProError`` as a blinked
    connection: a worker retried it three times and dropped the task.
    """


class ProfileCapabilityError(PermanentError):
    """The profile cannot do what was asked.

    No fetch header set, no ``http3`` section, no ALPN extension to restrict,
    no devices to choose from. Ask :func:`curlpro.capabilities` before
    choosing a profile, or catch this and move to another one — the profile
    will not grow the section between attempts. ``code == "profile_capability"``.
    """


class ConfigurationError(PermanentError):
    """The arguments do not make sense together.

    An unregistered profile name, a device that is not in the list, a page
    that is not a URL, a header listed twice, a negative timeout.
    ``code == "configuration"``.
    """


class ProxyError(CurlProError):
    """The proxy, not the target, failed the request.

    ``stage`` says where:

    - ``"dial"`` — the proxy itself could not be reached: TCP, or TLS for an
      ``https://`` proxy. The target was never asked for.
    - ``"auth"`` — it wanted credentials it did not get, or rejected the ones
      it got. That one arrives as :class:`ProxyAuthError`, which is also a
      :class:`PermanentError`: the same login will not pass next time.
    - ``"connect"`` — it was reached and could not or would not open the
      tunnel. ``status`` then carries its answer: the HTTP status of the
      CONNECT reply (502 from a gateway, 403 for a forbidden target) or the
      SOCKS5 reply code (5 is "connection refused" *at the target*, 4 "host
      unreachable"); ``None`` when it hung up without one — that case keeps
      ``code == "proxy_closed"``, everything else is ``code == "proxy"``.

    A pool decides from these, not from the message: a 502 is a minute's
    rest for the address, a 407 is never, a SOCKS reply 5 blames the
    destination rather than the proxy. Until 0.10 all four were one
    ``CurlProError`` with an empty code, and pools parsed the text.
    """

    def __init__(self, message: str, code: str | None = None, *,
                 stage: str | None = None, status: int | None = None):
        super().__init__(message, code)
        self.stage = stage
        self.status = status


class ProxyAuthError(ProxyError, PermanentError):
    """The proxy answered 407, or a SOCKS5 proxy rejected the login.

    Without credentials configured, or with credentials it did not accept.
    ``code == "proxy_auth"``, ``stage == "auth"``; retries are skipped.
    """


class CORSError(CurlProError):
    """The CORS preflight was refused, and the request itself was not sent.

    A browser sends ``OPTIONS`` before a cross-origin fetch that is not
    simple, and sends the request only when the answer allows it. This is
    that refusal: ``status`` and ``headers`` are the preflight's answer,
    ``reason`` says which check failed (no ``Access-Control-Allow-Origin``,
    a method or a header not allowed, a wildcard with credentials, a non-2xx
    status), ``method`` and ``url`` name the request that was not sent.

    Not a :class:`PermanentError` on purpose: a 503 to the OPTIONS is a bad
    minute, a missing ``Access-Control-Allow-Origin`` is forever, and the
    caller tells them apart by ``status`` better than a guess here would.
    A site that works in a browser answers a browser's preflight; if it
    refuses ours, the page named in ``page=`` is not one the site allows —
    or the preflight differs from the browser's, which is a bug to report.
    ``code == "cors"``. ``preflight=False`` on the session or the request
    sends without one, as before 0.10.
    """

    def __init__(self, message: str, code: str | None = None, *,
                 method: str | None = None, url: str | None = None,
                 reason: str | None = None, status: int | None = None,
                 headers: dict | None = None):
        super().__init__(message, code)
        self.method = method
        self.url = url
        self.reason = reason
        self.status = status
        self.headers = Headers(headers)
