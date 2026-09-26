"""The keyword arguments of the request methods, as types.

``Session.get(url, **kw)`` and its siblings used to take ``**kw: Any``: a
misspelt ``timout=`` reached the runtime before anyone noticed, and editors
could offer nothing (a field report). The methods now annotate ``**kw`` with
these ``TypedDict``s through ``Unpack`` (PEP 692), so mypy, pyright and IDEs
check every name and type. ``RequestKwargs`` is public for wrappers:

    def fetch(url: str, **kw: Unpack[curlpro.RequestKwargs]) -> curlpro.Response:
        return session.get(url, **kw)

Generated from the real signatures by the 0.12 patch and guarded by
``tests/test_signatures.py``: a parameter added to ``Session.request`` and
not here fails that test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterable, Mapping, TypedDict

if TYPE_CHECKING:
    from .expect import Expect


class _Common(TypedDict, total=False):
    """What every request method takes."""

    headers: Mapping[str, str | None] | None
    data: bytes | str | None
    json_body: Any
    files: Mapping[str, Any] | None
    fields: Mapping[str, str] | None
    body_file: str | Any
    header_order: Iterable[Any] | None
    default_headers: bool | None
    cookies: bool | None
    session_headers: bool | None
    protocol: str | float | None
    connect_timeout: float | None
    response_timeout: float | None
    allow_redirects: bool | None
    max_redirects: int | None
    retries: int | None
    retry_statuses: Iterable[int] | None
    retry_methods: Iterable[str] | None
    retry_backoff: float | None
    retry_max_backoff: float | None
    respect_retry_after: bool
    mode: str | None
    page: str | bool | None
    credentials: str | None
    preflight: bool | None
    resource: str | None
    crossorigin: str | None


class StreamKwargs(_Common, total=False):
    """``AsyncSession.stream``: a request without an expectation."""

    params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None
    auth: tuple[str, str] | str | None
    timeout: float | tuple[float, float] | None
    proxy: str | bool | None


class RequestKwargs(StreamKwargs, total=False):
    """``Session.get``/``post``/..., ``AsyncSession.request`` and its verbs."""

    expect: Expect | None
    rollback_cookies: bool


class _OneOffRest(_Common, total=False):
    """What ``curlpro.request`` takes beyond its named parameters: the request
    arguments, and the session switches it passes on."""

    params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None
    auth: tuple[str, str] | str | None
    expect: Expect | None
    rollback_cookies: bool
    force_http1: bool
    http3: bool
    post_quantum: bool


class OneOffKwargs(_OneOffRest, total=False):
    """``curlpro.get``/``post``/...: a one-off request in its own session."""

    impersonate: str
    verify: bool
    timeout: float | tuple[float, float]
    proxy: str | None
