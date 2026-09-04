"""Expectations about a response, checked before it reaches the caller.

A scraper always checks the same things by hand: the status is the one expected,
the page holds the marker of a successful login, there is no captcha in it, the
body is not empty at all. Written out every time, those checks are four ``if``
statements that are easy to forget — and a forgotten one turns a redirect to a
block page into "the parser stopped finding data".

Stated as an expectation, the same check reports what exactly did not match and
what arrived instead:

    r = s.get(url, expect=Expect(status=200, body="Welcome", not_body="captcha"))

A failure raises :class:`ExpectationFailed`, which is a
:class:`~curlpro.CurlProError`, so it is caught alongside network errors — and
together with ``rollback_cookies=True`` it undoes what the request wrote into
the jar.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ._ffi import CurlProError


class ExpectationFailed(CurlProError):
    """A response did not match the expectation.

    ``response`` is kept: an error page usually carries the reason, and that is
    exactly the body worth looking at.
    """

    def __init__(self, message: str, response: Any = None):
        super().__init__(message, "expectation")
        self.response = response
        self.status = getattr(response, "status", None)


def _as_list(value: Any) -> list[Any]:
    """One value or many: a string is a value, not a sequence of characters."""
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


class Expect:
    """What a response must and must not contain.

    Every field is optional; a field left out is not checked. Where several
    values are given, ``status`` requires one of them while the ``body`` and
    ``headers`` checks require all of them — that is how such checks read in
    practice: one status out of a list, but every marker present on the page.

    :param status: the allowed status or statuses
    :param not_status: statuses that must not appear
    :param body: substrings the body must contain
    :param not_body: substrings the body must not contain
    :param headers: substrings that must appear among the ``name: value`` lines,
        matched case-insensitively
    :param not_headers: substrings that must not appear there
    :param non_empty: the body must not be empty
    :param json: the body must parse as JSON
    """

    __slots__ = ("status", "not_status", "body", "not_body", "headers",
                 "not_headers", "non_empty", "json")

    def __init__(
        self,
        *,
        status: int | Iterable[int] | None = None,
        not_status: int | Iterable[int] | None = None,
        body: str | bytes | Iterable[str] | None = None,
        not_body: str | bytes | Iterable[str] | None = None,
        headers: str | Iterable[str] | None = None,
        not_headers: str | Iterable[str] | None = None,
        non_empty: bool = False,
        json: bool = False,
    ):
        self.status = _as_list(status)
        self.not_status = _as_list(not_status)
        self.body = _as_list(body)
        self.not_body = _as_list(not_body)
        self.headers = _as_list(headers)
        self.not_headers = _as_list(not_headers)
        self.non_empty = non_empty
        self.json = json

    def check(self, response: Any) -> Any:
        """Checks the response and returns it, or raises :class:`ExpectationFailed`."""
        for fail in (
            self._check_status,
            self._check_non_empty,
            self._check_body,
            self._check_headers,
            self._check_json,
        ):
            message = fail(response)
            if message:
                raise ExpectationFailed(f"{message} ({response.status} {response.url})",
                                        response=response)
        return response

    # -- individual checks ---------------------------------------------------

    def _check_status(self, r: Any) -> str:
        if self.status and r.status not in self.status:
            return f"status {r.status} is not among {sorted(self.status)}"
        if self.not_status and r.status in self.not_status:
            return f"status {r.status} is among the forbidden ones"
        return ""

    def _check_non_empty(self, r: Any) -> str:
        if self.non_empty and not r.content:
            return "the body is empty"
        return ""

    def _check_body(self, r: Any) -> str:
        if not (self.body or self.not_body):
            return ""
        # The body is matched as text: a scraper looks for words rather than
        # bytes, and the charset is already known to the response.
        text = r.text
        for want in self.body:
            if _text(want) not in text:
                return f"the body does not contain {_text(want)!r}"
        for reject in self.not_body:
            if _text(reject) in text:
                return f"the body contains the forbidden {_text(reject)!r}"
        return ""

    def _check_headers(self, r: Any) -> str:
        if not (self.headers or self.not_headers):
            return ""
        # Whole "name: value" lines are searched: the tool-style check "the
        # headers contain X" means both a name and a value, and splitting that
        # into two options would only add a decision to make.
        lines = [f"{name}: {value}".lower()
                 for name, values in r.headers.items() for value in values]
        for want in self.headers:
            needle = _text(want).lower()
            if not any(needle in line for line in lines):
                return f"the headers do not contain {_text(want)!r}"
        for reject in self.not_headers:
            needle = _text(reject).lower()
            if any(needle in line for line in lines):
                return f"the headers contain the forbidden {_text(reject)!r}"
        return ""

    def _check_json(self, r: Any) -> str:
        if not self.json:
            return ""
        try:
            r.json()
        except Exception as exc:  # noqa: BLE001 — any parse failure is the answer
            return f"the body does not parse as JSON: {exc}"
        return ""

    def __repr__(self) -> str:
        parts = []
        for name in self.__slots__:
            value = getattr(self, name)
            if value:
                parts.append(f"{name}={value!r}")
        return f"<Expect {' '.join(parts) or 'anything'}>"
