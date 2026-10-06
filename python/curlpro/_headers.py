"""Response headers: a dict of lists whose lookups ignore case."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Tuple, Union

_Source = Union[Mapping[str, List[str]], Iterable[Tuple[str, List[str]]], None]


class HeaderValues(List[str]):
    """The values of one header: a list, and also the string requests gives.

    Compared with a ``str``, printed, formatted or tested for truth, it is
    ``", ".join(values)`` — what ``curlpro.requests`` and requests itself
    answer for the same header. Everywhere else it is the list it always was:
    ``for line in r.headers.get("set-cookie")`` walks the lines, ``[0]`` is
    the first value, JSON writes an array.

    Why it is both. ``.get()`` has to be the list for code that walks a
    repeated header, and that code exists. But a field report (Qrator,
    2026-10-06) ported from curl_cffi and wrote ``r.headers.get(name) ==
    "captcha"``: false for ever, no error, and ``['captcha']`` in its log.
    Being equal to its string removes that silent failure without starting
    another — making ``.get()`` a plain ``str`` would have sent every loop over
    ``Set-Cookie`` through characters instead. What a string has and a list
    does not (``.lower()``, ``int()``, a regex) still fails loudly, as it
    should: those are the calls that want :meth:`Headers.first`.
    """

    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return ", ".join(self) == other
        return list.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    # A list is unhashable, and equal-to-a-string must not make it hashable:
    # a set of values would quietly mix the two.
    __hash__ = None  # type: ignore[assignment]

    def __str__(self) -> str:
        return ", ".join(self)

    def __format__(self, spec: str) -> str:
        return format(", ".join(self), spec)

    def __bool__(self) -> bool:
        # The string's truth: a header that is present but empty is "", and
        # `if r.headers.get(name):` means what it means under requests.
        return bool(", ".join(self))


class Headers(Dict[str, List[str]]):
    """The headers of a response: ``dict[str, list[str]]``, looked up by any case.

    Keys keep the spelling the native side hands over — the canonical one,
    ``Retry-After`` — and a value is the list of every value of the header,
    in order. ``r.headers["retry-after"]``, ``r.headers.get("RETRY-AFTER")``
    and ``"retry-after" in r.headers`` all find it.

    Until 0.12 this was a plain dict, and ``.get("retry-after")`` quietly
    returned ``None``: a scraper never honoured a solver's ``Retry-After``
    because of it (a field report). The values stay lists — code that walks
    ``Set-Cookie`` keeps working, and ``int(r.headers.get("retry-after"))``
    now fails loudly instead of meaning "no header". For the first value as
    a string there is ``r.header(name)``, and :meth:`first` here; for the
    values as a plain list, :meth:`get_list`.

    Since 0.15.2 each value is a :class:`HeaderValues`: still the list, but
    equal to and printed as ``", ".join(values)``, the string requests gives
    — so ``r.headers.get(name) == "captcha"``, written by code ported from
    curl_cffi, is true when it should be rather than false for ever.

    A value becomes one when it is first read, not when the headers are
    built: converting all 26 of a typical response up front took 6.5 µs to
    20 µs, half of what 0.14 had won back for the whole Python side of a
    request, and most headers of most responses are never read. Every way of
    reading a value converts it — lookups, ``pop``, and ``items()`` and
    ``values()``, which convert the lot first — so none hands out a bare list.

    A lowercase index finds a name in one lookup. Until 0.14 every lookup
    walked the keys lowering each, and building the headers of a response
    did so for every header it added: 54 µs for a response of 26 headers,
    a quarter of the Python side of a request.
    """

    __slots__ = ("_lower",)

    def __init__(self, data: _Source = None, **kw: List[str]):
        super().__init__()
        #: The stored spelling of each name, by its lowercase.
        self._lower: Dict[str, str] = {}
        if isinstance(data, Headers) and not kw:
            dict.update(self, data)
            self._lower = dict(data._lower)
            return
        if type(data) is dict and not kw:
            # The native side's headers: one spelling per name, so the lot
            # goes in at once, unless two spellings of one name say otherwise.
            dict.update(self, data)
            lower = {k.lower(): k for k in data if isinstance(k, str)}
            if len(lower) == len(data):
                self._lower = lower
                return
            dict.clear(self)
        if data is not None:
            self.update(data)
        if kw:
            self.update(kw)

    def __reduce__(self) -> Any:
        # Rebuilt through __init__: pickle and copy would otherwise set the
        # items before the index exists.
        return (self.__class__, (dict(self),))

    def _key(self, name: Any) -> Any:
        """The stored spelling of ``name``, or None when it is absent."""
        if dict.__contains__(self, name):
            return name
        if isinstance(name, str):
            return self._lower.get(name.lower())
        return None

    def _read(self, key: Any) -> Any:
        """The stored value under ``key``, made a HeaderValues the first time.

        It is put back, so the object a caller gets is the stored one and
        ``r.headers["x"].append(...)`` lands. Only an exact ``list`` is
        converted: a tuple or a string someone stored stays what it was."""
        value = dict.__getitem__(self, key)
        if type(value) is list:
            value = HeaderValues(value)
            dict.__setitem__(self, key, value)
        return value

    def _read_all(self) -> None:
        # Replacing the value of a key that exists does not resize the dict,
        # so this is safe while iterating its own items.
        for key, value in dict.items(self):
            if type(value) is list:
                dict.__setitem__(self, key, HeaderValues(value))

    def items(self):  # type: ignore[override]  # noqa: ANN201 — dict's own view
        self._read_all()
        return dict.items(self)

    def values(self):  # type: ignore[override]  # noqa: ANN201
        self._read_all()
        return dict.values(self)

    def __getitem__(self, name: str) -> List[str]:
        key = self._key(name)
        if key is None:
            raise KeyError(name)
        return self._read(key)

    def __contains__(self, name: object) -> bool:
        return self._key(name) is not None

    def __setitem__(self, name: str, value: List[str]) -> None:
        # Setting "retry-after" where "Retry-After" is stored replaces the
        # values and keeps the stored spelling: one name, one entry.
        key = self._key(name)
        if key is None:
            key = name
            if isinstance(name, str):
                self._lower[name.lower()] = name
        dict.__setitem__(self, key, value)

    def __delitem__(self, name: str) -> None:
        key = self._key(name)
        if key is None:
            raise KeyError(name)
        self._forget(key)
        dict.__delitem__(self, key)

    def _forget(self, key: Any) -> None:
        if isinstance(key, str):
            self._lower.pop(key.lower(), None)

    def get(self, name: str, default: Any = None) -> Any:  # type: ignore[override]
        key = self._key(name)
        return default if key is None else self._read(key)

    def pop(self, name: str, *default: Any) -> Any:  # type: ignore[override]
        key = self._key(name)
        if key is None:
            if default:
                return default[0]
            raise KeyError(name)
        value = self._read(key)
        self._forget(key)
        dict.__delitem__(self, key)
        return value

    def popitem(self) -> Tuple[str, List[str]]:
        key, value = dict.popitem(self)
        self._forget(key)
        return key, HeaderValues(value) if type(value) is list else value

    def clear(self) -> None:
        dict.clear(self)
        self._lower.clear()

    def setdefault(self, name: str, default: Any = None) -> Any:  # type: ignore[override]
        key = self._key(name)
        if key is None:
            self[name] = default
            key = self._key(name)
        return self._read(key)

    def update(self, data: _Source = None, **kw: List[str]) -> None:  # type: ignore[override]
        if data is not None:
            items = data.items() if isinstance(data, Mapping) else data
            for name, value in items:
                self[name] = value
        for name, value in kw.items():
            self[name] = value

    def __ior__(self, other: Any) -> "Headers":  # type: ignore[override]
        self.update(other)
        return self

    def copy(self) -> "Headers":
        return Headers(self)

    def first(self, name: str, default: str | None = None) -> str | None:
        """The first value of a header, or ``default`` — for code that wants a
        string. A header that is present and empty gives ``""``, not
        ``default``: it was sent."""
        # Read as stored, unconverted: r.encoding asks this of every response
        # whose text is read, and a string needs no HeaderValues on the way.
        key = self._key(name)
        values = None if key is None else dict.__getitem__(self, key)
        return values[0] if values is not None and len(values) else default

    def get_list(self, name: str) -> List[str]:
        """Every value of a header as a plain list, ``[]`` when it is absent —
        httpx's name for it, and the spelling that says "I want the list"."""
        key = self._key(name)
        values = None if key is None else dict.__getitem__(self, key)
        return [] if values is None else list(values)
