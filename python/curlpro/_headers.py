"""Response headers: a dict of lists whose lookups ignore case."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Tuple, Union

_Source = Union[Mapping[str, List[str]], Iterable[Tuple[str, List[str]]], None]


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
    a string there is ``r.header(name)``, and :meth:`first` here.

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

    def __getitem__(self, name: str) -> List[str]:
        key = self._key(name)
        if key is None:
            raise KeyError(name)
        return dict.__getitem__(self, key)

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
        return default if key is None else dict.__getitem__(self, key)

    def pop(self, name: str, *default: Any) -> Any:  # type: ignore[override]
        key = self._key(name)
        if key is None:
            if default:
                return default[0]
            raise KeyError(name)
        self._forget(key)
        return dict.pop(self, key)

    def popitem(self) -> Tuple[str, List[str]]:
        key, value = dict.popitem(self)
        self._forget(key)
        return key, value

    def clear(self) -> None:
        dict.clear(self)
        self._lower.clear()

    def setdefault(self, name: str, default: Any = None) -> Any:  # type: ignore[override]
        key = self._key(name)
        if key is None:
            self[name] = default
            return default
        return dict.__getitem__(self, key)

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
        """The first value of a header, or ``default`` — what requests'
        ``headers.get`` returns, for code that wants a string."""
        values = self.get(name)
        return values[0] if values else default
