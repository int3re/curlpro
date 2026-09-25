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
    """

    __slots__ = ()

    def __init__(self, data: _Source = None, **kw: List[str]):
        super().__init__()
        if data is not None:
            self.update(data)
        if kw:
            self.update(kw)

    def _key(self, name: Any) -> Any:
        """The stored spelling of ``name``, or None when it is absent."""
        if dict.__contains__(self, name):
            return name
        if isinstance(name, str):
            lowered = name.lower()
            for key in dict.keys(self):
                if isinstance(key, str) and key.lower() == lowered:
                    return key
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
        dict.__setitem__(self, name if key is None else key, value)

    def __delitem__(self, name: str) -> None:
        key = self._key(name)
        if key is None:
            raise KeyError(name)
        dict.__delitem__(self, key)

    def get(self, name: str, default: Any = None) -> Any:  # type: ignore[override]
        key = self._key(name)
        return default if key is None else dict.__getitem__(self, key)

    def pop(self, name: str, *default: Any) -> Any:  # type: ignore[override]
        key = self._key(name)
        if key is None:
            if default:
                return default[0]
            raise KeyError(name)
        return dict.pop(self, key)

    def setdefault(self, name: str, default: Any = None) -> Any:  # type: ignore[override]
        key = self._key(name)
        if key is None:
            dict.__setitem__(self, name, default)
            return default
        return dict.__getitem__(self, key)

    def update(self, data: _Source = None, **kw: List[str]) -> None:  # type: ignore[override]
        if data is not None:
            items = data.items() if isinstance(data, Mapping) else data
            for name, value in items:
                self[name] = value
        for name, value in kw.items():
            self[name] = value

    def copy(self) -> "Headers":
        return Headers(self)

    def first(self, name: str, default: str | None = None) -> str | None:
        """The first value of a header, or ``default`` — what requests'
        ``headers.get`` returns, for code that wants a string."""
        values = self.get(name)
        return values[0] if values else default
