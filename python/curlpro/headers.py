"""Session headers, added to every later request.

They are kept apart from the profile's own headers, so ``clear()`` restores
the plain browser fingerprint instead of stripping requests bare.

Order matters: a new name goes to the end of the list, while overriding a
header the profile already sets changes only its value and keeps its
position. Moving a profile header to the end would break the fingerprint.
"""

from __future__ import annotations

from typing import Iterator, MutableMapping

from ._ffi import _call


class SessionHeaders(MutableMapping[str, str]):
    """Dict-like access to the session headers.

        s.headers["X-Api-Key"] = "secret"   # in every later request
        del s.headers["X-Api-Key"]
        s.headers.clear()                   # only profile headers remain
    """

    __slots__ = ("_session_id", "_cache")

    def __init__(self, session_id: int):
        self._session_id = session_id
        # The values live on the Go side; only the names are kept here,
        # enough to support iteration and len without extra calls.
        self._cache: list[str] = []

    def __setitem__(self, name: str, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"header value must be a string, got {type(value).__name__}")
        data = _call(
            "curlpro_session_set_header",
            self._session_id,
            name.encode("utf-8"),
            value.encode("utf-8"),
        )
        self._cache = data["headers"]

    def __delitem__(self, name: str) -> None:
        data = _call("curlpro_session_remove_header", self._session_id, name.encode("utf-8"))
        if not data["removed"]:
            raise KeyError(name)
        self._cache = data["headers"]

    def __getitem__(self, name: str) -> str:
        # Values are not cached on the Python side so they cannot drift from
        # the native ones; presence is checked by name.
        lowered = name.lower()
        for known in self._names():
            if known.lower() == lowered:
                raise KeyError(
                    f"{name}: session header values cannot be read back, "
                    "only their names are available"
                )
        raise KeyError(name)

    def __iter__(self) -> Iterator[str]:
        return iter(self._names())

    def __len__(self) -> int:
        return len(self._names())

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        lowered = name.lower()
        return any(k.lower() == lowered for k in self._names())

    def clear(self) -> int:
        """Drops every session header, keeping the profile's own.

        Returns how many were dropped.
        """
        data = _call("curlpro_session_reset_headers", self._session_id)
        self._cache = []
        return data["removed"]

    def _names(self) -> list[str]:
        self._cache = _call("curlpro_session_headers", self._session_id)["headers"]
        return self._cache

    def __repr__(self) -> str:
        return f"<SessionHeaders {self._names()}>"
