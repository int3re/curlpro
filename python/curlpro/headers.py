"""Заголовки сессии, добавляемые ко всем последующим запросам.

Хранятся отдельно от заголовков профиля, поэтому ``clear()`` возвращает чистый
отпечаток браузера, а не обнуляет запросы целиком.

Порядок важен: новое имя уходит в конец списка, а переопределение заголовка,
который есть в профиле, меняет только значение и сохраняет его позицию.
Перенос профильного заголовка в конец сломал бы отпечаток.
"""

from __future__ import annotations

from typing import Iterator, MutableMapping

from ._ffi import _call


class SessionHeaders(MutableMapping[str, str]):
    """Словареподобный доступ к заголовкам сессии.

        s.headers["X-Api-Key"] = "secret"   # во всех последующих запросах
        del s.headers["X-Api-Key"]
        s.headers.clear()                   # остаются только профильные
    """

    __slots__ = ("_session_id", "_cache")

    def __init__(self, session_id: int):
        self._session_id = session_id
        # Значения живут на стороне Go; здесь держим только имена,
        # чтобы поддержать итерацию и len без лишних вызовов.
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
        # Значения не кешируются на стороне Python, чтобы не разойтись
        # с нативной частью; наличие проверяется по именам.
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
        """Убирает все заголовки сессии, оставляя заголовки профиля.

        Возвращает, сколько было убрано.
        """
        data = _call("curlpro_session_reset_headers", self._session_id)
        self._cache = []
        return data["removed"]

    def _names(self) -> list[str]:
        self._cache = _call("curlpro_session_headers", self._session_id)["headers"]
        return self._cache

    def __repr__(self) -> str:
        return f"<SessionHeaders {self._names()}>"
