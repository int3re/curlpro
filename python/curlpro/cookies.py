"""Куки сессии: просмотр, изменение, сохранение и загрузка.

Внутри клиента куки живут в банке, которая наружу отдаёт только пару
«имя-значение» для конкретного адреса. Здесь они видны целиком — с доменом,
путём, сроком и флагами, — потому что для парсера главное не прочитать куку,
а перенести авторизацию в следующий запуск.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from ._ffi import _call, encode


class Cookie(dict):
    """Одна кука. Словарь, чтобы её можно было сразу сериализовать."""

    __slots__ = ()

    @property
    def name(self) -> str:
        return self["name"]

    @property
    def value(self) -> str:
        return self["value"]

    @property
    def domain(self) -> str:
        return self.get("domain", "")

    @property
    def path(self) -> str:
        return self.get("path", "/")

    @property
    def expires(self) -> int:
        """Момент истечения в секундах эпохи; 0 — кука сеанса."""
        return int(self.get("expires", 0) or 0)

    def __repr__(self) -> str:
        return f"<Cookie {self.name}={self.value!r} для {self.domain}{self.path}>"


class Cookies(Mapping[str, str]):
    """Куки сессии.

    Ведёт себя как словарь имя-значение — этого хватает для чтения, — но
    полные записи доступны через :meth:`export` и :meth:`all`.

        s.cookies["session_id"]          # значение
        s.cookies.set("a", "1", domain="example.com")
        s.cookies.save("state.json")     # сохранить между запусками
        s.cookies.load_file("state.json")
    """

    __slots__ = ("_id",)

    def __init__(self, session_id: int):
        self._id = session_id

    # -- чтение ------------------------------------------------------------

    def all(self) -> list[Cookie]:
        """Полные записи: домен, путь, срок, флаги."""
        data = _call("curlpro_session_cookies", self._id)
        return [Cookie(c) for c in (data.get("cookies") or [])]

    def export(self) -> list[dict[str, Any]]:
        """То же в виде обычных словарей — для json.dump."""
        return [dict(c) for c in self.all()]

    def __getitem__(self, name: str) -> str:
        for c in self.all():
            if c.name == name:
                return c.value
        raise KeyError(name)

    def __iter__(self) -> Iterator[str]:
        return iter([c.name for c in self.all()])

    def __len__(self) -> int:
        return len(self.all())

    def __repr__(self) -> str:
        items = ", ".join(f"{c.name}={c.value!r}" for c in self.all())
        return f"<Cookies {items}>"

    # -- изменение ---------------------------------------------------------

    def set(self, name: str, value: str, *, domain: str, path: str = "/",
            expires: int = 0, secure: bool = False, http_only: bool = False,
            same_site: str = "") -> None:
        """Добавить куку. Домен обязателен: без него некому её слать."""
        self.load([{
            "name": name, "value": value, "domain": domain, "path": path,
            "expires": expires, "secure": secure, "http_only": http_only,
            "same_site": same_site,
        }])

    def load(self, cookies: list[Mapping[str, Any]]) -> None:
        """Загрузить куки в сессию: они пойдут в подходящие запросы."""
        _call("curlpro_session_set_cookies", self._id, encode(list(cookies)))

    def clear(self) -> None:
        """Забыть все куки сессии."""
        _call("curlpro_session_clear_cookies", self._id)

    # -- файлы -------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Сохранить куки в файл JSON."""
        Path(path).write_text(
            json.dumps(self.export(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def load_file(self, path: str | Path) -> None:
        """Загрузить куки из файла, сохранённого :meth:`save`.

        Отсутствие файла — не ошибка: первый запуск парсера начинается
        с пустой сессии, и проверять это каждый раз в вызывающем коде
        значит писать один и тот же if.
        """
        p = Path(path)
        if not p.exists():
            return
        data = json.loads(p.read_text(encoding="utf-8"))
        if data:
            self.load(data)
