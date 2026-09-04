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
        return f"<Cookie {self.name}={self.value!r} for {self.domain}{self.path}>"


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
        """Загрузить куки из файла: JSON или Netscape ``cookies.txt``.

        Формат определяется по содержимому, а не по имени: файлы от curl
        и расширений браузера называются как угодно, а вот начинаются
        по-разному — JSON со скобки, Netscape с комментария или домена.

        Отсутствие файла — не ошибка: первый запуск парсера начинается
        с пустой сессии, и проверять это каждый раз в вызывающем коде
        значит писать один и тот же if.
        """
        p = Path(path)
        if not p.exists():
            return
        text = p.read_text(encoding="utf-8")
        head = text.lstrip()[:1]
        if head in ("[", "{"):
            data = json.loads(text)
        else:
            data = parse_netscape(text)
        if data:
            self.load(data)

    def save_netscape(self, path: str | Path) -> None:
        """Сохранить куки в формате Netscape — том же, что у ``curl -c``.

        Формат беднее нашего JSON: в нём нет SameSite, — но его понимают
        curl, wget, yt-dlp и расширения браузера, и ради переноса сессии
        в чужой инструмент этой потери обычно не жалко.
        """
        Path(path).write_text(self.to_netscape(), encoding="utf-8")

    def load_netscape(self, path: str | Path) -> None:
        """Загрузить ``cookies.txt``, не гадая по содержимому.

        Нужен, когда файл заведомо в этом формате: пустой файл или файл
        из одних комментариев :meth:`load_file` принял бы за Netscape и так,
        но явный вызов читается понятнее и падает на JSON, а не молчит.
        """
        p = Path(path)
        if not p.exists():
            return
        data = parse_netscape(p.read_text(encoding="utf-8"))
        if data:
            self.load(data)

    def to_netscape(self) -> str:
        """Куки в виде текста ``cookies.txt``."""
        return format_netscape(self.export())


# -- формат Netscape -------------------------------------------------------
#
# Семь полей через табуляцию: домен, флаг поддоменов, путь, secure, срок,
# имя, значение. Флаг HttpOnly формат не предусматривает, поэтому curl
# помечает такие строки префиксом #HttpOnly_ — комментарием для тех, кто
# про него не знает.

NETSCAPE_HEADER = (
    "# Netscape HTTP Cookie File\n"
    "# Создан curlpro. Формат тот же, что у curl -c.\n"
    "\n"
)

_HTTP_ONLY_PREFIX = "#HttpOnly_"


def format_netscape(cookies: list[dict[str, Any]]) -> str:
    """Собирает текст ``cookies.txt`` из полных записей."""
    lines = [NETSCAPE_HEADER]
    for c in cookies:
        domain = str(c.get("domain", ""))
        if not domain:
            continue
        # Точка означает «и поддоменам тоже». Наши куки ведут себя именно так:
        # замер показал, что кука домена example.test уходит и на
        # sub.example.test, — поэтому домен пишется с точкой, а флаг TRUE.
        if not domain.startswith("."):
            domain = "." + domain
        prefix = _HTTP_ONLY_PREFIX if c.get("http_only") else ""
        lines.append("\t".join([
            prefix + domain,
            "TRUE",
            str(c.get("path") or "/"),
            "TRUE" if c.get("secure") else "FALSE",
            str(int(c.get("expires", 0) or 0)),
            str(c.get("name", "")),
            str(c.get("value", "")),
        ]) + "\n")
    return "".join(lines)


def parse_netscape(text: str) -> list[dict[str, Any]]:
    """Разбирает ``cookies.txt``. Ошибка называет номер строки.

    Молча пропускать кривые строки нельзя: файл обычно один на всю сессию,
    и потерянная кука выглядит как разлогин, а не как испорченный файл.
    """
    out: list[dict[str, Any]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r\n")
        http_only = line.startswith(_HTTP_ONLY_PREFIX)
        if http_only:
            line = line[len(_HTTP_ONLY_PREFIX):]
        elif line.lstrip().startswith("#"):
            continue
        if not line.strip():
            continue

        parts = line.split("\t")
        # Пустое значение в конце строки редакторы срезают вместе
        # с табуляцией — шесть полей означают куку без значения.
        if len(parts) == 6:
            parts.append("")
        if len(parts) != 7:
            raise ValueError(
                f"line {number}: {len(parts)} fields, but the Netscape format has seven "
                f"(domain, subdomains, path, secure, expiry, name, value)"
            )
        domain, _subdomains, path, secure, expires, name, value = parts
        try:
            # Некоторые расширения пишут срок с дробной частью.
            when = int(float(expires or 0))
        except ValueError:
            raise ValueError(f"line {number}: expiry {expires!r} is not a number") from None

        out.append({
            "name": name,
            "value": value,
            "domain": domain,
            "path": path or "/",
            "expires": when,
            "secure": secure.strip().upper() == "TRUE",
            "http_only": http_only,
            "same_site": "",
        })
    return out
