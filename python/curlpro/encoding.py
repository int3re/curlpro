"""Определение кодировки ответа.

Раньше ``Response.text`` всегда декодировал как UTF-8 с заменой битых байтов:
на странице в windows-1251 или shift_jis получался мусор, а таких сайтов
достаточно, чтобы парсер на этом сломался.

Порядок такой же, как у браузера: заголовок, метка порядка байтов, объявление
внутри самого документа. Сам документ смотрим последним и только в начале —
кодировка объявляется в первых килобайтах или не объявляется вовсе.
"""

from __future__ import annotations

import re

# Метки порядка байтов: если они есть, спорить не о чем.
_BOMS = (
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)

_CHARSET_IN_TYPE = re.compile(r"charset\s*=\s*\"?([\w.:+-]+)", re.I)
# <meta charset=...> и старая форма <meta http-equiv=content-type content=...>
_META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([\w.:+-]+)""", re.I)

# Сколько байт документа осматривать. HTML5 требует объявлять кодировку
# в первом килобайте; берём с запасом, но не читаем всё тело.
_SNIFF = 4096


def from_content_type(value: str | None) -> str | None:
    """Кодировка из заголовка Content-Type."""
    if not value:
        return None
    m = _CHARSET_IN_TYPE.search(value)
    if not m:
        return None
    return _normalize(m.group(1))


def from_bom(data: bytes) -> str | None:
    for bom, name in _BOMS:
        if data.startswith(bom):
            return name
    return None


def from_document(data: bytes) -> str | None:
    """Кодировка, объявленная в самом документе."""
    m = _META_CHARSET.search(data[:_SNIFF])
    if not m:
        return None
    return _normalize(m.group(1).decode("ascii", errors="ignore"))


def detect(content: bytes, content_type: str | None, default: str = "utf-8") -> str:
    """Кодировка ответа: заголовок, затем BOM, затем сам документ."""
    return (
        from_content_type(content_type)
        or from_bom(content)
        or from_document(content)
        or default
    )


def _normalize(name: str) -> str | None:
    """Приводит объявленное имя к тому, что понимает Python.

    ISO-8859-1 подменяется на windows-1252 намеренно: так требует HTML5,
    и так делают браузеры — страницы с этой меткой почти всегда содержат
    байты из диапазона 0x80–0x9F, которых в настоящем latin-1 нет.
    """
    name = name.strip().strip("\"'").lower()
    if not name:
        return None
    aliases = {
        "iso-8859-1": "windows-1252",
        "latin1": "windows-1252",
        "latin-1": "windows-1252",
        "ascii": "windows-1252",
        "us-ascii": "windows-1252",
        "utf8": "utf-8",
        "cp1251": "windows-1251",
        "win-1251": "windows-1251",
        "utf-8n": "utf-8",
    }
    name = aliases.get(name, name)
    try:
        "".encode(name)
    except LookupError:
        return None
    return name
