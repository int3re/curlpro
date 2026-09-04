"""Response charset detection.

``Response.text`` used to decode everything as UTF-8 with replacement, which
turned a windows-1251 or shift_jis page into garbage — and there are enough
such sites to break a scraper on.

The order is the browser's: the header, the byte order mark, then the
declaration inside the document itself. The document comes last and only its
head is read: a charset is declared in the first kilobytes or not at all.
"""

from __future__ import annotations

import re

# Byte order marks: when one is present there is nothing to argue about.
_BOMS = (
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)

_CHARSET_IN_TYPE = re.compile(r"charset\s*=\s*\"?([\w.:+-]+)", re.I)
# <meta charset=...> and the older <meta http-equiv=content-type content=...>
_META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([\w.:+-]+)""", re.I)

# How much of the document to sniff. HTML5 requires the charset to be
# declared within the first kilobyte; take a margin, but not the whole body.
_SNIFF = 4096


def from_content_type(value: str | None) -> str | None:
    """Charset from the Content-Type header."""
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
    """Charset declared inside the document itself."""
    m = _META_CHARSET.search(data[:_SNIFF])
    if not m:
        return None
    return _normalize(m.group(1).decode("ascii", errors="ignore"))


def detect(content: bytes, content_type: str | None, default: str = "utf-8") -> str:
    """Response charset: header first, then the BOM, then the document."""
    return (
        from_content_type(content_type)
        or from_bom(content)
        or from_document(content)
        or default
    )


def _normalize(name: str) -> str | None:
    """Maps a declared name onto something Python knows.

    ISO-8859-1 is deliberately replaced by windows-1252: HTML5 requires it
    and browsers do it — pages carrying that label almost always contain
    bytes in the 0x80-0x9F range, which real latin-1 does not have.
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
