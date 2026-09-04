"""Session cookies: reading, editing, saving and loading.

Inside the client cookies live in a jar that only ever hands out the
name-value pair for one address. Here they are visible in full — domain,
path, expiry and flags — because for a scraper the point is not reading a
cookie but carrying the login into the next run.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ._ffi import _call, encode


class Cookie(dict):
    """A single cookie. A dict, so it can be serialised as it is."""

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
        """Expiry in epoch seconds; 0 means a session cookie."""
        return int(self.get("expires", 0) or 0)

    def __repr__(self) -> str:
        return f"<Cookie {self.name}={self.value!r} for {self.domain}{self.path}>"


class Cookies(Mapping[str, str]):
    """The session's cookies.

    Behaves like a name-value mapping — enough for reading — while the full
    records stay available through :meth:`export` and :meth:`all`.

        s.cookies["session_id"]          # the value
        s.cookies.set("a", "1", domain="example.com")
        s.cookies.save("state.json")     # keep it between runs
        s.cookies.load_file("state.json")
    """

    __slots__ = ("_id", "_closed")

    def __init__(self, session_id: int):
        self._id = session_id
        self._closed = False

    def _live(self) -> int:
        """The session handle, or a readable error if the session is gone.

        Without it the native part answers "session N not found": a number the
        caller never chose, for a jar that died with its session. Cookies have
        to be taken out before close() — after it there is nothing to take.
        """
        if self._closed:
            raise RuntimeError(
                "session is closed, and its cookies went with it; "
                "export them with cookies.export() before closing")
        return self._id

    # -- reading -----------------------------------------------------------

    def all(self) -> list[Cookie]:
        """The full records: domain, path, expiry, flags."""
        data = _call("curlpro_session_cookies", self._live())
        return [Cookie(c) for c in (data.get("cookies") or [])]

    def export(self) -> list[dict[str, Any]]:
        """The same as plain dicts — ready for json.dump."""
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

    # -- editing -----------------------------------------------------------

    def set(self, name: str, value: str, *, domain: str, path: str = "/",
            expires: int = 0, secure: bool = False, http_only: bool = False,
            same_site: str = "") -> None:
        """Adds a cookie. The domain is required: without it there is nobody to send it to."""
        self.load([{
            "name": name, "value": value, "domain": domain, "path": path,
            "expires": expires, "secure": secure, "http_only": http_only,
            "same_site": same_site,
        }])

    def load(self, cookies: list[Mapping[str, Any]]) -> None:
        """Loads cookies into the session: they will ride along on matching requests."""
        _call("curlpro_session_set_cookies", self._live(), encode(list(cookies)))

    def clear(self) -> None:
        """Forgets every cookie of the session."""
        _call("curlpro_session_clear_cookies", self._live())

    # -- transactions --------------------------------------------------------

    def snapshot(self) -> list[dict[str, Any]]:
        """The current cookies as plain records, ready for :meth:`restore`."""
        return self.export()

    def restore(self, snapshot: list[Mapping[str, Any]]) -> None:
        """Puts the jar back into the state a snapshot describes.

        The jar is cleared first: without that, restoring would only add, and a
        cookie the failed request created would survive the rollback.
        """
        self.clear()
        if snapshot:
            self.load(list(snapshot))

    @contextmanager
    def transaction(self) -> Iterator["Cookies"]:
        """Undoes the cookie changes if the block raises.

            with s.cookies.transaction():
                s.post(login_url, fields=creds)
                s.get(account_url).raise_for_status()

        A half-finished login is worse than none: the session looks logged in
        while the server thinks otherwise, and the next run starts from a state
        nobody planned. On success the changes stay.
        """
        saved = self.snapshot()
        try:
            yield self
        except BaseException:
            self.restore(saved)
            raise

    # -- files ---------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Saves the cookies into a JSON file."""
        Path(path).write_text(
            json.dumps(self.export(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def load_file(self, path: str | Path) -> None:
        """Loads cookies from a file: JSON or Netscape ``cookies.txt``.

        The format is recognised by content, not by name: files from curl and
        from browser extensions are called anything, but they start
        differently — JSON with a bracket, Netscape with a comment or a domain.

        A missing file is not an error: the first run of a scraper starts with
        an empty session, and checking for that in the calling code every time
        means writing the same if over and over.
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
        """Saves the cookies in the Netscape format — the one ``curl -c`` writes.

        The format is poorer than our JSON: it has no SameSite. But curl,
        wget, yt-dlp and browser extensions all read it, and for carrying a
        session into another tool that loss is usually worth it.
        """
        Path(path).write_text(self.to_netscape(), encoding="utf-8")

    def load_netscape(self, path: str | Path) -> None:
        """Loads ``cookies.txt`` without guessing from the content.

        Useful when the file is known to be in that format: :meth:`load_file`
        would treat an empty or comment-only file as Netscape anyway, but the
        explicit call reads better and fails on JSON instead of staying quiet.
        """
        p = Path(path)
        if not p.exists():
            return
        data = parse_netscape(p.read_text(encoding="utf-8"))
        if data:
            self.load(data)

    def to_netscape(self) -> str:
        """The cookies as ``cookies.txt`` text."""
        return format_netscape(self.export())


# -- the Netscape format ---------------------------------------------------
#
# Seven tab-separated fields: domain, subdomain flag, path, secure, expiry,
# name, value. The format has no HttpOnly flag, so curl marks such lines with
# a #HttpOnly_ prefix — a comment to anyone who does not know about it.

NETSCAPE_HEADER = (
    "# Netscape HTTP Cookie File\n"
    "# Written by curlpro. Same format as curl -c.\n"
    "\n"
)

_HTTP_ONLY_PREFIX = "#HttpOnly_"


def format_netscape(cookies: list[dict[str, Any]]) -> str:
    """Builds ``cookies.txt`` text out of full records."""
    lines = [NETSCAPE_HEADER]
    for c in cookies:
        domain = str(c.get("domain", ""))
        if not domain:
            continue
        # A leading dot means "subdomains too". Our cookies behave exactly
        # that way: a measurement showed a cookie for example.test also goes
        # to sub.example.test — hence the dot and the TRUE flag.
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
    """Parses ``cookies.txt``. Errors name the line number.

    Broken lines must not be skipped silently: the file usually holds the
    whole session, and a lost cookie looks like a logout rather than a
    damaged file.
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
        # Editors trim an empty trailing value together with its tab,
        # so six fields mean a cookie with an empty value.
        if len(parts) == 6:
            parts.append("")
        if len(parts) != 7:
            raise ValueError(
                f"line {number}: {len(parts)} fields, but the Netscape format has seven "
                f"(domain, subdomains, path, secure, expiry, name, value)"
            )
        domain, _subdomains, path, secure, expires, name, value = parts
        try:
            # Some extensions write the expiry with a fractional part.
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
