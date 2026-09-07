"""A network identity that survives between runs.

A scraper that keeps five hundred accounts needs each of them to look like the
same machine every time: the same TLS fingerprint, the same exit address, the
same device, the same cookies. All of that already existed here — profile,
proxy, device, the cookie jar — but scattered across seven arguments, so
binding them together and storing them was the caller's problem, and every
caller solved it differently.

A persona is that binding, in one file:

    p = curlpro.Persona.new("chrome-151-windows", proxy="http://user:pass@host:8080")
    p.save("accounts/user42.json")

    p = curlpro.Persona.load("accounts/user42.json")
    with p.session() as s:
        s.get("https://example.com/")
    p.save()          # the cookies moved on; the identity did not

What it deliberately does not do is rotate anything. Choosing which persona to
use, when to retire one and how to spread them over proxies is policy, and
policy belongs to the caller — a library that decided it would be guessing.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

from .session import Session

#: The file format version. Read alongside the file rather than guessed at: a
#: persona outlives the code that wrote it, and a silent misread would restore
#: a subtly different identity, which is worse than refusing.
FORMAT = 1


class Persona:
    """One network identity: profile, exit, device, headers and cookies."""

    __slots__ = ("name", "profile", "proxy", "device", "headers", "cookies",
                 "created", "updated", "notes", "_path")

    def __init__(
        self,
        profile: str,
        *,
        name: str | None = None,
        proxy: str | None = None,
        device: str | None = None,
        headers: dict[str, str] | None = None,
        cookies: list[dict[str, Any]] | None = None,
        created: float | None = None,
        updated: float | None = None,
        notes: dict[str, Any] | None = None,
        path: str | Path | None = None,
    ):
        self.profile = profile
        self.name = name or uuid.uuid4().hex[:12]
        self.proxy = proxy
        self.device = device
        #: Session headers carried with the identity — Accept-Language above
        #: all, which is as much a part of looking consistent as the TLS is.
        self.headers = dict(headers or {})
        self.cookies = list(cookies or [])
        self.created = created if created is not None else time.time()
        self.updated = updated if updated is not None else self.created
        #: Anything the caller wants to keep next to the identity: the account
        #: it belongs to, when it was last banned, whatever. Never interpreted
        #: here.
        self.notes = dict(notes or {})
        self._path = Path(path) if path else None

    # -- creating, loading, saving ----------------------------------------

    @classmethod
    def new(cls, profile: str, **kw: Any) -> "Persona":
        """A fresh identity. The same as the constructor, named for reading."""
        return cls(profile, **kw)

    @classmethod
    def load(cls, path: str | Path) -> "Persona":
        """Reads a persona from a file."""
        p = Path(path)
        try:
            data = json.loads(p.read_text("utf-8"))
        except FileNotFoundError:
            raise FileNotFoundError(
                f"no persona at {p}: save() writes one, and load() will not "
                f"invent an identity that was never stored") from None
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{p} is not a persona file: {exc}. A truncated write leaves "
                f"exactly this, and continuing would silently start a new "
                f"identity under an old name") from None
        return cls.from_dict(data, path=p)

    @classmethod
    def from_dict(cls, data: dict[str, Any], path: str | Path | None = None) -> "Persona":
        version = data.get("version")
        if version != FORMAT:
            raise ValueError(
                f"persona format {version!r}, this build reads {FORMAT}. "
                f"Reading it anyway could restore a different identity than "
                f"the one stored, which is worse than refusing")
        if not data.get("profile"):
            raise ValueError("persona names no profile: there is no identity without one")
        return cls(
            data["profile"],
            name=data.get("name"),
            proxy=data.get("proxy") or None,
            device=data.get("device") or None,
            headers=data.get("headers"),
            cookies=data.get("cookies"),
            created=data.get("created"),
            updated=data.get("updated"),
            notes=data.get("notes"),
            path=path,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": FORMAT,
            "name": self.name,
            "profile": self.profile,
            "proxy": self.proxy,
            "device": self.device,
            "headers": dict(self.headers),
            "cookies": list(self.cookies),
            "created": self.created,
            "updated": self.updated,
            "notes": dict(self.notes),
        }

    def save(self, path: str | Path | None = None) -> Path:
        """Writes the persona, remembering where it went.

        The write is atomic: a persona is overwritten on every run, and a
        process killed mid-write would otherwise leave a truncated file — that
        is, a lost account rather than a stale one.
        """
        target = Path(path) if path else self._path
        if target is None:
            raise ValueError(
                "save() needs a path the first time; after that the persona "
                "remembers where it came from")
        target.parent.mkdir(parents=True, exist_ok=True)
        self.updated = time.time()

        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), "utf-8")
        tmp.replace(target)
        self._path = target
        return target

    # -- using it ---------------------------------------------------------

    def open(self, **overrides: Any) -> Session:
        """Opens a session wearing this identity, cookies restored.

        Overrides are passed straight to :class:`~curlpro.Session`, so anything
        not part of the identity — timeouts, retries, redirects — is set as
        usual. Overriding the identity itself is allowed too: it is the
        caller's identity to change.
        """
        kw: dict[str, Any] = {"impersonate": self.profile}
        if self.proxy:
            kw["proxy"] = self.proxy
        if self.device:
            kw["device"] = self.device
        kw.update(overrides)

        s = Session(**kw)
        try:
            for name, value in self.headers.items():
                s.headers[name] = value
            if self.cookies:
                s.cookies.load(self.cookies)
        except Exception:
            # A half-dressed session is worse than none: it would look like the
            # persona while missing its cookies, and the site would see a
            # familiar fingerprint with no login.
            s.close()
            raise
        return s

    def capture(self, session: Session) -> "Persona":
        """Takes the session's cookies back into the persona.

        Called by :meth:`session` on the way out. Separate because a long-lived
        session may want to checkpoint without closing.
        """
        self.cookies = session.cookies.export()
        return self

    def session(self, **overrides: Any) -> "_PersonaSession":
        """The identity as a context manager: dressed on entry, kept on exit.

            with p.session() as s:
                s.get("https://example.com/")
            p.save()

        The cookies are captured even when the block raises: a login half
        finished is still state, and throwing it away would make the next run
        start further back than it has to.
        """
        return _PersonaSession(self, overrides)

    def fingerprint(self, url: str = "https://example.com/") -> Any:
        """What this identity looks like on the wire, without sending anything.

        Cheap enough to assert on before a run: two personas meant to be
        different machines should not share a JA4.
        """
        with self.open() as s:
            return s.fingerprint(url)

    def __repr__(self) -> str:
        where = f" at {self._path}" if self._path else ""
        return (f"<Persona {self.name} {self.profile}"
                f"{' via proxy' if self.proxy else ''} "
                f"{len(self.cookies)} cookies{where}>")


class _PersonaSession:
    """The context manager returned by :meth:`Persona.session`."""

    __slots__ = ("_persona", "_overrides", "_session")

    def __init__(self, persona: Persona, overrides: dict[str, Any]):
        self._persona = persona
        self._overrides = overrides
        self._session: Session | None = None

    def __enter__(self) -> Session:
        self._session = self._persona.open(**self._overrides)
        return self._session

    def __exit__(self, *exc: object) -> None:
        s = self._session
        if s is None:
            return
        try:
            self._persona.capture(s)
        finally:
            s.close()


def load_all(directory: str | Path) -> Iterator[Persona]:
    """Every persona in a directory, in name order.

    A convenience for the common shape — a folder of accounts — and nothing
    more: which of them to use is not decided here.
    """
    for path in sorted(Path(directory).glob("*.json")):
        yield Persona.load(path)
