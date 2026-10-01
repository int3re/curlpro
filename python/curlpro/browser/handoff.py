"""A session opened in the browser it impersonates, and back again.

Some steps of a job need a browser — a login with a second factor, a page that
must run, a person's eye — and the rest are requests. :class:`Handoff` opens
the Chrome installed here as the session: the same version as its profile
(refused otherwise), the session's proxy, languages and time zone, and its
cookies, partitioned ones in their partitions. Whatever the browser does is
then the session's: the cookies come back into it on :meth:`Handoff.sync` and
when the handoff closes, and :meth:`Handoff.local_storage` reads the tokens a
single-page app keeps there. The session goes on with the browser's own
network fingerprint, so a site that saw the browser sees the same client.
"""

from __future__ import annotations

import time
from typing import Any

from .chrome import Chrome, same_browser
from .forward import Forwarder


class Handoff:
    """The session in its browser. Use as a context manager::

        with s.browser("https://example.com/login") as b:
            b.wait()              # until the window is closed
        s.get("https://example.com/account")   # with what the browser got
    """

    def __init__(self, session: Any, url: str = "", *, headless: bool = False,
                 executable: str | None = None, profile_dir: str | None = None):
        self._session = session
        probe = url or "https://example.com/"
        sent = {k.lower(): v for k, v in session.headers_for("GET", probe).items()}
        route = session._route(probe, None)
        proxy = session._proxy if route is None else (route or "")
        self._forwarder = None
        if proxy and "@" in proxy.split("://", 1)[-1]:
            self._forwarder = Forwarder(proxy)
            proxy = self._forwarder.address
        identity = getattr(session, "identity", None)
        zone = identity.timezone if identity is not None else ""
        self.chrome: Chrome | None = None
        self._last: list = []
        self._page = None
        try:
            self.chrome = Chrome("about:blank", executable=executable, proxy=proxy, headless=headless,
                                 profile_dir=profile_dir, accept_language=sent.get("accept-language", ""))
            same_browser(self.chrome.version(), sent.get("user-agent", ""), session.impersonate)
            # The cookies first, then the page: its first request carries them.
            self.chrome.set_cookies(session.cookies.export())
            tab = self.chrome.pages()[0]["targetId"]
            if url:
                _, self._page = self.chrome.go(url, timezone=zone, tab=tab)
            elif zone:
                self._page = self.chrome.page(tab)
                self._page.send("Emulation.setTimezoneOverride", timezoneId=zone)
        except BaseException:
            self.close(sync=False)
            raise

    def _live(self) -> Chrome:
        if self.chrome is None:
            raise RuntimeError("the browser of this handoff is closed")
        return self.chrome

    def sync(self) -> int:
        """Loads the browser's cookies into the session; returns how many."""
        cookies = self._live().cookies()
        self._last = cookies
        if cookies:
            self._session.cookies.load(cookies)
        return len(cookies)

    def push(self) -> None:
        """Puts the session's cookies — what its requests got since — into
        the browser."""
        self._live().set_cookies(self._session.cookies.export())

    def local_storage(self, origin: str) -> dict:
        """The ``localStorage`` of ``origin`` (``https://example.com``) — where
        single-page apps keep their tokens — read through the inspector,
        without a script in the page."""
        chrome = self._live()
        tabs = chrome.pages()
        if not tabs:
            return {}
        key = origin.rstrip("/") + "/"
        with chrome.page(tabs[0]["targetId"]) as p:
            try:
                got = p.send("DOMStorage.getDOMStorageItems",
                             storageId={"storageKey": key, "isLocalStorage": True})
            except RuntimeError:
                got = p.send("DOMStorage.getDOMStorageItems",
                             storageId={"securityOrigin": origin.rstrip("/"), "isLocalStorage": True})
        return {k: v for k, v in got.get("entries", [])}

    def wait(self, timeout: float | None = None, poll: float = 1.0) -> None:
        """Waits until the browser's window is closed (or ``timeout`` runs
        out), keeping the session's cookies up to date as it goes: once the
        last window closes the browser is gone, and so is what it held."""
        deadline = None if timeout is None else time.monotonic() + timeout
        chrome = self._live()
        while chrome.alive and (deadline is None or time.monotonic() < deadline):
            try:
                if not chrome.pages():
                    break
                self.sync()
            except (OSError, RuntimeError, ConnectionError):
                break
            time.sleep(poll)

    def close(self, sync: bool = True) -> None:
        """Brings the cookies back into the session and closes the browser."""
        if self.chrome is not None:
            if sync and self.chrome.alive:
                try:
                    self.sync()
                except (OSError, RuntimeError, ConnectionError):
                    pass
            elif sync and self._last:
                self._session.cookies.load(self._last)
            if self._page is not None:
                self._page.close()
                self._page = None
            self.chrome.close()
            self.chrome = None
        if self._forwarder is not None:
            self._forwarder.close()
            self._forwarder = None

    def __enter__(self) -> "Handoff":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
