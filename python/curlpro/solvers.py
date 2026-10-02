"""Getting past an anti-bot's check: what a solver is, and the one shipped.

A session with a ``solver`` that meets a challenge (:mod:`curlpro.challenge`)
hands it over: the solver gets the URL to open, the session's identity and a
``verify`` callback, gets the cookies that pass the check, and the session
sends the request again with them. Any object with ``solve(request)`` is a
solver; :class:`BrowserSolver` is the one in the package.

**Why a real browser, and why ours.** A challenge is a program that measures
the browser it runs in; re-implementing it is a race lost every time the
vendor ships a new one. So the check is run by the browser the session
impersonates — Chrome or Edge installed on this machine — driven through
:mod:`curlpro.browser`, which never attaches to the page: no ``Runtime.enable``,
no script of ours in it, no automation flag (the marks that give Playwright
and Puppeteer away). Then the session goes on with that browser's own TLS and
HTTP/2 fingerprint, because its profile is that browser's: the clearance a
site gave the browser is used by a client it cannot tell from the browser.
That is what a browser-and-requests pair built on anything else cannot do,
and the solver insists on it — a session whose profile is not the browser's
version is refused rather than sent with a cookie its fingerprint betrays.

**What it does.** A check that runs unattended passes by itself. One that
wants a click — Turnstile's checkbox — gets one: when the check has not passed
within a few seconds, the solver touches the page for that moment only, finds
the check's frame through the inspector and moves the mouse to it along a
curve at a person's pace (:meth:`curlpro.browser.chrome.Page.click`). Nothing
is sent to a captcha-solving service, and a puzzle beyond a click waits for a
person in the window. A block is not a challenge and is not handed over.
"""

from __future__ import annotations

import atexit
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from .challenge import Challenge


@dataclass
class SolveRequest:
    """What a solver is handed.

    ``url`` is the page to open — the request's own for a GET, else the page
    it was made from, else the site's root. ``impersonate``, ``user_agent``
    and ``accept_language`` are the session's; ``proxy`` the proxy the
    request went through ("" for none) — the browser must use the same, the
    clearance belongs to an address. ``verify(cookies)`` loads cookies into
    the session, sends the request again and says whether it got through;
    ``timeout`` is how long the session waits.
    """

    challenge: Challenge
    url: str
    impersonate: str
    user_agent: str
    accept_language: str
    proxy: str
    verify: Callable[[list], bool]
    timeout: float = 90.0
    #: The session's identity's time zone ("" for the machine's own): the
    #: browser keeps it, as the session's languages, so the check measures
    #: the same visitor the requests describe.
    timezone: str = ""


@dataclass
class Solution:
    """What a solver got: the cookies that passed the check, and the browser
    that passed it."""

    cookies: list = field(default_factory=list)
    user_agent: str = ""
    browser: str = ""


class Solver(Protocol):
    def solve(self, request: SolveRequest) -> Optional[Solution]:
        """Passes the check, or returns None when it could not in time."""
        ...


#: The cookie each vendor's own gate sets once passed: the moment to try the
#: request again at once. Any other change of the cookies — a site's own gate
#: behind Turnstile sets its own — is tried too, at most every few seconds.
_PASS_COOKIES = {"cloudflare": ("cf_clearance",), "datadome": ("datadome",)}
_RETRY_EVERY = 2.0
#: A check asked for a click gets at most this many, this far apart: a
#: checkbox that does not take is not hammered.
_MAX_CLICKS = 3
_CLICK_AGAIN = 8.0


class BrowserSolver:
    """Passes a check in the Chrome (or Edge) installed on this machine.

    ``headless=False`` by default: a headless Chrome says ``HeadlessChrome``
    in its User-Agent, which no profile carries, and the solver refuses the
    mismatch — and a check that wants a click needs a window for a person to
    click in. ``profile_dir`` keeps the browser profile between solves (a
    browser that has been to the site before is a returning visitor); without
    it each solve starts from a fresh one. ``executable`` overrides
    ``find_chrome()``.

    Open the session with :meth:`session_options` to get the profile and the
    identity of the browser that will solve::

        solver = BrowserSolver()
        s = curlpro.Session(**solver.session_options(), solver=solver)
    """

    def __init__(self, *, headless: bool = False, profile_dir: str | None = None,
                 executable: str | None = None, poll: float = 0.5, click: bool = True,
                 click_after: float = 2.5, timeout: float | None = None,
                 keep_open: bool = False):
        if keep_open and profile_dir:
            raise ValueError("keep_open starts each solve with no cookies; profile_dir keeps "
                             "one profile for every solve — pick one")
        self.headless = headless
        #: The longest a solve waits, when shorter than the session's.
        self.timeout = timeout
        #: Keep the browser between solves — one per proxy and languages —
        #: and solve in a new tab of it, one solve at a time, the cookies
        #: cleared first: a tab instead of a browser for each solve. Close it
        #: with close(), or use the solver as a context manager.
        #:
        #: Not a context per solve (``Target.createBrowserContext``): measured
        #: on Chrome 154, a page in such a context asks for the UI locale's
        #: default languages (``ja-JP,en-US,en`` under ``--lang=ja-JP``), not
        #: the profile's — not the session's ``Accept-Language``.
        self.keep_open = keep_open
        self._shared = None
        self._shared_key: tuple = ()
        self._shared_forwarder = None
        self._shared_lock = threading.Lock()
        self._solve_lock = threading.Lock()
        self.profile_dir = profile_dir
        self.executable = executable
        self.poll = poll
        #: Click a check that asks for it (Turnstile's checkbox) when it has
        #: not passed by itself within ``click_after`` seconds. False leaves
        #: the click to a person at the window.
        self.click = click
        self.click_after = click_after

    def session_options(self) -> dict:
        """``impersonate`` and ``device`` for a session that is this browser:
        the profile of its version and the identity of its build on this
        machine. Starts the browser once to ask it."""
        from .browser import Chrome, profile_for
        from .browser.chrome import device_options
        from .profiles import get_profile, list_profiles

        with Chrome("about:blank", executable=self.executable, headless=self.headless) as chrome:
            v = chrome.version()
        name, device = profile_for(v["userAgent"], v["product"])
        if name not in list_profiles():
            raise LookupError(f"this machine's browser is {v['product']} and the package has no "
                              f"profile {name!r} for it; update curlpro, or register one")
        pool = get_profile(name).data.get("devices") or []
        return {"impersonate": name, **device_options(device, pool)}

    def solve(self, request: SolveRequest) -> Optional[Solution]:
        from .browser import Chrome, Forwarder

        tz = request.timezone
        if self.keep_open:
            with self._solve_lock:
                chrome = self._browser(request.accept_language, request.proxy)
                v = chrome.version()
                self._same_browser(v, request)
                chrome.send("Storage.clearCookies")
                tab, page = chrome.go(request.url, timezone=tz)
                try:
                    return self._wait(chrome, request, v, tab)
                finally:
                    if page is not None:
                        page.close()
                    chrome.close_tab(tab)
        forwarder = None
        proxy = request.proxy
        if proxy and "@" in proxy.split("://", 1)[-1]:
            forwarder = Forwarder(proxy)
            proxy = forwarder.address
        page = None
        try:
            # Without a zone to set, the page opens from the command line, as
            # a person opens it, and nothing is attached; with one, the first
            # tab is attached before its page loads.
            with Chrome("about:blank" if tz else request.url, executable=self.executable, proxy=proxy,
                        headless=self.headless, profile_dir=self.profile_dir,
                        accept_language=request.accept_language) as chrome:
                v = chrome.version()
                self._same_browser(v, request)
                tab = chrome.pages()[0]["targetId"]
                if tz:
                    tab, page = chrome.go(request.url, timezone=tz, tab=tab)
                try:
                    return self._wait(chrome, request, v, tab)
                finally:
                    if page is not None:
                        page.close()
        finally:
            if forwarder is not None:
                forwarder.close()

    @staticmethod
    def _same_browser(v: dict, request: SolveRequest) -> None:
        """Refuses a session whose fingerprint is not the solving browser's."""
        from .browser.chrome import same_browser

        same_browser(v, request.user_agent, request.impersonate)

    def _browser(self, accept_language: str, proxy: str):  # noqa: ANN202 — Chrome
        """The browser kept open between solves, started on first use and
        again when it died or a session asks for other languages or another
        proxy — both are the browser's own, set when it starts."""
        from .browser import Chrome, Forwarder

        with self._shared_lock:
            c = self._shared
            if c is not None and c.alive and self._shared_key == (accept_language, proxy):
                return c
            self._close_shared()
            route = proxy
            if proxy and "@" in proxy.split("://", 1)[-1]:
                self._shared_forwarder = Forwarder(proxy)
                route = self._shared_forwarder.address
            self._shared = Chrome("about:blank", executable=self.executable, headless=self.headless,
                                  proxy=route, accept_language=accept_language)
            self._shared_key = (accept_language, proxy)
            if not getattr(self, "_atexit", False):
                atexit.register(self.close)
                self._atexit = True
            return self._shared

    def _close_shared(self) -> None:
        if self._shared is not None:
            self._shared.close()
            self._shared = None
        if self._shared_forwarder is not None:
            self._shared_forwarder.close()
            self._shared_forwarder = None

    def close(self) -> None:
        """Closes the browser kept open between solves (keep_open)."""
        with self._shared_lock:
            self._close_shared()

    def __enter__(self) -> "BrowserSolver":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _wait(self, chrome, request: SolveRequest, version: dict,  # noqa: ANN001
              tab: str) -> Optional[Solution]:
        want = set(_PASS_COOKIES.get(request.challenge.vendor, ()))
        limit = request.timeout if self.timeout is None else min(request.timeout, self.timeout)
        deadline = time.monotonic() + limit
        tried: set = set()
        last = 0.0
        clicks, next_click = 0, time.monotonic() + self.click_after
        while time.monotonic() < deadline:
            time.sleep(self.poll)
            cookies = chrome.cookies()
            key = frozenset((c["name"], c["value"], c["domain"]) for c in cookies)
            passed = bool(want & {c["name"] for c in cookies})
            if cookies and key not in tried and (passed or time.monotonic() - last >= _RETRY_EVERY):
                tried.add(key)
                last = time.monotonic()
                if request.verify(cookies):
                    return Solution(cookies, version["userAgent"], version["product"])
            if self.click and clicks < _MAX_CLICKS and time.monotonic() >= next_click:
                # The check has not passed by itself: if it is one that asks
                # for a click, the page is touched for that moment only.
                clicked = False
                if any(t["targetId"] == tab for t in chrome.pages()):
                    with chrome.page(tab) as page:
                        clicked = page.click_check()
                    if clicked:
                        clicks += 1
                next_click = time.monotonic() + (_CLICK_AGAIN if clicked else 2.0)
        return None
