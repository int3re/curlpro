"""The Chrome on this machine, started for one job and driven as little as
can be.

What gives an automated browser away today is less its properties than its
control channel. Playwright and Puppeteer attach to every page and switch the
DevTools Runtime domain on in each frame, and a page notices: an object it
logs is serialised by the inspector, a getter on it runs, and the page knows
someone is listening (the "Runtime.enable leak" anti-bots look for). They add
init scripts, isolated worlds and ``--enable-automation`` on top.

This module does none of it. Chrome starts with the URL on its command line,
as if a person had opened it; the only DevTools connection is the browser's
own endpoint, and it sends three commands: ``Browser.getVersion``,
``Target.getTargets`` (the open tabs' URLs and titles) and
``Storage.getCookies``. No page is attached to, no domain enabled, no script
run in the page — there is nothing for it to see. When a check wants a click,
the tab is attached for that moment only (:class:`Page`): the inspector reads
the DOM, shadow roots included, and the Input domain moves the mouse — events
the page receives as trusted ones — still without the Runtime domain and
without a script of ours; then the session is detached.

The flags are the ones a page cannot observe: a profile directory of its own,
the DevTools port (0 — Chrome picks one and writes it into the profile), no
first-run screens — and the one it could, ``navigator.webdriver``, which the
DevTools port switches on, switched back off (see the comment at the flags).

The leak probes anti-bots published against Runtime.enable (an Error whose
``stack`` getter the inspector reads, an object with a Proxy prototype it
walks) read the same in Chrome 154 with an inspector attached and without one
— measured on the solver stand, with the inspector proven attached by its
console events. They are not the reason for not attaching; not attaching is
simply the one state no probe can tell from a person's browser.

A proxy goes in as ``--proxy-server``; one with credentials through a local
forwarder that adds them (forward.py), since Chrome takes none on its command
line.
"""

from __future__ import annotations

import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ._ws import WS, WSClosed

_CANDIDATES = {
    "win32": [
        r"{ProgramFiles}\Google\Chrome\Application\chrome.exe",
        r"{ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        r"{LocalAppData}\Google\Chrome\Application\chrome.exe",
        r"{ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        r"{ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
    ],
    "darwin": [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ],
    "linux": ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"],
}


#: Flags that spare the machine without changing what a page reads: no
#: extensions, no background networking, no component updates, sync, default
#: apps or pings, no translate, optimization-guide or media-router services.
#: Measured one by one and together on the stand's fingerprint page (22
#: values: plugins, window.chrome, WebGL, client hints, quota, permissions,
#: media devices...): every value the same as Chrome started plain, where
#: --disable-gpu, the control, changed WebGL at once. At start they cost 30 MB
#: and one to three processes less (544 MB and 10 processes against 572 MB and
#: 11–13); over a browser's life they keep it from downloading components and
#: models and from talking to Google in the background. Left out on purpose:
#: --disable-site-isolation-trials, invisible but a browser visiting other
#: people's sites should keep its Spectre isolation.
LIGHT_FLAGS = (
    "--disable-extensions", "--disable-background-networking", "--disable-component-update",
    "--disable-default-apps", "--disable-sync", "--no-pings",
    "--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider,"
    "AutofillServerCommunication",
)


#: Which GPU the browser renders on: "" leaves it to Windows and Chrome (the
#: integrated one, on a laptop that has both), "high-performance" asks for the
#: discrete one through --force-high-performance-gpu — a switch Chromium
#: declares in gpu/config/gpu_switches.cc and that works on Windows, not only
#: on the Macs it was written for. Measured on a laptop with an Intel Iris Xe
#: and an RTX 4050, Chrome 154: of 368 values a page reads, 17 moved — the
#: WebGL vendor and renderer strings, four uniform limits ANGLE trims on
#: NVIDIA, and every pixel drawn, canvas 2D and WebGL alike — and nothing else,
#: the window's chrome included. That is the point: each GPU is a complete,
#: consistent identity, pixels and strings from the same card, which no
#: patched WebGL string can be. There is no switch for the opposite direction.
GPUS = ("", "high-performance")


_LEFT_BEHIND: list = []


def _remove_at_exit(directory: Path) -> None:
    """A profile a slow-dying browser still held when it was closed: removed
    when the process exits, by which time the browser is long gone."""
    if not _LEFT_BEHIND:
        import atexit
        atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _LEFT_BEHIND])
    _LEFT_BEHIND.append(directory)


def _merge_features(args: list[str]) -> list[str]:
    """One ``--disable-features`` and one ``--enable-features``, with every
    name given: Chrome keeps only the last of a repeated switch, so the light
    list would cancel the occlusion switch, and a caller's own list both."""
    names: dict[str, list[str]] = {}
    out: list[str] = []
    for a in args:
        key, sep, value = a.partition("=")
        if sep and key in ("--disable-features", "--enable-features"):
            if key not in names:
                names[key] = []
                out.append(key)
            names[key].extend(n for n in value.split(",") if n and n not in names[key])
        else:
            out.append(a)
    return [f"{a}={','.join(names[a])}" if a in names else a for a in out]


def find_chrome() -> str | None:
    """The browser to start: ``CURLPRO_CHROME`` if set, else an installed
    Chrome, else an installed Edge. None when there is neither."""
    if env := os.environ.get("CURLPRO_CHROME"):
        return env
    key = "win32" if sys.platform == "win32" else "darwin" if sys.platform == "darwin" else "linux"
    for raw in _CANDIDATES[key]:
        if key == "linux":
            if found := shutil.which(raw):
                return found
            continue
        path = raw
        for var in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
            path = path.replace("{" + var + "}", os.environ.get(var, ""))
        if Path(path).is_file():
            return path
    return None



def chrome_proxy(proxy: str) -> str:
    """The proxy address as Chrome's --proxy-server reads it, or ValueError.

    Chrome knows http, https, socks4, socks and socks5 (net/base/
    proxy_string_util.cc). Anything else is not an error there: the entry is
    "silently discarded" (net/proxy_resolution/proxy_list.cc), an empty list is
    UseDirect(), and the browser goes out from this machine's own address --
    the one the proxy was there to hide. So an unknown scheme is refused here.

    socks5h:// is the one with an exact equivalent, and it is translated rather
    than refused: the h asks the proxy to resolve the name, and Chrome's SOCKS5
    client always does that, sending the host as a domain (kEndPointDomain in
    net/socket/socks5_client_socket.cc). Until this existed a socks5h:// session
    opened in a browser went direct.
    """
    scheme, sep, rest = proxy.partition("://")
    if not sep:
        return proxy  # a bare host:port, which Chrome reads as http
    low = scheme.lower()
    if low == "socks5h":
        return "socks5://" + rest
    if low in ("http", "https", "socks4", "socks", "socks5"):
        return proxy
    raise ValueError(
        f"a browser cannot use a {scheme}:// proxy: Chrome's --proxy-server takes http, "
        "https, socks4 and socks5, and goes direct past anything else -- from this "
        "machine's own address. Give the browser an http://, https:// or socks5:// "
        "address; a masque:// proxy serves requests, not a browser")

def fingerprint_switch(profile) -> str:
    """The device profile as the patched build takes it: compact JSON, base64.

    ``profile`` is a dict or the path of a ``.profile.json`` written by
    ``scripts/fpcapture.py -profile``. Base64 because a JSON value's quotes and
    spaces through Windows command-line quoting is a parser bug waiting to
    happen (chromium/DESIGN.md); the encoding must stay byte for byte the one
    fpcapture writes, which a test holds it to.
    """
    import base64
    if not isinstance(profile, dict):
        profile = json.loads(Path(profile).read_text(encoding="utf-8"))
    compact = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(compact).decode("ascii")


class Chrome:
    """A Chrome started on ``url`` with a profile of its own.

    ``proxy`` is passed as is (``http://host:port``, ``socks5://host:port``);
    one with credentials must go through :class:`~curlpro.browser.forward.Forwarder`
    first. ``accept_language`` (the header's value) is written into the new
    profile, so the browser asks for the languages the session asks for.
    ``profile_dir`` keeps the profile between runs — a browser that has been
    to a site before looks like one; without it a temporary profile is made
    and removed on close. ``gpu="high-performance"`` runs the page on the
    machine's discrete GPU where Windows would pick the integrated one — a
    second, genuine identity on a dual-GPU machine (see :data:`GPUS`).
    ``light`` (on by default) adds :data:`LIGHT_FLAGS`;
    ``extra_args`` are added last, unmeasured — each flag is a possible mark;
    a ``--disable-features`` list among them is merged with the driver's own.
    ``fingerprint`` is a device profile — a ``.profile.json`` from
    ``scripts/fpcapture.py -profile``, or its dict — for the patched build
    (``chromium/``): it then reports that device's WebGL strings and limits,
    its fonts and its browser brand. A stock Chrome ignores the switch, and
    raises no infobar for it, since only listed flags do. Use as a context
    manager.
    """

    def __init__(self, url: str, *, executable: str | None = None, proxy: str = "",
                 headless: bool = False, profile_dir: str | os.PathLike[str] | None = None,
                 accept_language: str = "", window_size: tuple[int, int] = (1280, 860),
                 timeout: float = 30.0, extra_args: tuple = (), light: bool = True,
                 gpu: str = "", fingerprint=None):
        if gpu not in GPUS:
            raise ValueError(f"gpu must be one of {GPUS!r}, not {gpu!r}")
        exe = executable or find_chrome()
        if not exe:
            raise FileNotFoundError(
                "no Chrome or Edge found on this machine: install one, or point "
                "CURLPRO_CHROME (or executable=) at its binary")
        self._own_dir = profile_dir is None
        self.profile_dir = Path(profile_dir) if profile_dir else Path(tempfile.mkdtemp(prefix="curlpro-chrome-"))
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        port_file = self.profile_dir / "DevToolsActivePort"
        if port_file.exists():
            port_file.unlink()
        langs = [p.split(";", 1)[0].strip() for p in accept_language.split(",") if p.strip()]
        prefs = self.profile_dir / "Default" / "Preferences"
        if langs and not prefs.exists():
            # Chrome builds Accept-Language and navigator.languages from this
            # list, with its own q-values: "ru-RU,ru,en-US,en" goes out as
            # "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7".
            prefs.parent.mkdir(parents=True, exist_ok=True)
            prefs.write_text(json.dumps({"intl": {"accept_languages": ",".join(langs)}}), encoding="utf-8")
        args = [exe, f"--user-data-dir={self.profile_dir}", "--remote-debugging-port=0",
                # The DevTools port alone sets navigator.webdriver in Chrome
                # 154 (measured on the solver stand): a page reads one
                # property and knows. This turns the automation-controlled
                # feature off, and with it the flag. On its own it costs an
                # "unsupported command-line flag" infobar — the window's
                # chrome measured 151 px against 95 — which --test-type
                # suppresses: both together left 95 px and webdriver false.
                "--disable-blink-features=AutomationControlled", "--test-type",
                # A window covered by another one is "occluded" to Windows
                # Chrome, and its renderer stops acknowledging input: every
                # Input.dispatchMouseEvent of a click then waited out its 5 s,
                # and the Turnstile check was missed in roughly one run in
                # three. With occlusion off, 6 of 6 runs clicked at once. The
                # page reads "visible", as it does for the person who clicks;
                # the fingerprint page's 26 values were the same with these
                # two switches and without them, in 8 starts of 8.
                "--disable-features=CalculateNativeWinOcclusion",
                "--disable-backgrounding-occluded-windows",
                "--no-first-run", "--no-default-browser-check",
                f"--window-size={window_size[0]},{window_size[1]}"]
        if langs:
            args.append(f"--lang={langs[0]}")
        if proxy:
            args.append(f"--proxy-server={chrome_proxy(proxy)}")
            # WebRTC would otherwise offer the machine's own address next to
            # the proxy's: two addresses for one visitor.
            args.append("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        if headless:
            args.append("--headless=new")
        if gpu == "high-performance":
            args.append("--force-high-performance-gpu")
        if fingerprint is not None:
            # Windows caps a whole command line at 32,767 characters; a
            # measured profile is about 7,500 (157 fonts), so this is room
            # to spare, but a profile past it is refused here rather than
            # truncated by the system into a different device.
            switch = f"--curlpro-fingerprint={fingerprint_switch(fingerprint)}"
            if len(switch) > 30000:
                raise ValueError(f"the device profile is {len(switch)} characters on the "
                                 "command line, past what Windows passes whole")
            args.append(switch)
        if light:
            args.extend(LIGHT_FLAGS)
        # The caller's own, last: each flag is a possible mark, measured or not.
        args.extend(extra_args)
        args = _merge_features(args)
        args.append(url)
        self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      stdin=subprocess.DEVNULL)
        self._ws: WS | None = None
        self._next = 0
        # One command at a time on the one connection: solves from several
        # threads share a browser that is kept open.
        self._lock = threading.Lock()
        #: The languages the browser was started with, as the header says them.
        self.accept_language = accept_language
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"Chrome exited at start with code {self._proc.returncode} ({exe})")
            try:
                port, path = port_file.read_text(encoding="utf-8").split("\n")[:2]
                self._ws = WS(f"ws://127.0.0.1:{int(port)}{path.strip()}")
                break
            except (FileNotFoundError, ValueError, ConnectionError, OSError):
                time.sleep(0.1)
        if self._ws is None:
            self.close()
            raise TimeoutError(f"Chrome did not open its DevTools port within {timeout:g} s")

    def send(self, method: str, _session: str = "", **params: Any) -> dict:
        """One DevTools command and its result: on the browser's own endpoint,
        or on a page's session when ``_session`` names one."""
        with self._lock:
            if self._ws is None:
                raise WSClosed("the browser is closed")
            self._next += 1
            mine = self._next
            msg: dict = {"id": mine, "method": method, "params": params}
            if _session:
                msg["sessionId"] = _session
            self._ws.send(json.dumps(msg))
            while True:
                msg = json.loads(self._ws.recv())
                if msg.get("id") != mine:
                    continue  # an event; none is subscribed to, but a browser may send some
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error'].get('message', msg['error'])}")
                return msg.get("result", {})

    def version(self) -> dict:
        """``product`` (``Chrome/154.0.8037.58``) and ``userAgent``, among others."""
        return self.send("Browser.getVersion")

    def pages(self, context: str = "") -> list[dict]:
        """The open tabs — of one context when ``context`` names it — their
        ``url`` and ``title``, read without attaching."""
        return [t for t in self.send("Target.getTargets").get("targetInfos", [])
                if t.get("type") == "page" and (not context or t.get("browserContextId") == context)]

    def cookies(self, context: str = "") -> list[dict]:
        """Every cookie of the profile, or of one context, in the package's
        record form."""
        params = {"browserContextId": context} if context else {}
        return [to_record(c) for c in self.send("Storage.getCookies", **params).get("cookies", [])]

    def new_context(self, proxy: str = "") -> str:
        """A context of its own in this browser — cookies, cache, storage and
        proxy apart from every other — for one identity. A page in it reads
        the same storage quota as in the browser's own profile (10 GiB both,
        measured on Chrome 154), so it is not told for an incognito one by
        that. Costs about 0.5 s and 130–170 MB with a page open, where a new
        browser costs 0.9 s and 440 MB. But its pages ask for the UI locale's
        default languages, not the profile's (measured: ``ja-JP,en-US,en``
        where the profile said ``ja-JP,ja,en-US,en``) — so a session's
        languages hold in the browser's own profile, not in a context."""
        # The same rules as the command line: CDP hands proxyServer to the
        # same parser, which drops what it does not know and goes direct.
        params = {"proxyServer": chrome_proxy(proxy)} if proxy else {}
        return self.send("Target.createBrowserContext", **params)["browserContextId"]

    def open(self, url: str, context: str = "") -> str:
        """A new tab on ``url`` — in ``context`` when given — as a person opens
        one; returns its target id. Nothing is attached to it."""
        params = {"browserContextId": context} if context else {}
        return self.send("Target.createTarget", url=url, **params)["targetId"]

    def go(self, url: str, *, context: str = "", timezone: str = "",
           tab: str = "") -> "tuple[str, Page | None]":
        """Opens ``url`` in ``tab`` (a new tab when empty, in ``context``
        when given) and returns the tab's id and, with a ``timezone``, the
        :class:`Page` that holds it: the tab is attached before its page
        loads and the zone set on it (``Emulation.setTimezoneOverride``),
        which lasts while the Page stays open, through navigations, for the
        page and every worker of it (measured: dedicated, shared and service
        workers alike). Without a zone nothing stays attached."""
        if not timezone:
            if tab:
                with self.page(tab) as p:
                    p.send("Page.navigate", url=url)
                return tab, None
            return self.open(url, context), None
        target = tab or self.open("about:blank", context)
        page = self.page(target)
        try:
            page.send("Emulation.setTimezoneOverride", timezoneId=timezone)
        except RuntimeError as e:
            page.close()
            raise ValueError(f"time zone {timezone!r}: {e}") from None
        page.send("Page.navigate", url=url)
        return target, page

    def close_tab(self, target: str) -> None:
        try:
            self.send("Target.closeTarget", targetId=target)
        except (RuntimeError, OSError, WSClosed):
            pass

    def set_cookies(self, records: list, context: str = "") -> None:
        """Puts cookie records — a session's, in the package's form — into
        the browser, or into one of its contexts."""
        cookies = [to_devtools(r) for r in records]
        if cookies:
            params = {"browserContextId": context} if context else {}
            self.send("Storage.setCookies", cookies=cookies, **params)

    def drop_context(self, context: str) -> None:
        """Closes a context's tabs and forgets everything it held."""
        try:
            self.send("Target.disposeBrowserContext", browserContextId=context)
        except (RuntimeError, OSError, WSClosed):
            pass

    @property
    def alive(self) -> bool:
        return self._ws is not None and self._proc.poll() is None

    def page(self, target_id: str) -> "Page":
        """A session on one tab, for the moments the page must be touched —
        a click. Close it as soon as the moment is over."""
        sid = self.send("Target.attachToTarget", targetId=target_id, flatten=True)["sessionId"]
        return Page(self, sid)

    def close(self) -> None:
        if self._ws is not None:
            try:
                self.send("Browser.close")
            except (OSError, RuntimeError, WSClosed):
                pass
            with self._lock:
                if self._ws is not None:
                    self._ws.close()
                    self._ws = None
        # Closing must not fail. Chrome 154 on Windows usually exits 0.1-0.2 s
        # after Browser.close, but about one close in twenty took 9.5 s, and in
        # a suite run some outlived TerminateProcess by more than ten seconds
        # as well. This used to raise TimeoutExpired out of __exit__ — so a
        # solve that had already passed reached its caller as an exception
        # that was not even a ChallengeError. A process that will not die in
        # time is left to die on its own, and its profile is removed at exit.
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        if self._own_dir:
            # Chrome's helpers may hold a file a moment after the main process
            # is gone; Windows refuses to delete it meanwhile.
            for _ in range(20):
                shutil.rmtree(self.profile_dir, ignore_errors=True)
                if not self.profile_dir.exists():
                    break
                time.sleep(0.25)
            if self.profile_dir.exists():
                _remove_at_exit(self.profile_dir)

    def __enter__(self) -> "Chrome":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


#: The frames an interactive check lives in, by where they come from.
CHECK_FRAMES = ("challenges.cloudflare.com",)


class Page:
    """A tab, touched through DevTools without its Runtime: the DOM is read by
    the inspector (shadow roots, closed ones included, pierced), input goes
    through the Input domain — events the page receives as trusted ones, as
    from a real mouse — and no script of ours runs in it."""

    def __init__(self, chrome: Chrome, session: str):
        self._chrome = chrome
        self._session = session
        # Where the pointer is: a person's mouse is somewhere already.
        self._x, self._y = random.uniform(500, 900), random.uniform(350, 600)

    def send(self, method: str, **params: Any) -> dict:
        return self._chrome.send(method, _session=self._session, **params)

    def frames(self, sources: tuple = CHECK_FRAMES) -> list[tuple[float, float, float, float]]:
        """The boxes (left, top, width, height) of the iframes whose address
        holds one of ``sources``, on the page and in its shadow roots."""
        root = self.send("DOM.getDocument", depth=-1, pierce=True)["root"]
        found: list = []

        def walk(n: dict) -> None:
            if n.get("nodeName") == "IFRAME":
                a = n.get("attributes", [])  # name, value, name, value...
                src = next((a[i + 1] for i in range(0, len(a) - 1, 2) if a[i] == "src"), "")
                if any(s in src for s in sources):
                    found.append(n["nodeId"])
            for child in n.get("children", []) + n.get("shadowRoots", []):
                walk(child)

        walk(root)
        boxes = []
        for nid in found:
            try:
                q = self.send("DOM.getBoxModel", nodeId=nid)["model"]["border"]
            except RuntimeError:
                continue  # not rendered
            xs, ys = q[0::2], q[1::2]
            w, h = max(xs) - min(xs), max(ys) - min(ys)
            if w > 0 and h > 0:
                boxes.append((min(xs), min(ys), w, h))
        return boxes

    def click(self, x: float, y: float) -> None:
        """Moves the pointer to (x, y) along a curve, at a person's pace, and
        clicks: a check that measures the way to its checkbox sees a hand."""
        sx, sy = self._x, self._y
        # A cubic Bézier with the control points off the straight line.
        c1 = (sx + (x - sx) * random.uniform(0.2, 0.4) + random.uniform(-80, 80),
              sy + (y - sy) * random.uniform(0.2, 0.4) + random.uniform(-80, 80))
        c2 = (sx + (x - sx) * random.uniform(0.6, 0.8) + random.uniform(-40, 40),
              sy + (y - sy) * random.uniform(0.6, 0.8) + random.uniform(-40, 40))
        steps = random.randint(22, 38)
        duration = random.uniform(0.35, 0.8)
        for i in range(1, steps + 1):
            t = i / steps
            t = t * t * (3 - 2 * t)  # slow at both ends, as a hand moves
            u = 1 - t
            px = u ** 3 * sx + 3 * u * u * t * c1[0] + 3 * u * t * t * c2[0] + t ** 3 * x
            py = u ** 3 * sy + 3 * u * u * t * c1[1] + 3 * u * t * t * c2[1] + t ** 3 * y
            self.send("Input.dispatchMouseEvent", type="mouseMoved", x=px, y=py, button="none",
                      pointerType="mouse")
            time.sleep(duration / steps * random.uniform(0.6, 1.4))
        time.sleep(random.uniform(0.08, 0.25))
        self.send("Input.dispatchMouseEvent", type="mousePressed", x=x, y=y, button="left",
                  buttons=1, clickCount=1, pointerType="mouse")
        time.sleep(random.uniform(0.06, 0.15))
        self.send("Input.dispatchMouseEvent", type="mouseReleased", x=x, y=y, button="left",
                  buttons=0, clickCount=1, pointerType="mouse")
        self._x, self._y = x, y

    def click_check(self) -> bool:
        """Clicks the checkbox of the first interactive check on the page —
        Turnstile's sits at the left of its frame, a third of the way in —
        and says whether there was one."""
        boxes = self.frames()
        if not boxes:
            return False
        left, top, w, h = boxes[0]
        self.click(left + min(30.0, w / 3) + random.uniform(-4, 4), top + h / 2 + random.uniform(-4, 4))
        return True

    def close(self) -> None:
        try:
            self._chrome.send("Target.detachFromTarget", sessionId=self._session)
        except (RuntimeError, OSError, WSClosed):
            pass

    def __enter__(self) -> "Page":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def to_record(c: dict) -> dict:
    """A DevTools cookie as the package's cookie record."""
    domain = c.get("domain", "")
    rec = {
        "name": c["name"], "value": c.get("value", ""),
        "domain": domain.lstrip("."), "path": c.get("path", "/"),
        "expires": 0 if c.get("session") or c.get("expires", -1) < 0 else int(c["expires"]),
        "secure": bool(c.get("secure")), "http_only": bool(c.get("httpOnly")),
        "same_site": (c.get("sameSite") or "").lower(),
        # A leading dot is a Domain attribute; without one the cookie is the
        # host's alone.
        "host_only": not domain.startswith("."),
    }
    key = c.get("partitionKey")
    if isinstance(key, dict) and key.get("topLevelSite"):
        rec["partition"] = key["topLevelSite"]
    elif isinstance(key, str) and key:
        rec["partition"] = key
    return rec


def same_browser(version: dict, user_agent: str, impersonate: str) -> None:
    """Refuses a session whose fingerprint is not this browser's: its cookies
    and clearances would go out under a fingerprint that betrays them."""
    if version["userAgent"] == user_agent:
        return
    from ..errors import ConfigurationError

    name, _ = profile_for(version["userAgent"], version["product"])
    raise ConfigurationError(
        f"this machine's browser is {version['product']} and sends User-Agent "
        f"{version['userAgent']!r}; the session ({impersonate}) sends {user_agent!r}. "
        f"What one of them was given, the other would use under another fingerprint: "
        f"open the session as {name!r} — Session(**BrowserSolver().session_options(), ...)"
        + (" — and run the browser with a window (headless=False)"
           if "Headless" in version["userAgent"] else ""))


def to_devtools(rec: dict) -> dict:
    """A cookie record of the package as DevTools takes it. A host-only
    cookie is given by URL — given a domain, Chrome would make it a domain
    cookie that goes to every subdomain."""
    secure = bool(rec.get("secure"))
    path = rec.get("path") or "/"
    c: dict = {"name": rec["name"], "value": rec.get("value", ""), "path": path,
               "secure": secure, "httpOnly": bool(rec.get("http_only"))}
    if rec.get("host_only"):
        c["url"] = f"{'https' if secure else 'http'}://{rec['domain']}{path}"
    else:
        c["domain"] = "." + rec["domain"].lstrip(".")
    same = (rec.get("same_site") or "").lower()
    if same in ("strict", "lax", "none"):
        c["sameSite"] = same.capitalize()
    if rec.get("expires"):
        c["expires"] = rec["expires"]
    if rec.get("partition"):
        c["partitionKey"] = {"topLevelSite": rec["partition"], "hasCrossSiteAncestor": False}
    return c


def profile_for(user_agent: str, product: str) -> tuple[str, str]:
    """The package's profile name for a browser, and the device in its pool
    that matches the browser's build and this machine's OS release."""
    family = "edge" if "Edg/" in user_agent else "chrome"
    major = product.split("/", 1)[-1].split(".", 1)[0]
    os_name = ("windows" if "Windows" in user_agent else "macos" if "Mac OS X" in user_agent
               else "linux")
    full = product.split("/", 1)[-1]
    release = ""
    if os_name == "windows" and sys.platform == "win32":
        build = int(platform.version().split(".")[-1] or 0)
        names = [(26200, "Windows 11 25H2"), (26100, "Windows 11 24H2"), (22631, "Windows 11 23H2"),
                 (22621, "Windows 11 22H2"), (22000, "Windows 11 21H2"), (19045, "Windows 10 22H2"),
                 (19044, "Windows 10 21H2")]
        release = next((n for b, n in names if build >= b), "")
    device = f"{release}, Chrome {full}" if release else ""
    return f"{family}-{major}-{os_name}", device


def device_options(device: str, pool: list[dict]) -> dict:
    """``device`` (and ``devices`` when needed) for a session that is the
    browser whose device :func:`profile_for` named; ``pool`` is the profile's.

    The pool lists the builds known when the profile was made, and Chrome
    ships a patch every week or two: 154.0.8037.93 arrived overnight on a
    machine whose profile knew .58, and naming a device the pool lacks made
    every session fail. A build the pool lacks gets the pool's newest device
    of the same OS release with the browser's own build in it — the hints
    then say what the browser says."""
    if not device:
        return {}
    if any(d.get("name") == device for d in pool):
        return {"device": device}
    release, _, full = device.rpartition(", Chrome ")
    same = [d for d in pool if d.get("name", "").rpartition(", Chrome ")[0] == release
            and d.get("full_version")]
    if not same:
        return {}
    newest = max(same, key=lambda d: [int(x) for x in d["full_version"].split(".") if x.isdigit()])
    return {"device": device, "devices": [{**newest, "name": device, "full_version": full}]}


def site_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()
