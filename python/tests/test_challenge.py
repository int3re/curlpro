"""Anti-bot challenges: telling one from an ordinary answer, and getting past
it with a solver.

The detection and the session's handling of a solver run against the local
stand (challenge_stand.py) with a solver that sets the clearance itself. The
browser solver's own tests start the Chrome installed here and are skipped
where there is none — and on CI, where there is no screen for its window.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading
import time

import pytest

import curlpro
from curlpro.browser import Forwarder, find_chrome
from curlpro.browser.chrome import to_record
from curlpro.challenge import Challenge, detect

sys.path.insert(0, os.path.dirname(__file__))
from challenge_stand import Stand  # noqa: E402


@pytest.fixture()
def stand():
    s = Stand()
    yield s
    s.close()


# --- detection ----------------------------------------------------------------

def test_cloudflare_says_so_in_a_header():
    c = detect(403, {"cf-mitigated": ["challenge"], "CF-RAY": ["8f00-AMS"]}, b"", "https://x.test/")
    assert c == Challenge("cloudflare", "challenge", 403, "https://x.test/", "8f00-AMS",
                          ("cf-mitigated: challenge",))
    assert c.solvable and "8f00-AMS" in str(c)


@pytest.mark.parametrize("status,headers,body,vendor,kind", [
    (503, {"Server": "cloudflare"}, b"<script src='/cdn-cgi/challenge-platform/h/b/orchestrate'>",
     "cloudflare", "challenge"),
    (403, {"Server": "cloudflare"}, b"<div id='cf-error-details'>Sorry, you have been blocked", "cloudflare", "block"),
    (429, {"Server": "cloudflare", "CF-RAY": "x"}, b"error code: 1015", "cloudflare", "rate-limit"),
    (403, {"X-DataDome": "protected", "Set-Cookie": "datadome=abc; Path=/"},
     b"<script src='https://ct.captcha-delivery.com/c.js'>", "datadome", "captcha"),
    (403, {}, b"<div id='px-captcha'></div>", "human", "captcha"),
    (403, {"Server": "AkamaiGHost"}, b"<H1>Access Denied</H1>", "akamai", "block"),
    (403, {}, b"<script src='/_Incapsula_Resource?x=1'>", "imperva", "challenge"),
    (429, {"x-kpsdk-ct": "abc"}, b"", "kasada", "challenge"),
])
def test_the_vendors_by_their_marks(status, headers, body, vendor, kind):
    c = detect(status, headers, body)
    assert c is not None and (c.vendor, c.kind) == (vendor, kind), c
    assert c.solvable == (kind in ("challenge", "captcha"))


@pytest.mark.parametrize("status,headers,body", [
    (403, {"Server": "nginx"}, b"Forbidden"),
    (200, {"Server": "cloudflare"}, b"<script src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'>"),
    (404, {"Server": "cloudflare", "CF-RAY": "x"}, b"not found"),
])
def test_an_ordinary_answer_is_none(status, headers, body):
    # A 200 with Cloudflare's script on it is a page with JS detections, not
    # a gate; a plain 403 is a 403.
    assert detect(status, headers, body) is None


def test_a_response_knows_its_challenge(stand):
    with curlpro.Session("chrome-154-windows") as s:
        r = s.get(stand.base + "/gate")
        assert r.status == 403 and r.challenge.vendor == "cloudflare" and r.challenge.ray == "8f00test-AMS"
        with pytest.raises(curlpro.ChallengeError) as e:
            r.raise_for_challenge()
        assert e.value.code == "challenge" and e.value.response is r
        assert s.get(stand.base + "/blocked").challenge.kind == "block"
        assert s.get(stand.base + "/leak").challenge is None
        with s.stream("GET", stand.base + "/gate") as st:
            assert st.challenge.kind == "challenge"


# --- the session with a solver --------------------------------------------------

class Clearing:
    """A solver that does what the check page would: sets the clearance."""

    def __init__(self, works: bool = True):
        self.works = works
        self.calls: list = []

    def solve(self, request):  # noqa: ANN001, ANN201
        self.calls.append(request)
        host = request.url.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
        cookie = {"name": "cf_clearance", "value": "passed" if self.works else "no",
                  "domain": host, "path": "/", "host_only": True}
        if request.verify([cookie]):
            return curlpro.Solution([cookie], request.user_agent, "test")
        return None


def test_a_solver_gets_the_request_through(stand):
    solver = Clearing()
    with curlpro.Session("chrome-154-windows", solver=solver) as s:
        r = s.get(stand.base + "/gate")
        assert r.status == 200 and r.json() == {"ok": True} and r.challenge is None
        req = solver.calls[0]
        assert req.challenge.vendor == "cloudflare" and req.url == stand.base + "/gate"
        assert req.impersonate == "chrome-154-windows" and "Chrome/154" in req.user_agent
        assert req.proxy == ""
        # The clearance is in the jar: the next request goes straight through.
        assert s.get(stand.base + "/gate").status == 200
    assert len(solver.calls) == 1


def test_one_solve_for_a_burst(stand):
    solver = Clearing()
    with curlpro.Session("chrome-154-windows", solver=solver) as s:
        out: list = []
        threads = [threading.Thread(target=lambda: out.append(s.get(stand.base + "/gate").status))
                   for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert out == [200] * 6 and len(solver.calls) == 1


def test_a_solver_that_fails_raises_and_a_block_is_not_handed_over(stand):
    solver = Clearing(works=False)
    with curlpro.Session("chrome-154-windows", solver=solver) as s:
        with pytest.raises(curlpro.ChallengeError) as e:
            s.get(stand.base + "/gate")
        assert e.value.challenge.vendor == "cloudflare" and e.value.response.status == 403
        n = len(solver.calls)
        r = s.get(stand.base + "/blocked")
        assert r.status == 403 and r.challenge.kind == "block" and len(solver.calls) == n


def test_the_async_session_solves_off_the_loop(stand):
    solver = Clearing()

    async def main():
        async with curlpro.AsyncSession("chrome-154-windows", solver=solver) as s:
            rs = await asyncio.gather(*(s.get(stand.base + "/gate") for _ in range(4)))
            return [r.status for r in rs]

    assert asyncio.run(main()) == [200] * 4 and len(solver.calls) == 1


def test_a_solver_without_solve_is_refused():
    with pytest.raises(TypeError):
        curlpro.Session("chrome-154-windows", solver=object())


# --- the browser's pieces -------------------------------------------------------

def test_a_devtools_cookie_becomes_a_record():
    rec = to_record({"name": "cf_clearance", "value": "v", "domain": ".a.test", "path": "/",
                     "expires": 1900000000.5, "httpOnly": True, "secure": True, "session": False,
                     "sameSite": "None", "partitionKey": {"topLevelSite": "https://b.test",
                                                          "hasCrossSiteAncestor": True}})
    assert rec == {"name": "cf_clearance", "value": "v", "domain": "a.test", "path": "/",
                   "expires": 1900000000, "secure": True, "http_only": True, "same_site": "none",
                   "host_only": False, "partition": "https://b.test"}
    host = to_record({"name": "x", "value": "1", "domain": "a.test", "path": "/", "expires": -1,
                      "session": True})
    assert host["host_only"] and host["expires"] == 0 and "partition" not in host


def test_feature_lists_are_merged_into_one_switch():
    # Chrome keeps the last of a repeated switch: three lists given, one
    # read, and the occlusion fix gone with the other two.
    from curlpro.browser.chrome import _merge_features
    merged = _merge_features(["chrome", "--disable-features=A", "--lang=de", "--disable-features=B,A",
                              "--enable-features=X", "--disable-features=C"])
    assert merged == ["chrome", "--disable-features=A,B,C", "--lang=de", "--enable-features=X"]


class AuthProxy:
    """An HTTP proxy that wants credentials, and records what it was sent."""

    def __init__(self, user: str, password: str):
        import base64
        self.want = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.seen: list = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        from curlpro.browser.forward import _pipe, _read_head
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            head, rest = _read_head(c)
            lines = head.decode().split("\r\n")
            auth = next((x.split(":", 1)[1].strip() for x in lines if x.lower().startswith("proxy-authorization")), "")
            self.seen.append((lines[0], auth == self.want))
            if auth != self.want:
                c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                c.close()
                continue
            method, target, _ = lines[0].split(" ", 2)
            if method == "CONNECT":
                host, port = target.rsplit(":", 1)
                up = socket.create_connection((host, int(port)))
                c.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            else:
                from urllib.parse import urlsplit
                u = urlsplit(target)
                up = socket.create_connection((u.hostname, u.port))
                kept = [x for x in lines[1:] if not x.lower().startswith("proxy-")]
                up.sendall(f"{method} {u.path} HTTP/1.1\r\n".encode() + "\r\n".join(kept).encode()
                           + b"\r\n\r\n" + rest)
            threading.Thread(target=_pipe, args=(c, up), daemon=True).start()


def test_the_forwarder_adds_the_credentials(stand):
    up = AuthProxy("u", "p@ss")
    with Forwarder(f"http://u:p%40ss@127.0.0.1:{up.port}") as fw:
        # A cleartext request in absolute form, as Chrome sends one to a proxy.
        with curlpro.Session("chrome-154-windows", proxy=fw.address) as s:
            assert s.get(stand.base + "/leak").status == 200
        # A tunnel, as Chrome opens one for https.
        c = socket.create_connection(("127.0.0.1", int(fw.address.rsplit(":", 1)[1])))
        c.sendall(f"CONNECT 127.0.0.1:{stand.port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        assert c.recv(100).startswith(b"HTTP/1.1 200")
        c.sendall(f"GET /leak HTTP/1.1\r\nHost: 127.0.0.1:{stand.port}\r\nConnection: close\r\n\r\n".encode())
        got = b""
        while chunk := c.recv(65536):
            got += chunk
        c.close()
        assert got.startswith(b"HTTP/1.1 200") and b"probe" in got
    assert [ok for _, ok in up.seen] == [True, True], up.seen


# --- the browser solver, with the Chrome installed here ------------------------

browser = pytest.mark.skipif(
    find_chrome() is None or bool(os.environ.get("CI")),
    reason="needs the Chrome installed on this machine, and a screen for its window")


@pytest.mark.browser
@browser
def test_the_browser_passes_the_check_without_a_trace(stand):
    solver = curlpro.BrowserSolver()
    opts = solver.session_options()
    assert opts["impersonate"].startswith(("chrome-", "edge-"))
    with curlpro.Session(**opts, solver=solver) as s:
        r = s.get(stand.base + "/gate")
        assert r.status == 200 and r.json() == {"ok": True}
        ua = s.headers_for("GET", stand.base + "/")["User-Agent"]
    # What the check page measured in the browser: no webdriver, the
    # session's own User-Agent, a window without an infobar.
    page = stand.reports[0]
    assert page["webdriver"] == "false", page
    assert page["ua"] == ua
    assert int(page["chrome"]) < 120, page


@pytest.mark.browser
@pytest.mark.network
@browser
def test_the_browser_passes_cloudflares_turnstile(stand):
    # Cloudflare's real widget from challenges.cloudflare.com, with its
    # always-pass test sitekey: the widget runs in the browser and hands the
    # stand a token, the stand sets the clearance.
    solver = curlpro.BrowserSolver()
    with curlpro.Session(**solver.session_options(), solver=solver) as s:
        r = s.get(stand.base + "/turnstile?key=1x00000000000000000000AA")
    assert r.status == 200 and stand.tokens == ["XXXX.DUMMY.TOKEN.XXXX"]


@pytest.mark.browser
@pytest.mark.network
@browser
def test_a_check_that_wants_a_click_gets_one(stand):
    # Cloudflare's test sitekey that always asks for the checkbox. Without a
    # click it never passes; the solver finds the widget's frame in its
    # closed shadow root and clicks it.
    url = stand.base + "/turnstile?key=3x00000000000000000000FF"
    lazy = curlpro.BrowserSolver(click=False, timeout=8)
    with curlpro.Session(**lazy.session_options(), solver=lazy) as s:
        with pytest.raises(curlpro.ChallengeError):
            s.get(url)
    assert stand.tokens == []
    solver = curlpro.BrowserSolver()
    with curlpro.Session(**solver.session_options(), solver=solver) as s:
        r = s.get(url)
    assert r.status == 200 and stand.tokens == ["XXXX.DUMMY.TOKEN.XXXX"]


@pytest.mark.browser
@browser
def test_one_browser_kept_open_serves_several_solves(stand):
    # One browser for both solves, each in a tab of its own with the cookies
    # cleared first; the browser outlives them until closed.
    with curlpro.BrowserSolver(keep_open=True) as solver:
        opts = solver.session_options()
        first = None
        for _ in range(2):
            with curlpro.Session(**opts, solver=solver) as s:
                assert s.get(stand.base + "/gate").status == 200
            browser = solver._shared
            assert browser is not None and browser.alive
            first = first or browser
            assert browser is first
        # Two solves, two check pages: the second did not ride on the first
        # one's clearance.
        assert len(stand.reports) == 2
    assert not first.alive
    with pytest.raises(ValueError):
        curlpro.BrowserSolver(keep_open=True, profile_dir="x")


@pytest.mark.browser
@browser
def test_the_light_flags_change_nothing_a_page_reads(stand):
    # The stand's fingerprint page — plugins, window.chrome, WebGL, client
    # hints, quota, permissions, media devices — read under the flags that
    # spare the machine and without them: the same, value for value.
    from curlpro.browser import Chrome

    seen = []
    for light in (False, True):
        n = len(stand.fingerprints)
        with Chrome(stand.base + "/fp", light=light):
            for _ in range(200):
                if len(stand.fingerprints) > n:
                    break
                time.sleep(0.05)
        seen.append(stand.fingerprints[n])
    plain, light = seen
    assert "error" not in plain and plain["webdriver"] is False and plain["chromeHeight"] < 120
    assert light == plain


@pytest.mark.browser
@browser
def test_a_session_of_another_version_is_refused(stand):
    solver = curlpro.BrowserSolver()
    with curlpro.Session("chrome-151-windows", solver=solver) as s:
        with pytest.raises(curlpro.ConfigurationError, match="open the session as"):
            s.get(stand.base + "/gate")
