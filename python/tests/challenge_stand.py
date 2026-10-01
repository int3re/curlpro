"""A local stand that behaves as an anti-bot's gate, for the solver's tests.

``/gate`` answers 403 with ``cf-mitigated: challenge`` and a page — as
Cloudflare answers a managed challenge — until the request carries the
clearance cookie. The page is the "check": it waits a moment and sets the
cookie by script, as a JavaScript challenge does once it has measured the
browser, then reloads. On the way it reports to ``/report`` what a page can
read about the control channel:

- ``navigator.webdriver``, which the DevTools port switches on unless the
  browser is started not to;
- the window's own chrome (``outerHeight - innerHeight``): an infobar about a
  command-line flag adds some 56 px a page can measure;
- the two published Runtime.enable probes. On Chrome 154 they read the same
  with an inspector attached and without one (measured: the inspector proved
  attached by its console events), so they are reported, not asserted.

``/leak`` is the same report alone, without the gate. ``/turnstile`` is a gate
behind Cloudflare's real Turnstile widget, ``/blocked`` a Cloudflare block
page.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PROBE = """
<script>
(function () {
  // Two probes for an attached inspector. The old one: an Error whose stack
  // getter only the inspector reads when the error is logged. The current
  // one: an object with a Proxy for a prototype, which the inspector walks
  // when it previews the argument of a console call.
  var stack = false, proxy = "", phase = "setup";
  var e = new Error("probe");
  Object.defineProperty(e, "stack", { configurable: true, get: function () { stack = true; return ""; } });
  console.debug(e);
  var hits = [];
  var trap = function (name) { return function () { hits.push(phase + ":" + name); }; };
  var handler = {};
  ["get", "has", "ownKeys", "getOwnPropertyDescriptor", "getPrototypeOf"].forEach(function (n) {
    var mark = trap(n);
    handler[n] = function (t, k) {
      mark();
      return n === "has" ? false : n === "ownKeys" ? [] : n === "getPrototypeOf" ? null : undefined;
    };
  });
  var bait = Object.create(new Proxy({}, handler));
  phase = "groupEnd"; console.groupEnd(bait);
  phase = "log"; console.log(bait);
  phase = "after";
  proxy = hits.join(",");
  var send = function (quota) {
    fetch("/report?runtime=" + (stack || !!proxy) + "&stack=" + stack + "&proxy=" + proxy +
          "&webdriver=" + navigator.webdriver + "&chrome=" + (window.outerHeight - window.innerHeight) +
          "&quota=" + quota + "&tz=" + encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone) +
          "&langs=" + encodeURIComponent(navigator.languages.join(",")) +
          "&ua=" + encodeURIComponent(navigator.userAgent));
  };
  // The storage quota: an incognito profile gets a small one, and pages
  // that look for incognito read exactly this.
  setTimeout(function () {
    if (navigator.storage && navigator.storage.estimate) {
      navigator.storage.estimate().then(function (e) { send(e.quota); }, function () { send(-1); });
    } else { send(-1); }
  }, 300);
})();
</script>
"""

CHECK = """<!doctype html><html><head><title>Just a moment...</title></head><body>
<p>Checking your browser.</p>""" + PROBE + """
<script>
setTimeout(function () {
  document.cookie = "cf_clearance=passed; path=/; max-age=3600";
  location.reload();
}, 1200);
</script></body></html>"""


#: A gate in front of which sits Cloudflare's real Turnstile widget, loaded
#: from challenges.cloudflare.com with one of Cloudflare's published test
#: sitekeys (they work on any domain, localhost included): 1x...AA always
#: passes, 3x...FF always asks for a click. The token goes to /verify, which
#: sets the clearance; the stand does not ask Cloudflare whether a test
#: token is valid — a test key's token always is.
TURNSTILE = """<!doctype html><html><head><title>Just a moment...</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></head>
<body><div class="cf-turnstile" data-sitekey="SITEKEY" data-callback="passed"></div>
<script>
function passed(token) {
  fetch("/verify?token=" + encodeURIComponent(token)).then(function () { location.reload(); });
}
</script></body></html>"""


#: What a fingerprinting script reads about the browser, reported whole to
#: /fp-report: a flag that saves memory must leave every value as it was.
FINGERPRINT = """<!doctype html><title>fp</title><script>
(async function () {
  var fp = {};
  try {
    fp.webdriver = navigator.webdriver;
    fp.plugins = navigator.plugins.length;
    fp.mimeTypes = navigator.mimeTypes.length;
    fp.chrome = typeof window.chrome === "object" ? Object.keys(window.chrome).sort().join(",") : String(typeof window.chrome);
    fp.hardwareConcurrency = navigator.hardwareConcurrency;
    fp.deviceMemory = navigator.deviceMemory;
    fp.languages = navigator.languages.join(",");
    fp.platform = navigator.platform;
    fp.screen = [screen.width, screen.height, screen.colorDepth, devicePixelRatio].join("x");
    fp.chromeHeight = outerHeight - innerHeight;
    fp.notification = typeof Notification === "function" ? Notification.permission : "none";
    fp.pdfViewer = navigator.pdfViewerEnabled;
    fp.cookieEnabled = navigator.cookieEnabled;
    fp.visibility = document.visibilityState;
    fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    fp.tzOffset = new Date(2026, 0, 15).getTimezoneOffset() + "/" + new Date(2026, 6, 15).getTimezoneOffset();
    // A dedicated worker answers on its own: an override that reaches the
    // page and not its workers is a mismatch a script can see.
    fp.workerTimezone = await new Promise(function (done) {
      try {
        var src = "postMessage(Intl.DateTimeFormat().resolvedOptions().timeZone + '|' + navigator.languages.join(','))";
        var w = new Worker(URL.createObjectURL(new Blob([src], { type: "text/javascript" })));
        w.onmessage = function (e) { done(e.data); };
        setTimeout(function () { done("no answer"); }, 2000);
      } catch (e) { done("error: " + e); }
    });
    var gl = document.createElement("canvas").getContext("webgl");
    var dbg = gl && gl.getExtension("WEBGL_debug_renderer_info");
    fp.webgl = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) + " / " + gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "none";
    fp.webglExtensions = gl ? gl.getSupportedExtensions().length : 0;
    if (navigator.userAgentData) {
      fp.brands = navigator.userAgentData.brands.map(function (b) { return b.brand + "/" + b.version; }).join(",");
      var hi = await navigator.userAgentData.getHighEntropyValues(["fullVersionList", "platformVersion"]);
      fp.fullVersions = hi.fullVersionList.map(function (b) { return b.brand + "/" + b.version; }).join(",");
      fp.platformVersion = hi.platformVersion;
    }
    var q = await navigator.storage.estimate();
    fp.quota = q.quota;
    var perms = ["geolocation", "notifications", "camera", "microphone"];
    fp.permissions = (await Promise.all(perms.map(function (p) {
      return navigator.permissions.query({ name: p }).then(function (s) { return p + "=" + s.state; }, function () { return p + "=err"; });
    }))).join(",");
    fp.speechVoices = typeof speechSynthesis === "object" ? speechSynthesis.getVoices().length : -1;
    fp.mediaDevices = navigator.mediaDevices ? (await navigator.mediaDevices.enumerateDevices()).length : -1;
  } catch (e) { fp.error = String(e); }
  fetch("/fp-report", { method: "POST", body: JSON.stringify(fp) });
})();
</script>"""


#: The time zone and languages as every kind of script sees them: the page, a
#: dedicated worker, a shared worker and a service worker. An override that
#: reaches some and not others is a mismatch fingerprinting scripts compare.
ZONES = """<!doctype html><title>zones</title><script>
(async function () {
  var me = function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone + "|" + navigator.languages.join(",");
  };
  var out = { page: me() };
  var ask = function (make) {
    return new Promise(function (done) {
      try { make(done); } catch (e) { done("error: " + e); }
      setTimeout(function () { done("no answer"); }, 3000);
    });
  };
  var src = "Intl.DateTimeFormat().resolvedOptions().timeZone + '|' + navigator.languages.join(',')";
  out.dedicated = await ask(function (done) {
    var w = new Worker(URL.createObjectURL(new Blob(["postMessage(" + src + ")"], { type: "text/javascript" })));
    w.onmessage = function (e) { done(e.data); };
  });
  out.shared = await ask(function (done) {
    var w = new SharedWorker("/zones-shared.js");
    w.port.onmessage = function (e) { done(e.data); };
    w.port.start();
  });
  out.service = await ask(function (done) {
    navigator.serviceWorker.register("/zones-sw.js").then(function () {
      return navigator.serviceWorker.ready;
    }).then(function (reg) {
      navigator.serviceWorker.onmessage = function (e) { done(e.data); };
      reg.active.postMessage("zone");
    }, function (e) { done("error: " + e); });
  });
  fetch("/zones-report", { method: "POST", body: JSON.stringify(out) });
})();
</script>"""

ZONES_SHARED = ("onconnect = function (e) { var p = e.ports[0]; p.postMessage("
                "Intl.DateTimeFormat().resolvedOptions().timeZone + '|' + navigator.languages.join(',')); };")
ZONES_SW = ("self.addEventListener('install', function () { self.skipWaiting(); });"
            "self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });"
            "self.addEventListener('message', function (e) { e.source.postMessage("
            "Intl.DateTimeFormat().resolvedOptions().timeZone + '|' + navigator.languages.join(',')); });")


class Stand:
    def __init__(self) -> None:
        self.reports: list[dict] = []
        self.tokens: list[str] = []
        self.fingerprints: list[dict] = []
        self.zones: list[dict] = []
        self.storage_done = 0
        self.storage_cookies: list[str] = []
        self.gate_hits = 0
        stand = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, status: int, body: bytes, headers: list | None = None,
                      ctype: str = "text/html; charset=utf-8") -> None:
                self.send_response(status)
                for k, v in headers or []:
                    self.send_header(k, v)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                u = urlsplit(self.path)
                if u.path == "/report":
                    q = {k: v[0] for k, v in parse_qs(u.query).items()}
                    stand.reports.append(q)
                    self._send(204, b"")
                    return
                if u.path == "/fp":
                    self._send(200, FINGERPRINT.encode())
                    return
                if u.path == "/geo":
                    # What a geolocation service answers about the caller.
                    self._send(200, json.dumps({"ip": "203.0.113.7", "country": "DE",
                                                "timezone": "Europe/Berlin"}).encode(),
                               ctype="application/json")
                    return
                if u.path == "/storage":
                    # A page that keeps a token where single-page apps keep
                    # theirs, and sets a cookie of its own by script.
                    stand.storage_cookies.append(self.headers.get("Cookie") or "")
                    self._send(200, b"<!doctype html><title>storage</title><script>"
                                    b"localStorage.setItem('token', 'abc123');"
                                    b"document.cookie = 'js_cookie=1; path=/';"
                                    b"fetch('/storage-done');</script>")
                    return
                if u.path == "/storage-done":
                    stand.storage_done += 1
                    self._send(204, b"")
                    return
                if u.path == "/echo-cookies":
                    self._send(200, json.dumps({"cookie": self.headers.get("Cookie") or ""}).encode(),
                               ctype="application/json")
                    return
                if u.path == "/zones":
                    self._send(200, ZONES.encode())
                    return
                if u.path in ("/zones-shared.js", "/zones-sw.js"):
                    body = ZONES_SHARED if u.path == "/zones-shared.js" else ZONES_SW
                    self._send(200, body.encode(), ctype="text/javascript")
                    return
                if u.path == "/leak":
                    self._send(200, ("<!doctype html><title>leak</title>" + PROBE).encode())
                    return
                if u.path == "/gate":
                    stand.gate_hits += 1
                    if "cf_clearance=passed" in (self.headers.get("Cookie") or ""):
                        self._send(200, json.dumps({"ok": True}).encode(), ctype="application/json")
                    else:
                        self._send(403, CHECK.encode(), [("cf-mitigated", "challenge"),
                                                         ("Server", "cloudflare"), ("CF-RAY", "8f00test-AMS")])
                    return
                if u.path == "/turnstile":
                    if "ts_clearance=ok" in (self.headers.get("Cookie") or ""):
                        self._send(200, json.dumps({"ok": True}).encode(), ctype="application/json")
                    else:
                        key = parse_qs(u.query).get("key", ["1x00000000000000000000AA"])[0]
                        self._send(403, TURNSTILE.replace("SITEKEY", key).encode(),
                                   [("cf-mitigated", "challenge"), ("Server", "cloudflare")])
                    return
                if u.path == "/verify":
                    token = parse_qs(u.query).get("token", [""])[0]
                    stand.tokens.append(token)
                    self._send(204, b"", [("Set-Cookie", "ts_clearance=ok; Path=/")] if token else [])
                    return
                if u.path == "/blocked":
                    self._send(403, b"<title>Attention Required! | Cloudflare</title>"
                                    b"<div id='cf-error-details'>Sorry, you have been blocked</div>",
                               [("Server", "cloudflare"), ("CF-RAY", "8f00blk-AMS")])
                    return
                self._send(404, b"no")

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if urlsplit(self.path).path == "/fp-report":
                    stand.fingerprints.append(json.loads(body or b"{}"))
                if urlsplit(self.path).path == "/zones-report":
                    stand.zones.append(json.loads(body or b"{}"))
                self._send(204, b"")

            def log_message(self, *a: object) -> None:
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request: object, client_address: object) -> None:
                pass  # a browser drops connections it no longer needs

        self.server = Server(("127.0.0.1", 0), H)
        self.port = self.server.server_port
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
