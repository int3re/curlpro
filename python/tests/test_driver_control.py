"""Stage 41, step 1: the driver acts on a page without leaving a trace in it.

The page here reports into its own DOM what it saw — keys and whether they
were trusted, whether the console probe that catches Runtime.enable fired,
whether a name set from the driver's isolated world reached the page's world —
and the test reads that back.
"""

from __future__ import annotations

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from curlpro.browser import Chrome, find_chrome

PAGE = b"""<!doctype html><title>driver</title>
<input id=q autocomplete=off>
<button id=go onclick="document.getElementById('out').textContent='got:'+document.getElementById('q').value">go</button>
<div id=out></div>
<div style="height:3000px"></div><p id=bottom>bottom</p>
<script>
const d = document.body.dataset;
d.keys = 0; d.trusted = 1; d.probed = 0;
document.getElementById('q').addEventListener('keydown', e => {
  d.keys = +d.keys + 1; if (!e.isTrusted) d.trusted = 0;
});
// Runtime.enable makes the console serialise what it is given, and reading an
// Error's stack is how pages catch it.
const e = new Error();
Object.defineProperty(e, 'stack', {get() { d.probed = 1; return ''; }});
setInterval(() => { console.debug(e); d.secret = typeof window.secret; }, 100);
</script>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):  # quiet
        pass


@pytest.fixture()
def site():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


browser = pytest.mark.skipif(find_chrome() is None or bool(os.environ.get("CI")),
                             reason="needs the Chrome installed on this machine")


@pytest.mark.browser
@browser
def test_the_driver_types_clicks_reads_and_leaves_no_trace(site):
    with Chrome(site, headless=True) as ch:
        tab = next(p["targetId"] for p in ch.pages() if p.get("type", "page") == "page")
        page = ch.page(tab)
        try:
            page.wait_for("#q")
            page.fill("#q", "Привет 42")
            page.click_on("#go")
            page.wait_for("#out")
            assert page.text("#out") == "got:Привет 42"
            ds = page.evaluate("Object.assign({}, document.body.dataset)")
            assert int(ds["keys"]) == len("Привет 42"), ds
            assert ds["trusted"] == "1", "a key arrived untrusted"
            page.scroll(1500)
            assert page.evaluate("window.scrollY") > 500
            # A name set in the isolated world stays there.
            page.evaluate("window.secret = 1")
            time.sleep(0.4)  # the page's own timer reports what it sees
            ds = page.evaluate("Object.assign({}, document.body.dataset)")
            assert ds["secret"] == "undefined", "the page saw the driver's world"
            assert ds["probed"] == "0", "the console probe fired: Runtime was enabled"
        finally:
            page.close()
