"""Resource requests and page loads (0.13).

``resource=`` sends a request as the kind of resource a page loads it as;
``load_page`` loads a document and what its markup names. The values checked
here are the ones measured on the hcapture -subres stand (Chrome 153,
Firefox 156): the Go side replays the whole capture, these check that the
arguments reach it and that a page load asks for what a browser asks for.
"""
from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]

PAGE = b"""<!doctype html><html><head><meta charset=utf-8>
<link rel=stylesheet href="/style.css">
<link rel=preload as=font href="/pre.woff2" crossorigin>
<script src="/head.js"></script>
<script async src="/async.js"></script>
<script type=module src="/mod.js"></script>
<script type="application/ld+json">{"not": "a script"}</script>
<noscript><img src="/noscript.png"></noscript>
<link rel=prefetch href="/next.js">
</head><body>
<img src="/img.png">
<img src="/lazy.png" loading=lazy>
<img src="http://cdn.other.test:PORT/cdn.png">
<script src="/body.js"></script>
<iframe src="http://cdn.other.test:PORT/frame.html"></iframe>
<a href="/not-loaded">x</a>
</body></html>"""

CSS = b"""@font-face{font-family:F;src:url(/f.woff) format("woff"),url(/f.woff2) format("woff2")}
body{background:url(/bg.png)}"""


class Stand:
    def __init__(self) -> None:
        self.seen: list[dict] = []
        self.lock = threading.Lock()
        stand = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802
                rec = {"path": self.path, "host": self.headers.get("host", "")}
                for k, v in self.headers.items():
                    rec.setdefault(k.lower(), v)
                with stand.lock:
                    stand.seen.append(rec)
                if self.path == "/":
                    body, ctype = PAGE.replace(b"PORT", str(stand.port).encode()), "text/html"
                elif self.path.endswith(".css"):
                    body, ctype = CSS, "text/css"
                elif self.path.endswith(".html"):
                    body, ctype = b"<!doctype html><p>frame", "text/html"
                else:
                    body, ctype = b"x", "application/octet-stream"
                self.send_response(200)
                self.send_header("content-type", ctype)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a) -> None:  # noqa: ANN002
                pass

        ThreadingHTTPServer.daemon_threads = True
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        self.url = f"http://www.site.test:{self.port}/"
        self.resolve = {"www.site.test": f"127.0.0.1:{self.port}", "cdn.other.test": f"127.0.0.1:{self.port}"}
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def get(self, path: str) -> dict:
        found = [r for r in self.seen if r["path"] == path]
        assert found, f"{path} was not requested; requested: {[r['path'] for r in self.seen]}"
        return found[0]

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture(scope="module", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def stand():
    st = Stand()
    yield st
    st.close()


def test_capabilities_list_the_kinds():
    kinds = curlpro.capabilities("chrome-153-windows")["resources"]
    assert {"image", "script", "style", "font", "iframe", "beacon", "prefetch"} <= set(kinds)
    assert curlpro.capabilities("chrome-151-windows")["resources"] == []


def test_resource_headers_chrome():
    with curlpro.Session("chrome-153-windows") as s:
        page = "https://www.site.test/p"
        img = s.headers_for("GET", "https://cdn.other.test/a.png", resource="image", page=page, protocol="h2")
        assert img["sec-fetch-dest"] == "image" and img["sec-fetch-mode"] == "no-cors"
        assert img["priority"] == "i"
        assert img["accept"].startswith("image/avif,image/webp,image/apng")
        assert img["sec-fetch-storage-access"] == "active"
        assert img["referer"] == "https://www.site.test/"
        cors = s.headers_for("GET", "https://cdn.other.test/a.png", resource="image", crossorigin="anonymous",
                             page=page, protocol="h2")
        # Chrome puts Origin first on a CORS resource.
        assert list(cors)[0] == "origin" and cors["sec-fetch-mode"] == "cors"
        assert "sec-fetch-storage-access" not in cors
        script = s.headers_for("GET", "https://www.site.test/a.js", resource="script-async", page=page, protocol="h2")
        assert "priority" not in script


def test_resource_arguments_refused():
    with curlpro.Session("chrome-151-windows") as s:
        with pytest.raises(curlpro.ProfileCapabilityError, match="no resources section"):
            s.headers_for("GET", "https://example.com/", resource="image")
    with curlpro.Session("chrome-153-windows") as s:
        with pytest.raises(curlpro.ConfigurationError, match="knows"):
            s.headers_for("GET", "https://example.com/", resource="video")
        with pytest.raises(curlpro.ConfigurationError, match="leave mode out"):
            s.headers_for("GET", "https://example.com/", resource="image", mode="fetch")
        with pytest.raises(curlpro.ConfigurationError, match="name the resource"):
            s.headers_for("GET", "https://example.com/", crossorigin="anonymous")


def check_firefox_page(stand: Stand, page: curlpro.Page) -> None:
    assert page.document.status == 200
    kinds = {r.url.rsplit("/", 1)[-1]: r.kind for r in page.resources}
    assert kinds == {
        "style.css": "style", "pre.woff2": "font-preload", "head.js": "script", "async.js": "script-async",
        "mod.js": "module", "img.png": "image", "cdn.png": "image", "body.js": "script-body",
        "frame.html": "iframe", "favicon.ico": "icon", "next.js": "prefetch", "f.woff2": "font",
    }
    assert not page.failed
    doc = stand.get("/")
    assert doc["sec-fetch-dest"] == "document" and doc["sec-fetch-site"] == "none"
    # Firefox 156, measured: its priorities, and none on a body or async script.
    assert stand.get("/style.css")["priority"] == "u=2"
    assert stand.get("/head.js")["priority"] == "u=2"
    assert "priority" not in stand.get("/body.js") and "priority" not in stand.get("/async.js")
    assert stand.get("/img.png")["priority"] == "u=5, i"
    mod = stand.get("/mod.js")
    assert mod["sec-fetch-mode"] == "cors" and "origin" not in mod  # Firefox: Origin only cross-origin
    cdn = stand.get("/cdn.png")
    assert cdn["sec-fetch-site"] == "cross-site" and cdn["referer"] == f"http://www.site.test:{stand.port}/"
    assert cdn["sec-fetch-storage-access"] == "none"
    frame = stand.get("/frame.html")
    assert frame["sec-fetch-dest"] == "iframe" and frame["upgrade-insecure-requests"] == "1"
    assert "sec-fetch-user" not in frame and frame["priority"] == "u=4"
    # The font a stylesheet declares: its woff2, with the stylesheet as the
    # referrer, and Firefox's identity encoding.
    font = stand.get("/f.woff2")
    assert font["referer"] == f"http://www.site.test:{stand.port}/style.css"
    assert font["accept-encoding"] == "identity" and font["sec-fetch-dest"] == "font"
    # Not loaded: data, a lazy image, what <noscript> holds, a link, a
    # background image (it needs layout), the other font source.
    paths = [r["path"] for r in stand.seen]
    for absent in ("/lazy.png", "/noscript.png", "/not-loaded", "/bg.png", "/f.woff"):
        assert absent not in paths
    # The icon and the prefetch go after everything else.
    assert set(paths[-2:]) == {"/favicon.ico", "/next.js"}, paths


def test_load_page(stand):
    with curlpro.Session("firefox-156-windows", resolve=stand.resolve) as s:
        page = s.load_page(stand.url, css=True)
    check_firefox_page(stand, page)


def test_load_page_async(stand):
    async def run() -> curlpro.Page:
        async with curlpro.AsyncSession("firefox-156-windows", resolve=stand.resolve) as s:
            return await s.load_page(stand.url, css=True)

    check_firefox_page(stand, asyncio.run(run()))


def test_load_page_of_something_else(stand):
    with curlpro.Session("firefox-156-windows", resolve=stand.resolve) as s:
        page = s.load_page(f"http://www.site.test:{stand.port}/data.bin")
    assert page.document.status == 200 and page.resources == []


def test_discover_follows_the_markup():
    found = curlpro.page.discover(
        '<base href="https://cdn.example/a/"><link rel=stylesheet href=s.css media=print>'
        '<link rel=stylesheet href=t.css><link rel=preload as=style href=t.css>'
        '<script nomodule src=old.js></script><img srcset="x1.png 1x, x2.png 2x">'
        '<link rel=icon href=/i.png><img src="data:image/png;base64,AA">',
        "https://site.example/")
    assert found == [
        ("https://cdn.example/a/t.css", "style", None),
        ("https://cdn.example/a/x1.png", "image", None),
        ("https://cdn.example/i.png", "icon", None),
    ]
