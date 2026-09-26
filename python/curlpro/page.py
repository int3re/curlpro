"""Loading a page the way a browser loads it.

A browser does not stop at the document: it asks for the stylesheets,
scripts, images, icon and frames the markup names, each as the kind of
resource it is — its own Accept, ``sec-fetch-dest``, ``priority`` and
header order — in the order the markup names them, all at once over one
connection per host, and the icon last. An anti-bot that sees a document
fetched and nothing after it has seen something no browser does.

    page = session.load_page("https://example.com/")
    page.document.status
    for r in page.resources:
        print(r.kind, r.url, r.status)

What is fetched is what a browser fetches without running a script or laying
out the page: what the markup names (``<link rel=stylesheet>``,
``<link rel=preload>`` and ``modulepreload``, ``<script src>``,
``<img src>``, ``<iframe src>``, the icon, ``<link rel=prefetch>``) and,
with ``css=True``, the fonts the stylesheets declare. What a script would
load, what a lazy image near the viewport would, what a background image
on a rendered element would — those need a browser, and are not guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Any, Iterable
from urllib.parse import urljoin, urlsplit

if TYPE_CHECKING:
    from .session import Response

__all__ = ["Page", "PageResource", "discover"]


@dataclass
class PageResource:
    """One resource of a page: what was asked for and what came back.

    ``response`` is None when the request failed; ``error`` then says why.
    A failed resource does not fail the page, as it does not in a browser.
    """

    url: str
    kind: str
    crossorigin: str | None = None
    response: "Response | None" = None
    error: BaseException | None = None
    # The stylesheet that named it, for a font found with css=True.
    initiator: str | None = None

    @property
    def status(self) -> int | None:
        return self.response.status if self.response is not None else None

    @property
    def ok(self) -> bool:
        return self.response is not None and self.response.ok


@dataclass
class Page:
    """A loaded page: the document and its resources, in the order asked for."""

    document: "Response"
    resources: list[PageResource] = field(default_factory=list)

    @property
    def url(self) -> str:
        return self.document.url

    @property
    def failed(self) -> list[PageResource]:
        """The resources that got no response or an error status."""
        return [r for r in self.resources if not r.ok]

    def __iter__(self):  # noqa: ANN204
        return iter(self.resources)

    def __len__(self) -> int:
        return len(self.resources)

    def __repr__(self) -> str:
        return f"<Page {self.url} [{self.document.status}], {len(self.resources)} resources>"


# Script types a browser runs; anything else in a <script> is data.
_JS_TYPES = {"", "text/javascript", "application/javascript", "module",
             "text/ecmascript", "application/ecmascript", "text/jscript"}
# Elements that may stand in <head>; the first other one opens <body>.
_HEAD_TAGS = {"html", "head", "title", "meta", "link", "style", "script",
              "base", "noscript", "template"}
_SKIP_SCHEMES = ("data:", "blob:", "javascript:", "about:", "mailto:", "tel:")


class _Markup(HTMLParser):
    """Walks the markup and names the resources, in document order."""

    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.body = False
        self.skip = 0  # inside <noscript> or <template>: not loaded
        self.found: list[tuple[str, str, str | None]] = []
        self.late: list[tuple[str, str, str | None]] = []  # after load: icon, prefetch
        self.icon = False

    def _url(self, value: str | None) -> str | None:
        if not value:
            return None
        value = value.strip()
        if not value or value.startswith("#") or value.lower().startswith(_SKIP_SCHEMES):
            return None
        url = urljoin(self.base, value)
        return url if urlsplit(url).scheme in ("http", "https") else None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v if v is not None else "") for k, v in attrs}
        if tag in ("noscript", "template"):
            self.skip += 1
            return
        if self.skip:
            return
        if tag == "body" or (not self.body and tag not in _HEAD_TAGS):
            self.body = True
        if tag == "base" and "href" in a:
            # Only the first <base> counts, and only before anything used it.
            if not self.found:
                self.base = urljoin(self.base, a["href"])
            return
        co = a.get("crossorigin")
        cross = None if co is None else ("use-credentials" if co == "use-credentials" else "anonymous")
        if tag == "link":
            rel = set(a.get("rel", "").lower().split())
            url = self._url(a.get("href"))
            if not url:
                return
            if "stylesheet" in rel and "alternate" not in rel and "disabled" not in a:
                if a.get("media", "all").strip().lower() in ("", "all", "screen"):
                    self.found.append((url, "style", cross))
            elif "preload" in rel:
                kind = {"style": "style-preload", "script": "script-preload",
                        "font": "font-preload", "image": "image"}.get(a.get("as", "").lower())
                if kind:
                    self.found.append((url, kind, cross))
            elif "modulepreload" in rel:
                self.found.append((url, "module-preload", cross))
            elif "icon" in rel and not self.icon:
                self.icon = True
                self.late.insert(0, (url, "icon", None))
            elif "prefetch" in rel:
                self.late.append((url, "prefetch", None))
        elif tag == "script":
            kind_type = a.get("type", "").strip().lower()
            if kind_type not in _JS_TYPES or "nomodule" in a:
                return
            url = self._url(a.get("src"))
            if not url:
                return
            if kind_type == "module":
                kind = "module"
            elif "async" in a:
                kind = "script-async"
            elif "defer" in a:
                kind = "script-defer"
            else:
                kind = "script-body" if self.body else "script"
            self.found.append((url, kind, cross))
        elif tag == "img":
            if a.get("loading", "").lower() == "lazy":
                return
            src = a.get("src") or (a.get("srcset", "").split(",")[0].split() or [""])[0]
            url = self._url(src)
            if url:
                self.found.append((url, "image", cross))
        elif tag == "iframe":
            if a.get("loading", "").lower() == "lazy":
                return
            url = self._url(a.get("src"))
            if url:
                self.found.append((url, "iframe", None))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("noscript", "template") and self.skip:
            self.skip -= 1


def discover(html: str, base: str, *, favicon: bool = True) -> list[tuple[str, str, str | None]]:
    """The resources a browser would load for this markup, in the order it
    would ask for them: ``(url, kind, crossorigin)``.

    A URL is asked for once — a preload and the stylesheet that uses it are
    one request, as the preload is what the browser's cache serves. Without
    a ``<link rel=icon>`` the site's ``/favicon.ico`` is asked for last, as
    both browsers did on the stand.
    """
    p = _Markup(base)
    p.feed(html)
    p.close()
    late = list(p.late)
    if favicon and not p.icon:
        late.insert(0, (urljoin(base, "/favicon.ico"), "icon", None))
    if not favicon:
        late = [x for x in late if x[1] != "icon"]
    seen: set[str] = set()
    out = []
    for url, kind, cross in p.found + late:
        if url in seen:
            continue
        seen.add(url)
        out.append((url, kind, cross))
    return out


_FONT_FACE = re.compile(r"@font-face\s*{([^}]*)}", re.IGNORECASE | re.DOTALL)
_SRC = re.compile(r"src\s*:([^;]*)", re.IGNORECASE)
_URL = re.compile(r"""url\(\s*(['"]?)([^'")]+)\1\s*\)(\s*format\(\s*['"]?([\w-]+)['"]?\s*\))?""", re.IGNORECASE)


def css_fonts(css: str, sheet_url: str) -> list[str]:
    """The font each ``@font-face`` rule would load: the first source a
    browser supports, woff2 before the rest."""
    out = []
    for face in _FONT_FACE.findall(css):
        m = _SRC.search(face)
        if not m:
            continue
        sources = [(u, (fmt or "").lower()) for _, u, _, fmt in _URL.findall(m.group(1))]
        pick = next((u for u, fmt in sources if fmt == "woff2" or u.lower().split("?")[0].endswith(".woff2")), None)
        if pick is None and sources:
            pick = sources[0][0]
        if pick and not pick.lower().startswith(_SKIP_SCHEMES):
            out.append(urljoin(sheet_url, pick))
    return out


def referrer(referrer_url: str, target: str) -> str | None:
    """strict-origin-when-cross-origin: the whole referrer URL to its own
    origin, its origin elsewhere, nothing from https to http."""
    r, t = urlsplit(referrer_url), urlsplit(target)
    if r.scheme == "https" and t.scheme != "https":
        return None
    if (r.scheme, r.hostname, r.port) == (t.scheme, t.hostname, t.port):
        return referrer_url.split("#", 1)[0]
    return f"{r.scheme}://{r.netloc.rsplit('@', 1)[-1]}/"


def is_html(response: "Response") -> bool:
    ctype = (response.header("content-type") or "").lower()
    return "html" in ctype or (not ctype and response.content[:512].lstrip()[:1] == b"<")


def request_args(url: str, kind: str, cross: str | None, page: str, extra: dict[str, Any],
                 initiator: str | None = None) -> dict[str, Any]:
    """The arguments one resource request goes out with."""
    kw = dict(extra)
    kw.update(resource=kind, page=page)
    if cross:
        kw["crossorigin"] = cross
    if initiator:
        # A request a stylesheet makes names the stylesheet as its referrer;
        # the site relation stays the document's.
        ref = referrer(initiator, url)
        headers = dict(kw.get("headers") or {})
        headers["referer"] = ref
        kw["headers"] = headers
    return kw


def ordered(found: Iterable[tuple[str, str, str | None]]) -> tuple[list, list]:
    """Splits what the markup names into what goes at once and what goes
    after the page has loaded (the icon, prefetches)."""
    now, after = [], []
    for item in found:
        (after if item[1] in ("icon", "prefetch") else now).append(item)
    return now, after
