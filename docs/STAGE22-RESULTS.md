# Stage 22 — the cache, partitioned cookies, the top level, a speed pass

Date: 2026-09-29. The owner asked for "something good" in the next release and
a pass over speed. Three things a browser does that the library did not, all
keyed by the site in the address bar: a cache, cookies kept per top-level site,
and connections kept the same way — and the per-request costs measured and cut.

## The stand: `cmd/hcapture -cache` and `-chips`

**`-cache`** serves `www.a.localhost/c/index.html` with a stylesheet
(`max-age=3600`), a stylesheet from `b.localhost` (the same), a script with
`no-cache` and an ETag, a script with `no-store`, an image with only a
`Last-Modified` (the heuristic lifetime), an image with `max-age=1`, an ETag
and a `Last-Modified` (stale by the next page), an `immutable` image, and a
`fetch()` of an API answered `no-cache` with an ETag. The documents are
`no-cache` with an ETag and a `Last-Modified`, and set a cookie. The page links
to `page2.html` with the same resources, which is reloaded, then links back to
`index.html`, then navigates to `c.localhost/c/other.html`, which loads the two
stylesheets of the first page. The stand answers a matching validator with 304.

**`-chips`** puts a frame of `b.localhost` on `www.a.localhost/k/index.html`.
The frame sets `u=1` (`SameSite=None; Secure`) and `p=1` (the same,
`Partitioned`), then fetches its own origin; the page shows an image of `b`.
Then `b` is visited at the top level (and sets `f=1`), framed under
`c.localhost`, and framed under `www.a` again — each time with the frame's
fetch and the page's image of `b`.

Chrome — which had updated itself to **154** on the stand by this run — and
Firefox 156, over HTTP/2 and HTTP/1.1. The captures are in `capture/cache/` and
`capture/chips/`, without the ClientHello bytes.

## What the browsers did

**The cache.** On `page2.html` neither browser asked for the fresh
stylesheet, the heuristic image or the immutable one; it asked conditionally
for the `no-cache` script (`If-None-Match`), the stale image (both
validators) and the API, and in full for the `no-store` script. A reload
revalidated the document — Chrome with `cache-control: max-age=0` as the first
header, Firefox without it — and treated the resources as a link would: the
fresh ones stayed in the cache. The link back revalidated `index.html`. Under
`c.localhost` both browsers fetched both stylesheets anew: the cache is keyed by
the top-level site, as it was said to be since Chrome 86 and Firefox 85.

**Where the validators go.**

| | Chrome 154 | Firefox 156 |
|---|---|---|
| a resource | `accept if-none-match if-modified-since sec-fetch-site …` | `… sec-fetch-site if-modified-since if-none-match priority te` |
| `fetch()` | `… accept-language cookie if-none-match priority` | `… sec-fetch-site if-none-match priority te` |
| a document | `… cookie if-none-match if-modified-since priority`, `cache-control` first on a reload | `… sec-fetch-site if-modified-since if-none-match priority te` |

Firefox revalidated the image with `priority: u=5` where it first asked with
`u=5, i`; Chrome's priorities did not move. Over HTTP/1.1 Chrome puts
`Cache-Control` right after `Connection`. Firefox's link navigations over
HTTP/1.1 wrote `Connection Referer Cookie Upgrade-Insecure-Requests` — the order
0.13 left open — and its reload of `page2.html` wrote `Referer` before
`Connection`.

**Cookies.** Chrome 154 sent `u` wherever `b` was asked for — framed under
`a`, at `b`'s top level, framed under `c` — and `p` only under `a`; `f`, set by
`b` at its top level, went to `b` everywhere. A header held `u=1; p=1; f=1` in
the order the cookies were made, the two jars interleaved. Firefox 156 kept both
`u` and `p` for `b` under `a` alone: `b`'s top level got neither, the frame under
`c` got nothing, and `f` went to no frame of `b` — every cookie a third party
sets is kept for the top-level site it was set under (Total Cookie Protection),
and a site's own cookies stay with its first-party visits.

**Connections.** Firefox put the frame of `b` under `a`, its fetch and `a`'s
image of `b` on one connection; `b` at its top level, and `b` under `c`, each on
another; back under `a` it reused the first. It keys connections by the
top-level site, where 0.13 kept Firefox's pool whole. Chrome put the image of `b` on one connection and the frame
with its fetch on another (the key's cross-site-frame bit), and on the return to
`a` opened new ones for everything.

The Chrome 154 the stand ran sent the `sec-ch-ua` that `chrome-154-windows`,
derived from 153 by `scripts/derive-current.py`, predicted, byte for byte.

## What changed

**An HTTP cache** (`internal/client/cache.go`), off by default: in memory, or
on disk so the next session starts as a returning visitor. Freshness is RFC
9111's — `max-age`, `Expires` against `Date`, a tenth of the `Last-Modified`
age — with `no-cache`, `no-store` and `Vary`; a 304 hands back the stored body
under the merged headers. The validators and a reload's `cache-control` take the
profile's slots, placed by `scripts/gen-resources.py` from the `-cache` captures
into the ordinary orders, the fetch set, the client-hints orders
(`scripts/gen-identities.py`) and every resource kind, and carried into the
derived presets. A request takes fetch()'s cache modes: `default`, `no-store`,
`no-cache` (a reload), `force-cache` and `only-if-cached`. The replay test
builds every conditional request of both captures and checks it name by name and
value by value, except Firefox's HTTP/1.1 reload.

**The top level** (`internal/client/partition.go`). The cache, the pool and the
partitioned cookies are keyed by the site in the address bar: the URL's own for
a top-level navigation, the page's otherwise — and, for a request made from a
frame, the page the frame is in, which only the caller knows: `top_level` on the
session or the request. Until now the cache and the pool took the page even on a
navigation, so a link from `a` to `b` kept `b`'s document and connection under
`a`.

**Partitioned cookies.** The family's cookie policy gained `partitioning`:
`partitioned` for Chromium (CHIPS: the `Partitioned` attribute), `third-party`
for Firefox (everything a third party sets, and the attribute). A partitioned
cookie lives in a jar of its own site and goes only under it; the two jars merge
into one header in the jar's order — longer path, then older. A `Partitioned`
cookie without `Secure` is refused. Safari — not measured; WebKit's documented
ITP — now keeps nothing a third party sets, where the jar used to keep it. The
cookie record carries `partition`, and export, import and rollback keep it. The
`-chips` captures are replayed request by request.

**Connections.** Firefox's policy keys the pool by the top-level site; the
cross-site-frame bit is Chromium's alone (`ConnPolicy.FramePartition`).

**Python.** `Session(cache=True | "dir", cache_size=)`, `top_level=` on the
session (and `s.top_level`) and per request, `cache=` per request with fetch()'s
modes, `r.cache` and `r.from_cache` on every kind of response,
`s.cache_info()` and `s.clear_cache()`, `load_page(reload=True)`, and
`partition` on a cookie and on `s.cookies.set()`. A partitioned cookie stays out
of a Netscape `cookies.txt`, which has no column for it: a plain line would send
it under every site. A session's `cache` given a request's mode name
(`cache="no-cache"`) is refused rather than taken for a directory. ABI 0.25.0.

## The speed pass

Go, `go test -bench`, 0.13.0 and this tree run in turn on one machine (the
HTTP/1.1 cases are new to the benchmark and were run on 0.13.0's code too):

| | 0.13.0 | 0.14.0 |
|---|---|---|
| header assembly, HTTP/1.1 navigation | 11.2–11.6 µs, 143 allocations | 4.2–4.7 µs, 13 allocations |
| header assembly, HTTP/1.1 fetch | 15.8–17.7 µs, 133 allocations | 6.1–6.3 µs, 16 allocations |
| header assembly, HTTP/1.1 POST fetch | 17.7–18.3 µs, 150 allocations | 6.9–7.7 µs, 17 allocations |
| header assembly, HTTP/2 navigation / fetch | 3.9–4.1 / 4.2–5.3 µs | 3.9–4.3 / 4.3–5.1 µs |
| a request with a 4.6 KB body and its `Content-Length` | 41.7 KB, 183 allocations | 35.4 KB, 169 allocations |

Most of an HTTP/1.1 request's allocations were header names lowercased to be
compared: the profile's capitalised order, once per header per request. Names
are compared in place now, and the lowercase order the transport wants is made
once per header set. HTTP/2 stays where it was with the partitions added: the
cookie path stops at an empty jar before it compares any sites, and a host's
registrable domain is remembered rather than looked up in the public suffix
list on every comparison. A body with a `Content-Length` is read
into a buffer of that size, not grown from 512 bytes by doubling.

Python, the package's side of one `s.get()` with the native call replaced by
a canned response of 26 headers (`timeit`, one machine, 0.13.0 and this tree in
turn):

| | 0.13.0 | 0.14.0 |
|---|---|---|
| a GET, Python side | 99 µs | 24 µs |
| `Headers` for 26 names | 54 µs | 6.8 µs |
| four `headers.get()` | 5.2 µs | 0.8 µs |
| the proxy lookup with no proxy set | 9 µs | 3.5 µs |
| the request frame | 492 bytes | 176 bytes |

`Headers` checked every name it added against every name it held, lowering
both, and every lookup walked the keys the same way; it keeps a lowercase index
now, and the native side's headers — one spelling per name — go in at once.
The proxy lookup parsed the URL and read `NO_PROXY` before learning that no
proxy variable was set; it reads the variables first, and on Windows, where the
environment ignores case, asks for `HTTPS_PROXY` once instead of twice. The
request frame drops the fields that are `None` — the native side reads a
missing field and a null alike — and its spaces; the caller's `json_body` is
encoded as before.

## Left open

- Firefox's reload over HTTP/1.1 writes `Referer` before `Connection`; the
  profile's order is its link navigation's. The replay test skips that request.
- The partition key is the top-level site alone. Chromium documents a bit for
  a frame chain that leaves the site and comes back (`a` framed in `b` framed
  in `a`); the stand did not measure it, and the library treats such a request
  as a third party but keys it as `a`.
- Chrome opened new connections for everything when the stand came back to
  `a`, where Firefox reused its old ones; what closed Chrome's is not measured.
- fetch()'s `reload` cache mode (a full request that replaces the stored
  response) is not offered: `no-cache` is what a browser's reload does.
