# Stage 21 — resources, connections, free threading, the review's remainder

Date: 2026-09-26. Four items the owner picked from the list of what to do next:
requests for a page's resources and a page load built on them; connections
spent the way a browser spends them; Python without the GIL; the three
optimisations the review of the same day left open. The first two needed a
measurement the stand could not take, so it starts there.

## The stand: `cmd/hcapture -subres` and `-h1`

A page on `www.a.localhost` that loads what a real page loads: a stylesheet
with a `@font-face` and a background image in it, a preloaded stylesheet,
script and font, a `modulepreload`, a `prefetch`, a blocking script in `<head>`
and one in `<body>`, an async, a deferred and a module script, images from its
own origin, a sibling of its site (`api.a.localhost`) and another site
(`b.localhost`, `d.localhost`), plain, `crossorigin` and
`crossorigin=use-credentials`, a cross-site stylesheet, script and two frames,
two beacons, two scripts inserted by script. Once loaded it measures
connections: bursts of 1, 2, 4, 8 and 16 parallel first fetches to hosts it
never touched, credentialed and not, and a credentialed series to a host that
set a `SameSite=None` cookie. Every record now carries the TCP connection it
came on and when it arrived; every connection's life is logged with its SNI
and who ended it. `-h1` offers `http/1.1` alone and records HTTP/1.1 requests
with their case, parsed by hand like the HTTP/2 frames. The certificate
(`capture/certs-multi`) covers `localhost`, `*.localhost` and `*.a.localhost`.

Chrome 153 (headless, `--ignore-certificate-errors-spki-list`) and Firefox 156
(a throwaway profile trusting the stand through `cert_override.txt`), five runs
over HTTP/2 and one over HTTP/1.1 each. The captures are in `capture/subres/`
(without the ClientHello bytes).

## What the browsers sent

**Each kind of resource has a set of its own.** `sec-fetch-dest`,
`sec-fetch-mode`, `Accept` and `priority`, by what the markup says:

| Kind | Chrome 153 `priority` | Firefox 156 `priority` | `Accept` (Chrome / Firefox) |
|---|---|---|---|
| stylesheet, preloaded stylesheet | `u=0`, `u=0` | `u=2`, `u=0` | `text/css,*/*;q=0.1` both |
| blocking script in `<head>`, in `<body>` | `u=1`, `u=2` | `u=2`, none | `*/*` |
| async, deferred, script-inserted script | none | none | `*/*` |
| preloaded script, module, modulepreload | `u=1`, `u=1`, `u=1` | `u=1`, none, `u=1` | `*/*` |
| `<img>`, CSS background, icon | `i`, `i`, `u=1, i` | `u=5, i`, `u=4, i`, `u=6` | `image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8` / `image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5` |
| font from `@font-face`, preloaded font | `u=0`, `u=1` | none, `u=2` | `*/*` / `application/font-woff2;q=1.0,application/font-woff;q=0.9,*/*;q=0.8` |
| `<iframe>` document | `u=0, i` | `u=4` | the document `Accept` |
| prefetch (`sec-purpose: prefetch`), beacon | `u=4, i`, `u=4, i` | `u=6`, `u=6` | the document `Accept`; `*/*` |

Firefox asks for a font named by `@font-face` with `Accept-Encoding: identity`
— six runs of six — and for a preloaded one with the usual list. A request a
stylesheet makes names the stylesheet as its `Referer`; `sec-fetch-site` stays
the document's relation.

**The orders.** Chrome's no-cors order is its fetch order without the body
slots; a CORS resource puts `Origin` **first** (`origin, sec-ch-ua-platform,
user-agent, …`), where fetch() puts it after `accept`. Chrome sends `Origin`
on every CORS resource, its own origin included; Firefox only across origins.
Firefox writes `Referer` after `Origin` on a CORS resource and before it on
fetch(); a beacon has an order of its own there (`content-type,
content-length, sec-fetch-storage-access, origin, referer, cookie`). On
HTTP/1.1 Firefox's preloaded font writes `Referer` before `Connection` where
every other resource writes it after — the one order a kind needed alone.

**`sec-fetch-storage-access`** (Storage Access Headers). Both browsers send it
on a cross-site request that carries credentials — a no-cors resource, a
credentialed fetch or CORS resource, a frame — and never on a top-level
navigation nor on a same-site one: `active` in Chrome (third-party cookies are
allowed), `none` in Firefox (Total Cookie Protection). The fetch sets of the
Chrome 153 and Firefox 156 profiles lacked it: their credentialed cross-site
fetches went out without a header the browsers send.

**Connections.**

| | Chrome 153 | Firefox 156 |
|---|---|---|
| n parallel first requests to a fresh host | min(n, 4) TLS handshakes: 1, 2, 4, 4 for 1, 2, 4, 16; 3 or 4 for 8, by timing | min(n, 6): 1, 2, 4, 6, 6 |
| the spares, once one is up as HTTP/2 | closed right after the handshake, before the preface; one still handshaking abandoned | the HTTP/2 session set up, then GOAWAY; two still handshaking abandoned |
| another name on the same address | rode an HTTP/2 connection whose certificate covered it (`api.a.localhost` on `www.a`'s; later `www.a` on `d.localhost`'s); `*.localhost` did not count for `b`, `c`, `d` | its own connection every time — but see below |
| no-cors and `crossorigin` image to one host | two connections (privacy mode) | one |
| fetch `omit` and `include` to one host | two | one in four runs of five |
| an iframe to a host already connected | its own connection (the key's cross-site bit) | the same connection |

"One handshake per burst", the phrase the item was written with, is not what
either browser does; each races a few, and a library that opens one per
request races as many as there are requests.

Two things on the stand are not the browsers. Chrome closed every idle
connection at once, twice, about a second after start: a fresh profile's
certificate components loading. And Firefox's HTTP/2 coalescing is switched
off for a certificate trusted through an override, which the stand's is, so
Firefox's pooling across names is not measured.

## What changed

**Resource requests.** A profile section `resources` (ABI 0.24): the orders
by name (`no-cors`, `cors`, `navigate`), the HTTP/1.1 orders, seventeen kinds
with their `dest`, `mode`, `accept`, `accept_encoding`, `priority` and
`purpose`, `storage_access` and `cors_origin`. Written by
`scripts/gen-resources.py` from the captures into `chrome-153-windows` and
`firefox-156-windows`, and inherited down their chains (Chrome 153/154 on every
desktop, Edge 153/154, Firefox 156). The generator merges each group's
sequences with a topological sort and gives a kind an order of its own only
where its sequence contradicts the group's. The fetch sets of both deltas gain
the `sec-fetch-storage-access` slot at the measured position.

`resource=` and `crossorigin=` per request: the kind's set, the credentials
the element would carry (no-cors always; CORS to its own origin, or everywhere
with `use-credentials`), `Origin` as the family sends it, the storage-access
header on cross-site credentialed requests, a frame keyed apart in the pool.
`TestResourcesReplayStand` rebuilds every captured request from what a caller
would pass and requires the browser's set — names, order, HTTP/1.1 case,
values — over both transports and both browsers. Three things it skips, each
said in the test: Firefox's partitioned cookie (below), the stand's headless
User-Agent, and a navigation started by script, which carries no
`sec-fetch-user`.

`Session.load_page()` and `AsyncSession.load_page()`: the document as a
navigation, then what the markup names — stylesheets, preloads, scripts,
images, frames — at once in the markup's order, each as its kind; the icon
(`/favicon.ico` without a `<link rel=icon>`) and prefetches after the load;
`css=True` for the fonts the stylesheets declare, with the stylesheet as the
referrer. Nothing a script or a layout would decide is guessed.

**Connections** (`profile.ConnPolicy`, per family). A request with no
connection to a host whose protocol is unknown joins the key's attempt group,
which starts one attempt per waiting request up to four (Chromium) or six
(Firefox). The first to come up as HTTP/2 goes into the pool for all of them;
attempts still handshaking are abandoned; a spare that finishes is closed
before the preface in Chromium and after it, with GOAWAY, in Firefox — two
handshakes finishing together are settled by a claim, so exactly one reaches
the preface. An HTTP/1.1 result goes into the pool idle and marks the host,
so the remaining requests dial in parallel as before. A failure reaches every
waiter at once; each keeps its own connect limit. Chromium also pools across
names by address — a verified certificate covering the name, the wildcard not
standing over a registry-controlled name — and keys the pool by privacy mode
and by the page's site. Families without a measurement keep the old
behaviour. The stand in the tests counts what a CDN counts: TCP connections,
which of them sent the HTTP/2 preface, which carried a request.

**Free-threaded Python.** The package is ctypes and pure Python, the wheel
`py3-none`, so it installs on 3.14t as it is and leaves the GIL off. The audit
of its shared state found one real race, and not only without the GIL:
`ensure_loaded()` set its flag before loading the bundled profiles, and a
second thread opening a session at the same moment found an empty registry —
seven sessions of eight failed that way on 3.14 with the GIL. It is now
double-checked under a lock. `tests/test_threads.py` puts one session under
sixteen threads, a session per thread, parsing in threads, and the start-up
race; CI runs the suite on 3.14t with the GIL off, checks that importing the
package does not switch it on, installs every platform's wheel there, and
prints `scripts/ft-scaling.py`. On the measuring machine (sixteen cores),
3.14.6 free-threaded from the `python-freethreaded` package ran the whole
offline suite with the GIL off — 714 passed, the GIL check among them — and
importing the package, `websockets`' speedups included, left the GIL off.
Fetching and parsing 48 pages:

| | 1 thread | 8 threads | speedup |
|---|---|---|---|
| 3.14.6 with the GIL | 0.70 s | 0.69 s | x1.0 |
| 3.14.6 free-threaded, GIL off | 0.70 s | 0.17 s | x4.2 (x3.1 over four) |

**The review's remainder** (Go, `go test -bench`):

| | before | after |
|---|---|---|
| header assembly, navigation | 22 µs, 57 allocations, 13.1 KB | 6.9 µs, 13 allocations, 3.5 KB |
| header assembly, fetch from a page | 22 µs, 60 allocations | 7.8 µs, 15 allocations |
| a request with a 4.6 KB body, HTTP/2 | 224 allocations, 53 KB | 175 allocations, 41 KB |
| the same, gzip / zstd | 92 KB / 64 KB | 39 KB / 35 KB |
| zstd decode alone | 11 µs, 16.6 KB, 18 allocations | 4.3 µs, 185 B, 5 allocations |

The header sets are resolved once per session instead of twice per request,
`modeFor` stops rebuilding its map, `reorder` and `wireOrder` find what they
need in a merge pass instead of three maps, and the site relations work on
parsed URLs. zstd and gzip decoders are pooled; a body's Close waits for a Read
still inside the decoder before handing it on, so a pooled decoder is never in
two responses. The pool is swept at most once a second (half the idle timeout
when that is shorter), and the pick refuses an expired connection itself.

## Left open

- Firefox's partitioned cookies: a cookie a cross-site response sets is kept
  for that top-level site and sent back from it (the stand's `d.localhost`
  cookie was); the jar has no partitions, and the Firefox policy sends no
  cookie across sites.
- Firefox's HTTP/2 coalescing across names: needs a CA Firefox trusts without
  an override.
- Chrome queues a seventh HTTP/1.1 request to a host until a socket frees; the
  pool opens a connection for it that lives one request.
- A Firefox 156 navigation started by script wrote `Connection` before
  `Referer` and `Cookie` before `Upgrade-Insecure-Requests` over HTTP/1.1; the
  profile's order, from a Firefox 154 capture with form posts, has them the
  other way. Which kinds of navigation take which is not measured.
