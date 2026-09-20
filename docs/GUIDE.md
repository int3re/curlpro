# curlPro — the complete guide

*[Русская версия](GUIDE.ru.md)*

This is the whole library in one document, written for two readers: a person
integrating it, and an AI assistant researching it before touching code. Every
number and every behaviour here was checked against the code on 2026-09-20, at
version 0.9.0. Where the README says less, this document says more; where the
two disagree, this one is wrong and should be fixed — say so.

An assistant reading this: the library already does most of what a scraper
writes by hand. Section 15 lists what not to reimplement. Section 16 lists the
claims that were checked and the ones that turned out to be false.

## 1. What it is, in three sentences

curlPro is an HTTP client for Python whose traffic carries a browser's network
fingerprint: the TLS ClientHello, the HTTP/2 and HTTP/3 frames, the header set,
order and case, the WebSocket handshake, even the multipart boundary. The
browser is described by a JSON profile, not by code, so a new browser version
is a data edit that any user can make at runtime. The Python package is a thin
`ctypes` layer over a Go library (uTLS for TLS, a patched fhttp for HTTP/1.1
and HTTP/2, a vendored uquic for HTTP/3) that ships inside the wheel.

Four rules govern everything below. They explain most behaviour that looks
surprising at first:

- **Profiles are data.** A browser is a `.json` file; the code is generic. If
  something about a browser changes, the profile changes, not the library.
- **Measured, not assumed.** A value goes into a profile only after it was seen
  on the wire from a real browser. Where nothing was measured the library says
  so rather than guessing.
- **Refuse rather than ignore.** An option that cannot be honoured raises with
  the reason. Nothing is silently downgraded, dropped or substituted.
- **The wire is the truth.** `session.fingerprint()` and `session.audit()` are
  computed from the bytes that would go out, not from the configuration.

## 2. Install and run

```bash
pip install curlpro
```

The wheel carries the native library and all 50 profiles; neither Go nor a C
compiler is needed. Wheels exist for Linux x86-64 and ARM64 (glibc 2.28+),
macOS 13+ on Intel and Apple Silicon, and Windows x64; Python 3.9 or newer.
Anything else builds from the source archive with Go and a C compiler
(`README.md`, "Install").

Three ways profiles reach the library:

- **From the wheel, automatically.** `ensure_loaded()` runs on the first
  `Session`; nothing to call.
- **From a directory.** `curlpro.load_profiles("profiles")` — this is what a
  checkout of the repository needs, because there the profiles live next to the
  package rather than inside it.
- **At runtime.** `curlpro.register_profile(dict_or_json)` adds one profile
  without a release.

The native library has an ABI version (`0.20` for this release) that the Python
side checks on import. A wheel always carries a matching pair; the check exists
for source builds and for `CURLPRO_LIBRARY`, which points the package at a
library of your own. A mismatch raises at import time with the rebuild command
in the message.

From a checkout on Windows: `.\build.ps1` writes `dist/curlpro.dll`, then
`cd python; $env:PYTHONPATH='.'; python -m pytest tests`.

## 3. The mental model

Three layers, each adding to the one below:

| Layer | Owns | Set where |
|---|---|---|
| Profile | the fingerprint: TLS, HTTP/2, HTTP/3, the header sets and their order, the WebSocket handshake, devices | `profiles/*.json`, `register_profile()` |
| Session | memory and policy: cookies, added headers, removed headers, proxy, timeouts, retries, redirects, the device, the mode | `curlpro.Session(...)` |
| Request | one exchange: body, params, headers, order, protocol, and any override of a session policy | `s.get(...)`, `s.request(...)` |

A request is assembled as: profile headers for the chosen set (navigation or
fetch), then the session's headers, then the request's, then the order pattern,
then removals. The result is what `fingerprint().headers` previews. The same
assembly serves HTTP/1.1, HTTP/2 and HTTP/3 — there is one copy of the rules.

## 4. Sessions: every parameter

`curlpro.Session(impersonate="chrome-151-windows", **options)`. Every option
has a default that reproduces a browser; the table says what changes when you
touch it.

| Parameter | Default | Meaning |
|---|---|---|
| `impersonate` | `chrome-151-windows` | the profile name; `list_profiles()` has all 50 |
| `verify` | `True` | `True` — system roots; a PEM path — trust only that root; `False` — no verification |
| `cert` | `None` | `(certificate, key)` paths for mutual TLS |
| `trust_env` | `True` | take the proxy from `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`, honouring `NO_PROXY`; an explicit `proxy` always wins |
| `timeout` | `30.0` | a limit on the **whole** request, redirects included; a `(connect, total)` pair bounds connecting separately. `float("inf")` means no limit |
| `connect_timeout` | `None` | the connecting limit by name: resolution, TCP, TLS. Wins over the pair's first element |
| `response_timeout` | `None` | how long to wait for the response **headers** after the request went out. Does not bound the body. Raises `Timeout` with "response headers" in the message |
| `proxy` | `None` | `http://`, `https://`, `socks5://`, `socks5h://`, `user:pass@` allowed; a bare `host:port` is read as `http://`. The first CONNECT carries no credentials and adds them after a 407, as Chrome does; a proxy that hangs up instead gets a second CONNECT with them on a fresh connection; one that hangs up on that too raises with code `proxy_closed` |
| `default_headers` | `True` | send the profile's headers. `False` sends only yours — and no `User-Agent` at all unless you pass one; the library never substitutes Go's |
| `header_order` | `None` | the send order as a pattern with `...` for the profile's own order; section 6 |
| `allow_redirects`, `max_redirects` | `True`, `20` | follow 3xx; the chain is in `r.history` |
| `cookies` | `True` | the jar shared by the session's requests |
| `force_http1` | `False` | offer `http/1.1` alone in ALPN. This changes JA4 (two characters of it), legitimately: a browser without h2 looks like that |
| `post_quantum` | `True` | `False` drops X25519MLKEM768 and its 1216-byte key share: the hello of a browser with post-quantum key agreement off by policy. JA4 stays, JA3 and the size move, the hello fits one TCP segment |
| `resume` | `True` | TLS session resumption with tickets, one cache per session, as a browser does. On since the resuming hello was measured (Chrome 153 and Firefox 156): the first hello plus `pre_shared_key` last, no early data, and for Firefox without `session_ticket` — which is what goes out. The first hello of a session is untouched, so every fingerprint stays what it was |
| `http3` | `False` | go to QUIC at once. The profile needs an `http3` section (four have one, section 12) |
| `alt_svc` | `True` | move to HTTP/3 after an `Alt-Svc` header, as a browser does; a failed attempt falls back to TCP and is not retried for 5 minutes, doubling up to 24 hours. Needs an `http3` section; not through a proxy |
| `resolve` | `None` | `{"example.com:443": "10.0.0.7"}` — curl's `--resolve`; SNI and `Host` keep the name. Not through a proxy |
| `ip_version` | `None` | `"4"` or `"6"` — one address family |
| `keep_alive` | `True` | reuse connections. `False` closes after each response, without sending `Connection: close` |
| `max_idle_conns`, `idle_conn_timeout` | `0`, `0.0` | pool size and idle lifetime; zero means the library's defaults |
| `retries` | `0` | attempts after the first. Only idempotent methods are retried unless `retry_methods` says otherwise |
| `retry_statuses` | 408, 429, 500, 502, 503, 504 | which responses count as failures worth repeating |
| `retry_methods` | idempotent | GET, HEAD, PUT, DELETE, OPTIONS, TRACE; an explicit list allows POST |
| `retry_backoff`, `retry_max_backoff` | `0.2`, `10.0` | seconds; exponential between the two |
| `respect_retry_after` | `True` | a `Retry-After` header sets the wait |
| `mode` | `"auto"` | the header set: `navigate`, `fetch`, or decided per request (section 7) |
| `page` | `None` | the page the requests are made from — the initiator. Derives `Referer`, `Origin` and `sec-fetch-site` the way a browser does (section 7); `s.page = url` moves it as the scraper moves. Must be an absolute http(s) URL |
| `device`, `devices` | `None` | the phone for mobile profiles — a name from the profile's list or `"random"` — and a list of your own (section 11) |
| `max_response_size` | `0` | a body limit in bytes; exceeding it raises with code `too_large`. Binds `read()`, not `iter_content()` |
| `hooks` | `None` | `{"request": [...], "response": [...], "error": [...]}`; section 9 |

Session attributes worth knowing: `s.headers` (a mapping of the headers you
added, plus `s.headers.suppressed`), `s.cookies` (section 10), `s.hooks`,
`s.impersonate`, `s.fingerprint(url="https://example.com/")`, `s.audit()`,
`s.close()`. A session is a context manager; `__del__` closes it as well.

## 5. Requests: every parameter and the response

`s.request(method, url, **kw)`, with `get`, `post`, `put`, `patch`, `delete`,
`head`, `options` as shorthands. The module-level `curlpro.get(url, impersonate=...)`
and friends open a session for one request. Everything a session sets can be
overridden here for one request; `None` means "the session's".

| Parameter | Meaning |
|---|---|
| `params` | query string, a mapping or pairs, merged into the URL |
| `auth` | `("user", "password")` for Basic, or a string used as the bearer token |
| `data` | the body as bytes or str |
| `json_body` | any JSON-serialisable value; sets `content-type: application/json` unless you did |
| `fields` | a form; alone it is `application/x-www-form-urlencoded`, with `files` it is multipart |
| `files` | multipart files; the boundary is generated in the profile's style (`----WebKitFormBoundary…` for Chrome, dashes for Firefox) |
| `body_file` | a path streamed as the body with an explicit `Content-Length`; a browser never uploads a file chunked |
| `headers` | your headers. A value of `None` **removes** a header the profile or the session would send; `""` sends it empty. Anything else than `str` or `None` is a `TypeError` naming the header |
| `header_order` | the order pattern for this request, beating the session's (section 6) |
| `default_headers` | `True`/`False` — the profile headers, either way, for this request |
| `session_headers` | `False` — without the headers and removals set on the session |
| `cookies` | `False` — neither sends the jar nor stores `Set-Cookie`; two-way on purpose |
| `protocol` | `"http1"`/`1.1`, `"h2"`/`2`, `"h3"`/`3`. `h2` keeps the full ALPN list and **fails** if the server picks `http/1.1` (no browser offers h2 alone); `h3` needs TLS; over `http://` both are refused |
| `timeout`, `connect_timeout`, `response_timeout` | as on the session, for this request |
| `proxy` | an address, or `False` to go directly past the session proxy |
| `allow_redirects`, `max_redirects`, `retries`, `retry_*`, `respect_retry_after` | overrides of the session policy; `retries=0` switches the session's retries off for this request |
| `mode` | `"navigate"` or `"fetch"`; `fetch` on a profile without a fetch set is refused with the reason |
| `page` | the page this request is made from, overriding the session's; `False` sends it with no initiator at all |
| `expect` | an `Expect(...)`; a mismatch raises `ExpectationFailed` (section 8) |
| `rollback_cookies` | `True` restores the jar to its state before the request if the request fails, a failed expectation included |

The response:

| Member | Meaning |
|---|---|
| `status`, `ok`, `proto` | `200`, `status < 400`, `"HTTP/1.1"` / `"HTTP/2.0"` / `"HTTP/3.0"` |
| `headers` | `dict[str, list[str]]` — every value of every header |
| `header(name)` | the first value, case-insensitive, or `None` |
| `content`, `text` | bytes; str decoded with the detected charset |
| `encoding` | detected from `Content-Type`, then the BOM, then a `<meta charset>` in the first kilobytes; assignable when a site declares it wrongly |
| `json()` | `json.loads` on the raw bytes — UTF-8/16/32 are recognised by the parser itself |
| `url` | the final URL after redirects |
| `history` | the redirect chain as `Redirect(status, url, location)` records |
| `cookies` | the cookies **this** response set, as a mapping |
| `elapsed` | seconds, measured in Python around the native call |
| `raise_for_status()` | raises `HTTPError` (with `.status` and `.response`) on 4xx/5xx; returns the response otherwise |

Bodies arrive decoded: `gzip`, `deflate` (zlib or raw), `br` and `zstd`, in any
stacked order the server used. There is nothing to decompress yourself.

A redirect from `https://` to `http://` is not followed: the 3xx is returned with
its `Location`, because following it would put cookies and credentials on the
wire in clear text. Cleartext `http://` itself works — with the profile's
HTTP/1.1 header order and case, since that is all a plain-HTTP peer can see.

## 6. Headers: the set, the order, removals

**The set** comes from the profile and depends on the mode (section 7). Your
headers are layered on top: a name the profile already sends keeps its
position and takes your value; a new name goes where a browser would put a
custom header — before the profile's anchor, not at the end.

**Removal** is `None`: `headers={"Sec-Fetch-User": None}` for one request,
`s.headers["Sec-Fetch-User"] = None` for every request of the session. The rest
of the set is untouched. `""` is a value and is sent as an empty header, the way
a browser's `fetch()` sends one. The request's own value beats the session's
removal; `del s.headers[name]` and `s.headers.clear()` lift removals the way they
drop values; `s.headers.suppressed` lists them.

**The order** is a pattern over the browser's order, on the session or the
request. `...` stands for "the profile's own headers here":

```python
s.get(url, headers={"X-Api-Key": "k"},
      header_order=[..., "accept", "x-api-key", ...])   # right after Accept, the rest untouched
s.get(url, header_order=["x-api-key", ...])            # first
s.get(url, header_order=[..., "x-api-key"])            # last
s.get(url, header_order=[..., "accept-encoding", "accept-language", ...])   # two profile headers swapped
```

Rules: several `...` are allowed, and an unlisted profile header stays beside
the listed neighbour it follows in the profile; a list without `...` is the
list followed by the rest of the profile; names the request does not carry are
skipped, so one pattern serves every request; a name listed twice is refused;
a custom header the pattern does not mention still goes before the anchor. The
expansion runs against the order of the transport actually used — HTTP/1.1 has
`Host` and `Connection` and its own case, HTTP/2 has neither — so
`fingerprint().headers` and `headers_http1` show exactly what will go out.

`default_headers=False` is the blunt instrument: it drops the whole profile set,
`User-Agent` included, and the order with it. Since 0.7.0 it is rarely the right
tool; `None` removes one header and keeps the rest.

## 7. Navigation and fetch

A browser sends different header sets for a page load and for a `fetch()` or
XHR from a page. The fetch set has `accept: */*`, `sec-fetch-mode: cors`,
`sec-fetch-dest: empty`, `Origin`, `Referer`, and no `upgrade-insecure-requests`
or `sec-fetch-user`. Every Chromium, Firefox, Tor and Yandex profile carries
both sets, measured (Chrome 152 and Firefox 154 on a raw stand); Safari and
okhttp carry only the navigation set.

In `mode="auto"` (the default) the request itself decides, and any of these
means fetch:

- a method other than GET, HEAD or POST;
- a body that is not a form — JSON, XML;
- a header the navigation set never carries — any custom `X-…`, `Authorization`;
- a fetch-metadata value no navigation has: `sec-fetch-mode: cors`,
  `sec-fetch-dest: empty`.

So `s.get(url, headers={"X-Api-Key": "k"})` goes out as a fetch, which is what a
browser does with a custom header. When that is wrong for you, say
`mode="navigate"`. An explicit `mode="fetch"` on a profile without a fetch set is
refused with the reason: the navigation set under a fetch name — `sec-fetch-user:
?1` beside `sec-fetch-mode: cors` — is a request no browser makes, and an
anti-bot reads the pair for free.

**The page a request is made from.** A browser's fetch always comes from a page,
and three headers say which: `Referer`, `Origin` and `sec-fetch-site`. Without a
page the profile's own values go out — a navigation typed into the bar
(`sec-fetch-site: none`, no Referer) and a fetch from the request's own origin.
Name the page, on the session or the request, and the three are derived the way
Chrome 153 and Firefox 156 derive them (measured on `cmd/hcapture -origins`,
where the two agreed on every value):

```python
r = s.get("https://example.com/app")                 # the navigation: none, no Referer
s.page = r.url                                       # from here on, from that page
s.post("https://api.example.com/v1/x", json_body=...)
# origin: https://example.com   referer: https://example.com/   sec-fetch-site: cross-site
s.get("https://example.com/next", page=False)        # one request with no initiator
```

| Header | Rule (default policy `strict-origin-when-cross-origin`) |
|---|---|
| `Referer` | the page's URL, fragment and credentials stripped, to its own origin; the page's origin with a trailing slash to any other; nothing from an https page to an http URL |
| `Origin` | the page's origin — on every cross-origin fetch, with or without a body, and on any request with a body, a form post included; a same-origin GET fetch carries none |
| `sec-fetch-site` | `same-origin`, `same-site` (one registrable domain, by the public suffix list) or `cross-site`; along a redirect chain it is the relation of the page to every URL of the chain and only ever degrades |

A navigation from a page is treated as a click: `sec-fetch-user: ?1` stays. The
Referer sits where each family puts it — after `sec-fetch-dest` in Chromium,
after `Origin` in Firefox — through a slot in every profile. Your own `Referer`,
`Origin` or `sec-fetch-site` header wins over the derived one. Two things are
deliberately not done: cookies are sent as the jar says, not withheld on
cross-origin fetches the way an uncredentialed `fetch()` withholds them, and no
CORS preflight is sent before a non-simple cross-origin request — a browser
sends an `OPTIONS` first, and that is measured but not yet reproduced.

## 8. Expectations and cookie rollback

```python
from curlpro import Expect

r = s.get(url, expect=Expect(status=200, body="Dashboard", not_body="captcha",
                             non_empty=True, encoding="utf-8"))
```

| Field | Checks |
|---|---|
| `status`, `not_status` | the code; several values mean "one of" |
| `body`, `not_body` | substrings in the body; several mean "all of" |
| `headers`, `not_headers` | substrings among the `name: value` lines, case-insensitively |
| `non_empty` | the body is not empty |
| `json` | the body parses as JSON |
| `encoding` | the detected charset is this one; `cp1251` and `windows-1251` compare equal |

A mismatch raises `ExpectationFailed` (code `expectation`), a `CurlProError`
with the response attached. The check runs after the response hooks, on what
they returned.

`rollback_cookies=True` on a request, or `with s.cookies.transaction():` around
several, restores the jar if the block raises — a half-finished login is worse
than none. The snapshot is taken before sending; the rollback happens before the
error hooks run, so a hook that goes to the network sees the jar as it was.

## 9. Errors and hooks

```python
try:
    r = s.get(url)
    r.raise_for_status()
except curlpro.Timeout:                  # code "timeout"
    ...
except curlpro.ExpectationFailed as e:   # code "expectation", e.response kept
    ...
except curlpro.HTTPError as e:           # from raise_for_status(): e.status, e.response
    ...
except curlpro.WebSocketClosed:          # code "ws_closed"
    ...
except curlpro.CurlProError as e:        # everything else: e.code, str(e)
    ...
```

`CurlProError` is a `RuntimeError`; everything else here derives from it.
Branch on the type or on `code`, never on the message — messages are written
for people and are improved freely.

The first question a scraper asks is whether to retry, and the hierarchy
answers it:

```python
except curlpro.PermanentError:      # never retry: the answer will not change
except curlpro.Timeout:             # retry
except curlpro.CurlProError:        # everything else, usually worth one retry
```

`PermanentError` has two kinds. `ProfileCapabilityError` (`profile_capability`)
means the profile cannot do what was asked — no fetch set, no `http3` section,
no ALPN to restrict, no devices; ask :func:`capabilities` first or move to
another profile. `ConfigurationError` (`configuration`) means the arguments do
not make sense — an unregistered profile name, a device not in the list, a
page that is not a URL, a header listed twice. Both used to arrive as a plain
`CurlProError` with no code, indistinguishable from a blinked connection, and
a worker that retried them three times and dropped the task is where they come
from.

The codes: `timeout`, `expectation`, `profile_capability`, `configuration`,
`session_closed`, `too_large`, `ws_closed`, `ws_too_big`, `ws_protocol`,
`proxy_closed`. An error without a code is an ordinary failure with the reason
in the text.

Three hooks, each a list of callables on `s.hooks[...]`, also addable with
`@s.on_request`, `@s.on_response`, `@s.on_error`:

- **request** receives the request description — a dict with `method`, `url`,
  `headers` and the rest of the frame — before sending; it may edit it in place
  or return a replacement.
- **response** receives the `Response` after it arrived and may return a
  replacement; the expectation is checked on the replacement.
- **error** receives the exception of a failed request (network, timeout, a
  failed expectation) and may return an exception to raise instead. A hook that
  itself raises does not hide the original failure: the failure is noted on the
  exception and the remaining hooks still run.

## 10. Cookies

`s.cookies` is a mapping by name for reading, and a full jar underneath:

| Call | Does |
|---|---|
| `s.cookies["sid"]`, `.get`, `.keys`, `.items`, `.values` | the values |
| `.all()` | the full records as `Cookie` dicts: name, value, domain, path, expires (epoch seconds, 0 for a session cookie), flags |
| `.set(name, value, *, domain, path="/", expires=0, secure=False, http_only=False, same_site="")` | adds one; the domain is required |
| `.load(list)`, `.export()` | plain records in and out |
| `.save(path)`, `.load_file(path)` | JSON; `load_file` also reads Netscape `cookies.txt`, recognised by content, and treats a missing file as an empty first run |
| `.save_netscape(path)`, `.load_netscape(path)`, `.to_netscape()` | the `cookies.txt` that curl, wget, yt-dlp and browser extensions use |
| `.snapshot()`, `.restore(snapshot)`, `.transaction()` | the rollback machinery |
| `.clear()` | forget everything |

`r.cookies` on a response is only what that response set.

## 11. Profiles, devices and mobile

50 profiles ship in the wheel: 25 Chrome (98 to 152), 6 Edge, 4 Firefox (133,
135, 144, 155), 11 Safari (15.3 to 26.0.1, macOS and iOS), Tor 14, Yandex
Browser 26.8 for Android, and two okhttp 5.5 (JVM and Conscrypt). Many share a
TLS fingerprint: the 50 profiles form 17 distinct JA4 values, because a browser
family keeps its ClientHello across several versions and differs in the
User-Agent and headers. One group — Chrome 119 to 131 and Edge 119/120, the
last Chromium hellos before the post-quantum key share — shows a second JA4
spelling on some connections (`…1517…` beside `…1516…`): its hello sits near
512 bytes, and the padding extension appears or not with the random size of
the ECH GREASE payload, exactly as in the browsers themselves. The baselines
list both. `list_profiles()` names them all.

What each family carries, resolved through inheritance:

| Family | Navigation set | Fetch set | HTTP/1.1 set | WebSocket | HTTP/3 |
|---|---|---|---|---|---|
| Chrome, Edge, Yandex | yes | measured | yes | yes | chrome-151-windows, chrome-152-windows, chrome-152-android, yandex-26.8-android |
| Firefox, Tor | yes | measured | yes | yes | no |
| Safari | yes | **derived** | yes | no | no |
| okhttp | yes | none — a library has no fetch | no | no | no |

`curlpro.capabilities(name)` answers all of this for one profile without
opening a session: the modes it carries, the protocols it can speak, its
devices, whether it answers `Accept-CH`, and whether its fetch set is derived.

**The Safari fetch set is the one derived thing in the corpus.** Eleven Safari
profiles had no fetch set, so `mode="fetch"` on them was refused and they could
not make an XHR at all — and a user reported Safari passing their anti-bot
about twice as often as any Chrome while being unusable for exactly that
reason. `scripts/gen-safari-fetch.py` writes one from the Fetch standard and
the profile's own navigation set: `accept: */*`, no `upgrade-insecure-requests`
or `sec-fetch-user`, `sec-fetch-mode: cors`, `sec-fetch-dest: empty`, slots for
`Origin`, `Referer` and the body's headers — and, for the 15.x profiles, no
`sec-fetch-*` at all, because WebKit shipped Fetch Metadata in Safari 16.4 and
inventing them would be a worse tell than the missing set was. The **set** is
solid; the **order** is a guess, and order is part of the fingerprint. So it is
marked: `capabilities()["derived_fetch"]` is true, and `audit()` raises
`derived_fetch_set` whenever such a set is actually in use. Replace it with a
capture the day a Mac or an iPhone is at hand.

**Mobile.** `chrome-152-android` and `yandex-26.8-android` carry a pool of 46
real phones — exact `ro.product.model` strings from Google's Play device
catalogue, on plausible Android versions. `device="Pixel 8"` or
`device="random"` picks one for the session. The model travels in the
`sec-ch-ua-model` and `sec-ch-ua-platform-version` client hints, sent only after
the site asked with `Accept-CH` (and at once on `Critical-CH`), and — on both
profiles — in the User-Agent string, so the pool is 46 distinct strings. On
Yandex that is what the browser does. On Chrome it is a deliberate departure,
decided by the project's owner: a stock Chrome ≥110 sends the reduced
`Android 10; K` for every phone and discloses the model only in the hints, and
a defence that knows about the reduction can tell an unreduced string. Without
a device the profile goes out as captured, reduced string included. Your own
list goes in `devices=[{"name": ..., "model": ..., "platform_version": ...}]`.
A name not in the list is refused.

**Inheritance.** A profile may name `based_on`; it then stores only its
differences. Chrome 110 over Chrome 98 is one line: extension shuffling on.
`Profile.from_file(path).derive("chrome-153-windows", headers={...}).register()`
makes a delta from Python; `register_profile()` takes a dict, a JSON string or
bytes. The schema is in `docs/PROFILE-SCHEMA.md`.

**Capturing a browser** is a Go command, not part of the wheel:
`go build ./cmd/curlpro`, then `curlpro capture -name firefox-155-windows`
brings up a stand, drives the installed browser, folds several samples into a
profile and gives a full profile the family's HTTP/1.1, fetch and WebSocket
sets. `validate`, `diff`, `collapse` and `list` are the other subcommands;
`docs/CAPTURE.md` has the method and its pitfalls.

## 12. Transports: HTTP/1.1, HTTP/2, HTTP/3, WebSocket

The server chooses between HTTP/1.1 and HTTP/2 through ALPN from the list the
profile offers; `force_http1` restricts the offer. Each transport has its own
header set from the profile: HTTP/1.1 adds `Host` and `Connection` and uses the
browser's letter case; Chrome sends no `priority` there and Firefox no `TE`.

HTTP/3 turns on the way a browser does — over TCP first, then QUIC after an
`Alt-Svc` header — or at once with `http3=True`; `protocol="h3"` forces it for
one request. The QUIC transport parameters, SETTINGS, the GREASE frame and the
header order come from the profile's `http3` section, verified against
`quic.browserleaks.com`. Four profiles have the section (section 11).

WebSocket: `with s.websocket(url, headers=None, subprotocols=None, timeout=30.0,
max_message_size=0) as ws`. The handshake headers come from the profile's
`websocket` template — the set and order Chrome and Firefox send, including
`permessage-deflate`. `ws.send(str | bytes)` picks the frame type from the data,
`ws.recv()` returns `str` or `bytes`, `ws.ping()`, `ws.close(code=1000,
reason="")`, and `for message in ws` reads until the server closes
(`WebSocketClosed`). `timeout` is the silence limit on a read (code `timeout`,
the connection stays usable); `max_message_size` raises `ws_too_big`. Cleartext
`ws://` works too.

## 13. Streaming, uploads, async

```python
with s.stream("GET", url) as r:                 # the same arguments as request()
    for chunk in r.iter_content(64 * 1024):
        out.write(chunk)
    for line in r.iter_lines():                 # NDJSON and the like
        ...
```

A stream holds its connection until closed, hence `with`. `r.read()` collects
the rest and is bounded by `max_response_size`; `iter_content()` is not, on
purpose. Closing with the body unread drops the connection rather than draining
it. Uploads stream with `body_file=path`.

`AsyncSession` takes the same arguments as `Session` and offers the same
methods as coroutines: `await s.get(...)`, `async with s.stream(...) as r:
async for chunk in r.iter_content()`, `async with s.websocket(url) as ws`. A
request is a goroutine on the native side; the process keeps one thread and the
event loop never blocks. A cancelled task cancels the request natively.
`s.cookies`, `s.headers` and the hooks are the sync session's.

## 14. Fingerprint, audit and personas

`s.fingerprint(url="https://example.com/")` computes, without sending anything,
what a server would see:

| Field | Meaning |
|---|---|
| `ja4`, `ja4_r` | JA4 and its readable form — stable across connections and domains; the value to compare |
| `ja3n`, `ja3`, `ja3_text` | JA3 with sorted extensions (stable), and plain JA3, which **moves** between connections on Chrome ≥110 because the extensions are shuffled |
| `akamai` | the HTTP/2 fingerprint: SETTINGS, window update, priority, pseudo-header order |
| `ciphers`, `extensions`, `curves`, `sigalgs`, `alpn` | the raw lists, GREASE-free, in send order |
| `headers`, `headers_http1` | the header names an ordinary GET would send, over HTTP/2 and over HTTP/1.1 |
| `ja4h`, `ja4h_http1`, `ja4h_available` | the request fingerprint; empty with `ja4h_available == False` in a build made with `-tags nofoxio` |
| `user_agent`, `profile` | the string that would go out, and the profile name |
| `client_hello` | the marshalled ClientHello as bytes; `len()` answers whether it fits one TCP segment |
| `to_dict()`, `diff(other)`, `==` | everything as data; a field-by-field difference (extensions compared as sets, `ja3` and `client_hello` excluded) |

The values are checked against 50 live captures in `reference/baselines`: JA4,
JA3N and the Akamai string match the oracle on every one. The session's own
options count — `force_http1` and `post_quantum=False` change the hello, and
the fingerprint shows the hello that session sends.

`s.audit()` looks for contradictions inside the identity — the reason a correct
fingerprint still gets caught. Each `Finding` has `code`, `level` (`high`,
`medium`, `low`), `what`, `why`, `fix`. The checks are conservative; a stock
profile is silent except a phone profile with no device chosen:

| Code | Level | Fires when |
|---|---|---|
| `tor_language` | high | a Tor profile sends any `accept-language` but `en-US,en;q=0.5` |
| `ua_version` | high | the User-Agent's version disagrees with the profile's (Chrome, Edge, Firefox) |
| `ua_family` | high / medium | the User-Agent is another browser's, or names no browser at all |
| `platform` | high | `sec-ch-ua-platform` disagrees with the User-Agent |
| `mobile_no_device` | medium | a profile with a device list and no device chosen |
| `navigation_headers_on_fetch` | high | `sec-fetch-user` or `upgrade-insecure-requests` beside fetch metadata that says fetch |
| `accept_encoding` | medium | an `accept-encoding` that is not the profile's, or none at all |
| `no_user_agent` | high | no User-Agent at all — the shape `default_headers=False` leaves behind |
| `referer_site` | high | a Referer that disagrees with the fetch metadata or the Origin beside it: a hand-written Referer next to `sec-fetch-site: none`, a Referer from another origin under `same-origin`, or Origin and Referer naming two pages |
| `derived_fetch_set` | medium | the session is sending Safari's derived fetch set, whose order was not measured (section 11) |

`Persona` binds one identity — profile, proxy, device, headers (removals
included), cookies, free-form `notes` — to one JSON file:

```python
p = curlpro.Persona.new("chrome-152-windows", proxy="socks5h://user:pw@host:1080",
                        headers={"Accept-Language": "de-DE,de;q=0.9"})
p.save("accounts/user42.json")

p = curlpro.Persona.load("accounts/user42.json")
with p.session(timeout=20) as s:       # overrides go to Session; cookies restored
    s.get("https://example.com/")     # captured on exit, even if the block raises
p.save()                              # atomic write; a truncated file is refused on load
```

`p.open()` returns a plain session, `p.capture(s)` takes a session's cookies
back without closing it, `p.fingerprint()` and `p.audit()` work without a
network, `load_all(directory)` iterates a folder of personas. A persona rotates
nothing: which identity to use and when to retire it is the caller's policy.

## 15. What not to reimplement

An assistant asked to add any of these to code that already uses curlPro
should reach for the existing feature instead. Each line names it:

- **Decompression** of `gzip`, `deflate`, `br`, `zstd`, stacked in any order — `r.content` is already decoded.
- **Charset detection** — `r.text` and `r.encoding` follow the browser's order: header, BOM, document.
- **Redirects** with a history and the https→http refusal — `allow_redirects`, `r.history`, `r.url`.
- **Retries** with exponential backoff, `Retry-After` and idempotency — `retries=`, `retry_statuses=`, `retry_methods=`.
- **Cookie persistence**, `cookies.txt`, rollback — `s.cookies.save/load_file`, `transaction()`, `rollback_cookies=`.
- **Header order and case** — the profile, plus `header_order=[..., ...]` for edits; never build header lists by hand.
- **Removing a header** — `None`, not `default_headers=False`.
- **Fetch versus navigation sets** — `mode`, chosen automatically.
- **Referer, Origin and sec-fetch-site for a request from a page** — `page=` on the session or the request, never a hand-written `Referer`.
- **Client hints and phone models** — `device=`, `devices=`, already answering `Accept-CH` and `Critical-CH`.
- **Proxies** with environment variables, SOCKS5 with remote DNS, CONNECT authentication — `proxy=`, `trust_env`.
- **HTTP/3** with `Alt-Svc` and fallback — on by default where the profile has the section.
- **WebSocket** with the browser's handshake and `permessage-deflate` — `s.websocket()`.
- **Streaming** downloads and uploads — `s.stream()`, `body_file=`.
- **Response validation** — `Expect(...)` instead of hand-written `if` chains.
- **Identity files** — `Persona`, not an ad-hoc JSON of proxy plus cookies.
- **Fingerprint checks** — `s.fingerprint()` and `s.audit()` offline, not a call to an oracle.
- **Seeing the outgoing headers** — `s.headers_for(method, url, mode=..., page=...)`, not an echo server of your own.
- **Asking whether a profile can do something** — `curlpro.capabilities(name)`, not a probe request and a substring in the error text.
- **Telling a permanent failure from a passing one** — `except curlpro.PermanentError`, not a match on the message.
- **Reading a profile's data** — `curlpro.get_profile(name).data`, not the JSON inside `site-packages`.
- **A `requests` shim** — `import curlpro.requests as requests` exists; unsupported arguments raise instead of being ignored.
- **A new browser version** — a profile delta or `register_profile()`, not a library change.

## 16. Checked claims: what was false, what is true

Everything in this guide was verified against the code, the profiles and the
test suite on 2026-09-16. The audit of the older documents found these
statements wrong, and they were corrected in the same release:

- The README said the project documentation was written in Russian with the
  English file as a counterpart. False since 2026-09-08: English is the original
  and `README.ru.md` is the twin; a test keeps the two in step by structure.
- The README's list of error codes lacked `too_large` and `proxy_closed`,
  which the native side has raised since 0.3 and 0.5.2 respectively.
- The README's licence paragraph called fhttp MIT; it is BSD-3-Clause, as
  `NOTICE` says.
- `ARCHITECTURE.md` named 0.4.2 as the current release.
- `curlpro.request(method, url)` was documented by shape but not exported;
  it is now.

Facts that are easy to doubt and are true:

- Chrome ≥110 shuffles its TLS extensions per connection, so `ja3` moves while
  `ja4` and `ja3n` stay. That is correct behaviour, not a defect.
- A modern browser's ClientHello is ~1.9 KB because of the post-quantum key
  share and spans two TCP segments. The profiles reproduce that, and
  `post_quantum=False` is the knob to test paths that dislike it.
- Firefox 155 sends three key shares (X25519MLKEM768, x25519, secp256r1); the
  profile replays the raw hello captured from a live browser.
- postman-echo.com sits behind Cloudflare, which rewrites `Accept-Encoding` to
  `gzip, br` before the origin echoes it. Judge headers on a raw stand
  (`python/tests/rawserver.py`), not on a public echo.
- Adding any custom header switches the request to the fetch set in `auto`
  mode. That is what a browser does; `mode="navigate"` says otherwise.
- `timeout` caps the whole request, not the silence between bytes as in
  `requests`. A value carried over is safe: stricter, not looser.
- A resumed connection's ClientHello is not the first one: it carries
  `pre_shared_key` last, and Firefox drops `session_ticket` from it. Measured
  on both browsers and reproduced; neither browser offers early data on a
  resumed TCP connection, not even to a server that supports 0-RTT.

## 17. API index

| Name | Kind | One line |
|---|---|---|
| `Session` | class | one profile, reused connections, memory and policy |
| `AsyncSession` | class | the same over asyncio, native concurrency |
| `Response`, `Redirect` | class | a response; one hop of a redirect chain |
| `StreamResponse`, `AsyncStreamResponse` | class | a body read in chunks |
| `WebSocket`, `AsyncWebSocket` | class | an open WebSocket |
| `Cookies`, `Cookie` | class | the jar and one record |
| `Expect`, `ExpectationFailed` | class | a response expectation and its failure |
| `Fingerprint` | class | what a server sees, computed offline |
| `Finding`, `audit(target)` | class, function | one contradiction; the check over a session or persona |
| `Persona`, `load_all(dir)` | class, function | an identity between runs; a folder of them |
| `Profile` | class | a profile as an object: `from_file`, `derive`, `register`, `save` |
| `load_profiles(dir)`, `register_profile(x)`, `list_profiles()`, `ensure_loaded()` | function | profile management |
| `capabilities(name)`, `get_profile(name)`, `library_version()` | function | what a profile can do, a profile as data, the native library's own version |
| `s.headers_for(method, url, ...)` | method | the headers a request would carry, without sending it |
| `request`, `get`, `post`, `put`, `patch`, `delete`, `head`, `options` | function | one request in its own session; `impersonate=` picks the profile |
| `CurlProError`, `Timeout`, `HTTPError`, `WebSocketClosed` | exception | the hierarchy; `.code` on all |
| `PermanentError`, `ProfileCapabilityError`, `ConfigurationError` | exception | failures a retry cannot fix (section 9) |
| `curlpro.requests` | module | the `requests`-shaped face: `get`, `Session`, `status_code`, the same exceptions |

## 18. Where things live

For research in the repository:

| Path | Holds |
|---|---|
| `python/curlpro/session.py` | `Session`, `Response`, the request frame, hooks, module-level functions |
| `python/curlpro/aio.py`, `stream.py`, `websocket.py` | async, streaming, WebSocket |
| `python/curlpro/cookies.py`, `persona.py`, `headers.py` | the jar, personas, the session header mapping |
| `python/curlpro/fingerprint.py`, `audit.py`, `expect.py`, `encoding.py` | fingerprint, audit checks, expectations, charset detection |
| `python/curlpro/requests.py`, `proxies.py`, `timeouts.py`, `profiles.py`, `_ffi.py` | the compat layer, environment proxies, timeout parsing, profile loading, the native binding and ABI check |
| `internal/client/` | the Go client: header assembly (`headers.go`, `mode.go`), dialling and TLS (`client.go`, `conn.go`), HTTP/3 (`http3.go`), cookies, redirects, retries, WebSocket, fingerprint |
| `internal/profile/` | the profile schema, inheritance and validation |
| `internal/fingerprint/` | JA3, JA4, JA4H, Akamai |
| `lib/` | the cgo exports the Python side calls |
| `profiles/` | the 50 profiles; `scripts/gen-devices.py` owns the phone pool |
| `cmd/curlpro/` | capture, validate, diff, collapse, list |
| `docs/` | schema, capture method, fingerprint spec, research, the stage-by-stage record |
| `python/tests/` | the behaviour, one file per feature; `rawserver.py` is the raw-header stand |
