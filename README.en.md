# curlPro

**An HTTP client with a browser's network fingerprint. A browser profile is a JSON
file, not code.**

*[Русская версия](README.md) — the project documentation is written in Russian ·
Apache 2.0*

```python
import curlpro

with curlpro.Session("chrome-151-windows") as s:
    r = s.get("https://tls.browserleaks.com/json")
    print(r.json()["ja4"])      # t13d1516h2_8daaf6152771_806a8c22fdea — same as Chrome
```

A new Chrome ships every four weeks. In `curl_cffi` and `tls-client` that means
editing C or Go, rebuilding and releasing; here it is a JSON edit you can make from
Python without waiting for anyone:

```python
curlpro.register_profile({
    "name": "chrome-153-windows",
    "based_on": "chrome-152-windows",
    "headers": {"user_agent": "...Chrome/153.0.0.0..."},
})
```

---

## Contents

[Features](#features) · [How it compares](#how-it-compares) · [Install](#install) ·
[Quickstart](#quickstart) · [Session](#session) · [Request](#request) ·
[Per-request protocol](#per-request-protocol) · [Session memory](#session-memory) ·
[Response expectations](#response-expectations) · [Cookie rollback](#cookie-rollback) ·
[Errors and hooks](#errors-and-hooks) · [Streaming](#streaming) ·
[WebSocket](#websocket) · [Async](#async) · [HTTP/3](#http3) ·
[Network](#network-proxies-address-override-tls) · [Cookies](#cookies-between-runs) ·
[Mobile profiles](#mobile-profiles-and-client-hints) ·
[Navigation vs fetch](#navigation-vs-fetch) · [Profiles as data](#profiles-as-data) ·
[Measured, not assumed](#measured-not-assumed) · [Limits](#limits)

---

## Features

- **47 profiles**: Chrome 98-152, Edge, Firefox, Safari, Tor, Yandex Browser;
  mobile — Chrome and Yandex for Android, Safari for iOS.
- **Every fingerprint layer at once** — TLS, HTTP/2, HTTP/3, HTTP/1.1 and WebSocket
  (table below).
- **HTTP/3 with a verified fingerprint** and the `Alt-Svc` upgrade a browser performs.
- **Native async**: a request becomes a goroutine, and the process keeps one thread.
- **WebSocket** with a profile-driven handshake and `permessage-deflate`.
- **Streaming reads and uploads**, multipart, `gzip`/`deflate`/`br`/`zstd` decoding.
- **requests-compatible**: `params`, `auth`, `r.json()`, `r.history`, `r.elapsed`,
  `raise_for_status()`.
- **Scraper tooling**: response expectations, cookie rollback, `cookies.txt`, an
  error hook, host address override, retries honouring `Retry-After`.
- **Profile as data**: JSON with inheritance, runtime registration, and capturing a
  profile from a live browser with one command.

What exactly is reproduced:

| Layer | What the profile defines |
|---|---|
| TLS | the whole ClientHello: ciphers, extensions and their order, GREASE, ALPS, ECH, `trust_anchors`, per-connection extension shuffling |
| HTTP/2 | SETTINGS and their order, window size, `PRIORITY` on HEADERS, pseudo-header order |
| HTTP/3 | SETTINGS, the GREASE frame, `PRIORITY_UPDATE`, QUIC transport parameters, header order |
| HTTP/1.1 | name order **and case**, `Host` and `Connection` — a set of its own, unlike HTTP/2 |
| Headers | two sets (navigation and `fetch`), slot positions, the anchor for custom headers |
| WebSocket | the handshake header set and order, `permessage-deflate` |
| Forms | the multipart boundary style: `----WebKitFormBoundary` in Chrome, dashes in Firefox |

## How it compares

| | curlPro | curl_cffi | tls-client | wreq / rnet |
|---|---|---|---|---|
| Browser profile | **JSON data**, registered at runtime | C structs; the data path is a paid API | Go literals in code | Rust code |
| A new browser version | edit a file | a library release (or a subscription) | PR → merge → tag → rebuild for 8 platforms | a library release |
| Capturing a profile from a browser | `curlpro capture` — stand, browser, profile | by hand | by hand | by hand |
| HTTP/3 | yes, fingerprint compared with Chrome | no | 5 profiles out of ~40 | yes |
| WebSocket with the profile's fingerprint | yes | yes | no | no |
| Wrapper language | Python over Go | Python over C | Go, wrappers on top | Rust, a PyO3 wrapper |

The source-level analysis lives in [docs/RESEARCH.md](docs/RESEARCH.md), including
why "profiles in compiled code" breaks down structurally rather than through any
maintainer's fault.

## Install

There is no PyPI release yet — build from source. Go and a C compiler are required
(MinGW-w64 on Windows): cgo cannot build `c-shared` without one.

```powershell
.\build.ps1                                        # → dist/curlpro.dll
cd python; $env:PYTHONPATH='.'; python -m pytest tests
```

From the source archive (`curlpro-*.tar.gz`) it is one command: the archive
carries the Go module and the profiles, and the native part is built in place.

```bash
tar -xzf curlpro-0.2.0.tar.gz && cd curlpro-0.2.0/go
CGO_ENABLED=1 go build -buildmode=c-shared -o ../curlpro/lib/libcurlpro.so ./lib
```

`CGO_ENABLED=1` is not decoration: without it the build fails with "build
constraints exclude all Go files", a message that names neither the cause nor
the cure.

Profiles live in `profiles/` and load themselves when the library is installed from
a wheel. Running from the repository, point at them explicitly:

```python
curlpro.load_profiles("profiles")
```

## Quickstart

```python
import curlpro

# A one-off request — no session
r = curlpro.get("https://example.com", impersonate="firefox-144-macos")

# A session: connections are reused, cookies live between requests
with curlpro.Session("chrome-151-windows") as s:
    s.headers["X-Api-Key"] = "secret"          # on every later request
    r = s.post("https://example.com/api", json_body={"id": 7})
    print(r.status, r.json())
```

Async — the same API, the same arguments:

```python
import asyncio, curlpro

async def main(urls):
    async with curlpro.AsyncSession("chrome-151-windows") as s:
        return await asyncio.gather(*(s.get(u) for u in urls))

asyncio.run(main(urls))
```

## Session

```python
curlpro.Session("chrome-151-windows", proxy="socks5://127.0.0.1:1080", retries=3)
```

| Parameter | Meaning |
|---|---|
| `impersonate` | profile name; `chrome-151-windows` by default |
| `timeout` | limit for the whole request; a `(connect, total)` pair bounds establishing the connection separately |
| `proxy` | `http://`, `https://` or `socks5://`, `user:pass` allowed |
| `trust_env` | take the proxy from `HTTPS_PROXY`/`ALL_PROXY`, honouring `NO_PROXY` |
| `verify` | `True` — system roots, a PEM path — trust only that one, `False` — no verification |
| `cert` | a `(certificate, key)` pair for mTLS |
| `retries`, `retry_statuses`, `retry_methods`, `retry_backoff`, `retry_max_backoff`, `respect_retry_after` | the retry policy; only idempotent methods are retried by default |
| `allow_redirects`, `max_redirects` | following 3xx |
| `cookies` | the cookie jar shared by the session's requests |
| `default_headers`, `header_order`, `mode` | profile headers, desired order, header set (`navigate`/`fetch`/`auto`) |
| `force_http1`, `http3`, `alt_svc` | transport: forbid h2, go straight to QUIC, upgrade on `Alt-Svc` |
| `keep_alive`, `max_idle_conns`, `idle_conn_timeout` | connection reuse and pool size |
| `resolve`, `ip_version` | host address override, address family (`"4"`/`"6"`) |
| `device`, `devices` | the phone for mobile profiles and your own device list |
| `max_response_size` | body size limit; without one an endless response eats memory. Binds `read()`, not `iter_content()` |
| `hooks` | the `request`, `response` and `error` hooks |

## Request

Everything set on the session can be overridden for a single request:

```python
s.get(url, timeout=(3, 30), protocol="h2", cookies=False, retries=0)
```

| Parameter | Meaning |
|---|---|
| `params`, `auth` | query string and `Authorization` — as in requests |
| `data`, `json_body`, `fields`, `files`, `body_file` | body: bytes, JSON, form, multipart, a streamed file |
| `headers`, `header_order` | your own headers and their order |
| `protocol` | `1.1`/`http1`, `2`/`h2`, `3`/`h3` — the transport for this request |
| `timeout` | a number or a `(connect, total)` pair |
| `proxy` | an address, or `False` to bypass the session proxy |
| `cookies` | `False` — neither send nor store cookies |
| `session_headers` | `False` — without the headers added to the session |
| `default_headers` | `True`/`False` — the profile headers, either way |
| `mode` | `navigate` or `fetch` — which header set to use |
| `allow_redirects`, `max_redirects`, `retries`, … | overrides of the session policies |
| `expect` | a response expectation (see below) |
| `rollback_cookies` | undo what this request wrote into the jar if it fails |

The response answers with what requests users expect:

```python
r.status, r.ok, r.proto            # 200, True, "HTTP/2.0"
r.text, r.content, r.json()        # charset from Content-Type, the BOM or <meta charset>
r.headers, r.header("server")      # all values, and the first one case-insensitively
r.cookies, r.history, r.elapsed    # response cookies, the redirect chain, timing
r.raise_for_status()               # HTTPError carrying the status and the response
```

## Per-request protocol

The instruction beats both the session options and an `Alt-Svc` upgrade. Measured
against `cloudflare-quic.com` inside one session:

```python
with curlpro.Session("chrome-151-windows") as s:
    s.get(url).proto                      # HTTP/2.0 — the first request
    s.get(url).proto                      # HTTP/3.0 — upgraded via Alt-Svc
    s.get(url, protocol="h2").proto       # HTTP/2.0 — this one stays on TCP
    s.get(url, protocol=1.1).proto        # HTTP/1.1
    s.get(url, protocol=3).proto          # HTTP/3.0
```

`h2` does **not** trim the ALPN list to a single entry: no browser sends such a
list. If the server negotiates `http/1.1`, the request fails with a clear error
instead of silently travelling over the wrong protocol. That error is marked
non-retryable — a second attempt would negotiate exactly the same.

## Session memory

A session remembers cookies and the headers added to it. A single request can opt
out of either:

```python
s.get(url, cookies=False)          # past the jar: neither sent nor stored
s.get(url, session_headers=False)  # without the headers added to the session
s.get(url, default_headers=False)  # without the profile headers — only your own
```

The cookie isolation is deliberately two-way: "do not use the memory" reads as "do
not touch it at all". Such a request cannot leave a cookie behind that would make
the next one go out under a different identity — say, while checking a page "as an
anonymous visitor".

`default_headers` and `session_headers` are separate: the first is the browser's set
(that is the fingerprint), the second is what you added. Switching one off leaves
the other alone.

## Response expectations

A scraper writes the same checks around every request: the status is what was
expected, the page holds the marker of a successful login, a captcha did not arrive
instead of it. Written by hand, those checks get forgotten one at a time — and a
redirect to a block page looks like "the parser stopped finding data".

```python
from curlpro import Expect

r = s.get(url, expect=Expect(status=200, body="Dashboard",
                             not_body="captcha", non_empty=True))
```

| Field | What it checks |
|---|---|
| `status`, `not_status` | the response code; several values mean "one of" |
| `body`, `not_body` | a substring in the body; several mean "all of" |
| `non_empty` | the body is not empty |
| `json` | the body parses as JSON |
| `headers`, `not_headers` | a substring in the `name: value` lines |

A mismatch raises `ExpectationFailed`, which is a `CurlProError` and so is caught
alongside network errors. The message names what did not match and what arrived:

```
the body contains the forbidden 'captcha' (200 https://example.com/)
```

The check runs **after** the response hooks: what leaves the library is their
replacement, and that is what must be checked.

## Cookie rollback

A failed login must not leave the session half authenticated:

```python
s.post(login, fields=creds, expect=Expect(body="Dashboard"),
       rollback_cookies=True)          # on failure the jar is as it was

with s.cookies.transaction():          # the same across several requests
    s.post(login, fields=creds)
    s.get(account).raise_for_status()  # an exception rolls the whole block back
```

The snapshot is taken before sending: after a failure the jar has already changed
and there is nothing left to copy. Half a login is worse than no login.

## Errors and hooks

Every failure arrives as an exception naming both the cause and the consequence.
Branch on the type or on `code`, never on the message text:

```python
try:
    r = s.get(url, timeout=(3, 30))
    r.raise_for_status()
except curlpro.Timeout:                   # code == "timeout"
    ...                                   # the deadline expired; retrying is sane
except curlpro.ExpectationFailed as e:    # code == "expectation"
    print(e.response.text)                # the response is kept — the reason is in it
except curlpro.HTTPError as e:            # raised by raise_for_status()
    print(e.status, e.response.text)
except curlpro.WebSocketClosed:           # code == "ws_closed"
    ...
except curlpro.CurlProError as e:         # everything else from the native side
    print(e.code, e)
```

The outcome codes: `timeout`, `expectation`, `session_closed`, `ws_closed`,
`ws_too_big`, `ws_protocol`. The message is written for a human and names the
consequence, not only the fact:

```
timeout must be positive, got 0s (leave it unset for no limit)
unsupported proxy scheme "ftp" (use http, https or socks5)
protocol=h2: server negotiated http/1.1. The ALPN list is left intact on
  purpose: no browser offers h2 alone
```

Three places to step in without touching the library:

```python
with curlpro.Session() as s:
    @s.on_request
    def sign(meta):                       # meta may be edited in place
        meta.setdefault("headers", {})["X-Signature"] = sign_it(meta["url"])

    @s.on_response
    def log(resp):                        # may return a replacement
        print(resp.status, resp.url)

    @s.on_error
    def alert(exc):                       # network, timeout, failed expectation
        logging.warning("request failed: %s", exc)
```

## Streaming

The body is read in chunks — a megabyte download does not take a megabyte of memory:

```python
with s.stream("GET", url, timeout=5) as r:       # the same arguments as request()
    for chunk in r.iter_content(64 * 1024):
        out.write(chunk)

with s.stream("GET", ndjson_url) as r:
    for line in r.iter_lines():                  # line by line, nothing collected
        handle(json.loads(line))
```

The session's `max_response_size` binds `read()` — the call that collects the
body into memory — and deliberately does not bind `iter_content()`: reading in
chunks is how a body larger than memory is meant to be handled. Both errors
carry the code `too_large`.

Closing a stream with the body unread is cheap: the connection is dropped rather
than drained. Uploads are symmetric: `body_file=` streams a file with an explicit
`Content-Length` — without it the transport would switch to chunked, which a browser
does not do when uploading a file.

```python
s.post("https://example.com/upload", body_file="archive.zip")
```

## WebSocket

The handshake is an ordinary request with `Upgrade`, so its headers are part of the
fingerprint too and come from the profile.

```python
with curlpro.Session("chrome-151-windows") as s:
    with s.websocket("wss://echo.websocket.org/", max_message_size=1 << 20) as ws:
        ws.send("hello")           # str → a text frame
        ws.send(b"\x00\xff")       # bytes → a binary one
        ws.ping()
        for message in ws:         # until the server closes (WebSocketClosed);
            print(message)         # a silence timeout is CurlProError, code="timeout"
```

`permessage-deflate` is advertised and supported, including with a window below
32 KiB, which some servers demand.

## Async

A request becomes a goroutine, and there is one collector thread per process.
128 requests of 0.3 s each take 0.37 s instead of the 1.27 s a 32-thread pool needed.

```python
async with curlpro.AsyncSession("firefox-144-macos") as s:
    results = await asyncio.gather(*(s.get(u) for u in urls))

    # Streaming and WebSocket live there too, with no thread pool either
    async with s.stream("GET", url) as r:
        async for chunk in r.iter_content():
            out.write(chunk)

    async with s.websocket("wss://example.com/ws") as ws:
        await ws.send("hello")
        print(await ws.recv())
```

A cancelled task cancels the request natively: the connection is freed at once
instead of hanging until its own timeout.

## HTTP/3

It turns itself on the way a browser does: the first request goes over TCP, and
after seeing `Alt-Svc` in the response the client moves to QUIC from the next one.
If QUIC does not get through, the request falls back to TCP and the attempt is not
repeated for a while.

```python
with curlpro.Session("chrome-151-windows") as s:
    print(s.get("https://cloudflare-quic.com/").proto)   # HTTP/2.0
    print(s.get("https://cloudflare-quic.com/").proto)   # HTTP/3.0

with curlpro.Session("chrome-151-windows", http3=True) as s:   # QUIC right away
    print(s.get("https://quic.browserleaks.com/fp").json()["h3_text"])
    # 1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p — same as Chrome
```

## Network: proxies, address override, TLS

```python
curlpro.Session(
    proxy="socks5://user:pw@127.0.0.1:1080",   # http, https and socks5
    resolve={"example.com:443": "10.0.0.7"},   # curl's --resolve
    ip_version="4",                            # A records only
    verify="ca.pem",                           # a trust root of your own
    cert=("client.pem", "key.pem"),            # mutual authentication
    max_response_size=10 << 20,                # response body limit
)
```

The address override does not change the fingerprint: the name in SNI and in the
`Host` header stays the same, only the socket destination moves. Through an
`https://` proxy the channel to the proxy itself is encrypted, and the first
`CONNECT` goes without credentials, adding them only after a 407 — as Chrome does.

## Cookies between runs

```python
with curlpro.Session("chrome-152-windows") as s:
    s.cookies.load_file("state.json")     # a missing file is fine: the first run
    s.post("https://example.com/login", fields={"user": "u", "password": "p"})
    print(s.get("https://example.com/account").text)
    s.cookies.save("state.json")
```

Cookies are visible in full — domain, path, expiry, flags — and the Netscape format
is read too, the very `cookies.txt` that curl, wget and browser extensions write.
`load_file` recognises it by content, not by name:

```python
s.cookies["sid"]                          # the value
s.cookies.all()                           # the full records
s.cookies.set("token", "xyz", domain="example.com")
s.cookies.load_file("cookies.txt")        # curl, wget, a browser extension
s.cookies.save_netscape("cookies.txt")    # and back, for another tool
```

## Mobile profiles and client hints

Since version 110 Chrome cut both the model and the OS version out of the
`User-Agent`: every phone reports `Android 10; K` there. The real device lives in
the `sec-ch-ua-model` and `sec-ch-ua-platform-version` hints, and the browser sends
them only after the site asked with an `Accept-CH` header.

```python
with curlpro.Session("chrome-152-android", device="random") as s:
    s.get(url)          # sec-ch-ua-model: "SM-S911B" — but only once the site
                        # asked for the hints; before that there are none
```

The device is chosen once per session: a real client does not swap phones between
requests. Your own list goes into the `devices` parameter.

## Navigation vs fetch

A browser sends different headers for a page load and for a `fetch()` from a page:
the latter has `accept: */*`, `sec-fetch-mode: cors`, `Origin` and `Referer`, and
lacks `upgrade-insecure-requests` and `sec-fetch-user`. A custom header only ever
appears on fetch — so the set switches itself, based on the method, the body type
and the header names:

```python
s.get(url)                                  # the navigation set
s.get(url, headers={"X-Api-Key": "k"})      # the fetch set: as a browser sends it
s.get(url, headers={"X-Api-Key": "k"}, mode="navigate")   # if you need otherwise
```

## Profiles as data

A profile is JSON with inheritance: a child stores only the differences. Here is the
**whole** Chrome 110 profile after folding:

```json
{
  "based_on": "chrome-98-windows",
  "name": "chrome-110-windows",
  "tls": { "permute_extensions": true },
  "headers": { }
}
```

The entire TLS-level difference from Chrome 98 is the extension shuffling introduced
in version 110. A profile can be added at runtime or derived from an existing one:

```python
curlpro.register_profile(json.load(open("chrome-153-windows.json")))

base = curlpro.Profile.from_file("profiles/chrome-152-windows.json")
base.derive("chrome-153-windows",
            headers={"user_agent": "...Chrome/153.0.0.0..."}).register()
```

### A new browser in four commands

```powershell
curlpro capture  -name chrome-152-windows -samples 5
curlpro validate -only chrome-152-windows -oracle https://localhost:8443/json -insecure
curlpro diff     chrome-151-windows chrome-152-windows
curlpro collapse -apply
```

`capture` brings up a stand, drives the browser, folds the samples and writes the
profile; `validate` compares the fingerprint with the baseline; `diff` shows the
delta between versions; `collapse` folds profiles sharing a ClientHello into
`based_on` chains.

The profile schema is in [docs/PROFILE-SCHEMA.md](docs/PROFILE-SCHEMA.md), the
capture method in [docs/CAPTURE.md](docs/CAPTURE.md).

## Measured, not assumed

A fingerprint is verified by measurement, never by reasoning. The baselines come
from live browsers:

| Profile | JA4 | Source |
|---|---|---|
| `chrome-151-windows` | `t13d1516h2_8daaf6152771_806a8c22fdea` | [reference/](reference/), 6 samples |
| `yandex-26.8-android` | `t13d1516h2_8daaf6152771_806a8c22fdea` | `tls.peet.ws` plus our own stand over USB |
| `chrome-152-android` | `t13d1517h2_8daaf6152771_cb7bf5808d99` | 5 samples from a Pixel 7 over USB |

Chrome 151 is absent from the public corpora: curl-impersonate stops at 150,
wreq-util at 149. The HTTP/3 fingerprint is compared against
`quic.browserleaks.com`, and the HTTP/2 and HTTP/3 header order against our own
`cmd/hcapture` stand, which parses the HEADERS frame as it arrived.

Speed — 400 requests, a local stand, a reused connection:

| library | req/s | median | |
|---|---|---|---|
| **curlpro** | **1775** | 0.53 ms | 100% |
| curl_cffi | 1352 | 0.70 ms | 76% |
| requests (no fingerprint) | 867 | 1.12 ms | 49% |

## Limits

The library covers the network layer: the TLS ClientHello, HTTP/2 and HTTP/3 frames,
header order and case. It does **not** fake a JavaScript fingerprint (canvas, WebGL,
`navigator`) — that is the browser's level, and Playwright is the answer for such
tasks. Matching the network fingerprint is necessary but not sufficient: modern
systems score JA4 together with JA4H, JA3S/JARM and behavioural analysis.

HTML parsing is deliberately out of scope — pair it with `selectolax` or `lxml`.

## Stack

```
Python (ctypes) → libcurlpro.{so,dll,dylib} → Go
                                               ├── uTLS  (ClientHello)
                                               ├── fhttp (HTTP/2)
                                               └── uquic (HTTP/3, vendored in internal/h3)
```

Go was chosen for two uTLS capabilities: `ClientHelloSpec.UnmarshalJSON` — the
profile as data, and `Fingerprinter.RawClientHello` — learning a profile from
captured bytes. Together they close the loop "capture a browser → get a profile"
without a line of code.

The code and the error messages are in English; the project documentation is in
Russian.

## Documentation

The project documentation is written in Russian; this file is its English
counterpart. Start with [docs/AUDIT-BRIEF.md](docs/AUDIT-BRIEF.md) — a self-contained
snapshot of the current state, including the invariants ("looks like a bug, is
deliberate") and how to verify each of them.

| File | Content |
|---|---|
| [docs/AUDIT-BRIEF.md](docs/AUDIT-BRIEF.md) | State snapshot: repository map, invariants, verification recipes |
| [docs/AUDIT-QUESTIONS.md](docs/AUDIT-QUESTIONS.md) | Known debts, gaps in coverage, where help is wanted |
| [docs/PROFILE-SCHEMA.md](docs/PROFILE-SCHEMA.md) | The JSON profile schema, `based_on` inheritance, every field |
| [docs/CAPTURE.md](docs/CAPTURE.md) | How a baseline is captured: commands, pitfalls, public oracles |
| [docs/FINGERPRINT-SPEC.md](docs/FINGERPRINT-SPEC.md) | JA3/JA4/JA4H/Akamai formats, current browser values, disagreements between services |
| [docs/RESEARCH.md](docs/RESEARCH.md) | curl-impersonate, curl_cffi, uTLS, tls-client, httpcloak, wreq — read from the sources |
| [docs/HTTP3-RESEARCH.md](docs/HTTP3-RESEARCH.md) | HTTP/3: the oracles, the `perk` format, the QUIC-layer disagreements |
| [ARCHITECTURE.md](ARCHITECTURE.md) · [ROADMAP.md](ROADMAP.md) | Stack choice and boundaries; stages, risks, what is deliberately out of scope |
| [internal/h3/README.md](internal/h3/README.md) | The vendored http3 package: what changed against upstream and why |
| `docs/STAGE*-RESULTS.md` | The stage-by-stage record of what was measured, what was found and how it ended |

## License

Apache 2.0, the text is in [LICENSE](LICENSE). Third-party code and its licences are
listed in [NOTICE](NOTICE): the project stands on uTLS and uquic (BSD-3-Clause),
fhttp and quic-go/qpack (MIT), and carries a copy of the `http3` package from uquic
with fingerprint-related changes, described in
[internal/h3/README.md](internal/h3/README.md).

Browser profiles are data, not code: some were captured from live browsers, some
imported from the curl-impersonate signatures.
