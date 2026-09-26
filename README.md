# curlPro

**An HTTP client with a browser's network fingerprint. A browser profile is a JSON
file, not code.**

[![PyPI](https://img.shields.io/pypi/v/curlpro)](https://pypi.org/project/curlpro/)
[![Python](https://img.shields.io/pypi/pyversions/curlpro)](https://pypi.org/project/curlpro/)
[![tests](https://github.com/int3re/curlpro/actions/workflows/test.yml/badge.svg)](https://github.com/int3re/curlpro/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

*[Русская версия](README.ru.md)*

```bash
pip install curlpro
```

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
[Network](#network-proxies-address-override-tls) ·
[Own fingerprint](#your-own-fingerprint-without-a-request) · [Personas](#personas-an-identity-between-runs) ·
[requests compatibility](#requests-compatibility) · [Cookies](#cookies-between-runs) ·
[Mobile profiles](#mobile-profiles-and-client-hints) ·
[Navigation vs fetch](#navigation-vs-fetch) · [Page loads](#page-loads-and-resources) ·
[Profiles as data](#profiles-as-data) ·
[Measured, not assumed](#measured-not-assumed) · [Limits](#limits)

---

## Features

- **302 profiles**: 42 captured whole (Chrome 118-153, Edge, Firefox 133-156, Safari, Tor, Yandex Browser, okhttp 5.5), 14 captured but for their HTTP/2 SETTINGS, 238 transcribed from wreq-util and 8 derived for the versions current on 2026-09-26 (Chrome 154, Edge 154, Opera 136, Safari 27) — each marked, and `list_profiles(measured=True)` is the captured list;
  mobile — Chrome and Yandex for Android, Safari for iOS.
- **Every fingerprint layer at once** — TLS, HTTP/2, HTTP/3, HTTP/1.1 and WebSocket
  (table below).
- **HTTP/3 with a verified fingerprint** and the `Alt-Svc` upgrade a browser performs.
- **Native async**: a request becomes a goroutine, and the process keeps one thread;
  on free-threaded Python (3.14t) the GIL stays off and threads parse in parallel.
- **Page loads as a browser loads them**: `load_page()` fetches a document and the
  stylesheets, scripts, images, fonts and frames it names, each as its resource
  kind — its own `Accept`, `sec-fetch-dest`, `priority`, header order.
- **Connections as a browser spends them**: a burst races as many handshakes as
  the browser does and rides one HTTP/2 connection, Chromium pools names by
  address and keeps credentialed and uncredentialed requests apart.
- **WebSocket** with a profile-driven handshake and `permessage-deflate`.
- **Streaming reads and uploads**, multipart, `gzip`/`deflate`/`br`/`zstd` decoding.
- **requests-compatible**: `params`, `auth`, `r.json()`, `r.history`, `r.elapsed`,
  `raise_for_status()`.
- **Scraper tooling**: response expectations, cookie rollback, `cookies.txt`, an
  error hook, host address override, retries honouring `Retry-After`.
- **The fingerprint without a request**: `session.fingerprint()` returns JA3, JA3N,
  JA4, JA4H and the Akamai string computed offline — no network, no oracle.
- **A consistency audit**: `session.audit()` looks for contradictions inside the
  identity, the reason a correct fingerprint still gets caught.
- **Personas**: an identity — profile, device, cookies, headers — saved to a file
  and reopened as it was.
- **Cleartext `http://` and `ws://`** for a service of your own, so a solver or an
  internal API needs no second HTTP client.
- **Profile as data**: JSON with inheritance, runtime registration, and capturing a
  profile from a live browser with one command.

What exactly is reproduced:

| Layer | What the profile defines |
|---|---|
| TLS | the whole ClientHello: ciphers, extensions and their order, GREASE, ALPS, ECH, `trust_anchors`, per-connection extension shuffling |
| HTTP/2 | SETTINGS and their order, window size, `PRIORITY` on HEADERS, pseudo-header order |
| HTTP/3 | SETTINGS, the GREASE frame, `PRIORITY_UPDATE`, QUIC transport parameters, header order |
| HTTP/1.1 | name order **and case**, `Host` and `Connection` — a set of its own, unlike HTTP/2 |
| Headers | the navigation set, the `fetch` set and a set per resource kind, slot positions, the anchor for custom headers |
| Connections | handshakes per burst, HTTP/2 pooling across names, the privacy-mode and site partitions |
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

### Cleartext http://

`http://` and `ws://` work. There is no ClientHello over cleartext and so no TLS
fingerprint, but the HTTP/1.1 half of the profile still applies — the header
order and case are the profile's, and that is all a plain-HTTP peer can see
anyway. The point is not masking: it is that a caller whose own service speaks
plain HTTP — a solver, an internal API — should not have to keep a second HTTP
client beside this one.

Two things are refused rather than quietly downgraded: `protocol="h2"` over
`http://` would be h2c, which no browser speaks, and `protocol="h3"` needs TLS
by definition. A redirect from `https://` to `http://` is not followed either —
the 3xx is handed back with its `Location`, so the decision is the caller's;
following it would put the request's cookies and credentials on the wire in
clear text.


### Declining JA4H

JA4 for TLS is BSD-3 and free. JA4H is not: FoxIO License 1.1, patent-pending —
internal and academic use is free, commercial monetisation needs an OEM licence
from FoxIO. This library is Apache 2.0, so the obligation lands on whoever ships
a product computing the value, not on the library. A dependency review does not
weigh obligations, though — it flags licences.

So JA4H can be left out entirely:

```bash
go build -tags nofoxio -buildmode=c-shared -o dist/libcurlpro.so ./lib
```

None of the FoxIO-licensed code enters that binary. Everything else is
unchanged: JA3, JA3N, JA4, the Akamai string, the header preview and the audit
are computed exactly as before, checked by a test that runs under the tag in CI.
`fingerprint().ja4h` comes back empty and `fingerprint().ja4h_available` is
`False`, reported rather than left to be inferred — the real implementation
never returns an empty string.

The wheels on PyPI are built without the tag, so JA4H is present there.

## Install

```bash
pip install curlpro
```

Neither Go nor a compiler is needed: the native library and all 302 profiles are
already inside the wheel. Wheels are built for five platforms:

| Platform | Wheel |
|---|---|
| Linux x86-64, glibc 2.28+ | `manylinux_2_28_x86_64` |
| Linux ARM64, glibc 2.28+ | `manylinux_2_28_aarch64` |
| macOS 13+, Intel | `macosx_13_0_x86_64` |
| macOS 13+, Apple Silicon | `macosx_13_0_arm64` |
| Windows x64 | `win_amd64` |

The macOS 13 floor is not ours to choose: that is what Go 1.27 requires, and the
native part is built with it.

The same files are attached to the [release page](https://github.com/int3re/curlpro/releases/latest),
for installing without reaching the index:

```bash
pip install curlpro-*-manylinux_2_28_x86_64.whl
```

**Platforms outside the table** — Alpine and other musl distributions, Windows on
ARM, older glibc or macOS — have no wheel. There the source archive is built by
hand, and Go and a C compiler are required: `pip install` alone would leave the
package without its native part, and the failure would come at the first call
rather than at install time.

```bash
pip download curlpro --no-binary :all: --no-deps
tar -xzf curlpro-*.tar.gz && cd curlpro-*/go
CGO_ENABLED=1 go build -buildmode=c-shared -o ../curlpro/lib/libcurlpro.so ./lib
```

`CGO_ENABLED=1` is not decoration: without it the build fails with "build
constraints exclude all Go files", a message that names neither the cause nor
the cure.

### From the repository

For development and for editing profiles:

```powershell
.\build.ps1                                        # → dist/curlpro.dll
cd python; $env:PYTHONPATH='.'; python -m pytest tests
```

Profiles load themselves only from a wheel. Running from the repository, point at
them explicitly:

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
| `connect_timeout`, `response_timeout` | the same limits by name: connecting (resolution, TCP, TLS) and the wait for the response headers. `response_timeout` covers the gap the other two leave — a server that accepts and then thinks — and does not bound the body: once the headers are in, only `timeout` applies |
| `proxy` | `http://`, `https://`, `socks5://` or `socks5h://`, `user:pass` allowed. An address with no scheme — `1.2.3.4:8080` — is read as `http://`; there is no probing, a SOCKS proxy has to say so. `HTTP_PROXY` is read for `http://` requests and `HTTPS_PROXY` for `https://`, `ALL_PROXY` for both, `NO_PROXY` excludes. The first CONNECT goes without credentials and adds them after a 407, as Chrome does; a proxy that hangs up instead of challenging gets a second CONNECT with credentials on a fresh connection, and one that hangs up on that too is reported as such (`proxy_closed`) |
| `trust_env` | take the proxy from `HTTPS_PROXY`/`ALL_PROXY`, honouring `NO_PROXY` |
| `verify` | `True` — system roots, a PEM path — trust only that one, `False` — no verification |
| `cert` | a `(certificate, key)` pair for mTLS |
| `retries`, `retry_statuses`, `retry_methods`, `retry_backoff`, `retry_max_backoff`, `respect_retry_after` | the retry policy; only idempotent methods are retried by default |
| `allow_redirects`, `max_redirects` | following 3xx |
| `cookies` | the cookie jar shared by the session's requests |
| `default_headers`, `header_order`, `mode` | profile headers, desired order, header set (`navigate`/`fetch`/`auto`) |
| `force_http1`, `http3`, `alt_svc` | transport: forbid h2, go straight to QUIC, upgrade on `Alt-Svc` |
| `post_quantum` | `False` drops the X25519MLKEM768 group and its 1216-byte key share — the hello of a browser with post-quantum key agreement off by policy. JA4 stays, JA3 and the size move: ~1.9 KB over two TCP segments becomes one that fits in one |
| `resume` | TLS session resumption, on by default: the second connection to a host carries the ticket, the way a browser's does. The resuming hello was measured on Chrome 153 and Firefox 156 and is reproduced, Firefox's dropped `session_ticket` included; the first hello is untouched |
| `page` | the page the requests are made from: `Referer`, `Origin` and `sec-fetch-site` are derived from it as a browser derives them (see below); `s.page = url` moves it |
| `credentials`, `samesite` | which cookies a request from a page carries: `fetch()`'s credentials mode (`same-origin` by default — none to another origin, even of the same site; `include`; `omit`) and the `SameSite` rules of the browser family, measured on Chrome 153 and Firefox 156; `samesite=False` sends every match, as before 0.10 |
| `preflight` | the CORS preflight before a non-simple cross-origin fetch from a page — sent, checked, cached for its `Access-Control-Max-Age`; a refusal is `CORSError` and the request is not sent. `False` sends straight out |
| `keep_alive`, `max_idle_conns`, `idle_conn_timeout` | connection reuse and pool size |
| `resolve`, `ip_version` | host address override, address family (`"4"`/`"6"`) |
| `device`, `devices` | the identity for profiles with a pool — a phone, a Windows release and Chrome build, an iOS version — and your own list |
| `max_response_size` | body size limit; an endless response would eat memory. Not given: 100 MiB for a buffered response, none for a stream; `0` means no limit. Binds `read()`, not `iter_content()` |
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
| `headers`, `header_order` | your own headers, and the send order as a pattern — `[..., "accept", "x-api-key", ...]` puts a header right after Accept, `...` is the profile's own order (see below); a value of `None` removes a header the profile or the session would send, `""` sends it empty |
| `protocol` | `1.1`/`http1`, `2`/`h2`, `3`/`h3` — the transport for this request |
| `timeout` | a number or a `(connect, total)` pair |
| `connect_timeout`, `response_timeout` | the connecting limit and the headers-wait limit by name; `connect_timeout` wins over the pair's first element |
| `proxy` | an address, or `False` to bypass the session proxy |
| `cookies` | `False` — neither send nor store cookies |
| `session_headers` | `False` — without the headers added to the session |
| `default_headers` | `True`/`False` — the profile headers, either way |
| `mode` | `navigate` or `fetch` — which header set to use; `fetch` on a profile without a fetch set is refused with the reason, not sent as a navigation |
| `page` | the page this request is made from, overriding the session's; `False` sends it with no initiator |
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
s.get(url, headers={"Sec-Fetch-User": None})   # one profile header gone, the rest intact
```

The cookie isolation is deliberately two-way: "do not use the memory" reads as "do
not touch it at all". Such a request cannot leave a cookie behind that would make
the next one go out under a different identity — say, while checking a page "as an
anonymous visitor".

`default_headers` and `session_headers` are separate: the first is the browser's set
(that is the fingerprint), the second is what you added. Switching one off leaves
the other alone.

A header given as `None` is removed — from the profile's set or the session's — and
the rest goes out exactly as the browser sends it, order included. That is the way
to lose one navigation-only header without `default_headers=False`, which loses the
User-Agent and the order with it; on the session, `s.headers["Sec-Fetch-User"] =
None` does the same for every request, and `s.headers.suppressed` lists what is
gone. An empty string is a value: it is sent as an empty header, the way a
browser's `fetch()` sends one.

## Header order

The order is part of the fingerprint, so a custom header is placed where the
browser would put one — before the profile's anchor — without being asked. When
that is not the place, `header_order` is a pattern over the browser's order:
names, and `...` for "the profile's own headers here".

```python
s.get(url, headers={"X-Api-Key": "k"},
      header_order=[..., "accept", "x-api-key", ...])   # right after Accept, the rest untouched
s.get(url, header_order=["x-api-key", ...])            # first
s.get(url, header_order=[..., "accept-encoding", "accept-language", ...])   # two profile headers swapped
```

Several `...` are allowed: an unlisted profile header stays beside the listed
neighbour it follows in the profile. A list without `...` is the list followed
by the rest of the profile. Names the request does not carry are skipped, so one
pattern on the session serves every request; a name listed twice is refused.
`fingerprint().headers` shows the result before anything is sent.

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
| `encoding` | the body's charset — from `Content-Type`, the BOM, then the document — is this one; `cp1251` and `windows-1251` compare equal. Catches the page that came back in cp1251 where the code expected UTF-8 and `.text` would have decoded it into mojibake in silence |
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

A request's rollback is exact since 0.12: the native side logs the cookies the
request changed and undoes just those, so cookies another thread's request
received meanwhile stay. `transaction()` restores the snapshot it took before
the block. Half a login is worse than no login.

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

`PermanentError` — with `ProfileCapabilityError`, `ConfigurationError` and
`ProxyAuthError` under it — is the one a scraper branches on: it means the
answer will not change, so do not retry. A profile that has no fetch set, a
device that is not in the list, a page that is not a URL, a proxy login the
proxy rejects. Everything else is worth a retry. `ProxyError` says the proxy,
not the target, failed, with `.stage` (`dial`, `auth`, `connect`) and
`.status` — a pool decides from those, not from the text. `CORSError` is a
refused preflight, with the answer attached.

The outcome codes: `timeout`, `expectation`, `profile_capability`,
`configuration`, `proxy`, `proxy_auth`, `proxy_closed`, `cors`,
`session_closed`, `too_large`, `ws_closed`, `ws_too_big`, `ws_protocol`. The
message is written for a human and names the consequence, not only the fact:

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

## Your own fingerprint, without a request

What a server would see is computed locally, from the same ClientHello bytes
that would go on the wire. No network, no oracle:

```python
with curlpro.Session("chrome-151-windows") as s:
    fp = s.fingerprint()
    print(fp.ja4)       # t13d1516h2_8daaf6152771_806a8c22fdea
    print(fp.akamai)    # 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
    print(fp.headers)   # the order the names will go out in
    fp.client_hello     # the ClientHello itself: bytes, key shares drawn afresh per call
```

`headers_for()` answers the same question for one request rather than a plain
GET — its method, mode, page and headers — so seeing what goes out needs no
server of your own:

```python
s.headers_for("POST", api_url, mode="fetch", page=page_url)
# {'sec-ch-ua-platform': '"Windows"', ..., 'origin': ..., 'referer': ...}
```

And `capabilities()` says what a profile can do before you commit to it:

```python
curlpro.capabilities("safari-26.0-macos")
# {'modes': ['navigate', 'fetch'], 'protocols': ['http1', 'h2'],
#  'devices': [], 'derived_fetch': True, ...}
```

These values used to be obtainable only from browserleaks, which made every
check depend on someone else's service. The computation is checked against the
50 captures in `reference/baselines`: **JA4 50/50, JA3N 50/50, Akamai 50/50**.

`diff()` answers the question a profile edit actually raises — did a server
notice:

```python
a = curlpro.Session("chrome-151-windows").fingerprint()
b = curlpro.Session("chrome-152-windows").fingerprint()
a.diff(b)["extensions"]      # ... -> 'ca34' appeared: trust_anchors
```

The session's own options count: `force_http1` restricts ALPN, and ALPN is two
characters of JA4, so such a session has a different fingerprint — legitimately.

**JA4H** is the fingerprint of the request itself: method, protocol, whether
cookies and a referer are present, how many headers there are, the language, and
hashes of the header names and of the cookies. Two clients with identical TLS can
still differ here, which is why defences score the two together.

```python
s.fingerprint().ja4h          # ge20nn13enus_0c2c1d640f3e_000000000000_000000000000
```

> **JA4H is licensed differently.** JA4 for TLS is BSD-3 and free. JA4H falls
> under the [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4) and is
> patent-pending: internal and academic use is free, commercial monetisation
> requires an OEM licence from FoxIO. This library is Apache 2.0, so the
> obligation lands on whoever ships a product that computes these values.

One subtlety is deliberate: `fp.ja3` **moves** between connections for Chrome
≥110, because the extensions are shuffled and twelve builds give twelve values.
That is not a defect — a frozen order is itself an anomaly. Compare `ja4` or
`ja3n`, which sort.

## Personas: an identity between runs

Profile, proxy, device, headers and cookies — one identity, one file:

```python
p = curlpro.Persona.new("chrome-151-windows", proxy="http://user:pass@host:8080")
p.save("accounts/user42.json")

# next run: the same fingerprint, the same exit, the same cookies
p = curlpro.Persona.load("accounts/user42.json")
with p.session() as s:
    s.get("https://example.com/")
p.save()
```

The cookies are captured even when the block raises: a half-finished login is
still state. The write is atomic — a process killed mid-write would otherwise
leave a lost account rather than a stale one.

A persona deliberately rotates nothing: which one to use, when to retire it and
how to spread them over proxies is policy, and policy is yours. A library would
be guessing.

## requests compatibility

```python
import curlpro.requests as requests

r = requests.get("https://example.com/", timeout=10)
print(r.status_code, r.text[:200])
```

Existing code changes one import. This is a subset, and it says so: an argument
the shim cannot honour is **refused with a reason**, not ignored — a silently
dropped `verify=False` looks like it worked right up until it matters. Transport
adapters, requests hooks and `stream=True` are not implemented (for a real
stream there is `Session.stream`, which holds the connection).

The exceptions are not duplicated: `requests.HTTPError` *is*
`curlpro.HTTPError`, so an existing `except` catches the new errors.

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
    s.get(url)          # User-Agent: Android 15; SM-S911B — and sec-ch-ua-model:
                        # "SM-S911B" once the site asked for the hints
```

The device is chosen once per session: a real client does not swap phones between
requests. The pool holds 46 real phones — exact `ro.product.model` strings from
Google's Play device catalogue, weighted to the Russian market, each on a
plausible Android version — so `device="random"` draws a believable phone while
the TLS stays one. Your own list goes into the `devices` parameter, or you set
one phone by name.

One deliberate departure from Chrome, decided by the project's owner: a chosen
device is written into the `User-Agent` as well (`Android 15; SM-S911B`), the way
Yandex Browser writes it, so the 46 phones are 46 strings on Chrome too. A stock
Chrome ≥110 sends the reduced `Android 10; K` and discloses the model only in the
hints — and a defence that knows about the reduction can tell. Without a device
the profile goes out as captured, reduced string included; the string and the
hints always name the same phone and the same Android.

The desktop has its own pool since 0.11. `chrome-151…153-windows/macos/linux`
carry what varies between real users of one Chrome version: the Windows release
(`sec-ch-ua-platform-version`), the exact build (`sec-ch-ua-full-version`,
`-full-version-list`) and whether the browser is a 32-bit process
(`sec-ch-ua-wow64`); the macOS version and CPU; on Linux the build. The iOS
Safari profiles carry the iOS versions of their line — Safari 26 freezes the OS
token at `18_7` and writes the real version only in `Version/` — and the Firefox
Linux profiles the `Ubuntu; ` token. `device="random"` draws one for the
session, `fingerprint().device` names it, and without `device=` the capture
machine's values go out. The TLS stays one; the seed with its sources is
`scripts/identities.json`.

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

The values count as well as the names: a request carrying `sec-fetch-mode: cors`,
or a `sec-fetch-dest` no navigation has, is a fetch whatever else it carries. An
explicit `mode="fetch"` on a profile that has no fetch set — Safari, okhttp — is
refused with the reason rather than sent with the navigation set: `sec-fetch-mode:
cors` beside `sec-fetch-user: ?1` is a request no browser makes, and an anti-bot
reads the pair for free. Every Chromium and Firefox profile carries the set.

A browser's fetch comes from a page, and `Referer`, `Origin` and `sec-fetch-site`
say which. Name it, and the three are derived the way Chrome 153 and Firefox 156
derive them (measured, and the two agreed on every value): the Referer is the
page's URL to its own origin and the page's origin elsewhere, the Origin is the
page's origin on every cross-origin fetch and on anything with a body, and
`sec-fetch-site` is the relation between the page and the URL, degrading along a
redirect chain.

```python
r = s.get("https://example.com/app")                 # a navigation: sec-fetch-site none, no Referer
s.page = r.url                                       # from here on, from that page
s.post("https://api.example.com/v1/x", json_body=d)  # origin: https://example.com, referer: https://example.com/, cross-site
```

Without a page a fetch goes out from the request's own origin, as before. The
audit reports a hand-written `Referer` beside `sec-fetch-site: none`, the
commonest way to say "from a page" and "from nowhere" in one request.

From a page the cookies follow the browser too: `fetch()`'s default
`credentials="same-origin"` sends none to another origin — not even one of the
same site — and `"include"` sends across sites only what the `SameSite` rules
of the family allow (Chromium: `None`, plus an unattributed cookie on a POST
navigation for two minutes; Firefox: nothing on a fetch at all). A non-simple
cross-origin fetch — JSON, a custom header, a DELETE — is preceded by the CORS
preflight the browser sends, with its measured header set, and goes only when
the answer allows it; `r.preflight` shows it, `s.preflight_for(...)` shows it
before sending. Along a redirect chain `Origin` turns `null` where the Fetch
standard says so. All of it measured on Chrome 153 and Firefox 156
(`docs/STAGE18-RESULTS.md`); `samesite=False` and `preflight=False` restore
the behaviour before 0.10.

## Page loads and resources

A page is more than its document: the browser asks for every stylesheet,
script, image, font and frame the markup names, each as the kind of resource it
is, and an anti-bot watches that happen. `resource=` sends a request as one of
those kinds, and `load_page()` loads a document with its resources the way a
browser does — at once, in the markup's order, the icon last:

```python
page = s.load_page("https://example.com/", css=True)  # css: the fonts the stylesheets declare
for r in page.resources:
    print(r.kind, r.status, r.url)                    # style 200 …, script-async 200 …, image 200 …

s.get(img_url, resource="image", page=page.url)       # one resource by hand
s.get(font_url, resource="font", page=page.url)       # a font: CORS, Origin, its own Accept
```

Seventeen kinds — `style`, `script`, `script-async`, `module`, `image`, `icon`,
`font`, `iframe`, `prefetch`, `beacon` and the rest — measured on Chrome 153 and
Firefox 156 over HTTP/2 and HTTP/1.1, down to a head script's `u=1` against a
body script's `u=2` and Firefox asking for a stylesheet's font with
`Accept-Encoding: identity` (`docs/STAGE21-RESULTS.md`). The pool spends
connections the way the family does: a burst of first requests races four
handshakes in Chromium and six in Firefox and rides the first HTTP/2 connection;
Chromium lets an HTTP/2 connection serve another name on its address its
certificate covers, and keeps requests without credentials, and requests from
pages of other sites, on connections of their own.

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

The code, the error messages and the documentation are in English; the README
and the guide have Russian twins kept in step by a test.

## Documentation

Start with [docs/GUIDE.md](docs/GUIDE.md) — the complete guide: every
parameter, every behaviour, what not to reimplement, and which older claims
were checked and found false. [llms.txt](llms.txt) is the short entry point for
an AI assistant.

| File | Content |
|---|---|
| [docs/GUIDE.md](docs/GUIDE.md) | The complete guide, verified against the code; Russian twin in `docs/GUIDE.ru.md` |
| [llms.txt](llms.txt) | The one-page map for an AI assistant: rules, API surface, facts it tends to get wrong |
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
listed in [NOTICE](NOTICE): the project stands on uTLS, uquic and fhttp
(BSD-3-Clause) and quic-go/qpack (MIT), and carries a copy of the `http3` package from uquic
with fingerprint-related changes, described in
[internal/h3/README.md](internal/h3/README.md).

Browser profiles are data, not code: some were captured from live browsers, some
imported from the curl-impersonate signatures.
