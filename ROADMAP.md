# Roadmap

The stages are ordered so that each one ends in a checkable result. The key
principle: **validation appears early**, otherwise the profiles go stale silently.

## Stage 0 — the measurement stand ✅ done 2026-08-31

Without a reference there is no point writing the engine — there is nothing to check
the fingerprint against.

Chrome **151.0.7922.174** was captured: 6 unique JA3 values under one JA4, and the
extension sets collapse into one once GREASE is cut out. The criterion is met.

Artefacts: [capture/](capture/), [reference/chrome-151-windows.json](reference/chrome-151-windows.json).
The details, the divergences resolved and the notes on tooling —
[docs/STAGE0-RESULTS.md](docs/STAGE0-RESULTS.md). The recipes — [docs/CAPTURE.md](docs/CAPTURE.md).

The target values to check against in stage 1:
```
JA4     t13d1516h2_8daaf6152771_806a8c22fdea
Akamai  1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

## Stage 1 — the Go core, one profile, a live request ✅ done 2026-09-01

The spec is built from the **captured bytes** through `utls.Fingerprinter` rather
than from a built-in preset. The fingerprint matched a real Chrome 151 completely —
both the JA4 itself and the character of its variability (6 unique JA3 values under
one JA4).

The details and the spec-caching trap that was found —
[docs/STAGE1-RESULTS.md](docs/STAGE1-RESULTS.md). The artefact: [cmd/probe](cmd/probe/main.go).

The question of the GREASE entry in SETTINGS (issue #260 in tls-client) stays open:
on Chrome 151 it is not visible through fingerproxy, but the raw frames need parsing
with tshark.

## Stage 2 — profiles as data ✅ done 2026-09-01

The profile moved into [profiles/chrome-151-windows.json](profiles/chrome-151-windows.json)
and the fingerprint did not change. Implemented: `based_on` inheritance with cycle
protection, an ECH post-processor (uTLS cannot load it from JSON) and strict
validation — an unknown field, a missed override and a broken chain are errors, not
silent degradation.

Along the way a capture defect was fixed: the stage-0 samples contained the favicon's
headers instead of the main request's. The details — [docs/STAGE2-RESULTS.md](docs/STAGE2-RESULTS.md).

Planned but not done: `//go:embed` (the profile is still loaded from disk) and
`QUICTransportParametersExtension` — deferred until H3 arrives.

## Stage 3 — importing the corpus ✅ done 2026-09-01

43 signatures imported without loss, 17 checked by JA3N. Together with our own
capture that makes 44 profiles: Chrome 98–151, Edge, Firefox, Safari, Tor. Validation
caught three JA3N computation errors and the silent loss of six profiles to a name
collision. Three corpus files turned out to be internally inconsistent — analysed in
[docs/STAGE3-RESULTS.md](docs/STAGE3-RESULTS.md).

A known limitation: the corpus does not carry the priority on HEADERS, so for the
imported profiles that part of the fingerprint comes from fhttp's default and is
wrong for Firefox and Safari.

<details><summary>The original plan for the stage</summary>

- a parser for `lexiforest/curl-impersonate/tests/signatures/*.yaml` → our schema
- 43 files: Chrome 98–150, Safari 15–26, Firefox, Edge, Tor
- run every imported profile through the validator, checking against
  `third_party.ja3n_hash` and `akamai_text` from the YAML itself

The caveats: the Safari files have no `third_party` block (nothing to check against);
with `tls_permute_extensions: true` only JA3N is authoritative.

**The result:** ~40 working profiles instead of one, each with a passed check.
</details>

## Stage 4 — the FFI and Python ✅ done 2026-09-01

`dist/curlpro.dll` (c-shared, 8 exports) and a Python wrapper over ctypes with a
requests-style API. The fingerprint was checked against an **external** oracle,
`tls.browserleaks.com`: Chrome, Firefox and Safari gave exactly the JA4 and Akamai
strings written down in the specification. Runtime registration of a profile works.

The stage-0 question was closed along the way: the PRIORITY section is `0`, and what
diverged was not the browsers but two implementations' way of counting. The details —
[docs/STAGE4-RESULTS.md](docs/STAGE4-RESULTS.md).

The limits: HTTP/2 only, no cookie jar, no redirects, no async; the proxy is
unchecked.

<details><summary>The original plan for the stage</summary>

- `go build -buildmode=c-shared` → `libcurlpro.{so,dll,dylib}`
- a minimal set of exports: session create/destroy, request, cookies, profile
  load/unregister (httpcloak has 102, tls-client has 6; start closer to 6 and grow as
  needed)
- marshal the request and the response as JSON strings through `char*`, with explicit
  freeing
- a Python wrapper over `ctypes`, requests-style: `get/post`, `Session`,
  `AsyncSession`
- `load_profile_from_json()` — registering a profile at runtime **from Python**

The last one matters on principle: the user rolls out Chrome 153 on their own machine
without waiting for a release. That is exactly what neither curl_cffi (a paid API)
nor tls-client (Go code and a merged PR) has.

**The result:** `pip install -e .` and a working `curlpro.get(url, impersonate="chrome-150")`.
</details>

## Stage 5 — a full client ✅ 5.1–5.5 done 2026-09-01

The client is comparable with curl_cffi in features and **31% faster than it**
(1775 against 1352 req/s on a local stand).

The benchmark exposed the corruption of binary bodies: they travelled as a string
inside JSON, and invalid UTF-8 inflated — 10,000 bytes came back as 18,502. Fixed
with a binary frame. The details — [docs/STAGE5-RESULTS.md](docs/STAGE5-RESULTS.md).

**5.6 HTTP/3 is not done** — it stays the next step.

### 5.1 The transport: HTTP/1.1 and ALPN negotiation
The ALPN list comes from the profile rather than being set in code: Safari 15 and the
older Firefoxes have no `h2` in their ClientHello, and such profiles currently fail
with an error. The header order and case in HTTP/1.1 are part of the fingerprint too —
fhttp can do that.

### 5.2 HTTP semantics
- redirects that keep the header order and change `sec-fetch-*` correctly
- a cookie jar shared between the session's requests
- proxies: check CONNECT live, add SOCKS5
- explicit settings for certificate verification, timeouts and the redirect limit

### 5.3 Header control
A "substitute the profile's headers" flag and the ability to set your own order
outright. The user needs access to the order because anti-bots look at it too.

### 5.4 The asynchronous API ✅ done, the scheme changed 2026-09-04
`AsyncSession` over the same core. The "do not block the loop" question was answered
not with `run_in_executor` but by running the work in a goroutine: Python gets a
number and waits for completion on one thread per process. Requests, streaming reads
and WebSocket all travel that way.

### 5.5 Performance
The current FFI runs the request and response bodies as a JSON string — an extra copy
and an escape per kilobyte. Bodies need a binary path (pointer + length). Measure
against curl_cffi, tls-client and httpcloak under the same load.

### 5.6 HTTP/3
The heaviest item: a QUIC stack with ClientHello substitution
(`bogdanfinn/quic-go-utls`) is needed, plus the QUIC-level fingerprint — the
transport parameters and their order, QPACK, the GREASE frames. The profile schema is
already marked up for it in [PROFILE-SCHEMA.md](docs/PROFILE-SCHEMA.md); the
implementation is not there.

---

# The plan from here

Fixed on 2026-09-01, after proxies, multipart and streaming were closed.

The order is justified like this: first the things without which the profiles go
stale silently, then widening the coverage, then distribution.

## Stage 6 — the tools ✅ done 2026-09-01

`curlpro validate` runs all 44 profiles through the oracle and checks the fingerprint
against the recorded reference. The very first run found two **completely broken**
profiles (`chrome-119-macos`, `chrome-120-macos`: an empty PSK brought the handshake
down) and established that for two others the JA4 legitimately fluctuates because of
`padding`.

`curlpro diff` showed that Chrome 133 and 150 differ in exactly two fields — a
confirmation of the delta model.

`curlpro capture` reduced taking a reference to a single command. Checked end to end:
Chrome 151, captured afresh, matched the profile assembled by hand in stage 0 down to
the JA4.

The details — [docs/STAGE6-RESULTS.md](docs/STAGE6-RESULTS.md).

## Stage 7 — HTTP/3 ✅ done 2026-09-01

**Done on 2026-09-01.** Both layers are brought in line with Chrome.

**The H3 layer** — `uquic/http3` vendored into [internal/h3](internal/h3/) with
changes. On `quic.browserleaks.com/fp` the result is **byte-for-byte the same as
Chrome 144**, stably:

```
1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p
```

**The QUIC layer** — the transport parameters changed through `ClientHelloSpec`
([internal/profile/quic.go](internal/profile/quic.go)), with no patch to uquic. Of
the 13 parameters **12 match Chrome**; the thirteenth is the order in
version_information, where utls and curl-impersonate contradict each other, so it was
moved into a profile setting.

**Tied to the profiles.** The schema gained the `http3` and `quic` sections,
`chrome-151-windows` fills them in, and `client.Session` can travel over QUIC
(`Options.HTTP3`). The end-to-end check: 5 requests out of 5 matched Chrome.

Two races were closed along the way (the control stream went out in parallel with the
request; PRIORITY_UPDATE was sent once instead of per request) and response
decompression was added: the profile announces `br` and `zstd` and nobody was
decompressing them.

**What is left:** the QPACK dynamic table (we announce a capacity we do not support)
and settling the last disagreement with a capture.

HTTP/3 **works**: `cmd/h3probe` establishes a connection and gets a response through
uquic. The fingerprint at that point is not yet Chrome's — the precise diagnosis is in
[docs/HTTP3-RESEARCH.md](docs/HTTP3-RESEARCH.md).

The result of measuring against `fp.impersonate.pro/api/http3` (the only oracle that
returns parsed transport parameters):

- **the QUIC layer is nearly ready** — every value matches Chrome. Three things
  diverge: `12584` = `"10AF"` instead of `"ORIG"`, a superfluous `12583`, and above
  all version_information with the stale draft ID `16741339` instead of `0x11`.
- **the H3 layer matches in nothing** — the SETTINGS, the pseudo-header order, the
  GREASE frame, PRIORITY_UPDATE.

### 7.1 Vendoring the http3 package ✅ done

Along the way this fixed what is an open bug at bogdanfinn's
([#264](https://github.com/bogdanfinn/tls-client/issues/264)): the order of the
ordinary headers in H3 came from iterating a map.

A separate conclusion: moving to fhttp for its `HeaderOrderKey` did not work out — it
is built over a different utls fork and the types are incompatible. Sentinel keys of
our own are declared instead, which also spared us a second utls fork in the
dependencies.

### 7.2 The profile schema and the import

Adopt the `perk` format (`SETTINGS|pseudo|transport params|CID lengths`) so that the
four known strings from curl-impersonate can be imported directly.

### 7.3 Settle the last disagreement with a capture ✅ done 2026-09-03

`12583` and `12584` were settled in favour of httpcloak and the Chromium default. The
order in version_information was settled by a capture of our own: `cmd/quiccapture`
took three Chrome 152 connections and showed that **the GREASE position is random** —
`1,GREASE` in one sample, `GREASE,1` in two. Both sides of the argument are right;
each had seen one capture. The order is now drawn per connection, and
`grease_version_first` pins it if that is ever needed.

The same capture confirmed `google_connection_options: "ORIG"`, the absence of
`google_initial_rtt`, an empty SCID with an 8-byte DCID, two 1230-byte Initial
datagrams and a first packet number of 1. The details — [STAGE15](docs/STAGE15-RESULTS.md).

## Stage 8 — CI and distribution ✅ done 2026-09-05

Three workflows in `.github/workflows/`: tests on push, profile validation **on a
schedule** (they go stale from something other than commits), wheels for five
platforms on a tag. The profiles travel inside the wheel and `ensure_loaded()` picks
them up by itself.

Checked locally: the wheel installs into a clean venv, finds 44 profiles and returns
the right JA4. The details — [docs/STAGE8-RESULTS.md](docs/STAGE8-RESULTS.md).

The `reference/baselines/` references were taken from `tls.browserleaks.com` on
2026-09-03 for all 45 profiles — without them the scheduled check failed at the very
first step. The Go version in the workflows was raised to 1.27: with the 1.24 that was
there the module does not build at all.

The repository was published on 2026-09-04 — github.com/int3re/curlpro under Apache
2.0 — and the GitHub workflows run on it for the first time from that point.

Release **0.2.0 happened on 2026-09-05**: five wheels and a source archive on
[PyPI](https://pypi.org/project/curlpro/) and on the
[release page](https://github.com/int3re/curlpro/releases/tag/v0.2.0), published the
trusted way with an environment approval. The order of operations and the rakes — in
[docs/RELEASE.md](docs/RELEASE.md).

## Stage 15 — closing debts ✅ done 2026-09-03

Item 7.3, QPACK, GOAWAY and four header debts were closed — all by measurement rather
than by reasoning. The tools: `cmd/quiccapture` (decrypting a live browser's QUIC
Initial) and the raw-header capture server from stage 14, run against Chrome 152, Edge
and Firefox 154.

The main thing: the profile gained a second header set, `fetch`. A custom header in a
browser only ever appears on fetch/XHR, and their set is different in its entirety, so
a request carrying one on top of the navigation set was anomalous under any anchor.
Also: `http1.order` sets the set as well (Chrome does not send `priority` on
HTTP/1.1, Firefox does not send `TE`), support for the QPACK dynamic table appeared,
and the order in `version_information` turned out to be random — which is what settled
the utls-versus-curl-impersonate argument.

The details — [docs/STAGE15-RESULTS.md](docs/STAGE15-RESULTS.md).

## Stage 16 — the remaining debts and keep-alive ✅ done 2026-09-03

The debts left over after stage 15 were closed and a `keep_alive` option was added to
the session. Connection reuse worked before this too — a measurement showed one
connection for five requests — what was missing was the switch.

The `cmd/hcapture` stand appeared: TLS with ALPN `h2` and QUIC with ALPN `h3` on one
address, HEADERS parsed by hand. The HTTP/3 header order became observable for the
first time, and the very first measurement found a divergence: `Content-Length` went
out last for us while Chrome sends it first in the fetch set.

Also: CONNECT no longer carries `Proxy-Authorization` unasked (Chrome sends it only
after a 407), `permessage-deflate` compresses with a window smaller than 32 KiB too,
and two corpus profiles turned out to be broken — `pre_shared_key` on a fresh
connection.

The details — [docs/STAGE16-RESULTS.md](docs/STAGE16-RESULTS.md).

## Stage 17 — the per-connection limit, asynchronous streams, cookies.txt ✅ done 2026-09-04

Three items from the "what is left" list:

1. **`timeout=(connect, total)`** — as in requests, with one caveat: our second
   element limits the request as a whole rather than the silence between bytes. The
   limit covers name resolution, TCP and the TLS handshake; the first implementation
   limited TCP only, and a peer that went silent after `accept` ate the whole budget —
   the test for that is what drove the fix into the handshake.
2. **Streaming reads and WebSocket in `AsyncSession`** — they simply were not there
   before, and a 32-task thread pool was the ceiling. Now opening a stream, reading a
   chunk of the body, the socket handshake, receiving and sending all have
   asynchronous twins in the core; the pool is gone.
3. **Netscape `cookies.txt`** — the format of `curl -c`, wget and the browser
   extensions is read and written; `load_file` recognises it by its content.

Two defects were found and closed along the way, both by measurement:

- **the result could outrun the waiter** ([python/curlpro/_completions.py](python/curlpro/_completions.py)):
  the work is started and registered in two steps, and a chunk read manages to finish
  between them — the receiver threw such a result away and the task hung forever.
  Caught with 24 concurrent reads;
- **the socket configuration was read inside the goroutine already** ([lib/websocket.go](lib/websocket.go)):
  by that point the pointer into Python's memory had gone stale and the JSON parser
  got garbage. The parsing now happens before the launch.

The ABI was raised to 0.9.0.

## Stage 18 — the protocol and the profile headers per request ✅ done 2026-09-04

`protocol="http1" | "h2" | "h3"` (`1.1`, `2` and `3` are accepted too) picks the
transport for one request; it outweighs both the session's options and an Alt-Svc
switch. A measurement against cloudflare-quic.com within one session: `HTTP/2.0`, then
`HTTP/3.0` over Alt-Svc, then `HTTP/2.0` with `protocol="h2"`, `HTTP/1.1` with
`protocol=1.1` and `HTTP/3.0` again with `protocol=3`.

`h2` does not trim ALPN down to a single value while doing so — no browser sends such
a list — but fails with an error if the server negotiated http/1.1. The error is
marked non-retryable: a second attempt would give the same thing.

`default_headers` became three-valued per request: previously a request could only
switch the profile's headers off, and there was no way to give them back to a session
that had turned them off wholesale. The FFI field `no_default_headers` (bool) was
replaced by `default_headers` (a pointer), and the ABI was raised to 0.10.0.

## Stage 19 — session memory, expectations and the error hook ✅ done 2026-09-05

Five items that were missing against the interface of BAS-like tools:

1. **`cookies=False`** per request — the jar takes part neither in the sending nor in
   the recording. `cookies=True` on a session without a jar is rejected with an error.
2. **`session_headers=False`** — the headers added to the session do not go out; the
   profile's remain (those are governed by `default_headers`).
3. **`rollback_cookies=True`** and `s.cookies.transaction()` — the jar is rolled back
   if the request or the block failed. The snapshot is taken before sending: after a
   failure the jar has already changed.
4. **`Expect`** — checks on the status, the body and the headers, "contains / does not
   contain", "the body is not empty", "parses as JSON". A mismatch raises
   `ExpectationFailed` saying exactly what did not match.
5. **The `on_error` hook** — called on any request failure, and it may substitute the
   exception. Task cancellation and Ctrl+C do not pass through it: substituting a
   `CancelledError` would stop the cancellation.

The ABI was raised to 0.11.0 (the request fields `cookies` and `session_headers`).

## A separate list: the accumulated debt

None of this blocked release 0.2.0 and none of it blocks the work. The list is live:
the ✅ lines are closed, the rest are waiting — mostly on a measurement on hardware
that is not at hand.

| The debt | Why it matters |
|---|---|
| ~~43 profiles do not set `stream_weight`~~ ✅ closed 2026-09-01 | the values were filled in by family: Chrome/Edge 256 exclusive, Firefox/Tor 42, Safari — does not send it at all. Verified by a frame-by-frame breakdown of `fp.impersonate.pro`: Chrome has the `Priority (0x20)` flag, Safari does not |
| ~~The profiles are not collapsed into `based_on` chains~~ ✅ closed 2026-09-01 | `curlpro collapse` reduced 20 profiles to deltas and the catalogue shrank from 161 to 116 KB. All 44 fingerprints were unchanged. The vivid result: the whole difference between Chrome 98 and 110 is `permute_extensions: true` |
| ~~The HTTP/1.1 fingerprint was not checked~~ ✅ closed 2026-09-01 | a profile section `http1` appeared, with the order **and the case**; it is checked against a local raw-header server, because the public oracles normalise names |
| ~~The request body is not streamed~~ ✅ closed 2026-09-01 | `body_file` sends a file as a stream with an explicit `Content-Length` — without it the transport would go chunked, which a browser does not do |
| ~~TLS to an `https://` proxy~~ ✅ closed 2026-09-01 | the channel to the proxy is encrypted; previously a CONNECT with credentials went out in the clear to a TLS port |
| ~~The body is drained before a retry without a limit~~ ✅ closed 2026-09-01 | limited to 2 KB, as in `net/http` |
| ~~h2: a `GOAWAY` after processing is indistinguishable from one before it~~ ✅ closed 2026-09-03 | the distinction between "the request was processed" and "was not" is now made explicitly: retrying a non-idempotent method is allowed only when the request is known not to have been processed (no connection, a GOAWAY with a smaller last-stream-id, `REFUSED_STREAM`) |
| ~~The connection pool grows without a limit~~ ✅ closed 2026-09-01 | `MaxIdleConns` (64) and `IdleConnTimeout` (300 s, as in Chrome); connection busyness was introduced at the same time — HTTP/1.1 no longer spoils an open stream with a parallel request |
| ~~`cookie` is appended at the end rather than at the profile's position~~ ✅ closed 2026-09-02 | the profile declares `cookie` as an empty slot — a position without a value; the user's headers go in front of the `custom_anchor`. It was also found that the anchor worked on HTTP/1.1 only and that HTTP/3 lost `SuppressHeaders` — see STAGE13 |
| ~~The position of `Content-Length` is not confirmed by measurement~~ ✅ closed 2026-09-02 | a Chromium 148 measurement: third, right after `Connection`; `Content-Type` before `User-Agent`, `Origin` after. The slots were entered into the Chrome/Edge profiles (`http1.order` and `headers.order`), and the library adds `Origin` itself on any method but GET/HEAD — see STAGE14 |
| ~~Firefox's POST slots are not measured~~ ✅ closed 2026-09-03 | a Firefox 154 measurement: `Content-Type`, `Content-Length`, `Origin` after `Accept-Encoding`. The slots were entered into the Firefox and Tor profiles — see STAGE15 |
| The fetch cluster with two or more headers of one's own | Chromium lays out the hints and one's own headers as a function of the set of names (a Chrome 152 measurement: three runs, one result). The profile puts them in a single position, which coincides with the browser only when there is one header |
| Safari's POST slots are not measured | the browser is not on the measuring machine; Safari's `Content-Length` still goes out last. Closed on macOS with a single run of `cmd/hcapture` |
| ~~`custom_anchor: accept-encoding` is a guess, not a measurement~~ ✅ partly 2026-09-02 | a Chromium 148 measurement: the custom fetch/XHR headers go in the renderer's cluster before `Accept`, not before `accept-encoding`. Chrome/Edge were moved to the `accept` anchor; Firefox/Safari kept the guess |
| ~~The navigation profile does not know about a "fetch mode"~~ ✅ closed 2026-09-03 | a profile section `fetch` appeared with its own set, order and anchor; the mode is chosen automatically by the method, the body type and the custom names, or set explicitly (`mode=`). Measured on Chrome 152 and Firefox 154 — see STAGE15 |
| ~~Firefox's WebSocket handshake is not measured~~ ✅ closed 2026-09-03 | a Firefox 154 measurement matched the template recorded from the known captures, name for name |
| Safari's WebSocket handshake and fetch set | the browser is not on the measuring machine: Safari gets the RFC minimum from the code and the navigation set. Closed in the same place as the POST slots |
| ~~Chrome's `fetch.order`: `priority` is not measured~~ ✅ closed 2026-09-03 | a Chrome 152 measurement with the `cmd/hcapture` stand: `priority` is in the fetch set, its value is `u=1, i`, and it goes last. The position of `cookie` was confirmed at the same time — after `accept-language` — see STAGE16 |
| ~~CONNECT: `Proxy-Authorization` goes out immediately~~ ✅ closed 2026-09-03 | the first CONNECT goes out without credentials, the retry after a 407. The connection is reused if the proxy holds it, otherwise it is opened again — see STAGE16 |
| ~~permessage-deflate: a client window smaller than 32 KiB~~ ✅ closed 2026-09-03 | with a window smaller than the standard one the compressor is taken from `klauspost/compress`. Checked against a server of our own: RSV1 plus parsing the `zlib` stream with `wbits=-9` — such a stream cannot be read with a 32 KiB window |
| ~~Firefox's q ladder was inferred, not measured~~ ✅ closed 2026-09-08 | the audit read `0.8/0.5/0.3` as Firefox's signature and a 0.1 step as Chrome's. A live Firefox 155, asked with `intl.accept_languages` set explicitly, answered `ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7` for four languages and `ru-RU,ru;q=0.9` for two — a flat 0.1 step, the same as Chrome. The formula `1 - i/n` no longer holds, the shape no longer separates the two browsers, and the check was removed rather than narrowed: its other half ("a ladder holding 0.5 is Firefox's") misfires on a Chrome with six languages |
| The Firefox 133/135/144 ladders are still inferred | the corpus only ever carried two-item lists (`en-US,en;q=0.5`), which say nothing about a four-item shape, and the Russian values in those three profiles were written from the old formula. Firefox 155 is measured; when the change landed is not known, so replacing one guess with another buys nothing. Closes with a capture of an older Firefox |
| A profile without an `http1` section — not a debt but a property | all 47 profiles have the section (their own or through `based_on`). The code's approximation stays for the profiles registered at runtime out of three fields: there is nowhere for an order to come from there |
| ~~The HTTP/1.1 set was assumed equal to the HTTP/2 one~~ ✅ closed 2026-09-03 | measured: Chrome does not send `priority` on HTTP/1.1, Firefox does not send `TE`. When `http1.order` is given it sets the set as well, not just the order |
| ~~"A new Python with an old DLL" silently ignores options~~ ✅ closed 2026-09-02 | `curlpro_version` = `0.2.0`, and `_ffi.py` checks `REQUIRED_VERSION` at load. The problem is not theoretical: an hour of runs of the wrong code was lost to it — see STAGE13 |
| ~~QPACK: we announce a table capacity we do not support~~ ✅ closed 2026-09-03 | a decoder of our own, `internal/qpack`, with a dynamic table and blocked streams, checked against the appendix B examples of RFC 9204. `fp.impersonate.pro` now answers 5 times out of 5, where it was 1 out of 5 |
| A race in `fhttp` when closing HTTP/2 under load | found on 2026-09-05 by the test `TestConcurrentCloseDuringRequests` under `-race`: `handleResponse` assigns `cs.bufPipe = pipe{…}` without the connection mutex (`fhttp@v0.6.8/http2/transport.go:2361`) while `closeForError` closes that same pipe under it (`:1096` → `http2/pipe.go:105`). Closing the session while an HTTP/2 response is arriving writes the struct from two goroutines; a lost close means a reader that will only be released by the request timeout. There is nothing on our side to synchronise it with — either patch the dependency or wait for the requests in flight on `Close`, which changes what "close now" means. The subtest is skipped under the detector and the behaviour without it was checked over five runs |
| ~~Three corpus files are inconsistent~~ ✅ closed 2026-09-03 | taken apart one by one. `chrome-119-macos` and `chrome-120-macos` contained `pre_shared_key` — the session-resumption extension, because of which the profile did not bring a connection up at all; replaced with `padding`. `chrome-131-android` had its `sec-ch-ua-mobile` fixed — it was `?0` under a mobile UA — see STAGE16 |

---

## Stage 6 — the update tools

- `curlpro capture` — a wrapper over the stage-0 stand: bring up the echo server, wait
  for the browser, gather ≥5 samples, normalise, emit a JSON profile
- `curlpro validate` — replay a profile against browserleaks, diff against the expected
  hashes
- `curlpro diff <a> <b>` — what changed between versions (over `utls.UTLSIdToSpec`)

**The result:** adding a new Chrome is one command plus a review of the delta.

## Stage 6 — CI and distribution

- the matrix: every profile × validation against browserleaks, on a schedule (not only
  on push) — profiles go stale from changes on the services' side, not from commits
- building the wheels: linux x86_64/aarch64 (manylinux), macOS x86_64/arm64,
  Windows x86_64
- the binary goes into the wheel through `package-data`, as in httpcloak

**The result:** `pip install curlpro` works without Go on the user's machine.

---

## What we deliberately do not do

- **we do not patch curl and BoringSSL** — the build system would eat months and the
  profiles would stay in C
- **we do not support the JS/DOM fingerprint** — that is the browser's level, not an
  HTTP client's. For tasks that need canvas/WebGL the answer is Playwright, not this
  library
- **we do not compute JA4S inside the product** without going through the licence —
  FoxIO License 1.1, patent-pending, commercial monetisation requires an OEM licence
  (JA4 itself, for TLS, is BSD-3 and free). ~~JA4H~~ was implemented on 2026-09-08 by
  the maintainer's decision: the licence is the same, the obligation arises for
  whoever ships a product, and that is said in the code, in the README and in the
  module's documentation — so that it does not come as a surprise to them
- **we are not chasing Safari/iOS at the start** — a different stack, a separate pain;
  Chrome-stable covers most tasks, and Edge/Brave/Opera use the same fingerprint (only
  the `User-Agent` and `sec-ch-ua-platform` differ)

## The risks

| The risk | The mitigation |
|---|---|
| A new browser brings a new extension type → Go code needed | The frequency is about once every 6–12 months (ECH 119, zstd 123, Kyber 124, MLKEM 130, ML-DSA 150, trust_anchors 152). Acceptable |
| uTLS upstream does not tag the fresh parrots | Pin a master commit, watch the `sardanioss/utls` fork |
| fhttp is a fork of a fork and may get stuck | Isolate the HTTP/2 layer behind an interface so that it can be replaced |
| A matching fingerprint ≠ getting past an anti-bot | A deliberate boundary: JA4 and JA4H are scored together, plus JA3S/JARM and behavioural analysis. We close the network layer, not the whole stack |
