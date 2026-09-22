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

## Stage 20 — what shipped after 0.2.0 ✅ done 2026-09-08

Four releases in three days, each one on PyPI and on the release page, published
the trusted way with an environment approval.

**0.3.0** — the offline fingerprint, personas and `requests` compatibility.
`Session.fingerprint()` computes JA3/JA3N/JA4 and the Akamai string from the
ClientHello the session would actually send, with no network and no oracle,
validated 47/47 against the recorded captures.

**0.4.0** — JA4H, Russian profiles, the consistency audit, TLS session
resumption, and English as the documentation's primary language.

- **JA4H** is computed from the same header assembly that produces the wire
  order. Its licence is not the rest's: JA4 for TLS is BSD-3, JA4H is FoxIO
  License 1.1 and patent-pending, so the obligation falls on whoever ships a
  product computing it. Said in the file that computes it, in the module docs,
  in both READMEs and here.
- **46 of 47 profiles gained a Russian `accept-language`.** One string for
  everyone was not an option — the shape of the value is each browser's own
  signature. Tor was left alone deliberately.
- **`session.audit()`** looks for contradictions inside an identity: the TLS
  says one browser and the User-Agent another, a phone profile with no device,
  Tor with a language. It reads what the session would actually send rather than
  our own configuration.
- **`Session(resume=True)`** — off by default. A client that never resumes is an
  observable anomaly none of our metrics can see, because JA3, JA4, JA4H and
  Akamai all come from the first exchange. `OmitEmptyPsk` keeps the first
  handshake byte-for-byte what it was, under its own test.

**0.4.1** — the Install section on the package page begins with the install
command. In 0.4.0 it opened with the platform list and a `go build`, and anyone
jumping to the heading concluded that compiling was mandatory. Found by a reader
doing exactly that. The same pass corrected all three READMEs on a related
point: `pip install` does not build the source archive by itself — the backend
is a plain `setuptools.build_meta` with no hook, so on a platform with no wheel
the package installs without its native part and fails at the first call.

**0.4.2** — cleartext `http://` and `ws://` are accepted. They used to be
refused outright on the grounds that the library exists for the TLS fingerprint;
in practice that forced a second HTTP client into any project whose own service
speaks plain HTTP. There is no ClientHello over cleartext, but the HTTP/1.1 half
of the profile still applies, which is all a plain-HTTP peer can see. The scheme
joined the pool key — `http://host:8443` and `https://host:8443` share an
address — and the default port follows the scheme. `protocol="h2"` over
`http://` (h2c) and `protocol="h3"` (TLS by definition) are refused rather than
quietly downgraded, and a redirect from `https://` to `http://` is handed back
as a 3xx with its `Location` instead of being followed.

## Stage 21 — the first Firefox captured by us ✅ done 2026-09-08

`profiles/firefox-155-windows.json`: the first Firefox in the corpus that is not
macOS and not imported. JA4 `t13d1517h2_8daaf6152771_3cbfd9057e0d`, Akamai
`1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`, checked against browserleaks
and matching on a second run. 48 profiles now.

It exposed two defects and settled one question:

- **`capture` launched Chrome for `-name firefox-154-windows`.** The name only
  set the output file; the browser came from a list holding Chrome alone. The
  profile that came out was Chrome 152 under a Firefox name — not a weaker
  profile but a false one. The family is now read from the name, each has its
  own paths and its own switches, and an explicit `-browser` must agree with the
  name or the command stops.
- **The audit passed that profile in silence.** Its version check looked for the
  family's token in the User-Agent and returned nothing when the token was
  missing — which is the strongest form of the disagreement, not a reason to
  skip. It now reports a different browser as `high` and an unrecognisable
  User-Agent as `medium`.
- **The browser turned out to be 155, not 154** — caught by that same repaired
  check, which is what renamed the profile.

Firefox 155's cipher list has converged with Chrome's: 15 rather than the 17 of
Firefox 135, and the same `JA4_b`. Surprising enough to be worth a second
source, and there is one — a third-party BAS module distributing its own preset
data states the same 15 ciphers and the same `JA4_b` for Firefox 155, arrived at
independently. Its `JA4_c` disagrees with ours, but it also disagrees with the
extension and sigalg lists that same file declares: computing `JA4_c` from those
lists by the FoxIO spec gives our value.

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

## Stage 22 — three items from the external review ✅ done 2026-09-09

A review on 2026-09-08 scored the project 8.5 and named four open items. Three
are closed here; the fourth, automated capture of a new Chrome, is the one that
needs a decision rather than code.

**Dependencies are vendored.** utls and uquic are pinned to pseudo-versions on
master, because upstream does not tag the fresh parrots. The review read that as
"the build will break when the author is not around", which overstates it: a
pseudo-version *is* a pin — it names a commit and go.sum locks its hash — and
proxy.golang.org keeps an immutable copy. What it does not survive is the
upstream commit ceasing to exist. `vendor/` (24 MB, 1545 files) removes that
dependency: `GOPROXY=off go build ./...` now succeeds. The source archive on
PyPI is unaffected — the workflow copies only `internal lib go.mod go.sum` into
it, so it stays at 311 KB.

**JA4H can be excluded from the build.** `-tags nofoxio` replaces
`internal/fingerprint/ja4h.go` with a stub, and no FoxIO-licensed code enters
the binary. Everything else is computed as before — checked by a test that runs
under the tag, and the tag is built in CI on every push so it cannot rot into an
option that no longer compiles. `Fingerprint.ja4h_available` reports which build
is in use, because an empty string would otherwise read as "computed and came
out empty", which the real implementation never returns. The three Python tests
that assert on JA4H skip themselves when it is absent.

**Versioning is written down** in [docs/VERSIONING.md](docs/VERSIONING.md): what
a patch and a minor may change, what is outside the contract (error wording,
fingerprint values, `internal/`), how the ABI number differs from the package
version, and why there is no 1.0 yet — the corpus is still updated by hand, and
an API nobody has argued with is not worth freezing.

One claim in the review was checked and did not hold. It suspected the "48/48"
figure of being softer than it sounds, because the baseline schema allows a
wildcard `"*"` and the reviewer had spot-checked three files. All 48 were
checked: **no wildcard anywhere.** Four files carry two values for `ja4`/`ja3n` —
`chrome-119-linux`, `chrome-119-macos`, `chrome-120-macos`, `edge-120-linux` —
and that is not slack but a description of the browser: those profiles carry
`padding`, so the ClientHello length, and the fingerprint with it, legitimately
varies per connection. Found in stage 6 and recorded then.

## Stage 23 — okhttp, the first non-browser profile ✅ done 2026-09-11

`okhttp-5.5-conscrypt` and `okhttp-5.5-jvm`, 50 profiles now. okhttp is a
library rather than a browser, so it was measured the way nothing else in the
corpus could be: Java 21 plus the jars from Maven Central, no Gradle, no
device, a probe run against the stand five times with a fresh `SSLContext` each
time. Reproducible by anyone with a JVM.

**Two stacks, two fingerprints.** On Android okhttp's TLS comes from Conscrypt
(BoringSSL); on a desktop JVM from SunJSSE. Both were captured. Conscrypt gives
`t13d1512h2_8daaf6152771_40271e0a5736` — Chrome's cipher set to the hash, the
same BoringSSL underneath, 12 extensions to Chrome's 17. SunJSSE gives
`t13d1114h2_5e2a75874763_62776a4e08ff`. The HTTP/2 layer is okhttp's own and
identical on both: `4:16777216|16711681|0|m,p,a,s`, two headers
(`accept-encoding`, `user-agent: okhttp/5.5.0`). Both checked against
browserleaks and matching on a second run.

**Named for what was measured.** Not `android-okhttp`: Conscrypt on a desktop is
the same library Android ships, but its own version, and nothing here was
checked on a device. A name that promised Android would promise the unverified.

Two traps on the way, both recorded in [docs/CAPTURE.md](docs/CAPTURE.md):
SunJSSE sends no SNI for a name without a dot, so a stand on `localhost` gave
`t13i` instead of `t13d` — the probe resolves `www.example.com` itself; and a
reused connection resumes, so the resumed-handshake filter from stage 21 ate
every sample but the first until the context was made fresh per run.

The profile found the largest defect of the week: its 16 MiB stream window
drove fhttp's receive accounting into a quadratic runaway that every browser
profile had merely been too small to trigger — [docs/FHTTP-PATCH.md](docs/FHTTP-PATCH.md).
The release was held until that was fixed.

## Stage 24 — the limits by name, and the one that was missing ✅ done 2026-09-14

A user's list against the API: `connection_timeout`, `response_timeout`,
`ContentEncoding`, `ContentNotEmpty`, `ContentAsJson`. Checked against the code
rather than remembered: two existed under other names (`Expect(non_empty=True)`,
`Expect(json=True)`), one existed without a name of its own (the connecting
limit was the first element of `timeout=(connect, total)`), two did not exist.

**`response_timeout`** — the wait for the response headers. The gap the other
two limits left: a server that accepts the connection and then thinks for a
minute is past the connecting limit and still inside the total one. It is a
timer that cancels the request if nothing has arrived by then and is stopped
the moment the headers are in; the body reads under the total limit alone. A
second context would not do — on HTTP/2 the body is bound to the request
context, and cancelling a headers-only context after the headers would kill
the read that follows.

It found a defect of its own: on HTTP/1.1 the round trip took the limit from
the socket deadline and never looked at `ctx.Done()`, so a cancelled context
did not interrupt a blocked header read — the HTTP/1.1 case failed while the
HTTP/2 case passed. The header wait now watches the context and pulls the read
deadline to now on cancellation, restoring it afterwards unconditionally so the
body cannot inherit an expired deadline from the race. Four Go tests over both
transports; the one that matters as much as "it fires" is "it does not cut a
slow body". ABI 0.16.0.

**`connect_timeout`** and **`response_timeout`** are named keywords on the
session and per request, beside the pair; the named one wins over the pair's
first element.

**`Expect(encoding=)`** — the body's charset, as the detector sees it, must be
this one, names compared through `codecs` so that `cp1251` and `windows-1251`
are one answer. The check that catches a Russian site handing back a cp1251
page where the code expected UTF-8: `.text` would have decoded it into
mojibake without a word.

## Stage 25 — a large device pool, from real phones ✅ done 2026-09-14

`device="random"` drew from eight phones; now from 46. The value of it: the
device is the one identity axis that varies without touching the TLS a server
scores, so a big pool is many believable clients behind one fingerprint — the
question a user asked directly.

The models are not invented. Each is the exact `ro.product.model` a phone
reports — the string Chrome puts in `sec-ch-ua-model` and Yandex writes into the
User-Agent — taken from Google's public Play device catalogue, the global
variant (Samsung `…B`, not the US `…U`) because the library is for Russian
sites, and weighted to that market: Samsung, Xiaomi/Redmi/POCO, Pixel, Honor,
realme, OnePlus, vivo, Tecno, Infinix. Each on an Android version it plausibly
runs, spread across 13–16 — a pool where every phone ran one version would
itself be a tell.

The pool is owned by `scripts/gen-devices.py` from a committed, verified seed
(`scripts/android-devices.json`) and written into `chrome-152-android` and
`yandex-26.8-android` — the latter with `arch`, where the 46 models become 46
distinct User-Agent strings because Yandex writes the model into the string.
`gen-devices.py --check` in CI fails if a profile drifts from the seed. Pure
data: no ABI change, and the TLS fingerprints are untouched — checked by the
audit, which still fires on exactly the two profiles it did before.

## Stage 26 — a field report: fetch under a navigation name ✅ done 2026-09-15

A user's bug report with six items, each reproduced against a local stand
rather than taken on trust. Two were real and are closed; two were the network
between the user and the echo service; two were settled by measurement.

**Real: `mode="fetch"` sent the navigation set on Firefox 155.** The profile,
captured live, had no `fetch`, `http1` or `websocket` sections — a capture
measures TLS and HTTP/2 only — and an explicit fetch on a profile without a set
fell back to navigation without a word. So the caller's `sec-fetch-mode: cors`
went out beside the profile's `sec-fetch-user: ?1` and
`upgrade-insecure-requests: 1`, a request no browser makes, and Yandex
SmartCaptcha sent every attempt into the picture. Closed three ways: the
profile carries the Firefox family sets (measured on Firefox 154, carried by
133/135/144/Tor); `curlpro capture` gives a full profile the sets of the newest
sibling of its family (`-sets`), so the next raw capture cannot repeat this;
and an explicit fetch on a profile with no set is refused with the reason. In
auto mode the values of `sec-fetch-mode` and `sec-fetch-dest` now pick the set
the way a custom header's name does.

**Real: a header given as `None` went out empty.** The only way to drop one
profile header was `default_headers=False`, which drops the User-Agent and the
order with it. `None` removes now — per request, and on the session with
`s.headers[name] = None` — and `""` is sent as an empty header. ABI 0.17:
`suppress_headers` on the request, a suppression export on the session.

**The network: "Accept-Encoding is rewritten to `gzip, br`".** It is — by
Cloudflare in front of postman-echo.com, for system curl as well. The local
stand shows the profile's `gzip, deflate, br, zstd` on the wire, with and
without `default_headers`.

**Measured: "curlpro negotiated HTTP/1.1 where Firefox would take h2".**
`smartcaptcha.yandexcloud.net` selects `http/1.1` for any client offering
`h2, http/1.1` — Python's `ssl` included; `ya.ru` next to it selects `h2`. That
is why the missing `http1` section mattered: over HTTP/1.1 the Firefox 155
navigation went out with `TE: trailers` and without `Connection: keep-alive`,
and that host speaks nothing else.

**The audit** gained the checks the report asked for: navigation-only headers
beside fetch metadata (high), an `accept-encoding` that is not the profile's
(medium), and a request with no User-Agent at all (high) — the shape
`default_headers=False` leaves behind. The fingerprint carries
`profile_header_values`, the profile's own request, for the comparison.

## Stage 27 — the second field report: the ClientHello itself ✅ done 2026-09-16

The same reporter, on 0.7.0, with raw ClientHello captures of curl, Firefox
155 and Chrome 151 through curlpro. The headers are confirmed clean and the
Accept-Encoding claim withdrawn; what remains is a TLS-layer difference
against a client that passes their anti-bot at ~45%: system curl on Schannel,
a 168-byte TLS 1.2 hello, against curlpro's 1873-byte TLS 1.3 hello with a
1216-byte post-quantum key share that spans two TCP segments on a path with a
known MTU pathology.

**Answered from the capture: Firefox 155 sends three key shares.** The
report suspected the third (secp256r1, 65 bytes) was ours. The profile is the
raw hello recorded from the user's own Firefox 155 on 2026-09-08, and its
key_share carries X25519MLKEM768, x25519 and secp256r1 — what NSS sends. The
client replays the list; the bytes are the browser's.

**`post_quantum=False`.** The knob the report needed for its A/B: drops
X25519MLKEM768 from supported_groups and its share from key_share, which is
the hello of Chrome under `PostQuantumKeyAgreementEnabled=false` and of
Firefox with `security.tls.enable_kyber` off — a client that exists. Nothing
else moves: JA4 is unchanged, JA3 (which hashes the groups) and the size
change, and the hello fits one segment. Off by default: the browser sends
the share, and a size check in the audit was declined for the same reason —
every modern browser's hello spans two segments, so the check would fire on
every stock profile and say nothing.

**`fingerprint().client_hello`.** The marshalled message as bytes, so the
next report does not need a socket server to see what goes out; `len()` of
it answers the segment question. Not part of `diff()`: key shares and GREASE
are drawn afresh per call. ABI 0.18.

## Stage 28 — the header order as a pattern ✅ done 2026-09-16

A user asked to edit the order of the default headers and to place custom
ones among them, in one statement. `header_order` could take a full list —
which meant restating the profile's order and keeping it in step with the
profile — and a partial list put the listed names in one place and the rest
somewhere that depended on the profile's anchor: "put X-Api-Key after Accept"
was not sayable.

Now `header_order` is a pattern over the browser's order: names, and `...`
for "the profile's own headers here". `[..., "accept", "x-api-key", ...]`
puts a custom header right after Accept and leaves everything else as the
browser sends it; `["x-api-key", ...]` first; `[..., "accept-encoding",
"accept-language", ...]` swaps two profile headers. Several `...` are
allowed — an unlisted profile header stays beside the listed neighbour it
follows in the profile — and a list without `...` is the list followed by
the rest of the profile, which replaces the old anchor-dependent placement.
The expansion runs against the transport's own base (the HTTP/1.1 order with
Host and Connection, or the HTTP/2 set), before `reorder`, so the wire and
the fingerprint preview agree, and a custom header the pattern does not
mention still goes before the profile's anchor. A name listed twice is
refused. Pure Go and Python; the JSON field is the same, so no ABI change.

## Stage 29 — the documentation, rewritten against the code ✅ done 2026-09-16

A user's request, and a real one: the project is young, and an AI assistant
handed code that uses the library keeps rewriting what the library already
does — decompression, cookie files, header ordering, retries — because no one
document told it what exists. The README had grown by accretion and carried
claims that were no longer true.

`docs/GUIDE.md` (and its Russian twin) now describes the whole library in one
place: every session and request parameter with its default and meaning, the
response, headers and their order, navigation versus fetch, expectations,
errors and hooks, cookies, profiles and devices, transports, streaming and
async, fingerprint and audit, personas — plus two sections for assistants:
what not to reimplement, and which older claims were checked and found false.
`llms.txt` at the root is the one-page entry point. Every countable claim is
counted by `python/tests/test_guide_claims.py` — 50 profiles by family, 17
distinct JA4 values, the four HTTP/3 profiles, the error codes, the parameter
tables against the live signatures, the API index against the exports — so
the guide fails with the code rather than drifting from it.

The audit of the older documents found five false statements, corrected in
the same release: the README's claim that the documentation was Russian, its
error-code list missing `too_large` and `proxy_closed`, fhttp called MIT
instead of BSD-3-Clause, `ARCHITECTURE.md` naming 0.4.2 as current, and
`curlpro.request` documented by shape but not exported.

## Stage 30 — the initiator, and resumption on by default ✅ done 2026-09-19

Two of the items from the "what next" review, both settled by measurement
([STAGE17](docs/STAGE17-RESULTS.md)).

**The page a request is made from.** A fetch to an API on another origin
went out with the API's own origin in `Origin`, no `Referer` and
`sec-fetch-site: same-origin` — three headers a browser never sends together,
and the audit could not see it because nothing in the session said where the
request came from. `page` on the session and per request names the page, and
`Referer`, `Origin` and `sec-fetch-site` are derived from it the way Chrome
153 and Firefox 156 derive them, measured on a stand of three names
(`cmd/hcapture -origins`) where the two agreed on every value: the Referer is
the page's URL to its own origin and the page's origin elsewhere, the Origin
is the page's origin on every cross-origin fetch and on anything with a body,
the site relation degrades along a redirect chain. A `referer` slot went into
every Chromium and Firefox profile at the measured position, and the Firefox
`cookie` slot moved to where the same measurement showed it. The audit gained
`referer_site`. Not done, recorded as debt: the CORS preflight a browser
sends before a non-simple cross-origin request (measured, both browsers), and
withholding cookies on uncredentialed cross-origin fetches.

**Resumption on by default.** `resume` existed and was off because the
resuming hello had not been measured. Measured now on both browsers against
a stand that closes every connection (`cmd/hcapture -close`) and, for Chrome,
against a real 0-RTT server through a recording proxy: the first hello plus
`pre_shared_key` last, no `early_data` — exactly what uTLS produces — and for
Firefox without the empty `session_ticket`, which the Firefox family now drops
through `tls.resume_omits_session_ticket`, honoured only once a ticket exists
so the first hello and every fingerprint stay what they were. A client that
never resumed was a tell no fingerprint measured; it is gone. ABI 0.19.

**Addendum, 2026-09-20 — the device in Chrome's User-Agent.** By the owner's
decision, and against what Chrome does, `chrome-152-android` carries a
`user_agent_template`: a chosen device is written into the string
(`Android 15; SM-S911B`) as Yandex writes it, so the 46 phones are 46 strings
on Chrome as well. The concern was raised and overruled: a stock Chrome ≥110
sends the reduced `Android 10; K` for every phone, and a defence that knows
about the reduction can tell an unreduced string. Without a device the
captured, reduced string goes out; the string and the hints always name the
same phone and the same Android. Data only, no ABI change.

## Stage 31 — a field report on 0.8.0: four fixes ✅ done 2026-09-20

A user moved a production scraper onto 0.8.0 and sent seven findings. Six were
real; the seventh — that `llms.txt` only points at the guide instead of
carrying signatures — was not, the file has carried them since 0.7.2.

**`s.page` on `AsyncSession` did nothing.** The worst kind of defect in a
library whose rule is "refuse rather than ignore": the wrapper proxied three
properties and `page` was not among them, so the assignment made an attribute
on the wrapper and the request went out with no Referer and the wrong
sec-fetch-site. Found only with an echo server. It was also worse than
reported — `fingerprint()` and `audit()` had never been on `AsyncSession` at
all. All four are proxied now, `__slots__` turns the next forgotten name into
an `AttributeError` at the assignment, and a test compares the two public
surfaces so the next property cannot be forgotten quietly.

**A configuration failure was indistinguishable from a network one.** Every
one of them arrived as a bare `CurlProError` with `code=None`: the reporter's
worker retried "this profile has no fetch set" three times and dropped 48
tasks. Now `PermanentError` with two kinds — `ProfileCapabilityError`
(`profile_capability`) and `ConfigurationError` (`configuration`) — both
subclasses of `CurlProError`, so existing `except` clauses keep working. The
codes are set in Go, where the failures are born.

**A profile could not be asked what it can do.** `curlpro.capabilities(name)`
answers modes, protocols, devices, hints, WebSocket, HTTP/1.1 set and whether
the fetch set is derived — without opening a session. The reporter's stand-in
was a request to a closed port plus a substring match on the error text, which
`docs/VERSIONING.md` explicitly refuses to keep stable. Beside it:
`s.headers_for(...)` previews the headers of one request with its own mode and
page (no echo server needed), `get_profile(name)` returns the resolved profile
as data, and `library_version()` exposes the native version a bug report wants.

**Safari could not fetch.** Eleven profiles had no fetch set, and the reporter
measured Safari passing their anti-bot about twice as often as any Chrome
while being useless for the API calls that followed. `scripts/gen-safari-fetch.py`
derives one from the Fetch standard and each profile's own navigation set —
including *no* `sec-fetch-*` for the 15.x profiles, since WebKit shipped Fetch
Metadata in 16.4. This is the only derived data in the corpus and it says so:
`"derived": true` in the profile, `derived_fetch` in `capabilities()`, and an
audit finding when such a set is used. The set is solid, the order is a guess,
and a capture on real hardware should replace it.

Two things the report surfaced and this stage did not fix: the Safari profiles'
`http1.order` carries Chrome's `sec-ch-ua*` names (inert, since Safari gives
them no values, but wrong as data), and a cross-origin fetch sends no CORS
preflight. Both are in the debt list.

## Stage 32 — the second field report: what the page knows and did not use ✅ done 2026-09-21

The same scraper on 0.9.0 sent six more findings, of a different kind: not
"the library is silent where it should refuse" but "the library knows the
initiator page and does not use that knowledge to the end". Five were right,
one half — `headers_for()` does take `protocol=`, which the report missed,
but it lowercased HTTP/1.1 names and previewed `http://` in the HTTP/2 form.
The two decisions the owner took, both the browser's way: `credentials`
defaults to `same-origin`, and a refused preflight raises rather than sending
anyway — "between a quiet tell and a loud refusal, a library whose third
rule is refuse-rather-than-ignore does not get to choose".

Everything below was measured first (STAGE18): the stand grew cookie priming,
redirect chains and a 125-second hold, and Chrome 153 and Firefox 156 answered
every question but Safari's.

**Cookies from a page.** The jar matched by domain and path and sent
`SameSite=Strict` cookies beside `sec-fetch-site: cross-site` — a pair no
browser produces. Now `fetch()`'s credentials mode (`same-origin` by default)
and the SameSite attribute decide, with the family's policy as data
(`profile.CookiePolicyFor`, exposed in `capabilities()["cookies"]`): Chromium's
Lax-by-default and its two-minute POST window, Firefox's refusal to send any
cookie on a cross-site fetch, both browsers' refusal of `None` without
`Secure`. Cookie records gained `created`. `samesite=False` is the way back.

**The CORS preflight.** Sent on every non-simple cross-origin fetch from a
page, on every hop, with the family's measured OPTIONS order, checked against
the Fetch standard's CORS check, cached for `Access-Control-Max-Age`
(five seconds by default, capped per family). A refusal is `CORSError` with the
answer and the request is not sent; `r.preflight` and `s.preflight_for()`
show it; `preflight=False` is the way back. Closes the debt opened in Stage 30.

**`Origin` on a redirect.** The chain's starting origin, `null` under the Fetch
standard's tainting rule, and Chromium's own `null` on a navigation POST after
any cross-origin hop — Firefox keeps the standard's answer, and the profiles
differ accordingly.

**`ProxyError`.** Four proxy outcomes had one empty code; a pool parsed
"proxy refused CONNECT" out of the text. Now `ProxyError` with `stage` and
`status`, `ProxyAuthError` permanent, `proxy_closed` kept. SOCKS5 is a client
of our own (`x/net/proxy` hides the reply code in an internal type), so the
stages there are real; `socks5://` still resolves on the proxy, as it did.

**The smaller three.** `audit()` judges the sets a session's requests actually
went out with (the report's client set the mode per request and the Safari
warning never fired), plus `audit(mode="fetch")`; `headers_for()` reports
HTTP/1.1 names in the wire's case and takes that form by itself for `http://`;
`capabilities()["fetch_metadata"]` says whether `sec-fetch-*` is sent at all.

The version is 0.10.0: a cross-origin fetch with `page=` no longer carries
cookies and is preceded by an OPTIONS, which is what already-written code
sends. ABI 0.21.

## Stage 33 — the third field report: two edges of 0.10 ✅ done 2026-09-21

The scraper moved onto 0.10.0 the same day, confirmed every claim on the wire
— a live site accepted the library's preflight without a single refusal —
and sent two divergences. A response to a `credentials="omit"` fetch set
cookies, which a browser ignores (Fetch's includeCredentials decides both
what a request carries and whether its response may set cookies); the jar
kept the API's session cookie beside the caller's and the next credentialed
request carried a pair no browser sends. And `Response.preflight` was `None`
on every `AsyncSession` request while the OPTIONS had gone out: the wrapper
built its `Response` without `preflights` — and, it turned out, without
`history` and `elapsed` too, the same shape as the `s.page` defect of 0.8.
Both fixed, both guarded at the response level rather than the method
surface. Found beside them: an imported cookie whose domain is an IP address
was recorded but never sent — fhttp's copy of the jar keeps the older
net/http rule that refuses a Domain attribute on an IP — and is now stored as
the host-only cookie it is. Patch 0.10.1, ABI unchanged.

## Stage 34 — Firefox 156 and Chrome 153, captured live ✅ done 2026-09-22

Chrome 153 (`curlpro capture -based-on chrome-152-windows`, five samples):
one new TLS extension, `0xca34` — trust-anchor identifiers, 186 bytes —
which uTLS does not know and the profile replays as raw bytes; JA4 unchanged
from 152, JA3N moves, HTTP/2 identical. A lesson of the run: the local
fingerproxy stand folds the GREASE signature algorithm into its JA4, so a
Chromium profile shows a different JA4 there on every connection; the
baseline was recorded against browserleaks, which follows the
specification, and matched on a second run — the same way Firefox 156's
was. `fingerprint().device` now names the phone actually chosen
(`device="random"` used to report "random"), which the MTS field report
asked for to see which devices get banned.

The corpora were surveyed again for anything importable (the field report
asked for more Safari, Yandex on the desktop and fresher Chrome on macOS).
`lexiforest/curl-impersonate` still carries the 43 signatures already
imported, nothing newer. `sardanioss/httpcloak` has moved to header-only
presets on a `based_on` chain (its Chrome 152 file holds signature
algorithms, trust anchors and a header order — no hello, no HTTP/2), so
there is nothing to take. `0x676e67/wreq-util` (Chrome 100–153, Edge to 148,
Firefox to 151, Safari to 26.4 with iOS/iPadOS, Opera 116–131),
`bogdanfinn/tls-client` and `deedy5/primp` describe every browser as a
BoringSSL/uTLS configuration in source code, without the hashes a
self-check needs and without the raw hello: importing them means
transcribing another project's transcription and trusting it, which is
the one thing this corpus does not do. What was possible without new
hardware was done instead: four profiles derived from the live Windows
captures on measured evidence — `edge-153-windows` (Chrome's hello and
HTTP/2, Edge's User-Agent and brands; headless Edge 153 never reached the
stand) and `chrome-151/152/153-macos` (the platform in the User-Agent and
`sec-ch-ua-platform` is the whole difference in every Linux/macOS pair the
corpus holds). 56 profiles, still 17 JA4 values.

`curlpro capture -name firefox-156-windows -based-on firefox-155-windows
-manual`, with Firefox 156 driven through the stand by hand in throwaway
profiles that trust its certificate (the browser cannot ignore certificate
errors): five samples, one JA4. The one change from 155 is in TLS —
`supported_groups` lost the two FFDHE entries (ffdhe2048, ffdhe3072), so the
hello is four bytes shorter, JA4 stays `t13d1517h2_8daaf6152771_3cbfd9057e0d`
(it hashes no groups) and JA3N moves. HTTP/2 settings and the header sets
matched 155 and are inherited: the navigation and fetch orders, slots
included, were confirmed on the same Firefox 156 by the STAGE18 capture. The
baseline in `reference/baselines` is the stand's reading of the profile,
matched on a second run.

## Stage 35 — transcribed profiles, marked ✅ done 2026-09-22

The owner's decision on the corpora survey: transcribe the other projects'
descriptions, trust them, mark them at the profile level, and never touch a
version this project has measured. Done for `0x676e67/wreq-util` at commit
`e3922a2`, by `scripts/transcribe-wreq.py`: 238 profiles — 108 Chrome, 37
Edge, 39 Firefox, 22 Safari (macOS, iOS, iPadOS), 32 Opera — on top of the 56
captured, 294 in all.

How, and why this way. wreq-util holds no ClientHello and no hash; it holds
BoringSSL option tuples and, in its source, the statement that version N
inherits version M's tuple. The script reads those statements and, where M is
captured here, writes N as a delta on M: the captured hello, frames and header
sets, wreq-util's brand list and accept-language, the family's User-Agent
shape (wreq-util's own strings are partly malformed — `X11; U; Windows`, a
Firefox 139 with `rv:136.0`, a Safari 17.2.1 with `Version/16.0`), and a
`source` block. Building a hello from the options themselves was rejected:
that would be a transcription of a transcription, checkable against nothing.
Seven versions were left out because their tuple matches nothing captured
(Chrome 105; Firefox 109 and 117, whose PRIORITY frames the schema cannot
express; Firefox 128; Firefox private and Android), and Chromium's Android
and iOS variants because the first needs a device pool and the second is a
different TLS stack altogether. Four Safari versions stand on a captured one
with one HTTP/2 setting removed, as wreq-util claims.

The mark is a profile field, `source`, that travels down the `based_on`
chain; `capabilities()` reports `measured: false` and the block, the
fingerprint carries it, and `audit()` fires `transcribed_profile` on every
such session. `list_profiles(measured=True)` is the captured list, because
`random.choice(list_profiles())` in existing code would otherwise start
drawing claims — which is why this is 0.11.0 and not a patch. Where wreq-util
contradicts a measurement here, the profile's `note` says so rather than
resolving it: Firefox 136–151 declared equal to 135 while the captured 155
and 156 differ; Safari 26.1–26.4 declared equal to 18.5 without the
post-quantum share 26.0 carries; every Opera on Chromium 131's ALPS codepoint.
Trust, as decided, with the receipt attached.

## Stage 36 — the identities behind one browser version ✅ done 2026-09-22

The owner's request after Stage 35: full randomisation of the device for the
User-Agent and the fingerprint, not only on Android. What varies between real
users of one browser version, per family, and what the wire shows of it:

- Chromium on the desktop: nothing in the User-Agent since the reduction, and
  everything in the high-entropy hints — the Windows release
  (`sec-ch-ua-platform-version`, the UniversalApiContract version), the exact
  build (`sec-ch-ua-full-version` and `-full-version-list`), a 32-bit process
  (`sec-ch-ua-wow64`), on macOS the version and the CPU (`sec-ch-ua-arch`).
  Measured first: Chrome 153 on the capture machine, after two failed runs
  taught that headless Chrome sends the high-entropy hints only from a secure
  origin, which `--ignore-certificate-errors` does not make and
  `--ignore-certificate-errors-spki-list` does
  ([STAGE19](docs/STAGE19-RESULTS.md)). The 151–153 desktops gained the
  `client_hints` section they had lacked and a pool — Windows release × build ×
  wow64, macOS version × CPU × build, Linux × build — from Microsoft's contract
  table, chromiumdash and the release tables, every list with its source in
  `scripts/identities.json`.
- Safari on iOS: the iOS version in the string. Safari 18 writes it twice,
  `iPhone OS 18_1_1` and `Version/18.1.1`; Safari 26 froze the OS token at
  `18_7` — every 26.0 through 26.5 observed in real traffic says so — and
  writes the real version only in `Version/`. The three captured iOS profiles
  carry the versions of their own line under a template.
- Firefox on Linux: the `Ubuntu; ` token some builds carry.
- Not pooled, and why: `edge-153-windows`, because Edge writes its own build
  next to Chromium's in the list and neither is known without a real Edge;
  Safari on macOS, because the string says `10_15_7` on every Mac and Safari
  sends no hints; the transcribed desktops, because their hints were never
  measured and a pool on a claim is a claim squared.

`device="random"` draws one identity for the session, as on Android, and the
fingerprint names it; without `device=` the capture machine goes out. The TLS
never moves — that was the point of the project, and it still is.

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
| Safari's WebSocket handshake, and its fetch set is **derived** | the browser is not on the measuring machine — there is no Safari for Windows. The WebSocket handshake still gets the RFC minimum from the code. The fetch set, missing entirely until 2026-09-20, is now generated by `scripts/gen-safari-fetch.py` from the Fetch standard and each profile's own navigation set: the composition is sound, the **order is a guess**, and order is part of the fingerprint. Marked everywhere it is visible (`"derived": true`, `capabilities()["derived_fetch"]`, the audit's `derived_fetch_set`). Closed by one run of `cmd/hcapture` on a Mac or an iPhone |
| Safari's `http1.order` carries Chrome's `sec-ch-ua*` names | inherited from the imported signatures. Inert — Safari gives those names no values, so they never reach the wire — but wrong as data, and it means the Safari HTTP/1.1 order as a whole is unverified. Same capture closes it |
| ~~A cross-origin fetch sends no CORS preflight~~ ✅ closed 2026-09-21 | Stage 32: the OPTIONS goes with the family's measured order, is checked and cached, and a refusal stops the request; cookies follow `fetch()`'s credentials mode and SameSite. Measured on Chrome 153 and Firefox 156 (STAGE18) |
| Safari's cookie policy and preflight order are not measured | the browser is not on the measuring machine. Its cookie row is WebKit's documented ITP (no third-party cookies, no Lax-by-default, `None` without `Secure` accepted), its preflight order is derived from its own derived fetch set. Same Mac capture closes it along with the two Safari rows above |
| The scheme in the cookie site comparison is not measured | the stand is TLS only. Chromium's schemeful same-site (89+) is taken from its release notes, Firefox's `network.cookie.sameSite.schemeful` default (off) from its source. Closes with an `http://` listener on the stand |
| The HTTP/1.1 case of `Access-Control-Request-*` is assumed | the stand records HTTP/2; canonical case is what every browser is known to write, but it was not seen here. Closes with an http/1.1-only run of the origins page |
| Chromium's Lax+POST window is seen open at 15 s and shut at 140 s | two minutes is the value in the Chromium source; the stand did not bisect it. Closes with a second timed form post |
| ~~Chrome's `fetch.order`: `priority` is not measured~~ ✅ closed 2026-09-03 | a Chrome 152 measurement with the `cmd/hcapture` stand: `priority` is in the fetch set, its value is `u=1, i`, and it goes last. The position of `cookie` was confirmed at the same time — after `accept-language` — see STAGE16 |
| ~~CONNECT: `Proxy-Authorization` goes out immediately~~ ✅ closed 2026-09-03 | the first CONNECT goes out without credentials, the retry after a 407. The connection is reused if the proxy holds it, otherwise it is opened again — see STAGE16 |
| ~~A proxy that hangs up on CONNECT instead of answering 407~~ ✅ closed 2026-09-11 | found by a user against a commercial gateway: every request died with `unexpected EOF`, while `socks5h://` on the same port worked because SOCKS negotiates authentication up front. The browser sequence (no credentials until a 407) stays for a proxy that behaves; a hang-up before any byte, with credentials configured, is taken as the challenge the proxy failed to send and the CONNECT is repeated with them on a fresh socket. Either way the error names the situation and carries the code `proxy_closed`. Reproduced first: without the fix the new test dies with the user's exact message. **Corrected 2026-09-12:** the field proxy did not drop — a relay trace showed a complete 407 (`Content-Length: 24`, `Proxy-Authenticate: Basic realm=""`) followed by EOF with no `Connection: close`; the client trusted the missing header, retried into the dead socket and reported credentials "sent on the second attempt as well" while the proxy had seen one connection. A dead reused socket is now retried once on a fresh connection, and the message no longer claims an attempt that never reached the proxy |
| ~~permessage-deflate: a client window smaller than 32 KiB~~ ✅ closed 2026-09-03 | with a window smaller than the standard one the compressor is taken from `klauspost/compress`. Checked against a server of our own: RSV1 plus parsing the `zlib` stream with `wbits=-9` — such a stream cannot be read with a 32 KiB window |
| ~~Firefox's q ladder was inferred, not measured~~ ✅ closed 2026-09-08 | the audit read `0.8/0.5/0.3` as Firefox's signature and a 0.1 step as Chrome's. A live Firefox 155, asked with `intl.accept_languages` set explicitly, answered `ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7` for four languages and `ru-RU,ru;q=0.9` for two — a flat 0.1 step, the same as Chrome. The formula `1 - i/n` no longer holds, the shape no longer separates the two browsers, and the check was removed rather than narrowed: its other half ("a ladder holding 0.5 is Firefox's") misfires on a Chrome with six languages |
| The Firefox 133/135/144 ladders are still inferred | the corpus only ever carried two-item lists (`en-US,en;q=0.5`), which say nothing about a four-item shape, and the Russian values in those three profiles were written from the old formula. Firefox 155 is measured; when the change landed is not known, so replacing one guess with another buys nothing. Closes with a capture of an older Firefox |
| A profile without an `http1` section — not a debt but a property | all 48 browser profiles have the section (their own or through `based_on`). The code's approximation stays for the profiles registered at runtime out of three fields: there is nowhere for an order to come from there |
| ~~The HTTP/1.1 set was assumed equal to the HTTP/2 one~~ ✅ closed 2026-09-03 | measured: Chrome does not send `priority` on HTTP/1.1, Firefox does not send `TE`. When `http1.order` is given it sets the set as well, not just the order |
| ~~"A new Python with an old DLL" silently ignores options~~ ✅ closed 2026-09-02 | `curlpro_version` = `0.2.0`, and `_ffi.py` checks `REQUIRED_VERSION` at load. The problem is not theoretical: an hour of runs of the wrong code was lost to it — see STAGE13 |
| ~~QPACK: we announce a table capacity we do not support~~ ✅ closed 2026-09-03 | a decoder of our own, `internal/qpack`, with a dynamic table and blocked streams, checked against the appendix B examples of RFC 9204. `fp.impersonate.pro` now answers 5 times out of 5, where it was 1 out of 5 |
| ~~HTTP/2 receive window runs away under a large `INITIAL_WINDOW_SIZE`~~ ✅ closed 2026-09-11 | found by the okhttp profile (16 MiB window): a 45 MB body died with `FLOW_CONTROL_ERROR` where the real okhttp took 1.9 s. fhttp's `flow.available()` returns the smaller of the stream and connection windows while `add()` raises the stream only, so once the connection is the minimum every read re-credits the same bytes — 1250 WINDOW_UPDATEs, 3.2 GB of credit after 5 MB, RST at 2^31−1. Chrome profiles survived by arithmetic (6 MiB < half the connection window) and a control run shows them crediting 1.8 GB for a 24 MiB body — every profile was exposed. Four edits carried on the vendored fhttp, re-applied by `scripts/patch-fhttp.py`, guarded by `TestH2ReceiveWindowCreditIsNotRunaway`; upstream v0.6.9 does not fix it. Details in [docs/FHTTP-PATCH.md](docs/FHTTP-PATCH.md) |
| okhttp over HTTP/1.1 is not measured | the profiles carry the HTTP/2 header set; okhttp on a server that offers only http/1.1 sends its own order and `Connection: Keep-Alive`, which the code approximates. Closes with one run of the probe against a stand offering `http/1.1` only |
| okhttp on a real Android device is not verified | Conscrypt on the JVM is the library Android ships, but the version differs and the platform may configure it. Closes with a capture from a device or an emulator |
| ~~A race in `fhttp` when closing HTTP/2 under load~~ ✅ closed 2026-09-11 | fixed on the vendored copy, edit (f) in [docs/FHTTP-PATCH.md](docs/FHTTP-PATCH.md): `handleResponse` replaced the response pipe wholesale — mutex and all — while `closeForError` was closing it; the buffer now goes in through `pipe.setBuffer`, ported from x/net, which refuses a pipe already closed. Proven under `-race` both ways: stashed, the test reports a DATA RACE on the first run; applied, 10 of 10 pass. The subtest that was skipped for this now runs in CI as the guard. The original entry, kept for the record: found on 2026-09-05 by the test `TestConcurrentCloseDuringRequests` under `-race`: `handleResponse` assigns `cs.bufPipe = pipe{…}` without the connection mutex (`fhttp@v0.6.8/http2/transport.go:2361`) while `closeForError` closes that same pipe under it (`:1096` → `http2/pipe.go:105`). Closing the session while an HTTP/2 response is arriving writes the struct from two goroutines; a lost close means a reader that will only be released by the request timeout. There is nothing on our side to synchronise it with — either patch the dependency or wait for the requests in flight on `Close`, which changes what "close now" means. The subtest is skipped under the detector and the behaviour without it was checked over five runs |
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
