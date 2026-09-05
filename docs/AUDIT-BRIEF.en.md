# curlPro — a brief for an external audit

A full translation of [AUDIT-BRIEF.md](AUDIT-BRIEF.md). The Russian file is the
original; a test checks that the two keep the same structure, so a section added
to one and forgotten in the other fails the build rather than drifting quietly.

The document stands on its own: having read it, you can work with the repository
without the rest of the documentation. It describes the **current state** rather
than the intent — `ARCHITECTURE.md` was written at the start and is stale in
places.

An auditor needs sections 1–3 (what this is and how it is built), 4 (invariants —
what looks like a bug but is deliberate), 5 (how to check a finding) and
[AUDIT-QUESTIONS.md](AUDIT-QUESTIONS.md) — known debts and open questions.

---

## 1. What this is

A Python library for HTTP requests that are indistinguishable at the network
level from those of a real browser. An analogue of `curl_cffi` /
`impersonate.pro`, but with one hard requirement that shapes the whole
architecture:

> **A new Chrome or Firefox is added by editing data (a JSON profile), without
> rebuilding native code.**

`curl-impersonate` does not work that way: its profiles are ~2367 lines of C
structures in `lib/impersonate.c`, and a new browser means rebuilding BoringSSL.
A runtime path does exist there, but it is fed by the paid
`api.impersonate.pro` — that is, precisely the part we want to control is
monetised. The analysis is in [RESEARCH.md](RESEARCH.md).

Hence the stack: **Go + uTLS**, because only uTLS gives both of the things
needed — `ClientHelloSpec.UnmarshalJSON` (a profile as JSON) and
`Fingerprinter.RawClientHello` (captured bytes → a profile). The Rust analogues
(`wreq`, `rquest`) reach the same fingerprint quality, but their profiles are
code.

### What is impersonated

| Layer | What exactly |
|---|---|
| TLS | ciphers, extensions **and their order**, curves, sigalgs, ALPN, ALPS, cert_compression, key_share, GREASE, ECH, permute_extensions |
| HTTP/2 | SETTINGS **and order**, WINDOW_UPDATE, PRIORITY frames, pseudo-header order, stream_weight/exclusive |
| HTTP/3 | QUIC transport parameters and their order, SETTINGS, GREASE frames, PRIORITY_UPDATE, QPACK parameters |
| HTTP/1.1 | header order **and the case of the names** |
| Headers | the set, the order, the case, the positions of cookie and of user names |

Checkable metrics: JA3, JA3N, JA4, the Akamai HTTP/2 fingerprint, `perk` for
HTTP/3.

---

## 2. The stack and its boundaries

```
Python (ctypes)  →  dist/curlpro.dll   →  Go
                    (c-shared)             ├── refraction-networking/utls   ClientHello
                    │                      ├── bogdanfinn/fhttp             HTTP/1.1 + HTTP/2
                    │                      ├── refraction-networking/uquic  QUIC
                    │                      └── internal/h3 (vendored)       HTTP/3
                    └── binary frame: [uint32 LE len][JSON][body]
```

Go 1.27, cgo (MinGW-w64 on Windows, kept in `D:\mingw64`). The dependencies are
in `go.mod`; `uquic` and `utls` are pinned to master revisions rather than to
tags.

This is regularly read as "the build will break on its own": it will not. A
pseudo-version (`v1.8.3-0.20260802151714-23b1dac19c06`) is an exact commit, and
`go.sum` holds its hash; upstream may move master as much as it likes. The real
risk is a different and narrower one: a force-push or the disappearance of the
repository makes the build unreproducible, and the cure for that is vendoring
(`go mod vendor`) or a fork of our own — not a move to tags, since the tags do
not yet carry the features we need.

### What still requires Go changes

Not every browser is data-only. Code is needed for a new type of TLS extension
(a `TLSExtension` with `UnmarshalJSON`) and for the things upstream uTLS cannot
load from JSON — ECH and QUIC transport parameters, which have post-processors
(`internal/profile/spec.go`, `quic.go`). The frequency is once every 6–12 months.

---

## 3. A map of the repository

### The Go core

The line counts were re-measured on 2026-09-05; the previous ones lagged by
roughly a factor of two.

| Path | Lines | Role |
|---|---|---|
| `internal/profile/profile.go` | 758 | profile types, the registry, `based_on` inheritance, delta merging |
| `internal/profile/build.go` | 256 | building a `ClientHelloSpec` from JSON, 22 extension types |
| `internal/profile/spec.go` | 222 | the ECH post-processor — uTLS does not load it from JSON |
| `internal/profile/quic.go` | 165 | QUIC transport parameters |
| `internal/client/client.go` | 922 | the session, `Do`, the transport dispatcher |
| `internal/client/headers.go` | 477 | **header assembly: order, case, slots, the anchor** |
| `internal/client/websocket.go` | 780 | WebSocket over the same TLS |
| `internal/client/stream.go` | 328 | streaming body reads, the retry loop |
| `internal/client/pool.go` | 299 | the connection pool, eviction, busyness |
| `internal/client/http3.go` | 338 | the HTTP/3 path, the bridge between `net/http` and `fhttp` |
| `internal/client/proxy.go` | 252 | CONNECT, TLS to the proxy |
| `internal/client/conn.go` | 250 | the connection, the HTTP/1.1 round trip |
| `internal/client/retry.go` | 238 | the retry policy |
| `internal/client/redirect.go` | 235 | redirects, changing `sec-fetch-*` |
| `internal/client/decompress.go` | 139 | decompression on the HTTP/3 path |
| `internal/client/multipart.go` | 120 | form boundaries in the WebKit/Firefox style |
| `internal/client/body.go`, `bridge.go`, `sessionheaders.go` | 43/52/122 | the request body, the type bridge, session headers |
| `internal/qpack/` | 1105 | **our own** QPACK decoder (RFC 9204) with a dynamic table |
| `internal/h3/` | 4074 | the **vendored** `uquic/http3` — 19 files, see below |

`internal/qpack` exists because `quic-go/qpack` knows only the static table
while the profile advertises a capacity of 65536, as Chrome does: the server is
entitled to encode against the table, and without our own decoder the response
could not be parsed.

### The FFI and Python

`lib/` (611+275+240+240+76 lines) exports 33 functions. Profiles:
`curlpro_profiles_load_dir`, `curlpro_profile_register`, `curlpro_profiles_list`.
The session: `curlpro_session_new/close`, `curlpro_request`, session headers
(`set_header`, `remove_header`, `reset_headers`, `headers`), cookies
(`session_cookies`, `session_set_cookies`, `session_clear_cookies`). Streams:
`curlpro_stream_open/read/close`. WebSocket: `curlpro_ws_connect/send/recv/close`
and their asynchronous twins. The async layer: `curlpro_*_start`,
`curlpro_result_wait/take`, `curlpro_request_cancel`, `curlpro_async_pending`.
Housekeeping: `curlpro_version`, `curlpro_free`, `curlpro_debug_counts` (the
size of every registry — for hunting leaked handles).

`python/curlpro/`: `_ffi.py` (ctypes, frames, the version check), `session.py`
(`Session`, `Response`, the module-level `get/post/...`), `aio.py`
(`AsyncSession`), `stream.py`, `websocket.py`, `cookies.py` (the jar, snapshots,
the Netscape format), `expect.py` (expectations about a response), `headers.py`
(`SessionHeaders` as a `MutableMapping`), `timeouts.py`, `encoding.py`,
`proxies.py`, `profiles.py`, `_completions.py` (the receiver of async results).

### Data and tools

- `profiles/` — 47 profiles: Chrome 98–152, Edge, Firefox, Safari, Tor, Yandex
  Browser. The mobile ones were captured from a live Pixel 7 over USB:
  `chrome-152-android`, `yandex-26.8-android`. Some are collapsed into deltas
  through `based_on`.
- `corpus/` — 43 original `curl-impersonate` signatures (YAML).
- `reference/` — captured references and validation baselines.
- `cmd/probe` — checks JA4 against a reference; `cmd/h3probe` — the same for
  HTTP/3; `cmd/import` — YAML signatures → profiles; `cmd/curlpro` — `capture`,
  `validate`, `diff`, `list`, `collapse`.
- Stands for measuring a live browser: `cmd/hcapture` — header order over
  HTTP/2 and HTTP/3 (HEADERS is parsed by hand, and for HTTP/3 with our own
  QPACK); `cmd/quiccapture` — decrypting the QUIC Initial and the transport
  parameters.

### Documentation

`docs/STAGE0..STAGE13-RESULTS.md` — a chronology by stage: what was done, which
bugs were found and why particular decisions were taken. It is the best source
of "why is it like this", but reading all of it is not required.
`docs/FINGERPRINT-SPEC.md` — the exact JA3/JA4/Akamai formats and the
discrepancies between the checking services. `docs/PROFILE-SCHEMA.md` — the
profile schema. `docs/HTTP3-RESEARCH.md` — an analysis of the HTTP/3 oracles.

---

## 4. Invariants: what looks like a bug but is deliberate

The likeliest audit mistake is to "fix" one of these. Every item has been
checked and has a reason.

### 4.1 The fingerprint has to vary

- **Chrome ≥110 shuffles its extensions.** Five captures give 5 different JA3s
  and one JA4. The spec is rebuilt **for every connection**; caching it would
  freeze the order, and that in itself is an anomaly.
- **JA4 legitimately floats for two profiles.** `chrome-119-linux` and
  `edge-120-linux` give now 16, now 17 extensions: the GREASE ECH in uTLS picks
  its payload length at random from `{128,160,192,224}`, the ClientHello length
  jumps, and `padding` is sometimes added and sometimes not. BoringSSL behaves
  the same way. That is why the baseline stores a **set** of JA4 values rather
  than one.
- A deterministic retry schedule without jitter is a tell as well; see the debts.

### 4.2 Headers

- **Writing `req.Header[key] = ...` directly instead of `Header.Set`.** `Set`
  canonicalises the name and would erase the case the profile prescribes. In
  HTTP/1.1 the case is arbitrary, and browsers make use of that.
- **The order is passed as what is wanted, not as a list of what exists.** It
  makes sense to hold a place in it for `Content-Length`, which the transport
  adds after assembly. A name with no header behind it is simply skipped by the
  sorter (`wireOrder` in `headers.go`).
- **An empty value in a profile is a slot, not an empty header.** For
  `user-agent` it means "substitute from `headers.user_agent`", for `cookie` —
  "substitute from the jar, and if the jar is empty do not send it at all".
  Without the slot, cookie would be appended at the end, and the fingerprint
  would break from merely enabling the jar.
- **User headers go before the `custom_anchor`, not at the end.** The browser
  appends its housekeeping tail (`accept-encoding`, `cookie`, `priority`) last,
  so a foreign name after it stands out.
- **A custom header switches the set to `fetch`.** In a browser it only ever
  occurs on fetch/XHR, and those have an entirely different set. The profile
  describes both; the choice is automatic, and `mode="navigate"` pins it
  (STAGE15).
- **The HTTP/1.1 set is given by `http1.order` in full, not just its order.**
  Chrome does not send `priority` over HTTP/1.1, Firefox does not send `TE`,
  although both are present in HTTP/2.
- **Overriding a profile header changes the value in place.** Moving it to the
  end would break the fingerprint's order.

### 4.3 HTTP semantics

- **Having exhausted its retries, the client returns the last response rather
  than an error.** The server's answer is a result, not a client failure; curl
  and urllib3 behave the same way.
- **POST is not retried by default.** The server may have processed the request
  and failed to answer in time — a retry would create a second order. It is
  enabled explicitly through `retry_methods`.
- **The timeout is one deadline for the whole redirect chain,** not one per
  step: otherwise twenty redirects would stretch into twenty timeouts.
- **303 drops the body and changes the method to GET; 307 keeps both.** That is
  the RFC, not an omission.
- **On a redirect, `sec-fetch-site: none` and `sec-fetch-user` do not change.**
  Measured against Chromium 148: a navigation the browser began has no
  initiator, and both headers are the same on every hop, including a change of
  host. An explicitly given value is computed from the initiator of the chain
  and can only get worse.

### 4.4 Everything else

- **`internal/h3` is a deliberate vendoring,** not lazy copy-paste. `fhttp` is
  built on `bogdanfinn/utls` while `uquic` is built on
  `refraction-networking/utls`; their types are incompatible and would not build
  together. The changes against upstream are listed in `internal/h3/README.md` —
  mostly pseudo-header order and the housekeeping order keys.
- **HTTP/3 with a proxy is rejected when the session is created.** The proxy
  used to be ignored silently — that is, the real IP leaked.
- **The order inside `version_information` is drawn per connection.** A capture
  of Chrome 152 showed both variants: a constant order would be a tell
  (STAGE15). It is pinned by the field `quic.grease_version_first`.
- **Double decompression is a real trap.** Over HTTP/2 the `fhttp` transport
  decompresses (gzip/deflate/br/zstd), leaving `Content-Encoding` in place. Over
  HTTP/1.1 and HTTP/3 the decompression is ours (`decompress.go`): the first
  goes past `fhttp.Transport`, where `DecompressBody` lives, and the second is
  built on `net/http`, which decompresses only gzip and only when it set the
  header itself. Until stage 14 the HTTP/1.1 path did not decompress at all.
- **The fetch cluster is reproducible only with a single custom header.**
  Chromium lays out client hints and user headers in an order that depends on
  the **set of names**: with one custom header the profile's order comes out,
  with five a different one does (`x-b-two x-c-three sec-ch-ua-platform x-e-five
  x-d-four sec-ch-ua …`). Three runs with a clean profile gave the same result,
  so this is not randomness but a deterministic function of the names,
  resembling a hash-table walk. Reproducing it would mean reproducing Chromium's
  hash; the profile places all of its own headers at the `custom_anchor`
  position.
- **`verify` takes three kinds of value.** `True` — the system roots; a string —
  the path to your own root (and only to it: the point of the option is to trust
  exactly what was named); `False` — do not verify at all.
- **A proxy from the environment is a default, not an order.** `trust_env` is on,
  but an explicitly given `proxy` always wins, and an empty string in a request
  means "go direct" even with `HTTPS_PROXY` set.
- **Cookies are accounted for twice, and that is deliberate.** The `fhttp` jar
  is responsible for sending them (its domain and path matching is written and
  tested), while our own accounting in `internal/client/cookies.go` is
  responsible for exporting: outwards the jar only hands out the name-value pair
  for an address, which is not enough to save a session.
- **`Response.json()` ignores the declared encoding.** A JSON body is UTF-8 per
  RFC 8259, and sites write anything at all in the header. `.text`, on the
  contrary, respects the encoding: the header, the BOM, `<meta charset>`.
- **GREASE in `signature_algorithms` is drawn per connection.** Chrome 152 sends
  it first in the list, and the value changes between runs: a phone capture
  recorded `0xAAAA`, and the same browser later sent `0xEAEA`. A constant value
  would be a tell, so the profile stores the marker `2570` and `toSigSchemes`
  substitutes a random one. A side effect: the fingerproxy stand includes GREASE
  in the JA4 hash, so the local fingerprint of these profiles oscillates across
  sixteen values — in the local reference they carry `"ja4": ["*"]`. A public
  oracle computes by the specification, ignores GREASE, and there the comparison
  is ordinary.
- **`keep_alive=False` does not send `Connection: close`.** The connection is
  simply closed after the response. The header would send a sign a browser does
  not have: Chrome closes an idle connection silently (STAGE16).
- **The first CONNECT goes without `Proxy-Authorization`.** The credentials are
  added only after a 407 — that is what Chrome does. The extra round trip to the
  proxy is paid deliberately: it is the proxy that classifies clients (STAGE16).
- **`cookies=False` on a request isolates it in both directions.** Cookies do
  not go out and `Set-Cookie` from the response is not remembered. One-way
  isolation would be a surprise: "do not use the memory" reads as "do not touch
  it at all".
- **`cookies=True` on a session without a jar is an error, not a no-op.** You
  cannot enable what does not exist, and ignoring it silently would hide a typo
  in the session's configuration.
- **Expectations are checked after the response interceptors.** An interceptor
  may replace the response, and it is the replacement that goes out — so it is
  the replacement that must be checked.
- **Cancellation and Ctrl+C bypass the error interceptors.** A hook returning
  its own exception in place of `CancelledError` would swallow the cancellation
  and the task would never stop. The cookie rollback still happens: the request
  did not complete.
- **`protocol=h2` does not trim ALPN to a single value.** No browser sends a
  list consisting of h2 alone, and the fingerprint forgery would end right
  there. So h2 means "do not go to QUIC and do not agree to HTTP/1.1": with
  http/1.1 negotiated the request fails with an error.
- **A named protocol beats Alt-Svc and the session options.** Measured against
  cloudflare-quic.com: the session had already moved to h3, and a request with
  `protocol="h2"` still went over TCP. The reverse holds too — `protocol="http1"`
  in a session with `http3=True` gives HTTP/1.1.
- **A protocol-mismatch error is not retried.** On a second attempt the server
  negotiates exactly the same thing, and with `retries=3` that is three extra
  handshakes: such errors are marked `fatalError` and go past the retry policy.
- **The second element of `timeout` is a limit on the whole request, not on
  silence.** In requests the pair `(connect, read)` means "this much silence
  between bytes"; ours is `(connect, total)`. That is stricter rather than
  looser, so the familiar value is safe to pass; it is named directly in the
  documentation so that nobody counts on the opposite (STAGE17).
- **The connect limit covers the TLS handshake too.** A host that accepts the
  connection and then goes quiet would otherwise eat the whole request budget:
  the TCP part did get established. The first implementation limited only
  `dialRaw`, and a test with a silent server caught it on exactly that (STAGE17).
- **Cancelling an asynchronous read loses what was read.** Reading a chunk of
  the body and receiving a message have no context: the bytes are already off
  the wire and there is nothing to put them back into. So cancellation there
  removes only the waiting, and the stream or socket is closed afterwards rather
  than read further (STAGE17).
- **A result can outrun the party waiting for it.** The work is started and
  registered in two steps, and reading a chunk of the body manages to finish
  between them. The receiver parks such a result in `_ready` and takes it from
  the native side **under the same lock** as the lookup of the waiter:
  otherwise `register` wedges itself between the check and the parking
  (STAGE17).
- **`#HttpOnly_` in `cookies.txt` is not a comment.** The Netscape format knows
  no HttpOnly flag, and curl marks such lines with a prefix that looks like a
  comment. Skipping them along with the real comments loses exactly the cookies
  the file is carried for.
- **Cookies are written to the file with a leading dot and `TRUE`.** Measured: a
  cookie saved with the domain `example.test` also goes to `sub.example.test` —
  that is, it behaves as a domain cookie. The dot and the flag in the file mean
  exactly that; on load the core strips the dot, and the circle closes without
  losses.
- **`max_response_size` bounds `read()` but not `iter_content()`.** The limit
  protects the process memory, and reading in chunks is precisely how a body
  larger than memory is handled: limiting it would take away the way out along
  with the danger. `read()` collects the body whole and is therefore bounded on
  both paths — the ordinary one and the streaming one — with a single error code
  `too_large` (STAGE17). Before this fix the streaming path was not bounded at
  all: a measurement returned 100002 bytes under a limit of 1000.
- **A WebSocket outlives the closing of its session.** The socket is not in the
  pool: it becomes the property of the connection and lives until its own
  `close()`. Measured: after `session.close()` the same socket still sends and
  receives a message. Cutting it off with the session would break a connection
  that is held deliberately and for longer than the session.
- **An exception from an `on_error` hook does not replace the request error.**
  Replacing is what *returning* an exception from the hook is for; a hook that
  fails used to replace it by accident, and a typo in someone's logging arrived
  instead of the network error. Now the original goes out and the hook's failure
  is attached as a PEP 678 note (from Python 3.11) or goes to stderr. The
  remaining hooks still run: one broken hook disables itself, not its neighbours.
- **Touching the jar of a closed session is an error, not an empty jar.** The
  jar has no handle of its own, it reads the session; an empty list would mean
  "there are no cookies", when in fact they were not taken out in time. The
  message names the way out: `cookies.export()` before `close()`.
- **The code and the error messages are in English, the documentation is in
  Russian.** That was decided deliberately: the library is open and its code is
  read by people who do not read Russian, while the project documentation is
  kept in the language the project is discussed in. README and this brief have
  full English twins whose structure is checked by a test. The errors name not
  only the cause but the consequence: "timeout must be positive, got 0s (leave
  it unset for no limit)".
- **The repository is public:** github.com/int3re/curlpro, licensed Apache 2.0.
  Until September 2026 it was local on purpose, and older notes still mention
  that restriction — it has been lifted.

---

## 5. How to check a finding

Bare reasoning is unreliable here: a fingerprint is checked only by measurement.

### Building

```powershell
.\build.ps1          # writes dist/curlpro.dll — the ONLY path Python loads
```

⚠ Building by hand into another location is pointless: `_ffi.py` looks for
`curlpro.dll` in `python/curlpro/lib/` and in `dist/`. Time has already been lost
to this — runs were going against a DLL half an hour old. There is a version
check now (`REQUIRED_VERSION`), but you still have to rebuild through
`build.ps1`.

### Tests

```powershell
go test ./internal/...                    # unit tests, no network needed
$env:CGO_ENABLED=1; $env:CC="D:\mingw64\bin\gcc.exe"; $env:PATH="D:\mingw64\bin;$env:PATH"
go test -race ./internal/...              # -race needs cgo and gcc on PATH
cd python; $env:PYTHONPATH="."; python -m pytest tests -m "not network"   # 240 tests
cd python; $env:PYTHONPATH="."; python -m pytest tests -m network         # 49, they go out
```

The network tests carry the `network` marker and are kept apart: 49 out of 289
go to `httpbin.org`, `quic.browserleaks.com` and `cloudflare-quic.com`, and an
outage of someone else's service looked exactly like a bug in the library.
Without a network they **skip** rather than fail.

Our own stands live in `python/tests/`: `rawserver.py` (raw headers — public
oracles normalise the names; `persistent=True` holds the connection and counts
the accepted ones, which is how keep-alive is checked), `flakyserver.py`
(failure scenarios for retries), `proxyserver.py`, and a permessage-deflate
server inside `test_websocket_deflate.py`.

### The fingerprint stand

```bash
tools/echo-server_windows_amd64.exe -listen-addr localhost:8443 \
  -cert-filename capture/certs/tls.crt -certkey-filename capture/certs/tls.key
```

This is `echo-server` from `wi1dcard/fingerproxy`. The `/json/detail` endpoint
returns the raw ClientHello in base64, the parsed JA3/JA4 and the structure of
the HTTP/2 frames.

### Comparing fingerprints

```powershell
go run ./cmd/probe -n 2            # JA4 against the reference
go run ./cmd/h3probe               # the HTTP/3 fingerprint
go run ./cmd/curlpro validate -oracle https://localhost:8443/json -insecure `
    -baselines reference/baselines-local -pause 0      # all 47 profiles
```

The header order of a live browser is captured by the `cmd/hcapture` stand
(`-auto` starts Chrome itself, `-h3` moves it to QUIC) — that is the only way to
see the order in HTTP/3.

Current state (measured 2026-09-05): `go test -race ./internal/...` — ok on all
four packages, pytest without the network — 230 passed and 10 skipped,
`validate` — 47/47 including a check that the extension order stays stable,
`probe` and `h3probe` — a match with the reference, and the header order matched
live Chrome 152 over HTTP/2 and HTTP/3. The audit results are in
[STAGE14-RESULTS.md](STAGE14-RESULTS.md); the closing of the roadmap debts is in
[STAGE15-RESULTS.md](STAGE15-RESULTS.md) and
[STAGE16-RESULTS.md](STAGE16-RESULTS.md).

### What the checking does not cover

- Public oracles do not show the order of ordinary headers in **HTTP/3**: they
  return `perk` (SETTINGS, pseudo-headers, transport parameters). Since
  2026-09-05 our own client's order is checked by a stand of ours on `uquic`
  (`internal/client/h3stand_test.go`, four tests in `h3order_test.go`) — by the
  same HEADERS parsing through `internal/qpack` that `cmd/hcapture` uses on a
  live browser. What stays manual is the comparison against a **live browser**
  over HTTP/3: that captures a reference rather than checking us. For HTTP/1.1
  and HTTP/2 the wire order is checked continuously (`test_http1.py`,
  `test_h2_headers.py`).
- Concurrency has been covered since 2026-09-05:
  `internal/client/concurrency_test.go`, eight tests under `-race` — parallel
  requests, streams interleaved with requests, closing a session under load, the
  pool limit, `orphans`, the cookie jar, a race between two closes,
  cancellations. The detector caught nothing in our own code; it did find a race
  in `fhttp` on closing HTTP/2 — see the debts.
- Behaviour against real anti-bot systems. What is checked is a match with the
  reference, not "getting through".

---

## 6. Known discrepancies between the oracles

These are not bugs but disagreements between the services themselves; knowing
them saves chasing a ghost:

- `fingerproxy` counts priority from the HEADERS frame in the PRIORITY section
  of the Akamai fingerprint, `browserleaks` does not. Resolved by the
  frame-by-frame breakdown at `fp.impersonate.pro/api/http2`.
- `scrapfly` uses `supported_versions` instead of the legacy version in JA3 and
  sorts sigalgs against the specification. `browserleaks` is taken as the
  reference.
- `PRIORITY weight = wire_value + 1` (RFC 7540) is the commonest mistake in
  other implementations.
- Connecting by a bare IP changes JA4 (`d`→`i` and the extension count). Use
  `localhost` or `--host-resolver-rules`.
