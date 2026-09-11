# curlPro — tasks for an audit

A companion to [AUDIT-BRIEF.md](AUDIT-BRIEF.md): that one holds the design and
the invariants, this one what to check and where help is wanted.

> The audit was carried out on 2026-09-02; its findings and the fixes are in
> [STAGE14-RESULTS.md](STAGE14-RESULTS.md). Questions 2.1–2.6 below are kept as
> they were posed; the answers are there and in the debt table in ROADMAP.
>
> Refreshed on 2026-09-05 after a bug and leak hunt: 2.2 and 2.3 are closed, and
> the debt rows were checked against the code by measurement. What exactly was
> measured is stated in each row.

## How to work with this project

1. **Check by measurement, not by reasoning.** The claim "this header order is
   wrong", without a run against a stand, is a hypothesis. The commands are in
   section 5 of the brief.
2. **Consult section 4 of the brief** before calling anything a bug: it lists
   what looks like a mistake but is deliberate and checked.
3. **The repository is public:** github.com/int3re/curlpro, licensed Apache 2.0.
   Older notes still mention a "the repository is local" restriction — it has
   been lifted.
4. **The language of the code and of the documentation is English.** Comments,
   docstrings, error messages and tool output are English; since 2026-09-08 the
   documentation is too. README and the audit brief have Russian twins —
   README.ru.md and docs/AUDIT-BRIEF.ru.md — and their structures are kept in
   step by `python/tests/test_docs_parity.py`. The stage chronicle
   (`docs/STAGE*-RESULTS.md`, `docs/PLAN-*.md`) stays in Russian: it is a log of
   what happened when, not documentation to read front to back.

   Comments explain "why" rather than "what": if a change overturns someone's
   decision, it is worth saying where the earlier reasoning was wrong.
5. Read `docs/STAGE*-RESULTS.md` selectively — it is the chronology, the best
   source of "why is it like this", but reading all of it is not needed.

---

## Part 1. Known debts

Already found and understood — no need to spend an audit on them, though help
with solving them is welcome. The full list is in the table at the end of
[ROADMAP.md](../ROADMAP.md).

| Debt | What it is | Where |
|---|---|---|
| ~~**A race in `fhttp` when HTTP/2 is closed**~~ closed 2026-09-11 — edit (f) in [FHTTP-PATCH.md](FHTTP-PATCH.md), proven both ways under `-race`; the once-skipped subtest is now the guard | `handleResponse` assigns `cs.bufPipe = pipe{…}` without the connection mutex while `closeForError` closes that same pipe holding it. Closing a session while a response is arriving writes the struct from two goroutines: a lost close means a reader that waits for the request timeout. Found by `TestConcurrentCloseDuringRequests` under `-race`; our side cannot synchronise it, so the subtest is skipped under the detector | `fhttp@v0.6.8/http2/transport.go:2361` and `:1096` |
| HTTP/2 receive-window runaway in `fhttp` under a 16 MiB `INITIAL_WINDOW_SIZE` | closed 2026-09-11 by a patch carried on the vendored copy — [FHTTP-PATCH.md](FHTTP-PATCH.md). The second fhttp defect found by measurement; the race above was the first, and is closed as well |
| ~~HTTP/2: `GOAWAY`~~ ✅ 2026-09-03 | "processed" and "not processed" are separated explicitly: `h2Unprocessed` retries only the certainly-unprocessed — no connection, a GOAWAY with a lower last-stream-id, `REFUSED_STREAM`. The ambiguous case never reaches the retry policy | `internal/client/retry.go:h2Unprocessed` |
| `Content-Length` position — Safari remains | the slot is in place and works on both transports: a measurement on 2026-09-05 found `content-length` in the `headers.order` of **36 profiles** out of 47 and in `http1.order` of 18 (Chrome/Edge since STAGE14, Firefox/Tor since STAGE15). Safari has no measurement: the browser is not on the capture machine | `profiles/*.json` |
| `accept-language` for Firefox and Safari not measured | on 2026-09-08 the language tags in every profile except Tor were switched to Russian. The Chrome/Edge/Yandex value is a captured one: `ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7` stood in chrome-151/152 from a live capture. The Firefox (`0.8/0.5/0.3`) and Safari (a short list) shapes are derived from the known q ladder but not confirmed by a capture on a Russian locale | `profiles/firefox-*.json`, `profiles/safari-*.json` |
| `custom_anchor` not confirmed everywhere | the plan's default is gone: a measurement on 2026-09-05 gives 29 × `accept`, 15 × `sec-ch-ua-mobile`, 11 × `accept-encoding` and two composite lists. Chrome/Edge moved to `accept` on the Chromium 148 measurement; Firefox and Safari remain a guess | `profiles/*.json` |
| ~~QPACK: the dynamic table~~ ✅ | closed by an RFC 9204 decoder of our own with a dynamic table: `quic-go/qpack` knows only the static one, while the profile advertises a capacity of 65536 as Chrome does | `internal/qpack/decoder.go` |
| ~~Three corpus files disagreed~~ ✅ 2026-09-03 | two of the three turned out to be broken profiles: `pre_shared_key` instead of `padding` | `docs/STAGE16-RESULTS.md` |
| `version_information`: the GREASE order | uTLS documents "Chrome puts GREASE first", curl-impersonate writes `1,GREASE`. The latter may be an artefact of normalisation during serialisation | `internal/profile/quic.go` |
| The `QUICChrome_146` parrot | derived in uquic from **one** pcap sample; the experience of stage 0 showed that is not enough | a dependency |

---

## Part 2. Where help is wanted

Tasks with no solution of our own yet. Ordered by value.

### 2.1 Header order in HTTP/3 ✅ closed 2026-09-05

HPACK/QPACK sits between the header assembly and the wire, and it is the wire
that has to be observed. The state per transport:

| Transport | What checks it |
|---|---|
| HTTP/1.1 | our own stand `python/tests/rawserver.py` — public oracles normalise the names, so one had to be raised here |
| HTTP/2 | `echo-server` returns the HEADERS frame in wire order (`/json/detail` → `detail.metadata.HTTP2Frames.Headers`); used by `python/tests/test_h2_headers.py` |
| HTTP/3 | our own stand `internal/client/h3stand_test.go` — QUIC on `uquic`, HEADERS parsed by our own `internal/qpack` |

The HTTP/2 gap was closed while this document was being prepared: the stand could
return the order and we were not using it. That is exactly how a real bug lived
unnoticed — the custom-header anchor worked **over HTTP/1.1 only**, because every
Python header test runs with `force_http1=True` (see
`docs/STAGE13-RESULTS.md`).

**HTTP/3 was closed the way the question proposed** — with a server of our own on
`uquic` rather than by parsing pcap. The HEADERS parsing goes through the same
`internal/qpack` that `cmd/hcapture` uses on a live browser, so the test checks
exactly what a capture would show. Four tests in
`internal/client/h3order_test.go`: the stand sees the request, the wire order
matches the profile, a custom header goes before the housekeeping tail, and
overriding a profile header does not move the name.

Measured, the order on the wire (Chrome 151, HTTP/3):

```
sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests
user-agent accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest
accept-encoding accept-language priority
```

With one custom header the switch to the fetch set is visible too:

```
sec-ch-ua-platform user-agent sec-ch-ua x-custom-token sec-ch-ua-mobile accept
sec-fetch-site sec-fetch-mode sec-fetch-dest accept-encoding accept-language priority
```

What stays manual: the comparison against a **live browser** over HTTP/3 — that
captures a reference rather than checking us, and is done through
`cmd/hcapture -auto -h3`.

### 2.2 Concurrency ✅ closed 2026-09-05

Before: coverage through Python only, where the race detector does not run at
all — although the pool had already hidden something non-trivial: over HTTP/1.1 a
parallel request corrupted an open stream, because the mutex was released before
the body was read (`docs/STAGE12-RESULTS.md`).

Now: `internal/client/concurrency_test.go` — eight tests under `-race`.

| Test | What it holds |
|---|---|
| `TestConcurrentRequestsOneSession` | 12 goroutines × 15 requests, HTTP/1.1 and HTTP/2: every response answers its own request |
| `TestConcurrentStreamsAndRequests` | 8 open streams and 80 ordinary requests interleaved — the STAGE12 scenario itself |
| `TestConcurrentCloseDuringRequests` | closing a session under load: no hangs, the error code after the close is `session_closed`, a second `Close` does not panic |
| `TestConcurrentPoolStaysWithinLimit` | 20 simultaneous requests keep exactly 6 connections in the pool — `maxConnsPerHost` |
| `TestConcurrentOrphanIsUnregistered` | a softly evicted HTTP/2 connection finishes its streams and leaves `s.orphans` |
| `TestConcurrentCookieWrites` | 80 parallel writes to the jar interleaved with reads — all 80 are there |
| `TestConcurrentStreamCloseRacesSessionClose` | closing a stream and closing a session at once, five attempts |
| `TestConcurrentContextCancelDuringRequest` | ten cancelled requests leave no connection acquired |

**What it found:** a race in a dependency — it is in the debt table above. The
detector caught nothing in our own code across all eight.

The command: `CGO_ENABLED=1 CC=D:/mingw64/bin/gcc.exe go test -race ./internal/...`
(on Windows the detector needs gcc from MinGW).

### 2.3 Leaks on the FFI boundary ✅ closed 2026-09-05

Before: 33 exports (the earlier note said 19), each with its own ownership
discipline. We had already been caught by `restype` having to be `c_void_p`
rather than `c_char_p`, or ctypes loses the pointer and `curlpro_free` is never
called.

Now: the `curlpro_debug_counts` export reports the size of every registry —
sessions, streams, sockets, calls in flight — plus the goroutine count and the
heap. A leaked handle is invisible from Python: the object is gone while Go still
holds a connection and a goroutine.

A sweep of the boundary found nothing:

| What was checked | Result |
|---|---|
| 5000 requests, 200 sessions, 300 streams | RSS 43.9 → 57 MB and flat thereafter, heap 2576 → 3958 KB |
| Goroutines | 1 before, 1 after |
| Sessions, streams, sockets | the registries return to their original size |
| A stream abandoned without `close()` | released through `__del__` |
| An exception between `open` and `close` | no handle stays behind |
| Cancelled asynchronous calls | `pending` returns to zero |
| Calls against handles that never existed | an error, and the registry does not grow |
| `curlpro_session_close` during `curlpro_stream_read` | three runs: no hang, no crash, the read reaches the end |

Held by a regression: `python/tests/test_ffi_registry.py` (10 tests).

One thing remains a known property rather than a debt: handles created from a
session are not released by `curlpro_session_close` — Python holds them until
`__del__`. Measured: `streams: 10` while the objects are alive, `0` once they are
released.

### 2.4 How to measure `Content-Length` and `custom_anchor`

Both positions are guesses at the moment, because the ready-made
`curl-impersonate` signatures were captured from GET requests, where
`Content-Length` is absent and there are no custom headers at all.

**Wanted:** a way to capture a POST from a live Chrome/Firefox/Safari with a
custom header — reproducibly, rather than once by hand. The capture scheme is
described in `docs/CAPTURE.md` (echo-server plus `--host-resolver-rules`), but it
is built around a navigational GET.

### 2.5 The weak point of the profile schema ✅ answered in STAGE15

A profile is data, but not every browser is data-only: a new type of TLS
extension needs Go code (a `TLSExtension` with `UnmarshalJSON`), and ECH and the
QUIC transport parameters need post-processors, because upstream uTLS does not
load them from JSON.

**The question:** can that boundary be narrowed? A generic "unknown type plus raw
bytes" extension, say, so that a new codepoint does not require a release. The
risk: silently sending rubbish instead of a meaningful extension.

### 2.6 Performance

Measured once: 1775 req/s against 1352 for `curl_cffi` on a local stand
(`docs/STAGE5-RESULTS.md`). Bodies travel in a binary frame; JSON carries only
the metadata.

**The question:** where the obvious slack is left. The suspicious places are the
header assembly on every request (several map and slice allocations), rebuilding
the `ClientHelloSpec` per connection (mandatory, see the invariants — but could
it be cheaper), and the `bridge.go` path between `net/http` and `fhttp`.

---

## Part 3. What to look at with fresh eyes

No specific suspicions here — an unjaded reading is the point.

- **`internal/client/headers.go`** — the densest file in the project: slots, the
  anchor, the case, the interaction with the `fhttp` sorter. Recently rewritten,
  and the rewrite uncovered three bugs (`docs/STAGE13-RESULTS.md`). The logic is
  shared by three transports, so a mistake is expensive.
- **`internal/client/retry.go` + `stream.go`** — retries, draining the body,
  idempotence, `Retry-After`. Their interaction with redirects and the shared
  deadline is not trivial.
- **`internal/client/websocket.go`** (780 lines) — the second largest file in the
  client after `client.go`. RFC 6455 masking, fragmentation, the close handshake.
  We have already caught the WebSocket mutating `s.opts.ForceHTTP1` and thereby
  changing the ALPN of the whole session.
- **`internal/profile/build.go`** — 22 extension types, built from JSON. A
  mistake here corrupts the fingerprint quietly rather than failing.
- **`internal/h3/`** — a vendored copy with targeted changes; `fingerprint.go`,
  `order.go` and `request_writer.go` are the interesting ones. The rest is
  upstream and there is little point touching it.
- **The profile schema against reality** — `docs/PROFILE-SCHEMA.md` and any file
  from `profiles/`. Are there fields that are declared and affect nothing?
