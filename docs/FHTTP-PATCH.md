# The patch carried on the vendored fhttp

`vendor/github.com/bogdanfinn/fhttp/http2/transport.go` is not the upstream
v0.6.8 file. It carries six edits — five to the HTTP/2 receive-window accounting and one to
the response pipe — all marked `// curlpro:` in the source (`pipe.go` gained one
method), applied by
[scripts/patch-fhttp.py](../scripts/patch-fhttp.py) and guarded by
`internal/client/h2flow_test.go` and, under `-race`,
`TestConcurrentCloseDuringRequests`. This file says why.

## What happened

Measuring okhttp produced a profile declaring okhttp's own
`SETTINGS_INITIAL_WINDOW_SIZE` of 16 MiB. A 45 MB download through it died:

```
stream error: stream ID 1; FLOW_CONTROL_ERROR
```

The real okhttp 5.5.0 fetched the same URL in 1.9 s over h2. Bisecting the
profile pinned the failure to that single field — with Chrome's 6 MiB the
download completed — and a frame trace (`GODEBUG=http2debug=2`) showed the
mechanism: after 5 MB of data the client had sent **1250 stream WINDOW_UPDATEs
totalling 3.2 GB of credit**, each increment equal to everything received so
far. RFC 7540 §6.9.1 obliges the peer to reset a stream whose window passes
2^31−1, and the peer did, at update 1017.

## Why

fhttp's `flow` type serves both directions. Its `available()` returns the
smaller of the stream window and the connection window it is linked to;
its `add()` raises the stream window only. On the receive side that pair is
wrong: the first refresh lifts the stream above the connection, the connection
becomes the minimum, and from then on every read recomputes

```go
unsent := streamFlow - cs.inflow.available() + cs.bufPipe.Len()
```

from a number that `add()` never touches. The same bytes are credited again on
every read. The runaway is quadratic.

Chrome's profiles survived by arithmetic alone: a 6 MiB stream window is below
half the 15 MiB connection window, so the connection is refreshed before it can
become the minimum. That was luck, not correctness — the regression test shows
a Chrome-window control crediting 1.8 GB for a 24 MiB body, short of 2^31−1
only because the body ended first. Every profile in the corpus was exposed on a
long enough download or a busy enough connection.

Upstream `golang.org/x/net/http2` removed this design in 2022 (`inflow` with
explicit `unsent` accounting and a hard 2^31−1 guard). fhttp forked before that
and never took it: v0.6.9, the latest, keeps the link and changes only the sign
of `bufPipe.Len()` — which repairs the double count below but not the runaway.

## The six edits

| | Where | Was | Is |
|---|---|---|---|
| a | `newClientStream` | `cs.inflow.setConnFlow(&cc.inflow)` | removed — the receive window is not linked |
| b | `processData` | `cs.inflow.take(n)` alone (the link took the connection's share) | `cc.inflow` and `cs.inflow` checked and taken explicitly |
| c | `transportResponseBody.Read` | `isSmallWindow := cc.initialWindowSize < 1 MiB` — the *peer's* send window | `cc.streamFlow < 1 MiB` — our receive window |
| d | `transportResponseBody.Read` | `unsent := … + cs.bufPipe.Len()` | `… - cs.bufPipe.Len()` — buffered bytes were taken on arrival and are credited when read; adding them credited every one twice |
| e | `transportResponseBody.Read`, three sites | `cc.inflow.add(connAdd)` / `cs.inflow.add(streamAdd)` with the result ignored | the `false` that `flow.add` returns past 2^31−1 now zeroes the increment, so nothing is sent for a window already at its maximum. With a–d the sum cannot get there; this turns a would-be protocol violation into a no-op rather than a reset |
| f | `handleResponse` + `pipe.go` | `cs.bufPipe = pipe{…}` — a whole-struct write replacing the pipe's mutex, condition and done channel | `cs.bufPipe.setBuffer(…)`, ported from x/net: the buffer is installed under the pipe's own lock, and a pipe already closed refuses it |

The send side (`cs.flow`, `cc.flow`) keeps its link: for sending, "no more than
the smaller window allows" is exactly right.

## The second defect: a close that could be lost

Found earlier by `TestConcurrentCloseDuringRequests` under `-race`, and skipped
there for want of a fix. `handleResponse` assigned the response pipe wholesale:

```go
cs.bufPipe = pipe{b: &dataBuffer{expected: res.ContentLength}}
```

That write replaces the pipe's mutex, its condition variable and its done
channel. `closeForError`, holding only the connection mutex, calls
`cs.bufPipe.CloseWithError` on every stream — which locks the very mutex being
overwritten. Closing a session while an HTTP/2 response is arriving therefore
wrote the struct from two goroutines, and a close that lost the race was simply
gone: the reader woke only on the request timeout.

Upstream x/net never replaces the pipe. The buffer goes in through
`setBuffer`, under the pipe's lock, and `setBuffer` does nothing on a pipe that
is already closed — so a close that won stays won and the next `Read` returns
its error at once. Edit (f) ports exactly that. Proven both ways under the
detector: with the edit stashed the test reports `WARNING: DATA RACE` and fails
on the first of three runs; with it, ten of ten pass, and the whole
`internal/...` tree is clean under `-race`.

## Measured

| | Before | After |
|---|---|---|
| pypi.org/simple/, okhttp profile, 45 MB | RST at 5 MB | 200, 45 960 119 bytes, no RST |
| 24 MiB body, 16 MiB window, slow reader | RST (credit past 2^31−1) | credit 16.9 MB |
| 24 MiB body, 6 MiB window (Chrome), slow reader | credit 1.80 GB | credit 22.5 MB |

Correct accounting credits what was consumed plus at most one window of slack
for bytes buffered ahead of the reader. The test enforces exactly that bound.

## Keeping it

`go mod vendor` regenerates the tree and silently drops the edits. Three things
catch that: `scripts/patch-fhttp.py` re-applies them (idempotent, exact anchors,
fails loudly if the upstream text moved), `TestH2ReceiveWindowCreditIsNotRunaway`
fails against an unpatched transport, and `TestConcurrentCloseDuringRequests`
fails under `-race` against an unpatched pipe — which CI runs on every push.
Re-vendor, re-run the script, run both.

`TestFlowControlTrace` in the same package is the live check against pypi. It is
off by default and needs `FLOWTRACE` pointing at a profile directory.

## Not carried

Nothing. Both defects the project found in fhttp — the window runaway and the
close race — are carried here. What remains is the wish that upstream took
them, so this file could be deleted.
