# The patch carried on the vendored fhttp

`vendor/github.com/bogdanfinn/fhttp/http2/transport.go` is not the upstream
v0.6.8 file. It carries four edits to the HTTP/2 receive-window accounting, all
marked `// curlpro:` in the source, applied by
[scripts/patch-fhttp.py](../scripts/patch-fhttp.py) and guarded by
`internal/client/h2flow_test.go`. This file says why.

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

## The four edits

| | Where | Was | Is |
|---|---|---|---|
| a | `newClientStream` | `cs.inflow.setConnFlow(&cc.inflow)` | removed — the receive window is not linked |
| b | `processData` | `cs.inflow.take(n)` alone (the link took the connection's share) | `cc.inflow` and `cs.inflow` checked and taken explicitly |
| c | `transportResponseBody.Read` | `isSmallWindow := cc.initialWindowSize < 1 MiB` — the *peer's* send window | `cc.streamFlow < 1 MiB` — our receive window |
| d | `transportResponseBody.Read` | `unsent := … + cs.bufPipe.Len()` | `… - cs.bufPipe.Len()` — buffered bytes were taken on arrival and are credited when read; adding them credited every one twice |

The send side (`cs.flow`, `cc.flow`) keeps its link: for sending, "no more than
the smaller window allows" is exactly right.

## Measured

| | Before | After |
|---|---|---|
| pypi.org/simple/, okhttp profile, 45 MB | RST at 5 MB | 200, 45 960 119 bytes, no RST |
| 24 MiB body, 16 MiB window, slow reader | RST (credit past 2^31−1) | credit 16.9 MB |
| 24 MiB body, 6 MiB window (Chrome), slow reader | credit 1.80 GB | credit 22.5 MB |

Correct accounting credits what was consumed plus at most one window of slack
for bytes buffered ahead of the reader. The test enforces exactly that bound.

## Keeping it

`go mod vendor` regenerates the tree and silently drops the edits. Two things
catch that: `scripts/patch-fhttp.py` re-applies them (idempotent, exact anchors,
fails loudly if the upstream text moved) and `TestH2ReceiveWindowCreditIsNotRunaway`
fails against an unpatched transport. Re-vendor, re-run the script, run the
test.

`TestFlowControlTrace` in the same package is the live check against pypi. It is
off by default and needs `FLOWTRACE` pointing at a profile directory.

## Not carried

The 2^31−1 guard itself. `flow.add()` returns `false` on overflow and every
caller in fhttp ignores the result; with the link gone the sum can no longer run
away, so the guard was left out of the patch to keep it to what the measurement
required. It is the natural next edit if the window arithmetic is ever touched
again.

The second known fhttp defect — a data race between `handleResponse` writing
`cs.bufPipe` and `closeForError` closing it, found under `-race` when closing a
session mid-response — is untouched here and stays in the debt list.
