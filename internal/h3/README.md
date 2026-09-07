# internal/h3

A vendored copy of `github.com/refraction-networking/uquic/http3`, with changes
for the browser fingerprint.

## Why a copy rather than a dependency

The public `http3.Transport` API in uquic offers only `AdditionalSettings` (an
ordinary map, with no order) and `EnableDatagrams`. Neither the SETTINGS order,
nor the pseudo-header order, nor the GREASE frame, nor PRIORITY_UPDATE can be set
through it — and those are everything the HTTP/3 layer's fingerprint is made of.

The package imports nothing from uquic's `internal/`, only public APIs, so the
copy builds and goes on using the upstream `uquic`, `qlogwriter` and
`quicvarint`.

The server side (`server.go`, `response_writer.go`, `server_conn.go`,
`capsule.go`) was not copied — we are a client. The constants that lived in
`server.go` and are needed by a client moved to [consts.go](consts.go).

## Changes against upstream

Files of our own: [fingerprint.go](fingerprint.go), [order.go](order.go),
[consts.go](consts.go). Modified: `frames.go`, `request_writer.go`, `client.go`,
`transport.go`.

| What | Was | Is now |
|---|---|---|
| SETTINGS order | a map walk — random per connection | the `Order` field, the rest ascending |
| QPACK settings `0x01`, `0x07` | not sent at all | set through `AdditionalSettings` |
| pseudo-header order | hard-coded `:authority,:method,:path,:scheme` | from `PseudoHeaderOrderKey`, Chrome's order by default |
| ordinary header order | a map walk — random | from `HeaderOrderKey`, the rest alphabetical |
| GREASE frame | none | `SendGreaseFrame`, the identifier drawn per connection |
| PRIORITY_UPDATE | none | `PriorityParam` |
| `Content-Length` position | always at the tail | a slot from `HeaderOrderKey` (`withSlot`) |
| QPACK decoding | the static table of `quic-go/qpack` | our own `internal/qpack` decoder, with a dynamic table |

The upstream pseudo-header order matched neither Chrome (`m,a,s,p`) nor Firefox
(`m,s,a,p`).

The random ordinary-header order is the very defect still open as a bug against
`bogdanfinn/tls-client`
([#264](https://github.com/bogdanfinn/tls-client/issues/264)): for HTTP/3 the
order was not preserved, although it worked for HTTP/1.1 and HTTP/2.

The GREASE identifier (`0x1f*N + 0x21`) is drawn per connection. In bogdanfinn's
code `N` is hard-coded as `1e9`, so the identifier is always the same one — and a
constant value is a tell in itself.

## Why not fhttp

The first attempt replaced `net/http` with `github.com/bogdanfinn/fhttp` for its
`HeaderOrderKey`. It did not build: fhttp is built on `bogdanfinn/utls` while
uquic is built on `refraction-networking/utls`, and their `tls.ConnectionState`
types are incompatible.

Since the package is vendored anyway, the housekeeping keys are declared here
([order.go](order.go)) — without a second utls fork among the dependencies. The
keys contain a colon, which is illegal in a header name, so they are excluded
from validation in two places: `transport.go` and `request_writer.go`.

## Two races that had to be closed

The fingerprint "floated" at first — it matched on some requests and not others.
The causes turned out to be different, and both are visible only against a live
server.

**The control stream left in parallel with the request.** Upstream opens it in a
goroutine while the request is sent at once; these are different QUIC streams,
and the server managed to answer without having seen SETTINGS. A browser opens
the control stream before its first request — so now the first request waits for
that write (`settingsSent`, with a safety timeout).

**PRIORITY_UPDATE is addressed to a stream.** The frame carries the identifier of
the stream it concerns, which is why Chrome sends it before every request. A
single send with a zero at connection time gave a match **for the first request
only** — the characteristic "1 out of 5" pattern that led to the cause.

## QPACK: the dynamic table

The profile advertises `QPACK_MAX_TABLE_CAPACITY: 65536`, as Chrome does, and the
server is entitled to use the table. The upstream decoder does not support it
("Our QPACK implementation doesn't use the dynamic table yet"), and from the
second request onwards the answer from `fp.impersonate.pro` could not be parsed:
`qpack: expected Required Insert Count to be zero`.

Lowering the capacity would mean disagreeing with Chrome in the very first
SETTINGS field, so a decoder of our own was written instead —
[internal/qpack](../qpack). The client opens the encoder and decoder streams and
sends Section Acknowledgement and Insert Count Increment. It became 5 answers out
of 5, from 1 out of 5.

## The Content-Length position

Upstream added `content-length` last, after every request header. In the fetch
set Chrome sends it **first**, right after the pseudo-headers — measured with the
[cmd/hcapture](../../cmd/hcapture) stand against live Chrome 152 over HTTP/3. On
HTTP/2 the position came from the profile's order and on HTTP/3 it did not: a
divergence visible to any server that compares the two transports.

`withSlot` ([order.go](order.go)) inserts the name at the position given by
`HeaderOrderKey` even when the header itself is absent from `req.Header`: the
transport adds it later.

## The result

`quic.browserleaks.com/fp`, reproduced by `cmd/h3probe`:

```
received:   1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p
Chrome 144: 1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p
```

A byte-for-byte match, stable across three runs.

**This is the H3 layer only.** The QUIC layer — transport parameters, the Initial
packet — comes from uquic and holds three known divergences from Chrome; they are
analysed in [docs/HTTP3-RESEARCH.md](../../docs/HTTP3-RESEARCH.md).

## Updating

When uquic is updated the copy has to be carried over again. The order: copy the
changed files, drop the server ones, restore the changes from the table above.
That table and the comments in the code are the guide — each one marks what
differs from upstream and why.
