# HTTP/3: reconnaissance before the implementation

The state of things on 2026-09-01.

## The main conclusion

No library covers both layers. The H3 fingerprint is made of two independent
parts, and the projects close either one or the other:

| | The QUIC layer (Initial, transport parameters) | The H3 layer (SETTINGS, pseudo-headers) |
|---|---|---|
| `refraction-networking/uquic` | **yes** — `QUICSpec`, the Chrome 115/146 parrots | no, stock quic-go |
| `bogdanfinn/quic-go-utls` | no, stock quic-go | **yes** — the SETTINGS order, GREASE, PRIORITY_UPDATE |
| `sardanioss/httpcloak` | yes | yes | — but a vertical fork of six repositories, incompatible with our stack |

Our stack is `refraction-networking/utls` + `bogdanfinn/fhttp`. Hence the plan:
**uquic for the QUIC layer plus changes of our own to the H3 layer**.

## The oracles: what each covers

Verified with a live H3 request (`cmd/h3probe`).

`quic.browserleaks.com/json` **redirects to `/fp`** — the `/json` path that walks
through the articles is stale. It gives JA4-q and `h3_text`, that is, the H3 layer
only.

**`fp.impersonate.pro/api/http3` is the only one that returns parsed transport
parameters**, so it covers the QUIC layer as well. Its `perk` format has **four**
sections rather than the three the curl_cffi documentation describes:

```
SETTINGS | pseudo-headers | transport parameters | CID lengths
```

The normalisation is thought through and makes `perk_hash` usable in CI: GREASE
entries collapse into the literal `GREASE`, the random
`initial_source_connection_id` (id 15) is replaced by `AUTO`, and
`version_information` (id 17) prints as `chosen@available,…`.

**No oracle returns the ordinary header order** — only the SETTINGS and the
pseudo-headers. So it is captured with our own stand, `cmd/hcapture -h3`: QUIC
with ALPN `h3`, HEADERS parsed by our own QPACK decoder, the names printed in wire
order. The very first measurement against Chrome 152 found a divergence —
`Content-Length` went out last for us while Chrome puts it first in the fetch set
(see [STAGE16-RESULTS.md](STAGE16-RESULTS.md)). The order of Chrome's other
headers in HTTP/3 matched HTTP/2 name for name.

Separately: **JA4-q covers only the TLS ClientHello inside the QUIC Initial.** The
letter `q` is the transport's only contribution. Neither the transport parameters
nor the SETTINGS enter JA4, and there is no JA4T equivalent for UDP. So those
layers can only be checked through proprietary strings.

## Measured: what uquic gives out of the box

```
$ go run ./cmd/h3probe -url https://fp.impersonate.pro/api/http3
parrot: chrome146
  SCID/DCID: 0 / 8      first packet: number 1, lengths [1 2]

HTTP 200 OK (HTTP/3.0)   CID client/server: 0/8
perk: 6:10485760|a,m,p,s|5:6291456;1:30000;32:65536;8:100;15:AUTO;
      12584:0x31304146;9:103;GREASE;16741339:1@GREASE,1;6:6291456;
      12583:AUTO;4:15728640;7:6291456;3:1472|0,8
```

### The QUIC layer: three divergences, one of them still open

Compared against `chrome150` from curl-impersonate — **every main value matched
immediately**: `1:30000`, `3:1472`, `4:15728640`, `5/6/7:6291456`, `8:100`,
`9:103`, `32:65536`, an empty SCID, and CID lengths `0/8`.

Exactly three things diverged, and all three are from the disputed list below:

| | uquic was | Chrome | after the change |
|---|---|---|---|
| `12584` google_connection_options | `"10AF"` | `"ORIG"` | ✅ `0x4f524947` |
| `12583` google_initial_rtt | sends it | does not | ✅ removed |
| version_information ID | **16741339** (the draft `0xFF73DB`) | **17** (`0x11`) | ✅ `17` |
| version_information order | `GREASE,1` | `1,GREASE` | ⚠️ disputed |

The changes were made by modifying the `ClientHelloSpec` (see
[internal/profile/quic.go](../internal/profile/quic.go)) — patching uquic was not
needed: the transport parameters are available as an ordinary slice, and
`FakeQUICTransportParameter` is the escape hatch for any value.

**The remaining divergence is unresolved and moved into a profile setting.** The
utls documentation states outright that Chrome puts GREASE first, and the uquic
parrot does the same; curl-impersonate writes `1,GREASE`. It may be a matter of
normalisation during serialisation to a string rather than of the real byte
order. Only a capture of our own can settle it.

The tally over 13 parameters: **12 match, 1 is disputed**.

### The H3 layer: nothing matched — fixed

| | uquic was | Chrome 144 | after the changes |
|---|---|---|---|
| SETTINGS | `6:10485760` | `1:65536;6:262144;7:100;51:1;GREASE` | ✅ |
| pseudo-headers | `a,m,p,s` | `m,a,s,p` | ✅ |
| the GREASE frame | none | present | ✅ |
| PRIORITY_UPDATE | none | `984832` | ✅ |

The public `http3.Transport` API gives only `AdditionalSettings
map[uint64]uint64` (no order — a map!) and `EnableDatagrams`, so the package is
vendored into [internal/h3](../internal/h3/). The result matches Chrome
byte-for-byte and is stable across repeated runs:

```
1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p
```

How the changes are built — [internal/h3/README.md](../internal/h3/README.md).

## About the transport-parameter order

Popular articles claim the order is part of the fingerprint. The primary sources
for Chrome say the opposite: uquic documents
`RandomizeTransportParameters` as "reproduces the real Chrome, which shuffles the
order on every handshake", and `clienthellod` deliberately **sorts** the IDs
before hashing.

So for Chrome it is a **fixed** order that is the anomaly. What has to be compared
is the sorted set of IDs, the values, the number of GREASE entries, the DCID
length, the first packet number (1, not 0) and the datagram size. For Firefox the
order is fixed, and there it matters.

## The TLS handshake inside QUIC

The ClientHello for QUIC is built not from the profile's `tls` section but from a
uquic parrot (`QUICChrome_146`) — for Chrome those two handshakes are different,
and the description of a TCP connection must not be substituted there. A
measurement of Chrome 152 through `cmd/quiccapture` showed exactly how they
differ:

| What | TCP | QUIC |
|---|---|---|
| the extension set | 16, with `session_ticket`, `ec_point_formats`, SCT, EMS, `renegotiation_info` | 12, with `quic_transport_parameters` in their place |
| the signature algorithms | 12 entries, the first GREASE, with `0x0904`–`0x0906` | 9 entries, without GREASE and without those |
| `trust_anchors` | present | present |
| the extension order | shuffled | shuffled |

The parrot matched Chrome 152 on the ciphers and the signatures but was one
extension behind — `trust_anchors`. It is now added from the profile, and the
extension order is shuffled per connection: three captures of the browser gave
three different permutations of one set.

## Chrome's values

**HTTP/3 SETTINGS:** `1:65536` (QPACK max table), `6:262144` (max field section),
`7:100` (QPACK blocked streams), `51:1` (H3_DATAGRAM), plus one GREASE entry
(`0x1f*N + 0x21`). The order `[0x01, 0x06, 0x07, 0x33, GREASE]`.

**Firefox:** `1:65536;7:20;727725890:0;16765559:1;51:1;8:1` — 20 blocked streams,
announces WebTransport, sends no GREASE.

**Pseudo-headers:** Chrome `m,a,s,p`, Firefox `m,s,a,p`.

**PRIORITY_UPDATE:** Chrome sends type `0xF0700` (984832) with the body
`varint(0) + "u=0, i"`. Firefox does not send it.

**Chrome's QUIC transport parameters** (curl-impersonate's `chrome150`):
```
1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;
15:;17:1@1,GREASE;32:65536;12584:0x4f524947;GREASE
```

**Connection ID:** Chrome — an empty SCID, an 8-byte DCID. Firefox — SCID 3,
DCID 8/9/15 (different values give different fingerprints; uquic keeps three
parrots).

**The Initial packet:** the number starts at **1**, not 0; the number lengths are
`[1, 2]`; the ClientHello is fragmented across many CRYPTO frames interleaved with
PING and PADDING; and the post-quantum key share forces **two Initial datagrams**.

## The `perk` format (curl_cffi)

`HTTP3_SETTINGS | PseudoHeaderOrder | QUICTransportParameters` — three fields
separated by `|`, the analogue of the four-field `akamai` string for H2. Besides
the decimal form, the parameter values have five special ones: empty (`15:`),
`AUTO`, `v@list` (`17:1@1,GREASE`), hexadecimal (`12584:0x4f524947`) and a bare
`GREASE`.

The point of adopting this format is that it allows the four known strings from
curl-impersonate to be imported directly.

## Disagreements that only a capture can settle

The implementations contradict one another about the current Chrome — which is
not a detail but a direct risk of taking someone else's mistake for the truth.

| Question | The positions |
|---|---|
| `0x3127` google_initial_rtt | uquic sends it ("new in Chrome 146"); httpcloak **removed** it, claiming that a real Chrome 151 does not send it and that generating it required an extra TCP connection, which is a tell in itself |
| `0x3128` google_connection_options | `"RVCM"` (uquic 115), `"10AF"` (uquic 146), `"B2ON"` (azuretls), `"ORIG"` (httpcloak, citing Chromium's `kQuicOptions` default) |
| the order in `version_information` | uquic: `[GREASE, 1]`; curl-impersonate: `1,GREASE` |

The value of `0x3128` is a Finch parameter rather than a version constant: one and
the same Chrome 152 build is seen with both `"ORIG"` and `"IW50,ORIG"`. So it is a
profile field, not a constant in the code.

About azuretls's `"B2ON"`, httpcloak notes that it appears only under an explicit
`--enable-features=QuicConnectionOptions=B2ON` and "makes some QUIC detectors
silently drop the following frames".

The `QUICChrome_146` parrot in uquic is derived from **one** pcap sample. Our
experience with the TCP layer (stage 0) showed that a single capture is not enough
even for the extensions; for QUIC there is no more reason to trust one sample.

## What cannot be trusted

- **CycleTLS** — a stub: `CreateUQuicSpecFromFingerprint` and `...FromJA4` ignore
  their argument and always return Chrome 115 (a comment in the code: "once I find
  a route to test against").
- **enetx/surf** — QUIC fingerprinting was removed by the commit `remove uquic`
  (2025-12-31) and the values are commented out, yet the README still promises
  "Full Chrome and Firefox QUIC transport parameter matching".
- **`go get uquic@latest`** — gives the v0.0.6 tag from 2024, with Chrome 115. The
  Chrome 146 work lives only in master; a pseudo-version is needed.

## The oracle

`https://quic.browserleaks.com/` returns:

```json
{ "h3_hash": "ba909fc3dc419ea5c5b26c6323ac1879",
  "h3_text": "1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p" }
```

The format: `SETTINGS | the GREASE frame | PRIORITY_UPDATE | the pseudo-header
order`.

An important limit: **`h3_text` covers the H3 layer only**. It does not show the
transport parameters or the structure of the Initial packet — those need a pcap.
So automatic checking is possible for only half of the fingerprint.

## The limits of the corpus

In `curl-impersonate/tests/signatures/*.yaml` there is **no `http3` section in any
file** — even though the corpus README describes one. The H3 data lives in the C
structures of `patches/curl.patch` and only for four targets: `chrome145`,
`chrome146`, `chrome150`, `firefox147`. Safari and Tor have none at all.

So the stage-3 importer cannot fill those fields, and the H3 profiles have to be
captured by us or carried over by hand from the four known strings.
