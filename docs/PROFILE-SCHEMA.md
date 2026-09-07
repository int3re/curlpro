# The profile schema

A profile is a JSON file. The engine interprets it; nothing needs compiling until
a browser brings a genuinely new primitive.

The schema borrows the `based_on` delta model from `sardanioss/httpcloak` (MIT),
where it had proven itself: a monthly Chrome bump that changes only the UA and
the sigalgs is a file of ~40 lines.

## Resolution and inheritance

```
LookupCustom(name)                    // the runtime registry, registered from Python
  ↓ not there
the loaded directory                  // profiles/ inside the wheel, or one of your own
  ↓ not there
based_on → recursively upwards        // the chain of deltas
  ↓ the bottom
a Go literal                          // a full preset with real bytes
```

Cycle protection in `based_on` is mandatory — the chain can be long
(chrome-152 → 151 → 150 → … → 146).

> The original design put the profiles into the binary through `//go:embed`, and
> older notes still say so. It was not done that way: the profiles ship as data
> inside the wheel and are read from disk. There is not one `go:embed` in the
> repository.

## An example delta

```jsonc
{
  "version": 1,
  "preset": {
    "name": "chrome-152-windows",
    "based_on": "chrome-151-windows",
    "tls": {
      "signature_algorithms": [2308, 2309, 2310, 1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537],
      "trust_anchors": ["82df130201", "82df130206", "..."]
    },
    "headers": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
      "values": { "sec-ch-ua": "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\"" },
      "order": [
        { "key": "sec-ch-ua", "value": "\"Chromium\";v=\"152\", ..." },
        { "key": "sec-ch-ua-mobile", "value": "?0" },
        { "key": "sec-ch-ua-platform", "value": "\"Windows\"" },
        { "key": "upgrade-insecure-requests", "value": "1" },
        { "key": "user-agent", "value": "" },
        { "key": "accept", "value": "text/html,..." },
        { "key": "sec-fetch-site", "value": "none" },
        { "key": "accept-encoding", "value": "gzip, deflate, br, zstd" },
        { "key": "cookie", "value": "" },
        { "key": "priority", "value": "u=0, i" }
      ],
      "custom_anchor": "accept-encoding"
    }
  }
}
```

`2308/2309/2310` = `0x0904/0x0905/0x0906` = ML-DSA-44/65/87.

### An empty value is a slot

`"value": ""` means "a position with no value". A slot holds a place for a header
that will arrive later: from the session, from the request, or from the transport
itself. A slot with nothing behind it does not reach the request. A few names are
filled by the library:

- `user-agent` — from `headers.user_agent`;
- `cookie` — from the session jar, and if the jar is empty the header is not sent;
- `origin` — the request's origin, on any method except GET and HEAD (a browser
  sends `Origin` on anything with a body, including a navigational form POST);
- `content-length` — added by the transport after the assembly; the slot only
  fixes the position;
- `content-type` and any other name — the value from the session or request
  headers; without one the slot drops out.

The slot is needed because otherwise the header would be appended at the end:
Chrome sends `cookie` between `accept-language` and `priority`, and
`Content-Length` third, right after `Connection` (measured against Chromium 148,
STAGE14). The Chrome and Edge profiles carry `content-length`, `content-type` and
`origin` slots; the positions for Firefox and Safari are not measured.

### `custom_anchor`

The name of the header **before** which user-supplied headers are placed (through
the session or a request argument). An empty value means "at the end".

Measured against Chromium 148 and Chrome 152: custom fetch/XHR headers land in
the renderer's cluster together with `sec-ch-ua*`, `User-Agent` and
`Content-Type`. The order inside that cluster is decided by Blink's hash table
and cannot be reproduced exactly. The navigational set uses the anchor `accept`
as the closest approximation; the real cluster lives in the `fetch` section.

The anchor is a **comma-separated list**: the first name present in the set is
taken. That is how Firefox puts custom headers before `Connection` over HTTP/1.1
and before `Upgrade-Insecure-Requests` in HTTP/2, where there is no `Connection`.

The order list is read as **what is wanted**, not as a list of what exists. A name
with no header behind it is simply skipped.

### `websocket`

The WebSocket handshake is a set of its own: Chrome sends neither `sec-ch-ua` nor
`sec-fetch-*` nor `accept` on it, but does send `Pragma` and `Cache-Control`, and
puts `Sec-WebSocket-Key` after `Accept-Language`. The `websocket.order` section is
a list of pairs in send order and send case; an empty value is a slot: `host`,
`user-agent`, `origin`, `sec-websocket-key`, `sec-websocket-protocol` (which drops
out without subprotocols), `cookie`; any other empty name takes its value from
`headers.order` (`accept-encoding`, `accept-language`). The Chrome/Edge template
is measured (STAGE14), Firefox/Tor come from known captures, and Safari has no
section and gets the RFC minimum from the code.

### `fetch`

The second header set — for `fetch()` and `XMLHttpRequest` requests. The
navigational one does not suit them: the browser sends `accept: */*`,
`sec-fetch-mode: cors`, `sec-fetch-dest: empty`, `Origin` and `Referer`, while
sending no `upgrade-insecure-requests` and no `sec-fetch-user` at all. In a
browser a custom header occurs **only** on such requests, which is why a request
carrying one on top of the navigational set is anomalous whatever the anchor.

| Field | Purpose |
|---|---|
| `order` | pairs in send order; an empty value is a slot |
| `http1_order` | the order and case for HTTP/1.1, including `Host` and `Connection` |
| `custom_anchor` | the anchor for custom headers, a comma-separated list |

A slot whose name is known to the navigational set (`sec-ch-ua*`,
`accept-encoding`, `accept-language`, `user-agent`) takes its value from there: a
delta for a new Chrome version fixes `sec-ch-ua` once. The rest
(`content-type`, `content-length`, `origin`, `referer`, `cookie`) are filled by
the request, the library or the transport.

The mode is chosen automatically: fetch, if the method is not GET, HEAD or POST,
if the body does not look like a form, or if a header is set that the
navigational set does not know. Explicitly — `mode="navigate"` or
`mode="fetch"`. A profile with no `fetch` section is always navigational.

### What is mandatory

`tls.permute_extensions` is set explicitly — on the profile itself or on an
ancestor. There is no default: shuffling is right for Chrome ≥ 110 and wrong for
everyone else, and a profile without the field used to be shuffled silently.
`Resolve` rejects a profile without it, as it does a `stream_weight` outside
0..256 and an `http3.settings_order` that does not cover `settings`.

`tls.allow_blunt_mimicry` permits reproducing an extension uTLS does not know,
as raw bytes from `raw_client_hello`. Without it a new codepoint
(`trust_anchors` 0xCA34 in Chrome 152) breaks the parsing of a capture with
"unsupported extension", and the profile would need Go changes. The risk is
bounded: uTLS knows and generates the key material (`key_share`, ECH) itself, and
only static extensions go out raw. `curlpro capture` turns the field on by itself
when the spec will not build without it, and says so.

Boolean fields that a delta may **turn off** are pointers:
`send_grease_frame`, `priority_param`, `send_initial_rtt`,
`legacy_version_information_id`. With a bare bool, "false" was indistinguishable
from "not set".

## The fields

⚠ The tables below describe the **intended schema** rather than the current
parsing. The loader enables `DisallowUnknownFields`, so a field absent from the
Go structures in `internal/profile` is rejected. Implemented today: `tls` —
`raw_client_hello`, `client_hello_spec`, `cipher_suites`, `compression_methods`,
`extensions`, `signature_algorithms`, `alpn`, `permute_extensions`; `http1` —
`order`, `connection`; `http2` — `settings`, `connection_window_update`,
`pseudo_order`, `stream_weight`, `stream_exclusive`; `http3` — `settings`,
`settings_order`, `pseudo_order`, `send_grease_frame`, `priority_param`; `quic` —
`parrot`, `connection_options`, `send_initial_rtt`,
`legacy_version_information_id`, `grease_version_first`; `headers` —
`user_agent`, `order`, `form_boundary`, `custom_anchor`; `websocket` — `order`.
The rest is plan.

### `tls`
| Field | Purpose |
|---|---|
| `client_hello` | the name of a uTLS preset (`HelloChrome_133`) — the quick path |
| `client_hello_spec` | uTLS's native JSON `ClientHelloSpec` — the exact path |
| `raw_client_hello` | the raw record in base64 — the byte-exact path |
| `psk_client_hello`, `raw_psk_client_hello` | the same for a resumed connection |
| `quic_client_hello`, `quic_psk_client_hello` | separate specs for QUIC |
| `allow_blunt_mimicry` | reproduce unknown extensions verbatim (carefully — stale key_shares) |
| `signature_algorithms` | the sigalgs for TCP |
| `quic_signature_algorithms` | **separately**: Chrome 150 sends ML-DSA over TCP but not over QUIC |
| `delegated_credential_algorithms` | ext 34 (Firefox) |
| `alpn`, `alps` | the protocol lists; for ALPS, which codepoint — 17513 or 17613 |
| `cert_compression` | `brotli` / `zlib` / `zstd` |
| `key_share_curves` | the groups and how many of them |
| `trust_anchors` | ext 0xCA34, new in Chrome 152 |
| `permute_extensions` | whether to shuffle (Chrome 110+) |
| `record_size_limit` | ext 28 (Firefox) |
| `ja3`, `psk_ja3`, `ja3_extras` | the JA3 path — **for compatibility only**, and lossy (see FINGERPRINT-SPEC.md) |

### `http1`

| Field | Purpose |
|---|---|
| `order` | the header names in send order **and send case**; may name headers a request will not carry (`Content-Length`) |
| `connection` | the `Connection` value; empty means the header is not sent |

It differs from `http2` more than it looks. In HTTP/2 the names must be
lowercase; in HTTP/1.1 the case is arbitrary — and browsers use that:

```
Chrome:  Host, Connection, sec-ch-ua, …, Upgrade-Insecure-Requests,
         User-Agent, Accept, Sec-Fetch-*, Accept-Encoding, priority
Firefox: Host, User-Agent, Accept, …, Priority, TE
```

Chrome sends Title-Case for most names but leaves `sec-ch-*` and `priority`
lowercase. And `Host` and `Connection` appear, which do not exist in HTTP/2 at
all.

### `http2`
| Field | Purpose |
|---|---|
| `akamai` | the shortcut string `SETTINGS\|WU\|PRIORITY\|PSEUDO` — sets everything at once |
| `settings`, `settings_order` | the id/value pairs and **the send order** |
| `connection_window_update` | the WINDOW_UPDATE increment (Chrome: 15663105) |
| `priority_frames` | standalone PRIORITY frames |
| `header_priority` | PRIORITY on the HEADERS frame: `{stream_dep, exclusive, weight}` |
| `stream_weight`, `stream_exclusive` | the priority on the HEADERS frame. ⚠ on the wire the weight is one less (RFC 7540): Chrome 256, Firefox 42. **Zero means "do not send"**: that is how Safari behaves. An absent field hands the decision to the library, and its default (255, exclusive) is right only for Chrome |
| `no_rfc7540_priorities` | Safari 26 |
| `pseudo_order` | `[":method", ":authority", ":scheme", ":path"]` |
| `header_order` | the order of the ordinary headers |
| `hpack_header_order`, `hpack_indexing_policy`, `hpack_never_index` | fine HPACK tuning |
| `disable_cookie_split` | the HPACK "crumbling" of cookies |
| `data_frame_max_size`, `preface_ping_idle_ms`, `idle_ping_ms` | connection behaviour |
| `priority_table` | priority by `sec-fetch-dest` → `{urgency, incremental, emit_header}` |

### `http3`
`qpack_max_table_capacity`, `qpack_blocked_streams`, `max_field_section_size`,
`enable_datagrams`, `quic_initial_packet_size`, `quic_transport_param_order`,
`quic_connection_id_length`, `quic_connection_options`, `send_grease_frames`,
`quic_allow_0rtt`, `quic_chrome_style_initial`.

### `headers`
`user_agent`, `values` (a map), `order` (an ordered list of pairs).

The order **and the case** are part of the fingerprint. Chrome sends `sec-ch-ua`
lowercase and `Upgrade-Insecure-Requests` in Title-Case; in HTTP/2 everything is
lowercased, but the order is kept.

### `client_hints`
`full_version_list`, `platform_version`, `arch`, `bitness`, `model`, `wow64`.
Empty fields are derived from `sec-ch-ua` — otherwise a mismatch between the UA
and the client hints is easy to produce, and that mismatch is a signal in itself.

### `tcp` (optional, needs privileges)
`ttl` (128 on Windows / 64 on Linux), `mss`, `window_size`, `window_scale`,
`df_bit`. Out of reach of an ordinary user-space process; the field is reserved.

## Devices and high-entropy hints

From version 110 Chrome cut the model and the system version out of the
`User-Agent`: a capture of a Pixel 7 on Android 17 gives
`Mozilla/5.0 (Linux; Android 10; K) …` — the same placeholder on every phone. The
real device is reported through the hints, and the browser sends them **only
after the site has asked** with an `Accept-CH` header in a response:

```
sec-ch-ua-model: "Pixel 7"
sec-ch-ua-platform-version: "17.0.0"
sec-ch-ua-arch: ""            ← empty on Android
sec-ch-ua-bitness: ""
sec-ch-ua-form-factors: "Mobile"
```

The profile describes this in two sections:

```json
"devices": [
  { "name": "Pixel 7", "model": "Pixel 7", "platform_version": "17.0.0" }
],
"client_hints": {
  "values": { "sec-ch-ua-form-factors": "\"Mobile\"" },
  "order":       [ … the full navigation order with the hints … ],
  "fetch_order": [ … the same for fetch and subresources … ]
}
```

`order` is stored whole rather than as positions: once the hints appear Chromium
rebuilds the **entire** header cluster, and the order turns out to be a function
of the set of names. Two independent runs gave the same sequence, so it is a
measurement. If a site asks for a subset of the hints, the library keeps their
relative order — an approximation; the exact order for every subset would have to
be captured separately.

Browsers that did **not** cut the device out of the string get it substituted
there too. Such a profile declares a template:

```json
"headers": {
  "user_agent": "Mozilla/5.0 (Linux; arm_64; Android 17; Pixel 7) … YaBrowser/26.8.2.121.00 …",
  "user_agent_template": "Mozilla/5.0 (Linux; {arch}; Android {android}; {model}) … YaBrowser/26.8.2.121.00 …"
}
```

`{model}`, `{android}` (the major version), `{platform_version}` and `{arch}` are
understood. Without a `device=` the string stays exactly as captured.

The library will not substitute a model into a `User-Agent` where there is no
template: a modern Chrome has no such string at all, and one would give the client
away faster than an identical device on every session would. Consistency,
however, is mandatory: if the string says "SM-S911B", `sec-ch-ua-model` says the
same.

## A value that depends on the method

Besides `value`, a pair in `headers.order` may carry `value_by_method` — an
override for particular methods:

```json
{
  "key": "accept-encoding",
  "value": "gzip, deflate, br, zstd, sdch",
  "value_by_method": { "POST": "gzip, deflate, br, zstd" }
}
```

It came out of a capture of Yandex Browser 26.8 on a Pixel 7: `sdch` goes out on
GET, HEAD, DELETE and PUT but not on POST — including a POST with an empty body.
The rule is about the method rather than the body, which is why it is described by
method.

The method name is compared case-insensitively. An empty string means a slot: on
that method the header does not go out if there is nothing to fill it with. A
`fetch` slot that takes its value from the navigational set carries the overrides
along with it.

## The trust_anchors extension

Chrome 152 lists in extension 0xCA34 the short identifiers of the roots it
trusts, and the server picks a chain by them. In a profile that is a list of
relative OIDs:

```json
"tls": {
  "trust_anchors": ["11129.9.13", "44947.2.15", "52580.200109.1.11"]
}
```

The order in the file does not matter: it is **drawn afresh on every
connection**, because that is what the browser does. A measurement of Chrome 152
over three runs gave the same set of 32 entries in three different orders; a
constant permutation would tell the client from the browser on any sample of
several connections.

The list changes together with Chrome's root store — roughly every two weeks —
and is updated by editing data, without a rebuild.

## What must break the loading of a profile

A profile has to be rejected rather than quietly degraded:
- an unknown extension name → an error (unless `allow_blunt_mimicry` is explicit)
- `pre_shared_key` among the extensions → an error: the capture was made on a
  resumed session, whereas a browser has `padding` in that place
- `trust_anchors` in the extension list → an error: the list is set by the
  `tls.trust_anchors` field, because its order is drawn per connection
- a cycle in `based_on`
- a `settings_order` that does not cover every key in `settings`
- a profile that declares `http3` but does not declare `alpn` with `h3`

Quiet degradation is how curl-impersonate loses a non-standard TLS 1.3 cipher
order (it falls back to `kCiphersAESHardware` without a single warning). There is
no need to repeat that mistake.
