# Fingerprint formats — the exact specifications

All of this is checked against primary sources (the FoxIO JA4 spec, the
fingerproxy implementation, the Akamai talk at Black Hat EU 2017). The values are
as of 2026-08-31.

## JA3 (obsolescent, but needed for compatibility)

```
JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats   → MD5
```

It encodes: the legacy handshake version, the cipher list **in send order**, the
extension IDs **in send order**, `supported_groups` and `ec_point_formats`.
GREASE is cut out.

**What is lost** (important if a profile is built from a JA3 — and many
converters do exactly that):

- the payload of almost every extension: the ALPN list (`["h2","http/1.1"]` and
  `["http/1.1"]` give the same JA3), the sigalgs and their order,
  `supported_versions`, the groups and sizes in `key_share`,
  `psk_key_exchange_modes`, the `compress_certificate` algorithms, the
  `application_settings` protocols **and which of the two codepoints** is used
  (17513 versus 17613), `record_size_limit`, the ECH config_id / cipher suite /
  payload length, the padding length
- **the GREASE positions** — where exactly Chrome put GREASE (the first cipher,
  the first group, the first element of supported_versions, the first key_share,
  the extensions at positions 0 and n−1)
- the compression-method list — not a JA3 field at all

**Post-quantum makes the loss dramatic:** two ClientHellos with the same JA3
differ radically if one has `X25519MLKEM768` (0x11EC) in its key_share — that is
~1216 bytes, which push the ClientHello past a single TCP segment. JA3 does not
see it.

**JA3 is unstable for a modern Chrome.** Since Chrome 110 the extensions are
shuffled on every connection. Five consecutive captures gave 5 different JA3
values and 1 identical JA4. Use JA3N (sorted) or JA4.

## JA4

```
JA4 = JA4_a _ JA4_b _ JA4_c
    = t13d1516h2 _ 8daaf6152771 _ e5627efa2ab1
```

### JA4_a — 10 characters

| Pos | Field | Rule |
|---|---|---|
| 1 | protocol | `q`=QUIC, `d`=DTLS, `t`=TLS/TCP |
| 2–3 | TLS version | `0x0304`→`13`, `0303`→`12`, `0302`→`11`, `0301`→`10`, `0300`→`s3`, otherwise `00`. **The source is the highest non-GREASE value from ext 0x002b (supported_versions)**; if absent, the Protocol Version from the record. The handshake version is ignored |
| 4 | SNI | `d` if ext 0x0000 is present, otherwise `i` |
| 5–6 | cipher count | with a leading zero, capped at `99`. Without GREASE, **but with** the SCSVs (0x00FF, 0x5600) and 0xFE00–0xFEFF |
| 7–8 | extension count | the same rules; **including** SNI and ALPN |
| 9–10 | ALPN | the first and last ASCII alphanumeric character of the **first** ALPN value. `h2`→`h2`, `http/1.1`→`h1`, no ALPN→`00`. A single character is doubled. If the first or last byte is outside `0x30-39, 0x41-5A, 0x61-7A`, the first and last characters of the **hexadecimal representation** are taken instead |

### JA4_b
The ciphers as 4-character lowercase hex, GREASE removed, **sorted
lexicographically by hex**, comma-separated, SHA256, first 12 characters. An
empty list gives `000000000000` (not the hash of an empty string).

### JA4_c
`{sorted extensions}_{sigalgs IN THEIR ORIGINAL ORDER}`, SHA256, first 12.

The extensions are sorted, **the sigalgs are not**. **SNI (0000) and ALPN (0010)
are removed** from the list — they are already accounted for in JA4_a. That is
what makes JA4_c stable across a change of domain or of ALPN. No sigalgs means no
trailing underscore.

### Variants
- `JA4_r` — the lists inline instead of hashed, sorted
- `JA4_ro` — the original order, GREASE removed, **SNI and ALPN included**. When
  the `-o` flag is used the field must be called `ja4_o`

### Why JA4 beats JA3
The extension order is sorted, so it survives the shuffling of Chrome 110+
(empirically: 5 JA3 values against 1 JA4 over five captures). ALPN moves into
JA4_a, separating HTTP/2 clients from HTTP/1 ones. The sigalgs move into JA4_c.
The a/b/c parts are searchable independently — a partial match on `a_b` is
possible.

## JA4H (the HTTP client)

```
JA4H = {method}{version}{cookie}{referer}{nn}{lang} _ {hash_b} _ {hash_c} _ {hash_d}
```
- `method` — the first 2 characters of the method, lowercased (`ge`, `po`)
- `version` — `20` for h2, otherwise `11`/`10`
- `cookie` — `c` if a Cookie is present, otherwise `n`; `referer` — `r`/`n`
- `nn` — the header count, **excluding Cookie, Referer and every pseudo-header**,
  capped at 99
- `lang` — Accept-Language: hyphens removed, `;`→`,`, lowercased, the first value,
  **the first 4 characters padded with zeros on the right** (`en-US,en;q=0.9` →
  `enus`); none → `0000`
- `_b` = SHA256(the header names in send order, comma-separated), 12 characters
- `_c` = SHA256(the cookie **names**, sorted), 12; `000000000000` if there are no
  cookies
- `_d` = SHA256(the `name=value` pairs, sorted by name), 12

## Akamai HTTP/2

The format: `SETTINGS | WINDOW_UPDATE | PRIORITY | PSEUDO_HEADER_ORDER`

1. **SETTINGS** — `ID:Value` pairs separated by **semicolons**, **in send order**
   (not sorted)
2. **WINDOW_UPDATE** — the connection-level WINDOW_UPDATE increment.
   ⚠ It serialises as `%02d`: **an absent one gives `00`, not `0`**. Hence the
   `|00|` at browserleaks. Some implementations write an empty string there — a
   real disagreement between tools.
3. **PRIORITY** — `StreamID:Exclusive:DepStreamID:Weight` tuples, comma-separated;
   the literal `0` if there are none.
   ⚠ **Weight = wire_value + 1** (RFC 7540: "add one to obtain a weight between 1
   and 256"). The commonest mistake in implementations.
4. **The pseudo-header order** — **the first letter after the colon**, in send
   order, comma-separated: `m`=`:method`, `a`=`:authority`, `s`=`:scheme`,
   `p`=`:path`. Ordinary headers are skipped.

Extended six-section variants exist, but the canonical form is the four-section
one — used by browserleaks, scrapfly, peet, fingerproxy and curl-impersonate.

## Current values

### Chrome 150 / 133 (byte-for-byte identical)
```
1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
akamai_hash: 52d84b11737d980aef856699f885ca86
```
`HEADER_TABLE_SIZE=65536`, `ENABLE_PUSH=0`, `INITIAL_WINDOW_SIZE=6291456`,
`MAX_HEADER_LIST_SIZE=262144`; WINDOW_UPDATE `+15663105` (= 15 MB − 65535); no
PRIORITY; the order `m,a,s,p`.

Chrome ≤119 additionally sent `3:1000` (MAX_CONCURRENT_STREAMS).

⚠ An open question: issue #260 in tls-client claims that a real Chrome sends a
GREASE entry in SETTINGS (`…;6:262144;GREASE|15663105|0|m,a,s,p`), but the
maintainer could not reproduce it on peet. **Check this independently at the
first capture.**

### Firefox 144
```
1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
```
The differences that are easy to miss: `MAX_FRAME_SIZE=16384` is present, the
window is much smaller, the WINDOW_UPDATE differs, **the order is `m,p,a,s`**, the
first HEADERS is on **stream_id 15** (Chrome and Safari use 1), and a `te:
trailers` header is present.

### Safari 26
Sends a **second, empty SETTINGS frame** after the WINDOW_UPDATE, with the keys
`2,3,4,9` (`NO_RFC7540_PRIORITIES=1`), and the order `m,s,a,p`.

### The signature algorithms of Chrome 150+
The list is led by ML-DSA: `0x0904, 0x0905, 0x0906` (= 2308, 2309, 2310) —
ML-DSA-44/65/87. Confirmed independently in four projects (the curl-impersonate
YAML, tls-client's Chrome_150, primp, httpcloak's chrome-152).

Chrome 150 sends ML-DSA **over TCP but not over QUIC** — QUIC's anti-amplification
limits make large PQ certificate chains impractical. So the sigalgs for TCP and
for QUIC are **separate profile fields**.

### Chrome 152
A new extension, `trust_anchors` (0xCA34, draft-ietf-tls-trust-anchor-ids).

## Disagreements between the checking services

Verified on one byte-identical ClientHello:

- **the version in JA3:** browserleaks / peet / ja3.zone / impersonate.pro take
  the legacy `client_version` (`771`); **scrapfly takes the highest from
  `supported_versions` (`772`)** → an entirely different hash. A JA3 from scrapfly
  is comparable with nobody's.
- **the extension count in JA4:** browserleaks says `t13d5911h2`, scrapfly says
  `t13d5909h2` — scrapfly wrongly excludes SNI and ALPN from the **count**. The
  specification says to include them. browserleaks is right.
- **the sigalgs in JA4:** scrapfly sorts them, the specification forbids it.
  browserleaks and peet agree against scrapfly.
- **peet's JA4:** does not zero-pad single-digit counts (`t12d219h1` instead of
  `t12d2109h1`).
- **Akamai HTTP/2:** everybody agrees.

**The conclusion: browserleaks is the reference oracle for the hashes. scrapfly is
useful only for its `capture` field.**

## Licences

- **JA4** (TLS client) — BSD-3-Clause, no patent claims
- **JA4S / JA4H / JA4X / JA4T / JA4SSH** — FoxIO License 1.1, **patent-pending**.
  Free for internal and academic use; commercial monetisation requires an OEM
  licence. This matters here: the library computes JA4H — see
  `internal/fingerprint/ja4h.go`.
