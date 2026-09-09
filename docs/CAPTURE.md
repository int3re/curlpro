# Capturing a reference fingerprint

The recipe for "a new Chrome came out, a profile is needed". The commands were
checked on Windows/Git Bash.

## The quick way: take one that exists

Before capturing anything, check whether a ready-made signature already exists:

```
https://raw.githubusercontent.com/lexiforest/curl-impersonate/main/tests/signatures/<name>.yaml
```

**43 files**, Chrome 98→150 (including android and a split by OS), Safari
15.3→26.0.1 (including iOS), Firefox 133/135/144, Edge 98–120, Tor 14.5. One
usually appears within a few days of a browser release.

The structure of each file: `browser{name,os,version}`,
`signature.options.tls_permute_extensions`, `signature.http2.frames[]`
(SETTINGS/WINDOW_UPDATE/HEADERS with `pseudo_headers` and the full ordered header
list), `signature.tls_client_hello{ciphersuites, comp_methods, extensions[] with
decoded fields, handshake_version, record_version, session_id_length}`,
`third_party{akamai_hash, akamai_text, ja3_hash, ja3_text, ja3n_hash, ja3n_text,
user_agent}`.

Caveats:
- with `tls_permute_extensions: true` (Chrome) the `extensions:` list is **one
  observed permutation**; only JA3N is stable. Firefox and Safari files have no
  `options` block — their order is fixed and authoritative.
- `curlpro capture` derives `permute_extensions` from the samples: if the
  extension order (with GREASE reduced to a marker) differs in at least two
  samples it is `true`, otherwise `false`. At least two samples are needed; the
  field used to be written as `true` always, and a captured Firefox came out with
  a shuffling profile.
- the Safari files have **no `third_party:` block** — there will be no ready-made
  JA3
- `4588` = `0x11EC` = X25519MLKEM768 (Chrome 124–130 used `25497` =
  X25519Kyber768Draft00)
- ⚠ **`browsers.json` is a stale build manifest** (`{name, browser, binary,
  wrapper_script}`) with **zero** fingerprint data in it. Do not use it. The live
  list of targets is `docs/fingerprints.rst`.
- the project's documentation notes: *"Chromium-based browsers all share the same
  fingerprints, except for `User-Agent` and `sec-ch-ua-platform`"* — Edge, Brave
  and Opera need no TLS profile of their own.

## The full way: capture it yourself

### 1. The stand

`echo-server` from the [wi1dcard/fingerproxy](https://github.com/wi1dcard/fingerproxy)
releases — that one, not the proxy itself.

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
  -nodes -keyout tls.key -out tls.crt -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

./echo-server -listen-addr localhost:8443 -verbose
```

The endpoints:
- `GET /` — text: the User-Agent, the full ClientHello record in hex, JA3, JA4,
  the HTTP/2 fingerprint
- `GET /json` — `{"ja3":…,"ja4":…,"http2":…}`
- **`GET /json/detail`** — the important one.
  `detail.metadata.ClientHelloRecord` in base64 (the raw TLS record), the full
  `ConnectionState`, the `HTTP2Frames` structure (`Settings[]`,
  `WindowUpdateIncrement`, `Priorities[]`, `Headers[]` in wire order), and the
  parsed `ja3`/`ja4` objects with `ReadableCipherSuites`,
  `ReadableAllExtensions`, `ReadableSupportedGroups`,
  `ReadableSignatureAlgorithms`, `ja3_raw`.

One `/json/detail` response is enough to compose a profile.

⚠ Go canonicalises header names, so the backend sees `X-Ja3-Fingerprint`,
`X-Ja4-Fingerprint`, `X-Http2-Fingerprint` — compare them case-insensitively.
fingerproxy deliberately does **not** compute JA4H (its README: "Do not do it in
the reverse proxy").

### 1b. The stand for header order: cmd/hcapture

`echo-server` shows the HTTP/2 HEADERS frame but not the HTTP/3 one, and it
cannot serve a page that runs a `fetch` of its own. Hence a stand of ours:

```bash
go run ./cmd/hcapture -auto              # TLS + ALPN h2, the browser starts itself
go run ./cmd/hcapture -auto -h3          # plus QUIC, Chrome is moved onto HTTP/3
go run ./cmd/hcapture -h3                # without a browser: open the address by hand
```

The stand parses HEADERS by hand — HPACK for HTTP/2, our own `internal/qpack` for
HTTP/3 — and prints the names in wire order. The page performs a `fetch`, an XHR
and a link navigation, so one run captures both header sets, the navigational one
and the fetch one. A cookie is set on the first page: its position in the set was
a guess too.

Two traps, each of which cost a run:

- **Chrome reaches `localhost` over `::1`.** A listener bound only to
  `127.0.0.1` receives not one datagram.
- **`--ignore-certificate-errors` does not apply to QUIC.** Chrome sends the
  datagrams and drops the handshake silently. What is needed is
  `--ignore-certificate-errors-spki-list` with the stand key's fingerprint;
  hcapture computes it itself from `capture/certs/tls.crt`.

Chrome 152 was captured on both transports with this stand — see
[STAGE16-RESULTS.md](STAGE16-RESULTS.md).

**Capturing from a phone over USB.** `adb reverse tcp:8443 tcp:8443` — and the
phone sees the stand as `localhost`, so the stand's certificate with a localhost
SAN will do, and the browser is brought by a command:

```bash
adb shell am force-stop com.android.chrome
adb shell am start -a android.intent.action.VIEW -p com.android.chrome \
  -d https://localhost:8443/json/detail
```

The browser process has to be killed between samples: otherwise the connection is
reused, every sample gives the same ClientHello, and there is nothing to derive
`permute_extensions` from. `chrome-152-android` and `yandex-26.8-android` were
captured this way.

Two corrections to a profile captured like that. A launch by intent counts to the
browser as a navigation from another site, so the capture contains
`sec-fetch-site: cross-site` and no `sec-fetch-user` — for the profile they must
be brought to a typed-address navigation (`none` and `?1`). And `sec-ch-ua` and
the languages stay as they were on the measuring device.

**HTTP/3 cannot be captured from someone else's device with your own
certificate.** For QUIC Chromium requires the chain to lead to a publicly known
root and does not accept a locally installed CA — that is how it defends itself
against corporate interceptors, which do not speak QUIC. Over TCP the same
certificate passes without complaint, the page opens with a padlock, and QUIC
closes at once:

```
QUIC_SESSION_CLOSED: TLS handshake failure (ENCRYPTION_HANDSHAKE)
46: certificate unknown … CERTIFICATE_VERIFY_FAILED
```

(taken from Yandex Browser 26.8 on a Pixel 7 through `browser://net-export/`.)
On your own machine this is worked around with
`--ignore-certificate-errors-spki-list`, which does not exist on Android. Two
paths remain: a publicly trusted certificate for a name that points at a local
address, or measuring the same browser on a workstation — the HTTP/3 layer is set
by the Chromium version, not by the platform.

Usefully incidental: Chromium remembers a QUIC address that failed and stops
knocking on it for a while (`ALT_SVC_FOUND … "is_broken": true`). The mark is
attached to the host-and-port pair, so the next attempt has to be made on another
port, or the browser will not even send a datagram.

### 2. Point the browser at it

**SNI affects JA4** — this is measured:

| Target | SNI | JA4 |
|---|---|---|
| `https://localhost:8443` | `localhost` | `t13d**15**16h2_8daaf6152771_806a8c22fdea` |
| `https://127.0.0.1:8444` | none | `t13**i**15**15**h2_8daaf6152771_806a8c22fdea` |

Connecting by a bare IP changes `d` to `i` **and** drops the extension count from
16 to 15. The `_b` and `_c` hashes match, because JA4 excludes SNI and ALPN from
the hashed lists.

For byte-exact realism:
```bash
chrome --host-resolver-rules="MAP www.example.com 127.0.0.1:8443" \
       --user-data-dir=/tmp/p1 https://www.example.com
```
(this needs no administrator rights, unlike editing `hosts`)

**At least 5 runs** — see the section on shuffling.

### 3. The raw ClientHello bytes through tshark

```bash
export PATH="$PATH:/c/Program Files/Wireshark"

tshark -i 9 -f "tcp port 443" -a duration:25 -w /tmp/ch.pcapng

tshark -r /tmp/ch.pcapng -Y "tls.handshake.type == 1" \
  -T fields -e tcp.reassembled.data -e tcp.payload \
| awk -F'\t' '{print ($1 != "" ? $1 : $2)}' \
| head -1 | tr -d ':\n' | xxd -r -p > /tmp/ch.bin
```

⚠ **Three pitfalls:**

1. `-e tls.handshake` and `-e tls.record` are of type `FT_NONE` — they print `1`,
   not bytes.
2. **`-e tcp.payload` is wrong for a modern browser.** Measured on Chrome 151:
   the ClientHello is 1766 bytes in one TLS record spread over two TCP segments,
   because the post-quantum key_share `X25519MLKEM768` alone takes ~1216 bytes.
   `tcp.payload` returns only the last segment (366 bytes) — a silent truncation.
   `tcp.reassembled.data` is what is needed.
3. `-E occurrence=a` is **mandatory** when extracting lists, or only the first
   value is printed.

An integrity check: `len(bytes) == 5 + 4 + tls.handshake.length` (verified:
`1766 == 5 + 4 + 1757`).

The bytes begin with `16 0301 06e1 01 0006dd 0303…` — exactly the format
`utls.Fingerprinter` expects; nothing needs trimming.

**Wireshark computes JA3 and JA4 itself** (in a stock 4.4.6, without plugins):
```
tls.handshake.ja3, ja3_full, ja3s, ja3s_full   (since 3.6.0)
tls.handshake.ja4, ja4_r                        (since 4.2.0)
```
`-e tls.handshake.ja4_r` gives the normalised (sorted, GREASE-free) lists of
ciphers, extensions and sigalgs in one line. For building a profile that is the
most convenient form. `ja4_o`/`ja4_ro` and JA4H/S/X/T need the FoxIO plugin
(`ja4.dll` in `plugins\4.4\epan\`).

### 4. HTTP/2 through SSLKEYLOGFILE

The ClientHello is in the clear and always visible — no keys are needed for it.
**But the Akamai fingerprint and the header order live inside the encrypted
stream.**

```bash
export SSLKEYLOGFILE="C:\\Users\\$USERNAME\\AppData\\Local\\Temp\\sslkeys.log"
"/c/Program Files (x86)/Google/Chrome/Application/chrome.exe" --user-data-dir=/tmp/p1 https://…
"/c/Program Files/Mozilla Firefox/firefox.exe" -no-remote -profile /tmp/ffp1 https://…
```
⚠ Chrome must have **no running instance** — otherwise it hands the URL to the
existing process, which never saw the variable. Always a throwaway
`--user-data-dir`. Firefox needs `-no-remote`.

### Chrome for Testing is not a substitute — measured 2026-09-09

The obvious way to automate capture is to download the exact version from
[Chrome for Testing](https://googlechromelabs.github.io/chrome-for-testing/):
2506 builds are published there, per platform, so "Chrome 153 shipped, capture
it" needs no browser on the machine. It was measured before being trusted, and
it does not hold.

Consumer Chrome 152.0.7977.83 and Chrome for Testing 152.0.7977.82 were captured
on the same machine, the same day, through the same stand. Five runs, three of
CfT and two of consumer, each internally consistent:

```
consumer  t13d1517h2_8daaf6152771_cb7bf5808d99   17 extensions
CfT       t13d1518h2_8daaf6152771_4980c97edce0   18 extensions
```

The lists are identical but for one entry: CfT also sends **`0x12e0`**, which no
consumer Chrome does. It is there in every CfT run and in none of the consumer
runs, so it is not noise.

The consumer capture reproduced `profiles/chrome-152-windows.json` exactly —
the profile shipped in the library, captured weeks earlier. So the stand is
sound and the divergence is the browser's.

A profile built from CfT would therefore carry an extension no real user sends:
not a profile that is one version behind, but one that is confidently wrong,
and wrong in a way that singles out every client using it. **Capture from the
browser people actually run.** Google's own apt/choco/brew channels give exactly
that, and a fresh throwaway user-data-dir does not change the result — the
consumer captures above used one.

Two practical notes from the same session, both of which cost a run:

- **The unpacked browser needs the sandbox to be able to read it.** Files
  extracted by a script inherit the parent directory's ACL, and Chrome fails
  with `Sandbox cannot access executable`, after which the network service
  crashes in a loop and only some of the samples arrive. On Windows:
  `icacls <dir> /grant "*S-1-15-2-1:(OI)(CI)(RX)" /T`. Running with
  `--no-sandbox` would also work and is the wrong fix — it changes the browser
  being measured.
- **A cold browser needs longer than a warm one.** `-dwell` sets how long each
  window stays open; the default of 4 s is enough for an installed browser and
  too short for one just unpacked.

`curlpro capture` picks the browser from the family in `-name`, so
`-name firefox-154-windows` looks for Firefox and starts it with Firefox's own
switches. An explicit `-browser` still has to agree with the name: a profile
called firefox-154 built from a Chrome connection is not a weaker profile but a
false one, and nothing downstream can tell. Firefox has no equivalent of
`--ignore-certificate-errors`, so the stand's self-signed certificate stops at
an interstitial: the ClientHello is captured, the headers are not. Click through
it once, or use `-manual`.

```bash
tshark -r h2.pcapng -o "tls.keylog_file:$KL" -Y "http2.type==1" \
  -T fields -e http2.header.name                     # the pseudo- and ordinary header order

tshark -2 -r h2.pcapng -o "tls.keylog_file:$KL" -Y 'http2.type==8' \
  -T fields -e http2.window_update.window_size_increment    # -> 15663105
```
⚠ `-2` (two passes) is mandatory for WINDOW_UPDATE, or the output is silently
empty. `-e http2.settings.id` is broken in 4.4.6 — use `-V | grep`.

### 5. A raw TCP listener (the fallback)

Read 5 bytes → check for `0x16`, the legacy version (in practice `0x0301`, **not**
`0x0303`), a 2-byte big-endian length → read exactly that many. A loop over the
length is structurally immune to the segmentation problem.

The handshake will fail (there is no ServerHello) — which does not matter, the
ClientHello is already on the wire. Chrome does **not** retry-downgrade on a clean
reset, so one connection is one clean sample.

### 6. Bytes into a spec

```go
f := &tls.Fingerprinter{AllowBluntMimicry: false, RealPSKResumption: false}
spec, err := f.RawClientHello(raw)      // raw begins with 0x16
```
It is then worth diffing against `utls.UTLSIdToSpec(tls.HelloChrome_133)` — that
shows at once what changed between versions.

### 7. Validation

Replay the spec against `tls.browserleaks.com/tls` and compare `ja3n_hash`, `ja4`
and `akamai_text` with what the real browser produced.

Additionally: `tls.tlsfingerprint.io/api/tls/fingerprints/{norm_hex_id}/exists` —
confirms that such a fingerprint occurs in real traffic at all.

## Browser behaviour that breaks a naive capture

**Extension shuffling (Chrome 110+).** Five consecutive connections:
```
5 different JA3:  d727c155…, b19d37c7…, c6250e25…, 7ec443df…, 638be043…
1 identical JA4:  t13d1516h2_8daaf6152771_806a8c22fdea  (all five)
```
The sorted extension sets are identical. **Never build a profile from a single
Chrome capture — that order is noise.** Firefox does not shuffle; one capture is
enough for it.

**GREASE.** The values observed: `0xCACA, 0x2A2A, 0x9A9A, 0x6A6A, 0x4A4A, 0xBABA,
0xAAAA, 0x3A3A` — the RFC 8701 pattern `0x?A?A`. The values are random, **the
positions are not**: Chrome always puts one GREASE first and one last. It is also
present in the ciphers, supported_groups, supported_versions and key_share.

**The ClientHello length is unstable even with an identical JA4** — GREASE-ECH
(`0xfe0d`) pads in steps of 32 bytes. Only the normalised structure is stable. Do
not "fix" this with `--disable-features=PostQuantumKyber` — a real Chrome does not
send that.

## Public endpoints

| Endpoint | Status | What it gives |
|---|---|---|
| **`tls.browserleaks.com/json`**, **`/tls`** | ✅ the reference | `ja4, ja4_r, ja4_o, ja4_ro, ja3_hash, ja3_text, ja3n_hash, ja3n_text, akamai_hash, akamai_text`. `/tls` adds a parsed `tls{}` plus the ECH status. **The only source of JA4_o/JA4_ro.** The most specification-faithful JA4 |
| `tls.peet.ws/api/all` | ✅ | The only one that returns **TCP/IP and p0f**. Its JA4 does not zero-pad the counts |
| `tools.scrapfly.io/api/fp/anything` | ✅ h2 only | The **`capture` field = base64(gzip(JSON))**, which unpacks into a ready uTLS `ClientHelloSpec`. The best find — an immediately reproducible spec rather than a hash |
| `tools.scrapfly.io/api/fp/ja3` | ✅ | Its JA3 is comparable with nobody else's (see FINGERPRINT-SPEC.md) |
| `fp.impersonate.pro/api/http2` | ✅ | The most detailed h2 frame breakdown: `settings[], window_updates[], priority, headers_frame.flags[], header_order[]`. There is an `/api/http3`. No JA4 |
| `tls.tlsfingerprint.io/api/client-fingerprint` | ✅ | A full parse plus `num_id/hex_id` and `norm_num_id/norm_hex_id`. ⚠ the `tls.` subdomain specifically — without it, 404 |
| `check.ja3.zone/json` | ⚠ unstable | JA3 and its hash only |
| `ja3er.com` | ❌ **dead** | DNS resolves, TCP :443 and :80 time out. Down since ~2022 |
| `ja4db.com/api/read/` | ❌ | 301 → `ja4db.foxio.io`, the bulk endpoint returns 403, an account is needed |

⚠ On `tls.peet.ws` the paths `/api/http2`, `/api/ja3`, `/api/ja4` and
`/api/request-info` return **HTTP 200 with an HTML 404 body** — checking the
status code will mislead. The working ones are `/api/all`, `/api/tls`,
`/api/clean`.

## What to diff in the Chromium sources

`net/socket/ssl_client_socket_impl.cc` is the primary source:
```cpp
std::string command("ALL:!aPSK:!ECDSA+SHA1:!3DES");
static const uint16_t kVerifyPrefs[] = {
    SSL_SIGN_ML_DSA_44, SSL_SIGN_ML_DSA_65, SSL_SIGN_ML_DSA_87,
    SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256, … };
SSL_set_permute_extensions(ssl_.get(), 1);
SSL_CTX_set_grease_enabled(ssl_ctx_.get(), 1);
SSL_set_enable_ech_grease(ssl_.get(), 1);
SSL_set_alps_use_new_codepoint(...);
```
The cipher list is **not in Chromium** — it passes a string and lets BoringSSL
decide the order. A full diff also needs `boringssl/ssl/ssl_cipher.cc` (the
`kCiphers[]` order), `boringssl/ssl/ssl_key_share.cc` plus `net/ssl/ssl_config.cc`
(the groups and key_share — that is where Kyber switched to ML-KEM), and
`net/spdy/spdy_session.cc` plus `net/http/http_network_session.cc` (the H2
SETTINGS and WINDOW_UPDATE).

## Other profile corpora

| Source | TLS | H2 | Header order | By version | Note |
|---|---|---|---|---|---|
| `lexiforest/curl-impersonate` signatures | ✅ | ✅ | ✅ | ✅ | **the best — everything together, machine-readable** |
| `0x676e67/wreq-util` | ✅ | ✅ | ✅ by OS | ✅ | **the widest version coverage** |
| `sardanioss/httpcloak` `fingerprint/embedded/*.json` | ✅ | ✅ +H3 | ✅ | ✅ | **the best schema** — the `based_on` delta model |
| `refraction-networking/utls` `u_parrots.go` | ✅ | ❌ | ❌ | ✅ | TLS only, 3526 lines |
| `bogdanfinn/tls-client` | ✅ | ✅ | pseudo only | ✅ | Go structures, lags behind |
| `deedy5/primp` | ✅ | ✅ | ✅ | ✅ | Rust, Chrome 144–152, has ML-DSA and ECH |
| `tlsfingerprint.io` | ✅ | ❌ | ❌ | labels | 3.37M fingerprints, but **no bulk export** |
| `browserforge` | ❌ | ❌ | ✅ | by name | **zero TLS data** (checked by grep). The header order is by browser name rather than by version. The data moved to `apify/fingerprint-suite` |
| `salesforce/ja3` | hashes | ❌ | ❌ | ❌ | **archived 2025-05-01** |
| FoxIO `ja4plus-mapping.csv` | hashes | ❌ | ❌ | ❌ | 66 rows, 4 of them browsers without versions — useless |
