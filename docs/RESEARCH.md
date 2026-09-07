# The existing solutions, analysed

The state of things on 2026-08-31. Everything checked against the sources rather
than blog posts.

## curl-impersonate (lexiforest)

A curl fork linked against BoringSSL. Two patches: `patches/curl.patch` (443 KB)
and `patches/boringssl.patch` (1454 lines).

**How the profiles are stored.** `curl.patch` creates two files:
- `lib/impersonate.h` — 84 lines, a `struct impersonate_opts` with ~45 fields
  (`ciphers`, `curves`, `sig_hash_algs`, `alps`, `ech`, `tls_extension_order`,
  `http2_settings`, `quic_transport_parameters`, `http_headers[32]`, …)
- `lib/impersonate.c` — **2367 lines**, one block of designated initialisers per
  profile

`curl_easy_impersonate()` walks the `impersonations[]` array and calls
`curl_easy_setopt()`.

**What adding Chrome 150 cost** (PR #282, 2026-08-08):
```
84+/2-   patches/curl.patch              ← an entry in impersonations[]
145+/0-  tests/signatures/chrome_150.0.7871.127_macOS.yaml
6+/0-    bin/curl_chrome150
```
And in the same window it also needed: `Bump boringssl version to chrome 150`
(364+/507-), `Add missing mldsa algorithm list to curl` (the new ML-DSA names in
the substitution table), `Rewrite the extension and cipher order functions in
BoringSSL`, and `Add support for quic_cid_length` (a new CURLOPT). That is, **a
full rebuild**.

**Hard compile-time ceilings:**

1. The TLS 1.3 cipher order is compared by `strncmp` against **six** hard-coded
   74-byte prefixes (AESHardware / Firefox / Safari26 / CNSA / NoAESHardware /
   Other) in `ssl/handshake_client.cc`. Everything else falls **silently** back
   to `kCiphersAESHardware`. The least obvious limit of them all.
2. `TLS_EXTENSION_ORDER` is an **allowlist**, not an arbitrary order.
   `ssl_parse_extension_order` resolves every ID against the compiled
   `kExtensions[]` table; an unknown ID is an error. You can reorder and
   suppress; you cannot invent.
3. **GREASE is not patched at all** — `grep -i grease patches/boringssl.patch`
   gives zero hits. `CURLOPT_TLS_GREASE` is only on/off; the positions and the
   values are compiled in.
4. The HTTP/2 **frame** order is exposed by no CURLOPT (the contents of PRIORITY
   are, the order is not).

## curl_cffi

Three levels of runtime fingerprint control:

| Level | Mechanism | Coverage |
|---|---|---|
| 1 | `ja3=` / `akamai=` / `perk=` / `extra_fp=` | ~20 knobs, legacy, lossy |
| 2 | `curl_options={CurlOpt.X: v}` | any non-standard CURLOPT (~45) |
| 3 | `impersonate=Fingerprint(...)` | the whole profile as data, 1:1 with the C struct |

A common misconception: `extra_fp` is the weakest of the three, with just **15
fields**. ALPS, ECH, cert compression, the extension order, the key_share limit
and the PQ curves are absent from it, though available through levels 2 and 3.

**`ja3=` — the traps:**
- only `771` (TLS 1.2) is accepted — a bare `assert`, which disappears under
  `python -O`
- the extension list is applied **only if `permute` is False**; setting
  `extra_fp["tls_permute_extensions"]` silently throws your whole order away
- `akamai=` forces HTTP/2, overriding an `http_version=` set earlier

**The order of application** matters: `impersonate` → `ja3` → `extra_fp` →
`akamai` → `perk` → `curl_options`. `extra_fp.tls_min_version` overwrites the
`SSLVERSION` just set from `ja3`.

**The data path and its price.** `FingerprintManager` loads
`~/.config/impersonate/fingerprints.json` (on Windows:
`%APPDATA%\impersonate`), fetching it from
`https://api.impersonate.pro/v1/fingerprints` under an `IMPERSONATE_API_KEY`. The
profiles are applied by ~40 `setopt` calls — **with no C involved**. But
`docs/fingerprints.rst` says: open source gets its updates "on major releases",
and frequent updates are a commercial tier.

**Known type bugs:** `form_boundary: Optional[bool]` is in fact a string option
(`"webkit"`/`"firefox"`); `tls_cert_compression: Literal["zlib","brotli"]` — the C
side also accepts `zstd` and comma-separated lists.

## uTLS (refraction-networking)

The key find: **`ClientHelloSpec` speaks JSON natively.**

```go
type ClientHelloSpec struct {
    CipherSuites       []uint16
    CompressionMethods []uint8
    Extensions         []TLSExtension
    TLSVersMin         uint16
    TLSVersMax         uint16
    GetSessionID       func(ticket []byte) [32]byte
}
```

The methods: `FromRaw(raw []byte)`, `UnmarshalJSON()`,
`ImportTLSClientHelloFromJSON()`. The names resolve through `dicttls` (137
extension names), so a profile is readable by eye. The tests assert
`reflect.DeepEqual` between a JSON-loaded spec and the compiled parrot for
Chrome 102, Firefox 105, iOS 14 and Edge 106.

**The gaps in the JSON path** (Go code needed):
| Gap | Consequence |
|---|---|
| ECH: `GREASEEncryptedClientHelloExtension` has no `UnmarshalJSON`, and `0xfe0d` is **absent** from `dicttls` | JSON fails with `ErrUnknownExtension`. Chrome 120/131/133 cannot be reproduced from JSON in full |
| `QUICTransportParametersExtension` has no `UnmarshalJSON` | QUIC/H3 profiles do not load from JSON |
| `GetSessionID` is a function | not data by nature |

Interestingly **`FromRaw` does handle ECH**
(`ExtensionFromID(utlsExtensionECH)` returns a working type with `Write`) — so
capture works where JSON does not.

**`Fingerprinter`** — 75 lines, `u_fingerprinter.go`:
```go
f := &tls.Fingerprinter{AllowBluntMimicry: false, RealPSKResumption: false}
spec, err := f.RawClientHello(raw)   // raw begins with 0x16, record header included
```
GREASE is normalised to `0x0a0a` and re-randomised at `ApplyPreset` — the
positions are kept, the values are not. That is the right behaviour.

`AllowBluntMimicry` wraps an unknown extension in a `GenericExtension` and
**reproduces the captured bytes verbatim** — that is, a stale key_share or session
ticket. Use with care.

**Versions.** `HelloChrome_133`, `HelloFirefox_148` and `HelloSafari_26_3` are in
master, but **`HelloFirefox_148` and `HelloSafari_26_3` are not tagged**. `go get
v1.8.2` gives `HelloSafari_Auto = HelloSafari_16_0` — a parrot from 2022. Pin a
commit.

**`ShuffleChromeTLSExtensions` mutates the slice in place** and is called inside
the spec constructor. Cache the spec and you have frozen the order across every
connection, which is an anomaly in itself.

**uTLS does not go above the ClientHello** — its README says so directly. HTTP/2
needs a fork.

## fhttp (bogdanfinn) — a fork of x/net/http2

In the stock `golang.org/x/net/http2` all four components of the Akamai
fingerprint are hard-coded: `initialSettings` is assembled as a fixed slice, the
WINDOW_UPDATE comes from the constant `transportDefaultConnFlow` (1 GB − 65535,
nothing like Chrome's 15663105), PRIORITY is never sent, and the pseudo-headers
are written in Go's order (`:authority, :method, :path, :scheme` against Chrome's
`:method, :authority, :scheme, :path`).

fhttp adds exactly the missing knobs to `http2.Transport`:
```go
InitialStreamID   uint32
ConnectionFlow    uint32          // → the WINDOW_UPDATE increment
HeaderPriority    *PriorityParam  // → PRIORITY on the HEADERS frame
Priorities        []Priority      // → standalone PRIORITY frames
PseudoHeaderOrder []string
Settings          map[SettingID]uint32
SettingsOrder     []SettingID
```
Plus the sentinel keys `HeaderOrderKey` and `PHeaderOrderKey` in `http.Header`,
for the ordinary and pseudo-header order at the request level.

## bogdanfinn/tls-client — what to avoid

The profiles are Go literals (`profiles/*.go`, ~180 KB) on top of a **personal
uTLS fork** that is rebased about once a year (the fork's last commit
2026-01-10, upstream's 2026-08-02).

The chain for one new Chrome: capture → write the Go spec by hand → PR → merge →
tag a release → rebuild the shared libraries for 8 platforms. **Each of those
five steps got stuck at least once during 2026.**

The symptoms on 2026-08-31:
- `DefaultClientProfile = Chrome_150`; Chrome 152 has been sitting in open PR
  #265 since 26 August
- the Chrome 150 fix (ML-DSA) was merged on 2026-07-02 but **reached no tagged
  release** — the downloadable artefacts still hand out the pre-quantum signature
- the HTTP/3 fingerprint exists for only 5 profiles out of ~40; the default
  `Chrome_150` does not have one
- issue #260: the SETTINGS are missing the GREASE entry a real Chrome sends. The
  maintainer: *"when I run a request against peets api with a real chrome i do not
  see the GREASE in the http2 fingerprint"* — PR #261 is unmerged
- issue #130 "Add ja4" has been open since 2024-08-18, two years
- regression #191: the PSK silently dropped out of the ClientHello for ~6 months,
  so the `*_PSK` profiles were giving the wrong resumption fingerprint all that
  time

The conclusion: the "profiles in compiled code" architecture falls apart
structurally, not through any laziness of the maintainer.

## sardanioss/httpcloak — our reference

MIT, created 2025-12-28, very active (12 commits in a week). It solved exactly our
problem.

**Three levels of profile storage:**
1. Go literals in `fingerprint/presets.go` (145 KB) — the base presets with real
   bytes
2. `//go:embed embedded/*.json` — 36 files, Chrome 147–152 × 5 platforms, Firefox
3. a runtime registry, a `sync.Map` with `Register`/`LookupCustom`

**The inheritance mechanics** — the whole of `Chrome152Windows()`:
```go
func Chrome152Windows() *Preset {
	if p := LookupCustom("chrome-152-windows"); p != nil {
		return p
	}
	return Chrome151Windows()
}
```
The chain falls through to the last full Go literal (currently Chrome 146 for the
desktop). A comment in `embedded.go` explains the intent: *"New monthly Chrome
versions (which are usually pure header diffs over the previous version's TLS
fingerprint) can be added without a Go-code change by dropping a JSON file"*.

**The FFI:** `bindings/clib/httpcloak.go` — 130 KB, **102 functions with
`//export`**.
```bash
CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="-s -w" \
  -o "$DIST_DIR/libhttpcloak-${os}-${arch}${ext}"
```
Python: `bindings/python/httpcloak/client.py` (206 KB) loads it through
`ctypes.cdll`, and the wheels put the binary in through
`[tool.setuptools.package-data] httpcloak = ["lib/*"]`. There is no daemon —
direct FFI.

The comparison with tls-client (6 exports against 102, Go literals against JSON
overlays, Chrome 150 against 152) shows how much the profile model affects the
speed of catching up with browsers.

## wreq / rquest / rnet (Rust)

`0x676e67/wreq` → a fork of `penumbra-x/rquest` → the Python wrapper `rnet`
through PyO3. The profiles live in `wreq-util`: **the widest version coverage of
all** — Chrome 100–149, Firefox 109–151, Safari 15–26, Edge 101–148.

The fingerprint quality is no worse, but there is no equivalent of
`utls.Fingerprinter` (learning a profile from a capture), and the profiles are
Rust code as well. For our purpose it loses.
