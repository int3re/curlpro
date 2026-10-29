# Releasing a version

The package is built and published by the
[.github/workflows/wheels.yml](../.github/workflows/wheels.yml) workflow, on a
`v*` tag.

The first release was **0.2.0, 5 September 2026**:
[pypi.org/project/curlpro](https://pypi.org/project/curlpro/). The current one is
**0.20.0** — a minor: the client hints are Chrome's whole. A session answers
every hint a desktop Chromium answers — the machine (`device-memory`, `dpr`,
the viewport), the network (`rtt`, `downlink`, `ect`, with Chromium's per-site
noise) and the preferences (`sec-ch-prefers-*`) — a navigation in the browser
process's sequence, and a page's request (fetch, XHR, a subresource) laid out
the way Blink's header map hands it to the network stack: rapidhash over the
case-folded name, WTF's table, the caller's own headers placed where Chrome
places them (88 requests of Chrome 155 and 156, all in the model's order).
Hints come from a top-level navigation's `Accept-CH` only, go to other origins
as the page's `Permissions-Policy` delegates them, and into frames in the
navigation sequence (Chrome 156 with a delegating policy, matched). The values
are the device's: every pooled identity names its machine — the 46 phones
their screens, scale factors and memory, a navigation on a phone reporting the
viewport scaled to 980 wide, Macs by CPU — and the network is Chromium's own
default for the connection. `chrome-156-android` is derived on the captured
Chrome 156 (Chrome 152 for Android had sent the desktop's hello). 318
profiles, 48 captured. ABI 0.29.0: device fields an older library refuses.
Before it, **0.19.0** — a minor: what goes on the wire changed again, measured each time. A
Firefox profile now takes an origin's ECH configuration too, with NSS's inner
hello (measured against Firefox 159 on `cmd/echstand`); HTTP/3 carries ECH, so an
ECH origin with an h3 record goes to HTTP/3 (Chrome 156 over QUIC, matched — and
`supported_versions` compressed there, as BoringSSL does for a TLS 1.3-only
outer); a Chromium connection resumes inside ECH (the PSK in the inner hello
alone, Chrome 156's resumed hello matched); DoH requests are each browser's own
to the bytes of the query (ID 0, EDNS padding to 128, Firefox's no-address ECS,
its anonymous GET). A guessed QUIC connection is raced against TCP as Chrome's
JobController races them; HTTP/3 asked for outright travels through a SOCKS5
proxy that relays UDP (UDP ASSOCIATE). The profile corpus is published between
releases as a bundle signed with Ed25519 that `curlpro.update_profiles()`
fetches, checks and loads; `s.browser()` acts on its tab through `b.page`
without a trace (trusted input, an isolated world, never `Runtime.enable`). The
multipart boundary is Blink's table again (the `+` and `/` of the old one broke
strict parsers) and Firefox 135's `----geckoformboundary` for Firefox 135+.
Data: Chrome 156 (the default now), Firefox 159 and Opera 139 captured; Chrome
157 and Edge 156 derived; 317 profiles, 48 captured. Wheels: Windows on ARM64
added; no musl wheel (golang/go#54805). ABI 0.28.0: the bundle loader is a new
native function. Before it, **0.18.0** — a minor, because what goes on the wire changed without anyone
asking: a Chromium 108+ or Firefox 133+ session asks DNS for the origin's HTTPS
record (RFC 9460) before it connects, as those browsers do, and acts on it — an
`alpn=h3` record sends the first request to HTTP/3, and on a Chromium profile an
`ech` record makes the ClientHello real ECH (RFC 9849), its inner hello
BoringSSL's, measured against Chrome 155 on the new `cmd/echstand` and matched
field for field (`scripts/patch-utls.py` carries it on the vendored uTLS); a
rejection with retry configurations is retried once, as Chrome; a network
that drops ECH (Russia's does, to every Cloudflare site) gets one more
connection without it, where Chrome would fail, and the process leaves that
public name alone for ten minutes. `dns=` takes
servers or DNS over HTTPS, with Chrome's own DoH request; behind a proxy nothing
is resolved locally. Beside it: Firefox 158 captured; `image/jxl` in the Accept
of Chrome 155's documents and images and Firefox 158's images, measured; the
derived Chrome 155/156 for macOS and Linux on the captured Chrome 155; Chrome
152/153's trust_anchors drawn once per session, as each browser process did. Not
yet: ECH over QUIC (an ECH origin stays on TCP), resumption inside ECH,
Firefox's inner hello. ABI 0.27.0: `dns` is configuration an older library
would ignore, and `trust_anchors_order` does not load into one. 310 profiles.
Before it, **0.17.1** — a patch, from one field report and the re-checks it set off; every
change is to what a profile sends, each now matching the browser measured on a
bare socket and the browser's own source at its release tags. The report took
`firefox-155/156/157` — fifteen ciphers, Chrome's cipher hash in JA4, Gecko's
order — for a hello no browser sends; Firefox itself turned 0xc009 off in 151
and 0xc00a in 154, and Firefox 157.0.1 sent exactly that hello, field for field.
The same reading found `firefox-151-*` with 150's seventeen ciphers; they send
151's sixteen. In Chrome two things were wrong: the trust_anchors list, which
Chrome's root store cut from 32 to 28 in 153 and Chromium never permutes
(sorted bytewise from 154), went out as 152's 32 in a new order per connection
from every profile since 153; and the GREASE ECH length, which BoringSSL draws
from four per connection, stayed the one a capture caught on every replayed
Chromium profile (151 and later, Android 152, Edge 153/154, Opera 136). Now
`chrome-155-windows`, the default, matches Chrome 155.0.8059.40 field for field.
`curlpro capture` writes a capture's own trust_anchors list. 18 distinct JA4.
ABI 0.26.0, the native library rebuilt.
Before it, **0.17.0** — a minor, because what goes on the wire changed without anyone
asking: a session that names no profile is `chrome-155-windows`, captured live
on 2026-10-10, where it was `chrome-151-windows`, and a desktop Chromium
profile without `device=` answers `Accept-CH` with its version's newest build
(155.0.8059.40) instead of the first (155.0.8059.12), a build Chrome's own
updater leaves few users on. Beside them, proxies: an `https://` proxy is
greeted with the profile's own ClientHello, where Go's said "Go" before
anything else was sent (13 ciphers, 10 extensions, no ALPN), and tunnelled
over HTTP/2 when it offers `h2` — every tunnel a stream on one connection, with
Chrome's priorities, where each had paid a handshake; `masque://` is a proxy
reached over HTTP/3, the only kind that carries `http3=True` to the target —
CONNECT and CONNECT-UDP as Chrome writes them, its packet sizes, checked
against the Chromium source. Every redirect hop keeps its own response
headers (`r.history[0].header("set-cookie")`), where only the jar remembered
them. In the corpus, `chrome-155-windows` and `firefox-157-windows` captured
(155's hello, frames and header order are 153's; 157 differs from 156 only in
the User-Agent), Chrome 156 and the macOS and Linux Chrome 155 derived and
marked, the identity pools on every 154 build to .100 and on 155 and 156: 309
profiles, 44 captured whole, 13 derived. `curlpro capture` trusts the stand in
Firefox by itself, keeps a parent's measured header order when a capture
agrees with it, and refuses a parent that is not measured. ABI 0.26.0: the
redirect headers are a field Python reads, which an older library leaves
empty without a word.
Before it, **0.16.0** — a minor for what it adds: `gpu="high-performance"` on
`BrowserSolver`, `s.browser()` and `curlpro.browser.Chrome` runs the browser on
the discrete GPU of a dual-GPU machine, through Chromium's own
`--force-high-performance-gpu`, which works on Windows too. Measured on a
laptop with an Intel Iris Xe and an RTX 4050: of 368 values a page reads, 17
moved — the WebGL renderer strings, four uniform limits, every drawn pixel —
and nothing else; each card is a whole, real identity. And a fix: about one
Chrome in twenty took ~10 s to exit and some outlived the kill, and `close()`
then raised `TimeoutExpired` out of `__exit__` — a solve that had passed
reached the caller as that exception. A browser slow to die is now left to
die, its profile removed at exit. Python only, ABI 0.25.0.
Before it, **0.15.2** — a patch, from one field report (a Qrator solver for
`login.mts.ru`, ported from curl_cffi). `list_profiles()` answered `[]` in a
fresh process, the one profile function that did not load the bundled set
first — so `name if name in list_profiles() else default` sent every
User-Agent to the default, a ClientHello of the wrong version. `r.challenge`
knows Qrator, by the rules the report measured on the wire, and tells a 403
that is a verdict (`X-Qrator-Validate-Result`) from a bare one that is not
(`kind="no-verdict"`: what was sent could not be read). A header value is
still the list of values, and now also equal to and printed as the string
requests gives, so ported `r.headers.get(name) == "captcha"` is true when it
should be; converted on first read, at no cost to building a response.
`AsyncSession` names itself for an unknown argument. Python only, ABI 0.25.0.
Before it, **0.15.1** — a patch: `BrowserSolver().session_options()` failed once the
installed Chrome was a build the profile's device list did not have — Chrome
154.0.8037.93 arrived overnight on a machine whose profile knew builds up to
.58, and every solver session failed with `ConfigurationError`. A build the
list lacks now gets the list's newest device of the same OS release with the
browser's own build in it, so the client hints say what the browser says.
Python only, ABI 0.25.0. Before it, **0.15.0** — a minor for what it adds;
nothing a session already sent changes.
A response says which anti-bot's challenge or block it is (`r.challenge`), and a
session with a `solver` gets past a challenge: `BrowserSolver` passes it in the
Chrome installed on the machine — started with the URL on its command line,
read through its own DevTools endpoint, no page attached, no `Runtime.enable`,
`navigator.webdriver` off without the infobar that would show it, a
Turnstile checkbox clicked along a person's path — and the session goes on
with that browser's own fingerprint; a session of another version is refused.
`Identity` keeps one visitor: the proxy's country, time zone and languages, in
the session's `Accept-Language` and in its browser's page and every worker.
`s.browser(url)` opens the session in its browser and brings the cookies back.
The browser starts light (seven flags measured to change nothing a page reads)
and can stay open between solves. The collector of async results no longer
dies of an exception — on free-threaded Python near the commit limit it met
`MemoryError` and left every waiting request waiting for ever
(docs/STAGE23-RESULTS.md). Python only: the native library, ABI 0.25.0, is
0.14.0's. Before it, **0.14.0** — a minor, because what goes on the wire changed without anyone
asking: a navigation is keyed by its own site, so a link from one site to
another no longer rides a connection opened under the first; the Firefox
profiles key connections by the top-level site, where 0.13 kept one pool, and
send a third party the cookies it set under the same top-level site
(Total Cookie Protection), where they sent it none; a Chromium profile keeps a
`Partitioned` cookie for the top-level site it was set under; a Safari profile
keeps nothing a third party sets. Beside them: an HTTP cache off by default —
`cache=` on the session, fetch()'s cache modes per request, the validators
where Chrome 154 and Firefox 156 put them — `top_level=` for a request made from
a frame, a cookie's `partition` in export and import, and the per-request costs
cut: HTTP/1.1 header assembly almost three times cheaper, the Python side of a
request four times with a response of 26 headers (docs/STAGE22-RESULTS.md).
ABI 0.25.0: the cache and the top level are configuration an older library
would ignore. Before it, **0.13.0** — a minor, because what goes on the wire changed without anyone
asking: the pool spends connections as the profile's family does (a burst of
first requests races four handshakes in Chromium and six in Firefox and rides
one HTTP/2 connection; Chromium pools names by address and keeps
uncredentialed requests and other sites' pages on connections of their own),
and a credentialed cross-site fetch from the Chrome 153 and Firefox 156
profiles carries `sec-fetch-storage-access` as those browsers do. Beside them:
seventeen measured resource kinds behind `resource=` and `crossorigin=`,
`load_page()`, free-threaded Python (3.14t) tested in CI with the GIL off, a
start-up race in the loading of the bundled profiles fixed, and header
assembly three times cheaper (docs/STAGE21-RESULTS.md). ABI 0.24.0: a profile
with a `resources` section does not load into an older library. Before it,
**0.12.0** — a minor, because three defaults changed: a buffered response is
capped at 100 MiB unless `max_response_size` says otherwise, a request whose
reused keep-alive connection dies before any response byte is sent once more
on a new connection (any method, as Chromium does), and `response.headers` is
a `Headers` — still a dict of lists, looked up by any case. Beside them, from a
field report and three code reviews (docs/STAGE20-RESULTS.md): `device_kind`,
`curlpro.errors`, typed verbs (`RequestKwargs`), exact `rollback_cookies`, the
proxy of the environment on streams and WebSockets, and some thirty fixes in
the Go client, the FFI boundary and the Python package; in the corpus, the
HTTP/2 SETTINGS of fourteen old profiles (transcribed, marked with
`source.covers`), 41 brand lists computed as Chromium computes them, and eight
derived presets for the versions current on 2026-09-26 — Chrome 154, Edge 154,
Opera 136, Safari 27 — marked `source.kind = "derived"`, 302 profiles in all.
ABI 0.23.0: `device_kind`, `source.covers` and `derived` do not load into an
older library. Before it, **0.11.0** — a minor, because `list_profiles()` now returns 294 names where it
returned 56: 238 profiles transcribed from `0x676e67/wreq-util` joined the
corpus, each a delta on a captured profile with a `source` block, `measured:
false` in `capabilities()` and a `transcribed_profile` audit finding;
`list_profiles(measured=True)` is the captured list, and code that draws a
profile at random should use it. Beside them: `chrome-153-windows` and
`firefox-156-windows` captured live, `edge-153-windows` and three Chrome macOS
variants derived from the Windows captures, `fingerprint().device` naming
the phone actually chosen, and identity pools — Windows release and Chrome
build, macOS version and CPU, iOS version, the Ubuntu token — on the 151–153
desktops (with the `client_hints` section they lacked), the iOS Safari and the
Firefox Linux profiles, drawn by `device="random"`. ABI 0.22.0: a profile file with a `source` block
does not load into an older library, and `list_profiles(measured=)` reads a
new capability. Before it, **0.10.1** — a patch on 0.10.0 for two edges a third field report found the
same day: a response to an uncredentialed fetch no longer sets cookies, and an
`AsyncSession` response carries `preflights`, `history` and `elapsed` like the
sync one; an imported cookie with an IP-address domain is now actually sent.
ABI stays 0.21. Before it, **0.10.0** — a minor, because a request made from a `page` now sends what the
browser sends and already-written code sees the difference on the wire: a
cross-origin fetch carries no cookies unless `credentials="include"` (and then
only what `SameSite` allows, by the browser family's measured rules), a
non-simple cross-origin fetch is preceded by the CORS preflight — checked,
cached, refused as `CORSError` — and `Origin` turns `null` along a redirect
where the Fetch standard says so. `samesite=False` and `preflight=False` are
the way back. Beside it: `ProxyError` with `stage` and `status` and the
permanent `ProxyAuthError` replace one empty code for four proxy outcomes;
`audit()` judges the sets requests actually went out with; `headers_for()`
spells HTTP/1.1 names as the wire does; `capabilities()` gained
`fetch_metadata` and `cookies`. All of it from a second field report on
0.9.0, all of it measured on Chrome 153 and Firefox 156
(`docs/STAGE18-RESULTS.md`). ABI 0.21.0: a wheel carries the matching
library, a source build needs `go build` again.

## What happens on a tag

1. **version** — compares the tag with `version` in `python/pyproject.toml`. It
   runs first and everything waits on it: a `v0.3.0` tag while `version` still
   said `0.2.0` would build and publish a `0.2.0` wheel silently, and a number
   taken on PyPI is not freed by deleting it.
2. **build** — wheels on five platforms: Linux x86-64 and arm64, macOS Intel and
   Apple Silicon, Windows x86-64. Each is built on its own machine: cgo does not
   cross-compile without the target platform's toolchain.
3. Every wheel is checked where it was built: it installs, finds the profiles
   inside the package and opens a session. The check **does not depend on anyone
   else's service** — a release has to pass on a day when browserleaks is down;
   the fingerprint is asked for in a separate step with `continue-on-error`, for
   information only.
4. **sdist** — the source archive for platforms outside the list. The Go module
   and the profiles are put into it, and the contents are checked: there was a
   time when the archive came out empty (0 Go files) and the promise that it
   "builds the native part itself" was not kept.
5. **publish** — the upload to PyPI, the trusted way.

## What is configured once

Publishing goes the **trusted way** (trusted publishing): PyPI verifies the
signature of the run itself in GitHub, and no token needs to be kept in the
repository's secrets at all — there is nothing to steal.

1. A publisher is registered in the project's settings on PyPI:

   | Field | Value |
   |---|---|
   | Owner | `int3re` |
   | Repository | `curlpro` |
   | Workflow | `wheels.yml` |
   | Environment | `pypi` |

2. A `pypi` environment with a required approval (*Required reviewers* →
   `int3re`) is created in the repository. A push to the public index cannot be
   taken back: an occupied version is never freed, and without the approval one
   wrong tag would cost that number for good. The approval is the last place an
   error can still be stopped.

## How to release

```bash
# 1. Raise the version in python/pyproject.toml
# 2. Make sure everything is green
go test -race ./internal/... && cd python && python -m pytest tests -q -m "not network"

# 3. A dry run: builds everything but publishes nothing — publish only fires on a tag
gh workflow run wheels.yml --ref main

# 4. Tag and push — the same version as in pyproject, or the version job stops it
git tag -a vX.Y.Z -m "curlpro X.Y.Z"
git push origin vX.Y.Z
```

The workflow then builds the wheels and stops at the environment approval.

**The dry run before the tag is not a formality.** The very first one found two
defects, either of which would have wrecked the release: the `macos-13` runner no
longer exists (GitHub keeps the two latest versions of an OS), and a job asking
for it does not fail but queues for ever — while `publish` waits for all five
wheels. And the macOS platform tags promised `10.15` and `11.0` while Go 1.27
requires macOS 13: on 11 and 12 pip would have installed a wheel that cannot
load.

## After the release

The wheels and the archive are attached to the
[GitHub release](https://github.com/int3re/curlpro/releases), so that installing
without reaching the index is possible:

```bash
gh release create vX.Y.Z --title "curlpro X.Y.Z" --notes-file NOTES.md dist/*
```

The files are taken from the artefacts of the same run that was published: then
the checksums agree with the index byte for byte, and that is worth verifying —
`SHA256SUMS.txt` sits next to them for exactly that.

## Profiles between releases

Captures land more often than releases: browsers ship every two weeks. The
corpus is published on its own as a signed bundle that
`curlpro.update_profiles()` fetches:

```bash
python scripts/publish-profiles.py            # build, sign, replace the assets of the `profiles` release
python scripts/publish-profiles.py --dry-run  # build and sign only
```

The bundle is every profile of the committed tree, stamped with the package
version (a bundle older than an installed package is ignored by it), the native
library version as the oldest one that reads it, and the commit; it is signed
with the maintainer's Ed25519 key — `--key`, `CURLPRO_SIGNING_KEY`, or
`%APPDATA%/curlpro/profile-signing.key` (`~/.config/curlpro/` elsewhere) —
whose public half is compiled into the library (`internal/profile/bundle.go`).
The private key never enters the repository; losing it means a new key in a new
release, and the old bundles stop being trusted by it.

## The native part's version

The library has an ABI version of its own (`Version` in
[lib/curlpro.go](../lib/curlpro.go) and `REQUIRED_VERSION` in
`python/curlpro/_ffi.py`). It is **not** the package version, and it is raised
when Python starts depending on a new export or a new configuration field.
Without that an old library ignores unknown fields silently: an option is passed
and does not take effect — which looks like a logic error rather than a stale
build. An hour of runs against the wrong code was once lost to that trap.
