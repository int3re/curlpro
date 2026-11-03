# Stage 46 — fingerprints the corpus did not have: Yandex and Brave on the desktop, tls-client's

Date: 2026-11-03. The owner asked for the fingerprints found elsewhere that
the corpus lacked, Yandex Browser above all. What was found, and what came of
it:

| Client | Where it was | Here now |
|---|---|---|
| Yandex Browser 26.10 for Windows | nowhere as data; installed and captured | `yandex-26.10-windows`, captured |
| Brave 1.98 for Windows | nowhere as data; run from its portable archive and captured | `brave-1.98-windows`, captured |
| Brave 1.88 (Chromium 146) | tls-client's `Brave_146` | `brave-1.88-windows`, transcribed |
| OkHttp 4 on Android 7 to 13 | tls-client's `Okhttp4Android7`…`13` | `okhttp-4.10-android7`…`13`, transcribed |
| the Zalando, Nike, Mesh, Confirmed and MMS apps | tls-client's contributed profiles | `*-app-android`, `*-app-ios`, transcribed |

343 profiles now (318 before): 50 captured whole, 258 transcribed (238 from
wreq-util, 20 from tls-client), 21 derived (18 before: Yandex 26.10 for macOS,
Linux and iPhone), 28 distinct JA4 values (18 before).

## Yandex Browser 26.10

26.10.3.771 on Chromium 152.0.7977.771, installed per user from Yandex's
installer. The capture had to go around the browser: it shows its own
"security threat" page whatever the command line says
(`--ignore-certificate-errors`, the SPKI list, DevTools'
`Security.setIgnoreCertificateErrors`), and headless it ignores the URL. Its
warning page has a proceed link; `scripts/capture-proceed.py` clicks it over
DevTools in a throwaway profile, once per host, headed (CAPTURE.md). The
machine's certificate store was left alone.

- The hello is Chrome 152's to the byte, the 32 trust anchors included:
  JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`, the Chrome 152+ group's.
- The User-Agent is Chrome's reduced string with `YaBrowser/26.10.0.0`;
  `sec-ch-ua: "Chromium";v="152", "Not?A_Brand";v="24", "YaBrowser";v="26.10",
  "Yowser";v="2.5"`; the full version `26.10.3.771`, and the full version list
  with Chromium's own build. (A user-agent site's "Chrome/156" was wrong.)
- `accept-language: ru,en;q=0.9`; no `image/jxl` in `Accept`.
- To `Accept-CH` it answers every hint Chrome 152 does
  (`capture/hints/yandex-26.10-all.json`), its subresources are Chrome 152's
  layout (`capture/subres/yandex-26.10-h2.json`, `-h1.json`), and
  `scripts/gen-resources.py` wrote its resources from those.

**GOST.** On a machine with CryptoPro CSP, Yandex adds the GOST suites to the
hello. A JA4 of Yandex published by Scrapfly has the cipher hash
`d95c37398e29`; Chrome 152's fifteen suites plus 0xc100–0xc106, 0x0081 and
0xff85 give exactly that hash, and nothing smaller found does. Where in the
list they go on the wire is not in a JA4 (it sorts), and the stand has no
CryptoPro — installing one is not a step for a capture. So the profile is the
hello of the machines without it, and the GOST variant waits for a capture
from a machine that has it.

## Yandex on every system

The owner asked for Yandex across devices, from a Pixel to PCs, Macs and
iPhones. Real strings of Yandex 26.10 seen in traffic
(useragents.io, Yandex LLC's browsers, read 2026-11-03) gave the shape on each:

| System | A string seen | Here |
|---|---|---|
| Windows | `… Chrome/152.0.0.0 YaBrowser/26.10.0.0 Safari/537.36` | `yandex-26.10-windows`, captured; 45 identities |
| macOS | `(Macintosh; Intel Mac OS X 10_15_7) … Chrome/152.0.0.0 YaBrowser/26.10.0.0 …` | `yandex-26.10-macos`, derived on the Windows capture; 84 |
| Linux | `(X11; Linux x86_64) … Chrome/152.0.0.0 YaBrowser/26.10.0.0 …` | `yandex-26.10-linux`, derived on it; 4 |
| iPhone | `(iPhone; CPU iPhone OS 26_6_2 …) … Version/26.0 YaBrowser/26.10.3.674.10 SA/3 Mobile/15E148 Safari/604.1` | `yandex-26.10-ios`, derived on `safari-26-ios`; 68 |
| Android | `(Linux; arm_64; Android 16; TECNO CL8) … Chrome/152.0.7977.123 YaBrowser/26.10.2.123.00 Mobile …` | `yandex-26.8-android`, captured, 46 phones |

- **Desktop pools** (`scripts/gen-identities.py`): every release of the
  system on every machine of the seed — on Windows the five 64-bit releases
  (Yandex's installer puts the 64-bit build on 64-bit Windows; the capture
  measured `wow64 ?0`), on macOS each version on the machines of its CPU.
  An identity varies the platform version, the architecture and the machine
  (memory, scale, viewport, colour scheme, network), never the build: Yandex
  writes its own build and brands into the hints, no list of its builds per
  platform is published, and the measured `26.10.3.771` stays.
- **iPhone**: Yandex there is WebKit — Safari's `AppleWebKit/605.1.15` and
  `Version/` are in its string — so the hello, frames and header sets are
  the captured Safari 26 for iOS's. The string is Yandex's own: the real iOS
  version in three parts (`26_6_0` for 26.6), where Safari freezes `18_7`;
  `Version/` the major with `.0`; `YaBrowser/<build>.10 SA/3`. The pool is
  the 17 iOS 26 versions of the Safari line under the four 26.10 iPhone
  builds seen (26.10.0.1738, .1.984, .3.674, .4.504); the User-Agent template
  gained `{full_version}` for the build. About four in ten strings seen also
  carry `CriOS/152.0.7977.<build>` before `YaBrowser`; the pool leaves that
  form out. Yandex on iOS 18 sends iOS 18's hello and is not this profile.
- **Android**: 26.10 for Android is on Chromium 152 (152.0.7977.123–.128 in
  the strings seen), while the captured 26.8 is on 150 and sends no trust
  anchors. Its 46 phones stay on 26.8: a 26.10 twin would need its hello and
  its QUIC hello, which no capture here has — a phone on the stand would.

## Brave 1.98

1.98.63 on Chromium 156.0.8078.80, from `brave-v1.98.63-win32-x64.zip` of its
GitHub release, with a throwaway profile; it takes Chrome's flags, so the
usual tools drove it.

- No trust anchors: extension 0xCA34 is missing, and the JA4 is Chrome 150's
  and 151's, `t13d1516h2_8daaf6152771_806a8c22fdea`. A delta on Chrome 156
  inherited the parent's 32 and refused to build; it now says
  `"trust_anchors": []`, and `curlpro capture` writes that itself when the
  hello has none and the parent has some.
- `Sec-GPC: 1` after `Accept` on every request — navigation, fetch,
  subresources, HTTP/1.1 and HTTP/2; the profile's orders carry it.
- No `application/signed-exchange;v=b3;q=0.7` in the navigation `Accept`.
- `Accept-Language` farbled (`brave_reduce_language_network_delegate_helper.cc`,
  `FarbleAcceptLanguageHeader`): the first language and its base, then one of
  `;q=0.5`…`;q=0.9`, drawn from the site and a per-session key. Two runs of
  the stand gave `ru-RU,ru;q=0.5` and `;q=0.6`. `internal/client/farble.go`
  draws the weight per site (the registrable domain of the page) and session;
  `TestBraveFarblesAcceptLanguagePerSite` holds it to one value per site.
- To `Accept-CH` for all 21 it answers six: `sec-ch-ua-arch`,
  `-platform-version`, `-model`, `-bitness`, `-wow64` and
  `-full-version-list`, the builds zeroed (`156.0.0.0`). No full version, no
  form factors, nothing of the machine, the network or the preferences.

The Go tests that lay out a request as Blink does compare curlpro's assembly
with both captures (`capture/hints/yandex-26.10-all.json`,
`brave-1.98-all.json`), and agree.

## tls-client

`bogdanfinn/tls-client` at `9e4b45ec70e1293e8c88a80fa02a25a10ab1efd8`
(BSD-3-Clause) describes clients as uTLS `ClientHelloSpec` literals in Go.
Its browser profiles are versions this corpus has; what it has that the
corpus did not are OkHttp 4 on Android's platform TLS and a handful of apps.
`scripts/transcribe-tlsclient.py` reads `contributed_custom_profiles.go`,
resolves uTLS's constants from the vendored sources (both uTLS and the fork
tls-client builds on, aliases included) and writes each as a delta:
`tls.cipher_suites`, `tls.compression_methods`, `tls.extensions` in
tls-client's order, `tls.signature_algorithms` (the parents carry their own,
which would override), and `http2` — on `okhttp-5.5-conscrypt` for Android,
on `safari-26-ios` for iOS (with the iOS-version pool declined: an app sends
its own User-Agent).

**The check.** These hellos replay no captured twin, so each was compared
with tls-client's own: its spec built through its own uTLS fork, serialized,
fingerprinted, against the profile's spec built here. All nineteen agree in
JA4, JA4_r, the JA3N text and the Akamai string:

| Profile | JA4 |
|---|---|
| okhttp-4.10-android10…13, nike-app-android | `t13d1513h2_8daaf6152771_eca864cca44a` |
| okhttp-4.10-android9, confirmed-app-android | `t12d1209h2_d34a8e72043a_b39be8c56a14` |
| okhttp-4.10-android8 | `t12d1209h2_d34a8e72043a_e08eabe7240f` |
| okhttp-4.10-android7 | `t12d1208h2_d34a8e72043a_31a7e1922da8` |
| confirmed-app-android-2 | `t12d1210h2_d34a8e72043a_f88f2b2eb673` |
| zalando-app-android | `t13d1514h2_8daaf6152771_43ade6aba3df` |
| mesh-app-android | `t13d1516h2_8daaf6152771_e5627efa2ab1` (Chrome 100–118's) |
| mesh-app-android-2 | `t12d1409h1_c866b44c5a26_b39be8c56a14` |
| zalando/nike/mesh/confirmed-app-ios | `t13d1314h2_f57a46bbacb6_14788d8d241b` |
| mesh-app-ios-2 | `t13d1714h2_0633f72d41ca_14788d8d241b` |
| mms-app-ios | `t13d181000_e8a523a41297_78e6aca7449b` (no ALPN) |

Three things the first pass got wrong, found by that check: the parents'
`signature_algorithms` overrode Android 7's and 8's lists; tls-client writes
some SETTINGS as `math.MaxUint32`; and two specs do what no browser here does,
kept as tls-client has them, each said in the note and given a form in the
schema:

- MeshAndroid's ALPS extension names no protocol: `"alpn": []` on
  `application_settings` is now an explicit empty list (a missing one is still
  an error);
- ConfirmedAndroid2 pads every hello (`WillPad: true`), empty below 256 bytes:
  `"always": true` on `padding`.

**Brave 1.88.** tls-client's `Brave_146`, captured by it on 2026-03-27, is
Chrome 146's hello and frames byte for byte — JA4_r, JA3N and Akamai equal
the captured `chrome-142-macos`'s. Brave 1.88 is the release on Chromium 146
(v1.88.138, Chromium 146.0.7680.178, from Brave's releases). So
`brave-1.88-windows` stands on `chrome-142-macos`, as `chrome-146-windows`
does, with chrome-146-windows's header set and Brave 1.98's measured traits:
`Sec-GPC` in every order, no SXG, the Brave brand in Chrome's place, the
farbled weight. No client hints, like the Chrome 146 beside it.

**Left out.** `CloudflareCustom` (a custom spec, no client behind it), and
tls-client's browser profiles, whose versions are captured or transcribed
here already. The apps' own User-Agent and headers are in no source: the
caller sets them.

## Checks

- Go: `./...` (and `./lib` with cgo) pass; `TestPaddingAlwaysSendsAnEmptyExtension`,
  `TestALPSWithAnEmptyListIsExplicit`, `TestBraveFarblesAcceptLanguagePerSite` new.
- Python: the suite passes but for the tests that reach httpbin.org, where
  `TLS handshake: EOF` and timeouts came and went — the released 0.20.0 shows
  the same on the same host at the same time, and plain curl gets through:
  the path to the host, not the build.
- `gen-identities.py --check` and `gen-resources.py --check` in sync;
  `test_guide_claims.py` counts 340 profiles and 28 JA4 values.
