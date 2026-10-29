# Stage 45 — every client hint a site can ask for, and Blink's header map

Date: 2026-10-29. Chrome 156.0.8078.73 (the build its updater had staged,
`new_chrome.exe`) and Chrome 155.0.8059.85 on the capture machine — Windows 10
22H2, a 32-bit Chrome under `Program Files (x86)`, a 1920×1080 screen at 100%,
16104 MB of RAM, the dark theme — driven headless through `cmd/hcapture
-hintspage`. The page makes fetch and XHR with and without headers of its own
(`X-Api-Key`, `Content-Type`, an `Accept` of its own), an image, a script and a
stylesheet, then navigates to `/second` and does it all again. The records are
in `capture/hints/`:

| File | Chrome | `Accept-CH` |
|---|---|---|
| `chrome-156-all.json` | 156 | all 21 hints |
| `chrome-155-all.json` | 155 | all 21 hints |
| `chrome-156-google.json` | 156 | a search engine's set: `sec-ch-prefers-color-scheme`, `downlink`, `rtt` and the UA hints; `Critical-CH` on the colour scheme alone |
| `chrome-156-ua8.json` | 156 | the eight high-entropy UA hints |

Why: the owner's own browser showed a fingerprinting page the hints a search
engine asks for — `rtt`, `downlink`, `sec-ch-prefers-color-scheme` among them
— and curlpro answered only the eight User-Agent ones.

## A navigation: one fixed sequence

The browser process writes the hints in the order of
`content/browser/client_hints/client_hints.cc` (AddRequestClientHintsHeaders),
and the wire keeps it:

```
device-memory, sec-ch-device-memory, dpr, sec-ch-dpr, viewport-width,
sec-ch-viewport-width, sec-ch-viewport-height, rtt, downlink, ect,
sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-full-version, sec-ch-ua-arch,
sec-ch-ua-platform, sec-ch-ua-platform-version, sec-ch-ua-model,
sec-ch-ua-bitness, sec-ch-ua-wow64, sec-ch-ua-full-version-list,
sec-ch-ua-form-factors, sec-ch-prefers-color-scheme,
sec-ch-prefers-reduced-motion, sec-ch-prefers-reduced-transparency,
upgrade-insecure-requests, user-agent, accept, sec-fetch-*, …
```

A subset keeps the sequence: the search engine's set gave `rtt, downlink,
sec-ch-ua … sec-ch-ua-form-factors, sec-ch-prefers-color-scheme`. The
`Critical-CH` retry of the first page puts `upgrade-insecure-requests`,
`user-agent` and `accept` first, as Stage 19 saw; `/second` is the steady state.

## A page's request: Blink's hash map

Everything a page sends — fetch, XHR, an image, a script, a stylesheet, the
favicon — carries the headers Blink set in an `HTTPHeaderMap`: the page's own,
the hints, `User-Agent`. That is a `WTF::HashMap` keyed by
`DeprecatedCaseFoldingHash`, and the network stack copies it in iteration
order, which is bucket order. The model, from the source (third_party/blink
`wtf/hash_table.h`, `wtf/text/case_folding_hash.h`, `third_party/rapidhash`):

- the hash is rapidhash with its default seed and secrets over the name
  case-folded to UTF-16, keeping the low 24 bits (0 becomes 0x800000);
- the table starts at 8 buckets and doubles when half full, rehashing the old
  buckets in order; a collision probes triangularly (i += 1, 2, 3 …);
- the page's own headers go in first, then the hints in the order
  `FrameFetchContext::AddClientHintsIfNecessary` sets them, then `User-Agent`;
- `Content-Length` comes before the cluster, and the default `Accept`,
  `Origin`, `sec-fetch-*`, `Referer`, `Accept-Encoding`, `Accept-Language`,
  `Cookie` and `Priority` after it — the network stack adds them. An `Accept`
  the page sets itself is in the map.

Against the four captures: **88 requests, 25 to 27 names in the map each, all
in the model's order**, and Stage 19's Chrome 153 clusters, `X-Api-Key` and
all. With all hints asked for, a fetch goes out as

```
sec-ch-ua-full-version-list, sec-ch-ua-platform, viewport-width, device-memory,
sec-ch-ua, sec-ch-dpr, sec-ch-ua-model, sec-ch-ua-mobile, sec-ch-ua-form-factors,
sec-ch-ua-bitness, sec-ch-ua-wow64, sec-ch-ua-arch,
sec-ch-prefers-reduced-transparency, sec-ch-ua-full-version,
sec-ch-viewport-width, downlink, sec-ch-viewport-height, ect,
sec-ch-device-memory, sec-ch-prefers-reduced-motion, dpr,
sec-ch-prefers-color-scheme, user-agent, rtt, sec-ch-ua-platform-version,
accept, sec-fetch-site, …
```

and an `X-Api-Key` of the page's own lands in bucket 13, between
`sec-ch-ua-mobile`'s neighbours. Blink hashes this way since StringHasher
moved to rapidhash (main@1337378, 2024-08-05, Chrome 129); the stored fetch
orders of all 161 Chromium profiles from 129 on agree with the model as well.
The fingerprinting page's own preset, which a custom header had shifted,
differs from the model by exactly the swap such a header causes.

## The values

| Hint | On this machine | What it is |
|---|---|---|
| `device-memory`, `sec-ch-device-memory` | `16` | RAM rounded to the nearest power of two in GB, clamped to 2–32 on a desktop (8 on Android) — `approximated_device_memory.cc` |
| `dpr`, `sec-ch-dpr` | `1` | the screen's scale factor times the site's zoom |
| `viewport-width`, `sec-ch-viewport-width`, `sec-ch-viewport-height` | `764`, `764`, `429` headless | the page area in CSS pixels, scrollbar included; omitted when the size is unknown |
| `rtt` | `100` | the HTTP RTT estimate × a per-site multiplier, capped at 3 s, in 50 ms steps |
| `downlink` | `1.6` navigation, `1.55` / `1.5` / `1.75` the page's requests | the throughput estimate × the multiplier, capped at 10 Mbps, in 50 kbps steps |
| `ect` | `4g` | the class of the estimate |
| `sec-ch-prefers-color-scheme` | `dark` | the theme |
| `sec-ch-prefers-reduced-motion`, `-reduced-transparency` | `no-preference` | the accessibility settings |

The multiplier is `0.9 + ((hash(host) + salt) % 21) × 0.01`, the salt a number
from 1 to 21 drawn once per browser run — once in the browser process for
navigations (`client_hints.cc`), once per renderer for a page's requests
(`NetworkStateNotifier`) — which is why a navigation and a request of its page
may differ by a step. The session draws its two salts once.

A maximized window's viewport was not measured headless. The default,
1920×969, is the 1040 px work area less 71 px of Chrome's own UI: the restored
window's `outerHeight - innerHeight` of 95 (fpcapture on this machine) less
the two 8 px frame borders and the 8 px the tab strip gives up when maximized.

## What the library does now (0.20)

- Every hint above is answered once the site asks (`Accept-CH`), at once on
  `Critical-CH`, in a navigation in the browser's sequence.
- A page's requests on Chromium 129+ — fetch mode and subresources — are laid
  out by the model, the caller's own headers with them; subresources carry the
  asked-for hints too. An explicit `header_order` still wins.
- `rtt` and `downlink` carry the noise per site and per side.
- The values are the device's: Windows defaults to this machine (16, 1,
  1920×969, dark, 100 ms, 1.6 Mbps, 4g); every pooled identity names a machine
  from `scripts/identities.json` (`machines`); `devices=` takes the same fields.

## Not done

- Hints across origins: Chrome sends a page's high-entropy hints only to its
  own origin unless a Permissions-Policy delegates them; the library keys them
  by the request's origin.
- Frames: a same-origin iframe gets the hints in the navigation sequence; a
  frame request here carries none.
- macOS and Linux viewports, and the Android values (Android scales the
  viewport width to 980): not measured, not sent.
