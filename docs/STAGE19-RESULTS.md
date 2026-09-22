# Stage 19 — the desktop's high-entropy client hints

Date: 2026-09-22. Chrome 153.0.8010.52 on the capture machine — Windows 10
22H2 (build 19045), a 32-bit Chrome installed under `Program Files (x86)` —
driven headless through `cmd/hcapture` on its plain page, which answers every
response with `Accept-CH` and `Critical-CH` naming the eight high-entropy
hints. Every value below is what the stand recorded.

## Two things the run taught before it measured anything

- **Headless Chrome answers `Accept-CH` only for a secure origin, and
  `--ignore-certificate-errors` does not make one.** Three runs — headless,
  headed off-screen, headless again — got the three low-entropy hints and
  nothing else, whatever the stand asked for. With
  `--ignore-certificate-errors-spki-list=<sha256 of the stand key>` (the
  flag hcapture already used for QUIC) the certificate counts as trusted,
  the origin as secure, and the eleven hints arrive on the retry the
  `Critical-CH` triggers. The Pixel capture of Stage 16 had not run into
  this only because the phone trusted the stand's certificate.
- **The first navigation and every later one lay the hints out
  differently.** The `Critical-CH` retry of the first page puts
  `upgrade-insecure-requests`, `user-agent` and `accept` first and the
  hints after; a later navigation (`/second`) puts the eleven hints first.
  The Pixel capture, launched by intent, saw only the first shape — which is
  why the Android profiles' navigation order starts with
  `upgrade-insecure-requests`. Steady state is the second shape, and that is
  what the desktop profiles carry.

## The hints, and their order

Navigation, steady state (`GET /second`):

```
sec-ch-ua: "Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"
sec-ch-ua-mobile: ?0
sec-ch-ua-full-version: "153.0.8010.52"
sec-ch-ua-arch: "x86"
sec-ch-ua-platform: "Windows"
sec-ch-ua-platform-version: "10.0.0"
sec-ch-ua-model: ""
sec-ch-ua-bitness: "64"
sec-ch-ua-wow64: ?1
sec-ch-ua-full-version-list: "Google Chrome";v="153.0.8010.52", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.52"
sec-ch-ua-form-factors: "Desktop"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0.0.0 Safari/537.36
accept: text/html,…
sec-fetch-site / sec-fetch-mode / sec-fetch-dest / referer / accept-encoding / accept-language / cookie / priority
```

Fetch and XHR (`/fetch-get`, `/fetch-post`, `/xhr-post`, each with a custom
`X-Api-Key`): `content-length`, `sec-ch-ua-full-version-list`,
`sec-ch-ua-platform`, `sec-ch-ua`, `sec-ch-ua-bitness`, `sec-ch-ua-model`,
`x-api-key`, `sec-ch-ua-mobile`, `sec-ch-ua-wow64`, `sec-ch-ua-form-factors`,
`sec-ch-ua-arch`, `sec-ch-ua-full-version`, `user-agent`, `content-type`,
`sec-ch-ua-platform-version`, `accept`, `origin`, `sec-fetch-*`, `referer`,
`accept-encoding`, `accept-language`, `cookie`, `priority`. Without the
custom header the cluster is the Pixel's (Stage 16), which differs from this
one only in the two names around `x-api-key` — the layout is a function of
the set of names, as noted then — and the profiles carry the Pixel's.

What the values mean, for a pool:

| Hint | On this machine | What it is, and what varies between users |
|---|---|---|
| `platform-version` | `"10.0.0"` | the Windows `UniversalApiContract` version: Windows 10 22H2 gives 10, Windows 11 21H2/22H2/23H2 give 13/14/15, 24H2 gives 19 (Microsoft's table; Chromium's highest known contract is 19). macOS reports its own version, `15.7.1`; Linux reports `""` |
| `full-version`, `full-version-list` | `153.0.8010.52` | the exact build; users of one major run several at any moment (chromiumdash lists ten for 153). The list is the brand list with the builds written in, the GREASE brand's major padded to `8.0.0.0` |
| `arch`, `bitness` | `"x86"`, `"64"` | every Windows desktop; macOS says `arm` on Apple silicon and `x86` on Intel |
| `wow64` | `?1` | a 32-bit browser on 64-bit Windows — this install; most are `?0` |
| `model` | `""` | always empty on a desktop |
| `form-factors` | `"Desktop"` | always, on a desktop |

Reproduced by `scripts/gen-identities.py` from `scripts/identities.json`:
the Chromium desktop profiles of 151–153 gained the `client_hints` section
they lacked, with this machine's values as the defaults, and a pool of
identities (Windows release × build × wow64, macOS version × CPU × build,
Linux × build) that `device="random"` draws from. The TLS does not move.

## Not measured here

- Windows 11 contract versions, macOS and Linux values: from Microsoft's
  and Chromium's documentation, not from a machine at hand.
- The fetch cluster without a custom header on the desktop: taken from the
  Pixel (same Chromium, same layout function).
- Edge: `sec-ch-ua-full-version` and the `"Microsoft Edge"` entry of the list
  carry Edge's own build (`153.0.3xxx.xx`) next to Chromium's, and neither is
  known here. `edge-153-windows` keeps no pool and no hints section until an
  Edge reaches the stand.
- Whether a first navigation's layout is what a real site sees first — it
  is, on a first visit, and the profiles send the steady-state shape from
  the start. A capture of a multi-page session would settle it.
