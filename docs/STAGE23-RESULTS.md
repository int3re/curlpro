# Stage 23 — anti-bot challenges, and a browser driven as little as can be

Date: 2026-10-01. The owner asked whether the library could get past
Cloudflare's checks the way cloudscraper claims to, and then asked for a
browser that is not given away by its own automation. Re-implementing a
vendor's check is a race lost every time the vendor ships a new one, so the
check is run by a real browser. The work was to find out what gives an
automated browser away today, and to drive Chrome without any of it.

## What gives an automated browser away (2026)

From the published benchmarks and write-ups (May–September 2026; links in the
answer to the owner, not repeated here): the decisive layer is the control
channel, not the browser's properties. Playwright and Puppeteer attach to
every page and switch the DevTools `Runtime` domain on in each frame; the
startup sequence (`Target.setAutoAttach`), init scripts and
`--enable-automation` add to it. Patchright patches Playwright around
`Runtime.enable`; nodriver, zendriver and pydoll drive Chrome over DevTools
without a WebDriver; Camoufox patches Firefox in C++. In the one independent
benchmark with 31 targets, the raw-DevTools driver did best and every
Playwright variant was blocked somewhere.

## The stand

`python/tests/challenge_stand.py`. `/gate` answers 403 with `cf-mitigated:
challenge` (Cloudflare's documented mark) until the clearance cookie arrives;
its page is the "check": it reports what a page can read about the control
channel, waits 1.2 s and sets the cookie by script. `/turnstile` is a gate
behind Cloudflare's real Turnstile widget from challenges.cloudflare.com with
Cloudflare's published test sitekeys, which work on any domain; the token goes
to `/verify`, which sets the clearance. `/leak` is the report alone.

## What was measured, Chrome 154.0.8037.58 on Windows 10

| | result |
|---|---|
| `--remote-debugging-port` alone | `navigator.webdriver` = **true** |
| plus `--disable-blink-features=AutomationControlled` | `webdriver` false, and an "unsupported command-line flag" infobar: the window's chrome (`outerHeight − innerHeight`) 151 px instead of 95 |
| plus `--test-type` as well | `webdriver` false, 95 px — the same as Chrome started by hand |
| the Error-`stack` probe for an attached inspector | not triggered, attached or not |
| the Proxy-prototype probe (`console.groupEnd` / `console.log`) | the same traps (`get`) fire attached or not |

The control for the last two was real: a DevTools session on the page with
`Runtime.enable`, proven attached by the `Runtime.consoleAPICalled` events it
received for the very calls the probes made. So on Chrome 154 the two published
probes do not tell an attached inspector from none; whether anti-bots use
others is not known here. The driver does not attach either way: not attaching
is the one state no probe can tell from a person's browser.

The solver against the stand: the JavaScript check passed in 2.1–2.4 s, the
real Turnstile widget with the always-pass key in 3.7 s (token
`XXXX.DUMMY.TOKEN.XXXX` delivered by the widget). The check page reported
`webdriver` false, the session's own User-Agent and 95 px of window chrome.

**nowsecure.nl**, the page built for testing Cloudflare: Chrome under the
driver had Cloudflare's `cf_clearance` within 3 s. The site served curlPro
itself its page with no challenge at all (a 200, title "nowsecure.nl"), so it
could not serve as a gate for the solver. Its page stalls after the first
kilobytes from this machine — curl.exe the same — while cloudflare.com's
1.3 MB home page came whole in 1.3 s: the site, not the network.

## What was built

- `curlpro/challenge.py`: `detect()` and `Challenge` — Cloudflare by its
  documented header and its challenge, block and 1015 pages; DataDome, Akamai,
  HUMAN, Imperva and Kasada by the marks their pages carry (not measured here).
  `Response.challenge`, `raise_for_challenge()`, and `challenge` on streams
  from the headers alone.
- `Session(solver=)` and `AsyncSession(solver=)`: a challenge is handed to the
  solver, its cookies are loaded and the request is sent again; one solve per
  site at a time; the async session solves off the event loop; a block is
  never handed over; a failure is `ChallengeError` (`challenge`).
- `curlpro/browser`: `Chrome` starts the installed Chrome or Edge on the URL
  with its own profile and reads tabs and cookies from the browser's own
  DevTools endpoint — `Browser.getVersion`, `Target.getTargets`,
  `Storage.getCookies`, nothing else. A WebSocket client on the standard
  library (the package's own sends a browser's Origin, which DevTools
  refuses). `Forwarder` gives the browser a proxy with credentials: HTTP or
  SOCKS5 upstream, tunnels passed byte for byte.
- `BrowserSolver`: opens the page, waits for the vendor's pass cookie or any
  change of cookies, has the session verify, returns. A check that has not
  passed by itself in 2.5 s and has a Turnstile frame gets a click: the tab is
  attached for that moment (no `Runtime`), `DOM.getDocument` with shadow roots
  pierced finds the frame inside its closed shadow root, and
  `Input.dispatchMouseEvent` moves the mouse along a Bézier curve, slow at both
  ends, and clicks. Cloudflare's always-interactive test sitekey
  (`3x00000000000000000000FF`) passed in 7.5 s with it and timed out without
  it. `session_options()`
  gives the profile of the installed browser's version and the device of its
  build; a session of another version is refused. No new dependency.

The click was missed at first in about one run in three: each
`Input.dispatchMouseEvent` waited 5 s for its answer. Windows Chrome marks a
window covered by another one as occluded, and its renderer stops acknowledging
input — the test window was under the terminal. With
`--disable-features=CalculateNativeWinOcclusion` and
`--disable-backgrounding-occluded-windows`, now always on, 6 runs of 6 clicked
at once; the fingerprint page (below) read the same 26 values with the two
switches and without them in 8 starts, `document.visibilityState` "visible" in
all. Chrome keeps only the last of a repeated `--disable-features`, so the
driver merges every list it is given — its own, the light set's, the caller's —
into one.

## One browser for many solves

A context made over DevTools (`Target.createBrowserContext`) is Chrome's
off-the-record kind, and pages that look for incognito read the storage
quota. Measured: 10.0 GiB in the browser's own profile and in each context
alike. A browser started for a solve took 0.92 s to its first page and held
440 MB with its helper processes; each further context with a page open took
0.5–0.6 s and 130–170 MB more. The first `keep_open` gave each solve such a
context; it was taken back when the identity work measured the languages: a
page in a context made over DevTools asked for `ja-JP,en-US,en` — the defaults
of the UI locale `--lang=ja-JP` sets — where the browser's own profile, and the
session, said `ja-JP,ja,en-US,en`. Languages cannot be set per context without
a User-Agent override, which takes the client hints with it. So
`BrowserSolver(keep_open=True)` keeps one browser per proxy and languages and
solves in a new tab of it, one solve at a time, its cookies cleared first:
five solves of the gate — whose page waits 1.2 s by design — took 2.64 s
median with a browser each and 1.55 s with one kept open, the first of them
2.02 s (a busy machine: the same runs took 2.28 s and 1.69 s earlier).

## Light without being told

The stand's `/fp` page reads 22 values a fingerprinting script reads —
`navigator.plugins` and `mimeTypes`, `window.chrome`'s keys, hardware
concurrency and device memory, languages, platform, screen, window chrome,
notification permission, the PDF viewer, time zone, the unmasked WebGL vendor
and renderer and the number of WebGL extensions, the client-hint brands, full
versions and platform version, the storage quota, four permission states,
speech voices, media devices. Each candidate flag ran alone against three
plain starts, then the safe ones together, three runs each:

| | memory 3 s after the page | processes | fingerprint |
|---|---|---|---|
| plain Chrome 154 | 569–596 MB | 11–13 | — |
| `--disable-gpu` (the control) | −84 MB | 13 | WebGL changed |
| each of the 13 candidates alone | −30 to +35 MB, within the plain runs' spread | 10–14 | the same |
| the light set together | 541–544 MB against 571–572 | 10 | the same |

The light set — no extensions, background networking, component updates,
default apps, sync, pings, translate, optimization-guide or media-router
services — is on by default (`Chrome(light=True)`). At start it saves 30 MB and
one to three processes; over a kept-open browser's life it keeps it from
downloading components and models in the background. `--disable-site-isolation-
trials` saved as much and showed nothing either, and is left out: a browser that
visits other people's sites keeps its Spectre isolation. A test reads the
fingerprint page with the set and without it and requires every value equal.

## One visitor: time zone and languages

What a browser reports about where it is must agree with the address it comes
from. The stand's `/zones` page reads the time zone and languages in the page,
a dedicated worker, a shared worker and a service worker — the last two run
apart from the page, and an override that misses them is the leak
fingerprinting scripts compare.

| how | page | workers |
|---|---|---|
| `TZ=America/New_York` in Chrome's environment, Windows | `Europe/Moscow` | `Europe/Moscow` |
| `Emulation.setTimezoneOverride` on the tab before its page loads | `America/New_York`, `Date` offsets 300/240 | all three `America/New_York` |
| languages written into the profile (`intl.accept_languages`) | `de-DE,de,en-US,en` | all three the same |

The override held through navigations while the tab stayed attached.
`curlpro.Identity` carries country, time zone and languages; a session with
one sends the languages as `Accept-Language` with Chrome's weights and hands
the zone to its solver and to `s.browser()`. `Identity.lookup(proxy)` asks a
geolocation service (ipinfo.io by default) through the proxy where it comes
out; `Identity.for_country()` needs no network. Tests: the gate passed with a
Japanese identity, in a browser of its own and in a kept-open one, the check
page reporting `Asia/Tokyo` and `ja-JP,ja,en-US,en`; the four contexts of
`/zones` all reporting `America/Chicago|en-US,en`.

## The session in its browser, and back

`s.browser(url)` opens the installed Chrome as the session — refused unless it
is the profile's version — with the session's proxy, identity and cookies
(`Storage.setCookies` before the page loads; a host-only cookie by URL, since a
domain makes Chrome send it to subdomains), and brings the browser's cookies
back on `sync()`, while `wait()` waits for the window to close, and on leaving
the block. `local_storage(origin)` reads `DOMStorage` through the inspector —
both the `storageKey` and the older `securityOrigin` forms answered on Chrome
154 without `DOMStorage.enable`. Tested: the stand's page received the
session's cookie on its first request, its token came out of `localStorage`,
and the cookie it set by script went on with the session's next request.

## A hang on free-threaded Python, and its cause

A run of the suite on 3.14t hung in `test_concurrency_is_not_capped_by_threads`
(128 async requests to a stand that serves each connection in a thread). The
thread dump: the stand stuck in `Thread.start()` waiting for a thread that
never started, and no `curlpro-completions` thread at all — the one thread
that hands every async result to its waiter was gone, and nothing restarts it
until the next request registers. The machine was at its commit limit (39.1
of 39.4 GB; `WinError 1455` on the next start), and the reason a test of 128
requests weighed so much was the interpreter: 128 plain Python threads with no
curlpro committed 3.8 GB on 3.14t and 42 MB on 3.14. The collector now
survives any exception and keeps a result it could not hand over for the next
round; a test injects two `MemoryError`s into its wait and requires every
request answered (the old collector failed it by timeout).

## Left open

- A puzzle beyond a click (DataDome's slider, HUMAN's press-and-hold) waits
  for a person in the window.
- Headless is not offered as working: Chrome's headless User-Agent says
  `HeadlessChrome`, which no profile carries, and the solver refuses it.
- No Cloudflare managed challenge (an interstitial in front of a whole site)
  was available to measure the clearance's lifetime and what it is bound to;
  that needs a zone of our own.
- Whether `--test-type` has effects a page can see beyond the infobar is not
  known.
