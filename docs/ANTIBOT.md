# Anti-bot protections: recognising them, getting past them

Русская версия: [ANTIBOT.ru.md](ANTIBOT.ru.md).

curlPro meets anti-bot protections at three levels, and this document covers
all three:

1. **Not being stopped.** A request whose TLS ClientHello, HTTP/2 frames,
   header order and client hints are a real browser's gives a gate less to
   object to. That is the rest of the library ([GUIDE.md](GUIDE.md)); here it
   is the reason many requests never meet a gate at all. On nowsecure.nl, a
   page built to test Cloudflare, curlPro itself was served the page with no
   challenge.
2. **Knowing that you were stopped, and by whom.** `r.challenge` says which
   vendor answered and what kind of answer it is — a check, a captcha, a
   block, a rate limit, or a request the vendor could not read.
3. **Getting past it.** A check is run by a real browser, never re-implemented:
   `BrowserSolver` passes it in the Chrome installed on the machine and hands
   the session the cookies; a solver of your own plugs into the same place.

A matching network fingerprint is necessary and not sufficient: anti-bots also
score behaviour, the IP's reputation and what the page measures in the
browser. curlPro closes the network layer and gives the browser layer to a
browser. **Nothing in the package sends a challenge to a captcha-solving
service**, and it will not.

## In thirty seconds

```python
import curlpro

# Recognise: every response says whether it is an anti-bot's answer.
with curlpro.Session("chrome-154-windows") as s:
    r = s.get("https://example.com/")
    if r.challenge:                        # None for an ordinary answer
        print(r.challenge.vendor, r.challenge.kind, r.challenge.solvable, r.challenge.evidence)
    r.raise_for_challenge()                # ChallengeError (code "challenge") if it is one

# Get past: a challenge is passed in the installed Chrome, the request repeated.
solver = curlpro.BrowserSolver()
with curlpro.Session(**solver.session_options(), solver=solver) as s:
    r = s.get("https://example.com/")      # the page itself, past the check
```

## 1. What `r.challenge` holds

`None`, or a `Challenge`:

| Field | Meaning |
|---|---|
| `vendor` | `cloudflare`, `qrator`, `datadome`, `human` (PerimeterX), `akamai`, `imperva` (Incapsula), `kasada` |
| `kind` | what the answer is — the table below |
| `solvable` | whether a solver can help: true for `challenge` and `captcha` |
| `status` | the HTTP status of the answer |
| `url` | the URL that answered |
| `ray` | Cloudflare's request id (`cf-ray`), the one its support asks for; `""` elsewhere |
| `evidence` | the marks that matched, as strings — `("cf-mitigated: challenge",)`, `("x-qrator-validate-result: captcha", "x-qrator-token", ...)` |

| `kind` | It means | `solvable` | What to do |
|---|---|---|---|
| `challenge` | a check a browser runs and passes by itself: Cloudflare's managed and JavaScript challenges, Turnstile in front of a page, Qrator's 401, Akamai's and Imperva's interstitials, Kasada | yes | `BrowserSolver`, or a solver of your own |
| `captcha` | a check that may want a person: Turnstile's checkbox, DataDome's slider, HUMAN's press-and-hold, Qrator's picture and checkbox | yes | `BrowserSolver` with its window (Turnstile's checkbox is clicked for you; the rest wait for a person), or a solver of your own |
| `block` | a decision already made: Cloudflare's 1020, Akamai's "Access Denied", Imperva's incident page, DataDome without a captcha | no | no browser changes it — another address, a slower pace, another request |
| `rate-limit` | too many requests: Cloudflare's 1015 | no | slow down; with retries on (`retries=3` — they are off by default) a 429's `Retry-After` sets the wait |
| `no-verdict` | the anti-bot could not read what it was sent: Qrator's validation endpoint answering a bare 403 | no | the request is malformed — compare it with a browser's (section 4) |

`r.raise_for_challenge()` raises `ChallengeError` for any of them, with
`.challenge` and the answer as `.response`; `e.code == "challenge"`.

The answer is read on first use of `r.challenge` and remembered. Only the
first 64 KiB of a body are scanned: every challenge page names its vendor in
its head. A streamed response (`s.stream(...)`) has `.challenge` too, read
from the headers alone, since its body has not arrived.

## 2. The vendors, and exactly how each is recognised

Apart from Cloudflare's header and Qrator's own statuses, an answer is only
examined when its status is 403, 429 or 503: a 200 with a captcha widget on it
is a page that asks for one in its own form, not a gate in front of the page.

| Vendor | Recognised by | Source of the rule |
|---|---|---|
| Cloudflare | `cf-mitigated: challenge` on any status; its pages behind `Server: cloudflare` / `cf-ray` | the vendor's documentation; measured on the project's stand |
| Qrator | its 401 with `qrator_jsr`; the `X-Qrator-Validate-Result` verdict | measured on the wire against `login.mts.ru` by a field report |
| DataDome | the `x-datadome` header; `captcha-delivery.com` with the `datadome` cookie | the marks its pages are known to carry |
| HUMAN | `_pxAppId` or `px-captcha` in the page | the same |
| Akamai | the `sec-if-cpt-container` interstitial; `AkamaiGHost` with "Access Denied" | the same |
| Imperva | `_Incapsula_Resource`; "Incapsula incident ID" | the same |
| Kasada | a 429 with `x-kpsdk-*` headers | the same |

The last five were not measured on this project's stand. Each `Challenge`
says in `evidence` what it matched, so a wrong call can be told from a right
one — and a report of one, like the Qrator report, is how a rule gets
corrected.

### Cloudflare

| Answer | `kind` |
|---|---|
| `cf-mitigated: challenge`, any status, no body needed | `challenge` |
| 403/429/503 from Cloudflare with `/cdn-cgi/challenge-platform/` or `_cf_chl_opt` in the page | `challenge` |
| "error code: 1015", or a 429 whose page names Cloudflare | `rate-limit` |
| `cf-error-details`, "Sorry, you have been blocked", "error code: 10…" | `block` |

`cf-mitigated` is the header Cloudflare documents for exactly this ("Detect a
challenge page response"), so a challenge on an API call — a 403 with the
header and nothing a browser would render — is recognised from the headers
alone. `ray` carries `cf-ray`.

**Ready solution:** `BrowserSolver`. The pass cookie is `cf_clearance`; the
request is retried the moment it appears. Turnstile's checkbox, when it asks
for one, is clicked.

### Qrator

| Answer | `kind` |
|---|---|
| 401 with `Set-Cookie: qrator_jsr=` or the `/__qrator/` script in the page | `challenge` |
| 403 with `X-Qrator-Validate-Result: captcha` (and a fresh `X-Qrator-Token`) | `captcha` — the picture |
| 403 with any other verdict, or a 418 or 420 | `captcha` — the checkbox |
| 403 from `/__qrator/validate` **without** the verdict header | `no-verdict` |
| `Server: QRATOR` on an ordinary answer | `None` — it is on 200s too |

`no-verdict` is the distinction the field report paid half a day for. From
outside, both refusals are "403". One means *you were judged and sent to a
captcha*: a browser's 403 there carried the verdict and a new token. The other
means *what you sent could not be read*: the library's own validation request
came back bare, no verdict, no token, `content-length: 0`. Only the header
tells them apart. A `no-verdict` is not solvable — a browser would pass; it is
the request you built that failed.

The `/__qrator/` path is a vendor mark by itself, because the bare 403's only
other mark is a `Server` header that a proxy in between may rewrite.

**Ready solution:** a `challenge` or `captcha` is handed to the session's
solver like any other. **That `BrowserSolver` passes Qrator's real check has
not been verified by this project**: the rules above were measured, the solve
was not. The checkbox is not clicked for you — the solver clicks Cloudflare's
frames only — so it waits for a person at the window. A solver of your own
(section 3.4) plugs in where a dedicated Qrator solver is wanted.

### DataDome

| Answer | `kind` |
|---|---|
| the `x-datadome` or `x-datadome-cid` header, with `captcha-delivery.com` in the page | `captcha` |
| the header without it | `block` |
| `captcha-delivery.com` in the page with a `datadome` cookie set | `captcha` |

**Ready solution:** `BrowserSolver`, whose pass cookie for DataDome is
`datadome`. Its slider wants a person at the window. Not verified against
DataDome itself.

### HUMAN (PerimeterX)

`_pxAppId` or `px-captcha` in the page → `captcha`. The press-and-hold wants a
person at the `BrowserSolver` window; any change of cookies is tried. Not
verified against HUMAN itself.

### Akamai

`sec-if-cpt-container` or `/_sec/cp_challenge/` in the page → `challenge`;
`Server: AkamaiGHost` with "Access Denied" → `block`. The interstitial runs in
the browser by itself. Not verified against Akamai itself.

### Imperva (Incapsula)

`_Incapsula_Resource` in the page → `challenge`; "Incapsula incident ID" →
`block`. Not verified against Imperva itself.

### Kasada

A 429 with any `x-kpsdk-*` header → `challenge`. Not verified against Kasada
itself.

### An answer `r.challenge` does not recognise

A 403 with `r.challenge is None` is either the site's own refusal (an expired
session, a missing permission) or a vendor whose marks the package does not
know. `r.headers` and the first lines of `r.text` usually say which. A report
with the two answers side by side — a browser's and the library's, as the
Qrator report had them — is enough to add a vendor.

## 3. The ready solutions

### 3.1 `BrowserSolver`: the check, in the Chrome installed here

```python
solver = curlpro.BrowserSolver()
s = curlpro.Session(**solver.session_options(), solver=solver)
r = s.get(url)    # challenge → the browser passes it → its cookies → the request again
```

**What it does.** A session with a `solver` that meets a solvable challenge
hands it over: the solver opens the page in Chrome (or Edge) installed on the
machine, waits for the check to pass, gives the session the cookies, and the
session sends the request again. The answer you get is the page behind the
gate.

**Why it is not caught as automation.** Chrome starts with the URL on its
command line, as when a person opens it. The only DevTools traffic is the
browser's own endpoint — its version, its tabs, its cookies. No page is
attached to, no `Runtime.enable` is sent, no script of ours runs in the page,
and there is no `--enable-automation`: the marks that give Playwright and
Puppeteer away are not there. `navigator.webdriver`, which the DevTools port
switches on in Chrome 154, is switched back off, without the "unsupported
flag" infobar that would have grown the window's chrome by 56 px. The flags
that make it lighter were measured one by one to change nothing a page reads,
and together against all 340 values `scripts/fpcapture.py` records.

**Why the session then gets through.** The clearance belongs to a browser
fingerprint, and the session *is* that browser on the wire:
`session_options()` returns the profile of the installed browser's version and
the device of its exact build — `impersonate="chrome-154-windows"`,
`device="Windows 10 22H2, Chrome 154.0.8037.93"`. A session of another
version is refused with `ConfigurationError` rather than sent out with a
cookie its own ClientHello contradicts. A build the profile's device list does
not have yet — Chrome updates itself overnight — gets the newest device of the
same OS release with the browser's own build in it.

**What passes by itself, and what needs a click or a person.**

- A check that runs unattended passes unattended. The request is retried the
  moment the vendor's pass cookie appears (`cf_clearance`, `datadome`), and on
  any other change of cookies at most every 2 s — a site's own gate behind
  Turnstile sets its own cookie.
- **Turnstile's checkbox is clicked for you.** When the check has not passed
  within `click_after` (2.5 s), the tab is attached for that moment only: the
  inspector finds Cloudflare's check frame, in a closed shadow root too, and
  the mouse goes to it along a curve at a person's pace through DevTools'
  Input domain, whose events the page receives as trusted. Still no
  `Runtime`, still no script. At most three clicks, 8 s apart. Windows
  occlusion tracking is off, so a window under another one still takes the
  click at once.
- **Anything else that wants a person waits for one** in the browser window:
  a picture captcha, a slider, a press-and-hold, another vendor's checkbox.
  The window is why `headless=False` is the default.

**Measured:**

| Check | Result |
|---|---|
| a JavaScript check behind `cf-mitigated` (the stand) | passed in 2.1–2.4 s |
| Cloudflare's real Turnstile widget, always-pass test sitekey | passed in 3.7 s |
| Turnstile, the test sitekey that always asks for the checkbox | passed in 4–7.5 s with the click, never without |
| nowsecure.nl (real Cloudflare) | `cf_clearance` in 3 s |
| five solves with the browser kept open (`keep_open=True`) | 1.55 s median, against 2.64 s with a browser each |

**Options:**

| Option | Default | Meaning |
|---|---|---|
| `headless` | `False` | a headless Chrome says `HeadlessChrome` in its User-Agent, which no profile carries — the solver refuses the mismatch; and a captcha needs a window |
| `profile_dir` | none | keep the browser profile between solves: a browser that has been to the site before is a returning visitor. Without it, every solve starts from a fresh profile |
| `keep_open` | `False` | keep one browser between solves (section 3.2) |
| `click` | `True` | click Turnstile's checkbox; `False` leaves it to a person |
| `click_after` | 2.5 | seconds a check gets to pass by itself before the click |
| `timeout` | none | the longest a solve waits, when shorter than the session's 90 s |
| `poll` | 0.5 | how often the cookies are read |
| `executable` | found | the browser to run; `CURLPRO_CHROME` in the environment does the same |

**What it shares with the session.** The proxy — one with credentials goes
through a local forwarder that adds them and passes the tunnel through
untouched, since Chrome takes none on its command line; WebRTC is kept on the
proxy. The languages, written into the browser profile as a person sets them.
The identity's time zone (section 3.3).

**How the session uses it.** Requests to one site wait for one solve: a burst
of ten requests meeting the same gate is one browser, not ten. An
`AsyncSession` solves off the event loop. A `block`, a `rate-limit` and a
`no-verdict` are never handed over. A solve that does not get through raises
`ChallengeError` with the challenge page as `.response`. A streamed request is
not handed over — make one ordinary request to pass the gate first, then
stream with the cookies in the jar.

**What it needs.** Chrome or Edge installed, and nothing else: it speaks
DevTools over a WebSocket of the standard library.

### 3.2 One browser for many solves

```python
with curlpro.BrowserSolver(keep_open=True) as solver:
    for url in urls:
        with curlpro.Session(**solver.session_options(), solver=solver) as s:
            s.get(url)
```

One browser per proxy and languages — both are the browser's own, set when it
starts — and each solve in a new tab of it, one at a time, its cookies cleared
first. Not a browser context per solve: measured on Chrome 154, a page in a
context made over DevTools asks for the UI locale's default languages, not the
session's `Accept-Language`. Close it with `solver.close()` or the `with`
block. It cannot be combined with `profile_dir`.

### 3.3 One visitor: the identity

A browser behind a German address that reports another country's time zone
and languages is a contradiction fingerprinting scripts compare with the IP in
a line.

```python
ident = curlpro.Identity.lookup(proxy)            # where the proxy comes out (ipinfo.io, through it)
ident = curlpro.Identity.for_country("DE")        # or offline: de-DE, de, en-US, en; Europe/Berlin
s = curlpro.Session(**solver.session_options(), proxy=proxy, identity=ident, solver=solver)
```

The session sends the identity's languages as `Accept-Language` with Chrome's
weights, and the browser that solves keeps the same languages and time zone —
in the page, its `Date`, and its dedicated, shared and service workers
(measured on the stand). `lookup()` is the one network call and is made only
when asked.

### 3.4 A solver of your own

Any object with `solve(request) -> Solution | None` is a solver. Use it for a
vendor-specific solver, for clearance cookies obtained elsewhere, for a person
in another window.

```python
from urllib.parse import urlsplit
import curlpro

class StoredClearance:
    """Hands the session clearance cookies obtained by another process."""

    def __init__(self, store):
        self.store = store

    def solve(self, req: curlpro.SolveRequest):
        cookies = self.store.get(urlsplit(req.url).hostname)
        if cookies and req.verify(cookies):
            return curlpro.Solution(cookies, req.user_agent, "stored")
        return None                               # → ChallengeError for the caller

s = curlpro.Session("chrome-154-windows", solver=StoredClearance(my_store))
```

What a solver is handed (`SolveRequest`):

| Field | Meaning |
|---|---|
| `challenge` | the `Challenge`: vendor, kind, evidence |
| `url` | the page to open — the request's own for a GET, else the page it was made from, else the site's root |
| `impersonate`, `user_agent`, `accept_language` | the session's; a browser that solves must be the same |
| `proxy` | the proxy the request went through, `""` for none — the clearance belongs to an address |
| `timezone` | the identity's time zone, `""` for the machine's own |
| `verify(cookies)` | loads the cookies into the session, sends the request again, says whether it got through |
| `timeout` | how long the session waits (90 s) |

A cookie is a dict: `name`, `value`, `domain`, `path`, `host_only`, and
optionally `expires`, `secure`, `http_only`, `same_site`, `partition`. Return a
`Solution(cookies, user_agent, browser)` after a `verify` that said yes, or
`None`. The session's guarantees hold for any solver: one solve per site at a
time, async off the loop, a failure as `ChallengeError`.

### 3.5 By hand: the session in its browser

```python
with curlpro.Session(**curlpro.BrowserSolver().session_options()) as s:
    with s.browser(url) as b:        # its proxy, identity and cookies, set before the page loads
        b.wait()                     # a person passes the check; closing the window ends it
    s.get(url)                       # the cookies came back
```

For the check nothing passes automatically, or to see what a browser sends
where the library's request fails. `sync()` brings the cookies back at any
moment, `local_storage(origin)` reads the page's storage, and leaving the
block brings everything back.

## 4. Recipes

| You see | It is | Do |
|---|---|---|
| a 403, `r.challenge` is `None` | the site's own refusal, or a vendor the package does not know | read `r.headers` and the start of `r.text`; report a new vendor with a browser's answer beside yours |
| `cloudflare` / `challenge` | a JavaScript or managed challenge | `solver=BrowserSolver()` |
| `cloudflare` / `challenge`, then a Turnstile checkbox | the interactive Turnstile | the same — the checkbox is clicked |
| `datadome` / `captcha`, `human` / `captcha` | a slider, a press-and-hold | `BrowserSolver` with its window, and a person; or a solver of your own |
| `qrator` / `challenge` | its 401 and script | hand it to a solver; `BrowserSolver` is not verified on it |
| `qrator` / `captcha` | judged and sent to the picture or the checkbox | a person at the `BrowserSolver` window, or a solver of your own |
| `qrator` / `no-verdict` | your validation request could not be read | not a judgement of you: fix the request — compare it with what a browser sends (`s.browser()`, `s.headers_for(method, url)`) |
| any `block` | a decision about the address or the request | another address, a slower pace; a solver will not help |
| `cloudflare` / `rate-limit` | 1015 | slow down; `Session(retries=3)` retries a 429 and waits what its `Retry-After` says (`respect_retry_after`, on by default — but `retries` is 0 by default, so nothing is retried until you ask) |
| `ConfigurationError: open the session as …` | the session's profile is not the installed browser's version | open it with `**solver.session_options()` |
| `ChallengeError: … the solver did not get past it` | the solve timed out or never verified | a person at the window, a longer `timeout`, `profile_dir` for a returning visitor |
| a challenge on every request in a burst | | one solve per site: the rest wait for it and reuse its cookies |

## 5. What is verified, and what is not

| Claim | Status |
|---|---|
| Cloudflare is recognised by `cf-mitigated` | the vendor's documented mark; tested |
| `BrowserSolver` passes a JavaScript check and Turnstile, clicking its checkbox | measured on the stand with Cloudflare's real Turnstile widget and test sitekeys |
| `BrowserSolver` gets `cf_clearance` from real Cloudflare | measured on nowsecure.nl |
| The browser leaves no automation mark a page can read | measured: `webdriver` false, no infobar, 340 values unchanged by the flags |
| Qrator's rules | measured on the wire by a field report; replayed on the stand |
| `BrowserSolver` passes Qrator's real check | **not verified** |
| DataDome, HUMAN, Akamai, Imperva, Kasada are recognised | by the marks their pages are known to carry; **not measured here** |
| `BrowserSolver` passes their checks | **not verified** |

## 6. What it will not do

- **Send a challenge to a captcha-solving service.** Not in the package, not
  as an option. A solver of your own is your own business.
- **Re-implement a vendor's check.** The check is a program that measures the
  browser it runs in; a re-implementation is a race lost every time the vendor
  ships a new one.
- **Run headless.** Chrome's headless User-Agent says `HeadlessChrome`, which
  no profile carries; the solver refuses rather than present a contradiction.
