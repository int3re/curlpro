# Stage 17 — the initiator, and the resuming hello

Date: 2026-09-19. Chrome 153.0.0.0 and Firefox 156.0, both installed on the
capture machine, both driven headless. Every value below is what the stand
recorded; nothing is inferred from a specification.

## 1. What a page sends to its own origin, its site and another site

Stand: `cmd/hcapture -origins -auto` (Chrome) and the same stand with a Firefox
profile trusting its certificate. The page lives at
`https://www.a.localhost:8443/app/index.html?tab=1`; `api.a.localhost` is the
same site (one registrable domain, `a.localhost`), `b.localhost` is another
site. The page performs, against each of the three: `fetch` GET, `fetch` POST
with a plain body, `fetch` POST with JSON and a custom header, XHR GET; then
loads an image and a script cross-site, navigates cross-site by script, posts
a form back cross-site, and navigates same-origin by script.

**The two browsers agreed on every value.**

| Request | Origin | Referer | sec-fetch-site |
|---|---|---|---|
| navigation, typed (the start page) | — | — | `none` |
| fetch GET, same origin | — | `…/app/index.html?tab=1` (full URL) | `same-origin` |
| fetch POST, same origin | page origin | full URL | `same-origin` |
| XHR GET, same origin | — | full URL | `same-origin` |
| fetch GET, same site | page origin | `https://www.a.localhost:8443/` (origin only) | `same-site` |
| fetch POST, same site | page origin | origin only | `same-site` |
| fetch GET / POST, cross site | page origin | origin only | `cross-site` |
| XHR GET, cross site | page origin | origin only | `cross-site` |
| image, script, cross site | — | origin only | `cross-site` (`no-cors`, dest `image` / `script`) |
| navigation, cross site (script) | — | origin only | `cross-site` |
| form POST, cross site | page origin | origin only | `cross-site` |
| navigation, same origin (script) | — | full URL of the previous page | `same-origin` |

Two more things the run showed:

- **A preflight.** A cross-origin fetch with `Content-Type: application/json`
  and a custom header is preceded by an `OPTIONS` with its own header set
  (Chrome: `accept`, `access-control-request-method`,
  `access-control-request-headers`, `origin`, `user-agent`, `sec-fetch-*`,
  `referer`, `accept-encoding`, `accept-language`, `priority` — no
  `sec-ch-ua`). Same-origin requests get none. Not reproduced yet; recorded
  as debt.
- **Script navigations carry no `sec-fetch-user`.** Only a user gesture sets
  it. A navigation from a page in the library is treated as a click and keeps
  the profile's `?1`; a script-initiated one is not distinguished.
- **Chrome 153 sends `sec-fetch-storage-access: active`** on cross-site
  `no-cors` subresources (image, script). Not on fetch, XHR or navigation.
- **Firefox puts `cookie` before `upgrade-insecure-requests`** on a
  navigation (`…, accept-encoding, referer, cookie, upgrade-insecure-requests,
  sec-fetch-dest, …`), where the family's HTTP/2 navigation order had it after
  `sec-fetch-user`. The profiles were corrected; the HTTP/1.1 order was not
  measured and is left as it was.

Where the Referer lands: Chromium after `sec-fetch-dest` (navigation and
fetch alike), Firefox after `origin` on a navigation and after
`accept-encoding` on a fetch (the fetch set already carried the slot).

## 2. The resuming ClientHello

Stand: `cmd/hcapture -close`, which closes every connection after one
response so each later request of the page resumes on a new one; the record
carries the raw hello and the server's `DidResume`. Then, because a Go server
issues no early-data tickets, Chrome through a recording CONNECT proxy to
`www.cloudflare.com`, a server that supports 0-RTT.

| Client | Server | Resumed hello |
|---|---|---|
| Chrome 153 | the stand | first hello plus `pre_shared_key` (0x0029) last; no `early_data`; `session_ticket` kept; extension set otherwise identical (shuffled, as always) |
| Chrome 153 | www.cloudflare.com | the same: `pre_shared_key` last, no `early_data` |
| Firefox 156 | the stand | `pre_shared_key` last; no `early_data`; **`session_ticket` (0x0023) dropped** |
| Firefox 156 | push.services.mozilla.com | `pre_shared_key` last, no `early_data`, `session_ticket` dropped (that hello also lacked `compress_certificate`; the stand's did not, so the library follows the stand) |

The `pre_shared_key` layout is the server's: one identity of the ticket's
length, one 32-byte binder (SHA-256 suites), 148 bytes on the stand.

curlpro with `resume=True` on the same stand: `chrome-152-windows` produces
the first hello plus `pre_shared_key` last, `session_ticket` kept, no
`early_data` — the Chrome shape; `firefox-155-windows` the same with
`session_ticket` dropped once the profile says `resume_omits_session_ticket`
— the Firefox shape. Both resume (`DidResume` true). `internal/client/resumeshape_test.go`
holds the check.

## What changed

- `page` on the session and per request, and `s.page` to move it: Referer,
  Origin and sec-fetch-site derived by the rules above, over every transport;
  along a redirect chain sec-fetch-site is the page's relation to each URL
  and only degrades. WebSocket handshakes take the page's origin.
- A `referer` slot in the navigation and HTTP/1.1 orders of every Chromium
  and Firefox profile, at the measured position; the Firefox `cookie` slot
  moved.
- `resume=True` by default; `tls.resume_omits_session_ticket` on the Firefox
  family, honoured only once a ticket exists so the first hello is untouched.
- The audit's `referer_site`: a Referer beside `sec-fetch-site: none`, or
  disagreeing with `sec-fetch-site` or `Origin`.
- `cmd/hcapture -origins` and `-close`, so both measurements can be repeated.
