# Stage 18 — cookies from a page, the Origin on redirects, the preflight

Date: 2026-09-21. Chrome 153.0.0.0 and Firefox 156.0, both installed on the
capture machine, both driven headless. Every value below is what the stand
recorded; nothing is inferred from a specification. The stand is
`cmd/hcapture -origins` extended for this stage: it now sets five cookies on
each of its three names in a first-party context before the page starts,
answers CORS with the request's origin and `Allow-Credentials: true`, serves
302 and 307 redirects between the names, and holds the browser for 125 s so a
cross-site POST can be seen with young cookies and with old ones. HTTP/2 splits
the `Cookie` header into one field per cookie; the tables join them.

The three names: the page is on `www.a.localhost`, `api.a.localhost` is the
same site (one registrable domain), `b.localhost` is another site. The five
cookies on every name: `strict=1; SameSite=Strict`, `lax=1; SameSite=Lax`,
`none=1; SameSite=None; Secure`, `nonens=1; SameSite=None` (no Secure), and
`plain=1` with no attribute.

## 1. Which cookies a request carries

`nonens` never appeared anywhere in either browser: **both refuse
`SameSite=None` without `Secure` at set time.**

| Request from the page | Chrome 153 | Firefox 156 |
|---|---|---|
| fetch GET / POST / XHR, same origin, default credentials | all five (four) | the same |
| fetch, same origin, `credentials: "omit"` | none | none |
| fetch, same **site** (api.a), default credentials | **none** | **none** |
| fetch, same site, `credentials: "include"`; XHR `withCredentials` | strict, lax, none, plain | the same |
| fetch, cross site (b), default credentials | none | none |
| fetch, cross site, `credentials: "include"`; XHR `withCredentials` | **none=1 only** | **nothing at all** |
| image, script, cross site (`no-cors`) | none=1 | nothing |
| navigation GET, cross site | lax, none, plain | lax, none, plain |
| form POST, cross site, cookies ~15 s old | none, **plain** (Lax+POST); not lax | none, plain; not lax |
| form POST, cross site, cookies ~140 s old | none only | none, plain |
| form POST from the page to its own origin, 307 to b, ~20 s old | none, plain | none, plain |

Read across: `fetch()`'s default `same-origin` sends no cookie to another
origin even of the same site — the difference between `same-origin` and
`same-site` is the whole point of the credentials mode. With `include` the
SameSite attribute decides, and the families differ on two things: Chromium
treats an unattributed cookie as Lax (so it is withheld on a cross-site fetch
and, past two minutes, on a cross-site POST navigation), and Firefox's Total
Cookie Protection sends nothing of the target's first-party jar on any
cross-site subresource or fetch, `include` or not. The Lax+POST window is
Chromium's: `plain` rode the cross-site POST at 15 s and not at 140 s; Firefox
sent it both times.

Reproduced by `internal/client/samesite.go` and `profile.CookiePolicyFor`;
guarded by `samesite_test.go` and `python/tests/test_samesite.py`.

## 2. The Origin header along a redirect

| Chain (fetch unless noted) | Where it landed | Chrome 153 | Firefox 156 |
|---|---|---|---|
| page → api.a `/r1` → 302 → b | b | `null` | `null` |
| page → www.a `/r2` (own origin) → 302 → b | b | `https://www.a…` | `https://www.a…` |
| page → www.a `/r2b` → 302 → api.a → 302 → b | api.a; b | real; `null` | real; `null` |
| page → www.a `/r4` POST → 307 → b | b | `https://www.a…` | `https://www.a…` |
| **form POST** www.a `/r3` → 307 → b | b | **`null`** | `https://www.a…` |

The fetches follow the Fetch standard's "redirect-tainted origin" in both
browsers: the origin turns opaque when a hop leaves an origin the request's
origin did not match. The navigation is where they part — Chromium nulls a
POST navigation after any cross-origin hop, Firefox keeps the standard's
answer. `sec-fetch-site` on every hop was the relation of the page to that
URL, as measured in Stage 17.

Reproduced in `redirect.go` (`nextRequest`) and `headers.go`, the family
difference as `profile.TaintsOriginOnNavigationRedirect`; guarded by
`originnull_test.go`.

## 3. The CORS preflight

A cross-origin fetch with a JSON body and a custom header, a DELETE without
headers, and both with `credentials: "include"`: the OPTIONS came out the
same in every case, and identical to Stage 17's. Chrome 153, HTTP/2:

```
accept: */*
access-control-request-method: POST         (DELETE for the DELETE; then no …-headers)
access-control-request-headers: content-type,x-api-key
origin: https://www.a.localhost:8443
user-agent: …
sec-fetch-mode: cors
sec-fetch-site: cross-site                  (same-site for api.a)
sec-fetch-dest: empty
referer: https://www.a.localhost:8443/
accept-encoding: gzip, deflate, br, zstd
accept-language: …
priority: u=1, i
```

Firefox 156: `user-agent, accept, accept-language, accept-encoding,
access-control-request-method, access-control-request-headers, referer,
origin, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, priority, te`. Neither
carries a cookie, a `sec-ch-ua` name or the request's own headers. Note that
the order is not the fetch set's: Chrome puts `accept` first and
`sec-fetch-mode` before `sec-fetch-site`, where its fetch set has
`user-agent` first and site before mode.

Reproduced by `preflight.go` and `profile.PreflightOrder`; guarded by
`preflight_test.go` and `python/tests/test_preflight.py`.

## Not measured here

- Safari, for all three questions (no Safari on the capture machine): its
  cookie policy is WebKit's documented ITP, its preflight order is derived
  from its (already derived) fetch set, and both say so in the code.
- The scheme in the site comparison for cookies (the stand is TLS only):
  Chromium's schemeful same-site is taken from its release notes, Firefox's
  pref default (off) from its source.
- The HTTP/1.1 order and case of the two `Access-Control-Request-*` names
  (the stand records HTTP/2): canonical case is assumed.
- The exact length of Chromium's Lax+POST window: seen open at 15 s and shut
  at 140 s, two minutes taken from the Chromium source.
