# Stage 20 — a field report, three reviews and the presets of 26 September

Date: 2026-09-26. Four inputs: the field report of 2026-09-24 (five complaints
and a question), three independent reviews run over the code (the Go client,
the profiles with the FFI boundary and tools, the Python package), and a survey
of the browser versions current today. Every finding below was reproduced
before it was fixed, and each fix has a test that fails without it.

## The question: a kept-alive connection the server gave up

Measured on a raw stand (HTTP/1.1 in the clear and over TLS, HTTP/2 over TLS),
killing a kept-alive connection three ways:

| What the server did | HTTP/1.1 before | HTTP/2 before | Both now |
|---|---|---|---|
| closed the idle connection (a keep-alive timeout) | failed at `retries=0`; POST failed always | new connection, fine | the pool notices the close while idling; fine |
| reset the connection after the request arrived | failed at `retries=0`; POST failed always | the same | resent once on a new connection, any method |
| closed it after the first byte of a response | — | — | not resent: the server may have processed it |

Chromium's rule, read in `net/http/http_network_transaction.cc`: a request is
resent when the connection was reused and no response headers arrived
(`ShouldResendRequest`), on reset, close, abort, "not connected" and an empty
response; a truncated response is not. The idle check is a read kept pending on
every idle HTTP/1.1 connection and cancelled at hand-out — net/http's scheme. A
first version probed with a one-millisecond read deadline instead: a reused
request went from 0.2 ms to 1.6 ms on Windows, where the timer rounds up. The
pending read costs nothing measurable.

## The field report's five complaints

- **Response headers** were a plain dict: `.get("retry-after")` returned
  `None`. `Headers` keeps the dict of lists and looks up by any case.
- **`devices`** changed meaning in 0.11 without a word. `device_kind`
  (`phone`, `desktop`, `iphone`, `distro`) says what a pool holds.
- **The exceptions** lived in `curlpro._ffi`. `curlpro.errors` now; the old
  import still works.
- **The verbs** took `**kw: Any`. `Unpack[RequestKwargs]`, generated from the
  real signatures; `scripts/check-typing.py` makes mypy prove a misspelt
  argument is caught on the sync, async and one-off paths.
- **No default body limit.** 100 MiB for a buffered response; streams uncapped.

## The reviews: what was real

Go client: an undrained redirect or preflight body hard-closed a shared HTTP/2
connection and killed its other streams; a ten-byte zstd frame allocated 512
MB (fhttp's decoder, on HTTP/2 — the window is now capped at Chromium's 8 MB
and HTTP/2 bodies go through the library's own decoder); the Critical-CH retry
dropped its own error and repeated POSTs; 103 Early Hints was returned as the
response; a cookie for a foreign domain overwrote the real site's record; an
internationalised host went out as raw UTF-8 in Host; the HTTP/3 path skipped
the cookie gate, the CA, `resolve=` and `ip_version=`; a cancelled HTTP/1.1
download kept its connection; any HTTP/2 error retired the shared connection;
`ClearCookies` raced with requests in flight.

Profiles and FFI: the registry's `supported_versions` slice went to uTLS
uncopied, and uTLS rewrote its GREASE entry in place — concurrent handshakes
raced on one array (a test: `0x0a0a` became `0x4a4a` in the registry); a
derived profile lost its family and with it the cookie policy; a capture on a
pooled parent inherited 153's hints; a body of 2 GiB wrapped the C int length;
`Register` accepted what could not resolve.

Python: a timed-out chunk read or WebSocket receive lost its data; a late
cancellation leaked a stream; the environment's proxy beat an explicit session
proxy, and streams and WebSockets ignored the environment altogether — direct,
from the real address; `json_body` overwrote a `Content-Type` in another case;
host-only cookies became domain cookies after a save; a rollback erased other
threads' cookies; a BOM lost to the header charset; a persona drew a new phone
every session; `retry_backoff=0` slept 200 ms; the `requests` facade broke on
form dicts, cookie dicts, HEAD redirects, string params and file objects.

## The corpus

- **SETTINGS.** Fourteen corpus profiles (Chrome 98–116, Chrome 99 Android,
  Edge 98–101, Safari 15.3/15.5) sent an empty SETTINGS frame: their
  signatures recorded none. The values are now wreq-util's for each version,
  marked `source.covers = ["http2.settings"]`; the baselines were re-recorded
  against browserleaks.
- **Brands.** 41 transcribed brand lists were wrong in wreq-util. Chromium's
  algorithm, checked against every capture from 105 up, computes them now.
- **Pools.** macOS versions in Chromium's three-part form; the Chrome 153
  builds released since the 22nd; macOS 27.0; Safari 26.0 on iOS pins 18_6.

## The presets of 26 September

| Browser | Current | Here |
|---|---|---|
| Chrome | 154.0.8037.57 (stable 09-22), 155 on 10-06 | `chrome-154-*` derived on the 153 capture; the Chrome here is 153.0.8010.54 |
| Edge | 154.0.4258.37 (09-24) | `edge-154-windows` derived; the Edge installed here is 139 |
| Firefox | 156.0.1; 157 on 09-29 | `firefox-156-windows` captured |
| Safari | 27.0 with iOS 27 and macOS 27 (09-14) | `safari-27-ios`, `-macos` derived on the 26 captures |
| Opera | 136.0.6008.52 on Chromium 152 | `opera-136-*` derived on the Chrome 152 capture |
| Yandex | 26.8.3/26.8.4 desktop, Chromium base unpublished | not added |

wreq-util has no commit after e3922a2; curl-impersonate and tls-client added
nothing newer than what is here.

## Not measured

- Chrome 154, Edge 154, Safari 27, Opera 136: every hello is a twin's, taken on
  trust and marked. A capture replaces each.
- Where Tor puts `Sec-GPC` on HTTP/1.1: its order is Firefox's, which sends no
  such header; the header is left out on HTTP/1.1 rather than placed by guess.
- The default User-Agents of `safari-18.4-ios` (`18_0` with `Version/18.4`) and
  `safari-26-ios` (`26_0`) are the corpus captures' as recorded; the pools give
  the release strings.
