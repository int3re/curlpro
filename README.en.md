# curlPro

A Python HTTP client that reproduces a browser's network fingerprint.

> The project is written and documented in Russian — see [README.md](README.md)
> for the full documentation. This page is a summary in English.

**Status:** stages 0–8 done, roadmap debts closed. A Python library on top of a Go
core: 47 browser profiles as JSON (Chrome 98–152, Edge, Firefox, Safari, Tor,
Yandex Browser; mobile ones for Android and iOS), HTTP/1.1, HTTP/2, HTTP/3 and
WebSocket. Fingerprints verified against `tls.browserleaks.com`,
`quic.browserleaks.com` and `fp.impersonate.pro`.

```python
import curlpro

with curlpro.Session("chrome-152-windows") as s:
    r = s.get("https://tls.browserleaks.com/json")
    print(r.json()["ja4"])      # t13d1517h2_8daaf6152771_cb7bf5808d99
```

## What makes it different

**A profile is data, not code.** Every other library of this kind keeps browser
profiles in compiled code: a new Chrome every four weeks means editing C or Go,
rebuilding and releasing. Here a profile is a JSON file, and a new browser
version is a data change — you can even add one at runtime:

```python
curlpro.register_profile({
    "name": "chrome-153-windows",
    "based_on": "chrome-152-windows",
    "headers": {"user_agent": "...Chrome/153.0.0.0..."},
})
```

Profiles inherit through `based_on`, so a delta holds only what differs. The
whole difference between Chrome 98 and Chrome 110 turned out to be one line:
extension permutation, which appeared in 110.

**HTTP/3 actually works.** Not just TLS: QUIC transport parameters, HTTP/3
SETTINGS order, the GREASE frame, PRIORITY_UPDATE, and a QPACK decoder with a
dynamic table written for this project — the upstream one does not support it,
and `fp.impersonate.pro` answered once out of five requests because of that.

**Mobile profiles were measured, not copied.** `chrome-152-android` and
`yandex-26.8-android` were captured from a real Pixel 7 over USB: TLS, HTTP/2,
HTTP/1.1 header order and case, the fetch/XHR set, and the WebSocket handshake.

**Different devices, done the way the browser does it.** Modern Chrome froze the
device out of the User-Agent: every Android phone reports `Android 10; K`.
Real devices differ through client hints, and the browser only sends those after
the site asks with `Accept-CH` — which is exactly what this library reproduces:

```python
with curlpro.Session("chrome-152-android", device="random") as s:
    s.get(url)     # sec-ch-ua-model and sec-ch-ua-platform-version after Accept-CH
```

## For scrapers

```python
with curlpro.Session("chrome-152-windows") as s:
    s.cookies.load_file("state.json")     # a missing file is fine: first run
    s.post("https://example.com/login", fields={"user": "u", "password": "p"})
    print(s.get("https://example.com/account").text)   # charset from the header,
                                                      # BOM, or <meta charset>
    s.cookies.save("state.json")
```

Netscape `cookies.txt` is read too — the file `curl -c`, wget and browser
extensions write. `load_file` recognises it by content, not by name:

```python
s.cookies.load_file("cookies.txt")        # from curl, wget, an extension
s.cookies.save_netscape("cookies.txt")    # and back, for another tool
```

Timeouts split the way `requests` splits them, with one difference worth
knowing: the second element caps the whole request, not the silence between
bytes — stricter, so the familiar number is safe to keep.

```python
s.get(url, timeout=(3, 30))               # 3 s to connect, 30 s in total
```

Async is native — a request becomes a goroutine, and one helper thread serves
the whole process. 128 requests of 0.3 s each take 0.37 s instead of the 1.27 s
a 32-thread pool needed:

```python
async with curlpro.AsyncSession("firefox-144-macos") as s:
    results = await asyncio.gather(*(s.get(u) for u in urls))

    # Streaming and WebSocket run the same way — no thread pool either
    async with s.stream("GET", url) as r:
        async for chunk in r.iter_content():
            out.write(chunk)
    async with s.websocket("wss://example.com/ws") as ws:
        await ws.send("hello")
        print(await ws.recv())
```

Also available: hooks (`on_request`, `on_response`), proxies (HTTP CONNECT and
SOCKS5), retries, streaming upload and download, multipart, `--resolve`-style
address substitution, and `keep_alive` control.

HTML parsing is deliberately out of scope — pair it with `selectolax` or `lxml`.

## Build

```powershell
.\build.ps1                                        # → dist/curlpro.dll
cd python; $env:PYTHONPATH='.'; python -m pytest tests
```

Requires Go and a C compiler (MinGW-w64 on Windows): cgo cannot build `c-shared`
without one. There is no PyPI release yet.

## Limits

The library covers the network layer: TLS ClientHello, HTTP/2 and HTTP/3 frames,
header order and case. It does **not** fake a JavaScript fingerprint (canvas,
WebGL, navigator) — that is the browser's level. Matching the network
fingerprint is necessary but not sufficient: modern systems score JA4 together
with JA4H, JA3S/JARM and behaviour.

## License

Apache 2.0 — see [LICENSE](LICENSE). Third-party code and its licenses are
listed in [NOTICE](NOTICE).
