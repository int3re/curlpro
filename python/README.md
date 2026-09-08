# curlpro

An HTTP client with a browser's network fingerprint: the TLS ClientHello, the
HTTP/2 and HTTP/3 frames, header order and header case.

```bash
pip install curlpro
```

```python
import curlpro

with curlpro.Session("chrome-151-windows") as s:
    r = s.get("https://example.com")
    print(r.status, r.text[:200])
```

Neither Go nor a compiler is needed: the native library and all 47 profiles are
already inside the wheel, and the profiles load themselves.

## Why another one

The existing clients keep their browser profiles in compiled code: a new Chrome
comes out every four weeks, and each time that means editing C or Go, rebuilding
and releasing. Here a profile is data, and it can be registered at runtime:

```python
curlpro.register_profile({
    "name": "chrome-152-windows",
    "based_on": "chrome-151-windows",
    "headers": {"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/152.0.0.0 ..."},
})
```

## Your own fingerprint, without a request

What a server would see is computed locally, from the same ClientHello bytes that
would go on the wire. No network, no oracle:

```python
with curlpro.Session("chrome-151-windows") as s:
    fp = s.fingerprint()
    print(fp.ja4)       # t13d1516h2_8daaf6152771_806a8c22fdea
    print(fp.akamai)    # 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

Checked against 47 captures: JA4 47/47, JA3N 47/47, Akamai 47/47.

`audit()` answers the second question — the one people actually lose days to.
Not "does my fingerprint look right" but "does anything here disagree with
anything else", because that is what gives a client away:

```python
for finding in s.audit():
    print(finding)
```

## Personas

Profile, proxy, device, headers and cookies — one identity, one file:

```python
p = curlpro.Persona.new("chrome-151-windows", proxy="http://user:pass@host:8080")
p.save("accounts/user42.json")

p = curlpro.Persona.load("accounts/user42.json")
with p.session() as s:
    s.get("https://example.com/")
p.save()          # the cookies moved on; the identity did not
```

## requests compatibility

```python
import curlpro.requests as requests

r = requests.get("https://example.com/", timeout=10)
```

Existing code changes one import. It is a subset, and it says so: an argument the
shim cannot honour is refused with a reason rather than ignored.

## What is inside

A thin ctypes wrapper over a native library written in Go: the handshake is
driven by [uTLS](https://github.com/refraction-networking/utls), HTTP/2 by
[fhttp](https://github.com/bogdanfinn/fhttp), QUIC by
[uquic](https://github.com/refraction-networking/uquic).

The fingerprint is checked against `tls.browserleaks.com`: Chrome 151 gives
`t13d1516h2_8daaf6152771_806a8c22fdea` — the same JA4 as the live browser.

## Boundaries

The library covers the network layer. It does **not** forge the JS fingerprint
(canvas, WebGL, navigator) — that is the browser's level, and the answer there is
Playwright. Matching the network fingerprint is necessary but not sufficient:
modern systems score JA4 together with JA4H, JA3S/JARM and behaviour.

HTTP/1.1, HTTP/2, HTTP/3 and WebSocket are supported, along with cookies,
redirects, proxies (HTTP CONNECT and SOCKS5), multipart, streaming reads and
uploads, and an asynchronous API.

```python
# WebSocket: the handshake follows the profile's template, permessage-deflate works
with curlpro.Session() as s:
    with s.websocket("wss://echo.websocket.org/", max_message_size=1 << 20) as ws:
        ws.send("hello")         # str   -> a text frame
        ws.send(b"\x00\xff")     # bytes -> a binary one
        for message in ws:       # until the server closes: curlpro.WebSocketClosed;
            print(message)       # a silence timeout is CurlProError with .code == "timeout"

# A large file goes as a stream rather than through memory
with curlpro.Session() as s:
    s.post("https://example.com/upload", body_file="archive.zip")

# The connection is reused between requests, as a browser's is. keep_alive=False
# gives every request its own — needed when a balancer pins a client to one node.
with curlpro.Session(keep_alive=False) as s:
    s.get("https://example.com/")
```

The HTTP/3 fingerprint is checked against Chrome 144 on `quic.browserleaks.com`:

```python
with curlpro.Session("chrome-151-windows", http3=True) as s:
    print(s.get("https://quic.browserleaks.com/fp").json()["h3_text"])
    # 1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p
```

The QPACK dynamic table is supported by a decoder of our own: the profile
advertises a capacity as Chrome does, and a server that uses it gets parsed.

## Install

```bash
pip install curlpro
```

Nothing to compile: the native library and all 47 profiles travel inside the
wheel. Wheels are built for Linux (x86-64 and ARM64, glibc 2.28+), macOS 13+
(Intel and Apple Silicon) and Windows x64. The macOS 13 floor is not ours to
choose: that is what Go 1.27 requires, and the native part is built with it.

Platforms outside that list — Alpine and other musl distributions, Windows on
ARM, older glibc or macOS — have no wheel. There the source archive is built by
hand, and Go and a C compiler are required: `pip install` alone would leave the
package without its native part, and the failure would come at the first call
rather than at install time.

```bash
pip download curlpro --no-binary :all: --no-deps
tar -xzf curlpro-*.tar.gz && cd curlpro-*/go
CGO_ENABLED=1 go build -buildmode=c-shared -o ../curlpro/lib/libcurlpro.so ./lib
```

The library is looked up through `CURLPRO_LIBRARY`, then in `curlpro/lib/`, then
in `dist/`.

Full documentation and sources — [github.com/int3re/curlpro](https://github.com/int3re/curlpro).
