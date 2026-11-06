# Node.js

`curlpro` — over [koffi](https://koffi.dev) (prebuilt for every platform, no
compiler needed), Node 18+.

```bash
npm install            # koffi
CURLPRO_LIBRARY=../../dist/curlpro.dll CURLPRO_PROFILES=../../profiles node example.js
```

```js
const { Session, CurlproError } = require('curlpro');

const s = new Session('chrome-156-windows');
console.log(s.fingerprint('https://example.com/').ja4);   // offline

const r = await s.get('https://example.com/', { headers: { 'accept-language': 'en' } });
console.log(r.status, r.proto, r.text().length);

const res = await s.post('https://httpbin.org/post', { json: { a: 1 }, signal: AbortSignal.timeout(5000) });

for await (const chunk of await s.stream('GET', 'https://example.com/big')) { /* Buffer */ }

const ws = await s.websocket('wss://example.com/socket');
await ws.send('hi');
console.log((await ws.receive()).text());
ws.close();
s.close();
```

- `request/get/post/put/delete` return Promises: the work runs in the library
  and a single koffi worker waits on `curlpro_result_wait` for every call in the
  process; `signal` aborts the request.
- `requestSync` blocks the JS thread — for scripts only.
- `CurlproError` has `code`, `details` and `permanent`.
- Types are in [index.d.ts](index.d.ts).

The published `curlpro` package depends optionally on `@curlpro/<platform>-<arch>`
(win32, linux, darwin × x64, arm64): npm installs only the one for the machine,
and the binding finds the library there. The profiles are in the main package.
The binding copies results out with `koffi.decode` rather than `koffi.view`,
so it also works where external buffers are forbidden (Electron).
