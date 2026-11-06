// The Node binding end to end: offline fingerprint, the same fingerprint as a
// server saw it, parallel requests, cancellation, a stream, an error code.
//
//   CURLPRO_LIBRARY=../../dist/curlpro.dll CURLPRO_PROFILES=../../profiles node example.js
const { Session, CurlproError, version, debugCounts } = require('./index.js');

(async () => {
  console.log(`libcurlpro ${version()}`);
  const s = new Session('chrome-156-windows');
  console.log('ja4 offline:  ', s.fingerprint('https://tls.peet.ws/').ja4);

  const r = await s.get('https://tls.peet.ws/api/clean');
  console.log(`${r.status} ${r.proto} ${r.url} (${r.body.length} bytes)`);
  console.log('ja4 by server:', r.json().ja4);

  const sync = s.requestSync('GET', 'https://example.com/');
  console.log(`sync: ${sync.status} ${sync.proto}`);

  const all = await Promise.all(Array.from({ length: 5 }, () => s.get('https://example.com/')));
  console.log('async x5:', all.map((x) => `${x.status} ${x.proto}`).join(', '));

  try {
    await s.get('https://httpbin.org/delay/5', { signal: AbortSignal.timeout(1) });
    console.log('cancel: not cancelled?');
  } catch (e) {
    console.log('cancel:', e.name);
  }

  const st = await s.stream('GET', 'https://example.com/');
  let total = 0;
  for await (const chunk of st) total += chunk.length;
  console.log(`stream: ${st.status} ${st.proto}, ${total} bytes`);

  try { new Session('no-such-browser'); } catch (e) {
    console.log(`error code: ${e.code}, permanent: ${e.permanent}, CurlproError: ${e instanceof CurlproError}`);
  }

  s.close();
  console.log('left open:', JSON.stringify(debugCounts()));
})().catch((e) => { console.error(e); process.exit(1); });
