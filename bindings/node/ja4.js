// Prints the offline JA4 of chrome-156-windows for https://example.com/ — the
// value scripts/bindings-agree.sh compares across every binding.
const { Session } = require('./index.js');

const s = new Session('chrome-156-windows');
console.log(s.fingerprint('https://example.com/').ja4);
s.close();
