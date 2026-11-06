# PHP

`Curlpro\Session` — over PHP's FFI extension, PHP 8.1+. Blocking requests,
fingerprint, preview, session headers and cookies; streams and WebSockets are
not wrapped yet (the ABI has them: docs/C-ABI.md).

> **Not run yet.** There was no PHP on the machine this binding was written on.
> The declarations are include/curlpro.h without the preprocessor, which
> `FFI::cdef` does not run.

```php
require 'vendor/autoload.php';   // or src/curlpro.php

$s = new Curlpro\Session('chrome-156-windows');
echo $s->fingerprint('https://example.com/')['ja4'], "\n";   // offline

$r = $s->get('https://example.com/', ['headers' => ['accept-language' => 'en']]);
echo $r->status, ' ', $r->proto, ' ', strlen($r->body), "\n";

$r = $s->post('https://httpbin.org/post', ['json' => ['a' => 1], 'timeout_ms' => 5000]);

try {
    $s->get('https://slow.example/');
} catch (Curlpro\CurlproException $e) {
    if ($e->errorCode === 'timeout') { /* retry */ }
}
```

The release archive `curlpro-php-<v>.zip` carries the library for every
platform in `lib/<platform>/` and the profiles in `profiles/`; the binding picks
the one for the machine.

FFI is off for web requests by default: set `ffi.enable=1`, or preload the
binding with `opcache.preload` and `ffi.enable=preload`.

```bash
CURLPRO_LIBRARY=../../dist/curlpro.dll CURLPRO_PROFILES=../../profiles php -d ffi.enable=1 example.php
```
