<?php
// CURLPRO_LIBRARY=../../dist/curlpro.dll CURLPRO_PROFILES=../../profiles php -d ffi.enable=1 example.php
require __DIR__ . '/src/curlpro.php';

use Curlpro\CurlproException;
use Curlpro\Library;
use Curlpro\Session;

echo 'libcurlpro ', Library::version(), "\n";
$s = new Session('chrome-156-windows');
echo 'ja4 offline:   ', $s->fingerprint('https://tls.peet.ws/')['ja4'], "\n";

$r = $s->get('https://tls.peet.ws/api/clean');
echo "{$r->status} {$r->proto} {$r->url}\n";
echo 'ja4 by server: ', $r->json()['ja4'], "\n";

try {
    new Session('no-such-browser');
} catch (CurlproException $e) {
    echo "error code: {$e->errorCode}, permanent: ", var_export($e->permanent(), true), "\n";
}
$s->close();
