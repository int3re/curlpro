<?php
// Prints the offline JA4 of chrome-156-windows for https://example.com/ — the
// value scripts/bindings-agree.sh compares across every binding.
require __DIR__ . '/src/curlpro.php';

$s = new Curlpro\Session('chrome-156-windows');
echo $s->fingerprint('https://example.com/')['ja4'], PHP_EOL;
$s->close();
