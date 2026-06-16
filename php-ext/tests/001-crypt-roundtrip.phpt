--TEST--
hydra_crypt(): encrypt/decrypt roundtrip (procedural)
--SKIPIF--
<?php if (!extension_loaded("hydra_stream")) die("skip hydra_stream not available"); ?>
--FILE--
<?php
$key   = str_repeat("\x01", 32);
$nonce = str_repeat("\x02", 16);
$pt    = "Hello, HydraStream! This is a test message.";

$ct = hydra_crypt($key, $nonce, $pt);
var_dump($ct === $pt);              // ciphertext differs from plaintext

$back = hydra_crypt($key, $nonce, $ct);
var_dump($back === $pt);           // roundtrip recovers plaintext

echo strlen($ct), "\n";           // length preserved
var_dump(hydra_crypt($key, $nonce, "") === "");  // empty input
?>
--EXPECT--
bool(false)
bool(true)
43
bool(true)
--CREDITS--
HydraStream
