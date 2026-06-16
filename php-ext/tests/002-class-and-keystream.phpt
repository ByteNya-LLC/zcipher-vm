--TEST--
HydraStream class streaming + hydra_keystream() determinism
--SKIPIF--
<?php if (!extension_loaded("hydra_stream")) die("skip hydra_stream not available"); ?>
--FILE--
<?php
$key   = str_repeat("\x09", 32);
$nonce = str_repeat("\x0a", 16);

// Two independent streams; identical chunk boundaries -> roundtrip.
$enc = new HydraStream($key, $nonce);
$dec = new HydraStream($key, $nonce);

$msg = "streaming chunks";          // 16 bytes
$c1  = $enc->crypt(substr($msg, 0, 8));
$c2  = $enc->crypt(substr($msg, 8));

$plain = $dec->crypt($c1) . $dec->crypt($c2);
var_dump($plain === $msg);

// keystream is deterministic for the same key+nonce
$ks1 = hydra_keystream($key, $nonce, 64);
$ks2 = hydra_keystream($key, $nonce, 64);
var_dump($ks1 === $ks2);
var_dump(strlen($ks1));

// constants are exported
var_dump(HYDRA_KEY_SIZE, HYDRA_NONCE_SIZE);
?>
--EXPECT--
bool(true)
bool(true)
int(64)
int(32)
int(16)
--CREDITS--
HydraStream
