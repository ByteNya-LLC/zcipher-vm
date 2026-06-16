--TEST--
HydraStream argument validation throws ValueError
--SKIPIF--
<?php if (!extension_loaded("hydra_stream")) die("skip hydra_stream not available"); ?>
--FILE--
<?php
try {
    hydra_crypt("short", str_repeat("\0", 16), "x");
} catch (\ValueError $e) {
    echo $e->getMessage(), "\n";
}

try {
    hydra_crypt(str_repeat("\0", 32), "short", "x");
} catch (\ValueError $e) {
    echo $e->getMessage(), "\n";
}

try {
    hydra_keystream(str_repeat("\0", 32), str_repeat("\0", 16), -5);
} catch (\ValueError $e) {
    echo $e->getMessage(), "\n";
}

try {
    new HydraStream("k", "n");
} catch (\ValueError $e) {
    echo $e->getMessage(), "\n";
}
?>
--EXPECT--
hydra_crypt(): Argument #1 ($key) must be exactly 32 bytes
hydra_crypt(): Argument #2 ($nonce) must be exactly 16 bytes
hydra_keystream(): Argument #3 ($len) must be greater than or equal to 0
HydraStream::__construct(): Argument #1 ($key) must be exactly 32 bytes
--CREDITS--
HydraStream
