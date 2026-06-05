<?php
declare(strict_types=1);

/*
 * Reads from STDIN: lines of "keyHex|nonceHex|plaintextHex".
 * Writes to STDOUT: ciphertext hex per input line.
 *
 * Loads the auto-generated obfuscated cipher class from the manifest.
 * One PHP process handles many vectors; the cipher state is fresh per
 * vector (we re-init mem each round via hydra(null, 0, key, nonce, 0)).
 */

$manifestPath = $argv[1] ?? 'build/generated-src/php/manifest.php.txt';
$phpDir       = dirname($manifestPath);

$manifest = file($manifestPath, FILE_IGNORE_NEW_LINES);
if ($manifest === false || count($manifest) < 2) {
    fwrite(STDERR, "bad manifest: $manifestPath\n");
    exit(2);
}
$fqcn = $manifest[0];
$mth  = $manifest[1];

$shortName = substr($fqcn, strrpos($fqcn, '\\') + 1);
require $phpDir . '/' . $shortName . '.php';

$callable = [$fqcn, $mth];

while (!feof(STDIN)) {
    $line = fgets(STDIN);
    if ($line === false) break;
    $line = trim($line);
    if ($line === '') continue;

    [$kh, $nh, $ph] = explode('|', $line);
    $key   = hex2bin($kh);
    $nonce = hex2bin($nh);
    $pt    = hex2bin($ph);
    $len   = strlen($pt);

    $mem = null;
    $argsInit = [&$mem, 0, $key, $nonce, 0];
    call_user_func_array($callable, $argsInit);

    $argsCrypt = [&$mem, 1, $pt, '', $len];
    $ct = call_user_func_array($callable, $argsCrypt);

    echo bin2hex($ct), "\n";
}