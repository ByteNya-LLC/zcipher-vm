# hydra_stream — PHP extension

A native PHP extension that wraps the **HydraStream** stream cipher defined in
[`../hydra_stream.h`](../hydra_stream.h). Unlike the generated PHP runtime
produced by `SourceGenerator` (which runs the obfuscation VM in pure PHP), this
extension calls the original C implementation directly, so it is fast and a
1:1 match of the reference cipher.

Tested against **PHP 8.0** and **PHP 8.4** (the C API used here is stable across
8.0 → 8.4).

## API

```php
// Procedural (one-shot, fresh state per call)
string hydra_crypt(string $key, string $nonce, string $data);     // encrypt == decrypt (XOR keystream)
string hydra_keystream(string $key, string $nonce, int $len);     // raw keystream bytes

// Object oriented (persistent stream state across calls)
final class HydraStream {
    public function __construct(string $key, string $nonce);
    public function crypt(string $data): string;     // advances the stream
    public function keystream(int $len): string;     // advances the stream
    public function reset(string $key, string $nonce): void;
}

// Exported constants
HYDRA_KEY_SIZE;    // 32  (256-bit key)
HYDRA_NONCE_SIZE;  // 16  (128-bit nonce)
```

- `$key` **must** be exactly 32 bytes, `$nonce` exactly 16 bytes — otherwise a
  `ValueError` is thrown.
- This is a stream cipher: encryption and decryption are the same operation.
  Re-initialize (new object / fresh `hydra_crypt` call) with the same key+nonce
  to decrypt.
- **Never reuse a key+nonce pair** for two different messages.
- All buffers are binary-safe PHP strings (may contain NUL bytes).

### Example

```php
<?php
$key   = random_bytes(HYDRA_KEY_SIZE);
$nonce = random_bytes(HYDRA_NONCE_SIZE);

$ct = hydra_crypt($key, $nonce, "secret payload");
$pt = hydra_crypt($key, $nonce, $ct);   // back to plaintext

// Streaming form:
$h  = new HydraStream($key, $nonce);
$c1 = $h->crypt($chunk1);
$c2 = $h->crypt($chunk2);
```

## Building

### Option A — Docker (builds 8.0 and 8.4 in one go) — recommended

Requires Docker only; no local PHP dev tools needed.

```bash
./build-docker.sh             # builds PHP 8.0 and 8.4, runs the test suite
./build-docker.sh 8.1 8.2     # build any other versions
```

Outputs go to `dist/`:

```
dist/hydra_stream-php8.0.so
dist/hydra_stream-php8.4.so
```

### Option B — Local toolchain

Requires the PHP development package for the target version
(`apt install php-dev`, `dnf install php-devel`, …), which provides `phpize`
and `php-config`.

```bash
./build-local.sh                          # uses phpize/php-config on PATH
PHP_CONFIG=php-config8.0 ./build-local.sh  # target a specific version
```

Then run the tests:

```bash
make test
```

The built module is at `modules/hydra_stream.so`.

### From Gradle (root project)

```bash
./gradlew buildPhpExtension      # delegates to ./build-docker.sh
```

## Installing

Copy the matching `.so` into your PHP extension directory and enable it:

```bash
cp dist/hydra_stream-php8.4.so "$(php-config --extension-dir)/hydra_stream.so"
echo "extension=hydra_stream.so" > /etc/php/8.4/cli/conf.d/30-hydra_stream.ini
php -m | grep hydra_stream
```

Or load it ad-hoc:

```bash
php -d extension=dist/hydra_stream-php8.4.so -r 'var_dump(function_exists("hydra_crypt"));'
```

## Files

| File | Purpose |
|------|---------|
| `hydra_stream_ext.c` | Extension glue (functions, `HydraStream` class) |
| `php_hydra_stream.h` | Module header |
| `config.m4` / `config.w32` | `phpize` build config (Unix / Windows) |
| `tests/*.phpt` | Test suite run by `make test` |
| `build-docker.sh` | Multi-version Docker build |
| `build-local.sh` | Local `phpize` build |
