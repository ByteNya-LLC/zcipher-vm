# Calling the Generated HydraStream VM - Usage Guide

`SourceGenerator` generates three target implementations (Java / PHP / Go) from the same VM bytecode and writes them to:

```
build/generated-src/main/java/com/bytenya/zcipher/vm/gen/<Cls>.java
build/generated-src/php/<Cls>.php
build/generated-src/go/main.go
```

All three languages expose the **same entry function**. The function handles both initialization and encryption/decryption; the specific operation is selected by the `op` argument. The function name and class name are randomized from the seed on each generation run (obfuscation), so the generator also writes a `manifest.txt` file with the actual symbols callers should use.

## 1. Shared Calling Convention

| Argument | Meaning |
|----------|---------|
| `mem` | Persistent VM state buffer. **Must be null/empty on the first call**. The VM allocates and returns it after the call; later calls must pass back the previous returned `mem` unchanged. |
| `op` | `0` = initialization (key schedule + warm-up); `1` = encrypt/decrypt one data block. |
| `a` | When `op=0`, this is the key (32 bytes = 256 bits). When `op=1`, this is the input data. |
| `b` | When `op=0`, this is the nonce (16 bytes = 128 bits). When `op=1`, this is the output buffer (Java only; PHP/Go return output through the function result). |
| `len` | Ignored when `op=0`; pass `0`. When `op=1`, this is the data length. |

Constants:

- `HYDRA_KEY_SIZE = 32`
- `HYDRA_NONCE_SIZE = 16`
- This is a stream cipher, so encryption and decryption use the same function. To decrypt, run `init` again with the same key/nonce, then pass the ciphertext as the `op=1` input.

Typical flow (pseudocode):

```
mem = null
mem    = F(mem, 0, key,   nonce, 0)         // initialize
ct/out = F(mem, 1, plain, outBuf, len)      // encrypt / decrypt
```

> Run `op=0` again for every message (every key+nonce pair). The same key+nonce pair **must not be reused** for multiple messages. `runner.php` enforces this by resetting `mem` to `null` for each input line.

---

## 2. Java Target

Generated file: `build/generated-src/main/java/com/bytenya/zcipher/vm/gen/<Cls>.java`
Manifest: `.../vm/gen/manifest.txt` (first line is the FQCN, second line is the method name)

Signature:

```java
public static byte[] METHOD(byte[] mem, int op, byte[] a, byte[] b, int len)
```

- The return value is the **new / possibly expanded `mem`**. The next call must pass it back.
- When `op=1`, the ciphertext is also copied into the first `len` bytes of argument `b`, so `b.length` must be at least `len`.
- When `op=0`, `b` is the nonce and is not modified by this function.

Minimal example:

```java
import com.bytenya.zcipher.vm.gen.<Cls>;   // read from manifest.txt

byte[] key   = new byte[32];   // fill with the 256-bit key
byte[] nonce = new byte[16];   // fill with the 128-bit nonce (unique per message)
byte[] plain = "hello".getBytes();

byte[] mem = null;
mem = <Cls>.<method>(mem, 0, key, nonce, 0);           // init

byte[] ct = new byte[plain.length];
mem = <Cls>.<method>(mem, 1, plain, ct, plain.length); // encrypt

// Decrypt: initialize again, then crypt.
mem = <Cls>.<method>(mem, 0, key, nonce, 0);
byte[] back = new byte[ct.length];
mem = <Cls>.<method>(mem, 1, ct, back, ct.length);
```

Reflection call (when the compile-time class name is unknown):

```java
List<String> man = Files.readAllLines(Path.of("build/generated-src/main/java/com/bytenya/zcipher/vm/gen/manifest.txt"));
Class<?> cls = Class.forName(man.get(0));
Method  m   = cls.getMethod(man.get(1), byte[].class, int.class, byte[].class, byte[].class, int.class);

Object[] initArgs  = { null, 0, key, nonce, 0 };
byte[] mem = (byte[]) m.invoke(null, initArgs);
Object[] cryptArgs = { mem, 1, plain, new byte[plain.length], plain.length };
mem = (byte[]) m.invoke(null, cryptArgs);
byte[] ct = (byte[]) cryptArgs[3];   // output is in b
```

---

## 3. PHP Target

Generated file: `build/generated-src/php/<Cls>.php`
Manifests:
- `manifest.txt` - uses escaped double backslashes for convenient Java-side reading.
- `manifest.php.txt` - uses PHP-style separators and can be used directly by PHP callers.

Signature:

```php
namespace zcipher\vm\gen;
final class <Cls> {
    public static function METHOD(?string &$mem, int $op, string $a, string $b, int $len): string;
}
```

- `$mem` is passed **by reference**. Pass `null` on the first call, then keep using the same variable.
- When `op=0`, the function returns an empty string. When `op=1`, it returns a ciphertext string of length `$len` (PHP uses `string` as the byte buffer; **do not** treat it as text).
- When `op=1`, `$b` is only a placeholder. Pass an empty string `""`; output is returned by the function.

Minimal example:

```php
<?php
require 'build/generated-src/php/<Cls>.php';

[$ns, $mth] = file('build/generated-src/php/manifest.php.txt', FILE_IGNORE_NEW_LINES);
$fn = [$ns, $mth];   // equivalent to [\zcipher\vm\gen\<Cls>::class, '<method>']

$key   = hex2bin('00112233...');           // 32 bytes
$nonce = hex2bin('aabbccdd...');           // 16 bytes
$plain = "hello";

$mem = null;
call_user_func_array($fn, [&$mem, 0, $key, $nonce, 0]);     // init

$ct = call_user_func_array($fn, [&$mem, 1, $plain, '', strlen($plain)]); // encrypt

// Decrypt: initialize again.
$mem = null;
call_user_func_array($fn, [&$mem, 0, $key, $nonce, 0]);
$back = call_user_func_array($fn, [&$mem, 1, $ct, '', strlen($ct)]);
```

The repository includes `src/main/php/runner.php`, which already implements STDIN batch driving. Each input line has the format `keyHex|nonceHex|plaintextHex`, and the output is ciphertext hex. You can run it directly with `php runner.php build/generated-src/php/manifest.php.txt`.

---

## 4. Go Target

Generated file: `build/generated-src/go/main.go`
Manifest: `build/generated-src/go/manifest.txt` (one line, the function name `<FN>`)

Signature:

```go
func <FN>(mem []byte, op int, a []byte, b []byte, len int) (newMem []byte, out []byte)
```

- The function returns two slices: the first is the updated `mem`, and the second is the output.
- When `op=0`, `out == nil`. When `op=1`, `out` is a newly allocated `len`-byte ciphertext.
- The caller only needs to keep and pass back the first return value. The `b` argument is irrelevant in Go; pass `nil`. **Output is returned by the function.**

Minimal example (called from the same package as the generated `main.go`):

```go
key   := make([]byte, 32)
nonce := make([]byte, 16)
plain := []byte("hello")

var mem []byte
mem, _ = <FN>(mem, 0, key, nonce, 0)                 // init

var ct []byte
mem, ct = <FN>(mem, 1, plain, nil, len(plain))       // encrypt

// Decrypt: initialize again.
mem, _ = <FN>(mem, 0, key, nonce, 0)
var back []byte
mem, back = <FN>(mem, 1, ct, nil, len(ct))
_ = back
```

The generated `main.go` already includes a `main()` function. It reads `keyHex|nonceHex|ptHex` lines from STDIN and writes ciphertext hex lines, so it can be driven directly as a subprocess with `go run build/generated-src/go/main.go`. This is also how `GoEquivalenceCheck` validates it.

---

## 5. Quick Comparison Across Targets

| Item | Java | PHP | Go |
|------|------|-----|----|
| Entry point | Static method | Static method | Top-level function |
| `mem` passing | Argument + return value | Reference `&$mem` | Argument + first return value |
| Output | Written to `b` while `mem` is returned | Returned string | Second return value |
| `b` during crypt | Output buffer | Placeholder (pass `""`) | Placeholder (pass `nil`) |
| Symbol manifest | `manifest.txt` (FQCN + method name) | `manifest.txt` / `manifest.php.txt` | `manifest.txt` (function name) |

---

## 6. Common Pitfalls

- **Reusing key+nonce**: This is a stream cipher. Reuse is strictly forbidden. Every new message must use a different nonce; otherwise, XORing two ciphertexts directly leaks the XOR of the plaintexts.
- **Dropping `mem`**: Every call must pass back the `mem` returned by the previous call, or the VM state is lost. To reset, set `mem` back to `null/nil` and run `op=0` again.
- **Output location**: Java writes output to `b`; PHP / Go return it. Do not mix these up.
- **Case / endianness**: All buffers are byte arrays interpreted as `uint8`; `MUL32/REM32` use signed 32-bit semantics; the rest of the ALU truncates as unsigned 32-bit. These details are internal to the VM, so callers only see byte streams.
- **Generated symbols change**: Every `SourceGenerator` run with a different seed (default: `System.currentTimeMillis()`) changes class names, method names, and internal variable names. Callers should therefore read symbols from `manifest.txt` instead of hard-coding them.
