package com.bytenya.zcipher.compiler;

import com.bytenya.zcipher.HydraStream;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

public class InlineEquivalenceCheck {

    private static final String INLINED_CLASS = "com.bytenya.zcipher.HydraStream";
    private static final Path INLINED_PATH = Path.of(
            "build", "generated-classes", "com", "bytenya", "zcipher", "HydraStream.class");

    static void main(String[] args) throws Exception {
        if (!Files.exists(INLINED_PATH)) {
            System.err.println("Inlined class missing at " + INLINED_PATH.toAbsolutePath()
                    + " — run ZCipherCompilerMain first.");
            System.exit(2);
        }
        byte[] inlinedBytes = Files.readAllBytes(INLINED_PATH);

        ClassLoader parent = HydraStream.class.getClassLoader();
        ClassLoader inlinedLoader = new ClassLoader(parent) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                synchronized (getClassLoadingLock(name)) {
                    if (INLINED_CLASS.equals(name)) {
                        Class<?> c = findLoadedClass(name);
                        if (c == null) {
                            c = defineClass(name, inlinedBytes, 0, inlinedBytes.length);
                        }
                        if (resolve) resolveClass(c);
                        return c;
                    }
                    return super.loadClass(name, resolve);
                }
            }
        };

        Class<?> inlined = inlinedLoader.loadClass(INLINED_CLASS);
        Class<?> stateClass = HydraStream.State.class;
        Method inlinedInit = inlined.getMethod("hydraInit", stateClass, byte[].class, byte[].class);
        Method inlinedCrypt = inlined.getMethod("hydraCrypt", stateClass, byte[].class, byte[].class, int.class);

        Random rng = new Random(0xC0FFEE);
        int total = 0;
        int failed = 0;

        // Case set 1: zero key/nonce, varied lengths spanning block boundary (128 B).
        for (int len : new int[]{0, 1, 16, 127, 128, 129, 255, 256, 257, 1000, 4096}) {
            byte[] key = new byte[32];
            byte[] nonce = new byte[16];
            byte[] pt = new byte[len];
            rng.nextBytes(pt);
            total++;
            if (!compareCase(inlinedInit, inlinedCrypt, key, nonce, pt, "zero-kn len=" + len)) failed++;
        }

        // Case set 2: random key/nonce.
        for (int trial = 0; trial < 8; trial++) {
            byte[] key = new byte[32];
            byte[] nonce = new byte[16];
            rng.nextBytes(key);
            rng.nextBytes(nonce);
            int len = 64 + rng.nextInt(4096);
            byte[] pt = new byte[len];
            rng.nextBytes(pt);
            total++;
            if (!compareCase(inlinedInit, inlinedCrypt, key, nonce, pt, "rand trial=" + trial + " len=" + len))
                failed++;
        }

        // Case set 3: 1-bit key flip should produce identical-length but completely different ciphertext.
        {
            byte[] key1 = new byte[32];
            byte[] key2 = new byte[32];
            byte[] nonce = new byte[16];
            rng.nextBytes(key1);
            System.arraycopy(key1, 0, key2, 0, 32);
            key2[7] ^= 0x01;
            rng.nextBytes(nonce);
            byte[] pt = new byte[512];

            byte[] ct1 = encryptWithInlined(inlinedInit, inlinedCrypt, key1, nonce, pt);
            byte[] ct2 = encryptWithInlined(inlinedInit, inlinedCrypt, key2, nonce, pt);
            byte[] origCt1 = encryptWithOriginal(key1, nonce, pt);
            byte[] origCt2 = encryptWithOriginal(key2, nonce, pt);
            total += 2;
            boolean ok1 = Arrays.equals(ct1, origCt1);
            boolean ok2 = Arrays.equals(ct2, origCt2);
            System.out.println((ok1 ? "PASS" : "FAIL") + " key-sensitivity ct1 == orig");
            System.out.println((ok2 ? "PASS" : "FAIL") + " key-sensitivity ct2 == orig");
            if (!ok1) failed++;
            if (!ok2) failed++;
            // Sanity: the two ciphertexts under different keys must differ (catches a stuck pass).
            int diff = 0;
            for (int i = 0; i < ct1.length; i++) if (ct1[i] != ct2[i]) diff++;
            System.out.println("  (ct1 vs ct2 differing bytes: " + diff + " / " + ct1.length + ")");
        }

        // Case set 4: cross roundtrip — encrypt with inlined, decrypt with original.
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[16];
            rng.nextBytes(key);
            rng.nextBytes(nonce);
            byte[] pt = new byte[1500];
            rng.nextBytes(pt);
            byte[] ct = encryptWithInlined(inlinedInit, inlinedCrypt, key, nonce, pt);
            byte[] back = encryptWithOriginal(key, nonce, ct);
            total++;
            boolean ok = Arrays.equals(pt, back);
            System.out.println((ok ? "PASS" : "FAIL") + " roundtrip inlined-encrypt -> orig-decrypt");
            if (!ok) failed++;
        }

        System.out.println();
        System.out.println("Equivalence: " + (total - failed) + "/" + total + " passed.");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static boolean compareCase(Method inlinedInit, Method inlinedCrypt,
                                       byte[] key, byte[] nonce, byte[] pt, String label) throws Exception {
        int len = pt.length;

        HydraStream.State stOrig = new HydraStream.State();
        byte[] origCt = new byte[len];
        HydraStream.hydraInit(stOrig, key, nonce);
        HydraStream.hydraCrypt(stOrig, pt, origCt, len);

        HydraStream.State stIn = new HydraStream.State();
        byte[] inCt = new byte[len];
        inlinedInit.invoke(null, stIn, key, nonce);
        inlinedCrypt.invoke(null, stIn, pt, inCt, len);

        boolean ctMatch = Arrays.equals(origCt, inCt);
        boolean stateMatch = stateEquals(stOrig, stIn);
        boolean ok = ctMatch && stateMatch;
        System.out.println((ok ? "PASS" : "FAIL") + " " + label
                + " [ct=" + (ctMatch ? "ok" : "MISMATCH")
                + ", state=" + (stateMatch ? "ok" : "MISMATCH") + "]");
        return ok;
    }

    private static byte[] encryptWithInlined(Method inlinedInit, Method inlinedCrypt,
                                             byte[] key, byte[] nonce, byte[] pt) throws Exception {
        HydraStream.State st = new HydraStream.State();
        byte[] ct = new byte[pt.length];
        inlinedInit.invoke(null, st, key, nonce);
        inlinedCrypt.invoke(null, st, pt, ct, pt.length);
        return ct;
    }

    private static byte[] encryptWithOriginal(byte[] key, byte[] nonce, byte[] pt) {
        HydraStream.State st = new HydraStream.State();
        byte[] ct = new byte[pt.length];
        HydraStream.hydraInit(st, key, nonce);
        HydraStream.hydraCrypt(st, pt, ct, pt.length);
        return ct;
    }

    private static boolean stateEquals(HydraStream.State a, HydraStream.State b) {
        if (!Arrays.equals(a.lane, b.lane)) return false;
        if (a.feedback != b.feedback) return false;
        if (a.selector != b.selector) return false;
        if (a.roundKey != b.roundKey) return false;
        if (a.mixAcc != b.mixAcc) return false;
        if (a.counter != b.counter) return false;
        if (!Arrays.equals(a.key, b.key)) return false;
        return Arrays.equals(a.nonce, b.nonce);
    }
}
