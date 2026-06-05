package com.bytenya.zcipher.vm.gen;

import com.bytenya.zcipher.HydraStream;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Loads the auto-generated obfuscated runtime via reflection (its class
 * and method names are randomized per build) and verifies the cipher
 * output matches the reference HydraStream byte-for-byte.
 */
class HydraStreamGeneratedTest {

    private static Method hydraMethod() throws Exception {
        Path manifest = Path.of("build", "generated-src", "main", "java",
                "com", "bytenya", "zcipher", "vm", "gen", "manifest.txt");
        List<String> lines = Files.readAllLines(manifest);
        String fqcn = lines.get(0).trim();
        String mth  = lines.get(1).trim();
        Class<?> cls = Class.forName(fqcn);
        return cls.getMethod(mth, byte[].class, int.class, byte[].class, byte[].class, int.class);
    }

    private static byte[] referenceCt(byte[] key, byte[] nonce, byte[] pt) {
        HydraStream.State st = new HydraStream.State();
        HydraStream.hydraInit(st, key, nonce);
        byte[] ct = new byte[pt.length];
        HydraStream.hydraCrypt(st, pt, ct, pt.length);
        return ct;
    }

    private static byte[] makeKey(int seed) {
        byte[] k = new byte[HydraStream.HYDRA_KEY_SIZE];
        for (int i = 0; i < k.length; i++) k[i] = (byte) (seed + i * 7);
        return k;
    }
    private static byte[] makeNonce(int seed) {
        byte[] n = new byte[HydraStream.HYDRA_NONCE_SIZE];
        for (int i = 0; i < n.length; i++) n[i] = (byte) (seed * 13 + i * 3);
        return n;
    }
    private static byte[] randomLikePlaintext(int len, int seed) {
        byte[] p = new byte[len];
        int x = seed | 1;
        for (int i = 0; i < len; i++) {
            x = x * 1664525 + 1013904223;
            p[i] = (byte) (x >>> 24);
        }
        return p;
    }

    @Test
    void singleEncryptMatchesReference() throws Exception {
        Method hydra = hydraMethod();
        assertNotNull(hydra);

        byte[] key = makeKey(0x42);
        byte[] nonce = makeNonce(0x99);
        byte[] pt = randomLikePlaintext(1234, 0xBEEF);

        byte[] mem = (byte[]) hydra.invoke(null, null, 0, key, nonce, 0);
        byte[] ct = new byte[pt.length];
        mem = (byte[]) hydra.invoke(null, mem, 1, pt, ct, pt.length);

        assertArrayEquals(referenceCt(key, nonce, pt), ct);
    }

    @Test
    void streamingMultipleCallsAdvancesState() throws Exception {
        Method hydra = hydraMethod();
        byte[] key = makeKey(0xF1);
        byte[] nonce = makeNonce(0xE2);

        int chunk = 200;
        int total = chunk * 5;

        // generated runtime: persistent mem across calls
        byte[] mem = (byte[]) hydra.invoke(null, null, 0, key, nonce, 0);
        byte[] genOut = new byte[total];
        byte[] zChunk = new byte[chunk];
        byte[] outChunk = new byte[chunk];
        for (int off = 0; off < total; off += chunk) {
            mem = (byte[]) hydra.invoke(null, mem, 1, zChunk, outChunk, chunk);
            System.arraycopy(outChunk, 0, genOut, off, chunk);
        }

        // reference: same chunked behaviour
        byte[] refOut = new byte[total];
        HydraStream.State st = new HydraStream.State();
        HydraStream.hydraInit(st, key, nonce);
        byte[] zChunk2 = new byte[chunk];
        byte[] outChunk2 = new byte[chunk];
        for (int off = 0; off < total; off += chunk) {
            HydraStream.hydraCrypt(st, zChunk2, outChunk2, chunk);
            System.arraycopy(outChunk2, 0, refOut, off, chunk);
        }
        assertArrayEquals(refOut, genOut);
    }

    @Test
    void variedLengths() throws Exception {
        Method hydra = hydraMethod();
        for (int len : new int[]{0, 1, 16, 127, 128, 129, 255, 256, 257, 1000, 4096}) {
            byte[] key = new byte[32];
            byte[] nonce = new byte[16];
            byte[] pt = randomLikePlaintext(len, len * 7919);

            byte[] mem = (byte[]) hydra.invoke(null, null, 0, key, nonce, 0);
            byte[] ct = new byte[len];
            mem = (byte[]) hydra.invoke(null, mem, 1, pt, ct, len);
            assertArrayEquals(referenceCt(key, nonce, pt), ct, "len=" + len);
        }
    }
}