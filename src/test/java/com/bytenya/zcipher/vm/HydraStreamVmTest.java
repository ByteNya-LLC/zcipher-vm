package com.bytenya.zcipher.vm;

import com.bytenya.zcipher.HydraStream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Mirror of HydraStreamTest that drives the cipher through the ZCipher VM.
 * Each test gets a fresh HydraStreamVm; the cipher state lives inside the VM.
 */
class HydraStreamVmTest {

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

    private static HydraStreamVm freshVm(byte[] key, byte[] nonce) {
        HydraStreamVm vm = new HydraStreamVm();
        vm.hydraInit(key, nonce);
        return vm;
    }

    private static byte[] referenceCt(byte[] key, byte[] nonce, byte[] pt) {
        HydraStream.State st = new HydraStream.State();
        HydraStream.hydraInit(st, key, nonce);
        byte[] ct = new byte[pt.length];
        HydraStream.hydraCrypt(st, pt, ct, pt.length);
        return ct;
    }

    @Test
    void roundTripMatchesReference() {
        byte[] key = makeKey(0x11);
        byte[] nonce = makeNonce(0x22);
        byte[] pt = randomLikePlaintext(1000, 0xC0FFEE);

        byte[] vmCt = new byte[pt.length];
        freshVm(key, nonce).hydraCrypt(pt, vmCt, pt.length);
        assertArrayEquals(referenceCt(key, nonce, pt), vmCt);

        byte[] back = new byte[pt.length];
        freshVm(key, nonce).hydraCrypt(vmCt, back, vmCt.length);
        assertArrayEquals(pt, back);
    }

    @Test
    void roundTripAcrossManyBlocks() {
        int len = HydraStream.HYDRA_BLOCK_BYTES * 7 + 37;
        byte[] key = makeKey(0xAB);
        byte[] nonce = makeNonce(0xCD);
        byte[] pt = randomLikePlaintext(len, 0xDEADBEEF);

        byte[] vmCt = new byte[len];
        freshVm(key, nonce).hydraCrypt(pt, vmCt, len);
        assertArrayEquals(referenceCt(key, nonce, pt), vmCt);
    }

    @Test
    void inPlaceEncryptionWorks() {
        byte[] key = makeKey(7);
        byte[] nonce = makeNonce(9);
        byte[] pt = randomLikePlaintext(513, 42);
        byte[] buf = pt.clone();

        freshVm(key, nonce).hydraCrypt(buf, buf, buf.length);
        assertFalse(java.util.Arrays.equals(pt, buf));
        freshVm(key, nonce).hydraCrypt(buf, buf, buf.length);
        assertArrayEquals(pt, buf);
    }

    @Test
    void zeroLengthInputIsNoop() {
        byte[] key = makeKey(1);
        byte[] nonce = makeNonce(2);
        byte[] in = new byte[0];
        byte[] out = new byte[0];
        freshVm(key, nonce).hydraCrypt(in, out, 0);
        freshVm(key, nonce).hydraKeystream(out, 0);
    }

    @Test
    void keystreamMatchesReference() {
        byte[] key = makeKey(5);
        byte[] nonce = makeNonce(11);
        int len = 4096;

        byte[] refKs = new byte[len];
        {
            HydraStream.State st = new HydraStream.State();
            HydraStream.hydraInit(st, key, nonce);
            HydraStream.hydraKeystream(st, refKs, len);
        }
        byte[] vmKs = new byte[len];
        freshVm(key, nonce).hydraKeystream(vmKs, len);
        assertArrayEquals(refKs, vmKs);
    }

    @Test
    void differentKeysProduceDifferentKeystreams() {
        byte[] nonce = makeNonce(1);
        byte[] keyA = makeKey(0);
        byte[] keyB = makeKey(0);
        keyB[0] ^= 0x01;

        byte[] ksA = new byte[256];
        byte[] ksB = new byte[256];
        freshVm(keyA, nonce).hydraKeystream(ksA, 256);
        freshVm(keyB, nonce).hydraKeystream(ksB, 256);
        assertFalse(java.util.Arrays.equals(ksA, ksB));
    }

    @Test
    void cryptingZerosEqualsKeystream() {
        byte[] key = makeKey(0x55);
        byte[] nonce = makeNonce(0xAA);
        int len = HydraStream.HYDRA_BLOCK_BYTES * 3 + 5;

        byte[] zeros = new byte[len];
        byte[] ct = new byte[len];
        freshVm(key, nonce).hydraCrypt(zeros, ct, len);

        byte[] ks = new byte[len];
        freshVm(key, nonce).hydraKeystream(ks, len);

        assertArrayEquals(ks, ct);
    }

    @Test
    void firstBlockChangesPerKey() {
        byte[] nonce = makeNonce(0);
        byte[] keyA = makeKey(0);
        byte[] keyB = keyA.clone();
        keyB[31] ^= 0x01;

        byte[] a = new byte[HydraStream.HYDRA_BLOCK_BYTES];
        byte[] b = new byte[HydraStream.HYDRA_BLOCK_BYTES];
        freshVm(keyA, nonce).hydraKeystream(a, a.length);
        freshVm(keyB, nonce).hydraKeystream(b, b.length);

        int diff = 0;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) diff++;
        assertTrue(diff > a.length / 4);
    }

    @Test
    void keystreamDistribution() {
        byte[] key = makeKey(0x12);
        byte[] nonce = makeNonce(0x34);
        int len = 16384;
        byte[] ks = new byte[len];
        freshVm(key, nonce).hydraKeystream(ks, len);

        int[] hist = new int[256];
        for (int i = 0; i < len; i++) hist[ks[i] & 0xFF]++;

        int nonZero = 0;
        for (int c : hist) if (c > 0) nonZero++;
        assertEquals(256, nonZero);
    }

    @Test
    void successiveCryptCallsContinueStreamFromState() {
        // The whole point of embedded state: a single VM instance keeps the
        // cipher counter advancing across multiple hydraCrypt calls, matching
        // the reference's state-threaded behavior.
        byte[] key = makeKey(0xF1);
        byte[] nonce = makeNonce(0xE2);
        int chunk = 200;
        int total = chunk * 5;

        byte[] refKs = new byte[total];
        HydraStream.State st = new HydraStream.State();
        HydraStream.hydraInit(st, key, nonce);
        HydraStream.hydraKeystream(st, refKs, total);

        // Pull the same bytes from the VM via repeated calls on one instance.
        byte[] vmOut = new byte[total];
        HydraStreamVm vm = freshVm(key, nonce);
        byte[] zeros = new byte[chunk];
        byte[] piece = new byte[chunk];
        for (int off = 0; off < total; off += chunk) {
            vm.hydraCrypt(zeros, piece, chunk);
            System.arraycopy(piece, 0, vmOut, off, chunk);
        }

        // Note: HydraStream.hydraCrypt re-allocates its internal block buffer
        // per call too, so chunked vs single does NOT match the reference's
        // hydraCrypt either (block-boundary loss). We instead compare against
        // chunked reference.
        byte[] refChunked = new byte[total];
        HydraStream.State st2 = new HydraStream.State();
        HydraStream.hydraInit(st2, key, nonce);
        byte[] zPiece = new byte[chunk];
        byte[] outPiece = new byte[chunk];
        for (int off = 0; off < total; off += chunk) {
            HydraStream.hydraCrypt(st2, zPiece, outPiece, chunk);
            System.arraycopy(outPiece, 0, refChunked, off, chunk);
        }

        assertArrayEquals(refChunked, vmOut);
    }
}