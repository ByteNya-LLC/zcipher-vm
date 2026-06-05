package com.bytenya.zcipher.compiler;

import com.bytenya.zcipher.HydraStream;
import com.bytenya.zcipher.vm.HydraStreamVm;

import java.util.Arrays;
import java.util.Random;

/**
 * Bulk-random equivalence sweep: drive HydraStream and HydraStreamVm with the
 * same key/nonce/plaintext, fail loudly if any byte differs.
 */
public final class VmEquivalenceCheck {

    public static void main(String[] args) {
        Random rng = new Random(0xC0FFEE);
        int total = 0, failed = 0;

        // Set 1: zero key/nonce, varied lengths spanning block boundaries.
        for (int len : new int[]{0, 1, 16, 127, 128, 129, 255, 256, 257, 1000, 4096}) {
            byte[] key = new byte[32];
            byte[] nonce = new byte[16];
            byte[] pt = new byte[len];
            rng.nextBytes(pt);
            total++;
            if (!compareCase(key, nonce, pt, "zero-kn len=" + len)) failed++;
        }

        // Set 2: random key/nonce.
        for (int trial = 0; trial < 8; trial++) {
            byte[] key = new byte[32];
            byte[] nonce = new byte[16];
            rng.nextBytes(key);
            rng.nextBytes(nonce);
            int len = 64 + rng.nextInt(4096);
            byte[] pt = new byte[len];
            rng.nextBytes(pt);
            total++;
            if (!compareCase(key, nonce, pt, "rand trial=" + trial + " len=" + len)) failed++;
        }

        // Set 3: roundtrip — encrypt with VM, decrypt with original.
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[16];
            rng.nextBytes(key);
            rng.nextBytes(nonce);
            byte[] pt = new byte[1500];
            rng.nextBytes(pt);

            HydraStreamVm vm = new HydraStreamVm();
            vm.hydraInit(key, nonce);
            byte[] ct = new byte[pt.length];
            vm.hydraCrypt(pt, ct, pt.length);

            HydraStream.State s2 = new HydraStream.State();
            HydraStream.hydraInit(s2, key, nonce);
            byte[] back = new byte[ct.length];
            HydraStream.hydraCrypt(s2, ct, back, ct.length);

            total++;
            boolean ok = Arrays.equals(pt, back);
            System.out.println((ok ? "PASS" : "FAIL") + " roundtrip vm-encrypt -> orig-decrypt");
            if (!ok) failed++;
        }

        System.out.println();
        System.out.println("Equivalence: " + (total - failed) + "/" + total + " passed.");
        if (failed != 0) System.exit(1);
    }

    private static boolean compareCase(byte[] key, byte[] nonce, byte[] pt, String label) {
        int len = pt.length;

        HydraStream.State stOrig = new HydraStream.State();
        byte[] origCt = new byte[len];
        HydraStream.hydraInit(stOrig, key, nonce);
        HydraStream.hydraCrypt(stOrig, pt, origCt, len);

        HydraStreamVm vm = new HydraStreamVm();
        vm.hydraInit(key, nonce);
        byte[] vmCt = new byte[len];
        vm.hydraCrypt(pt, vmCt, len);

        boolean ok = Arrays.equals(origCt, vmCt);
        System.out.println((ok ? "PASS" : "FAIL") + " " + label
                + " [ct=" + (ok ? "ok" : "MISMATCH") + "]");
        if (!ok && len > 0) {
            int mis = 0;
            for (int i = 0; i < Math.min(len, 16); i++) {
                if (origCt[i] != vmCt[i]) mis++;
            }
            System.out.printf("  (first-16-byte mismatches: %d, first orig=%02x vm=%02x)%n",
                    mis, origCt[0] & 0xFF, vmCt[0] & 0xFF);
        }
        return ok;
    }
}