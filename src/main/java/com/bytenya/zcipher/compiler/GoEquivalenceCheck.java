package com.bytenya.zcipher.compiler;

import com.bytenya.zcipher.HydraStream;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

/**
 * Drives the auto-generated Go runtime through a `go run` subprocess and
 * verifies its ciphertext byte-for-byte against the reference HydraStream.
 */
public final class GoEquivalenceCheck {

    public static void main(String[] args) throws Exception {
        Path goFile = Path.of("build", "generated-src", "go", "main.go");
        if (!Files.exists(goFile)) throw new RuntimeException("missing " + goFile);

        ProcessBuilder pb = new ProcessBuilder("go", "run", goFile.toAbsolutePath().toString());
        pb.redirectErrorStream(false);
        Process p = pb.start();

        Random rng = new Random(0xC0FFEE);
        int[] lengths = {0, 1, 16, 127, 128, 129, 255, 256, 257, 1000, 4096};
        int n = lengths.length + 8;
        String[] expected = new String[n];
        String[] labels = new String[n];

        try (BufferedWriter w = new BufferedWriter(
                     new OutputStreamWriter(p.getOutputStream(), StandardCharsets.UTF_8))) {
            int idx = 0;
            for (int len : lengths) {
                byte[] key = new byte[32], nonce = new byte[16], pt = new byte[len];
                rng.nextBytes(key); rng.nextBytes(nonce); rng.nextBytes(pt);
                expected[idx] = toHex(reference(key, nonce, pt));
                labels[idx] = "zero-rng len=" + len;
                w.write(toHex(key) + "|" + toHex(nonce) + "|" + toHex(pt));
                w.newLine();
                idx++;
            }
            for (int trial = 0; trial < 8; trial++) {
                int len = 100 + rng.nextInt(3000);
                byte[] key = new byte[32], nonce = new byte[16], pt = new byte[len];
                rng.nextBytes(key); rng.nextBytes(nonce); rng.nextBytes(pt);
                expected[idx] = toHex(reference(key, nonce, pt));
                labels[idx] = "rand trial=" + trial + " len=" + len;
                w.write(toHex(key) + "|" + toHex(nonce) + "|" + toHex(pt));
                w.newLine();
                idx++;
            }
        }

        int total = 0, failed = 0;
        try (BufferedReader r = new BufferedReader(
                     new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            for (int i = 0; i < expected.length; i++) {
                String got = r.readLine();
                boolean ok = expected[i].equals(got);
                System.out.println((ok ? "PASS" : "FAIL") + " " + labels[i]);
                if (!ok) {
                    System.out.println("  expected: " + truncate(expected[i]));
                    System.out.println("  got:      " + truncate(got));
                    failed++;
                }
                total++;
            }
        }

        try (BufferedReader er = new BufferedReader(
                     new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = er.readLine()) != null) System.err.println("[go] " + line);
        }
        int rc = p.waitFor();

        System.out.println();
        System.out.println(total - failed + "/" + total + " Go equivalence cases passed (go exit=" + rc + ")");
        if (failed != 0 || rc != 0) System.exit(1);
    }

    private static byte[] reference(byte[] key, byte[] nonce, byte[] pt) {
        HydraStream.State st = new HydraStream.State();
        HydraStream.hydraInit(st, key, nonce);
        byte[] ct = new byte[pt.length];
        HydraStream.hydraCrypt(st, pt, ct, pt.length);
        return ct;
    }

    private static String toHex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte v : b) s.append(String.format("%02x", v & 0xFF));
        return s.toString();
    }

    private static String truncate(String s) {
        if (s == null) return "<null>";
        return s.length() <= 64 ? s : s.substring(0, 60) + "...(" + s.length() + ")";
    }
}