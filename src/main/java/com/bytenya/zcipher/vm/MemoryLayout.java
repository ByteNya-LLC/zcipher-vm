package com.bytenya.zcipher.vm;

/*
 * Fixed addresses inside the VM's flat byte memory.
 *
 * Layout:
 *
 *   0      .. 199   state struct (always lives at address 0)
 *   200    .. 4295  HYDRA_SBOX (1024 i32, little-endian)
 *   4296   .. 4327  HYDRA_PHI  (8    i32, little-endian)
 *   4328   .. ...   per-method scratch (one slot per inlined NEWARRAY site)
 *   ...    .. ...   per-method I/O buffers (key/nonce/in/out)
 *
 * The state, sbox and phi offsets are compile-time constants and the
 * translator bakes them into the emitted bytecode as immediates.
 * Scratch and I/O bases are passed in via argument registers.
 */
public final class MemoryLayout {
    private MemoryLayout() {}

    /* ── state struct (mirrors HydraStream.State field-by-field) ── */
    public static final int STATE_BASE   = 0;
    public static final int OFF_LANE     = 0;       // int[32] — 128 bytes
    public static final int OFF_FEEDBACK = 128;     // int
    public static final int OFF_SELECTOR = 132;     // int
    public static final int OFF_ROUNDKEY = 136;     // int
    public static final int OFF_MIXACC   = 140;     // int
    public static final int OFF_COUNTER  = 144;     // long (8 bytes)
    public static final int OFF_KEY      = 152;     // byte[32]
    public static final int OFF_NONCE    = 184;     // byte[16]
    public static final int STATE_SIZE   = 200;

    /* ── constant pool ── */
    public static final int SBOX_BASE = 200;
    public static final int SBOX_SIZE = 4 * 256 * 4;     // 4096
    public static final int PHI_BASE  = SBOX_BASE + SBOX_SIZE;   // 4296
    public static final int PHI_SIZE  = 8 * 4;                   // 32

    /* ── start of per-method scratch region ── */
    public static final int SCRATCH_BASE = PHI_BASE + PHI_SIZE;  // 4328

    private static int[] reflectIntField(String name) {
        try {
            java.lang.reflect.Field f = com.bytenya.zcipher.HydraStream.class
                    .getDeclaredField(name);
            f.setAccessible(true);
            return (int[]) f.get(null);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    public static int[] hydraSbox() { return reflectIntField("HYDRA_SBOX"); }
    public static int[] hydraPhi()  { return reflectIntField("HYDRA_PHI"); }

    /** Write the constant pool (sbox + phi) into memory at their fixed offsets. */
    public static void writeConstants(byte[] mem) {
        int[] sbox = hydraSbox();
        for (int i = 0; i < sbox.length; i++) {
            writeWord(mem, SBOX_BASE + i * 4, sbox[i]);
        }
        int[] phi = hydraPhi();
        for (int i = 0; i < phi.length; i++) {
            writeWord(mem, PHI_BASE + i * 4, phi[i]);
        }
    }

    public static void writeWord(byte[] mem, int off, int v) {
        mem[off    ] = (byte)  v;
        mem[off + 1] = (byte) (v >>>  8);
        mem[off + 2] = (byte) (v >>> 16);
        mem[off + 3] = (byte) (v >>> 24);
    }

    public static int readWord(byte[] mem, int off) {
        return  (mem[off    ] & 0xFF)
              | ((mem[off + 1] & 0xFF) <<  8)
              | ((mem[off + 2] & 0xFF) << 16)
              | ((mem[off + 3] & 0xFF) << 24);
    }

    public static void writeLong(byte[] mem, int off, long v) {
        for (int i = 0; i < 8; i++) {
            mem[off + i] = (byte) (v >>> (i * 8));
        }
    }

    public static long readLong(byte[] mem, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= (((long) mem[off + i]) & 0xFFL) << (i * 8);
        }
        return v;
    }
}