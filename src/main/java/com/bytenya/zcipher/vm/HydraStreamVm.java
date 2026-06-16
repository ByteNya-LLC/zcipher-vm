package com.bytenya.zcipher.vm;

import com.bytenya.zcipher.HydraStream;
import com.bytenya.zcipher.compiler.JvmToVmTranslator;
import com.bytenya.zcipher.compiler.JvmToVmTranslator.CompiledMethod;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/*
 * Stream-cipher engine running entirely inside the ZCipher VM.
 *
 * The cipher state lives in this VM's flat byte memory at MemoryLayout.STATE_BASE
 * and persists between hydraInit / hydraCrypt calls — there is no Java
 * State object to marshal in or out. Each instance owns one cipher state;
 * use a fresh instance to start a new key+nonce session.
 */
public final class HydraStreamVm {

    public static final Path INLINED_CLASS_PATH = Path.of(
            "build", "generated-classes", "com", "bytenya", "zcipher", "HydraStream.class");

    private static final CompiledMethod INIT;
    private static final CompiledMethod CRYPT;

    static {
        try {
            INIT = compileMethod("hydraInit");
            CRYPT = compileMethod("hydraCrypt");
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final long[] initRegs;

    /* ── per-instance VM state ──────────────────────────────────────── */
    private final long[] cryptRegs;
    private byte[] mem;
    public HydraStreamVm() {
        this.initRegs = new long[INIT.regCount()];
        this.cryptRegs = new long[CRYPT.regCount()];
        // Initial size covers the state struct + constants + larger of the two
        // scratch regions + a key/nonce buffer pair (used by hydraInit). The
        // crypt path may grow this on the fly when len is large.
        int initialSize = MemoryLayout.SCRATCH_BASE
                + Math.max(INIT.scratchSize(), CRYPT.scratchSize())
                + HydraStream.HYDRA_KEY_SIZE + HydraStream.HYDRA_NONCE_SIZE + 8;
        this.mem = new byte[initialSize];
        MemoryLayout.writeConstants(mem);
    }

    private static CompiledMethod compileMethod(String name) throws IOException {
        if (!Files.exists(INLINED_CLASS_PATH)) {
            throw new IOException("Inlined class missing at " + INLINED_CLASS_PATH.toAbsolutePath()
                    + " — run ZCipherCompilerMain first.");
        }
        byte[] bytes = Files.readAllBytes(INLINED_CLASS_PATH);
        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        for (MethodNode m : cn.methods) {
            if (m.name.equals(name)) {
                return new JvmToVmTranslator(cn, m).translate();
            }
        }
        throw new IllegalStateException("method " + name + " not found in inlined class");
    }

    /* ── public API ─────────────────────────────────────────────────── */

    /* exposed for diagnostics */
    public static CompiledMethod compiledHydraInit() {
        return INIT;
    }

    public static CompiledMethod compiledHydraCrypt() {
        return CRYPT;
    }

    public void hydraInit(byte[] key, byte[] nonce) {
        if (key.length != HydraStream.HYDRA_KEY_SIZE)
            throw new IllegalArgumentException("key must be " + HydraStream.HYDRA_KEY_SIZE + " bytes");
        if (nonce.length != HydraStream.HYDRA_NONCE_SIZE)
            throw new IllegalArgumentException("nonce must be " + HydraStream.HYDRA_NONCE_SIZE + " bytes");

        int keyAddr = MemoryLayout.SCRATCH_BASE + INIT.scratchSize();
        int nonceAddr = keyAddr + HydraStream.HYDRA_KEY_SIZE;
        ensureMem(nonceAddr + HydraStream.HYDRA_NONCE_SIZE + 8);

        System.arraycopy(key, 0, mem, keyAddr, HydraStream.HYDRA_KEY_SIZE);
        System.arraycopy(nonce, 0, mem, nonceAddr, HydraStream.HYDRA_NONCE_SIZE);

        initRegs[0] = MemoryLayout.STATE_BASE;
        initRegs[1] = keyAddr;
        initRegs[2] = nonceAddr;

        Interpreter.run(INIT.bytecode(), initRegs, mem);
    }

    /* ── memory growth ──────────────────────────────────────────────── */

    public void hydraCrypt(byte[] in, byte[] out, int len) {
        int inAddr = MemoryLayout.SCRATCH_BASE + CRYPT.scratchSize();
        int outAddr = inAddr + len;
        ensureMem(outAddr + len + 8);

        if (len > 0) System.arraycopy(in, 0, mem, inAddr, len);

        cryptRegs[0] = MemoryLayout.STATE_BASE;
        cryptRegs[1] = inAddr;
        cryptRegs[2] = outAddr;
        cryptRegs[3] = len;

        Interpreter.run(CRYPT.bytecode(), cryptRegs, mem);

        if (len > 0) System.arraycopy(mem, outAddr, out, 0, len);
    }

    public void hydraKeystream(byte[] out, int len) {
        // Mirror HydraStream.hydraKeystream: encrypt zeros.
        byte[] zeros = new byte[len];
        hydraCrypt(zeros, out, len);
    }

    private void ensureMem(int needed) {
        if (mem.length >= needed) return;
        byte[] grown = new byte[Math.max(needed, mem.length * 2)];
        // State + constants live in the prefix; copy them forward.
        System.arraycopy(mem, 0, grown, 0, mem.length);
        mem = grown;
    }
}