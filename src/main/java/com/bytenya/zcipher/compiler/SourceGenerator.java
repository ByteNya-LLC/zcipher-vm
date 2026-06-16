package com.bytenya.zcipher.compiler;

import com.bytenya.zcipher.HydraStream;
import com.bytenya.zcipher.compiler.JvmToVmTranslator.CompiledMethod;
import com.bytenya.zcipher.vm.MemoryLayout;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public final class SourceGenerator {

    private static final String OUT_PKG = "com.bytenya.zcipher.vm.gen";
    private static final String OUT_PHP_NS = "zcipher\\vm\\gen";
    // Go output: package main, single-file program that includes a runner.

    private final Names N;
    private final byte[] xorKey;

    public SourceGenerator(long seed) {
        Random r = new Random(seed);
        this.N = new Names(r);
        this.xorKey = new byte[16];
        r.nextBytes(this.xorKey);
        for (int i = 0; i < this.xorKey.length; i++) {
            if (this.xorKey[i] == 0) this.xorKey[i] = (byte) (i + 1);
        }
    }

    static void main(String[] args) throws IOException {
        Path javaBase = args.length > 0
                ? Path.of(args[0])
                : Path.of("build", "generated-src", "main", "java");
        Path phpBase = args.length > 1
                ? Path.of(args[1])
                : Path.of("build", "generated-src", "php");
        Path goBase = args.length > 2
                ? Path.of(args[2])
                : Path.of("build", "generated-src", "go");
        long seed = args.length > 3
                ? Long.parseLong(args[3])
                : System.currentTimeMillis();

        Path inlinedClass = Path.of("build", "generated-classes",
                "com", "bytenya", "zcipher", "HydraStream.class");
        if (!Files.exists(inlinedClass)) {
            throw new IOException("inlined HydraStream.class missing — run inlineHydra first");
        }
        ClassNode cn = new ClassNode();
        new ClassReader(Files.readAllBytes(inlinedClass))
                .accept(cn, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        CompiledMethod init = compile(cn, "hydraInit");
        CompiledMethod crypt = compile(cn, "hydraCrypt");

        // ── Java target ──
        SourceGenerator gJava = new SourceGenerator(seed);
        String javaSource = gJava.emit(init, crypt);
        Path javaPkg = javaBase.resolve(OUT_PKG.replace('.', '/'));
        Files.createDirectories(javaPkg);
        try (var s = Files.list(javaPkg)) {
            s.forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                }
            });
        }
        String javaCls = gJava.N.get("CLS");
        String javaMth = gJava.N.get("MTH");
        Path javaFile = javaPkg.resolve(javaCls + ".java");
        Files.writeString(javaFile, javaSource, StandardCharsets.UTF_8);
        Files.writeString(javaPkg.resolve("manifest.txt"),
                OUT_PKG + "." + javaCls + "\n" + javaMth + "\n");
        System.out.println("[java] seed=" + seed
                + " class=" + OUT_PKG + "." + javaCls
                + " method=" + javaMth
                + " size=" + javaSource.length());

        // ── PHP target (different seed -> different obfuscation) ──
        SourceGenerator gPhp = new SourceGenerator(seed ^ 0x5BD1E9955BD1E995L);
        String phpSource = gPhp.emitPhp(init, crypt);
        Files.createDirectories(phpBase);
        try (var s = Files.list(phpBase)) {
            s.forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                }
            });
        }
        String phpCls = gPhp.N.get("CLS");
        String phpMth = gPhp.N.get("MTH");
        Path phpFile = phpBase.resolve(phpCls + ".php");
        Files.writeString(phpFile, phpSource, StandardCharsets.UTF_8);
        Files.writeString(phpBase.resolve("manifest.txt"),
                OUT_PHP_NS.replace("\\", "\\\\") + "\\\\" + phpCls + "\n" + phpMth + "\n");
        // Plain manifest with PHP-style separator for PHP-side consumption.
        Files.writeString(phpBase.resolve("manifest.php.txt"),
                OUT_PHP_NS + "\\" + phpCls + "\n" + phpMth + "\n");
        System.out.println("[php]  seed=" + (seed ^ 0x5BD1E9955BD1E995L)
                + " class=" + OUT_PHP_NS + "\\" + phpCls
                + " method=" + phpMth
                + " size=" + phpSource.length());

        // ── Go target ──
        SourceGenerator gGo = new SourceGenerator(seed ^ 0x9E3779B97F4A7C15L);
        String goSource = gGo.emitGo(init, crypt);
        Files.createDirectories(goBase);
        try (var s = Files.list(goBase)) {
            s.forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                }
            });
        }
        String goFn = gGo.N.get("FN");
        Path goFile = goBase.resolve("main.go");
        Files.writeString(goFile, goSource, StandardCharsets.UTF_8);
        Files.writeString(goBase.resolve("manifest.txt"), goFn + "\n");
        System.out.println("[go]   seed=" + (seed ^ 0x9E3779B97F4A7C15L)
                + " func=" + goFn
                + " size=" + goSource.length());
    }

    private static CompiledMethod compile(ClassNode cn, String name) {
        for (MethodNode m : cn.methods) {
            if (m.name.equals(name)) return new JvmToVmTranslator(cn, m).translate();
        }
        throw new IllegalStateException(name);
    }

    private static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static String hex(int v) {
        return "0x" + Integer.toHexString(v);
    }

    /* ── XOR mask ───────────────────────────────────────────────────── */
    private byte[] mask(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte) (data[i] ^ xorKey[i % xorKey.length]);
        return out;
    }

    /* ── source emission ────────────────────────────────────────────── */

    private String emit(CompiledMethod init, CompiledMethod crypt) {
        // Names for everything reachable in the generated source.
        String CLS = N.get("CLS");
        String MTH = N.get("MTH");
        String pMem = N.get("p_mem"), pOp = N.get("p_op"), pA = N.get("p_a"),
                pB = N.get("p_b"), pLen = N.get("p_len");
        String INIT_CODE = N.get("v_INIT_CODE");
        String CRYPT_CODE = N.get("v_CRYPT_CODE");
        String SBOX = N.get("v_SBOX");
        String PHI = N.get("v_PHI");
        String KEY = N.get("v_KEY");
        String KSZ = N.get("c_KEY_SIZE"), NSZ = N.get("c_NONCE_SIZE");
        String SB = N.get("c_SBOX_BASE"), PB = N.get("c_PHI_BASE"), STB = N.get("c_STATE_BASE"),
                SCB = N.get("c_SCRATCH_BASE");
        String IR = N.get("c_INIT_REGS"), ISC = N.get("c_INIT_SCRATCH"),
                CR = N.get("c_CRYPT_REGS"), CSC = N.get("c_CRYPT_SCRATCH");
        String code = N.get("v_code"), regs = N.get("v_regs"), pc = N.get("v_pc"),
                opc = N.get("v_opc"), outA = N.get("v_outA");
        String keyA = N.get("v_keyA"), nonA = N.get("v_nonA"), inA = N.get("v_inA"),
                need = N.get("v_need"), grow = N.get("v_grow"),
                ix = N.get("v_ix"), nm = N.get("v_nm"), js = N.get("v_js"), jp = N.get("v_jp");
        String dsp = N.get("l_dispatch");

        // Per-case scratch slot names (reused across all cases — each case is its own scope).
        String D = N.get("s_D"), A = N.get("s_A"), B = N.get("s_B"),
                T = N.get("s_T"), V = N.get("s_V"), W = N.get("s_W"),
                OF = N.get("s_OF"), AD = N.get("s_AD"), SH = N.get("s_SH");
        // Extra slots needed by the SBOX and 64-bit ops.
        String B0 = N.get("s_B0"), B1 = N.get("s_B1"), B2 = N.get("s_B2"), B3 = N.get("s_B3"),
                S0 = N.get("s_S0"), S1 = N.get("s_S1"), S2 = N.get("s_S2"), S3 = N.get("s_S3"),
                WD = N.get("s_WD"), SL = N.get("s_SL"), RZ = N.get("s_RZ");

        StringBuilder o = new StringBuilder(64 * 1024);
        o.append("package ").append(OUT_PKG).append(";");
        o.append("import java.util.Base64;");
        o.append("public final class ").append(CLS).append("{");
        o.append("private ").append(CLS).append("(){}");
        o.append("public static byte[] ").append(MTH).append("(byte[] ").append(pMem)
                .append(",int ").append(pOp).append(",byte[] ").append(pA)
                .append(",byte[] ").append(pB).append(",int ").append(pLen).append("){");

        // Embedded data.
        o.append("byte[] ").append(KEY).append("=Base64.getDecoder().decode(\"")
                .append(b64(xorKey)).append("\");");
        o.append("byte[] ").append(INIT_CODE).append("=Base64.getDecoder().decode(\"")
                .append(b64(mask(init.bytecode()))).append("\");");
        o.append("byte[] ").append(CRYPT_CODE).append("=Base64.getDecoder().decode(\"")
                .append(b64(mask(crypt.bytecode()))).append("\");");
        int[] sboxInts = MemoryLayout.hydraSbox();
        byte[] sboxBytes = new byte[sboxInts.length];
        for (int i = 0; i < sboxInts.length; i++) sboxBytes[i] = (byte) sboxInts[i];
        o.append("byte[] ").append(SBOX).append("=Base64.getDecoder().decode(\"")
                .append(b64(mask(sboxBytes))).append("\");");
        int[] phiInts = MemoryLayout.hydraPhi();
        byte[] phiBytes = new byte[phiInts.length * 4];
        for (int i = 0; i < phiInts.length; i++) {
            int v = phiInts[i];
            phiBytes[i * 4] = (byte) v;
            phiBytes[i * 4 + 1] = (byte) (v >>> 8);
            phiBytes[i * 4 + 2] = (byte) (v >>> 16);
            phiBytes[i * 4 + 3] = (byte) (v >>> 24);
        }
        o.append("byte[] ").append(PHI).append("=Base64.getDecoder().decode(\"")
                .append(b64(mask(phiBytes))).append("\");");

        // Unmask all four arrays.
        for (String arr : new String[]{INIT_CODE, CRYPT_CODE, SBOX, PHI}) {
            o.append("for(int ").append(ix).append("=0;").append(ix).append("<").append(arr)
                    .append(".length;").append(ix).append("++)").append(arr).append("[")
                    .append(ix).append("]^=").append(KEY).append("[").append(ix).append("%")
                    .append(KEY).append(".length];");
        }

        // Layout constants.
        o.append("int ").append(STB).append("=").append(MemoryLayout.STATE_BASE).append(";");
        o.append("int ").append(SB).append("=").append(MemoryLayout.SBOX_BASE).append(";");
        o.append("int ").append(PB).append("=").append(MemoryLayout.PHI_BASE).append(";");
        o.append("int ").append(SCB).append("=").append(MemoryLayout.SCRATCH_BASE).append(";");
        o.append("int ").append(IR).append("=").append(init.regCount()).append(";");
        o.append("int ").append(ISC).append("=").append(init.scratchSize()).append(";");
        o.append("int ").append(CR).append("=").append(crypt.regCount()).append(";");
        o.append("int ").append(CSC).append("=").append(crypt.scratchSize()).append(";");
        o.append("int ").append(KSZ).append("=").append(HydraStream.HYDRA_KEY_SIZE).append(";");
        o.append("int ").append(NSZ).append("=").append(HydraStream.HYDRA_NONCE_SIZE).append(";");

        // Allocate / preload mem on first call.
        o.append("if(").append(pMem).append("==null){");
        o.append("int ").append(nm).append("=").append(SCB).append("+Math.max(").append(ISC)
                .append(",").append(CSC).append(")+").append(KSZ).append("+").append(NSZ).append("+8;");
        o.append(pMem).append("=new byte[").append(nm).append("];");
        o.append("for(int ").append(js).append("=0;").append(js).append("<").append(SBOX)
                .append(".length;").append(js).append("++)").append(pMem).append("[").append(SB)
                .append("+").append(js).append("*4]=").append(SBOX).append("[").append(js).append("];");
        o.append("System.arraycopy(").append(PHI).append(",0,").append(pMem).append(",")
                .append(PB).append(",").append(PHI).append(".length);");
        o.append("}");

        // Route by op.
        o.append("byte[] ").append(code).append(";long[] ").append(regs).append(";");
        o.append("int ").append(outA).append("=-1;");
        o.append("if(").append(pOp).append("==0){");
        o.append("int ").append(keyA).append("=").append(SCB).append("+").append(ISC).append(";");
        o.append("int ").append(nonA).append("=").append(keyA).append("+").append(KSZ).append(";");
        o.append("int ").append(need).append("=").append(nonA).append("+").append(NSZ).append("+8;");
        o.append("if(").append(pMem).append(".length<").append(need).append("){");
        o.append("byte[] ").append(grow).append("=new byte[Math.max(").append(need).append(",")
                .append(pMem).append(".length*2)];");
        o.append("System.arraycopy(").append(pMem).append(",0,").append(grow).append(",0,")
                .append(pMem).append(".length);");
        o.append(pMem).append("=").append(grow).append(";}");
        o.append("System.arraycopy(").append(pA).append(",0,").append(pMem).append(",")
                .append(keyA).append(",").append(KSZ).append(");");
        o.append("System.arraycopy(").append(pB).append(",0,").append(pMem).append(",")
                .append(nonA).append(",").append(NSZ).append(");");
        o.append(regs).append("=new long[").append(IR).append("];");
        o.append(regs).append("[0]=").append(STB).append(";").append(regs).append("[1]=")
                .append(keyA).append(";").append(regs).append("[2]=").append(nonA).append(";");
        o.append(code).append("=").append(INIT_CODE).append(";}else{");
        o.append("int ").append(inA).append("=").append(SCB).append("+").append(CSC).append(";");
        o.append(outA).append("=").append(inA).append("+").append(pLen).append(";");
        o.append("int ").append(need).append("=").append(outA).append("+").append(pLen).append("+8;");
        o.append("if(").append(pMem).append(".length<").append(need).append("){");
        o.append("byte[] ").append(grow).append("=new byte[Math.max(").append(need).append(",")
                .append(pMem).append(".length*2)];");
        o.append("System.arraycopy(").append(pMem).append(",0,").append(grow).append(",0,")
                .append(pMem).append(".length);");
        o.append(pMem).append("=").append(grow).append(";}");
        o.append("if(").append(pLen).append(">0)System.arraycopy(").append(pA).append(",0,")
                .append(pMem).append(",").append(inA).append(",").append(pLen).append(");");
        o.append(regs).append("=new long[").append(CR).append("];");
        o.append(regs).append("[0]=").append(STB).append(";").append(regs).append("[1]=")
                .append(inA).append(";").append(regs).append("[2]=").append(outA).append(";")
                .append(regs).append("[3]=").append(pLen).append(";");
        o.append(code).append("=").append(CRYPT_CODE).append(";}");

        // Dispatch loop.
        String C = code, R = regs, M = pMem, P = pc;
        o.append("int ").append(P).append("=0;");
        o.append(dsp).append(":for(;;){");
        o.append("int ").append(opc).append("=").append(C).append("[").append(P).append("]&0xFF;");
        o.append("switch(").append(opc).append("){");

        // Helpers to spell out inline little-endian reads from `code`.
        // Offsets are integer literals (the +N inside [pc+N]).
        // u16(off) = ((c[p+off]&0xFF)|((c[p+off+1]&0xFF)<<8))
        java.util.function.IntFunction<String> u16 = (off) ->
                "((" + C + "[" + P + "+" + off + "]&0xFF)|((" + C + "[" + P + "+" + (off + 1) + "]&0xFF)<<8))";
        java.util.function.IntFunction<String> i16 = (off) ->
                "((short)" + u16.apply(off) + ")";
        java.util.function.IntFunction<String> i32 = (off) ->
                "((" + C + "[" + P + "+" + off + "]&0xFF)|((" + C + "[" + P + "+" + (off + 1) + "]&0xFF)<<8)"
                        + "|((" + C + "[" + P + "+" + (off + 2) + "]&0xFF)<<16)|((" + C + "[" + P + "+" + (off + 3) + "]&0xFF)<<24))";

        // Per-case body emitters. Each case opens its own block so var names can
        // safely shadow across cases.
        // 32-bit ALU template: regs[D] = (regs[A] OP regs[B]) & 0xFFFFFFFFL
        java.util.function.BiConsumer<Integer, String> alu32 = (op, expr) -> {
            o.append("case ").append(hex(op)).append(":{int ")
                    .append(D).append("=").append(u16.apply(1)).append(",")
                    .append(A).append("=").append(u16.apply(3)).append(",")
                    .append(B).append("=").append(u16.apply(5)).append(";")
                    .append(R).append("[").append(D).append("]=(").append(expr.replace("$a", R + "[" + A + "]").replace("$b", R + "[" + B + "]"))
                    .append(")&0xFFFFFFFFL;").append(P).append("+=7;break;}");
        };
        java.util.function.BiConsumer<Integer, String> alu64 = (op, expr) -> {
            o.append("case ").append(hex(op)).append(":{int ")
                    .append(D).append("=").append(u16.apply(1)).append(",")
                    .append(A).append("=").append(u16.apply(3)).append(",")
                    .append(B).append("=").append(u16.apply(5)).append(";")
                    .append(R).append("[").append(D).append("]=").append(expr.replace("$a", R + "[" + A + "]").replace("$b", R + "[" + B + "]"))
                    .append(";").append(P).append("+=7;break;}");
        };

        // 0x01 MOV
        o.append("case ").append(hex(0x01)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(";")
                .append(R).append("[").append(D).append("]=").append(R).append("[").append(A).append("];")
                .append(P).append("+=5;break;}");
        // 0x02 LDI
        o.append("case ").append(hex(0x02)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(T).append("=").append(i32.apply(3)).append(";")
                .append(R).append("[").append(D).append("]=(long)").append(T).append(";")
                .append(P).append("+=7;break;}");
        // 0x03 LDIQ
        o.append("case ").append(hex(0x03)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(";long ")
                .append(V).append("=0;for(int ").append(W).append("=0;").append(W).append("<8;")
                .append(W).append("++)").append(V).append("|=((long)").append(C).append("[")
                .append(P).append("+3+").append(W).append("]&0xFFL)<<(").append(W).append("*8);")
                .append(R).append("[").append(D).append("]=").append(V).append(";")
                .append(P).append("+=11;break;}");

        alu32.accept(0x10, "$a + $b");
        alu32.accept(0x11, "$a - $b");
        // MUL32 and REM32 want signed int math then mask
        o.append("case ").append(hex(0x12)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(",")
                .append(B).append("=").append(u16.apply(5)).append(";int ")
                .append(V).append("=((int)").append(R).append("[").append(A).append("])*((int)")
                .append(R).append("[").append(B).append("]);").append(R).append("[").append(D)
                .append("]=((long)").append(V).append(")&0xFFFFFFFFL;").append(P).append("+=7;break;}");
        o.append("case ").append(hex(0x13)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(",")
                .append(B).append("=").append(u16.apply(5)).append(";int ")
                .append(V).append("=((int)").append(R).append("[").append(A).append("])%((int)")
                .append(R).append("[").append(B).append("]);").append(R).append("[").append(D)
                .append("]=((long)").append(V).append(")&0xFFFFFFFFL;").append(P).append("+=7;break;}");
        alu32.accept(0x14, "$a & $b");
        alu32.accept(0x15, "$a | $b");
        alu32.accept(0x16, "$a ^ $b");
        // SHL32 / SHR32 / ROL32 / ROR32
        for (int op : new int[]{0x17, 0x18, 0x19, 0x1A}) {
            o.append("case ").append(hex(op)).append(":{int ")
                    .append(D).append("=").append(u16.apply(1)).append(",")
                    .append(A).append("=").append(u16.apply(3)).append(",")
                    .append(B).append("=").append(u16.apply(5)).append(";int ")
                    .append(SH).append("=(int)(").append(R).append("[").append(B).append("]&0x1F);long ")
                    .append(V).append("=").append(R).append("[").append(A).append("]&0xFFFFFFFFL;");
            switch (op) {
                case 0x17 ->
                        o.append(R).append("[").append(D).append("]=(").append(V).append("<<").append(SH).append(")&0xFFFFFFFFL;");
                case 0x18 ->
                        o.append(R).append("[").append(D).append("]=").append(V).append(">>>").append(SH).append(";");
                case 0x19 ->
                        o.append(R).append("[").append(D).append("]=").append(SH).append("==0?").append(V).append(":((")
                                .append(V).append("<<").append(SH).append(")|(").append(V).append(">>>(32-").append(SH).append(")))&0xFFFFFFFFL;");
                case 0x1A ->
                        o.append(R).append("[").append(D).append("]=").append(SH).append("==0?").append(V).append(":((")
                                .append(V).append(">>>").append(SH).append(")|(").append(V).append("<<(32-").append(SH).append(")))&0xFFFFFFFFL;");
            }
            o.append(P).append("+=7;break;}");
        }
        alu64.accept(0x20, "$a + $b");
        alu64.accept(0x21, "$a * $b");
        // SHR64
        o.append("case ").append(hex(0x22)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(",")
                .append(B).append("=").append(u16.apply(5)).append(";int ")
                .append(SH).append("=(int)(").append(R).append("[").append(B).append("]&0x3F);")
                .append(R).append("[").append(D).append("]=").append(R).append("[").append(A).append("]>>>")
                .append(SH).append(";").append(P).append("+=7;break;}");
        alu64.accept(0x23, "$a ^ $b");
        // SEXT8, SEXT32
        o.append("case ").append(hex(0x30)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(";")
                .append(R).append("[").append(D).append("]=(long)(byte)").append(R).append("[").append(A).append("];")
                .append(P).append("+=5;break;}");
        o.append("case ").append(hex(0x31)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(";")
                .append(R).append("[").append(D).append("]=(long)(int)").append(R).append("[").append(A).append("];")
                .append(P).append("+=5;break;}");
        // LDB / LDBS / STB
        o.append("case ").append(hex(0x40)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(",")
                .append(OF).append("=").append(i16.apply(5)).append(";int ")
                .append(AD).append("=(int)").append(R).append("[").append(A).append("]+").append(OF).append(";")
                .append(R).append("[").append(D).append("]=").append(M).append("[").append(AD).append("]&0xFFL;")
                .append(P).append("+=7;break;}");
        o.append("case ").append(hex(0x41)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(",")
                .append(OF).append("=").append(i16.apply(5)).append(";int ")
                .append(AD).append("=(int)").append(R).append("[").append(A).append("]+").append(OF).append(";")
                .append(R).append("[").append(D).append("]=(long)(byte)").append(M).append("[").append(AD).append("];")
                .append(P).append("+=7;break;}");
        o.append("case ").append(hex(0x42)).append(":{int ")
                .append(A).append("=").append(u16.apply(1)).append(",")
                .append(OF).append("=").append(i16.apply(3)).append(",")
                .append(B).append("=").append(u16.apply(5)).append(";int ")
                .append(AD).append("=(int)").append(R).append("[").append(A).append("]+").append(OF).append(";")
                .append(M).append("[").append(AD).append("]=(byte)").append(R).append("[").append(B).append("];")
                .append(P).append("+=7;break;}");
        // LDW / STW
        o.append("case ").append(hex(0x43)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(",")
                .append(OF).append("=").append(i16.apply(5)).append(";int ")
                .append(AD).append("=(int)").append(R).append("[").append(A).append("]+").append(OF).append(";int ")
                .append(V).append("=(").append(M).append("[").append(AD).append("]&0xFF)|((")
                .append(M).append("[").append(AD).append("+1]&0xFF)<<8)|((")
                .append(M).append("[").append(AD).append("+2]&0xFF)<<16)|((")
                .append(M).append("[").append(AD).append("+3]&0xFF)<<24);")
                .append(R).append("[").append(D).append("]=((long)").append(V).append(")&0xFFFFFFFFL;")
                .append(P).append("+=7;break;}");
        o.append("case ").append(hex(0x44)).append(":{int ")
                .append(A).append("=").append(u16.apply(1)).append(",")
                .append(OF).append("=").append(i16.apply(3)).append(",")
                .append(B).append("=").append(u16.apply(5)).append(";int ")
                .append(AD).append("=(int)").append(R).append("[").append(A).append("]+").append(OF).append(";int ")
                .append(V).append("=(int)").append(R).append("[").append(B).append("];")
                .append(M).append("[").append(AD).append("]=(byte)").append(V).append(";")
                .append(M).append("[").append(AD).append("+1]=(byte)(").append(V).append(">>>8);")
                .append(M).append("[").append(AD).append("+2]=(byte)(").append(V).append(">>>16);")
                .append(M).append("[").append(AD).append("+3]=(byte)(").append(V).append(">>>24);")
                .append(P).append("+=7;break;}");
        // LDQ / STQ
        o.append("case ").append(hex(0x45)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(",")
                .append(OF).append("=").append(i16.apply(5)).append(";int ")
                .append(AD).append("=(int)").append(R).append("[").append(A).append("]+").append(OF).append(";long ")
                .append(V).append("=0;for(int ").append(W).append("=0;").append(W).append("<8;")
                .append(W).append("++)").append(V).append("|=((long)").append(M).append("[")
                .append(AD).append("+").append(W).append("]&0xFFL)<<(").append(W).append("*8);")
                .append(R).append("[").append(D).append("]=").append(V).append(";")
                .append(P).append("+=7;break;}");
        o.append("case ").append(hex(0x46)).append(":{int ")
                .append(A).append("=").append(u16.apply(1)).append(",")
                .append(OF).append("=").append(i16.apply(3)).append(",")
                .append(B).append("=").append(u16.apply(5)).append(";int ")
                .append(AD).append("=(int)").append(R).append("[").append(A).append("]+").append(OF).append(";long ")
                .append(V).append("=").append(R).append("[").append(B).append("];")
                .append("for(int ").append(W).append("=0;").append(W).append("<8;").append(W).append("++)")
                .append(M).append("[").append(AD).append("+").append(W).append("]=(byte)(")
                .append(V).append(">>>(").append(W).append("*8));")
                .append(P).append("+=7;break;}");
        // SBOX (specialized)
        o.append("case ").append(hex(0x50)).append(":{int ")
                .append(D).append("=").append(u16.apply(1)).append(",")
                .append(A).append("=").append(u16.apply(3)).append(",")
                .append(B).append("=").append(u16.apply(5)).append(";long ")
                .append(WD).append("=").append(R).append("[").append(A).append("],")
                .append(SL).append("=").append(R).append("[").append(B).append("];");
        // unpack bytes / selector nibbles
        o.append("int ").append(B0).append("=(int)(").append(WD).append("&0xFF),")
                .append(B1).append("=(int)((").append(WD).append(">>>8)&0xFF),")
                .append(B2).append("=(int)((").append(WD).append(">>>16)&0xFF),")
                .append(B3).append("=(int)((").append(WD).append(">>>24)&0xFF),")
                .append(S0).append("=(int)(").append(SL).append("&0x03),")
                .append(S1).append("=(int)((").append(SL).append(">>>2)&0x03),")
                .append(S2).append("=(int)((").append(SL).append(">>>4)&0x03),")
                .append(S3).append("=(int)((").append(SL).append(">>>6)&0x03);");
        // sbox lookup expression: M[SB + idx*4] & 0xFF
        // s0==s2 branch
        o.append("if(").append(S0).append("==").append(S2).append("){")
                .append(B0).append("=").append(M).append("[").append(SB).append("+((")
                .append(S0).append("<<8)|(").append(M).append("[").append(SB).append("+((")
                .append(S1).append("<<8)|").append(B0).append(")*4]&0xFF))*4]&0xFF;")
                .append(B2).append("=").append(M).append("[").append(SB).append("+((")
                .append(S2).append("<<8)|(").append(M).append("[").append(SB).append("+((")
                .append(S3).append("<<8)|").append(B2).append(")*4]&0xFF))*4]&0xFF;")
                .append("}else{")
                .append(B0).append("=").append(M).append("[").append(SB).append("+((")
                .append(S0).append("<<8)|").append(B0).append(")*4]&0xFF;")
                .append(B2).append("=").append(M).append("[").append(SB).append("+((")
                .append(S2).append("<<8)|").append(B2).append(")*4]&0xFF;")
                .append("}");
        // s1==s3 branch
        o.append("if(").append(S1).append("==").append(S3).append("){")
                .append(B1).append("=").append(M).append("[").append(SB).append("+((")
                .append(S3).append("<<8)|(").append(M).append("[").append(SB).append("+((")
                .append(S0).append("<<8)|").append(B1).append(")*4]&0xFF))*4]&0xFF;")
                .append(B3).append("=").append(M).append("[").append(SB).append("+((")
                .append(S1).append("<<8)|(").append(M).append("[").append(SB).append("+((")
                .append(S2).append("<<8)|").append(B3).append(")*4]&0xFF))*4]&0xFF;")
                .append("}else{")
                .append(B1).append("=").append(M).append("[").append(SB).append("+((")
                .append(S1).append("<<8)|").append(B1).append(")*4]&0xFF;")
                .append(B3).append("=").append(M).append("[").append(SB).append("+((")
                .append(S3).append("<<8)|").append(B3).append(")*4]&0xFF;")
                .append("}");
        o.append("int ").append(RZ).append("=(").append(B3).append("<<24)|(")
                .append(B2).append("<<16)|(").append(B1).append("<<8)|").append(B0).append(";")
                .append(R).append("[").append(D).append("]=((long)").append(RZ).append(")&0xFFFFFFFFL;")
                .append(P).append("+=7;break;}");

        // 0x60 JMP
        o.append("case ").append(hex(0x60)).append(":{").append(P).append("=").append(i32.apply(1))
                .append(";break;}");
        // JZ32 / JNZ32 (1-reg compare against 0)
        o.append("case ").append(hex(0x61)).append(":{int ")
                .append(A).append("=").append(u16.apply(1)).append(",")
                .append(T).append("=").append(i32.apply(3)).append(";if((int)")
                .append(R).append("[").append(A).append("]==0)").append(P).append("=").append(T)
                .append(";else ").append(P).append("+=7;break;}");
        o.append("case ").append(hex(0x62)).append(":{int ")
                .append(A).append("=").append(u16.apply(1)).append(",")
                .append(T).append("=").append(i32.apply(3)).append(";if((int)")
                .append(R).append("[").append(A).append("]!=0)").append(P).append("=").append(T)
                .append(";else ").append(P).append("+=7;break;}");
        // 2-reg signed/unsigned compares
        String[] ops2 = {"==", "!=", "<", ">=", ">", "<="};
        int[] codes2 = {0x63, 0x64, 0x65, 0x66, 0x67, 0x68};
        for (int i = 0; i < codes2.length; i++) {
            o.append("case ").append(hex(codes2[i])).append(":{int ")
                    .append(A).append("=").append(u16.apply(1)).append(",")
                    .append(B).append("=").append(u16.apply(3)).append(",")
                    .append(T).append("=").append(i32.apply(5)).append(";if((int)")
                    .append(R).append("[").append(A).append("]").append(ops2[i]).append("(int)")
                    .append(R).append("[").append(B).append("])").append(P).append("=").append(T)
                    .append(";else ").append(P).append("+=9;break;}");
        }
        // unsigned: <0, >=0, >0, <=0 of compareUnsigned
        String[] uOps = {"<", ">=", ">", "<="};
        int[] uCodes = {0x69, 0x6A, 0x6B, 0x6C};
        for (int i = 0; i < uCodes.length; i++) {
            o.append("case ").append(hex(uCodes[i])).append(":{int ")
                    .append(A).append("=").append(u16.apply(1)).append(",")
                    .append(B).append("=").append(u16.apply(3)).append(",")
                    .append(T).append("=").append(i32.apply(5)).append(";if(Integer.compareUnsigned((int)")
                    .append(R).append("[").append(A).append("],(int)")
                    .append(R).append("[").append(B).append("])").append(uOps[i]).append("0)")
                    .append(P).append("=").append(T).append(";else ").append(P).append("+=9;break;}");
        }

        // RET
        o.append("case ").append(hex(0x70)).append(":break ").append(dsp).append(";");
        o.append("default:throw new IllegalStateException(\"\");");
        o.append("}}");

        // Copy out + return.
        o.append("if(").append(pOp).append("==1&&").append(pLen).append(">0)System.arraycopy(")
                .append(pMem).append(",").append(outA).append(",").append(pB).append(",0,")
                .append(pLen).append(");");
        o.append("return ").append(pMem).append(";}}");

        // suppress unused-warning markers for jp/v_jp (kept for future expansion)
        if (jp.length() < 0) {
            o.append(jp);
        }
        return o.toString();
    }

    /* ── PHP emission: same shape as emit() but PHP syntax ── */
    private String emitPhp(CompiledMethod init, CompiledMethod crypt) {
        String CLS = N.get("CLS");
        String MTH = N.get("MTH");
        String pMem = N.get("p_mem"), pOp = N.get("p_op"), pA = N.get("p_a"),
                pB = N.get("p_b"), pLen = N.get("p_len");
        String INIT_CODE = N.get("v_INIT_CODE");
        String CRYPT_CODE = N.get("v_CRYPT_CODE");
        String SBOX = N.get("v_SBOX");
        String PHI = N.get("v_PHI");
        String KEY = N.get("v_KEY");
        String KSZ = N.get("c_KEY_SIZE"), NSZ = N.get("c_NONCE_SIZE");
        String SB = N.get("c_SBOX_BASE"), PB = N.get("c_PHI_BASE"), STB = N.get("c_STATE_BASE"),
                SCB = N.get("c_SCRATCH_BASE");
        String IR = N.get("c_INIT_REGS"), ISC = N.get("c_INIT_SCRATCH"),
                CR = N.get("c_CRYPT_REGS"), CSC = N.get("c_CRYPT_SCRATCH");
        String code = N.get("v_code"), regs = N.get("v_regs"), pc = N.get("v_pc"),
                opc = N.get("v_opc"), outA = N.get("v_outA");
        String keyA = N.get("v_keyA"), nonA = N.get("v_nonA"), inA = N.get("v_inA"),
                need = N.get("v_need"), ix = N.get("v_ix"), nm = N.get("v_nm"), js = N.get("v_js");
        String D = N.get("s_D"), A = N.get("s_A"), B = N.get("s_B"),
                T = N.get("s_T"), V = N.get("s_V"), W = N.get("s_W"),
                OF = N.get("s_OF"), AD = N.get("s_AD"), SH = N.get("s_SH");
        String B0 = N.get("s_B0"), B1 = N.get("s_B1"), B2 = N.get("s_B2"), B3 = N.get("s_B3"),
                S0 = N.get("s_S0"), S1 = N.get("s_S1"), S2 = N.get("s_S2"), S3 = N.get("s_S3"),
                WD = N.get("s_WD"), SL = N.get("s_SL"), RZ = N.get("s_RZ");

        // Pack constant data the same way Java does.
        int[] sboxInts = MemoryLayout.hydraSbox();
        byte[] sboxBytes = new byte[sboxInts.length];
        for (int i = 0; i < sboxInts.length; i++) sboxBytes[i] = (byte) sboxInts[i];
        int[] phiInts = MemoryLayout.hydraPhi();
        byte[] phiBytes = new byte[phiInts.length * 4];
        for (int i = 0; i < phiInts.length; i++) {
            int v = phiInts[i];
            phiBytes[i * 4] = (byte) v;
            phiBytes[i * 4 + 1] = (byte) (v >>> 8);
            phiBytes[i * 4 + 2] = (byte) (v >>> 16);
            phiBytes[i * 4 + 3] = (byte) (v >>> 24);
        }

        StringBuilder o = new StringBuilder(64 * 1024);
        o.append("<?php\n");
        o.append("namespace ").append(OUT_PHP_NS).append(";\n");
        o.append("final class ").append(CLS).append("{");
        o.append("private function __construct(){}");
        o.append("public static function ").append(MTH).append("(?string &$").append(pMem)
                .append(",int $").append(pOp).append(",string $").append(pA)
                .append(",string $").append(pB).append(",int $").append(pLen).append("):string{");

        // Embed XOR-masked data.
        o.append("$").append(KEY).append("=base64_decode(\"").append(b64(xorKey)).append("\");");
        o.append("$").append(INIT_CODE).append("=base64_decode(\"").append(b64(mask(init.bytecode()))).append("\");");
        o.append("$").append(CRYPT_CODE).append("=base64_decode(\"").append(b64(mask(crypt.bytecode()))).append("\");");
        o.append("$").append(SBOX).append("=base64_decode(\"").append(b64(mask(sboxBytes))).append("\");");
        o.append("$").append(PHI).append("=base64_decode(\"").append(b64(mask(phiBytes))).append("\");");

        // Unmask all four strings.
        for (String var : new String[]{INIT_CODE, CRYPT_CODE, SBOX, PHI}) {
            o.append("for($").append(ix).append("=0;$").append(ix).append("<strlen($")
                    .append(var).append(");$").append(ix).append("++)$").append(var).append("[$")
                    .append(ix).append("]=chr(ord($").append(var).append("[$").append(ix)
                    .append("])^ord($").append(KEY).append("[$").append(ix).append("%16]));");
        }

        // Layout constants.
        o.append("$").append(STB).append("=").append(MemoryLayout.STATE_BASE).append(";");
        o.append("$").append(SB).append("=").append(MemoryLayout.SBOX_BASE).append(";");
        o.append("$").append(PB).append("=").append(MemoryLayout.PHI_BASE).append(";");
        o.append("$").append(SCB).append("=").append(MemoryLayout.SCRATCH_BASE).append(";");
        o.append("$").append(IR).append("=").append(init.regCount()).append(";");
        o.append("$").append(ISC).append("=").append(init.scratchSize()).append(";");
        o.append("$").append(CR).append("=").append(crypt.regCount()).append(";");
        o.append("$").append(CSC).append("=").append(crypt.scratchSize()).append(";");
        o.append("$").append(KSZ).append("=").append(HydraStream.HYDRA_KEY_SIZE).append(";");
        o.append("$").append(NSZ).append("=").append(HydraStream.HYDRA_NONCE_SIZE).append(";");

        // Allocate / preload mem on first call.
        o.append("if($").append(pMem).append("===null){");
        o.append("$").append(nm).append("=$").append(SCB).append("+max($").append(ISC)
                .append(",$").append(CSC).append(")+$").append(KSZ).append("+$").append(NSZ).append("+8;");
        o.append("$").append(pMem).append("=str_repeat(\"\\0\",$").append(nm).append(");");
        o.append("for($").append(js).append("=0;$").append(js).append("<strlen($").append(SBOX)
                .append(");$").append(js).append("++)$").append(pMem).append("[$").append(SB)
                .append("+$").append(js).append("*4]=$").append(SBOX).append("[$").append(js).append("];");
        o.append("$").append(pMem).append("=substr_replace($").append(pMem).append(",$")
                .append(PHI).append(",$").append(PB).append(",strlen($").append(PHI).append("));");
        o.append("}");

        // Route by op.
        o.append("$").append(code).append("=\"\";$").append(regs).append("=[];$").append(outA).append("=-1;");
        o.append("if($").append(pOp).append("===0){");
        o.append("$").append(keyA).append("=$").append(SCB).append("+$").append(ISC).append(";");
        o.append("$").append(nonA).append("=$").append(keyA).append("+$").append(KSZ).append(";");
        o.append("$").append(need).append("=$").append(nonA).append("+$").append(NSZ).append("+8;");
        o.append("if(strlen($").append(pMem).append(")<$").append(need).append(")$")
                .append(pMem).append("=str_pad($").append(pMem).append(",max($").append(need)
                .append(",strlen($").append(pMem).append(")*2),\"\\0\");");
        o.append("$").append(pMem).append("=substr_replace($").append(pMem).append(",substr($")
                .append(pA).append(",0,$").append(KSZ).append("),$").append(keyA).append(",$")
                .append(KSZ).append(");");
        o.append("$").append(pMem).append("=substr_replace($").append(pMem).append(",substr($")
                .append(pB).append(",0,$").append(NSZ).append("),$").append(nonA).append(",$")
                .append(NSZ).append(");");
        o.append("$").append(regs).append("=array_fill(0,$").append(IR).append(",0);");
        o.append("$").append(regs).append("[0]=$").append(STB).append(";$").append(regs)
                .append("[1]=$").append(keyA).append(";$").append(regs).append("[2]=$").append(nonA).append(";");
        o.append("$").append(code).append("=$").append(INIT_CODE).append(";");
        o.append("}else{");
        o.append("$").append(inA).append("=$").append(SCB).append("+$").append(CSC).append(";");
        o.append("$").append(outA).append("=$").append(inA).append("+$").append(pLen).append(";");
        o.append("$").append(need).append("=$").append(outA).append("+$").append(pLen).append("+8;");
        o.append("if(strlen($").append(pMem).append(")<$").append(need).append(")$")
                .append(pMem).append("=str_pad($").append(pMem).append(",max($").append(need)
                .append(",strlen($").append(pMem).append(")*2),\"\\0\");");
        o.append("if($").append(pLen).append(">0)$").append(pMem).append("=substr_replace($")
                .append(pMem).append(",substr($").append(pA).append(",0,$").append(pLen).append("),$")
                .append(inA).append(",$").append(pLen).append(");");
        o.append("$").append(regs).append("=array_fill(0,$").append(CR).append(",0);");
        o.append("$").append(regs).append("[0]=$").append(STB).append(";$").append(regs)
                .append("[1]=$").append(inA).append(";$").append(regs).append("[2]=$").append(outA)
                .append(";$").append(regs).append("[3]=$").append(pLen).append(";");
        o.append("$").append(code).append("=$").append(CRYPT_CODE).append(";");
        o.append("}");

        // Dispatch loop.
        String C = code, R = regs, M = pMem, P = pc;
        o.append("$").append(P).append("=0;");
        o.append("while(true){");
        o.append("$").append(opc).append("=ord($").append(C).append("[$").append(P).append("]);");
        o.append("switch($").append(opc).append("){");

        java.util.function.IntFunction<String> u16 = (off) ->
                "(ord($" + C + "[$" + P + "+" + off + "])|(ord($" + C + "[$" + P + "+" + (off + 1) + "])<<8))";
        java.util.function.IntFunction<String> i16 = (off) ->
                "((" + u16.apply(off) + "<<48)>>48)";
        java.util.function.IntFunction<String> u32 = (off) ->
                "(ord($" + C + "[$" + P + "+" + off + "])|(ord($" + C + "[$" + P + "+" + (off + 1) + "])<<8)|(ord($" + C + "[$" + P + "+" + (off + 2) + "])<<16)|(ord($" + C + "[$" + P + "+" + (off + 3) + "])<<24))";

        // 0x01 MOV
        o.append("case 0x1:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(R).append("[$")
                .append(D).append("]=$").append(R).append("[$").append(A).append("];$").append(P).append("+=5;break;}");
        // 0x02 LDI (sign-extend low 32 to 64)
        o.append("case 0x2:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(T).append("=(").append(u32.apply(3)).append("<<32)>>32;$").append(R)
                .append("[$").append(D).append("]=$").append(T).append(";$").append(P).append("+=7;break;}");
        // 0x03 LDIQ
        o.append("case 0x3:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(V).append("=0;for($").append(W).append("=0;$").append(W).append("<8;$")
                .append(W).append("++)$").append(V).append("|=ord($").append(C).append("[$")
                .append(P).append("+3+$").append(W).append("])<<($").append(W).append("*8);$")
                .append(R).append("[$").append(D).append("]=$").append(V).append(";$")
                .append(P).append("+=11;break;}");

        // 32-bit ALU simple ops
        String[] alu32op = {"+", "-", "&", "|", "^"};
        int[] alu32code = {0x10, 0x11, 0x14, 0x15, 0x16};
        for (int i = 0; i < alu32code.length; i++) {
            o.append("case ").append(hex(alu32code[i])).append(":{$").append(D).append("=")
                    .append(u16.apply(1)).append(";$").append(A).append("=").append(u16.apply(3))
                    .append(";$").append(B).append("=").append(u16.apply(5)).append(";$").append(R)
                    .append("[$").append(D).append("]=($").append(R).append("[$").append(A).append("]")
                    .append(alu32op[i]).append("$").append(R).append("[$").append(B)
                    .append("])&0xFFFFFFFF;$").append(P).append("+=7;break;}");
        }

        // 0x12 MUL32: signed 32x32 -> low 32. PHP int is 64-bit signed, so sign-extend low 32 then *.
        o.append("case 0x12:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(V).append("=(($").append(R).append("[$")
                .append(A).append("]<<32)>>32)*(($").append(R).append("[$").append(B).append("]<<32)>>32);$")
                .append(R).append("[$").append(D).append("]=$").append(V).append("&0xFFFFFFFF;$")
                .append(P).append("+=7;break;}");
        // 0x13 REM32
        o.append("case 0x13:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(V).append("=(($").append(R).append("[$")
                .append(A).append("]<<32)>>32)%(($").append(R).append("[$").append(B).append("]<<32)>>32);$")
                .append(R).append("[$").append(D).append("]=$").append(V).append("&0xFFFFFFFF;$")
                .append(P).append("+=7;break;}");

        // SHL32 / SHR32 / ROL32 / ROR32
        for (int op : new int[]{0x17, 0x18, 0x19, 0x1A}) {
            o.append("case ").append(hex(op)).append(":{$").append(D).append("=")
                    .append(u16.apply(1)).append(";$").append(A).append("=").append(u16.apply(3))
                    .append(";$").append(B).append("=").append(u16.apply(5)).append(";$").append(SH)
                    .append("=$").append(R).append("[$").append(B).append("]&0x1F;$").append(V)
                    .append("=$").append(R).append("[$").append(A).append("]&0xFFFFFFFF;");
            switch (op) {
                case 0x17 -> o.append("$").append(R).append("[$").append(D).append("]=($").append(V)
                        .append("<<$").append(SH).append(")&0xFFFFFFFF;");
                case 0x18 -> o.append("$").append(R).append("[$").append(D).append("]=$").append(V)
                        .append(">>$").append(SH).append(";");
                case 0x19 -> o.append("$").append(R).append("[$").append(D).append("]=$").append(SH)
                        .append("===0?$").append(V).append(":(($").append(V).append("<<$").append(SH)
                        .append(")|($").append(V).append(">>(32-$").append(SH).append(")))&0xFFFFFFFF;");
                case 0x1A -> o.append("$").append(R).append("[$").append(D).append("]=$").append(SH)
                        .append("===0?$").append(V).append(":(($").append(V).append(">>$").append(SH)
                        .append(")|($").append(V).append("<<(32-$").append(SH).append(")))&0xFFFFFFFF;");
            }
            o.append("$").append(P).append("+=7;break;}");
        }

        // ADD64, MUL64, XOR64
        o.append("case 0x20:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(R).append("[$").append(D).append("]=$")
                .append(R).append("[$").append(A).append("]+$").append(R).append("[$").append(B)
                .append("];$").append(P).append("+=7;break;}");
        o.append("case 0x21:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(R).append("[$").append(D).append("]=$")
                .append(R).append("[$").append(A).append("]*$").append(R).append("[$").append(B)
                .append("];$").append(P).append("+=7;break;}");
        // 0x22 SHR64: unsigned right shift, mask top bits after
        o.append("case 0x22:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(SH).append("=$").append(R).append("[$")
                .append(B).append("]&0x3F;$").append(V).append("=$").append(R).append("[$")
                .append(A).append("];$").append(R).append("[$").append(D).append("]=$").append(SH)
                .append("===0?$").append(V).append(":(($").append(V).append(">>$").append(SH)
                .append(")&(PHP_INT_MAX>>($").append(SH).append("-1)));$").append(P).append("+=7;break;}");
        o.append("case 0x23:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(R).append("[$").append(D).append("]=$")
                .append(R).append("[$").append(A).append("]^$").append(R).append("[$").append(B)
                .append("];$").append(P).append("+=7;break;}");

        // SEXT8 / SEXT32
        o.append("case 0x30:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(R).append("[$")
                .append(D).append("]=($").append(R).append("[$").append(A).append("]<<56)>>56;$")
                .append(P).append("+=5;break;}");
        o.append("case 0x31:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(R).append("[$")
                .append(D).append("]=($").append(R).append("[$").append(A).append("]<<32)>>32;$")
                .append(P).append("+=5;break;}");

        // LDB / LDBS / STB
        o.append("case 0x40:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(OF).append("=")
                .append(i16.apply(5)).append(";$").append(AD).append("=$").append(R).append("[$")
                .append(A).append("]+$").append(OF).append(";$").append(R).append("[$").append(D)
                .append("]=ord($").append(M).append("[$").append(AD).append("]);$").append(P).append("+=7;break;}");
        o.append("case 0x41:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(OF).append("=")
                .append(i16.apply(5)).append(";$").append(AD).append("=$").append(R).append("[$")
                .append(A).append("]+$").append(OF).append(";$").append(V).append("=ord($")
                .append(M).append("[$").append(AD).append("]);$").append(R).append("[$").append(D)
                .append("]=($").append(V).append("<<56)>>56;$").append(P).append("+=7;break;}");
        o.append("case 0x42:{$").append(A).append("=").append(u16.apply(1)).append(";$")
                .append(OF).append("=").append(i16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(AD).append("=$").append(R).append("[$")
                .append(A).append("]+$").append(OF).append(";$").append(M).append("[$")
                .append(AD).append("]=chr($").append(R).append("[$").append(B).append("]&0xFF);$")
                .append(P).append("+=7;break;}");

        // LDW / STW
        o.append("case 0x43:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(OF).append("=")
                .append(i16.apply(5)).append(";$").append(AD).append("=$").append(R).append("[$")
                .append(A).append("]+$").append(OF).append(";$").append(V).append("=ord($")
                .append(M).append("[$").append(AD).append("])|(ord($").append(M).append("[$")
                .append(AD).append("+1])<<8)|(ord($").append(M).append("[$").append(AD)
                .append("+2])<<16)|(ord($").append(M).append("[$").append(AD).append("+3])<<24);$")
                .append(R).append("[$").append(D).append("]=$").append(V).append("&0xFFFFFFFF;$")
                .append(P).append("+=7;break;}");
        o.append("case 0x44:{$").append(A).append("=").append(u16.apply(1)).append(";$")
                .append(OF).append("=").append(i16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(AD).append("=$").append(R).append("[$")
                .append(A).append("]+$").append(OF).append(";$").append(V).append("=$").append(R)
                .append("[$").append(B).append("];$").append(M).append("[$").append(AD)
                .append("]=chr($").append(V).append("&0xFF);$").append(M).append("[$").append(AD)
                .append("+1]=chr(($").append(V).append(">>8)&0xFF);$").append(M).append("[$")
                .append(AD).append("+2]=chr(($").append(V).append(">>16)&0xFF);$").append(M)
                .append("[$").append(AD).append("+3]=chr(($").append(V).append(">>24)&0xFF);$")
                .append(P).append("+=7;break;}");

        // LDQ / STQ
        o.append("case 0x45:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(OF).append("=")
                .append(i16.apply(5)).append(";$").append(AD).append("=$").append(R).append("[$")
                .append(A).append("]+$").append(OF).append(";$").append(V).append("=0;for($")
                .append(W).append("=0;$").append(W).append("<8;$").append(W).append("++)$")
                .append(V).append("|=ord($").append(M).append("[$").append(AD).append("+$")
                .append(W).append("])<<($").append(W).append("*8);$").append(R).append("[$")
                .append(D).append("]=$").append(V).append(";$").append(P).append("+=7;break;}");
        o.append("case 0x46:{$").append(A).append("=").append(u16.apply(1)).append(";$")
                .append(OF).append("=").append(i16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(AD).append("=$").append(R).append("[$")
                .append(A).append("]+$").append(OF).append(";$").append(V).append("=$").append(R)
                .append("[$").append(B).append("];for($").append(W).append("=0;$").append(W)
                .append("<8;$").append(W).append("++)$").append(M).append("[$").append(AD)
                .append("+$").append(W).append("]=chr(($").append(V).append(">>($").append(W)
                .append("*8))&0xFF);$").append(P).append("+=7;break;}");

        // SBOX (0x50)
        o.append("case 0x50:{$").append(D).append("=").append(u16.apply(1)).append(";$")
                .append(A).append("=").append(u16.apply(3)).append(";$").append(B).append("=")
                .append(u16.apply(5)).append(";$").append(WD).append("=$").append(R).append("[$")
                .append(A).append("];$").append(SL).append("=$").append(R).append("[$").append(B).append("];");
        o.append("$").append(B0).append("=$").append(WD).append("&0xFF;$").append(B1)
                .append("=($").append(WD).append(">>8)&0xFF;$").append(B2).append("=($").append(WD)
                .append(">>16)&0xFF;$").append(B3).append("=($").append(WD).append(">>24)&0xFF;");
        o.append("$").append(S0).append("=$").append(SL).append("&0x3;$").append(S1)
                .append("=($").append(SL).append(">>2)&0x3;$").append(S2).append("=($").append(SL)
                .append(">>4)&0x3;$").append(S3).append("=($").append(SL).append(">>6)&0x3;");
        o.append("if($").append(S0).append("===$").append(S2).append("){$").append(B0)
                .append("=ord($").append(M).append("[$").append(SB).append("+(($").append(S0)
                .append("<<8)|ord($").append(M).append("[$").append(SB).append("+(($").append(S1)
                .append("<<8)|$").append(B0).append(")*4]))*4]);$").append(B2).append("=ord($")
                .append(M).append("[$").append(SB).append("+(($").append(S2).append("<<8)|ord($")
                .append(M).append("[$").append(SB).append("+(($").append(S3).append("<<8)|$")
                .append(B2).append(")*4]))*4]);}else{$").append(B0).append("=ord($").append(M)
                .append("[$").append(SB).append("+(($").append(S0).append("<<8)|$").append(B0)
                .append(")*4]);$").append(B2).append("=ord($").append(M).append("[$").append(SB)
                .append("+(($").append(S2).append("<<8)|$").append(B2).append(")*4]);}");
        o.append("if($").append(S1).append("===$").append(S3).append("){$").append(B1)
                .append("=ord($").append(M).append("[$").append(SB).append("+(($").append(S3)
                .append("<<8)|ord($").append(M).append("[$").append(SB).append("+(($").append(S0)
                .append("<<8)|$").append(B1).append(")*4]))*4]);$").append(B3).append("=ord($")
                .append(M).append("[$").append(SB).append("+(($").append(S1).append("<<8)|ord($")
                .append(M).append("[$").append(SB).append("+(($").append(S2).append("<<8)|$")
                .append(B3).append(")*4]))*4]);}else{$").append(B1).append("=ord($").append(M)
                .append("[$").append(SB).append("+(($").append(S1).append("<<8)|$").append(B1)
                .append(")*4]);$").append(B3).append("=ord($").append(M).append("[$").append(SB)
                .append("+(($").append(S3).append("<<8)|$").append(B3).append(")*4]);}");
        o.append("$").append(RZ).append("=(($").append(B3).append("<<24)|($").append(B2)
                .append("<<16)|($").append(B1).append("<<8)|$").append(B0).append(")&0xFFFFFFFF;$")
                .append(R).append("[$").append(D).append("]=$").append(RZ).append(";$")
                .append(P).append("+=7;break;}");

        // 0x60 JMP
        o.append("case 0x60:{$").append(P).append("=").append(u32.apply(1)).append(";break;}");
        // 0x61 JZ32 / 0x62 JNZ32 — compare low-32 (sign-extended) to 0
        o.append("case 0x61:{$").append(A).append("=").append(u16.apply(1)).append(";$")
                .append(T).append("=").append(u32.apply(3)).append(";if((($").append(R).append("[$")
                .append(A).append("]<<32)>>32)===0)$").append(P).append("=$").append(T)
                .append(";else $").append(P).append("+=7;break;}");
        o.append("case 0x62:{$").append(A).append("=").append(u16.apply(1)).append(";$")
                .append(T).append("=").append(u32.apply(3)).append(";if((($").append(R).append("[$")
                .append(A).append("]<<32)>>32)!==0)$").append(P).append("=$").append(T)
                .append(";else $").append(P).append("+=7;break;}");

        // Signed compares
        String[] sOps = {"==", "!=", "<", ">=", ">", "<="};
        int[] sCs = {0x63, 0x64, 0x65, 0x66, 0x67, 0x68};
        for (int i = 0; i < sCs.length; i++) {
            o.append("case ").append(hex(sCs[i])).append(":{$").append(A).append("=")
                    .append(u16.apply(1)).append(";$").append(B).append("=").append(u16.apply(3))
                    .append(";$").append(T).append("=").append(u32.apply(5))
                    .append(";if((($").append(R).append("[$").append(A).append("]<<32)>>32)")
                    .append(sOps[i]).append("(($").append(R).append("[$").append(B)
                    .append("]<<32)>>32))$").append(P).append("=$").append(T).append(";else $")
                    .append(P).append("+=9;break;}");
        }
        // Unsigned compares: low 32 bits as unsigned
        String[] uOps = {"<", ">=", ">", "<="};
        int[] uCs = {0x69, 0x6A, 0x6B, 0x6C};
        for (int i = 0; i < uCs.length; i++) {
            o.append("case ").append(hex(uCs[i])).append(":{$").append(A).append("=")
                    .append(u16.apply(1)).append(";$").append(B).append("=").append(u16.apply(3))
                    .append(";$").append(T).append("=").append(u32.apply(5))
                    .append(";if(($").append(R).append("[$").append(A).append("]&0xFFFFFFFF)")
                    .append(uOps[i]).append("($").append(R).append("[$").append(B)
                    .append("]&0xFFFFFFFF))$").append(P).append("=$").append(T).append(";else $")
                    .append(P).append("+=9;break;}");
        }

        // 0x70 RET — break out of switch+while
        o.append("case 0x70:break 2;");
        o.append("default:throw new \\Exception(\"\");");
        o.append("}}");

        // Return crypt output if any.
        o.append("if($").append(pOp).append("===1&&$").append(pLen).append(">0)return substr($")
                .append(pMem).append(",$").append(outA).append(",$").append(pLen).append(");");
        o.append("return\"\";");
        o.append("}}");
        return o.toString();
    }

    /* ── Go emission: same shape as emit()/emitPhp(), Go syntax, with embedded runner ── */
    private String emitGo(CompiledMethod init, CompiledMethod crypt) {
        String FN = N.get("FN");
        String pMem = N.get("p_mem"), pOp = N.get("p_op"), pA = N.get("p_a"),
                pB = N.get("p_b"), pLen = N.get("p_len");
        String INIT_CODE = N.get("v_INIT_CODE");
        String CRYPT_CODE = N.get("v_CRYPT_CODE");
        String SBOX = N.get("v_SBOX");
        String PHI = N.get("v_PHI");
        String KEY = N.get("v_KEY");
        String KSZ = N.get("c_KEY_SIZE"), NSZ = N.get("c_NONCE_SIZE");
        String SB = N.get("c_SBOX_BASE"), PB = N.get("c_PHI_BASE"), STB = N.get("c_STATE_BASE"),
                SCB = N.get("c_SCRATCH_BASE");
        String IR = N.get("c_INIT_REGS"), ISC = N.get("c_INIT_SCRATCH"),
                CR = N.get("c_CRYPT_REGS"), CSC = N.get("c_CRYPT_SCRATCH");
        String code = N.get("v_code"), regs = N.get("v_regs"), pc = N.get("v_pc"),
                opc = N.get("v_opc"), outA = N.get("v_outA"), outBuf = N.get("v_outBuf");
        String keyA = N.get("v_keyA"), nonA = N.get("v_nonA"), inA = N.get("v_inA"),
                need = N.get("v_need"), grow = N.get("v_grow");
        String ix = N.get("v_ix"), nm = N.get("v_nm"), js = N.get("v_js");
        String dispatch = N.get("l_dispatch");
        String D = N.get("s_D"), A = N.get("s_A"), B = N.get("s_B"),
                T = N.get("s_T"), V = N.get("s_V"), W = N.get("s_W"),
                OF = N.get("s_OF"), AD = N.get("s_AD"), SH = N.get("s_SH");
        String B0 = N.get("s_B0"), B1 = N.get("s_B1"), B2 = N.get("s_B2"), B3 = N.get("s_B3"),
                S0 = N.get("s_S0"), S1 = N.get("s_S1"), S2 = N.get("s_S2"), S3 = N.get("s_S3"),
                WD = N.get("s_WD"), SL = N.get("s_SL"), RZ = N.get("s_RZ");
        // runner-local names (for main())
        String mScan = N.get("m_scan"), mLine = N.get("m_line"), mParts = N.get("m_parts"),
                mKey = N.get("m_key"), mNonce = N.get("m_nonce"), mPt = N.get("m_pt"),
                mMem = N.get("m_mem"), mCt = N.get("m_ct");

        int[] sboxInts = MemoryLayout.hydraSbox();
        byte[] sboxBytes = new byte[sboxInts.length];
        for (int i = 0; i < sboxInts.length; i++) sboxBytes[i] = (byte) sboxInts[i];
        int[] phiInts = MemoryLayout.hydraPhi();
        byte[] phiBytes = new byte[phiInts.length * 4];
        for (int i = 0; i < phiInts.length; i++) {
            int v = phiInts[i];
            phiBytes[i * 4] = (byte) v;
            phiBytes[i * 4 + 1] = (byte) (v >>> 8);
            phiBytes[i * 4 + 2] = (byte) (v >>> 16);
            phiBytes[i * 4 + 3] = (byte) (v >>> 24);
        }

        StringBuilder o = new StringBuilder(96 * 1024);
        o.append("package main\n");
        o.append("import (\n\"bufio\"\n\"encoding/base64\"\n\"encoding/hex\"\n\"os\"\n\"strings\"\n)\n");

        o.append("func ").append(FN).append("(").append(pMem).append(" []byte, ")
                .append(pOp).append(" int, ").append(pA).append(" []byte, ")
                .append(pB).append(" []byte, ").append(pLen).append(" int) ([]byte, []byte) {\n");

        // Embedded data.
        o.append(KEY).append(", _ := base64.StdEncoding.DecodeString(\"")
                .append(b64(xorKey)).append("\")\n");
        o.append(INIT_CODE).append(", _ := base64.StdEncoding.DecodeString(\"")
                .append(b64(mask(init.bytecode()))).append("\")\n");
        o.append(CRYPT_CODE).append(", _ := base64.StdEncoding.DecodeString(\"")
                .append(b64(mask(crypt.bytecode()))).append("\")\n");
        o.append(SBOX).append(", _ := base64.StdEncoding.DecodeString(\"")
                .append(b64(mask(sboxBytes))).append("\")\n");
        o.append(PHI).append(", _ := base64.StdEncoding.DecodeString(\"")
                .append(b64(mask(phiBytes))).append("\")\n");

        for (String var : new String[]{INIT_CODE, CRYPT_CODE, SBOX, PHI}) {
            o.append("for ").append(ix).append(" := 0; ").append(ix).append(" < len(")
                    .append(var).append("); ").append(ix).append("++ { ").append(var).append("[")
                    .append(ix).append("] ^= ").append(KEY).append("[").append(ix).append("%len(")
                    .append(KEY).append(")] }\n");
        }

        o.append(STB).append(" := ").append(MemoryLayout.STATE_BASE).append("\n");
        o.append(SB).append(" := ").append(MemoryLayout.SBOX_BASE).append("\n");
        o.append(PB).append(" := ").append(MemoryLayout.PHI_BASE).append("\n");
        o.append(SCB).append(" := ").append(MemoryLayout.SCRATCH_BASE).append("\n");
        o.append(IR).append(" := ").append(init.regCount()).append("\n");
        o.append(ISC).append(" := ").append(init.scratchSize()).append("\n");
        o.append(CR).append(" := ").append(crypt.regCount()).append("\n");
        o.append(CSC).append(" := ").append(crypt.scratchSize()).append("\n");
        o.append(KSZ).append(" := ").append(HydraStream.HYDRA_KEY_SIZE).append("\n");
        o.append(NSZ).append(" := ").append(HydraStream.HYDRA_NONCE_SIZE).append("\n");

        // Allocate / preload mem on first call.
        o.append("if ").append(pMem).append(" == nil {\n");
        o.append(nm).append(" := ").append(SCB).append(" + ").append(ISC).append("\n");
        o.append("if ").append(CSC).append(" > ").append(ISC).append(" { ").append(nm)
                .append(" = ").append(SCB).append(" + ").append(CSC).append(" }\n");
        o.append(nm).append(" += ").append(KSZ).append(" + ").append(NSZ).append(" + 8\n");
        o.append(pMem).append(" = make([]byte, ").append(nm).append(")\n");
        o.append("for ").append(js).append(" := 0; ").append(js).append(" < len(")
                .append(SBOX).append("); ").append(js).append("++ { ").append(pMem)
                .append("[").append(SB).append("+").append(js).append("*4] = ")
                .append(SBOX).append("[").append(js).append("] }\n");
        o.append("copy(").append(pMem).append("[").append(PB).append(":], ").append(PHI).append(")\n");
        o.append("}\n");

        // Route by op.
        o.append("var ").append(code).append(" []byte\n");
        o.append("var ").append(regs).append(" []uint64\n");
        o.append(outA).append(" := -1\n");
        o.append("if ").append(pOp).append(" == 0 {\n");
        o.append(keyA).append(" := ").append(SCB).append(" + ").append(ISC).append("\n");
        o.append(nonA).append(" := ").append(keyA).append(" + ").append(KSZ).append("\n");
        o.append(need).append(" := ").append(nonA).append(" + ").append(NSZ).append(" + 8\n");
        o.append("if len(").append(pMem).append(") < ").append(need).append(" {\n");
        o.append(grow).append(" := ").append(need).append("\n");
        o.append("if len(").append(pMem).append(")*2 > ").append(grow).append(" { ").append(grow)
                .append(" = len(").append(pMem).append(")*2 }\n");
        o.append("nb := make([]byte, ").append(grow).append(")\n");
        o.append("copy(nb, ").append(pMem).append(")\n");
        o.append(pMem).append(" = nb\n");
        o.append("}\n");
        o.append("copy(").append(pMem).append("[").append(keyA).append(":], ").append(pA)
                .append("[:").append(KSZ).append("])\n");
        o.append("copy(").append(pMem).append("[").append(nonA).append(":], ").append(pB)
                .append("[:").append(NSZ).append("])\n");
        o.append(regs).append(" = make([]uint64, ").append(IR).append(")\n");
        o.append(regs).append("[0] = uint64(").append(STB).append(")\n");
        o.append(regs).append("[1] = uint64(").append(keyA).append(")\n");
        o.append(regs).append("[2] = uint64(").append(nonA).append(")\n");
        o.append(code).append(" = ").append(INIT_CODE).append("\n");
        o.append("} else {\n");
        o.append(inA).append(" := ").append(SCB).append(" + ").append(CSC).append("\n");
        o.append(outA).append(" = ").append(inA).append(" + ").append(pLen).append("\n");
        o.append(need).append(" := ").append(outA).append(" + ").append(pLen).append(" + 8\n");
        o.append("if len(").append(pMem).append(") < ").append(need).append(" {\n");
        o.append(grow).append(" := ").append(need).append("\n");
        o.append("if len(").append(pMem).append(")*2 > ").append(grow).append(" { ").append(grow)
                .append(" = len(").append(pMem).append(")*2 }\n");
        o.append("nb := make([]byte, ").append(grow).append(")\n");
        o.append("copy(nb, ").append(pMem).append(")\n");
        o.append(pMem).append(" = nb\n");
        o.append("}\n");
        o.append("if ").append(pLen).append(" > 0 { copy(").append(pMem).append("[")
                .append(inA).append(":], ").append(pA).append("[:").append(pLen).append("]) }\n");
        o.append(regs).append(" = make([]uint64, ").append(CR).append(")\n");
        o.append(regs).append("[0] = uint64(").append(STB).append(")\n");
        o.append(regs).append("[1] = uint64(").append(inA).append(")\n");
        o.append(regs).append("[2] = uint64(").append(outA).append(")\n");
        o.append(regs).append("[3] = uint64(").append(pLen).append(")\n");
        o.append(code).append(" = ").append(CRYPT_CODE).append("\n");
        o.append("}\n");

        // Dispatch loop.
        String C = code, R = regs, M = pMem, P = pc;
        o.append(P).append(" := 0\n");
        o.append(dispatch).append(":\n");
        o.append("for {\n");
        o.append(opc).append(" := ").append(C).append("[").append(P).append("]\n");
        o.append("switch ").append(opc).append(" {\n");

        java.util.function.IntFunction<String> u16 = (off) ->
                "(int(" + C + "[" + P + "+" + off + "])|int(" + C + "[" + P + "+" + (off + 1) + "])<<8)";
        java.util.function.IntFunction<String> i16 = (off) ->
                "int(int16(" + u16.apply(off) + "))";
        java.util.function.IntFunction<String> u32 = (off) ->
                "(uint32(" + C + "[" + P + "+" + off + "])|uint32(" + C + "[" + P + "+" + (off + 1) + "])<<8|uint32(" + C + "[" + P + "+" + (off + 2) + "])<<16|uint32(" + C + "[" + P + "+" + (off + 3) + "])<<24)";

        // 0x01 MOV
        o.append("case 0x01: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(R).append("[")
                .append(D).append("] = ").append(R).append("[").append(A).append("]; ").append(P).append(" += 5\n");
        // 0x02 LDI sign-extend low 32 to 64
        o.append("case 0x02: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(T).append(" := uint64(int64(int32(").append(u32.apply(3)).append("))); ")
                .append(R).append("[").append(D).append("] = ").append(T).append("; ").append(P).append(" += 7\n");
        // 0x03 LDIQ
        o.append("case 0x03: ").append(D).append(" := ").append(u16.apply(1)).append("; var ")
                .append(V).append(" uint64 = 0; for ").append(W).append(" := 0; ").append(W)
                .append(" < 8; ").append(W).append("++ { ").append(V).append(" |= uint64(")
                .append(C).append("[").append(P).append("+3+").append(W).append("]) << (")
                .append(W).append("*8) }; ").append(R).append("[").append(D).append("] = ")
                .append(V).append("; ").append(P).append(" += 11\n");

        // 32-bit ALU simple ops
        String[] alu32op = {"+", "-", "&", "|", "^"};
        int[] alu32code = {0x10, 0x11, 0x14, 0x15, 0x16};
        for (int i = 0; i < alu32code.length; i++) {
            o.append("case ").append(hex(alu32code[i])).append(": ").append(D).append(" := ")
                    .append(u16.apply(1)).append("; ").append(A).append(" := ").append(u16.apply(3))
                    .append("; ").append(B).append(" := ").append(u16.apply(5)).append("; ")
                    .append(R).append("[").append(D).append("] = (").append(R).append("[").append(A)
                    .append("] ").append(alu32op[i]).append(" ").append(R).append("[").append(B)
                    .append("]) & 0xFFFFFFFF; ").append(P).append(" += 7\n");
        }
        // MUL32 / REM32 (signed)
        o.append("case 0x12: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(V).append(" := uint64(int32(")
                .append(R).append("[").append(A).append("]) * int32(").append(R).append("[")
                .append(B).append("])) & 0xFFFFFFFF; ").append(R).append("[").append(D)
                .append("] = ").append(V).append("; ").append(P).append(" += 7\n");
        o.append("case 0x13: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(V).append(" := uint64(int32(")
                .append(R).append("[").append(A).append("]) % int32(").append(R).append("[")
                .append(B).append("])) & 0xFFFFFFFF; ").append(R).append("[").append(D)
                .append("] = ").append(V).append("; ").append(P).append(" += 7\n");

        // SHL32 / SHR32 / ROL32 / ROR32
        for (int op : new int[]{0x17, 0x18, 0x19, 0x1A}) {
            o.append("case ").append(hex(op)).append(": ").append(D).append(" := ")
                    .append(u16.apply(1)).append("; ").append(A).append(" := ").append(u16.apply(3))
                    .append("; ").append(B).append(" := ").append(u16.apply(5)).append("; ")
                    .append(SH).append(" := uint(").append(R).append("[").append(B).append("] & 0x1F); ")
                    .append(V).append(" := ").append(R).append("[").append(A).append("] & 0xFFFFFFFF; ");
            switch (op) {
                case 0x17 -> o.append(R).append("[").append(D).append("] = (").append(V)
                        .append(" << ").append(SH).append(") & 0xFFFFFFFF;");
                case 0x18 -> o.append(R).append("[").append(D).append("] = ").append(V)
                        .append(" >> ").append(SH).append(";");
                case 0x19 -> o.append("if ").append(SH).append(" == 0 { ").append(R).append("[")
                        .append(D).append("] = ").append(V).append(" } else { ").append(R)
                        .append("[").append(D).append("] = ((").append(V).append(" << ")
                        .append(SH).append(") | (").append(V).append(" >> (32 - ").append(SH)
                        .append("))) & 0xFFFFFFFF };");
                case 0x1A -> o.append("if ").append(SH).append(" == 0 { ").append(R).append("[")
                        .append(D).append("] = ").append(V).append(" } else { ").append(R)
                        .append("[").append(D).append("] = ((").append(V).append(" >> ")
                        .append(SH).append(") | (").append(V).append(" << (32 - ").append(SH)
                        .append("))) & 0xFFFFFFFF };");
            }
            o.append(" ").append(P).append(" += 7\n");
        }

        // ADD64, MUL64, SHR64, XOR64
        o.append("case 0x20: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(R).append("[").append(D).append("] = ")
                .append(R).append("[").append(A).append("] + ").append(R).append("[").append(B)
                .append("]; ").append(P).append(" += 7\n");
        o.append("case 0x21: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(R).append("[").append(D).append("] = ")
                .append(R).append("[").append(A).append("] * ").append(R).append("[").append(B)
                .append("]; ").append(P).append(" += 7\n");
        o.append("case 0x22: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(SH).append(" := uint(").append(R)
                .append("[").append(B).append("] & 0x3F); ").append(R).append("[").append(D)
                .append("] = ").append(R).append("[").append(A).append("] >> ").append(SH).append("; ")
                .append(P).append(" += 7\n");
        o.append("case 0x23: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(R).append("[").append(D).append("] = ")
                .append(R).append("[").append(A).append("] ^ ").append(R).append("[").append(B)
                .append("]; ").append(P).append(" += 7\n");

        // SEXT8 / SEXT32
        o.append("case 0x30: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(R).append("[")
                .append(D).append("] = uint64(int64(int8(").append(R).append("[").append(A)
                .append("]))); ").append(P).append(" += 5\n");
        o.append("case 0x31: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(R).append("[")
                .append(D).append("] = uint64(int64(int32(").append(R).append("[").append(A)
                .append("]))); ").append(P).append(" += 5\n");

        // LDB / LDBS / STB
        o.append("case 0x40: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(OF).append(" := ")
                .append(i16.apply(5)).append("; ").append(AD).append(" := int(").append(R).append("[")
                .append(A).append("]) + ").append(OF).append("; ").append(R).append("[").append(D)
                .append("] = uint64(").append(M).append("[").append(AD).append("]); ").append(P)
                .append(" += 7\n");
        o.append("case 0x41: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(OF).append(" := ")
                .append(i16.apply(5)).append("; ").append(AD).append(" := int(").append(R).append("[")
                .append(A).append("]) + ").append(OF).append("; ").append(R).append("[").append(D)
                .append("] = uint64(int64(int8(").append(M).append("[").append(AD).append("]))); ")
                .append(P).append(" += 7\n");
        o.append("case 0x42: ").append(A).append(" := ").append(u16.apply(1)).append("; ")
                .append(OF).append(" := ").append(i16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(AD).append(" := int(").append(R).append("[")
                .append(A).append("]) + ").append(OF).append("; ").append(M).append("[").append(AD)
                .append("] = byte(").append(R).append("[").append(B).append("]); ").append(P)
                .append(" += 7\n");

        // LDW / STW
        o.append("case 0x43: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(OF).append(" := ")
                .append(i16.apply(5)).append("; ").append(AD).append(" := int(").append(R).append("[")
                .append(A).append("]) + ").append(OF).append("; ").append(V).append(" := uint64(")
                .append(M).append("[").append(AD).append("])|uint64(").append(M).append("[").append(AD)
                .append("+1])<<8|uint64(").append(M).append("[").append(AD).append("+2])<<16|uint64(")
                .append(M).append("[").append(AD).append("+3])<<24; ").append(R).append("[").append(D)
                .append("] = ").append(V).append("; ").append(P).append(" += 7\n");
        o.append("case 0x44: ").append(A).append(" := ").append(u16.apply(1)).append("; ")
                .append(OF).append(" := ").append(i16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(AD).append(" := int(").append(R).append("[")
                .append(A).append("]) + ").append(OF).append("; ").append(V).append(" := ").append(R)
                .append("[").append(B).append("]; ").append(M).append("[").append(AD).append("] = byte(")
                .append(V).append("); ").append(M).append("[").append(AD).append("+1] = byte(")
                .append(V).append(" >> 8); ").append(M).append("[").append(AD).append("+2] = byte(")
                .append(V).append(" >> 16); ").append(M).append("[").append(AD).append("+3] = byte(")
                .append(V).append(" >> 24); ").append(P).append(" += 7\n");

        // LDQ / STQ
        o.append("case 0x45: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(OF).append(" := ")
                .append(i16.apply(5)).append("; ").append(AD).append(" := int(").append(R).append("[")
                .append(A).append("]) + ").append(OF).append("; var ").append(V).append(" uint64 = 0; ")
                .append("for ").append(W).append(" := 0; ").append(W).append(" < 8; ").append(W)
                .append("++ { ").append(V).append(" |= uint64(").append(M).append("[").append(AD)
                .append("+").append(W).append("]) << (").append(W).append("*8) }; ").append(R)
                .append("[").append(D).append("] = ").append(V).append("; ").append(P).append(" += 7\n");
        o.append("case 0x46: ").append(A).append(" := ").append(u16.apply(1)).append("; ")
                .append(OF).append(" := ").append(i16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(AD).append(" := int(").append(R).append("[")
                .append(A).append("]) + ").append(OF).append("; ").append(V).append(" := ").append(R)
                .append("[").append(B).append("]; for ").append(W).append(" := 0; ").append(W)
                .append(" < 8; ").append(W).append("++ { ").append(M).append("[").append(AD)
                .append("+").append(W).append("] = byte(").append(V).append(" >> (").append(W)
                .append("*8)) }; ").append(P).append(" += 7\n");

        // SBOX
        o.append("case 0x50: ").append(D).append(" := ").append(u16.apply(1)).append("; ")
                .append(A).append(" := ").append(u16.apply(3)).append("; ").append(B).append(" := ")
                .append(u16.apply(5)).append("; ").append(WD).append(" := ").append(R).append("[")
                .append(A).append("]; ").append(SL).append(" := ").append(R).append("[").append(B)
                .append("]; ");
        o.append(B0).append(" := int(").append(WD).append(" & 0xFF); ").append(B1)
                .append(" := int((").append(WD).append(" >> 8) & 0xFF); ").append(B2)
                .append(" := int((").append(WD).append(" >> 16) & 0xFF); ").append(B3)
                .append(" := int((").append(WD).append(" >> 24) & 0xFF); ");
        o.append(S0).append(" := int(").append(SL).append(" & 3); ").append(S1)
                .append(" := int((").append(SL).append(" >> 2) & 3); ").append(S2)
                .append(" := int((").append(SL).append(" >> 4) & 3); ").append(S3)
                .append(" := int((").append(SL).append(" >> 6) & 3); ");
        o.append("if ").append(S0).append(" == ").append(S2).append(" { ")
                .append(B0).append(" = int(").append(M).append("[").append(SB).append("+(")
                .append(S0).append("<<8|int(").append(M).append("[").append(SB).append("+(")
                .append(S1).append("<<8|").append(B0).append(")*4]))*4]); ")
                .append(B2).append(" = int(").append(M).append("[").append(SB).append("+(")
                .append(S2).append("<<8|int(").append(M).append("[").append(SB).append("+(")
                .append(S3).append("<<8|").append(B2).append(")*4]))*4]); ")
                .append("} else { ")
                .append(B0).append(" = int(").append(M).append("[").append(SB).append("+(")
                .append(S0).append("<<8|").append(B0).append(")*4]); ")
                .append(B2).append(" = int(").append(M).append("[").append(SB).append("+(")
                .append(S2).append("<<8|").append(B2).append(")*4]); }; ");
        o.append("if ").append(S1).append(" == ").append(S3).append(" { ")
                .append(B1).append(" = int(").append(M).append("[").append(SB).append("+(")
                .append(S3).append("<<8|int(").append(M).append("[").append(SB).append("+(")
                .append(S0).append("<<8|").append(B1).append(")*4]))*4]); ")
                .append(B3).append(" = int(").append(M).append("[").append(SB).append("+(")
                .append(S1).append("<<8|int(").append(M).append("[").append(SB).append("+(")
                .append(S2).append("<<8|").append(B3).append(")*4]))*4]); ")
                .append("} else { ")
                .append(B1).append(" = int(").append(M).append("[").append(SB).append("+(")
                .append(S1).append("<<8|").append(B1).append(")*4]); ")
                .append(B3).append(" = int(").append(M).append("[").append(SB).append("+(")
                .append(S3).append("<<8|").append(B3).append(")*4]); }; ");
        o.append(RZ).append(" := uint64((").append(B3).append("<<24)|(").append(B2)
                .append("<<16)|(").append(B1).append("<<8)|").append(B0).append(") & 0xFFFFFFFF; ")
                .append(R).append("[").append(D).append("] = ").append(RZ).append("; ").append(P)
                .append(" += 7\n");

        // 0x60 JMP
        o.append("case 0x60: ").append(P).append(" = int(").append(u32.apply(1)).append(")\n");
        // 0x61/0x62 JZ32/JNZ32: compare low 32 (signed) to 0
        o.append("case 0x61: ").append(A).append(" := ").append(u16.apply(1)).append("; ")
                .append(T).append(" := int(").append(u32.apply(3)).append("); if int32(")
                .append(R).append("[").append(A).append("]) == 0 { ").append(P).append(" = ")
                .append(T).append(" } else { ").append(P).append(" += 7 }\n");
        o.append("case 0x62: ").append(A).append(" := ").append(u16.apply(1)).append("; ")
                .append(T).append(" := int(").append(u32.apply(3)).append("); if int32(")
                .append(R).append("[").append(A).append("]) != 0 { ").append(P).append(" = ")
                .append(T).append(" } else { ").append(P).append(" += 7 }\n");

        // Signed compares
        String[] sOps = {"==", "!=", "<", ">=", ">", "<="};
        int[] sCs = {0x63, 0x64, 0x65, 0x66, 0x67, 0x68};
        for (int i = 0; i < sCs.length; i++) {
            o.append("case ").append(hex(sCs[i])).append(": ").append(A).append(" := ")
                    .append(u16.apply(1)).append("; ").append(B).append(" := ").append(u16.apply(3))
                    .append("; ").append(T).append(" := int(").append(u32.apply(5))
                    .append("); if int32(").append(R).append("[").append(A).append("]) ")
                    .append(sOps[i]).append(" int32(").append(R).append("[").append(B)
                    .append("]) { ").append(P).append(" = ").append(T).append(" } else { ")
                    .append(P).append(" += 9 }\n");
        }
        // Unsigned compares: low 32 as uint32
        String[] uOps = {"<", ">=", ">", "<="};
        int[] uCs = {0x69, 0x6A, 0x6B, 0x6C};
        for (int i = 0; i < uCs.length; i++) {
            o.append("case ").append(hex(uCs[i])).append(": ").append(A).append(" := ")
                    .append(u16.apply(1)).append("; ").append(B).append(" := ").append(u16.apply(3))
                    .append("; ").append(T).append(" := int(").append(u32.apply(5))
                    .append("); if uint32(").append(R).append("[").append(A).append("]) ")
                    .append(uOps[i]).append(" uint32(").append(R).append("[").append(B)
                    .append("]) { ").append(P).append(" = ").append(T).append(" } else { ")
                    .append(P).append(" += 9 }\n");
        }
        // RET
        o.append("case 0x70: break ").append(dispatch).append("\n");
        o.append("default: panic(\"\")\n");
        o.append("}\n");   // end switch
        o.append("}\n");   // end for
        // Build output buffer for crypt
        o.append("var ").append(outBuf).append(" []byte\n");
        o.append("if ").append(pOp).append(" == 1 && ").append(pLen).append(" > 0 { ")
                .append(outBuf).append(" = make([]byte, ").append(pLen).append("); copy(")
                .append(outBuf).append(", ").append(pMem).append("[").append(outA).append(":")
                .append(outA).append("+").append(pLen).append("]) }\n");
        o.append("return ").append(pMem).append(", ").append(outBuf).append("\n");
        o.append("}\n");

        // ── runner main() ──
        o.append("func main() {\n");
        o.append(mScan).append(" := bufio.NewScanner(os.Stdin)\n");
        o.append(mScan).append(".Buffer(make([]byte, 1<<20), 1<<24)\n");
        o.append("var ").append(mMem).append(" []byte\n");
        o.append("for ").append(mScan).append(".Scan() {\n");
        o.append(mLine).append(" := strings.TrimSpace(").append(mScan).append(".Text())\n");
        o.append("if ").append(mLine).append(" == \"\" { continue }\n");
        o.append(mParts).append(" := strings.Split(").append(mLine).append(", \"|\")\n");
        o.append(mKey).append(", _ := hex.DecodeString(").append(mParts).append("[0])\n");
        o.append(mNonce).append(", _ := hex.DecodeString(").append(mParts).append("[1])\n");
        o.append(mPt).append(", _ := hex.DecodeString(").append(mParts).append("[2])\n");
        o.append(mMem).append(", _ = ").append(FN).append("(").append(mMem).append(", 0, ")
                .append(mKey).append(", ").append(mNonce).append(", 0)\n");
        o.append("var ").append(mCt).append(" []byte\n");
        o.append(mMem).append(", ").append(mCt).append(" = ").append(FN).append("(").append(mMem)
                .append(", 1, ").append(mPt).append(", nil, len(").append(mPt).append("))\n");
        o.append("os.Stdout.WriteString(hex.EncodeToString(").append(mCt).append(") + \"\\n\")\n");
        o.append("}\n");
        o.append("}\n");

        return o.toString();
    }

    /* ── name allocator ─────────────────────────────────────────────── */
    static final class Names {
        private static final char[] START = "Ilo".toCharArray();
        private static final char[] BODY = "Ilo01".toCharArray();
        private static final Set<String> RESERVED = Set.of(
                "if", "do", "for", "int", "new", "try", "var", "null", "true", "false", "byte", "long",
                "void", "this", "case", "else", "char", "class", "while", "break", "throw", "static",
                "final", "return", "switch", "import", "public", "private", "throws", "package",
                "default", "native", "interface", "instanceof");
        private final Random rng;
        private final Map<String, String> map = new HashMap<>();
        private final Set<String> used = new HashSet<>();

        Names(Random rng) {
            this.rng = rng;
        }

        String get(String key) {
            return map.computeIfAbsent(key, k -> generate());
        }

        String fresh() {
            return generate();
        }

        private String generate() {
            for (int attempt = 0; attempt < 200; attempt++) {
                int len = 4 + rng.nextInt(4);
                StringBuilder sb = new StringBuilder(len);
                sb.append(START[rng.nextInt(START.length)]);
                for (int i = 1; i < len; i++) sb.append(BODY[rng.nextInt(BODY.length)]);
                String s = sb.toString();
                if (used.add(s) && !RESERVED.contains(s)) return s;
            }
            throw new RuntimeException("name collision saturated");
        }
    }
}