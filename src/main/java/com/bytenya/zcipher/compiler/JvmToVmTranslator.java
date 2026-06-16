package com.bytenya.zcipher.compiler;

import com.bytenya.zcipher.vm.MemoryLayout;
import com.bytenya.zcipher.vm.VmAssembler;
import com.bytenya.zcipher.vm.VmAssembler.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/*
 * Lowers a single inlined-HydraStream MethodNode (hydraInit / hydraCrypt)
 * to ZCipher VM bytecode.
 *
 * Strategy:
 *   - Java local slot N      -> VM register N
 *   - Java operand stack     -> VM registers maxLocals + depth, depth-indexed
 *                               (longs occupy a single register; the second JVM
 *                               slot is unused on either side)
 *   - Temporaries (address calc, immediate-shift) -> registers above the stack
 *   - Each NEWARRAY site is preassigned a unique scratch byte-offset.
 *
 * State register convention: arg 0 (the `state` reference) holds the byte
 * address of the marshalled state struct in flat memory. The wrapper sets
 * it to MemoryLayout.STATE_BASE (0).
 */
public final class JvmToVmTranslator {

    public static final String HYDRA_OWNER = "com/bytenya/zcipher/HydraStream";
    public static final String STATE_OWNER = "com/bytenya/zcipher/HydraStream$State";
    private final ClassNode cn;
    private final MethodNode m;
    private final VmAssembler asm = new VmAssembler();
    private final int maxLocals;
    private final int stackBase;
    private final int tempBase;
    /**
     * Sizes of items on the simulated VM stack (1 = cat-1, 2 = cat-2/long).
     */
    private final List<Integer> stackSizes = new ArrayList<>();
    /**
     * State at each label (saved when first jumped-to or when fall-through reaches it).
     */
    private final Map<LabelNode, List<Integer>> stackAtLabel = new IdentityHashMap<>();
    private final Map<LabelNode, Label> labelMap = new IdentityHashMap<>();
    /**
     * Scratch offset (relative to scratch base register) for each NEWARRAY site.
     */
    private final Map<AbstractInsnNode, Integer> scratchOffsets = new IdentityHashMap<>();
    private final Frame<SourceValue>[] sourceFrames;
    private int scratchSize = 0;

    /**
     * Whether current PC is reachable. Goes false after GOTO/RETURN/throw, true at next label.
     */
    private boolean reachable = true;

    @SuppressWarnings({"unchecked", "rawtypes"})
    public JvmToVmTranslator(ClassNode cn, MethodNode m) {
        this.cn = cn;
        this.m = m;
        this.maxLocals = m.maxLocals;
        this.stackBase = maxLocals;
        // reserve plenty of room for stack (long takes 2 slots in JVM but we use 1 reg, so maxStack is an upper bound)
        this.tempBase = stackBase + Math.max(m.maxStack, 4) + 4;
        try {
            Analyzer a = new Analyzer<>(new SourceInterpreter());
            this.sourceFrames = a.analyze(cn.name, m);
        } catch (AnalyzerException e) {
            throw new RuntimeException("source analysis failed for " + m.name, e);
        }
    }

    private static int stateFieldOffset(String name) {
        return switch (name) {
            case "lane" -> MemoryLayout.OFF_LANE;
            case "feedback" -> MemoryLayout.OFF_FEEDBACK;
            case "selector" -> MemoryLayout.OFF_SELECTOR;
            case "roundKey" -> MemoryLayout.OFF_ROUNDKEY;
            case "mixAcc" -> MemoryLayout.OFF_MIXACC;
            case "counter" -> MemoryLayout.OFF_COUNTER;
            case "key" -> MemoryLayout.OFF_KEY;
            case "nonce" -> MemoryLayout.OFF_NONCE;
            default -> throw new IllegalArgumentException("unknown State field " + name);
        };
    }

    /* ── public entry point ── */

    private static int elemBytes(int newarrayOperand) {
        return switch (newarrayOperand) {
            case Opcodes.T_BYTE, Opcodes.T_BOOLEAN -> 1;
            case Opcodes.T_SHORT, Opcodes.T_CHAR -> 2;
            case Opcodes.T_INT, Opcodes.T_FLOAT -> 4;
            case Opcodes.T_LONG, Opcodes.T_DOUBLE -> 8;
            default -> throw new IllegalArgumentException("newarray type " + newarrayOperand);
        };
    }

    public CompiledMethod translate() {
        // First pass: assign each NEWARRAY site a scratch byte-offset.
        for (AbstractInsnNode insn : m.instructions.toArray()) {
            if (insn instanceof IntInsnNode in && in.getOpcode() == Opcodes.NEWARRAY) {
                int count = newarraySize(insn);
                int bytes = count * elemBytes(in.operand);
                scratchOffsets.put(insn, scratchSize);
                scratchSize += bytes;
            }
        }

        // Second pass: emit VM bytecode.
        for (AbstractInsnNode insn = m.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            translateInsn(insn);
        }

        // Make sure every label is bound (some may be referenced only from try-catch we skip; nothing else).
        for (Map.Entry<LabelNode, Label> e : labelMap.entrySet()) {
            if (e.getValue().pos == -1) {
                throw new IllegalStateException("unbound label in " + m.name);
            }
        }

        int argRegs = methodArgRegCount();
        int regCount = tempBase + 4;
        return new CompiledMethod(m.name, m.desc, asm.toBytecode(), scratchSize, regCount, argRegs);
    }

    /* ── stack helpers (depth-indexed register IDs) ── */

    private int methodArgRegCount() {
        Type[] args = Type.getArgumentTypes(m.desc);
        int slots = 0;
        if ((m.access & Opcodes.ACC_STATIC) == 0) slots++;
        for (Type t : args) slots += t.getSize();   // long takes 2 JVM slots
        return slots;
    }

    private int regAtDepth(int depth) {
        return stackBase + depth;
    }

    private int curDepth() {
        return stackSizes.size();
    }

    private int push(int sz) {
        int r = regAtDepth(curDepth());
        stackSizes.add(sz);
        return r;
    }

    private int push() {
        return push(1);
    }

    private int pushLong() {
        return push(2);
    }

    private int pop() {
        stackSizes.remove(stackSizes.size() - 1);
        return regAtDepth(curDepth());
    }

    private int peek() {
        return regAtDepth(curDepth() - 1);
    }

    private int peekSize() {
        return stackSizes.get(stackSizes.size() - 1);
    }

    /* temporaries: a few fixed registers above the stack */
    private int tmp0() {
        return tempBase;
    }

    private int tmp1() {
        return tempBase + 1;
    }

    private int tmp2() {
        return tempBase + 2;
    }

    /* ── per-instruction translation ── */

    private Label vmLabel(LabelNode ln) {
        return labelMap.computeIfAbsent(ln, k -> asm.newLabel());
    }

    private void translateInsn(AbstractInsnNode insn) {
        if (insn instanceof LabelNode ln) {
            // Mark VM label here.
            asm.mark(vmLabel(ln));
            // Restore stack state recorded for this label, if any.
            List<Integer> saved = stackAtLabel.get(ln);
            if (saved != null) {
                stackSizes.clear();
                stackSizes.addAll(saved);
            }
            reachable = true;
            return;
        }
        if (insn.getType() == AbstractInsnNode.FRAME || insn.getType() == AbstractInsnNode.LINE) {
            return;
        }
        if (!reachable) {
            // Skip dead code between an unconditional jump and the next label.
            return;
        }

        int op = insn.getOpcode();
        switch (op) {
            /* ── constants ── */
            case Opcodes.ACONST_NULL: {
                int r = push();
                asm.emit_ldi(r, 0);
                break;
            }
            case Opcodes.ICONST_M1:
            case Opcodes.ICONST_0:
            case Opcodes.ICONST_1:
            case Opcodes.ICONST_2:
            case Opcodes.ICONST_3:
            case Opcodes.ICONST_4:
            case Opcodes.ICONST_5: {
                int v = op - Opcodes.ICONST_0;
                int r = push();
                asm.emit_ldi(r, v);
                break;
            }
            case Opcodes.LCONST_0:
            case Opcodes.LCONST_1: {
                int v = op - Opcodes.LCONST_0;
                int r = pushLong();
                asm.emit_ldiq(r, v);
                break;
            }
            case Opcodes.BIPUSH:
            case Opcodes.SIPUSH: {
                int v = ((IntInsnNode) insn).operand;
                int r = push();
                asm.emit_ldi(r, v);
                break;
            }
            case Opcodes.LDC: {
                Object cst = ((LdcInsnNode) insn).cst;
                if (cst instanceof Integer i) {
                    int r = push();
                    asm.emit_ldi(r, i);
                } else if (cst instanceof Long l) {
                    int r = pushLong();
                    asm.emit_ldiq(r, l);
                } else {
                    throw new UnsupportedOperationException("LDC " + cst.getClass());
                }
                break;
            }

            /* ── locals ── */
            case Opcodes.ILOAD:
            case Opcodes.ALOAD: {
                int slot = ((VarInsnNode) insn).var;
                int r = push();
                asm.emit_mov(r, slot);
                break;
            }
            case Opcodes.LLOAD: {
                int slot = ((VarInsnNode) insn).var;
                int r = pushLong();
                asm.emit_mov(r, slot);
                break;
            }
            case Opcodes.ISTORE:
            case Opcodes.ASTORE: {
                int slot = ((VarInsnNode) insn).var;
                int s = peek();
                asm.emit_mov(slot, s);
                pop();
                break;
            }
            case Opcodes.LSTORE: {
                int slot = ((VarInsnNode) insn).var;
                int s = peek();
                asm.emit_mov(slot, s);
                pop();
                break;
            }
            case Opcodes.IINC: {
                IincInsnNode ii = (IincInsnNode) insn;
                asm.emit_ldi(tmp0(), ii.incr);
                asm.emit_add32(ii.var, ii.var, tmp0());
                break;
            }

            /* ── 32-bit arithmetic ── */
            case Opcodes.IADD:
                alu32(Opcodes.IADD);
                break;
            case Opcodes.ISUB:
                alu32(Opcodes.ISUB);
                break;
            case Opcodes.IMUL:
                alu32(Opcodes.IMUL);
                break;
            case Opcodes.IREM:
                alu32(Opcodes.IREM);
                break;
            case Opcodes.IAND:
                alu32(Opcodes.IAND);
                break;
            case Opcodes.IOR:
                alu32(Opcodes.IOR);
                break;
            case Opcodes.IXOR:
                alu32(Opcodes.IXOR);
                break;
            case Opcodes.ISHL:
                alu32(Opcodes.ISHL);
                break;
            case Opcodes.IUSHR:
                alu32(Opcodes.IUSHR);
                break;
            case Opcodes.INEG: {
                int s = pop();
                int d = push();
                // NEG: dst = 0 - src
                asm.emit_ldi(tmp0(), 0);
                asm.emit_sub32(d, tmp0(), s);
                break;
            }

            /* ── 64-bit arithmetic ── */
            case Opcodes.LADD: {
                int b = pop();
                int a = pop();
                int d = pushLong();
                asm.emit_add64(d, a, b);
                break;
            }
            case Opcodes.LMUL: {
                int b = pop();
                int a = pop();
                int d = pushLong();
                asm.emit_mul64(d, a, b);
                break;
            }
            case Opcodes.LXOR: {
                int b = pop();
                int a = pop();
                int d = pushLong();
                asm.emit_xor64(d, a, b);
                break;
            }
            case Opcodes.LUSHR: {
                int b = pop();
                int a = pop();
                int d = pushLong();
                asm.emit_shr64(d, a, b);
                break;
            }

            /* ── conversions ── */
            case Opcodes.I2L: {
                int s = pop();
                int d = pushLong();
                asm.emit_sext32(d, s);
                break;
            }
            case Opcodes.L2I: {
                int s = pop();
                int d = push();
                // truncate: keep low 32, zero-extend → 32-bit AND with 0xFFFFFFFF
                asm.emit_ldi(tmp0(), -1);   // 0xFFFFFFFF
                asm.emit_and32(d, s, tmp0());
                break;
            }
            case Opcodes.I2B: {
                int s = pop();
                int d = push();
                asm.emit_sext8(d, s);
                break;
            }

            /* ── stack manipulation ── */
            case Opcodes.DUP: {
                int top = peek();
                int r = push();
                asm.emit_mov(r, top);
                break;
            }
            case Opcodes.DUP2: {
                if (peekSize() == 2) {
                    // duplicate one cat-2 value
                    int top = peek();
                    int r = pushLong();
                    asm.emit_mov(r, top);
                } else {
                    // duplicate two cat-1 values: [a b] -> [a b a b]
                    int b = regAtDepth(curDepth() - 1);
                    int a = regAtDepth(curDepth() - 2);
                    int ra = push();
                    asm.emit_mov(ra, a);
                    int rb = push();
                    asm.emit_mov(rb, b);
                }
                break;
            }
            case Opcodes.POP:
                pop();
                break;
            case Opcodes.POP2: {
                if (peekSize() == 2) pop();
                else {
                    pop();
                    pop();
                }
                break;
            }

            /* ── fields ── */
            case Opcodes.GETFIELD: {
                FieldInsnNode fi = (FieldInsnNode) insn;
                int ref = pop();
                int dst;
                int off = stateFieldOffset(fi.name);
                switch (fi.desc) {
                    case "I" -> {
                        dst = push();
                        asm.emit_ldw(dst, ref, off);
                    }
                    case "J" -> {
                        dst = pushLong();
                        asm.emit_ldq(dst, ref, off);
                    }
                    case "[I", "[B" -> {
                        // push (ref + off) as the "array address"
                        dst = push();
                        asm.emit_ldi(tmp0(), off);
                        asm.emit_add32(dst, ref, tmp0());
                    }
                    default -> throw new UnsupportedOperationException("GETFIELD desc=" + fi.desc);
                }
                break;
            }
            case Opcodes.PUTFIELD: {
                FieldInsnNode fi = (FieldInsnNode) insn;
                int val = pop();
                int ref = pop();
                int off = stateFieldOffset(fi.name);
                switch (fi.desc) {
                    case "I" -> asm.emit_stw(ref, off, val);
                    case "J" -> asm.emit_stq(ref, off, val);
                    default -> throw new UnsupportedOperationException("PUTFIELD desc=" + fi.desc);
                }
                break;
            }
            case Opcodes.GETSTATIC: {
                FieldInsnNode fi = (FieldInsnNode) insn;
                int dst = push();
                if (HYDRA_OWNER.equals(fi.owner) && "HYDRA_SBOX".equals(fi.name)) {
                    asm.emit_ldi(dst, MemoryLayout.SBOX_BASE);
                } else if (HYDRA_OWNER.equals(fi.owner) && "HYDRA_PHI".equals(fi.name)) {
                    asm.emit_ldi(dst, MemoryLayout.PHI_BASE);
                } else if (HYDRA_OWNER.equals(fi.owner)) {
                    // Public final int constants like HYDRA_KEY_SIZE — load their values.
                    Object val = staticIntValue(fi.name);
                    if (val instanceof Integer iv) asm.emit_ldi(dst, iv);
                    else throw new UnsupportedOperationException("GETSTATIC " + fi.name);
                } else {
                    throw new UnsupportedOperationException("GETSTATIC " + fi.owner + "." + fi.name);
                }
                break;
            }

            /* ── arrays ── */
            case Opcodes.NEWARRAY: {
                pop();   // size — compile-time known, ignored at runtime
                int dst = push();
                int off = scratchOffsets.get(insn);
                asm.emit_ldi(dst, MemoryLayout.SCRATCH_BASE + off);
                break;
            }
            case Opcodes.IALOAD: {
                int idx = pop();
                int arr = pop();
                int dst = push();
                // addr = arr + idx*4 ; load word
                asm.emit_ldi(tmp0(), 2);
                asm.emit_shl32(tmp1(), idx, tmp0());
                asm.emit_add32(tmp2(), arr, tmp1());
                asm.emit_ldw(dst, tmp2(), 0);
                break;
            }
            case Opcodes.IASTORE: {
                int val = pop();
                int idx = pop();
                int arr = pop();
                asm.emit_ldi(tmp0(), 2);
                asm.emit_shl32(tmp1(), idx, tmp0());
                asm.emit_add32(tmp2(), arr, tmp1());
                asm.emit_stw(tmp2(), 0, val);
                break;
            }
            case Opcodes.BALOAD: {
                int idx = pop();
                int arr = pop();
                int dst = push();
                asm.emit_add32(tmp0(), arr, idx);
                asm.emit_ldbs(dst, tmp0(), 0);
                break;
            }
            case Opcodes.BASTORE: {
                int val = pop();
                int idx = pop();
                int arr = pop();
                asm.emit_add32(tmp0(), arr, idx);
                asm.emit_stb(tmp0(), 0, val);
                break;
            }

            /* ── control flow ── */
            case Opcodes.GOTO: {
                JumpInsnNode jin = (JumpInsnNode) insn;
                LabelNode tgt = jin.label;
                recordLabelStack(tgt);
                asm.emit_jmp(vmLabel(tgt));
                reachable = false;
                break;
            }
            case Opcodes.IFEQ: {
                int a = pop();
                JumpInsnNode jin = (JumpInsnNode) insn;
                recordLabelStack(jin.label);
                asm.emit_jz32(a, vmLabel(jin.label));
                break;
            }
            case Opcodes.IFNE: {
                int a = pop();
                JumpInsnNode jin = (JumpInsnNode) insn;
                recordLabelStack(jin.label);
                asm.emit_jnz32(a, vmLabel(jin.label));
                break;
            }
            case Opcodes.IFLT: {
                int a = pop();
                JumpInsnNode jin = (JumpInsnNode) insn;
                recordLabelStack(jin.label);
                asm.emit_ldi(tmp0(), 0);
                asm.emit_jlt32(a, tmp0(), vmLabel(jin.label));
                break;
            }
            case Opcodes.IFGE: {
                int a = pop();
                JumpInsnNode jin = (JumpInsnNode) insn;
                recordLabelStack(jin.label);
                asm.emit_ldi(tmp0(), 0);
                asm.emit_jge32(a, tmp0(), vmLabel(jin.label));
                break;
            }
            case Opcodes.IFGT: {
                int a = pop();
                JumpInsnNode jin = (JumpInsnNode) insn;
                recordLabelStack(jin.label);
                asm.emit_ldi(tmp0(), 0);
                asm.emit_jgt32(a, tmp0(), vmLabel(jin.label));
                break;
            }
            case Opcodes.IFLE: {
                int a = pop();
                JumpInsnNode jin = (JumpInsnNode) insn;
                recordLabelStack(jin.label);
                asm.emit_ldi(tmp0(), 0);
                asm.emit_jle32(a, tmp0(), vmLabel(jin.label));
                break;
            }
            case Opcodes.IF_ICMPEQ:
            case Opcodes.IF_ICMPNE:
            case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE:
            case Opcodes.IF_ICMPGT:
            case Opcodes.IF_ICMPLE: {
                int b = pop();
                int a = pop();
                JumpInsnNode jin = (JumpInsnNode) insn;
                recordLabelStack(jin.label);
                Label vlbl = vmLabel(jin.label);
                switch (op) {
                    case Opcodes.IF_ICMPEQ -> asm.emit_jeq32(a, b, vlbl);
                    case Opcodes.IF_ICMPNE -> asm.emit_jne32(a, b, vlbl);
                    case Opcodes.IF_ICMPLT -> asm.emit_jlt32(a, b, vlbl);
                    case Opcodes.IF_ICMPGE -> asm.emit_jge32(a, b, vlbl);
                    case Opcodes.IF_ICMPGT -> asm.emit_jgt32(a, b, vlbl);
                    case Opcodes.IF_ICMPLE -> asm.emit_jle32(a, b, vlbl);
                }
                break;
            }
            case Opcodes.TABLESWITCH: {
                TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
                int key = pop();
                // chain compares
                for (int i = 0; i < ts.labels.size(); i++) {
                    int caseVal = ts.min + i;
                    LabelNode caseLbl = ts.labels.get(i);
                    recordLabelStack(caseLbl);
                    asm.emit_ldi(tmp0(), caseVal);
                    asm.emit_jeq32(key, tmp0(), vmLabel(caseLbl));
                }
                recordLabelStack(ts.dflt);
                asm.emit_jmp(vmLabel(ts.dflt));
                reachable = false;
                break;
            }
            case Opcodes.LOOKUPSWITCH: {
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                int key = pop();
                for (int i = 0; i < ls.keys.size(); i++) {
                    int caseVal = ls.keys.get(i);
                    LabelNode caseLbl = ls.labels.get(i);
                    recordLabelStack(caseLbl);
                    asm.emit_ldi(tmp0(), caseVal);
                    asm.emit_jeq32(key, tmp0(), vmLabel(caseLbl));
                }
                recordLabelStack(ls.dflt);
                asm.emit_jmp(vmLabel(ls.dflt));
                reachable = false;
                break;
            }
            case Opcodes.RETURN: {
                asm.emit_ret();
                reachable = false;
                break;
            }

            default:
                throw new UnsupportedOperationException(
                        "opcode 0x" + Integer.toHexString(op) + " in " + m.name + " (" + insn.getClass().getSimpleName() + ")");
        }
    }

    /* ── helpers ── */

    private void alu32(int jvmOp) {
        int b = pop();
        int a = pop();
        int d = push();
        switch (jvmOp) {
            case Opcodes.IADD -> asm.emit_add32(d, a, b);
            case Opcodes.ISUB -> asm.emit_sub32(d, a, b);
            case Opcodes.IMUL -> asm.emit_mul32(d, a, b);
            case Opcodes.IREM -> asm.emit_rem32(d, a, b);
            case Opcodes.IAND -> asm.emit_and32(d, a, b);
            case Opcodes.IOR -> asm.emit_or32(d, a, b);
            case Opcodes.IXOR -> asm.emit_xor32(d, a, b);
            case Opcodes.ISHL -> asm.emit_shl32(d, a, b);
            case Opcodes.IUSHR -> asm.emit_shr32(d, a, b);
            default -> throw new IllegalArgumentException(Integer.toHexString(jvmOp));
        }
    }

    private void recordLabelStack(LabelNode ln) {
        if (!stackAtLabel.containsKey(ln)) {
            stackAtLabel.put(ln, new ArrayList<>(stackSizes));
        }
    }

    private int newarraySize(AbstractInsnNode insn) {
        // The size operand was pushed by some preceding instruction(s). Use the
        // SourceInterpreter frame at this site to find the producer and read
        // its constant.
        int idx = m.instructions.indexOf(insn);
        Frame<SourceValue> f = sourceFrames[idx];
        if (f == null) throw new IllegalStateException("dead newarray site");
        SourceValue sv = f.getStack(f.getStackSize() - 1);
        Integer constant = null;
        for (AbstractInsnNode src : sv.insns) {
            Integer v = constIntFrom(src);
            if (v == null) return -1;
            if (constant == null) constant = v;
            else if (!constant.equals(v)) return -1;
        }
        if (constant == null) {
            throw new IllegalStateException("NEWARRAY size has no producers in " + m.name);
        }
        return constant;
    }

    private Integer constIntFrom(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return op - Opcodes.ICONST_0;
        if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) return ((IntInsnNode) insn).operand;
        if (op == Opcodes.LDC) {
            Object cst = ((LdcInsnNode) insn).cst;
            if (cst instanceof Integer i) return i;
        }
        return null;
    }

    private Object staticIntValue(String fieldName) {
        try {
            java.lang.reflect.Field f = com.bytenya.zcipher.HydraStream.class.getDeclaredField(fieldName);
            f.setAccessible(true);
            return f.get(null);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    public int totalScratchSize() {
        return scratchSize;
    }

    public record CompiledMethod(String name, String desc, byte[] bytecode, int scratchSize, int regCount,
                                 int argRegs) {
    }
}