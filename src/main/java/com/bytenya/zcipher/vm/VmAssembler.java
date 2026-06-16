package com.bytenya.zcipher.vm;

import java.util.ArrayList;
import java.util.List;

/*
 * Assembler for the ZCipher VM. Each emit_* method writes one fully-formed
 * instruction into the buffer. Branch targets use Label objects: the target
 * address is patched in once mark(label) records the position.
 *
 * All multi-byte fields are little-endian. Register ids are 16-bit unsigned.
 */
public final class VmAssembler {

    private byte[] buf = new byte[256];
    private int pos = 0;

    public int pos() {
        return pos;
    }

    public Label newLabel() {
        return new Label();
    }

    public void mark(Label l) {
        if (l.pos != -1) throw new IllegalStateException("label already marked");
        l.pos = pos;
        for (int site : l.patchSites) {
            patchInt(site, pos);
        }
        l.patchSites.clear();
    }

    private void ensure(int n) {
        if (pos + n > buf.length) {
            int newLen = Math.max(buf.length * 2, pos + n);
            byte[] nb = new byte[newLen];
            System.arraycopy(buf, 0, nb, 0, pos);
            buf = nb;
        }
    }

    private void writeByte(int v) {
        ensure(1);
        buf[pos++] = (byte) v;
    }

    private void writeShort(int v) {
        ensure(2);
        buf[pos++] = (byte) v;
        buf[pos++] = (byte) (v >>> 8);
    }

    private void writeReg(int r) {
        if (r < 0 || r > 0xFFFF) throw new IllegalArgumentException("reg out of range: " + r);
        writeShort(r);
    }

    private void writeInt(int v) {
        ensure(4);
        buf[pos++] = (byte) v;
        buf[pos++] = (byte) (v >>> 8);
        buf[pos++] = (byte) (v >>> 16);
        buf[pos++] = (byte) (v >>> 24);
    }

    private void writeLong(long v) {
        ensure(8);
        for (int i = 0; i < 8; i++) buf[pos++] = (byte) (v >>> (i * 8));
    }

    private void patchInt(int at, int v) {
        buf[at] = (byte) v;
        buf[at + 1] = (byte) (v >>> 8);
        buf[at + 2] = (byte) (v >>> 16);
        buf[at + 3] = (byte) (v >>> 24);
    }

    private void writeBranchTarget(Label l) {
        if (l.pos != -1) {
            writeInt(l.pos);
        } else {
            l.patchSites.add(pos);
            writeInt(0);
        }
    }

    public void emit_mov(int dst, int src) {
        writeByte(Op.MOV);
        writeReg(dst);
        writeReg(src);
    }

    /* ── emit one instruction per method ── */

    public void emit_ldi(int dst, int imm32) {
        writeByte(Op.LDI);
        writeReg(dst);
        writeInt(imm32);
    }

    public void emit_ldiq(int dst, long imm64) {
        writeByte(Op.LDIQ);
        writeReg(dst);
        writeLong(imm64);
    }

    private void emit_alu3(int op, int dst, int a, int b) {
        writeByte(op);
        writeReg(dst);
        writeReg(a);
        writeReg(b);
    }

    public void emit_add32(int d, int a, int b) {
        emit_alu3(Op.ADD32, d, a, b);
    }

    public void emit_sub32(int d, int a, int b) {
        emit_alu3(Op.SUB32, d, a, b);
    }

    public void emit_mul32(int d, int a, int b) {
        emit_alu3(Op.MUL32, d, a, b);
    }

    public void emit_rem32(int d, int a, int b) {
        emit_alu3(Op.REM32, d, a, b);
    }

    public void emit_and32(int d, int a, int b) {
        emit_alu3(Op.AND32, d, a, b);
    }

    public void emit_or32(int d, int a, int b) {
        emit_alu3(Op.OR32, d, a, b);
    }

    public void emit_xor32(int d, int a, int b) {
        emit_alu3(Op.XOR32, d, a, b);
    }

    public void emit_shl32(int d, int a, int s) {
        emit_alu3(Op.SHL32, d, a, s);
    }

    public void emit_shr32(int d, int a, int s) {
        emit_alu3(Op.SHR32, d, a, s);
    }

    public void emit_rol32(int d, int a, int s) {
        emit_alu3(Op.ROL32, d, a, s);
    }

    public void emit_ror32(int d, int a, int s) {
        emit_alu3(Op.ROR32, d, a, s);
    }

    public void emit_add64(int d, int a, int b) {
        emit_alu3(Op.ADD64, d, a, b);
    }

    public void emit_mul64(int d, int a, int b) {
        emit_alu3(Op.MUL64, d, a, b);
    }

    public void emit_shr64(int d, int a, int s) {
        emit_alu3(Op.SHR64, d, a, s);
    }

    public void emit_xor64(int d, int a, int b) {
        emit_alu3(Op.XOR64, d, a, b);
    }

    public void emit_sext8(int d, int s) {
        writeByte(Op.SEXT8);
        writeReg(d);
        writeReg(s);
    }

    public void emit_sext32(int d, int s) {
        writeByte(Op.SEXT32);
        writeReg(d);
        writeReg(s);
    }

    private void writeImm16(int v) {
        if (v < Short.MIN_VALUE || v > Short.MAX_VALUE)
            throw new IllegalArgumentException("imm16 out of range: " + v);
        writeShort(v & 0xFFFF);
    }

    private void emit_load(int op, int dst, int base, int off) {
        writeByte(op);
        writeReg(dst);
        writeReg(base);
        writeImm16(off);
    }

    private void emit_store(int op, int base, int off, int src) {
        writeByte(op);
        writeReg(base);
        writeImm16(off);
        writeReg(src);
    }

    public void emit_ldb(int dst, int base, int off) {
        emit_load(Op.LDB, dst, base, off);
    }

    public void emit_ldbs(int dst, int base, int off) {
        emit_load(Op.LDBS, dst, base, off);
    }

    public void emit_stb(int base, int off, int src) {
        emit_store(Op.STB, base, off, src);
    }

    public void emit_ldw(int dst, int base, int off) {
        emit_load(Op.LDW, dst, base, off);
    }

    public void emit_stw(int base, int off, int src) {
        emit_store(Op.STW, base, off, src);
    }

    public void emit_ldq(int dst, int base, int off) {
        emit_load(Op.LDQ, dst, base, off);
    }

    public void emit_stq(int base, int off, int src) {
        emit_store(Op.STQ, base, off, src);
    }

    public void emit_sbox(int dst, int word, int sel) {
        writeByte(Op.SBOX);
        writeReg(dst);
        writeReg(word);
        writeReg(sel);
    }

    public void emit_jmp(Label target) {
        writeByte(Op.JMP);
        writeBranchTarget(target);
    }

    private void emit_jcc1(int op, int a, Label target) {
        writeByte(op);
        writeReg(a);
        writeBranchTarget(target);
    }

    private void emit_jcc2(int op, int a, int b, Label target) {
        writeByte(op);
        writeReg(a);
        writeReg(b);
        writeBranchTarget(target);
    }

    public void emit_jz32(int a, Label t) {
        emit_jcc1(Op.JZ32, a, t);
    }

    public void emit_jnz32(int a, Label t) {
        emit_jcc1(Op.JNZ32, a, t);
    }

    public void emit_jeq32(int a, int b, Label t) {
        emit_jcc2(Op.JEQ32, a, b, t);
    }

    public void emit_jne32(int a, int b, Label t) {
        emit_jcc2(Op.JNE32, a, b, t);
    }

    public void emit_jlt32(int a, int b, Label t) {
        emit_jcc2(Op.JLT32, a, b, t);
    }

    public void emit_jge32(int a, int b, Label t) {
        emit_jcc2(Op.JGE32, a, b, t);
    }

    public void emit_jgt32(int a, int b, Label t) {
        emit_jcc2(Op.JGT32, a, b, t);
    }

    public void emit_jle32(int a, int b, Label t) {
        emit_jcc2(Op.JLE32, a, b, t);
    }

    public void emit_jltu32(int a, int b, Label t) {
        emit_jcc2(Op.JLTU32, a, b, t);
    }

    public void emit_jgeu32(int a, int b, Label t) {
        emit_jcc2(Op.JGEU32, a, b, t);
    }

    public void emit_jgtu32(int a, int b, Label t) {
        emit_jcc2(Op.JGTU32, a, b, t);
    }

    public void emit_jleu32(int a, int b, Label t) {
        emit_jcc2(Op.JLEU32, a, b, t);
    }

    public void emit_ret() {
        writeByte(Op.RET);
    }

    public byte[] toBytecode() {
        byte[] out = new byte[pos];
        System.arraycopy(buf, 0, out, 0, pos);
        return out;
    }

    public static final class Label {
        final List<Integer> patchSites = new ArrayList<>();   // 4-byte slots that need the address
        public int pos = -1;             // resolved byte offset, or -1 if unresolved
    }
}