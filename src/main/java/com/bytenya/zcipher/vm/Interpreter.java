package com.bytenya.zcipher.vm;

/*
 * ZCipher VM interpreter.
 *
 * State:
 *   regs   long[]   — 64-bit unified register file
 *   mem    byte[]   — flat byte memory (state + constants + scratch + io)
 *   code   byte[]   — bytecode
 *   pc     int      — instruction pointer (byte offset into code)
 *
 * Calling convention:
 *   The host pre-loads argument registers and the constant region of memory,
 *   then calls run(...). The bytecode terminates with RET.
 */
public final class Interpreter {

    public static void run(byte[] code, long[] regs, byte[] mem) {
        int pc = 0;
        for (; ; ) {
            int op = code[pc] & 0xFF;
            switch (op) {
                case Op.MOV: {
                    int dst = u16(code, pc + 1);
                    int src = u16(code, pc + 3);
                    regs[dst] = regs[src];
                    pc += 5;
                    break;
                }
                case Op.LDI: {
                    int dst = u16(code, pc + 1);
                    int imm = i32(code, pc + 3);
                    regs[dst] = imm; // sign-extend
                    pc += 7;
                    break;
                }
                case Op.LDIQ: {
                    int dst = u16(code, pc + 1);
                    long imm = i64(code, pc + 3);
                    regs[dst] = imm;
                    pc += 11;
                    break;
                }

                case Op.ADD32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    regs[d] = ((regs[a] + regs[b]) & 0xFFFFFFFFL);
                    pc += 7;
                    break;
                }
                case Op.SUB32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    regs[d] = ((regs[a] - regs[b]) & 0xFFFFFFFFL);
                    pc += 7;
                    break;
                }
                case Op.MUL32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    int r = ((int) regs[a]) * ((int) regs[b]);
                    regs[d] = ((long) r) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }
                case Op.REM32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    int r = ((int) regs[a]) % ((int) regs[b]);
                    regs[d] = ((long) r) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }
                case Op.AND32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    regs[d] = (regs[a] & regs[b]) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }
                case Op.OR32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    regs[d] = (regs[a] | regs[b]) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }
                case Op.XOR32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    regs[d] = (regs[a] ^ regs[b]) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }
                case Op.SHL32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), s = u16(code, pc + 5);
                    int sh = (int) (regs[s] & 0x1F);
                    regs[d] = ((regs[a] & 0xFFFFFFFFL) << sh) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }
                case Op.SHR32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), s = u16(code, pc + 5);
                    int sh = (int) (regs[s] & 0x1F);
                    regs[d] = (regs[a] & 0xFFFFFFFFL) >>> sh;
                    pc += 7;
                    break;
                }
                case Op.ROL32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), s = u16(code, pc + 5);
                    int sh = (int) (regs[s] & 0x1F);
                    long v = regs[a] & 0xFFFFFFFFL;
                    regs[d] = sh == 0 ? v : ((v << sh) | (v >>> (32 - sh))) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }
                case Op.ROR32: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), s = u16(code, pc + 5);
                    int sh = (int) (regs[s] & 0x1F);
                    long v = regs[a] & 0xFFFFFFFFL;
                    regs[d] = sh == 0 ? v : ((v >>> sh) | (v << (32 - sh))) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }

                case Op.ADD64: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    regs[d] = regs[a] + regs[b];
                    pc += 7;
                    break;
                }
                case Op.MUL64: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    regs[d] = regs[a] * regs[b];
                    pc += 7;
                    break;
                }
                case Op.SHR64: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), s = u16(code, pc + 5);
                    int sh = (int) (regs[s] & 0x3F);
                    regs[d] = regs[a] >>> sh;
                    pc += 7;
                    break;
                }
                case Op.XOR64: {
                    int d = u16(code, pc + 1), a = u16(code, pc + 3), b = u16(code, pc + 5);
                    regs[d] = regs[a] ^ regs[b];
                    pc += 7;
                    break;
                }

                case Op.SEXT8: {
                    int d = u16(code, pc + 1), s = u16(code, pc + 3);
                    regs[d] = (byte) regs[s];
                    pc += 5;
                    break;
                }
                case Op.SEXT32: {
                    int d = u16(code, pc + 1), s = u16(code, pc + 3);
                    regs[d] = (int) regs[s];
                    pc += 5;
                    break;
                }

                case Op.LDB: {
                    int d = u16(code, pc + 1), base = u16(code, pc + 3), off = i16(code, pc + 5);
                    int addr = (int) regs[base] + off;
                    regs[d] = mem[addr] & 0xFFL;
                    pc += 7;
                    break;
                }
                case Op.LDBS: {
                    int d = u16(code, pc + 1), base = u16(code, pc + 3), off = i16(code, pc + 5);
                    int addr = (int) regs[base] + off;
                    regs[d] = mem[addr];
                    pc += 7;
                    break;
                }
                case Op.STB: {
                    int base = u16(code, pc + 1), off = i16(code, pc + 3), src = u16(code, pc + 5);
                    int addr = (int) regs[base] + off;
                    mem[addr] = (byte) regs[src];
                    pc += 7;
                    break;
                }
                case Op.LDW: {
                    int d = u16(code, pc + 1), base = u16(code, pc + 3), off = i16(code, pc + 5);
                    int addr = (int) regs[base] + off;
                    regs[d] = ((long) MemoryLayout.readWord(mem, addr)) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }
                case Op.STW: {
                    int base = u16(code, pc + 1), off = i16(code, pc + 3), src = u16(code, pc + 5);
                    int addr = (int) regs[base] + off;
                    MemoryLayout.writeWord(mem, addr, (int) regs[src]);
                    pc += 7;
                    break;
                }
                case Op.LDQ: {
                    int d = u16(code, pc + 1), base = u16(code, pc + 3), off = i16(code, pc + 5);
                    int addr = (int) regs[base] + off;
                    regs[d] = MemoryLayout.readLong(mem, addr);
                    pc += 7;
                    break;
                }
                case Op.STQ: {
                    int base = u16(code, pc + 1), off = i16(code, pc + 3), src = u16(code, pc + 5);
                    int addr = (int) regs[base] + off;
                    MemoryLayout.writeLong(mem, addr, regs[src]);
                    pc += 7;
                    break;
                }

                case Op.SBOX: {
                    int d = u16(code, pc + 1), w = u16(code, pc + 3), s = u16(code, pc + 5);
                    long word = regs[w];
                    long sel = regs[s];
                    int b0 = (int) (word & 0xFF);
                    int b1 = (int) ((word >>> 8) & 0xFF);
                    int b2 = (int) ((word >>> 16) & 0xFF);
                    int b3 = (int) ((word >>> 24) & 0xFF);
                    int s0 = (int) (sel & 0x03);
                    int s1 = (int) ((sel >>> 2) & 0x03);
                    int s2 = (int) ((sel >>> 4) & 0x03);
                    int s3 = (int) ((sel >>> 6) & 0x03);
                    if (s0 == s2) {
                        b0 = sboxByte(mem, (s0 << 8) | sboxByte(mem, (s1 << 8) | b0));
                        b2 = sboxByte(mem, (s2 << 8) | sboxByte(mem, (s3 << 8) | b2));
                    } else {
                        b0 = sboxByte(mem, (s0 << 8) | b0);
                        b2 = sboxByte(mem, (s2 << 8) | b2);
                    }
                    if (s1 == s3) {
                        b1 = sboxByte(mem, (s3 << 8) | sboxByte(mem, (s0 << 8) | b1));
                        b3 = sboxByte(mem, (s1 << 8) | sboxByte(mem, (s2 << 8) | b3));
                    } else {
                        b1 = sboxByte(mem, (s1 << 8) | b1);
                        b3 = sboxByte(mem, (s3 << 8) | b3);
                    }
                    int result = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
                    regs[d] = ((long) result) & 0xFFFFFFFFL;
                    pc += 7;
                    break;
                }

                case Op.JMP: {
                    pc = i32(code, pc + 1);
                    break;
                }
                case Op.JZ32: {
                    int a = u16(code, pc + 1);
                    int target = i32(code, pc + 3);
                    if ((int) regs[a] == 0) pc = target;
                    else pc += 7;
                    break;
                }
                case Op.JNZ32: {
                    int a = u16(code, pc + 1);
                    int target = i32(code, pc + 3);
                    if ((int) regs[a] != 0) pc = target;
                    else pc += 7;
                    break;
                }
                case Op.JEQ32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if ((int) regs[a] == (int) regs[b]) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JNE32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if ((int) regs[a] != (int) regs[b]) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JLT32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if ((int) regs[a] < (int) regs[b]) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JGE32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if ((int) regs[a] >= (int) regs[b]) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JGT32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if ((int) regs[a] > (int) regs[b]) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JLE32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if ((int) regs[a] <= (int) regs[b]) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JLTU32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if (Integer.compareUnsigned((int) regs[a], (int) regs[b]) < 0) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JGEU32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if (Integer.compareUnsigned((int) regs[a], (int) regs[b]) >= 0) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JGTU32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if (Integer.compareUnsigned((int) regs[a], (int) regs[b]) > 0) pc = target;
                    else pc += 9;
                    break;
                }
                case Op.JLEU32: {
                    int a = u16(code, pc + 1), b = u16(code, pc + 3);
                    int target = i32(code, pc + 5);
                    if (Integer.compareUnsigned((int) regs[a], (int) regs[b]) <= 0) pc = target;
                    else pc += 9;
                    break;
                }

                case Op.RET:
                    return;

                default:
                    throw new IllegalStateException(
                            "bad opcode 0x" + Integer.toHexString(op) + " @ pc=" + pc);
            }
        }
    }

    private static int sboxByte(byte[] mem, int idx) {
        return mem[MemoryLayout.SBOX_BASE + idx * 4] & 0xFF;
    }

    private static int u16(byte[] a, int off) {
        return (a[off] & 0xFF) | ((a[off + 1] & 0xFF) << 8);
    }

    private static int i16(byte[] a, int off) {
        return (short) ((a[off] & 0xFF) | ((a[off + 1] & 0xFF) << 8));
    }

    private static int i32(byte[] a, int off) {
        return (a[off] & 0xFF) | ((a[off + 1] & 0xFF) << 8) | ((a[off + 2] & 0xFF) << 16) | ((a[off + 3] & 0xFF) << 24);
    }

    private static long i64(byte[] a, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v |= ((long) a[off + i] & 0xFFL) << (i * 8);
        return v;
    }
}