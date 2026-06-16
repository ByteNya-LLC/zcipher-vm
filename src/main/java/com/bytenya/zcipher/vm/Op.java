package com.bytenya.zcipher.vm;

/*
 * ZCipher VM opcode table.
 *
 * Encoding: [opcode:1][operands...]. Operand widths are fixed per opcode:
 *   r2 = 16-bit little-endian register id
 *   i2 = 16-bit signed little-endian immediate
 *   i4 = 32-bit signed little-endian immediate
 *   i8 = 64-bit signed little-endian immediate
 *
 * Branch targets are absolute byte offsets into the bytecode.
 * Registers are unified 64-bit. 32-bit ALU ops zero the high half of dst.
 */
public final class Op {
    /* move / immediates */
    public static final int MOV = 0x01;  // dst src
    public static final int LDI = 0x02;  // dst imm32 (sign-ext to 64)
    public static final int LDIQ = 0x03;  // dst imm64
    /* 32-bit ALU */
    public static final int ADD32 = 0x10;
    public static final int SUB32 = 0x11;
    public static final int MUL32 = 0x12;
    public static final int REM32 = 0x13;  // signed
    public static final int AND32 = 0x14;
    public static final int OR32 = 0x15;
    public static final int XOR32 = 0x16;
    public static final int SHL32 = 0x17;
    public static final int SHR32 = 0x18;  // logical right
    public static final int ROL32 = 0x19;
    public static final int ROR32 = 0x1A;
    /* 64-bit ALU */
    public static final int ADD64 = 0x20;
    public static final int MUL64 = 0x21;
    public static final int SHR64 = 0x22;
    public static final int XOR64 = 0x23;
    /* sign-extend */
    public static final int SEXT8 = 0x30;  // i2b
    public static final int SEXT32 = 0x31;  // i2l
    /* memory (little-endian) */
    public static final int LDB = 0x40;  // unsigned byte
    public static final int LDBS = 0x41;  // signed byte (BALOAD)
    public static final int STB = 0x42;
    public static final int LDW = 0x43;  // 32-bit, zero-ext
    public static final int STW = 0x44;
    public static final int LDQ = 0x45;  // 64-bit
    public static final int STQ = 0x46;
    /* specialized cipher op */
    public static final int SBOX = 0x50;  // dst word selector
    /* branches */
    public static final int JMP = 0x60;  // target
    public static final int JZ32 = 0x61;
    public static final int JNZ32 = 0x62;
    public static final int JEQ32 = 0x63;
    public static final int JNE32 = 0x64;
    public static final int JLT32 = 0x65;  // signed
    public static final int JGE32 = 0x66;
    public static final int JGT32 = 0x67;
    public static final int JLE32 = 0x68;
    public static final int JLTU32 = 0x69;  // unsigned
    public static final int JGEU32 = 0x6A;
    public static final int JGTU32 = 0x6B;
    public static final int JLEU32 = 0x6C;
    /* control */
    public static final int RET = 0x70;

    private Op() {
    }

    /* Encoded instruction sizes (in bytes), keyed by opcode. */
    public static int size(int op) {
        return switch (op) {
            case MOV -> 1 + 2 + 2;
            case LDI -> 1 + 2 + 4;
            case LDIQ -> 1 + 2 + 8;

            case ADD32, SUB32, MUL32, REM32, AND32, OR32, XOR32,
                 SHL32, SHR32, ROL32, ROR32,
                 ADD64, MUL64, SHR64, XOR64,
                 SBOX -> 1 + 2 + 2 + 2;

            case SEXT8, SEXT32 -> 1 + 2 + 2;

            case LDB, LDBS, LDW, LDQ -> 1 + 2 + 2 + 2;
            case STB, STW, STQ -> 1 + 2 + 2 + 2;

            case JMP -> 1 + 4;
            case JZ32, JNZ32 -> 1 + 2 + 4;
            case JEQ32, JNE32, JLT32, JGE32, JGT32, JLE32,
                 JLTU32, JGEU32, JGTU32, JLEU32 -> 1 + 2 + 2 + 4;

            case RET -> 1;

            default -> throw new IllegalArgumentException("unknown opcode 0x" + Integer.toHexString(op));
        };
    }

    public static String name(int op) {
        return switch (op) {
            case MOV -> "MOV";
            case LDI -> "LDI";
            case LDIQ -> "LDIQ";
            case ADD32 -> "ADD32";
            case SUB32 -> "SUB32";
            case MUL32 -> "MUL32";
            case REM32 -> "REM32";
            case AND32 -> "AND32";
            case OR32 -> "OR32";
            case XOR32 -> "XOR32";
            case SHL32 -> "SHL32";
            case SHR32 -> "SHR32";
            case ROL32 -> "ROL32";
            case ROR32 -> "ROR32";
            case ADD64 -> "ADD64";
            case MUL64 -> "MUL64";
            case SHR64 -> "SHR64";
            case XOR64 -> "XOR64";
            case SEXT8 -> "SEXT8";
            case SEXT32 -> "SEXT32";
            case LDB -> "LDB";
            case LDBS -> "LDBS";
            case STB -> "STB";
            case LDW -> "LDW";
            case STW -> "STW";
            case LDQ -> "LDQ";
            case STQ -> "STQ";
            case SBOX -> "SBOX";
            case JMP -> "JMP";
            case JZ32 -> "JZ32";
            case JNZ32 -> "JNZ32";
            case JEQ32 -> "JEQ32";
            case JNE32 -> "JNE32";
            case JLT32 -> "JLT32";
            case JGE32 -> "JGE32";
            case JGT32 -> "JGT32";
            case JLE32 -> "JLE32";
            case JLTU32 -> "JLTU32";
            case JGEU32 -> "JGEU32";
            case JGTU32 -> "JGTU32";
            case JLEU32 -> "JLEU32";
            case RET -> "RET";
            default -> "OP_" + Integer.toHexString(op);
        };
    }
}