package com.bytenya.zcipher;

/*
 * HydraStream Cipher v1.0 - Java port (no Java standard library).
 * ================================================================
 * Direct translation of hydra_stream.h. Uses only language built-ins:
 * primitives, arrays, control flow, classes. No imports, no library
 * function calls (no Math/System/String/Arrays/Integer/etc.).
 *
 * Public API:
 *   HydraStream.State          - cipher state container
 *   HydraStream.hydraInit      - initialize with 32-byte key, 16-byte nonce
 *   HydraStream.hydraCrypt     - encrypt/decrypt (XOR with keystream)
 *   HydraStream.hydraKeystream - generate raw keystream bytes
 *
 * Translation rules applied:
 *   - C uint32_t   -> Java int  (modular wrap-around is identical)
 *   - C uint64_t   -> Java long
 *   - C uint8_t    -> Java byte (with & 0xFF when used as index/value)
 *   - C >> on unsigned -> Java >>> (logical right shift)
 *   - C unsigned compare on full uint32 -> uGreater/uLess helpers below
 *   - C memcpy/memset -> manual loops
 */

public class HydraStream {

    /* Configuration */
    public static final int HYDRA_KEY_SIZE = 32;
    public static final int HYDRA_NONCE_SIZE = 16;
    public static final int HYDRA_LANES = 4;
    public static final int HYDRA_LANE_WORDS = 8;
    public static final int HYDRA_ROUNDS = 12;
    public static final int HYDRA_SBOX_COUNT = 4;
    public static final int HYDRA_BLOCK_BYTES = HYDRA_LANES * HYDRA_LANE_WORDS * 4;

    /* S-Box pool: 4 different 8->8 substitution tables, flattened.
     * Indexed as HYDRA_SBOX[(sboxIdx << 8) | byteValue]. */
    private static final int[] HYDRA_SBOX = {
            /* S-box 0: based on multiplicative inverse in GF(2^8) + affine */
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
            /* S-box 1: bit-reversal + XOR 0xA5 + rotate nibble */
            0xa5, 0x25, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x0d, 0x8d, 0x4d, 0xcd, 0x3d, 0xbd, 0x7d, 0xfd,
            0xa3, 0x23, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x0b, 0x8b, 0x4b, 0xcb, 0x3b, 0xbb, 0x7b, 0xfb,
            0xa9, 0x29, 0x69, 0xe9, 0x19, 0x99, 0x59, 0xd9, 0x01, 0x81, 0x41, 0xc1, 0x31, 0xb1, 0x71, 0xf1,
            0xaf, 0x2f, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf, 0x07, 0x87, 0x47, 0xc7, 0x37, 0xb7, 0x77, 0xf7,
            0xa4, 0x24, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x0c, 0x8c, 0x4c, 0xcc, 0x3c, 0xbc, 0x7c, 0xfc,
            0xa2, 0x22, 0x62, 0xe2, 0x12, 0x92, 0x52, 0xd2, 0x0a, 0x8a, 0x4a, 0xca, 0x3a, 0xba, 0x7a, 0xfa,
            0xa8, 0x28, 0x68, 0xe8, 0x18, 0x98, 0x58, 0xd8, 0x00, 0x80, 0x40, 0xc0, 0x30, 0xb0, 0x70, 0xf0,
            0xae, 0x2e, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x06, 0x86, 0x46, 0xc6, 0x36, 0xb6, 0x76, 0xf6,
            0xa1, 0x21, 0x61, 0xe1, 0x11, 0x91, 0x51, 0xd1, 0x09, 0x89, 0x49, 0xc9, 0x39, 0xb9, 0x79, 0xf9,
            0xa7, 0x27, 0x67, 0xe7, 0x17, 0x97, 0x57, 0xd7, 0x0f, 0x8f, 0x4f, 0xcf, 0x3f, 0xbf, 0x7f, 0xff,
            0xac, 0x2c, 0x6c, 0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x04, 0x84, 0x44, 0xc4, 0x34, 0xb4, 0x74, 0xf4,
            0xaa, 0x2a, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x02, 0x82, 0x42, 0xc2, 0x32, 0xb2, 0x72, 0xf2,
            0xa6, 0x26, 0x66, 0xe6, 0x16, 0x96, 0x56, 0xd6, 0x0e, 0x8e, 0x4e, 0xce, 0x3e, 0xbe, 0x7e, 0xfe,
            0xab, 0x2b, 0x6b, 0xeb, 0x1b, 0x9b, 0x5b, 0xdb, 0x03, 0x83, 0x43, 0xc3, 0x33, 0xb3, 0x73, 0xf3,
            0xad, 0x2d, 0x6d, 0xed, 0x1d, 0x9d, 0x5d, 0xdd, 0x05, 0x85, 0x45, 0xc5, 0x35, 0xb5, 0x75, 0xf5,
            0xa0, 0x20, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x08, 0x88, 0x48, 0xc8, 0x38, 0xb8, 0x78, 0xf8,
            /* S-box 2: polynomial evaluation mod 257, truncated */
            0xd2, 0x3a, 0xe1, 0x58, 0xbf, 0x07, 0x9e, 0x46, 0xc3, 0x1b, 0x82, 0xf9, 0x60, 0xa8, 0x2f, 0x77,
            0x0e, 0xd6, 0x4d, 0xb4, 0x2c, 0x93, 0xeb, 0x52, 0xa0, 0x18, 0x8f, 0xf7, 0x6e, 0xc5, 0x3d, 0x84,
            0xfb, 0x63, 0xca, 0x31, 0xa9, 0x10, 0x88, 0xff, 0x66, 0xce, 0x35, 0x9d, 0x04, 0x7c, 0xe3, 0x4b,
            0xb2, 0x2a, 0x91, 0xe9, 0x50, 0xb8, 0x20, 0x97, 0xef, 0x56, 0xae, 0x15, 0x7d, 0xe4, 0x4c, 0xb3,
            0x1a, 0x81, 0xf8, 0x70, 0xc7, 0x3e, 0x86, 0xfd, 0x64, 0xac, 0x13, 0x8b, 0xf2, 0x6a, 0xc1, 0x38,
            0x90, 0x08, 0x7f, 0xe6, 0x5e, 0xb5, 0x2d, 0x94, 0xec, 0x53, 0xbb, 0x22, 0x8a, 0xf1, 0x69, 0xd0,
            0x47, 0x9f, 0x06, 0x6e, 0xd5, 0x4c, 0xa3, 0x1b, 0x72, 0xda, 0x41, 0xa9, 0x10, 0x78, 0xef, 0x57,
            0xbe, 0x25, 0x8d, 0xf4, 0x5c, 0xc3, 0x3b, 0x92, 0xea, 0x51, 0xb9, 0x21, 0x98, 0x00, 0x67, 0xcf,
            0x36, 0x9e, 0x05, 0x7d, 0xe4, 0x4b, 0xa3, 0x1a, 0x82, 0xe9, 0x50, 0xb8, 0x30, 0x97, 0x0f, 0x76,
            0xde, 0x45, 0xbd, 0x24, 0x8c, 0xf3, 0x5b, 0xc2, 0x29, 0x91, 0x08, 0x80, 0xf7, 0x6f, 0xd6, 0x3e,
            0xa5, 0x0d, 0x74, 0xdc, 0x43, 0xab, 0x12, 0x7a, 0xe1, 0x59, 0xc0, 0x27, 0x8f, 0x16, 0x7e, 0xe5,
            0x4d, 0xb4, 0x2c, 0x83, 0xfb, 0x62, 0xca, 0x31, 0x99, 0x01, 0x68, 0xd0, 0x47, 0xaf, 0x17, 0x8e,
            0xf5, 0x5d, 0xc4, 0x3c, 0xa3, 0x0b, 0x72, 0xea, 0x51, 0xb9, 0x20, 0x88, 0xf0, 0x57, 0xcf, 0x36,
            0x9e, 0x06, 0x7d, 0xe5, 0x4c, 0xa4, 0x1c, 0x83, 0xeb, 0x52, 0xba, 0x21, 0x99, 0x00, 0x78, 0xdf,
            0x47, 0xbe, 0x26, 0x9d, 0xf5, 0x5c, 0xc4, 0x3b, 0x93, 0x0a, 0x81, 0xe9, 0x60, 0xb8, 0x2f, 0x87,
            0xfe, 0x66, 0xcd, 0x34, 0xac, 0x13, 0x7b, 0xe2, 0x5a, 0xc1, 0x28, 0x90, 0x07, 0x6f, 0xd6, 0x4e,
            /* S-box 3: CRC-derived permutation */
            0x48, 0xd1, 0x3a, 0xe7, 0x5c, 0x9f, 0x06, 0xb2, 0x74, 0xc8, 0x1d, 0xaf, 0x63, 0xf5, 0x29, 0x8e,
            0xdb, 0x40, 0xa7, 0x1e, 0x85, 0xf3, 0x6c, 0x2a, 0x9d, 0x51, 0xc6, 0x38, 0xbe, 0x04, 0x7f, 0xe0,
            0x17, 0x8c, 0xf9, 0x62, 0xd5, 0x4b, 0xae, 0x33, 0xc0, 0x5e, 0x94, 0x0a, 0x7d, 0xe8, 0x26, 0xb1,
            0x43, 0xdc, 0xa1, 0x1f, 0x86, 0xf0, 0x6d, 0x2b, 0x9e, 0x52, 0xc7, 0x39, 0xbf, 0x05, 0x70, 0xe9,
            0x16, 0x8b, 0xfa, 0x61, 0xd4, 0x4a, 0xad, 0x32, 0xc1, 0x5f, 0x93, 0x09, 0x7e, 0xe3, 0x27, 0xb0,
            0x44, 0xdd, 0xa0, 0x10, 0x87, 0xf1, 0x6e, 0x2c, 0x9b, 0x53, 0xc4, 0x3f, 0xb8, 0x08, 0x71, 0xea,
            0x15, 0x8a, 0xfb, 0x60, 0xd3, 0x49, 0xac, 0x31, 0xc2, 0x50, 0x92, 0x0b, 0x7c, 0xe4, 0x28, 0xb3,
            0x45, 0xde, 0xa2, 0x11, 0x88, 0xf2, 0x6f, 0x2d, 0x9a, 0x54, 0xc5, 0x30, 0xb9, 0x0c, 0x72, 0xeb,
            0x14, 0x89, 0xfc, 0x67, 0xd2, 0x41, 0xab, 0x3e, 0xc3, 0x57, 0x91, 0x0d, 0x75, 0xe5, 0x2e, 0xb4,
            0x46, 0xdf, 0xa3, 0x12, 0x8d, 0xf4, 0x68, 0x2f, 0x99, 0x55, 0xce, 0x37, 0xba, 0x0e, 0x73, 0xec,
            0x13, 0x8f, 0xfd, 0x66, 0xd0, 0x42, 0xaa, 0x3d, 0xc9, 0x56, 0x90, 0x0f, 0x76, 0xe6, 0x2e, 0xb5,
            0x47, 0xd8, 0xa4, 0x19, 0x8e, 0xf6, 0x69, 0x20, 0x98, 0x5a, 0xcf, 0x36, 0xbb, 0x0d, 0x77, 0xed,
            0x12, 0x88, 0xfe, 0x65, 0xd6, 0x4c, 0xa9, 0x3c, 0xca, 0x59, 0x95, 0x02, 0x79, 0xe2, 0x25, 0xb6,
            0x4f, 0xd9, 0xa5, 0x18, 0x83, 0xf7, 0x6a, 0x21, 0x97, 0x5b, 0xcc, 0x35, 0xbc, 0x03, 0x78, 0xee,
            0x11, 0x84, 0xff, 0x64, 0xd7, 0x4d, 0xa8, 0x3b, 0xcb, 0x58, 0x96, 0x01, 0x7a, 0xe1, 0x24, 0xb7,
            0x4e, 0xda, 0xa6, 0x19, 0x82, 0xf8, 0x6b, 0x22, 0x9c, 0x5d, 0xcd, 0x34, 0xbd, 0x00, 0x7b, 0xef,
    };

    /* Mixing constants (golden ratio fractions) */
    private static final int[] HYDRA_PHI = {
            0x9e3779b9, 0x517cc1b7, 0x27d4eb2f, 0x1e3779b9,
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    };

    /* ── Cipher State ──────────────────────────────────────────────── */

    private static int rotl32(int x, int n) {
        n &= 31;
        return (x << n) | (x >>> (32 - n));
    }

    /* ── Rotate helpers ────────────────────────────────────────────── */

    private static int rotr32(int x, int n) {
        n &= 31;
        return (x >>> n) | (x << (32 - n));
    }

    private static boolean uGreater(int a, int b) {
        return (a ^ 0x80000000) > (b ^ 0x80000000);
    }

    /* ── Unsigned 32-bit comparison helpers ─────────────────────────
     * Java has no unsigned int. Flipping the sign bit before a signed
     * compare yields the unsigned ordering. */

    private static boolean uLess(int a, int b) {
        return (a ^ 0x80000000) < (b ^ 0x80000000);
    }

    private static int hydraNonlinearMix(int a, int b, int ctrl, int sel) {
        int result;
        int tag = (ctrl >>> 4) & 0x07;
        int shift = (sel ^ ctrl) & 0x1F;
        int mask = (a ^ b) + ctrl;

        switch (tag) {
            case 0: {
                result = rotl32(a ^ b, shift) + (ctrl * 0x01000193);
                if ((mask & 0x8000) != 0) {
                    result ^= rotr32(b, (a & 0x0F) + 1);
                } else {
                    result += rotl32(a, (b & 0x0F) + 1);
                }
                break;
            }
            case 1: {
                result = (a * 0x5bd1e995) ^ (b >>> (shift & 0x0F));
                int low2 = result & 0x03;
                if (low2 == 0) {
                    result = rotl32(result, 13) ^ ctrl;
                } else if (low2 == 1) {
                    result = rotr32(result, 7) + mask;
                } else if (low2 == 2) {
                    result ^= (mask << 5) | (ctrl >>> 3);
                } else {
                    result += rotl32(ctrl ^ mask, 11);
                }
                break;
            }
            case 2: {
                result = rotr32(a + ctrl, shift) ^ (b * 0xcc9e2d51);
                if ((b & 0x100) != 0) {
                    result = (result << 3) ^ (result >>> 5) ^ mask;
                    if ((result & 0x40) != 0)
                        result += rotl32(a, 19);
                    else
                        result ^= rotr32(b, 23);
                } else {
                    result = (result * 0x1b873593) + a;
                }
                break;
            }
            case 3: {
                /* butterfly mix: swap halves conditionally */
                int hi = (a >>> 16) | (b << 16);
                int lo = (b >>> 16) | (a << 16);
                if ((ctrl & 0x200) != 0) {
                    result = hi ^ rotl32(lo, shift);
                } else {
                    result = lo ^ rotr32(hi, shift);
                }
                if (((hi ^ lo) & 0xFF) > 0x7F)
                    result ^= 0xDEADBEEF;
                else
                    result += 0x8BADF00D;
                break;
            }
            case 4: {
                /* polynomial-like evaluation; branch on overflow proxy */
                result = a;
                result = result * 31 + b;
                result = result * 31 + ctrl;
                result = result * 31 + mask;
                if (uLess(result, a)) {
                    result = rotl32(result, (ctrl & 7) + 1) ^ b;
                } else {
                    result = rotr32(result, (mask & 7) + 1) + a;
                }
                if (((result >>> 8) & 0xFF) == ((result >>> 24) & 0xFF))
                    result ^= HYDRA_PHI[shift & 0x07];
                break;
            }
            case 5: {
                /* byte-level cross-mixing; t0,t1 bounded by 255*255 */
                int ab0 = a & 0xFF;
                int ab1 = (a >>> 8) & 0xFF;
                int bb0 = b & 0xFF;
                int bb1 = (b >>> 8) & 0xFF;
                int t0 = ab0 * bb1;
                int t1 = ab1 * bb0;
                result = (t0 << 16) | (t1 & 0xFFFF);
                result ^= ctrl;
                if (t0 > t1)
                    result = rotl32(result, 5) + mask;
                else if (t0 < t1)
                    result = rotr32(result, 9) ^ mask;
                else
                    result += rotl32(mask, 17);
                break;
            }
            case 6: {
                /* fibonacci-step mixing */
                int f0 = a, f1 = b;
                int iters = (ctrl & 0x03) + 2;
                for (int i = 0; i < iters; i++) {
                    int t = f0 + f1;
                    f0 = f1;
                    f1 = t ^ (ctrl >>> (i + 1));
                    if ((t & 0x01) != 0)
                        f1 = rotl32(f1, 3);
                    else
                        f1 = rotr32(f1, 5);
                }
                result = f1 ^ mask;
                break;
            }
            default: { /* case 7: GF(2^32) approximate XOR-multiply */
                result = 0;
                int aa = a, bb = b ^ ctrl;
                for (int i = 0; i < 8; i++) {
                    if ((bb & 1) != 0)
                        result ^= aa;
                    if ((aa & 0x80000000) != 0)
                        aa = (aa << 1) ^ 0x1EDC6F41; /* CRC-32C poly */
                    else
                        aa <<= 1;
                    bb >>>= 1;
                }
                result ^= mask;
                break;
            }
        }
        return result;
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *  BRANCH-HEAVY NON-LINEAR MIXING FUNCTION
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

    private static int hydraSboxSubstitute(int word, int selector) {
        int b0 = word & 0xFF;
        int b1 = (word >>> 8) & 0xFF;
        int b2 = (word >>> 16) & 0xFF;
        int b3 = (word >>> 24) & 0xFF;

        int s0 = selector & 0x03;
        int s1 = (selector >>> 2) & 0x03;
        int s2 = (selector >>> 4) & 0x03;
        int s3 = (selector >>> 6) & 0x03;

        if (s0 == s2) {
            b0 = HYDRA_SBOX[(s0 << 8) | HYDRA_SBOX[(s1 << 8) | b0]];
            b2 = HYDRA_SBOX[(s2 << 8) | HYDRA_SBOX[(s3 << 8) | b2]];
        } else {
            b0 = HYDRA_SBOX[(s0 << 8) | b0];
            b2 = HYDRA_SBOX[(s2 << 8) | b2];
        }

        if (s1 == s3) {
            b1 = HYDRA_SBOX[(s3 << 8) | HYDRA_SBOX[(s0 << 8) | b1]];
            b3 = HYDRA_SBOX[(s1 << 8) | HYDRA_SBOX[(s2 << 8) | b3]];
        } else {
            b1 = HYDRA_SBOX[(s1 << 8) | b1];
            b3 = HYDRA_SBOX[(s3 << 8) | b3];
        }

        return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *  STATE-DEPENDENT S-BOX SUBSTITUTION
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

    private static void hydraCrossLaneMix(State st) {
        int pivot = st.feedback ^ st.selector;

        for (int w = 0; w < HYDRA_LANE_WORDS; w++) {
            int la = (pivot + w) & 0x03;
            int lb = (pivot >>> (w + 1)) & 0x03;

            if (la == lb)
                lb = (lb + 1) & 0x03;

            int va = st.lane[la * HYDRA_LANE_WORDS + w];
            int vb = st.lane[lb * HYDRA_LANE_WORDS + w];

            if ((pivot & (1 << w)) != 0) {
                st.lane[la * HYDRA_LANE_WORDS + w] = va ^ rotl32(vb, va & 0x1F);
                st.lane[lb * HYDRA_LANE_WORDS + w] = vb + rotr32(va, vb & 0x1F);
            } else {
                st.lane[la * HYDRA_LANE_WORDS + w] = va + (vb ^ pivot);
                st.lane[lb * HYDRA_LANE_WORDS + w] = vb ^ (va + pivot);
            }
        }

        st.mixAcc = 0;
        for (int i = 0; i < HYDRA_LANES * HYDRA_LANE_WORDS; i++) {
            st.mixAcc ^= st.lane[i];
            if ((st.mixAcc & 1) != 0)
                st.mixAcc = rotl32(st.mixAcc, 3);
            else
                st.mixAcc = rotr32(st.mixAcc, 5);
        }
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *  CROSS-LANE BUTTERFLY PERMUTATION
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

    private static void hydraRound(State st, int laneIdx, int roundNum) {
        int Lbase = laneIdx * HYDRA_LANE_WORDS;
        int rk = st.roundKey ^ HYDRA_PHI[roundNum & 0x07];

        /* ── step 1: data-dependent word permutation within lane ── */
        int[] order = new int[HYDRA_LANE_WORDS];
        for (int i = 0; i < HYDRA_LANE_WORDS; i++)
            order[i] = i;

        for (int i = 0; i < HYDRA_LANE_WORDS - 1; i++) {
            int cmpVal = st.lane[Lbase + order[i]] ^ rk;
            int nextVal = st.lane[Lbase + order[i + 1]] ^ st.feedback;
            if (uGreater(cmpVal, nextVal)) {
                int tmp = order[i];
                order[i] = order[i + 1];
                order[i + 1] = tmp;
            }
        }

        /* ── step 2: pairwise non-linear mix in shuffled order ──── */
        for (int i = 0; i < HYDRA_LANE_WORDS; i += 2) {
            int wa = st.lane[Lbase + order[i]];
            int wb = st.lane[Lbase + order[i + 1]];

            int mixed = hydraNonlinearMix(wa, wb, rk, st.selector);
            st.lane[Lbase + order[i]] ^= mixed;
            st.lane[Lbase + order[i + 1]] += mixed;

            st.feedback ^= mixed;

            int hi4 = mixed & 0xF0;
            if (hi4 > 0x80)
                st.feedback = rotl32(st.feedback, 7);
            else if (hi4 > 0x40)
                st.feedback = rotr32(st.feedback, 11);
            else if (hi4 > 0x20)
                st.feedback = rotl32(st.feedback, 3) ^ mixed;
            else
                st.feedback += rotr32(mixed, 13);
        }

        /* ── step 3: S-box substitution with evolving selector ──── */
        for (int i = 0; i < HYDRA_LANE_WORDS; i++) {
            st.lane[Lbase + i] = hydraSboxSubstitute(st.lane[Lbase + i], st.selector);
            st.selector ^= st.lane[Lbase + i];
            st.selector = rotl32(st.selector, 5);

            if ((st.lane[Lbase + i] & 0xFF) > (st.selector & 0xFF))
                st.selector += st.lane[Lbase + i] >>> 16;
            else
                st.selector ^= st.lane[Lbase + i] << 8;
        }

        /* ── step 4: add round key with state-dependent twist ───── */
        for (int i = 0; i < HYDRA_LANE_WORDS; i++) {
            int twist = rk ^ st.feedback ^ st.mixAcc;
            if ((twist & (1 << (i * 4))) != 0) {
                st.lane[Lbase + i] += twist;
                if ((st.lane[Lbase + i] & 0x8000) != 0)
                    st.lane[Lbase + i] = rotl32(st.lane[Lbase + i], (twist & 0x07) + 1);
            } else {
                st.lane[Lbase + i] ^= twist;
                if ((st.lane[Lbase + i] & 0x0080) != 0)
                    st.lane[Lbase + i] = rotr32(st.lane[Lbase + i], (twist & 0x07) + 1);
            }
            rk = rotl32(rk, 9) ^ st.lane[Lbase + i];
        }

        st.roundKey = rk;
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *  SINGLE ROUND FUNCTION
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

    private static void hydraKeySchedule(State st, byte[] key, byte[] nonce) {
        /* memcpy(st->key, key, ...) */
        System.arraycopy(key, 0, st.key, 0, HYDRA_KEY_SIZE);
        /* memcpy(st->nonce, nonce, ...) */
        System.arraycopy(nonce, 0, st.nonce, 0, HYDRA_NONCE_SIZE);

        st.counter = 0L;
        st.feedback = 0x6A09E667;  /* sqrt(2) fractional */
        st.selector = 0xBB67AE85;  /* sqrt(3) fractional */
        st.roundKey = 0x3C6EF372;  /* sqrt(5) fractional */
        st.mixAcc = 0xA54FF53A;  /* sqrt(7) fractional */

        /* ── load key words (little-endian) ─────────────────────── */
        int[] kw = new int[8];
        for (int i = 0; i < 8; i++) {
            kw[i] = (key[i * 4] & 0xFF)
                    | ((key[i * 4 + 1] & 0xFF) << 8)
                    | ((key[i * 4 + 2] & 0xFF) << 16)
                    | ((key[i * 4 + 3] & 0xFF) << 24);
        }

        int[] nw = new int[4];
        for (int i = 0; i < 4; i++) {
            nw[i] = (nonce[i * 4] & 0xFF)
                    | ((nonce[i * 4 + 1] & 0xFF) << 8)
                    | ((nonce[i * 4 + 2] & 0xFF) << 16)
                    | ((nonce[i * 4 + 3] & 0xFF) << 24);
        }

        /* ── initialize each lane differently ───────────────────── */
        for (int l = 0; l < HYDRA_LANES; l++) {
            for (int w = 0; w < HYDRA_LANE_WORDS; w++) {
                int base = kw[w] ^ HYDRA_PHI[w];
                int nonceMix = nw[l] ^ rotl32(nw[(l + 1) & 3], 11);
                int idx = l * HYDRA_LANE_WORDS + w;

                switch (l) {
                    case 0:
                        st.lane[idx] = base + nonceMix;
                        if ((base & 0x01) != 0)
                            st.lane[idx] = rotl32(st.lane[idx], 7);
                        break;
                    case 1:
                        st.lane[idx] = base ^ nonceMix;
                        if ((nonceMix & 0x80) != 0)
                            st.lane[idx] += rotl32(base, 13);
                        else
                            st.lane[idx] ^= rotr32(base, 9);
                        break;
                    case 2:
                        st.lane[idx] = rotl32(base, l + w) ^ nonceMix;
                        if (uGreater(base, nonceMix))
                            st.lane[idx] = ~st.lane[idx] + 1;
                        break;
                    case 3:
                        st.lane[idx] = (base * 0x01000193) ^ nonceMix;
                        if (((base >>> 24) & 0xFF) > 0x80) {
                            st.lane[idx] ^= HYDRA_PHI[(w + l) & 7];
                            if ((nonceMix & 0x400) != 0)
                                st.lane[idx] = rotl32(st.lane[idx], 5);
                        }
                        break;
                }
            }
        }

        /* ── warm-up rounds: establish deep state dependency ────── */
        for (int r = 0; r < 20; r++) {
            for (int l = 0; l < HYDRA_LANES; l++)
                hydraRound(st, l, r);
            hydraCrossLaneMix(st);

            if ((st.feedback & 0xFFFF) > 0x8000)
                st.feedback ^= st.mixAcc;
            else
                st.feedback += st.selector;
        }
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *  KEY SCHEDULE
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

    private static void hydraGenerateBlock(State st, byte[] out) {
        /* inject counter into state.
         * Casting (long * int) -> int takes the low 32 bits, which
         * matches C's (uint64 * uint32) -> uint32 truncation. */
        st.lane[0] ^= (int) st.counter;
        st.lane[HYDRA_LANE_WORDS + 1] ^= (int) (st.counter >>> 32);
        st.lane[2 * HYDRA_LANE_WORDS + 2] ^= (int) (st.counter * 0x9e3779b9);
        st.lane[3 * HYDRA_LANE_WORDS + 3] ^= (int) ((st.counter >>> 16) ^ st.feedback);
        st.counter++;

        /* ── main rounds ────────────────────────────────────────── */
        for (int r = 0; r < HYDRA_ROUNDS; r++) {
            int[] laneOrder = new int[HYDRA_LANES];
            int ordSeed = st.selector ^ st.feedback;
            for (int i = 0; i < HYDRA_LANES; i++)
                laneOrder[i] = i;

            /* state-dependent Fisher-Yates-ish shuffle */
            for (int i = HYDRA_LANES - 1; i > 0; i--) {
                int j = ((ordSeed >>> (i * 3)) & 0x07) % (i + 1);
                if (j != i) {
                    int tmp = laneOrder[i];
                    laneOrder[i] = laneOrder[j];
                    laneOrder[j] = tmp;
                }
            }

            for (int i = 0; i < HYDRA_LANES; i++) {
                hydraRound(st, laneOrder[i], r);
            }

            if (((r & 1) == 0) || ((st.feedback & 0x04) != 0)) {
                hydraCrossLaneMix(st);
            }

            if (r == (HYDRA_ROUNDS / 2)) {
                st.feedback ^= st.roundKey;
                st.selector += st.mixAcc;
                if ((st.selector & 0xFF00) > 0x8000)
                    st.roundKey = rotl32(st.roundKey, 11);
            }
        }

        /* ── extract keystream: each lane produces LANE_WORDS*4 ── */
        int[] ks = new int[HYDRA_LANES * HYDRA_LANE_WORDS];
        for (int l = 0; l < HYDRA_LANES; l++) {
            int adj = (l + 1) & (HYDRA_LANES - 1);
            for (int w = 0; w < HYDRA_LANE_WORDS; w++) {
                int laneIdx = l * HYDRA_LANE_WORDS + w;
                int adjIdx = adj * HYDRA_LANE_WORDS + ((w + l) & (HYDRA_LANE_WORDS - 1));
                int v = st.lane[laneIdx]
                        ^ rotl32(st.lane[adjIdx], 11);

                if ((st.lane[laneIdx] & 0x01) != 0)
                    v = rotl32(v, 3);
                else
                    v ^= rotr32(st.mixAcc, 7);

                ks[laneIdx] = hydraSboxSubstitute(v, st.selector ^ laneIdx);

                int base = laneIdx * 4;
                out[base] = (byte) ks[laneIdx];
                out[base + 1] = (byte) (ks[laneIdx] >>> 8);
                out[base + 2] = (byte) (ks[laneIdx] >>> 16);
                out[base + 3] = (byte) (ks[laneIdx] >>> 24);
            }
        }

        /* ── post-extraction state update (forward secrecy) ─────── */
        for (int i = 0; i < HYDRA_LANES * HYDRA_LANE_WORDS; i++) {
            int t = st.lane[i] + ks[i];
            int low2 = t & 0x03;
            if (low2 == 0)
                st.lane[i] = rotl32(t, 7);
            else if (low2 == 1)
                st.lane[i] = rotr32(t, 5) ^ st.feedback;
            else if (low2 == 2)
                st.lane[i] = t + st.mixAcc;
            else
                st.lane[i] = t ^ rotl32(st.selector, 13);
        }

        st.feedback ^= ks[0] ^ ks[HYDRA_LANES * HYDRA_LANE_WORDS - 1];
        st.selector += ks[3] ^ ks[HYDRA_LANES * HYDRA_LANE_WORDS / 2];
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *  KEYSTREAM BLOCK GENERATION (128 bytes)
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

    /* Initialize cipher with 32-byte key and 16-byte nonce. */
    public static void hydraInit(State st, byte[] key, byte[] nonce) {
        /* memset(st, 0, sizeof(*st)) */
        for (int i = 0; i < HYDRA_LANES * HYDRA_LANE_WORDS; i++)
            st.lane[i] = 0;
        st.feedback = 0;
        st.selector = 0;
        st.roundKey = 0;
        st.mixAcc = 0;
        st.counter = 0L;
        for (int i = 0; i < HYDRA_KEY_SIZE; i++) st.key[i] = 0;
        for (int i = 0; i < HYDRA_NONCE_SIZE; i++) st.nonce[i] = 0;

        hydraKeySchedule(st, key, nonce);
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *  PUBLIC API
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

    /* Encrypt or decrypt: out[i] = in[i] ^ keystream[i]. May alias. */
    public static void hydraCrypt(State st, byte[] in, byte[] out, int len) {
        byte[] block = new byte[HYDRA_BLOCK_BYTES];
        int blockPos = HYDRA_BLOCK_BYTES; /* force first generation */

        for (int i = 0; i < len; i++) {
            if (blockPos >= HYDRA_BLOCK_BYTES) {
                hydraGenerateBlock(st, block);
                blockPos = 0;
            }
            out[i] = (byte) (in[i] ^ block[blockPos]);
            blockPos++;
        }

        /* wipe keystream block */
        for (int i = 0; i < HYDRA_BLOCK_BYTES; i++) block[i] = 0;
    }

    /* Generate raw keystream (no input data). */
    public static void hydraKeystream(State st, byte[] out, int len) {
        byte[] block = new byte[HYDRA_BLOCK_BYTES];
        int blockPos = HYDRA_BLOCK_BYTES;

        for (int i = 0; i < len; i++) {
            if (blockPos >= HYDRA_BLOCK_BYTES) {
                hydraGenerateBlock(st, block);
                blockPos = 0;
            }
            out[i] = block[blockPos];
            blockPos++;
        }

        for (int i = 0; i < HYDRA_BLOCK_BYTES; i++) block[i] = 0;
    }

    public static class State {
        public final int[] lane = new int[HYDRA_LANES * HYDRA_LANE_WORDS];
        public final byte[] key = new byte[HYDRA_KEY_SIZE];
        public final byte[] nonce = new byte[HYDRA_NONCE_SIZE];
        public int feedback;   /* non-linear feedback accumulator        */
        public int selector;   /* S-box / path selector                  */
        public int roundKey;   /* derived per-round sub-key              */
        public int mixAcc;     /* cross-lane mixing accumulator          */
        public long counter;    /* monotonic counter for uniqueness       */
    }
}