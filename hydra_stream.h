/*
 * HydraStream Cipher v1.0
 * ========================
 * A symmetric-key stream cipher designed for execution inside a code
 * virtual machine. Intentionally uses:
 *   - Heavy branching based on previously computed state
 *   - Cross-variable mathematical operations (butterfly mixing)
 *   - State-dependent S-box selection (polymorphic substitution)
 *   - Non-linear feedback with data-dependent rotation
 *   - Multi-lane architecture with lane-crossing
 *
 * NOT a cryptographically proven cipher. Designed for obfuscation
 * resistance in a VM context. For real security, use AES/ChaCha20.
 *
 * Architecture Overview:
 * ┌──────────────────────────────────────────────────────┐
 * │  256-bit Key                                         │
 * │    │                                                 │
 * │    ▼                                                 │
 * │  ┌─────────┐   ┌─────────┐   ┌─────────┐           │
 * │  │ Lane A  │──▶│ Lane B  │──▶│ Lane C  │──▶ ...    │
 * │  │ (8x u32)│◀──│ (8x u32)│◀──│ (8x u32)│           │
 * │  └────┬────┘   └────┬────┘   └────┬────┘           │
 * │       │              │              │                │
 * │       ▼              ▼              ▼                │
 * │  ┌─────────────────────────────────────────┐        │
 * │  │  Branch Mixer (state-dependent paths)   │        │
 * │  │  → selects S-box, rotation, feedback    │        │
 * │  └─────────────────────┬───────────────────┘        │
 * │                        │                             │
 * │                        ▼                             │
 * │               Keystream byte out                     │
 * └──────────────────────────────────────────────────────┘
 */

#ifndef HYDRA_STREAM_H
#define HYDRA_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ── Configuration ─────────────────────────────────────────────── */

#define HYDRA_KEY_SIZE      32   /* 256-bit key                    */
#define HYDRA_NONCE_SIZE    16   /* 128-bit nonce                  */
#define HYDRA_LANES          4   /* number of parallel state lanes */
#define HYDRA_LANE_WORDS     8   /* 32-bit words per lane          */
#define HYDRA_ROUNDS        12   /* mixing rounds per block        */
#define HYDRA_SBOX_COUNT     4   /* polymorphic S-box pool         */

/* ── Rotate helpers ────────────────────────────────────────────── */

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t rotr32(uint32_t x, unsigned n) {
    n &= 31;
    return (x >> n) | (x << (32 - n));
}

/* ── S-Box Pool (4 different 8→8 substitution tables) ──────────
 *  Which S-box is selected depends on runtime state, creating a
 *  polymorphic substitution that is hard to trace statically.    */

static const uint8_t HYDRA_SBOX[HYDRA_SBOX_COUNT][256] = {
    /* S-box 0: based on multiplicative inverse in GF(2^8) + affine */
    {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    },
    /* S-box 1: bit-reversal + XOR 0xA5 + rotate nibble */
    {
        0xa5,0x25,0x65,0xe5,0x15,0x95,0x55,0xd5,0x0d,0x8d,0x4d,0xcd,0x3d,0xbd,0x7d,0xfd,
        0xa3,0x23,0x63,0xe3,0x13,0x93,0x53,0xd3,0x0b,0x8b,0x4b,0xcb,0x3b,0xbb,0x7b,0xfb,
        0xa9,0x29,0x69,0xe9,0x19,0x99,0x59,0xd9,0x01,0x81,0x41,0xc1,0x31,0xb1,0x71,0xf1,
        0xaf,0x2f,0x6f,0xef,0x1f,0x9f,0x5f,0xdf,0x07,0x87,0x47,0xc7,0x37,0xb7,0x77,0xf7,
        0xa4,0x24,0x64,0xe4,0x14,0x94,0x54,0xd4,0x0c,0x8c,0x4c,0xcc,0x3c,0xbc,0x7c,0xfc,
        0xa2,0x22,0x62,0xe2,0x12,0x92,0x52,0xd2,0x0a,0x8a,0x4a,0xca,0x3a,0xba,0x7a,0xfa,
        0xa8,0x28,0x68,0xe8,0x18,0x98,0x58,0xd8,0x00,0x80,0x40,0xc0,0x30,0xb0,0x70,0xf0,
        0xae,0x2e,0x6e,0xee,0x1e,0x9e,0x5e,0xde,0x06,0x86,0x46,0xc6,0x36,0xb6,0x76,0xf6,
        0xa1,0x21,0x61,0xe1,0x11,0x91,0x51,0xd1,0x09,0x89,0x49,0xc9,0x39,0xb9,0x79,0xf9,
        0xa7,0x27,0x67,0xe7,0x17,0x97,0x57,0xd7,0x0f,0x8f,0x4f,0xcf,0x3f,0xbf,0x7f,0xff,
        0xac,0x2c,0x6c,0xec,0x1c,0x9c,0x5c,0xdc,0x04,0x84,0x44,0xc4,0x34,0xb4,0x74,0xf4,
        0xaa,0x2a,0x6a,0xea,0x1a,0x9a,0x5a,0xda,0x02,0x82,0x42,0xc2,0x32,0xb2,0x72,0xf2,
        0xa6,0x26,0x66,0xe6,0x16,0x96,0x56,0xd6,0x0e,0x8e,0x4e,0xce,0x3e,0xbe,0x7e,0xfe,
        0xab,0x2b,0x6b,0xeb,0x1b,0x9b,0x5b,0xdb,0x03,0x83,0x43,0xc3,0x33,0xb3,0x73,0xf3,
        0xad,0x2d,0x6d,0xed,0x1d,0x9d,0x5d,0xdd,0x05,0x85,0x45,0xc5,0x35,0xb5,0x75,0xf5,
        0xa0,0x20,0x60,0xe0,0x10,0x90,0x50,0xd0,0x08,0x88,0x48,0xc8,0x38,0xb8,0x78,0xf8,
    },
    /* S-box 2: polynomial evaluation mod 257, truncated */
    {
        0xd2,0x3a,0xe1,0x58,0xbf,0x07,0x9e,0x46,0xc3,0x1b,0x82,0xf9,0x60,0xa8,0x2f,0x77,
        0x0e,0xd6,0x4d,0xb4,0x2c,0x93,0xeb,0x52,0xa0,0x18,0x8f,0xf7,0x6e,0xc5,0x3d,0x84,
        0xfb,0x63,0xca,0x31,0xa9,0x10,0x88,0xff,0x66,0xce,0x35,0x9d,0x04,0x7c,0xe3,0x4b,
        0xb2,0x2a,0x91,0xe9,0x50,0xb8,0x20,0x97,0xef,0x56,0xae,0x15,0x7d,0xe4,0x4c,0xb3,
        0x1a,0x81,0xf8,0x70,0xc7,0x3e,0x86,0xfd,0x64,0xac,0x13,0x8b,0xf2,0x6a,0xc1,0x38,
        0x90,0x08,0x7f,0xe6,0x5e,0xb5,0x2d,0x94,0xec,0x53,0xbb,0x22,0x8a,0xf1,0x69,0xd0,
        0x47,0x9f,0x06,0x6e,0xd5,0x4c,0xa3,0x1b,0x72,0xda,0x41,0xa9,0x10,0x78,0xef,0x57,
        0xbe,0x25,0x8d,0xf4,0x5c,0xc3,0x3b,0x92,0xea,0x51,0xb9,0x21,0x98,0x00,0x67,0xcf,
        0x36,0x9e,0x05,0x7d,0xe4,0x4b,0xa3,0x1a,0x82,0xe9,0x50,0xb8,0x30,0x97,0x0f,0x76,
        0xde,0x45,0xbd,0x24,0x8c,0xf3,0x5b,0xc2,0x29,0x91,0x08,0x80,0xf7,0x6f,0xd6,0x3e,
        0xa5,0x0d,0x74,0xdc,0x43,0xab,0x12,0x7a,0xe1,0x59,0xc0,0x27,0x8f,0x16,0x7e,0xe5,
        0x4d,0xb4,0x2c,0x83,0xfb,0x62,0xca,0x31,0x99,0x01,0x68,0xd0,0x47,0xaf,0x17,0x8e,
        0xf5,0x5d,0xc4,0x3c,0xa3,0x0b,0x72,0xea,0x51,0xb9,0x20,0x88,0xf0,0x57,0xcf,0x36,
        0x9e,0x06,0x7d,0xe5,0x4c,0xa4,0x1c,0x83,0xeb,0x52,0xba,0x21,0x99,0x00,0x78,0xdf,
        0x47,0xbe,0x26,0x9d,0xf5,0x5c,0xc4,0x3b,0x93,0x0a,0x81,0xe9,0x60,0xb8,0x2f,0x87,
        0xfe,0x66,0xcd,0x34,0xac,0x13,0x7b,0xe2,0x5a,0xc1,0x28,0x90,0x07,0x6f,0xd6,0x4e,
    },
    /* S-box 3: CRC-derived permutation */
    {
        0x48,0xd1,0x3a,0xe7,0x5c,0x9f,0x06,0xb2,0x74,0xc8,0x1d,0xaf,0x63,0xf5,0x29,0x8e,
        0xdb,0x40,0xa7,0x1e,0x85,0xf3,0x6c,0x2a,0x9d,0x51,0xc6,0x38,0xbe,0x04,0x7f,0xe0,
        0x17,0x8c,0xf9,0x62,0xd5,0x4b,0xae,0x33,0xc0,0x5e,0x94,0x0a,0x7d,0xe8,0x26,0xb1,
        0x43,0xdc,0xa1,0x1f,0x86,0xf0,0x6d,0x2b,0x9e,0x52,0xc7,0x39,0xbf,0x05,0x70,0xe9,
        0x16,0x8b,0xfa,0x61,0xd4,0x4a,0xad,0x32,0xc1,0x5f,0x93,0x09,0x7e,0xe3,0x27,0xb0,
        0x44,0xdd,0xa0,0x10,0x87,0xf1,0x6e,0x2c,0x9b,0x53,0xc4,0x3f,0xb8,0x08,0x71,0xea,
        0x15,0x8a,0xfb,0x60,0xd3,0x49,0xac,0x31,0xc2,0x50,0x92,0x0b,0x7c,0xe4,0x28,0xb3,
        0x45,0xde,0xa2,0x11,0x88,0xf2,0x6f,0x2d,0x9a,0x54,0xc5,0x30,0xb9,0x0c,0x72,0xeb,
        0x14,0x89,0xfc,0x67,0xd2,0x41,0xab,0x3e,0xc3,0x57,0x91,0x0d,0x75,0xe5,0x2e,0xb4,
        0x46,0xdf,0xa3,0x12,0x8d,0xf4,0x68,0x2f,0x99,0x55,0xce,0x37,0xba,0x0e,0x73,0xec,
        0x13,0x8f,0xfd,0x66,0xd0,0x42,0xaa,0x3d,0xc9,0x56,0x90,0x0f,0x76,0xe6,0x2e,0xb5,
        0x47,0xd8,0xa4,0x19,0x8e,0xf6,0x69,0x20,0x98,0x5a,0xcf,0x36,0xbb,0x0d,0x77,0xed,
        0x12,0x88,0xfe,0x65,0xd6,0x4c,0xa9,0x3c,0xca,0x59,0x95,0x02,0x79,0xe2,0x25,0xb6,
        0x4f,0xd9,0xa5,0x18,0x83,0xf7,0x6a,0x21,0x97,0x5b,0xcc,0x35,0xbc,0x03,0x78,0xee,
        0x11,0x84,0xff,0x64,0xd7,0x4d,0xa8,0x3b,0xcb,0x58,0x96,0x01,0x7a,0xe1,0x24,0xb7,
        0x4e,0xda,0xa6,0x19,0x82,0xf8,0x6b,0x22,0x9c,0x5d,0xcd,0x34,0xbd,0x00,0x7b,0xef,
    },
};

/* ── Mixing constants (golden ratio fractions) ─────────────────── */

static const uint32_t HYDRA_PHI[8] = {
    0x9e3779b9, 0x517cc1b7, 0x27d4eb2f, 0x1e3779b9,
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
};

/* ── Cipher State ──────────────────────────────────────────────── */

typedef struct {
    uint32_t lane[HYDRA_LANES][HYDRA_LANE_WORDS];  /* 4 lanes × 8 words   */
    uint32_t feedback;     /* non-linear feedback accumulator               */
    uint32_t selector;     /* S-box / path selector (changes each step)     */
    uint32_t round_key;    /* derived per-round sub-key                     */
    uint32_t mix_acc;      /* cross-lane mixing accumulator                 */
    uint64_t counter;      /* monotonic counter for uniqueness              */
    uint8_t  key[HYDRA_KEY_SIZE];
    uint8_t  nonce[HYDRA_NONCE_SIZE];
} hydra_state_t;


/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  BRANCH-HEAVY NON-LINEAR MIXING FUNCTION
 *  ────────────────────────────────────────
 *  This is the core of the anti-RE design. Every branch depends on
 *  a variable that was computed from other state, so a VM can turn
 *  each branch into an opaque dispatch.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

static uint32_t hydra_nonlinear_mix(uint32_t a, uint32_t b,
                                    uint32_t ctrl, uint32_t sel)
{
    uint32_t result;
    uint32_t tag   = (ctrl >> 4) & 0x07;   /* 3-bit branch selector     */
    uint32_t shift = (sel ^ ctrl) & 0x1F;  /* data-dependent shift      */
    uint32_t mask  = (a ^ b) + ctrl;       /* cross-var derived mask    */

    /* ── 8-way branch: path selected by runtime state ──────────── */
    switch (tag) {
        case 0:
            result = rotl32(a ^ b, shift) + (ctrl * 0x01000193);
            /* secondary branch inside: feedback direction */
            if ((mask & 0x8000) != 0) {
                result ^= rotr32(b, (a & 0x0F) + 1);
            } else {
                result += rotl32(a, (b & 0x0F) + 1);
            }
            break;

        case 1:
            result = (a * 0x5bd1e995) ^ (b >> (shift & 0x0F));
            /* nested branch based on accumulator parity */
            if ((result & 0x03) == 0) {
                result = rotl32(result, 13) ^ ctrl;
            } else if ((result & 0x03) == 1) {
                result = rotr32(result, 7) + mask;
            } else if ((result & 0x03) == 2) {
                result ^= (mask << 5) | (ctrl >> 3);
            } else {
                result += rotl32(ctrl ^ mask, 11);
            }
            break;

        case 2:
            result = rotr32(a + ctrl, shift) ^ (b * 0xcc9e2d51);
            if ((b & 0x100) != 0) {
                result = (result << 3) ^ (result >> 5) ^ mask;
                if ((result & 0x40) != 0)
                    result += rotl32(a, 19);
                else
                    result ^= rotr32(b, 23);
            } else {
                result = (result * 0x1b873593) + a;
            }
            break;

        case 3: {
            /* butterfly mix: swap halves conditionally */
            uint32_t hi = (a >> 16) | (b << 16);
            uint32_t lo = (b >> 16) | (a << 16);
            if ((ctrl & 0x200) != 0) {
                result = hi ^ rotl32(lo, shift);
            } else {
                result = lo ^ rotr32(hi, shift);
            }
            /* additional data-dependent XOR fold */
            if (((hi ^ lo) & 0xFF) > 0x7F)
                result ^= 0xDEADBEEF;
            else
                result += 0x8BADF00D;
            break;
        }

        case 4:
            /* polynomial-like evaluation */
            result = a;
            result = result * 31 + b;
            result = result * 31 + ctrl;
            result = result * 31 + mask;
            /* branch on overflow proxy */
            if (result < a) {
                result = rotl32(result, (ctrl & 7) + 1) ^ b;
            } else {
                result = rotr32(result, (mask & 7) + 1) + a;
            }
            /* third-level branch */
            if (((result >> 8) & 0xFF) == ((result >> 24) & 0xFF))
                result ^= HYDRA_PHI[shift & 0x07];
            break;

        case 5: {
            /* byte-level cross-mixing */
            uint8_t ab0 = (uint8_t)(a);
            uint8_t ab1 = (uint8_t)(a >> 8);
            uint8_t bb0 = (uint8_t)(b);
            uint8_t bb1 = (uint8_t)(b >> 8);
            uint32_t t0 = (uint32_t)ab0 * bb1;
            uint32_t t1 = (uint32_t)ab1 * bb0;
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
            uint32_t f0 = a, f1 = b;
            for (int i = 0; i < (int)((ctrl & 0x03) + 2); i++) {
                uint32_t t = f0 + f1;
                f0 = f1;
                f1 = t ^ (ctrl >> (i + 1));
                /* inner branch */
                if ((t & 0x01) != 0)
                    f1 = rotl32(f1, 3);
                else
                    f1 = rotr32(f1, 5);
            }
            result = f1 ^ mask;
            break;
        }

        default: /* case 7 */
            /* GF(2^32) approximate: XOR-multiply with branches */
            result = 0;
            {
                uint32_t aa = a, bb = b ^ ctrl;
                for (int i = 0; i < 8; i++) {
                    if ((bb & 1) != 0)
                        result ^= aa;
                    /* conditional "reduction" */
                    if ((aa & 0x80000000) != 0)
                        aa = (aa << 1) ^ 0x1EDC6F41; /* CRC-32C poly */
                    else
                        aa <<= 1;
                    bb >>= 1;
                }
            }
            result ^= mask;
            break;
    }

    return result;
}


/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  STATE-DEPENDENT S-BOX SUBSTITUTION
 *  ──────────────────────────────────
 *  Applies a different S-box per byte position, chosen by the
 *  current selector state. Creates polymorphic substitution.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

static uint32_t hydra_sbox_substitute(uint32_t word, uint32_t selector)
{
    uint8_t b0 = (uint8_t)(word);
    uint8_t b1 = (uint8_t)(word >> 8);
    uint8_t b2 = (uint8_t)(word >> 16);
    uint8_t b3 = (uint8_t)(word >> 24);

    /* each byte uses a different S-box, selected by different bits */
    unsigned s0 = (selector)       & 0x03;
    unsigned s1 = (selector >> 2)  & 0x03;
    unsigned s2 = (selector >> 4)  & 0x03;
    unsigned s3 = (selector >> 6)  & 0x03;

    /* branch: if selector nibbles match, cascade S-boxes */
    if (s0 == s2) {
        b0 = HYDRA_SBOX[s0][HYDRA_SBOX[s1][b0]];
        b2 = HYDRA_SBOX[s2][HYDRA_SBOX[s3][b2]];
    } else {
        b0 = HYDRA_SBOX[s0][b0];
        b2 = HYDRA_SBOX[s2][b2];
    }

    if (s1 == s3) {
        b1 = HYDRA_SBOX[s3][HYDRA_SBOX[s0][b1]];
        b3 = HYDRA_SBOX[s1][HYDRA_SBOX[s2][b3]];
    } else {
        b1 = HYDRA_SBOX[s1][b1];
        b3 = HYDRA_SBOX[s3][b3];
    }

    return ((uint32_t)b3 << 24) | ((uint32_t)b2 << 16) |
           ((uint32_t)b1 << 8)  | (uint32_t)b0;
}


/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  CROSS-LANE BUTTERFLY PERMUTATION
 *  ────────────────────────────────
 *  Mixes data between lanes so no lane can be analysed in isolation.
 *  The permutation pattern is state-dependent.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

static void hydra_cross_lane_mix(hydra_state_t *st)
{
    uint32_t pivot = st->feedback ^ st->selector;

    for (int w = 0; w < HYDRA_LANE_WORDS; w++) {
        /* pick two lanes to cross based on state */
        unsigned la = (pivot + (uint32_t)w) & 0x03;
        unsigned lb = (pivot >> (w + 1))    & 0x03;

        if (la == lb)
            lb = (lb + 1) & 0x03;

        uint32_t va = st->lane[la][w];
        uint32_t vb = st->lane[lb][w];

        /* state-dependent cross operation */
        if ((pivot & (1u << w)) != 0) {
            st->lane[la][w] = va ^ rotl32(vb, (va & 0x1F));
            st->lane[lb][w] = vb + rotr32(va, (vb & 0x1F));
        } else {
            st->lane[la][w] = va + (vb ^ pivot);
            st->lane[lb][w] = vb ^ (va + pivot);
        }
    }

    /* update mixing accumulator from all lanes */
    st->mix_acc = 0;
    for (int l = 0; l < HYDRA_LANES; l++) {
        for (int w = 0; w < HYDRA_LANE_WORDS; w++) {
            st->mix_acc ^= st->lane[l][w];
            /* branch: fold direction by parity */
            if ((st->mix_acc & 1) != 0)
                st->mix_acc = rotl32(st->mix_acc, 3);
            else
                st->mix_acc = rotr32(st->mix_acc, 5);
        }
    }
}


/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  SINGLE ROUND FUNCTION
 *  ─────────────────────
 *  Runs one round on a single lane with full branch coverage.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

static void hydra_round(hydra_state_t *st, int lane_idx, uint32_t round_num)
{
    uint32_t *L = st->lane[lane_idx];
    uint32_t rk = st->round_key ^ HYDRA_PHI[round_num & 0x07];

    /* ── step 1: data-dependent word permutation within lane ── */
    unsigned order[HYDRA_LANE_WORDS];
    for (int i = 0; i < HYDRA_LANE_WORDS; i++)
        order[i] = (unsigned)i;

    /* simple state-dependent shuffle (bubblesort-ish with branches) */
    for (int i = 0; i < HYDRA_LANE_WORDS - 1; i++) {
        uint32_t cmp_val = L[order[i]] ^ rk;
        uint32_t next_val = L[order[i + 1]] ^ st->feedback;
        if (cmp_val > next_val) {
            unsigned tmp = order[i];
            order[i] = order[i + 1];
            order[i + 1] = tmp;
        }
    }

    /* ── step 2: pairwise non-linear mix in shuffled order ──── */
    for (int i = 0; i < HYDRA_LANE_WORDS; i += 2) {
        uint32_t wa = L[order[i]];
        uint32_t wb = L[order[i + 1]];

        uint32_t mixed = hydra_nonlinear_mix(wa, wb, rk, st->selector);
        L[order[i]]     ^= mixed;
        L[order[i + 1]] += mixed;

        /* update feedback from result (creates chain dependency) */
        st->feedback ^= mixed;

        /* branch: rotate feedback based on mixed value bits */
        if ((mixed & 0xF0) > 0x80)
            st->feedback = rotl32(st->feedback, 7);
        else if ((mixed & 0xF0) > 0x40)
            st->feedback = rotr32(st->feedback, 11);
        else if ((mixed & 0xF0) > 0x20)
            st->feedback = rotl32(st->feedback, 3) ^ mixed;
        else
            st->feedback += rotr32(mixed, 13);
    }

    /* ── step 3: S-box substitution with evolving selector ──── */
    for (int i = 0; i < HYDRA_LANE_WORDS; i++) {
        L[i] = hydra_sbox_substitute(L[i], st->selector);

        /* evolve the selector from the substituted value */
        st->selector ^= L[i];
        st->selector  = rotl32(st->selector, 5);

        /* branch: selector evolution path */
        if ((L[i] & 0xFF) > (st->selector & 0xFF))
            st->selector += L[i] >> 16;
        else
            st->selector ^= L[i] << 8;
    }

    /* ── step 4: add round key with state-dependent twist ───── */
    for (int i = 0; i < HYDRA_LANE_WORDS; i++) {
        uint32_t twist = rk ^ st->feedback ^ st->mix_acc;
        /* branch: addition vs XOR based on bit pattern */
        if ((twist & (1u << (i * 4))) != 0) {
            L[i] += twist;
            if ((L[i] & 0x8000) != 0)
                L[i] = rotl32(L[i], (twist & 0x07) + 1);
        } else {
            L[i] ^= twist;
            if ((L[i] & 0x0080) != 0)
                L[i] = rotr32(L[i], (twist & 0x07) + 1);
        }
        rk = rotl32(rk, 9) ^ L[i];
    }

    /* propagate round key back */
    st->round_key = rk;
}


/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  KEY SCHEDULE
 *  ────────────
 *  Expands the key+nonce into the initial state with branch-heavy
 *  derivation. Every lane gets a different view of the key.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

static void hydra_key_schedule(hydra_state_t *st,
                               const uint8_t key[HYDRA_KEY_SIZE],
                               const uint8_t nonce[HYDRA_NONCE_SIZE])
{
    memcpy(st->key, key, HYDRA_KEY_SIZE);
    memcpy(st->nonce, nonce, HYDRA_NONCE_SIZE);
    st->counter  = 0;
    st->feedback = 0x6A09E667;  /* sqrt(2) fractional */
    st->selector = 0xBB67AE85;  /* sqrt(3) fractional */
    st->round_key = 0x3C6EF372; /* sqrt(5) fractional */
    st->mix_acc  = 0xA54FF53A;  /* sqrt(7) fractional */

    /* ── load key words into lanes with lane-dependent transforms ── */
    uint32_t kw[8];
    for (int i = 0; i < 8; i++) {
        kw[i] = ((uint32_t)key[i*4])           |
                ((uint32_t)key[i*4 + 1] << 8)  |
                ((uint32_t)key[i*4 + 2] << 16) |
                ((uint32_t)key[i*4 + 3] << 24);
    }

    uint32_t nw[4];
    for (int i = 0; i < 4; i++) {
        nw[i] = ((uint32_t)nonce[i*4])           |
                ((uint32_t)nonce[i*4 + 1] << 8)  |
                ((uint32_t)nonce[i*4 + 2] << 16) |
                ((uint32_t)nonce[i*4 + 3] << 24);
    }

    /* ── initialize each lane differently ────────────────────────── */
    for (int l = 0; l < HYDRA_LANES; l++) {
        for (int w = 0; w < HYDRA_LANE_WORDS; w++) {
            uint32_t base = kw[w] ^ HYDRA_PHI[w];
            uint32_t nonce_mix = nw[l] ^ rotl32(nw[(l + 1) & 3], 11);

            /* branch: lane-dependent initialization path */
            switch (l) {
                case 0:
                    st->lane[l][w] = base + nonce_mix;
                    if ((base & 0x01) != 0)
                        st->lane[l][w] = rotl32(st->lane[l][w], 7);
                    break;
                case 1:
                    st->lane[l][w] = base ^ nonce_mix;
                    if ((nonce_mix & 0x80) != 0)
                        st->lane[l][w] += rotl32(base, 13);
                    else
                        st->lane[l][w] ^= rotr32(base, 9);
                    break;
                case 2:
                    st->lane[l][w] = rotl32(base, l + w) ^ nonce_mix;
                    if (base > nonce_mix)
                        st->lane[l][w] = ~st->lane[l][w] + 1;
                    break;
                case 3:
                    st->lane[l][w] = (base * 0x01000193) ^ nonce_mix;
                    /* deeper branch: high byte test */
                    if (((base >> 24) & 0xFF) > 0x80) {
                        st->lane[l][w] ^= HYDRA_PHI[(w + l) & 7];
                        if ((nonce_mix & 0x400) != 0)
                            st->lane[l][w] = rotl32(st->lane[l][w], 5);
                    }
                    break;
            }
        }
    }

    /* ── warm-up rounds: establish deep state dependency ────────── */
    for (int r = 0; r < 20; r++) {
        for (int l = 0; l < HYDRA_LANES; l++)
            hydra_round(st, l, (uint32_t)r);
        hydra_cross_lane_mix(st);

        /* evolve feedback with branch */
        if ((st->feedback & 0xFFFF) > 0x8000)
            st->feedback ^= st->mix_acc;
        else
            st->feedback += st->selector;
    }
}


/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  KEYSTREAM BLOCK GENERATION
 *  ──────────────────────────
 *  Produces one block (128 bytes) of keystream with all the
 *  branch-heavy processing active.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

#define HYDRA_BLOCK_BYTES (HYDRA_LANES * HYDRA_LANE_WORDS * 4)

static void hydra_generate_block(hydra_state_t *st,
                                 uint8_t out[HYDRA_BLOCK_BYTES])
{
    /* inject counter into state (prevents cycle repetition) */
    st->lane[0][0] ^= (uint32_t)(st->counter);
    st->lane[1][1] ^= (uint32_t)(st->counter >> 32);
    st->lane[2][2] ^= (uint32_t)(st->counter * 0x9e3779b9);
    st->lane[3][3] ^= (uint32_t)((st->counter >> 16) ^ st->feedback);
    st->counter++;

    /* ── main rounds ──────────────────────────────────────────── */
    for (uint32_t r = 0; r < HYDRA_ROUNDS; r++) {
        /* branch: lane processing order depends on state */
        int lane_order[HYDRA_LANES];
        uint32_t ord_seed = st->selector ^ st->feedback;
        for (int i = 0; i < HYDRA_LANES; i++)
            lane_order[i] = i;

        /* state-dependent Fisher-Yates-ish shuffle */
        for (int i = HYDRA_LANES - 1; i > 0; i--) {
            unsigned j = ((ord_seed >> (i * 3)) & 0x07) % ((unsigned)i + 1);
            if (j != (unsigned)i) {
                int tmp = lane_order[i];
                lane_order[i] = lane_order[j];
                lane_order[j] = tmp;
            }
        }

        /* process lanes in shuffled order */
        for (int i = 0; i < HYDRA_LANES; i++) {
            hydra_round(st, lane_order[i], r);
        }

        /* cross-lane mix every 2 rounds (branch) */
        if (((r & 1) == 0) || ((st->feedback & 0x04) != 0)) {
            hydra_cross_lane_mix(st);
        }

        /* branch: mid-round feedback injection */
        if (r == (HYDRA_ROUNDS / 2)) {
            st->feedback ^= st->round_key;
            st->selector += st->mix_acc;
            if ((st->selector & 0xFF00) > 0x8000)
                st->round_key = rotl32(st->round_key, 11);
        }
    }

    /* ── extract keystream: each lane produces LANE_WORDS*4 bytes ── */
    uint32_t ks[HYDRA_LANES * HYDRA_LANE_WORDS];
    for (int l = 0; l < HYDRA_LANES; l++) {
        /* cross-lane fold: XOR with adjacent lane */
        int adj = (l + 1) & (HYDRA_LANES - 1);
        for (int w = 0; w < HYDRA_LANE_WORDS; w++) {
            uint32_t v = st->lane[l][w] ^ rotl32(st->lane[adj][(w + l) & (HYDRA_LANE_WORDS - 1)], 11);
            /* branch: fold direction per lane word */
            if ((st->lane[l][w] & 0x01) != 0)
                v = rotl32(v, 3);
            else
                v ^= rotr32(st->mix_acc, 7);

            /* final S-box pass on output */
            int ks_idx = l * HYDRA_LANE_WORDS + w;
            ks[ks_idx] = hydra_sbox_substitute(v, st->selector ^ (uint32_t)(ks_idx));

            /* write to output buffer (little-endian) */
            int base = ks_idx * 4;
            out[base]     = (uint8_t)(ks[ks_idx]);
            out[base + 1] = (uint8_t)(ks[ks_idx] >> 8);
            out[base + 2] = (uint8_t)(ks[ks_idx] >> 16);
            out[base + 3] = (uint8_t)(ks[ks_idx] >> 24);
        }
    }

    /* ── post-extraction state update (forward secrecy) ───────── */
    for (int l = 0; l < HYDRA_LANES; l++) {
        for (int w = 0; w < HYDRA_LANE_WORDS; w++) {
            int ks_idx = l * HYDRA_LANE_WORDS + w;
            uint32_t t = st->lane[l][w] + ks[ks_idx];
            /* branch: post-mix evolution */
            if ((t & 0x03) == 0)
                st->lane[l][w] = rotl32(t, 7);
            else if ((t & 0x03) == 1)
                st->lane[l][w] = rotr32(t, 5) ^ st->feedback;
            else if ((t & 0x03) == 2)
                st->lane[l][w] = t + st->mix_acc;
            else
                st->lane[l][w] = t ^ rotl32(st->selector, 13);
        }
    }

    st->feedback ^= ks[0] ^ ks[HYDRA_LANES * HYDRA_LANE_WORDS - 1];
    st->selector += ks[3] ^ ks[HYDRA_LANES * HYDRA_LANE_WORDS / 2];
}


/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  PUBLIC API
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

/*
 * hydra_init: Initialize cipher with key and nonce.
 *   key:   32 bytes (256-bit)
 *   nonce: 16 bytes (128-bit, must be unique per message)
 */
static void hydra_init(hydra_state_t *st,
                       const uint8_t key[HYDRA_KEY_SIZE],
                       const uint8_t nonce[HYDRA_NONCE_SIZE])
{
    memset(st, 0, sizeof(*st));
    hydra_key_schedule(st, key, nonce);
}

/*
 * hydra_crypt: Encrypt or decrypt (XOR with keystream).
 *   in:   input buffer
 *   out:  output buffer (may alias in)
 *   len:  byte count
 */
static void hydra_crypt(hydra_state_t *st,
                        const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t block[HYDRA_BLOCK_BYTES];
    size_t  block_pos = HYDRA_BLOCK_BYTES; /* force first generation */

    for (size_t i = 0; i < len; i++) {
        if (block_pos >= HYDRA_BLOCK_BYTES) {
            hydra_generate_block(st, block);
            block_pos = 0;
        }
        out[i] = in[i] ^ block[block_pos];
        block_pos++;
    }

    /* wipe keystream block from stack */
    memset(block, 0, sizeof(block));
}

/*
 * hydra_keystream: Generate raw keystream (no input data).
 */
static void hydra_keystream(hydra_state_t *st,
                            uint8_t *out, size_t len)
{
    uint8_t block[HYDRA_BLOCK_BYTES];
    size_t  block_pos = HYDRA_BLOCK_BYTES;

    for (size_t i = 0; i < len; i++) {
        if (block_pos >= HYDRA_BLOCK_BYTES) {
            hydra_generate_block(st, block);
            block_pos = 0;
        }
        out[i] = block[block_pos];
        block_pos++;
    }

    memset(block, 0, sizeof(block));
}

#endif /* HYDRA_STREAM_H */
