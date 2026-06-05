# HydraStream Cipher v1.0 — Design Document

## Overview

HydraStream is a symmetric-key stream cipher designed to maximize resistance to static analysis when executed inside a code virtual machine. It produces a keystream XORed with plaintext, using a 256-bit key and 128-bit nonce.

**This is NOT a cryptographically audited cipher.** It is designed for the specific goal of being hard to reverse-engineer inside a VM. For real-world cryptographic security, use AES-CTR or ChaCha20-Poly1305.

---

## Cipher Parameters

| Parameter       | Value           |
|-----------------|-----------------|
| Key size        | 256 bits        |
| Nonce size      | 128 bits        |
| State size      | 4 lanes × 8 × 32-bit = 1024 bits + 128 bits control |
| Block output    | 128 bytes       |
| Mixing rounds   | 12 per block    |
| Warm-up rounds  | 20 at init      |
| S-box pool      | 4 × 256-byte tables |

---

## Architecture

```
          256-bit Key + 128-bit Nonce
                    │
            ┌───────▼────────┐
            │  Key Schedule   │  (branch-heavy, lane-dependent init)
            │  + 20 warm-up   │
            └───────┬────────┘
                    │
    ┌───────┬───────┼───────┬───────┐
    ▼       ▼       ▼       ▼       │
 Lane 0  Lane 1  Lane 2  Lane 3    │  4 parallel state lanes
 8×u32   8×u32   8×u32   8×u32     │  (8 words each)
    │       │       │       │       │
    └───┬───┘───┬───┘───┬───┘       │
        ▼       ▼       ▼           │
   Cross-Lane Butterfly Mix         │  state-dependent permutation
        │       │       │           │
        ▼       ▼       ▼           │
   ┌────────────────────────┐       │
   │  12 Rounds per block:  │       │
   │  1. Data-dep word perm │       │  in-lane word reorder
   │  2. Pairwise NL mix    │       │  8-way branching function
   │  3. Polymorphic S-box  │       │  4 tables, state-selected
   │  4. Round key twist    │       │  add vs XOR by state
   └────────────┬───────────┘       │
                │                   │
                ▼                   │
        128-byte keystream block    │
                │                   │
                ▼                   │
        XOR with plaintext          │
                │                   │
       counter++ & state evolve ────┘
```

---

## Anti-Reverse-Engineering Features

### 1. Heavy Branching (8-way + nested)

The core `hydra_nonlinear_mix` function uses a **3-bit tag** derived from runtime state to select among 8 completely different math paths. Each path contains 1–3 additional nested branches. This means:

- **Static analysis** cannot determine which path executes without solving the full state.
- **VM translation** turns each branch into an opaque dispatch through the VM's handler table.
- **Branch coverage** is near-uniform (~12.5% per tag), so no path can be pruned as "rare."

Total branch points per block generation: ~300+

### 2. Cross-Variable Dependencies

Every branch condition is derived from variables that were computed by previous operations on other variables:

```
feedback ──► ctrl ──► tag (selects branch)
selector ──► shift (selects rotation amount)
a ^ b    ──► mask (used inside every branch path)
```

This makes it impossible to analyze any single variable in isolation. In a VM context, the attacker must track the full register file.

### 3. Polymorphic S-box Selection

Instead of one fixed substitution table, HydraStream has **4 S-boxes** and selects which byte uses which table based on the `selector` register. Additionally:

- When selector nibbles match, it **cascades** two S-boxes (double substitution).
- The selector evolves after every substitution, so the same code path produces different substitutions at different times.

### 4. State-Dependent Execution Order

The lane processing order within each round is **shuffled** based on `selector ^ feedback`. The word processing order within each lane is **sorted** by data-dependent comparison. This means:

- Two runs with different keys execute operations in a completely different order.
- VM trace recordings from one key reveal nothing about another.

### 5. Multi-Lane Cross-Mixing

The 4 lanes cannot be analyzed independently because `hydra_cross_lane_mix` couples them via state-dependent butterfly permutations. Which lanes cross-mix and how depends on `feedback ^ selector`.

### 6. Forward Secrecy via State Evolution

After extracting each keystream block, the internal state is irreversibly evolved. Even if an attacker captures the state at time T, they cannot recover keystream at time T−1.

---

## VM Integration Guide

### Recommended VM properties

1. **Register-based VM** (not stack-based) — preserves cross-variable dependencies as register-to-register operations.

2. **Opaque dispatch** — each branch should compile to an indirect jump through a handler table. The 8-way switch in `hydra_nonlinear_mix` becomes 8 handler addresses resolved at runtime.

3. **Instruction encoding** — encode each math op as a VM opcode. The cipher uses: ADD, XOR, OR, AND, ROTL, ROTR, MUL, compare-and-branch, S-box-lookup, byte-extract. This gives ~12 distinct opcodes.

4. **Anti-pattern-match** — the nested branches inside each switch case should be compiled as separate handler chains, not inlined. This prevents pattern matching across the flattened bytecode.

### Opcode budget estimate

| Operation          | Approximate VM ops per block |
|--------------------|------------------------------|
| Rotations          | ~200                         |
| XOR/ADD/MUL        | ~350                         |
| Branches           | ~300                         |
| S-box lookups      | ~256                         |
| Memory load/store  | ~400                         |
| **Total**          | **~1,500 ops per 128 bytes** |

### Branch density metric

The cipher achieves approximately **1 branch per 5 VM operations**, which is well above the threshold (~1:20) where VM obfuscation provides meaningful protection against automated deobfuscation tools.

---

## Test Results

```
Roundtrip:           PASS (encrypt then decrypt = original)
Nonce sensitivity:   100% bytes differ (1-bit nonce change)
Key sensitivity:     100% bytes differ (1-bit key change)
Bit avalanche:       0.5033 (ideal: 0.5000)
Branch distribution: 11.5%–13.9% per tag (near-uniform)
Throughput:          ~6.3 MB/s (unoptimized, single-thread)
```

---

## File Inventory

| File              | Description                              |
|-------------------|------------------------------------------|
| `hydra_stream.h`  | Header-only cipher implementation        |
| `hydra_test.c`    | Test suite with 6 tests                  |
| `DESIGN.md`       | This document                            |

---

## Usage Example

```c
#include "hydra_stream.h"

uint8_t key[32]   = { /* your 256-bit key */ };
uint8_t nonce[16] = { /* unique per message */ };

hydra_state_t state;
hydra_init(&state, key, nonce);

// Encrypt
hydra_crypt(&state, plaintext, ciphertext, length);

// Decrypt (re-init with same key+nonce)
hydra_init(&state, key, nonce);
hydra_crypt(&state, ciphertext, decrypted, length);
```
