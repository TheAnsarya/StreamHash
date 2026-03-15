# RIPEMD Family

## Overview

RIPEMD (RACE Integrity Primitives Evaluation Message Digest) is a family of cryptographic hash functions developed by Hans Dobbertin, Antoon Bosselaers, and Bart Preneel. Originally created for the EU RACE project, the family provides multiple output sizes with a unique dual-line parallel construction.

## Variants

| Variant | Output | Block Size | Rounds | Security Level |
|---------|--------|-----------|--------|---------------|
| **RIPEMD-128** | 128 bits (16 bytes) | 64 bytes | 64 | 64-bit collision resistance |
| **RIPEMD-160** | 160 bits (20 bytes) | 64 bytes | 80 | 80-bit collision resistance |
| **RIPEMD-256** | 256 bits (32 bytes) | 64 bytes | 64 | 128-bit (extended RIPEMD-128) |
| **RIPEMD-320** | 320 bits (40 bytes) | 64 bytes | 80 | 160-bit (extended RIPEMD-160) |

## Algorithm Design

### Merkle-Damgård Construction

All RIPEMD variants use Merkle-Damgård with a unique **dual parallel line** structure:

```
Input Block → [Left Line]  → combine → Output
            → [Right Line] →
```

### Dual-Line Architecture

Each compression processes the same input block through TWO independent paths with different:

- **Round constants** — different additive constants per line
- **Rotation amounts** — different bit rotation values
- **Word selection order** — different message word scheduling

The two lines converge in the finalization step.

### Round Functions

RIPEMD-160 (and RIPEMD-320) use 5 round functions applied over 80 rounds:

| Rounds | Function | Description |
|--------|----------|-------------|
| 0-15 | f(x, y, z) = x ⊕ y ⊕ z | XOR |
| 16-31 | f(x, y, z) = (x ∧ y) ∨ (¬x ∧ z) | Selection |
| 32-47 | f(x, y, z) = (x ∨ ¬y) ⊕ z | Majority variant |
| 48-63 | f(x, y, z) = (x ∧ z) ∨ (y ∧ ¬z) | Selection variant |
| 64-79 | f(x, y, z) = x ⊕ (y ∨ ¬z) | Asymmetric XOR |

RIPEMD-128 (and RIPEMD-256) use 4 round functions over 64 rounds.

### Extended Variants (256, 320)

RIPEMD-256 and RIPEMD-320 are NOT simply longer versions—they run two parallel instances of RIPEMD-128 and RIPEMD-160 respectively with cross-chaining between the parallel lines.

## StreamHash Implementation

StreamHash implements all four RIPEMD variants natively in pure safe C#.

### Key Features

- **32-bit word operations** — uses `uint` arithmetic throughout
- **Pre-computed message word indices** — avoids runtime computation
- **Dual-line processing** — faithful implementation of the parallel structure
- **Configurable variants** — selects round count/function based on output size

### Usage

```csharp
using StreamHash.Core;

// RIPEMD-160 (most common, used by Bitcoin)
var hasher = HashFacade.Create(HashAlgorithmNames.Ripemd160);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();
```

## Performance (1MB data)

| Variant | StreamHash | BouncyCastle | Ratio |
|---------|----------:|------------:|------:|
| RIPEMD-128 | 3.49 ms | 4.25 ms | **0.82x** (1.2x faster) |
| RIPEMD-160 | 3.02 ms | 4.33 ms | **0.70x** (1.4x faster) |
| RIPEMD-256 | 3.43 ms | 3.52 ms | 0.97x (~equal) |
| RIPEMD-320 | 5.36 ms | 4.81 ms | 1.11x (slightly slower) |

StreamHash is significantly faster for RIPEMD-128 and RIPEMD-160, at parity for RIPEMD-256, and slightly slower for RIPEMD-320.

## Security

- **RIPEMD-160** is the most widely used variant, notably in Bitcoin address generation
- **RIPEMD-128** provides only 64-bit collision resistance (not recommended for new applications)
- **No known practical attacks** on RIPEMD-160 as of 2026
- **RIPEMD-256/320** provide larger output but same security level as their base variants

## References

- [RIPEMD-160: A Strengthened Version of RIPEMD](https://homes.esat.kuleuven.be/~bosMDela/ripemd160.html)
- [ISO/IEC 10118-3:2004](https://www.iso.org/standard/39876.html)
- [Original RIPEMD-160 Paper](https://link.springer.com/chapter/10.1007/3-540-60865-6_44)
