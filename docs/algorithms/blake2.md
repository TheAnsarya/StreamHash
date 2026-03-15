# BLAKE2

## Overview

BLAKE2 is a cryptographic hash function designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein. It is faster than MD5, SHA-1, SHA-2, and SHA-3, while providing at least as much security as the latest standard SHA-3.

BLAKE2 is based on BLAKE, which was a SHA-3 finalist. It comes in two main variants:

- **BLAKE2b** — optimized for 64-bit platforms, up to 64-byte digests
- **BLAKE2s** — optimized for 32-bit platforms, up to 32-byte digests

## Variants

| Property | BLAKE2b | BLAKE2s |
|----------|---------|---------|
| **Output Size** | 1-64 bytes (configurable) | 1-32 bytes (configurable) |
| **Block Size** | 128 bytes | 64 bytes |
| **Word Size** | 64-bit | 32-bit |
| **Rounds** | 12 | 10 |
| **Max Input** | Unlimited | Unlimited |
| **State Size** | 8 × 64-bit words | 8 × 32-bit words |

## Algorithm Design

BLAKE2 uses a modified ChaCha stream cipher as its compression function core:

1. **Initialization**: Set up an 8-word state vector from IV, XORed with parameter block
2. **Compression**: Process 128-byte (BLAKE2b) or 64-byte (BLAKE2s) blocks
3. **Finalization**: XOR the state with the two halves of the chaining value

### Compression Function

The compression function operates on a 4×4 matrix of words using the `G` mixing function:

```
G(a, b, c, d) with message words:
  a = a + b + m[sigma[r][2i]]
  d = (d ^ a) >>> R1
  c = c + d
  b = (b ^ c) >>> R2
  a = a + b + m[sigma[r][2i+1]]
  d = (d ^ a) >>> R3
  c = c + d
  b = (b ^ c) >>> R4
```

Where R1/R2/R3/R4 are rotation constants (32/24/16/63 for BLAKE2b, 16/12/8/7 for BLAKE2s).

### Message Schedule

BLAKE2 uses the SIGMA permutation table (same as BLAKE) to select message words for each round:

| Round | σ permutation |
|-------|---------------|
| 0 | 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 |
| 1 | 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 |
| ... | (10 permutations, cycled for rounds 10-11 in BLAKE2b) |

## StreamHash Implementation

StreamHash implements BLAKE2b and BLAKE2s in pure safe C# with fully unrolled compression rounds for maximum performance.

### Key Optimizations

- **Fully unrolled rounds** — all 12 (BLAKE2b) / 10 (BLAKE2s) rounds are unrolled at compile time
- **Local variable caching** — state and message words loaded into locals before compression
- **Zero allocations** in hot paths via pre-allocated buffers
- **Configurable output size** — supports all valid digest lengths

### Usage

```csharp
using StreamHash.Core;

// Default 32-byte BLAKE2b hash
var hasher = HashFacade.Create(HashAlgorithmNames.Blake2b);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();

// Streaming
using var blake2b = new NativeBlake2bDigest(digestSize: 32);
blake2b.Update(chunk1);
blake2b.Update(chunk2);
byte[] result = blake2b.FinalizeHash();
```

## Performance (1MB data)

| Implementation | BLAKE2b | BLAKE2s |
|---|---:|---:|
| Blake2Fast (SSE2-AVX512 SIMD) | 732 µs | 1,220 µs |
| BouncyCastle (AVX2/SSSE3 SIMD) | 840 µs | 1,337 µs |
| **StreamHash (safe C#)** | **1,060 µs** | **1,586 µs** |

StreamHash's pure C# implementation achieves **1.19-1.26x** of the SIMD-accelerated BouncyCastle implementation — competitive for a non-SIMD approach.

**Optimization history**: 6.29x → 4.42x (local variables) → 1.59x (full round unrolling) → **1.19-1.26x** (safe refactor)

## Security

- **Collision resistance**: 2^(n/2) for n-bit digest
- **Preimage resistance**: 2^n for n-bit digest
- **Standardized**: RFC 7693
- **Widely used**: Argon2 password hashing, WireGuard, libsodium

## References

- [RFC 7693 — The BLAKE2 Cryptographic Hash and MAC](https://www.rfc-editor.org/rfc/rfc7693)
- [BLAKE2 Official Website](https://www.blake2.net/)
- [BLAKE2 Paper](https://blake2.net/blake2.pdf)
