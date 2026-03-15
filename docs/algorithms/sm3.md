# SM3

## Overview

SM3 is a cryptographic hash function published by the Chinese National Cryptography Administration as part of the ShangMi (SM) suite of algorithms. It is standardized as GB/T 32905-2016 and is mandatory for Chinese commercial cryptographic applications.

## Algorithm Details

| Property | Value |
|----------|-------|
| **Output Size** | 256 bits (32 bytes) |
| **Block Size** | 64 bytes (512 bits) |
| **Word Size** | 32-bit |
| **Rounds** | 64 |
| **Standard** | GB/T 32905-2016 |

## Algorithm Design

SM3 is structurally similar to SHA-256 but uses different round constants, different rotation amounts, and a unique message expansion.

### State

Eight 32-bit state words: `V0` through `V7` (matching SHA-256's structure).

### Message Expansion

SM3's message expansion is unique:

1. Parse message block into 16 × 32-bit words `W[0..15]`
2. Extend to 68 words: `W[i] = P1(W[i-16] ^ W[i-9] ^ (W[i-3] <<< 15)) ^ (W[i-13] <<< 7) ^ W[i-6]`
3. Derive 64 additional words: `W'[i] = W[i] ^ W[i+4]`

Where `P1(x) = x ^ (x <<< 15) ^ (x <<< 23)` is a permutation function.

### Compression Function

64 rounds split into two phases:

| Rounds | T constant | Boolean function |
|--------|-----------|-----------------|
| 0-15 | 0x79cc4519 | FF_j = X ⊕ Y ⊕ Z |
| 16-63 | 0x7a879d8a | FF_j = (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z) |

### Key Differences from SHA-256

- Different message expansion (P1 permutation)
- Different rotation constants
- Two-phase round structure with different T constants
- GG function changes behavior at round 16

## StreamHash Implementation

StreamHash implements SM3 natively with pre-computed message expansion and unrolled loops.

### Key Optimizations

- **Pre-computed message expansion** — W and W' arrays computed before round loop
- **Unrolled compression loops** — separate loops for rounds 0-15 and 16-63
- **32-bit word operations** — pure `uint` arithmetic
- **Minimal allocations** — pre-allocated working buffers

### Usage

```csharp
using StreamHash.Core;

var hasher = HashFacade.Create(HashAlgorithmNames.Sm3);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();
```

## Performance (1MB data)

| Implementation | Time | Ratio |
|---|---:|---:|
| **StreamHash** | **4.88 ms** | **0.87x** |
| BouncyCastle | 5.64 ms | 1.00x |

StreamHash is **1.1x faster** than BouncyCastle.

## Security

- **Chinese national standard** — GB/T 32905-2016
- **256-bit security** — 128-bit collision resistance
- **Required for** Chinese government and commercial cryptography
- **ISO/IEC 10118-3:2018** — internationally recognized
- **Used in** Chinese SSL/TLS, digital signatures, certificate authorities

## References

- [GB/T 32905-2016 SM3 Cryptographic Hash Algorithm](https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml)
- [SM3 Description (English)](https://tools.ietf.org/html/draft-sca-cfrg-sm3-02)
