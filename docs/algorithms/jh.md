# JH

## Overview

JH is a cryptographic hash function designed by Hongjun Wu. It was one of the five finalists in the NIST SHA-3 competition. JH uses a 1024-bit internal state with an AES-like structure and pre-computed S-box lookup tables.

## Variants

| Variant | Output | State Size | Block Size | Rounds |
|---------|--------|-----------|-----------|--------|
| **JH-256** | 256 bits (32 bytes) | 1024 bits | 64 bytes | 42 |
| **JH-512** | 512 bits (64 bytes) | 1024 bits | 64 bytes | 42 |

## Algorithm Design

### Generalized AES Structure

JH's round function uses 4-bit S-boxes arranged in an AES-like structure:

1. **S-box Layer** — 256 parallel 4-bit S-boxes
2. **Linear Transformation** — diffusion via bit permutation
3. **Constant Addition** — round-dependent constants

### Compression Function

JH uses a wide-pipe Merkle-Damgård construction with a 1024-bit state:

```
H_i = F(H_{i-1}) ⊕ M_i ⊕ (H_{i-1} truncated)
```

Where `F` applies 42 rounds of the AES-like transformation.

### Pre-computed Lookup Tables

The combined S-box and linear transformation is pre-computed as byte-level lookup tables for efficiency, similar to AES T-tables.

## StreamHash Implementation

### Key Features

- **1024-bit state** — processed as 16 × 64-bit words
- **42 rounds** of AES-like transformation
- **Pre-computed byte-level S-box tables** for fast processing
- **Configurable output** — JH-256 and JH-512 variants

### Usage

```csharp
using StreamHash.Core;

var jh256 = HashFacade.Create(HashAlgorithmNames.JH256);
jh256.Update(data);
byte[] hash = jh256.FinalizeHash();

var jh512 = HashFacade.Create(HashAlgorithmNames.JH512);
```

## Security

- **SHA-3 finalist** — strong security analysis during the competition
- **1024-bit internal state** — very large security margin
- **No known attacks** better than generic for the full 42-round version
- **128-bit security** (JH-256), **256-bit security** (JH-512)

## References

- [JH Hash Function (Specification)](https://www3.ntu.edu.sg/home/wuhj/research/jh/)
- [Hongjun Wu's JH Page](https://www3.ntu.edu.sg/home/wuhj/research/jh/jh_round3.pdf)
