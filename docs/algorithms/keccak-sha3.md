# Keccak / SHA-3

## Overview

Keccak is the cryptographic hash function family designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. It won the NIST SHA-3 competition in 2012 and was standardized as SHA-3 (FIPS 202).

Keccak uses a sponge construction with a 1600-bit state and 24 rounds of the Keccak-f permutation.

## Variants

### SHA-3 (FIPS 202)

| Variant | Output | Rate (r) | Capacity (c) | Security |
|---------|--------|----------|---------------|----------|
| SHA3-224 | 224 bits | 1152 bits | 448 bits | 112 bits |
| SHA3-256 | 256 bits | 1088 bits | 512 bits | 128 bits |
| SHA3-384 | 384 bits | 832 bits | 768 bits | 192 bits |
| SHA3-512 | 512 bits | 576 bits | 1024 bits | 256 bits |

### Original Keccak (Pre-FIPS)

| Variant | Output | Rate (r) | Capacity (c) | Notes |
|---------|--------|----------|---------------|-------|
| Keccak-256 | 256 bits | 1088 bits | 512 bits | Different padding from SHA3-256 |
| Keccak-512 | 512 bits | 576 bits | 1024 bits | Different padding from SHA3-512 |

**Key difference**: SHA-3 uses domain separation padding (`0x06`), while original Keccak uses `0x01`.

## Algorithm Design

### Sponge Construction

```
Input → [Absorb] → Permutation → [Squeeze] → Output
         r bits       f=1600        r bits
```

1. **Absorb Phase**: XOR input blocks (r bits at a time) into state, apply permutation
2. **Squeeze Phase**: Extract output blocks from state, apply permutation between blocks

### Keccak-f[1600] Permutation

The state is a 5×5 array of 64-bit lanes (1600 bits total). Each of 24 rounds applies five steps:

| Step | Operation | Purpose |
|------|-----------|---------|
| **θ (theta)** | Column parity + XOR | Linear diffusion |
| **ρ (rho)** | Lane rotation | Inter-slice diffusion |
| **π (pi)** | Lane permutation | Position shuffling |
| **χ (chi)** | Non-linear mixing | S-box equivalent |
| **ι (iota)** | Round constant XOR | Break symmetry |

### Round Constants

24 round constants derived from a linear feedback shift register (LFSR):

```
RC[0]  = 0x0000000000000001    RC[12] = 0x000000008000808b
RC[1]  = 0x0000000000008082    RC[13] = 0x800000000000008b
RC[2]  = 0x800000000000808a    RC[14] = 0x8000000080008089
...                             ...
RC[11] = 0x8000000080008081    RC[23] = 0x8000000080008008
```

## StreamHash Implementation

StreamHash implements Keccak natively in pure safe C# with significant optimizations.

### Key Optimizations

- **Fully unrolled round function** — all 24 rounds are inlined, eliminating loop overhead
- **Lane-complement optimization** — reduces gate count in χ step
- **Zero allocations** in hot path via pre-allocated 200-byte state buffer
- **Support for all variants**: SHA3-224/256/384/512, Keccak-256/512

### Usage

```csharp
using StreamHash.Core;

// SHA3-256
var hasher = HashFacade.Create(HashAlgorithmNames.Sha3_256);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();

// Keccak-256 (Ethereum style)
var keccak = HashFacade.Create(HashAlgorithmNames.Keccak256);
keccak.Update(data);
byte[] ethHash = keccak.FinalizeHash();
```

## Performance (1MB data)

| Algorithm | StreamHash | BouncyCastle | Ratio |
|-----------|----------:|------------:|------:|
| Keccak-512 | 6.53 ms | 6.87 ms | **0.95x** (faster!) |
| SHA3-384 | 4.35 ms | 4.34 ms | 1.00x (equal) |
| SHA3-224 | 3.13 ms | 3.09 ms | 1.01x (equal) |
| Keccak-256 | 3.45 ms | 3.40 ms | 1.02x (~equal) |
| SHA3-512 | 6.32 ms | 6.19 ms | 1.02x (~equal) |
| SHA3-256 | 3.51 ms | 3.30 ms | 1.06x (near parity) |

**Optimization history**: 1.49-1.63x → **0.95-1.06x** after loop unrolling optimization. StreamHash now matches or beats BouncyCastle on all Keccak/SHA-3 variants.

## Security

- **Collision resistance**: 2^(n/2) for n-bit output
- **Preimage resistance**: 2^n
- **Standardized**: FIPS 202 (SHA-3), NIST SP 800-185 (derived functions)
- **Sponge security**: Provides `min(2^(c/2), 2^n)` against generic attacks

## References

- [FIPS 202 — SHA-3 Standard](https://csrc.nist.gov/pubs/fips/202/final)
- [The Keccak Reference](https://keccak.team/keccak_specs_summary.html)
- [Keccak Team Website](https://keccak.team/)
