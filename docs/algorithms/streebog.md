# Streebog (GOST R 34.11-2012)

## Overview

Streebog is the Russian federal standard hash function, standardized as GOST R 34.11-2012. It was adopted as a replacement for the older GOST R 34.11-94 and is used in Russian government and commercial cryptographic applications.

## Variants

| Variant | Output | Block Size | Rounds | Standard |
|---------|--------|-----------|--------|----------|
| **Streebog-256** | 256 bits (32 bytes) | 64 bytes | 12 | GOST R 34.11-2012 |
| **Streebog-512** | 512 bits (64 bytes) | 64 bytes | 12 | GOST R 34.11-2012 |

## Algorithm Design

### Merkle-Damgård with Checksum

Streebog extends the traditional Merkle-Damgård construction with an additional checksum accumulator:

```
For each 512-bit block M_i:
  h = g(h, M_i)          # compression function
  N = N + 512             # message length counter
  Σ = Σ + M_i             # checksum accumulator

Finalization:
  h = g(h, N)             # compress length
  h = g(h, Σ)             # compress checksum
```

The checksum provides additional protection against length-extension attacks.

### Compression Function g(h, m)

The compression function uses a 12-round block cipher in Miyaguchi-Preneel mode:

1. **LPS transformation** — Linear, Permutation, Substitution (applied in reverse order)
2. **Key schedule** — derived from the hash state `h`
3. **XOR** with message block

### LPS Transformation

Each round applies:

| Step | Operation | Purpose |
|------|-----------|---------|
| **S** (Substitution) | 64 parallel 8-bit S-boxes | Non-linearity |
| **P** (Permutation) | Byte transposition | Diffusion |
| **L** (Linear) | 64-bit Galois field multiplication | Avalanche |

### 64-bit Lane Processing

The 512-bit state is processed as 8 × 64-bit lanes, enabling efficient 64-bit arithmetic on modern CPUs.

## StreamHash Implementation

StreamHash implements both Streebog variants natively with optimized S-box lookups and linear transformation.

### Key Optimizations

- **Pre-computed lookup tables** for the combined LPS transformation
- **64-bit lane processing** — leverages `ulong` arithmetic
- **Abstract base class** — shared compression logic for 256 and 512 variants
- **Efficient checksum accumulation** — 512-bit addition via 64-bit carries

### Usage

```csharp
using StreamHash.Core;

// Streebog-256
var hasher256 = HashFacade.Create(HashAlgorithmNames.Streebog256);
hasher256.Update(data);
byte[] hash256 = hasher256.FinalizeHash();

// Streebog-512
var hasher512 = HashFacade.Create(HashAlgorithmNames.Streebog512);
hasher512.Update(data);
byte[] hash512 = hasher512.FinalizeHash();
```

## Performance (1MB data)

| Variant | StreamHash | BouncyCastle | Ratio |
|---------|----------:|------------:|------:|
| Streebog-512 | 14.52 ms | 23.30 ms | **0.62x** (1.6x faster) |
| Streebog-256 | 14.74 ms | 23.29 ms | **0.63x** (1.6x faster) |

StreamHash is **1.6x faster** than BouncyCastle for both Streebog variants.

## Security

- **Russian federal standard** — mandatory for government applications
- **Collision resistance**: 2^128 (Streebog-256), 2^256 (Streebog-512)
- **No known practical attacks** as of 2026
- **IND-CPA secure** block cipher construction

## References

- [GOST R 34.11-2012 Specification](https://tc26.ru/en/standards/national-standards/)
- [RFC 6986 — GOST R 34.11-2012: Hash Function](https://www.rfc-editor.org/rfc/rfc6986)
