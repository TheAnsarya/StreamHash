# SHA Family (Legacy Variants)

## Overview

StreamHash implements several SHA (Secure Hash Algorithm) variants that are not covered by .NET's built-in `System.Security.Cryptography` namespace. These are provided for completeness and legacy compatibility.

## Variants

| Variant | Output | Block Size | Rounds | Status |
|---------|--------|-----------|--------|--------|
| **SHA-0** | 160 bits (20 bytes) | 64 bytes | 80 | **Withdrawn** (1995) |
| **SHA-224** | 224 bits (28 bytes) | 64 bytes | 64 | Active (FIPS 180-4) |
| **SHA-512/224** | 224 bits (28 bytes) | 128 bytes | 80 | Active (FIPS 180-4) |
| **SHA-512/256** | 256 bits (32 bytes) | 128 bytes | 80 | Active (FIPS 180-4) |

**Note**: SHA-1, SHA-256, SHA-384, SHA-512 are implemented using .NET's hardware-accelerated `System.Security.Cryptography` implementations.

## SHA-0

### History

SHA-0 was the original Secure Hash Algorithm published as FIPS 180 in 1993. It was **withdrawn in 1995** and replaced by SHA-1, which adds a single left rotation in the message schedule to fix a weakness.

### Key Difference from SHA-1

```
SHA-0: W[i] = W[i-3] ⊕ W[i-8] ⊕ W[i-14] ⊕ W[i-16]
SHA-1: W[i] = (W[i-3] ⊕ W[i-8] ⊕ W[i-14] ⊕ W[i-16]) <<< 1  ← rotation added
```

The missing rotation in SHA-0 allows collision attacks. SHA-0 collisions have been found.

### Security Warning

**SHA-0 is broken.** Collisions can be found in practical time. Included only for historical reference and test verification.

## SHA-224

SHA-224 is a truncated version of SHA-256 with different initialization vectors.

### Relationship to SHA-256

- Same compression function (64 rounds, 32-bit words)
- Same block size (64 bytes)
- **Different IV** — derived from fractional parts of different primes
- **Truncated output** — 224 bits from 256-bit state (drops last 32-bit word)

## SHA-512/t Family

SHA-512/224 and SHA-512/256 are truncated variants of SHA-512, specified in FIPS 180-4.

### Custom IV Generation

The IVs for SHA-512/t are derived using a special procedure:

1. Take SHA-512's standard IV
2. XOR each word with `0xa5a5a5a5a5a5a5a5`
3. Hash the ASCII string "SHA-512/t" using this modified SHA-512
4. The resulting hash becomes the IV for SHA-512/t

### Advantages Over SHA-256

- **64-bit operations** — faster on 64-bit platforms
- **Larger block size** (128 bytes) — fewer compression calls for large inputs
- SHA-512/256 provides better throughput than SHA-256 on 64-bit CPUs

## StreamHash Implementation

### SHA-0

- Native implementation with 80 rounds of 32-bit operations
- Big-endian byte ordering
- Identical to SHA-1 except for the missing rotation

### SHA-224

- Native implementation reusing SHA-256 compression with different IV
- 64 rounds, 32-bit words, big-endian

### SHA-512/t

- Wraps .NET's `IncrementalHash` for hardware acceleration
- Custom IV generation per FIPS 180-4 specification
- 64-bit word operations, 128-byte blocks

### Usage

```csharp
using StreamHash.Core;

// SHA-0 (historical only)
var sha0 = HashFacade.Create(HashAlgorithmNames.Sha0);

// SHA-224
var sha224 = HashFacade.Create(HashAlgorithmNames.Sha224);

// SHA-512/256 (faster than SHA-256 on 64-bit)
var sha512_256 = HashFacade.Create(HashAlgorithmNames.Sha512_256);
```

## Performance (1MB data)

| Variant | StreamHash | BouncyCastle | Ratio |
|---------|----------:|------------:|------:|
| SHA-224 | 4.40 ms | 4.60 ms | 0.96x (~equal) |
| SHA-512/256 | 2.75 ms | 2.80 ms | 0.99x (equal) |
| SHA-512/224 | 2.73 ms | 2.74 ms | 1.00x (equal) |

SHA-512/t variants achieve parity with BouncyCastle by leveraging .NET's hardware acceleration.

## References

- [FIPS 180-4 — Secure Hash Standard (SHS)](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [SHA-0 Collision (Wang et al.)](https://link.springer.com/chapter/10.1007/978-3-540-85174-5_2)
