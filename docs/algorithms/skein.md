# Skein

## Overview

Skein is a cryptographic hash function family designed by Bruce Schneier, Niels Ferguson, Stefan Lucks, Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas, and Jesse Walker. It was a SHA-3 finalist and is built on the Threefish tweakable block cipher.

## Variants

| Variant | Internal State | Block Size | Default Output | Threefish Block |
|---------|---------------|-----------|---------------|-----------------|
| **Skein-256** | 256 bits | 32 bytes | 256 bits | Threefish-256 |
| **Skein-512** | 512 bits | 64 bytes | 512 bits | Threefish-512 |
| **Skein-1024** | 1024 bits | 128 bytes | 1024 bits | Threefish-1024 |

All variants support arbitrary output lengths.

## Algorithm Design

### UBI (Unique Block Iteration) Chaining

Skein uses the UBI chaining mode based on Matyas-Meyer-Oseas:

```
H_i = E(H_{i-1}, M_i) ⊕ M_i
```

Where `E` is the Threefish tweakable block cipher.

### Threefish Block Cipher

Threefish is a tweakable block cipher using only three operations:

- **Addition** (mod 2^64)
- **XOR**
- **Rotation** (bitwise)

No S-boxes, no table lookups — designed for constant-time execution.

| Threefish Variant | Rounds | Words |
|-------------------|--------|-------|
| Threefish-256 | 72 | 4 × 64-bit |
| Threefish-512 | 72 | 8 × 64-bit |
| Threefish-1024 | 80 | 16 × 64-bit |

### Tweak

The 128-bit tweak encodes:

- **Position** — byte offset in the message (bits 0-95)
- **Tree level** — for tree hashing (bits 112-118)
- **Type** — message, key, config, output, etc. (bits 120-125)
- **First/Final flags** — block position markers (bits 126-127)

### Processing Phases

1. **Configuration block** — hash parameters (output length, tree structure)
2. **Message blocks** — process input data through UBI chain
3. **Output block** — generate final hash via additional Threefish call

## StreamHash Implementation

StreamHash implements all three Skein variants with an optimized Threefish core.

### Key Optimizations

- **Optimized Threefish block cipher** — key schedule computation interleaved with rounds
- **Abstract base class** — shared `Skein` logic with variant-specific subclasses
- **Pre-computed subkey injection** at every 4 rounds
- **Configurable output size** — supports arbitrary digest lengths

### Usage

```csharp
using StreamHash.Core;

// Skein-512 with default 512-bit output
var hasher = HashFacade.Create(HashAlgorithmNames.Skein512);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();

// Skein-256 with 256-bit output
var skein256 = HashFacade.Create(HashAlgorithmNames.Skein256);
```

## Performance (1MB data)

| Variant | StreamHash | BouncyCastle | Ratio |
|---------|----------:|------------:|------:|
| Skein-512 | 1.52 ms | 2.28 ms | **0.66x** (1.5x faster) |
| Skein-1024 | 2.21 ms | 2.84 ms | **0.78x** (1.3x faster) |
| Skein-256 | 2.26 ms | 2.83 ms | **0.80x** (1.3x faster) |

StreamHash is **1.3-1.5x faster** than BouncyCastle across all Skein variants.

## Security

- **SHA-3 finalist** — strong security margin with many rounds
- **No S-boxes** — resistant to cache-timing side channels
- **Tweakable** — supports MAC, KDF, PRG, and personalization natively
- **Collision resistance**: 2^(n/2) for n-bit output

## References

- [Skein Hash Function Family](https://www.schneier.com/academic/skein/)
- [The Skein Hash Function Family (Paper)](https://www.schneier.com/wp-content/uploads/2015/01/skein1.3.pdf)
- [Threefish Block Cipher Specification](https://www.schneier.com/academic/skein/threefish.html)
