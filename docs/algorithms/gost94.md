# GOST R 34.11-94

## Overview

GOST R 34.11-94 is the original Russian federal hash standard, preceding Streebog. It is based on the GOST 28147-89 block cipher and produces a 256-bit hash. While superseded by Streebog (GOST R 34.11-2012), it remains important for legacy compatibility and verification.

## Algorithm Details

| Property | Value |
|----------|-------|
| **Output Size** | 256 bits (32 bytes) |
| **Block Size** | 256 bits (32 bytes) |
| **Rounds** | 32 (GOST cipher) × 4 (compression rounds) |
| **Based On** | GOST 28147-89 block cipher |
| **S-box Variant** | D-A (CryptoPro) |

## Algorithm Design

### Compression Function

The compression function uses four applications of the GOST 28147-89 cipher in a custom mode:

1. **Key Generation** — derive four 256-bit keys from the hash state and message block
2. **Encryption** — encrypt the hash state using GOST 28147-89 with each key
3. **Output Mixing** — XOR chain of encrypted values with input

### GOST 28147-89 Cipher

The underlying cipher is a 32-round Feistel network with:

- 8 S-boxes (4-bit to 4-bit substitutions)
- 32 rounds of Feistel operations
- 256-bit key split into eight 32-bit subkeys

### S-box Selection

GOST 94 supports multiple S-box definitions. StreamHash uses the **D-A (CryptoPro)** variant, which is the most widely deployed.

### Processing Steps

```
For each 256-bit block:
  1. Generate keys: K1, K2, K3, K4 from h ⊕ m
  2. Encrypt: E_K1(h), E_K2(h), E_K3(h), E_K4(h)
  3. Mix outputs with XOR cascade
  4. Update length counter (Σ) and checksum (L)

Finalization:
  Compress length counter
  Compress checksum
```

## StreamHash Implementation

StreamHash implements GOST-94 natively with significant memory optimization.

### Key Optimizations

- **Inline S-box lookups** — pre-computed tables for fast substitution
- **Optimized key schedule** — minimizes allocations during key generation
- **Only 728 bytes allocated** — compared to BouncyCastle's 25 MB(!)
- **Pure safe C#** — no unsafe code

### Memory Advantage

| Implementation | Allocation |
|---|---:|
| BouncyCastle | 25,165,904 B (~25 MB) |
| **StreamHash** | **728 B** |

**35,000x less memory** — BouncyCastle allocates ~25 MB per hash due to repeated array creation in the key schedule. StreamHash pre-computes and reuses buffers.

### Usage

```csharp
using StreamHash.Core;

var hasher = HashFacade.Create(HashAlgorithmNames.Gost94);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();
```

## Performance (1MB data)

| Implementation | Time | Ratio |
|---|---:|---:|
| **StreamHash** | **107.6 ms** | **0.70x** |
| BouncyCastle | 154.7 ms | 1.00x |

StreamHash is **1.4x faster** with **35,000x less memory**.

## Security

- **Superseded** by Streebog (GOST R 34.11-2012) since 2012
- **Collision attacks** exist in reduced-round variants
- **Still required** for legacy system compatibility
- Not recommended for new applications

## References

- [RFC 5831 — GOST R 34.11-94: Hash Function Algorithm](https://www.rfc-editor.org/rfc/rfc5831)
- [GOST 28147-89 Block Cipher](https://en.wikipedia.org/wiki/GOST_(block_cipher))
