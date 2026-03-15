# MD Family (MD2, MD4, MD5)

## Overview

The MD (Message Digest) family was designed by Ronald Rivest at MIT. MD5 is the most widely known, but StreamHash also implements MD2 and MD4 for completeness and legacy verification.

## Variants

| Variant | Output | Block Size | Rounds | Designer | Year |
|---------|--------|-----------|--------|----------|------|
| **MD2** | 128 bits (16 bytes) | 16 bytes | 18 × 48 | Rivest | 1989 |
| **MD4** | 128 bits (16 bytes) | 64 bytes | 48 | Rivest | 1990 |
| **MD5** | 128 bits (16 bytes) | 64 bytes | 64 | Rivest | 1992 |

## MD2

### Design

MD2 is unique among the MD family—it uses byte-level operations rather than 32-bit words:

- **S-box substitution** — based on digits of π
- **Checksum** — 16-byte checksum appended before final hash
- **18 rounds** of 48-byte state processing

### Characteristics

- Extremely slow by modern standards (~10 MB/s)
- Designed for 8-bit processors
- Provably secure under certain assumptions about the checksum

## MD4

### Design

MD4 introduced the Merkle-Damgård construction with 32-bit operations:

- **48 rounds** split into 3 groups of 16
- Three different boolean functions (F, G, H)
- 32-bit word operations with left rotations

### Security

MD4 is **completely broken** — collisions can be found in milliseconds.

## MD5

### Design

MD5 is an improved version of MD4 with:

- **64 rounds** split into 4 groups of 16 (vs MD4's 48 in 3 groups)
- Four boolean functions (F, G, H, I)
- More complex message word selection
- Additional per-round additive constants (based on sin function)

### Security

MD5 is **cryptographically broken** for collision resistance. Practical collision attacks exist. Still used as a checksum for data integrity (not security).

## StreamHash Implementation

### MD2

- Full native implementation with S-box and checksum
- Pre-computed π-based substitution table
- Byte-level processing (no 32-bit word operations)

### MD4

- Native implementation, 1.42 ms for 1 MB (0.85x vs BouncyCastle)
- Pure 32-bit operations with left rotations

### MD5

- Uses .NET's hardware-accelerated `System.Security.Cryptography.MD5`
- 1.66 ms for 1 MB (0.64x vs BouncyCastle — 1.6x faster)

### Usage

```csharp
using StreamHash.Core;

var md2 = HashFacade.Create(HashAlgorithmNames.Md2);
var md4 = HashFacade.Create(HashAlgorithmNames.Md4);
var md5 = HashFacade.Create(HashAlgorithmNames.Md5);

md5.Update(data);
byte[] hash = md5.FinalizeHash();
```

## Performance (1MB data)

| Variant | StreamHash | BouncyCastle | Ratio |
|---------|----------:|------------:|------:|
| MD4 | 1.42 ms | 1.68 ms | **0.85x** (1.2x faster) |
| MD5 | 1.66 ms | 2.58 ms | **0.64x** (1.6x faster) |
| MD2 | 97.70 ms | 101.7 ms | 0.96x (~equal) |

## Security Warning

**None of the MD family should be used for cryptographic security:**

- **MD2** — slow and proven insecure
- **MD4** — completely broken, trivial collisions
- **MD5** — practical collision attacks exist (chosen-prefix attacks demonstrated)

These are included for legacy compatibility, file integrity checking, and verification against reference outputs.

## References

- [RFC 1319 — The MD2 Message-Digest Algorithm](https://www.rfc-editor.org/rfc/rfc1319)
- [RFC 1320 — The MD4 Message-Digest Algorithm](https://www.rfc-editor.org/rfc/rfc1320)
- [RFC 1321 — The MD5 Message-Digest Algorithm](https://www.rfc-editor.org/rfc/rfc1321)
