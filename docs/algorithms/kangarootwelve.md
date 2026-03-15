# KangarooTwelve (K12)

## Overview

KangarooTwelve is a fast extendable-output function (XOF) designed by Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, and Ronny Van Keer. It uses a reduced-round Keccak permutation (12 rounds instead of 24) with a tree hashing mode for parallelism.

## Algorithm Details

| Property | Value |
|----------|-------|
| **Output Size** | Variable (XOF — arbitrary length) |
| **Block Size** | 8192 bytes (chunk size) |
| **Permutation** | Keccak-p[1600, 12] |
| **Security** | 128-bit |
| **Rate** | 1344 bits (168 bytes) |

## Algorithm Design

### Reduced Rounds

KangarooTwelve uses Keccak-p[1600, 12] — only 12 rounds instead of Keccak's full 24 rounds. This gives approximately 2x the throughput of SHA3-256 while maintaining 128-bit security.

### Tree Hashing Mode

```
Input → 8192-byte chunks → Leaf hashes
                              ↓
                         Kangaroo hopping
                              ↓
                          Root hash → Output
```

1. **Single-chunk optimization**: If input ≤ 8192 bytes, use simple Keccak sponge (no tree)
2. **Multi-chunk**: First 8192 bytes hashed directly, remaining chunks produce 256-bit leaves
3. **Kangaroo hopping**: Leaves combined with final node using domain separation

### Domain Separation

KangarooTwelve uses specific byte suffixes:

- `0x07` — single chunk (no tree)
- `0x0B` — inner/leaf nodes
- `0xFF` — final node

### Custom String

KangarooTwelve supports appending a custom string `S` to the input, enabling personalization and domain separation without key management.

## StreamHash Implementation

### Key Features

- **12-round Keccak permutation** — shared optimized implementation with SHA-3
- **8192-byte chunk processing** — tree mode for large inputs
- **128-bit security** — suitable for most applications
- **Extendable output** — can produce arbitrary-length digests
- **Domain separation** — proper padding for single vs multi-chunk inputs

### Usage

```csharp
using StreamHash.Core;

var k12 = HashFacade.Create(HashAlgorithmNames.KangarooTwelve);
k12.Update(data);
byte[] hash = k12.FinalizeHash();
```

## Security

- **128-bit security** — sufficient for most applications
- **Reduced rounds** — half the rounds of full Keccak, but still with wide security margin
- **No known attacks** better than generic
- **Designed by the Keccak team** — same designers as SHA-3

## References

- [KangarooTwelve: Fast Hashing Based on Keccak-p](https://keccak.team/kangarootwelve.html)
- [KangarooTwelve Specification](https://keccak.team/files/KangarooTwelve.pdf)
- [NIST SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final)
