# MetroHash

## Overview

MetroHash is a set of extremely fast non-cryptographic hash functions created by J. Andrew Rogers. It is designed for high-throughput hash table operations and achieves ~15+ GB/s on modern 64-bit CPUs.

## Variants

| Variant | Output | Block Size | Speed |
|---------|--------|-----------|-------|
| **MetroHash64** | 64 bits | 32 bytes | ~15+ GB/s |
| **MetroHash128** | 128 bits | 32 bytes | ~15+ GB/s |

## Algorithm Design

### Core Approach

MetroHash uses 4 parallel 64-bit state variables that process data independently before being merged:

1. **Initialize** — 4 state variables seeded from initial hash value
2. **Block Processing** — each 32-byte block updates all 4 state variables
3. **Merge** — combine state variables with rotations and multiplications
4. **Finalize** — process remaining bytes + avalanche mixing

### Key Properties

- **Instruction-level parallelism** — 4 independent accumulator chains
- **64-bit multiplication** — primary mixing operation
- **Rotation-based diffusion** — bitwise rotations for avalanche
- **SIMD-aware design** — structure maps well to SIMD lanes

## StreamHash Implementation

### Key Features

- **Native pure C# implementation** — not a wrapper
- **4 parallel 64-bit state variables**
- **SIMD detection** — checks for AVX2, SSE4.1 availability
- **32-byte block processing**

### Usage

```csharp
using StreamHash.Core;

var metro64 = HashFacade.Create(HashAlgorithmNames.MetroHash64);
metro64.Update(data);
byte[] hash = metro64.FinalizeHash();

var metro128 = HashFacade.Create(HashAlgorithmNames.MetroHash128);
```

## Security

**NOT cryptographically secure.** Designed purely for speed in hash tables and data processing.

## References

- [MetroHash: Faster, Better Hash Functions](https://github.com/jandrewrogers/MetroHash)
