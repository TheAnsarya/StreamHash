# wyhash

## Overview

wyhash is an ultra-fast non-cryptographic hash function created by Wang Yi. It uses 128-bit multiply (MUM — Multiply, Unmix, Mix) as its core operation and achieves 15-25 GB/s throughput on modern CPUs.

## Algorithm Details

| Property | Value |
|----------|-------|
| **Output Size** | 64 bits |
| **Block Size** | 48 bytes |
| **Core Operation** | 128-bit multiply (MUM) |
| **Accumulators** | 3 parallel |
| **License** | Public domain (Unlicense) |

## Algorithm Design

### MUM Operation

The core mixing function uses 128-bit multiplication:

```
MUM(a, b):
  full = (uint128)a * b
  return (uint64)(full >> 64) ^ (uint64)full
```

The 128-bit multiply followed by XOR folding provides excellent avalanche properties with minimal instruction count.

### Block Processing

- **3 parallel accumulators** processing 48-byte blocks
- Each accumulator: `acc = MUM(acc ^ data_word, secret_word)`
- Final merge of accumulators using MUM

### Small Key Optimization

Special fast paths for inputs ≤ 16 bytes to minimize overhead for hash table lookups.

## StreamHash Implementation

### Key Features

- **Native pure C# implementation**
- **3 parallel 64-bit accumulators** for instruction-level parallelism
- **128-bit multiply** via `Math.BigMul` (or manual emulation)
- **48-byte block processing**
- **SIMD detection** for potential hardware acceleration

### Usage

```csharp
using StreamHash.Core;

var hasher = HashFacade.Create(HashAlgorithmNames.Wyhash64);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();
```

## Security

**NOT cryptographically secure.** Designed for maximum speed in:

- Hash tables (extremely fast for small keys)
- Random number generation (wyhash is also a PRNG)
- Data fingerprinting

## References

- [wyhash — The fastest hash function](https://github.com/wangyi-fudan/wyhash)
