# xxHash Family

## Overview

xxHash is a family of extremely fast non-cryptographic hash functions created by Yann Collet. The family includes xxHash32, xxHash64, xxHash3 (64-bit), and xxHash128. xxHash3 (released 2019) achieves over 29 GB/s on modern hardware.

## Variants

| Variant | Output | Block Size | Speed (1MB) | Year |
|---------|--------|-----------|-----------|------|
| **xxHash32** | 32 bits | 16 bytes | ~7.2 GB/s | 2012 |
| **xxHash64** | 64 bits | 32 bytes | ~11.4 GB/s | 2012 |
| **xxHash3 (64-bit)** | 64 bits | 256 bytes | ~29.2 GB/s | 2019 |
| **xxHash128** | 128 bits | 256 bytes | ~28.7 GB/s | 2019 |

## Algorithm Design

### xxHash32/64 (Classic)

Classic xxHash uses a simple accumulator-based design:

1. **4 parallel accumulators** (32-bit for xxH32, 64-bit for xxH64)
2. Each accumulator: `acc = rotl(acc + input * PRIME2, rotation) * PRIME1`
3. **Merge**: combine 4 accumulators with rotations and additions
4. **Finalize**: process remaining bytes + avalanche mixing

### xxHash3 / xxHash128

xxHash3 is a complete redesign for SIMD parallelism:

1. **Stripe-based processing** — 64 bytes per stripe
2. **Secret-based mixing** — XOR with 192-byte secret key
3. **Hardware acceleration** — designed for SSE2/AVX2/NEON
4. **Accumulator model** — 8 × 64-bit accumulators

### Primes (xxHash32)

```
PRIME32_1 = 0x9e3779b1    (2654435761)
PRIME32_2 = 0x85ebca77    (2246822519)
PRIME32_3 = 0xc2b2ae3d    (3266489917)
PRIME32_4 = 0x27d4eb2f    (668265263)
PRIME32_5 = 0x165667b1    (374761393)
```

## StreamHash Implementation

StreamHash wraps `System.IO.Hashing` for xxHash implementations, adding streaming interface compatibility.

### Architecture

- **Thin wrappers** around `System.IO.Hashing.XxHash32/64/128/3`
- **Streaming interface** via `IStreamingHash<T>` adaptation
- **System.IO.Hashing** provides hardware-accelerated implementations internally

### Why Wrappers?

`System.IO.Hashing` provides optimized one-shot and append APIs but doesn't implement StreamHash's `IStreamingHash<T>` interface. The wrappers provide:

- Consistent API across all 70 algorithms
- Streaming `Update()` / `FinalizeHash()` pattern
- Integration with `HashFacade` and multi-hash processing

### Usage

```csharp
using StreamHash.Core;

// Via HashFacade
var xxh3 = HashFacade.Create(HashAlgorithmNames.XxHash3);
xxh3.Update(data);
byte[] hash = xxh3.FinalizeHash();

// All variants
var xxh32 = HashFacade.Create(HashAlgorithmNames.XxHash32);
var xxh64 = HashFacade.Create(HashAlgorithmNames.XxHash64);
var xxh128 = HashFacade.Create(HashAlgorithmNames.XxHash128);
```

## Performance (1MB data)

### vs System.IO.Hashing (Baseline)

| Algorithm | StreamHash | System.IO.Hashing | Ratio |
|-----------|----------:|------------------:|------:|
| CRC64 | 46.9 µs | 47.1 µs | 1.00x |
| CRC32 | 37.6 µs | 37.3 µs | 1.01x |
| xxHash3 | 35.9 µs | 34.5 µs | 1.04x |
| xxHash128 | 36.4 µs | 34.9 µs | 1.05x |
| xxHash64 | 92.0 µs | 87.9 µs | 1.05x |
| xxHash32 | 146.1 µs | 134.7 µs | 1.09x |

The 1-9% overhead is the cost of the streaming wrapper interface.

### vs HashDepot

| Algorithm | StreamHash | HashDepot | Ratio |
|-----------|----------:|---------:|------:|
| xxHash64 | 92.0 µs | 195.7 µs | **0.47x** (2.1x faster) |
| xxHash32 | 146.1 µs | 182.2 µs | **0.80x** (1.3x faster) |

## Security

**NOT cryptographically secure.** xxHash is designed for:

- Hash tables and data structures
- Content-addressable storage
- File integrity checking (non-adversarial)
- Data deduplication

## References

- [xxHash — Extremely fast hash algorithm](https://github.com/Cyan4973/xxHash)
- [xxHash Specification](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md)
- [xxHash3 Design](https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html)
