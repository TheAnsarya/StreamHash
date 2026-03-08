# CityHash

## Overview

CityHash is a family of hash functions developed by Google for fast string hashing. The algorithms are optimized for hash tables and other applications requiring fast, high-quality hashing of strings.

## Variants

### CityHash64

- **Output Size:** 64 bits (8 bytes)
- **Block Size:** 64 bytes (streaming)
- **Use Case:** Hash tables, data structures

### CityHash128

- **Output Size:** 128 bits (16 bytes)
- **Block Size:** 128 bytes (streaming)
- **Use Case:** Distributed systems, content-addressable storage

## Algorithm Details

CityHash uses multiple code paths optimized for different input lengths:

| Input Length | Strategy |
|--------------|----------|
| 0-3 bytes | Simple mixing |
| 4-7 bytes | 32-bit operations |
| 8-16 bytes | 64-bit operations |
| 17-32 bytes | Two 64-bit reads |
| 33-64 bytes | Four 64-bit reads |
| 65+ bytes | Block-based processing |

### Key Operations

- **Rotate64:** Bitwise rotation for mixing
- **ShiftMix:** XOR with right-shifted value
- **HashLen16:** 128-to-64 bit compression
- **WeakHashLen32WithSeeds:** 256-to-128 bit mixing

## Performance

CityHash achieves ~10+ GB/s on modern x86-64 CPUs by:

- Using 64-bit multiplications
- Minimizing branch mispredictions
- Optimizing for instruction-level parallelism

## Streaming Implementation

The streaming version maintains state across updates:

```csharp
// State variables for streaming
private ulong _x, _y, _z;
private ulong _v0, _v1;  // Intermediate values
private ulong _w0, _w1;  // Weak hash state
```

### Initialization

On the first 64-byte block:

1. Initialize x, y, z from block data
2. Compute v0, v1 using WeakHashLen32WithSeeds
3. Compute w0, w1 for state mixing

### Block Processing

Each subsequent block:

1. Mix x, y, z with block data and state
2. Update v0, v1, w0, w1
3. Swap z and x for next iteration

### Finalization

1. Process any remaining bytes
2. Apply final mixing: `HashLen16(v0 + w0, w1 + HashLen16(x + z, y, len), len)`

## Usage Example

```csharp
using StreamHash.Core;

// One-shot hashing
byte[] data = "Hello, World!"u8.ToArray();
ulong hash64 = CityHash64.Hash(data);
UInt128 hash128 = CityHash128.Hash(data);

// Streaming
using var hasher = new CityHash64();
hasher.Update(chunk1);
hasher.Update(chunk2);
ulong result = hasher.Finalize();
```

## Security Considerations

⚠️ **NOT cryptographically secure**

CityHash is designed for speed, not security:

- Vulnerable to hash-flooding attacks
- Predictable output for known inputs
- No keying mechanism

For security-sensitive applications, use SipHash or a cryptographic hash.

## References

- [CityHash - Google's Official Repository](https://github.com/google/cityhash)
- [Introducing CityHash - Google Blog](https://opensource.googleblog.com/2011/04/introducing-cityhash.html)
- [CityHash Source Code](https://github.com/google/cityhash/blob/master/src/city.cc)

## License

CityHash is released under the MIT License by Google.
