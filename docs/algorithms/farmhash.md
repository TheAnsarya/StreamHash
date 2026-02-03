# FarmHash

## Overview

FarmHash is a family of hash functions developed by Google as a successor to CityHash. It provides improved performance and quality while maintaining compatibility for certain use cases.

## Algorithm Details

### FarmHash64

- **Output Size:** 64 bits (8 bytes)
- **Block Size:** 64 bytes (streaming)
- **Design:** Evolved from CityHash with platform-specific optimizations

## Key Differences from CityHash

| Feature | CityHash | FarmHash |
|---------|----------|----------|
| Platform optimization | x86-64 focused | Multi-platform |
| Hash quality | Excellent | Improved |
| Speed | Very fast | Often faster |
| CRC intrinsics | Optional | Better integrated |

## Implementation

FarmHash uses similar techniques to CityHash:

### Constants

```csharp
private const ulong K0 = 0xc3a5c85c97cb3127UL;
private const ulong K1 = 0xb492b66fbe98f273UL;
private const ulong K2 = 0x9ae16a3b2f90404fUL;
```

### State Management

```csharp
// Streaming state
private ulong _x, _y, _z;
private ulong _v0, _v1;
private ulong _w0, _w1;
```

### Short Message Handling

FarmHash, like CityHash, uses optimized paths for short messages:

| Length | Operation |
|--------|-----------|
| 1-3 bytes | Byte mixing with K0, K2 |
| 4-7 bytes | 32-bit fetch, HashLen16 |
| 8-16 bytes | 64-bit operations |
| 17-32 bytes | Double 64-bit reads |
| 33-63 bytes | Complex mixing |
| 64+ bytes | Block processing |

### Block Processing

Each 64-byte block:

```csharp
_x = Rotate64(_x + _y + _v0 + s1, 37) * K1;
_y = Rotate64(_y + _v1 + s6, 42) * K1;
_x ^= _w1;
_y += _v0 + s5;
_z = Rotate64(_z + _w0, 33) * K1;
```

## Usage Example

```csharp
using StreamHash.Core;

// One-shot hashing
byte[] data = GetData();
ulong hash = FarmHash64.Hash(data);

// Streaming (large files)
using var hasher = new FarmHash64();
foreach (var chunk in ReadChunks(file)) {
    hasher.Update(chunk);
}
ulong result = hasher.Finalize();
```

## Performance Characteristics

- **Throughput:** ~10-15 GB/s on modern x86-64
- **Latency:** Very low for short strings
- **Memory:** O(1) space for streaming

## When to Use FarmHash

✅ **Good for:**
- Hash tables and maps
- Data partitioning/sharding
- Content fingerprinting
- Cache key generation
- Bloom filters

❌ **Not suitable for:**
- Cryptographic applications
- DoS-resistant hashing
- Security-sensitive contexts

## Security Considerations

⚠️ **NOT cryptographically secure**

FarmHash prioritizes speed over security:
- No keying mechanism
- Vulnerable to collision attacks
- Predictable for adversarial inputs

## References

- [FarmHash - Google's Official Repository](https://github.com/google/farmhash)
- [Introducing FarmHash - Google Blog](https://opensource.googleblog.com/2014/03/introducing-farmhash.html)
- [FarmHash vs CityHash Performance](https://github.com/google/farmhash/blob/master/README)

## License

FarmHash is released under the MIT License by Google.
