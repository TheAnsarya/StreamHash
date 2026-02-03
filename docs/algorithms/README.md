# StreamHash Algorithm Reference

This directory contains detailed documentation for each streaming hash algorithm implemented in StreamHash.

## Algorithms by Category

### Non-Cryptographic Fast Hashes

| Algorithm | Output | Speed | Key | Documentation |
|-----------|--------|-------|-----|---------------|
| [MurmurHash3-32](murmurhash3.md) | 32-bit | ~3-5 GB/s | Seed | General purpose |
| [MurmurHash3-128](murmurhash3.md) | 128-bit | ~5-7 GB/s | Seed | Reduced collisions |
| [CityHash64](cityhash.md) | 64-bit | ~10+ GB/s | None | Google, fast strings |
| [CityHash128](cityhash.md) | 128-bit | ~8+ GB/s | None | Larger output space |
| [FarmHash64](farmhash.md) | 64-bit | ~10-15 GB/s | None | CityHash successor |
| [SpookyHash V2](spookyhash.md) | 128-bit | ~10+ GB/s | Seed | Bob Jenkins |

### Keyed/Security-Aware Hashes

| Algorithm | Output | Speed | Key | Documentation |
|-----------|--------|-------|-----|---------------|
| [SipHash-2-4](siphash.md) | 64-bit | ~2-3 GB/s | 128-bit | DoS-resistant PRF |
| [HighwayHash64](highwayhash.md) | 64-bit | ~10+ GB/s | 256-bit | SIMD, DoS-resistant |

## Choosing an Algorithm

### For Hash Tables (No Security Concerns)

**Best:** MurmurHash3-32, CityHash64, FarmHash64

These are fast, have excellent distribution, and work well for in-memory hash tables.

### For Distributed Systems

**Best:** CityHash128, MurmurHash3-128, SpookyHash128

128-bit output reduces collision probability for large-scale systems.

### For Network/Untrusted Input

**Best:** SipHash-2-4, HighwayHash64

These keyed hashes protect against hash-flooding DoS attacks.

### For Maximum Speed

**Best:** FarmHash64, CityHash64, HighwayHash64 (with SIMD)

Optimized for modern 64-bit CPUs with high instruction-level parallelism.

## Algorithm Comparison

### Speed (Higher = Better)

```
FarmHash64     ████████████████ ~15 GB/s
HighwayHash64  ███████████████  ~12 GB/s (SIMD)
CityHash64     ██████████████   ~10 GB/s
SpookyHash128  █████████████    ~10 GB/s
MurmurHash3_128 ████████        ~7 GB/s
MurmurHash3_32  ██████          ~5 GB/s
SipHash-2-4    █████           ~3 GB/s
```

### Security (Higher = Better)

```
SipHash-2-4    ████████████████ PRF security
HighwayHash64  ███████████      DoS-resistant
MurmurHash3    ███              Seed only
CityHash       ██               None
FarmHash       ██               None
SpookyHash     ███              Seed only
```

### Output Size vs Collision Probability

| Bits | Collision Probability (50% at N items) |
|------|----------------------------------------|
| 32 | ~77,000 items |
| 64 | ~5 billion items |
| 128 | ~2^64 items |

## Common Patterns

### File Hashing

```csharp
using var hasher = new MurmurHash3_128();
using var stream = File.OpenRead("file.bin");
byte[] buffer = new byte[81920]; // 80KB
int read;
while ((read = stream.Read(buffer)) > 0) {
    hasher.Update(buffer.AsSpan(0, read));
}
var hash = hasher.Finalize();
```

### Hash Table Key

```csharp
public int GetHashCode() {
    return (int)MurmurHash3_32.Hash(GetBytes(), seed: 0);
}
```

### Secure Network Hash

```csharp
// Server-side with secret key
private static readonly ulong[] ServerKey = GetSecretKey();

public ulong HashPacket(ReadOnlySpan<byte> packet) {
    return HighwayHash64.Hash(packet, ServerKey);
}
```

## Additional Resources

- [SMHasher Test Suite](https://github.com/aappleby/smhasher) - Hash quality testing
- [Hash Function Shootout](https://github.com/rurban/smhasher) - Performance comparisons
- [What is a Good Hash Function?](https://research.neustar.biz/2012/02/02/choosing-a-good-hash-function/) - Design principles
