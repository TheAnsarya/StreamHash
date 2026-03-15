# StreamHash Algorithm Reference

This directory contains detailed documentation for each streaming hash algorithm implemented in StreamHash.

## Algorithms by Category

### Checksums & CRCs

| Algorithm | Output | Documentation |
|-----------|--------|---------------|
| CRC-16 (7 variants) | 16-bit | [CRC-16](crc16.md) |
| CRC-32 | 32-bit | System.IO.Hashing wrapper |
| CRC-32C | 32-bit | System.IO.Hashing wrapper |
| CRC-64 | 64-bit | System.IO.Hashing wrapper |

### Non-Cryptographic Fast Hashes

| Algorithm | Output | Speed | Key | Documentation |
|-----------|--------|-------|-----|---------------|
| [xxHash3](xxhash.md) | 64-bit | ~29 GB/s | Secret | Fastest hash |
| [xxHash128](xxhash.md) | 128-bit | ~29 GB/s | Secret | 128-bit xxHash3 |
| [xxHash64](xxhash.md) | 64-bit | ~11 GB/s | Seed | Classic xxHash |
| [xxHash32](xxhash.md) | 32-bit | ~7 GB/s | Seed | 32-bit xxHash |
| [wyhash64](wyhash.md) | 64-bit | ~15-25 GB/s | None | Ultra-fast MUM |
| [MetroHash64](metrohash.md) | 64-bit | ~15+ GB/s | None | 4-way parallel |
| [MetroHash128](metrohash.md) | 128-bit | ~15+ GB/s | None | 128-bit Metro |
| [FarmHash64](farmhash.md) | 64-bit | ~10-15 GB/s | None | CityHash successor |
| [CityHash64](cityhash.md) | 64-bit | ~10+ GB/s | None | Google, fast strings |
| [CityHash128](cityhash.md) | 128-bit | ~8+ GB/s | None | Larger output space |
| [SpookyHash V2](spookyhash.md) | 128-bit | ~10+ GB/s | Seed | Bob Jenkins |
| [MurmurHash3-32](murmurhash3.md) | 32-bit | ~3-5 GB/s | Seed | General purpose |
| [MurmurHash3-128](murmurhash3.md) | 128-bit | ~5-7 GB/s | Seed | Reduced collisions |
| [FNV-1a](fnv1a.md) | 32/64-bit | Byte-at-a-time | None | Simplest hash |

### Keyed/Security-Aware Hashes

| Algorithm | Output | Speed | Key | Documentation |
|-----------|--------|-------|-----|---------------|
| [SipHash-2-4](siphash.md) | 64-bit | ~2-3 GB/s | 128-bit | DoS-resistant PRF |
| [HighwayHash64](highwayhash.md) | 64-bit | ~10+ GB/s | 256-bit | SIMD, DoS-resistant |

### Cryptographic Hashes — SHA/MD Family

| Algorithm | Output | Documentation |
|-----------|--------|---------------|
| MD2, MD4, MD5 | 128-bit | [MD Family](md-family.md) |
| SHA-0 | 160-bit | [SHA Family](sha-family.md) |
| SHA-1 | 160-bit | .NET hardware-accelerated |
| SHA-224 | 224-bit | [SHA Family](sha-family.md) |
| SHA-256, SHA-384, SHA-512 | 256-512 bit | .NET hardware-accelerated |
| SHA-512/224, SHA-512/256 | 224-256 bit | [SHA Family](sha-family.md) |

### Cryptographic Hashes — SHA-3/Keccak

| Algorithm | Output | Documentation |
|-----------|--------|---------------|
| SHA3-224/256/384/512 | 224-512 bit | [Keccak/SHA-3](keccak-sha3.md) |
| Keccak-256/512 | 256-512 bit | [Keccak/SHA-3](keccak-sha3.md) |
| KangarooTwelve | Variable (XOF) | [KangarooTwelve](kangarootwelve.md) |

### Cryptographic Hashes — BLAKE Family

| Algorithm | Output | Documentation |
|-----------|--------|---------------|
| BLAKE2b (1-64 bytes) | Configurable | [BLAKE2](blake2.md) |
| BLAKE2s (1-32 bytes) | Configurable | [BLAKE2](blake2.md) |
| BLAKE3 | 32 bytes (XOF) | [BLAKE3](blake3.md) |

### Cryptographic Hashes — RIPEMD Family

| Algorithm | Output | Documentation |
|-----------|--------|---------------|
| RIPEMD-128/160/256/320 | 128-320 bit | [RIPEMD](ripemd.md) |

### Cryptographic Hashes — Other

| Algorithm | Output | Documentation |
|-----------|--------|---------------|
| [Whirlpool](Whirlpool.md) | 512-bit | ISO/IEC 10118-3 |
| [Tiger-192](tiger.md) | 192-bit | 64-bit optimized |
| [Skein-256/512/1024](skein.md) | Configurable | SHA-3 finalist, Threefish |
| [Grøstl-256/512](groestl.md) | 256-512 bit | SHA-3 finalist, AES-based |
| [JH-256/512](jh.md) | 256-512 bit | SHA-3 finalist |
| [SM3](sm3.md) | 256-bit | Chinese national standard |
| [Streebog-256/512](streebog.md) | 256-512 bit | Russian GOST R 34.11-2012 |
| [GOST R 34.11-94](gost94.md) | 256-bit | Russian legacy standard |

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
