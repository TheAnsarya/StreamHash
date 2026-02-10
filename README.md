# StreamHash

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/)
[![.NET](https://img.shields.io/badge/.NET-10.0-blue.svg)](https://dotnet.microsoft.com/)
[![NuGet](https://img.shields.io/nuget/v/StreamHash)](https://www.nuget.org/packages/StreamHash)

**StreamHash** is a high-performance, memory-efficient streaming hash library for .NET 10+. It provides incremental/streaming implementations of popular hash algorithms and a unified `HashFacade` API supporting **70 algorithms** - all fully implemented and accessible.

## 🎯 Why StreamHash?

Many popular hash algorithms (MurmurHash, CityHash, SpookyHash, etc.) don't have official streaming APIs. This means hashing a 10GB file requires 10GB of RAM! StreamHash solves this by providing streaming implementations that process data in chunks, using only ~16MB of memory regardless of file size.

## ✨ Features

- **🚀 Memory Efficient**: Hash multi-gigabyte files with minimal memory footprint
- **⚡ High Performance**: SIMD-optimized implementations where available
- **🔄 Streaming API**: Process data incrementally with `Update()` and `Finalize()`
- **📦 Zero Allocations**: Hot paths are allocation-free using `Span<T>`
- **🎯 Unified API**: `HashFacade` provides access to all 70 algorithms through a single interface
- **🔐 Full Crypto Support**: All cryptographic algorithms via BouncyCastle integration
- **⚡ Batch Streaming**: Process 70 algorithms in parallel with `CreateAllStreaming()`
- **🧪 Thoroughly Tested**: 762+ tests validating against official test vectors
- **📖 Fully Documented**: XML docs, examples, and algorithm references

## 📊 Algorithm Support (All 70 Fully Implemented!)

### Native Streaming Implementations (16)

| Algorithm | Digest Size | Status |
|-----------|-------------|--------|
| MurmurHash3-32/128 | 32/128-bit | ✅ Complete |
| CityHash64/128 | 64/128-bit | ✅ Complete |
| SpookyHash V2 | 128-bit | ✅ Complete |
| SipHash-2-4 | 64-bit | ✅ Complete |
| FarmHash64 | 64-bit | ✅ Complete |
| HighwayHash64 | 64-bit | ✅ Complete |
| KangarooTwelve | Variable (XOF) | ✅ Complete |
| MetroHash64/128 | 64/128-bit | ✅ Complete |
| wyhash64 | 64-bit | ✅ Complete |
| xxHash32/64/3/128* | 32-128 bit | ✅ Complete |

### HashFacade Unified API (70 algorithms)

The `HashFacade` class provides one-shot and streaming access to **all 70 algorithms**:

#### Checksums (9)
CRC32, CRC32C, CRC64, CRC-16-CCITT, CRC-16-MODBUS, CRC-16-USB, Adler-32, Fletcher-16, Fletcher-32

#### Fast Non-Crypto (22)
xxHash32/64/3/128, MurmurHash3-32/128, CityHash64/128, FarmHash64, SpookyHash128, SipHash-2-4, HighwayHash64, MetroHash64/128, wyhash64, FNV-1a (32/64), DJB2, DJB2a, SDBM, Lose Lose

#### MD Family (3)
MD2, MD4, MD5

#### SHA-1/2 Family (9)
SHA-0, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256

#### SHA-3 & Keccak (6)
SHA3-224, SHA3-256, SHA3-384, SHA3-512, Keccak-256, Keccak-512

#### BLAKE Family (5)
BLAKE-256, BLAKE-512, BLAKE2b, BLAKE2s, BLAKE3

#### RIPEMD Family (4)
RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320

#### Other Cryptographic (14)
Whirlpool, Tiger-192, GOST R 34.11-94, Streebog-256, Streebog-512, Skein-256, Skein-512, Skein-1024, Grøstl-256, Grøstl-512, JH-256, JH-512, KangarooTwelve, SM3

## 🚀 Quick Start

### Installation

```bash
dotnet add package StreamHash --version 1.8.0
```

### Batch Streaming API (New in v1.7.0, Optimized in v1.8.0)

Hash files with **all 70 algorithms in parallel** - perfect for file verification tools:

```csharp
using StreamHash.Core;

// Create batch hasher for all 70 algorithms
using var multi = HashFacade.CreateAllStreaming();

// Stream file through all hashers in parallel
using var stream = File.OpenRead("large-file.bin");
byte[] buffer = new byte[16 * 1024 * 1024]; // 16MB buffer recommended
int read;
while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) {
    multi.Update(buffer.AsSpan(0, read));
}

// Get all 70 hashes as hex strings
Dictionary<string, string> results = multi.FinalizeAll();
// results["SHA256"] = "abc123..."
// results["MD5"] = "def456..."
// ... all 70 algorithms
```

**Performance**: 34MB file with 70 algorithms: **~12 seconds** (~2.8 MB/s effective throughput)

### Basic Hashes API (New in v1.10.0)

For the common use case of verifying files with standard hashes (CRC32, MD5, SHA-1, SHA-256):

```csharp
using StreamHash.Core;

// Hash a file with the 4 most common algorithms
using var basicHasher = HashFacade.CreateBasicHashesStreaming();
using var stream = File.OpenRead("download.zip");
var buffer = new byte[16 * 1024 * 1024];  // 16MB buffer
int bytesRead;
while ((bytesRead = stream.Read(buffer)) > 0) {
	basicHasher.Update(buffer.AsSpan(0, bytesRead));
}

var results = basicHasher.FinalizeAll();
// Use constants instead of magic strings!
Console.WriteLine($"CRC32:   {results[HashAlgorithmNames.Crc32]}");
Console.WriteLine($"MD5:     {results[HashAlgorithmNames.Md5]}");
Console.WriteLine($"SHA-1:   {results[HashAlgorithmNames.Sha1]}");
Console.WriteLine($"SHA-256: {results[HashAlgorithmNames.Sha256]}");
```

**Performance**: ~17.5x faster than computing all 70 algorithms when you only need these 4.

**Tip**: Use `HashAlgorithmNames` constants instead of string literals to avoid typos and enable refactoring!

### HashFacade API (Recommended)

```csharp
using StreamHash.Core;

// One-shot hashing
byte[] data = File.ReadAllBytes("file.bin");
byte[] hash = HashFacade.ComputeHash(HashAlgorithm.XxHash64, data);
string hex = HashFacade.ComputeHashHex(HashAlgorithm.Sha256, data);

// Streaming hashing
using var hasher = HashFacade.CreateStreaming(HashAlgorithm.MurmurHash3_128);
hasher.Update(chunk1);
hasher.Update(chunk2);
byte[] result = hasher.FinalizeBytes();

// Algorithm info
var info = HashFacade.GetInfo(HashAlgorithm.Sha256);
Console.WriteLine($"{info.DisplayName}: {info.DigestSize} bytes, Crypto: {info.IsCryptographic}");
```

### Direct Streaming API

```csharp
using StreamHash.Core;

// Hash a file incrementally
using var hasher = new MurmurHash3_128();
using var stream = File.OpenRead("large-file.bin");

byte[] buffer = new byte[1024 * 1024]; // 1MB buffer
int bytesRead;

while ((bytesRead = await stream.ReadAsync(buffer)) > 0) {
    hasher.Update(buffer.AsSpan(0, bytesRead));
}

UInt128 hash = hasher.Finalize();
Console.WriteLine($"Hash: {hasher.FinalizeHex()}");
```

## 📖 Documentation

- [📚 Algorithm Reference](docs/algorithms/README.md)
- [🔧 API Documentation](docs/api/README.md)
- [📈 Performance Benchmarks](docs/benchmarks.md)

## 🏗️ Building

```bash
# Clone the repository
git clone https://github.com/TheAnsarya/StreamHash.git
cd StreamHash

# Build
dotnet build StreamHash.sln

# Run tests (752+ tests)
dotnet test

# Run benchmarks
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks
```

## 📊 Benchmarks (v1.8.0)

Performance on Intel i7-8700K (Coffee Lake), .NET 10.0.2, Windows 10:

### Fast Non-Crypto Hashes (1MB data)
| Algorithm | Time | Throughput |
|-----------|-----:|------------|
| CRC32 | 36 µs | 27.8 GB/s |
| XxHash3 | 43 µs | 23.3 GB/s |
| XxHash128 | 51 µs | 19.6 GB/s |
| XxHash64 | 83 µs | 12.0 GB/s |
| Wyhash64 | 130 µs | 7.7 GB/s |
| CityHash128 | 133 µs | 7.5 GB/s |
| FarmHash64 | 160 µs | 6.3 GB/s |
| CityHash64 | 199 µs | 5.0 GB/s |
| MurmurHash3_128 | 257 µs | 3.9 GB/s |
| SpookyHash128 | 341 µs | 2.9 GB/s |
| MurmurHash3_32 | 545 µs | 1.8 GB/s |
| **HighwayHash64** | **756 µs** | **1.4 GB/s** (AVX2 SIMD in v1.6.2) |

### Cryptographic Hashes (1MB data)
| Algorithm | Time | Notes |
|-----------|-----:|-------|
| Tiger-192 | 2.19 ms | Fast crypto |
| SHA-1 | 1.48 ms | Legacy |
| MD5 | 1.63 ms | Legacy |
| SHA-512 | 2.15 ms | 64-bit optimized |
| SHA3-256 | 3.18 ms | Keccak-based |
| SHA-256 | 3.67 ms | Standard |
| SM3 | 5.43 ms | Chinese standard |
| SHA3-512 | 6.22 ms | Keccak-based |
| Blake2b | 6.52 ms | Modern |
| Blake3 | 8.49 ms | Parallelizable |
| **Whirlpool** | **16.5 ms** | Custom T-tables (3.2x faster in v1.6.2) |
| **Grøstl-256** | **61 ms** | AES-NI + T-tables (~2.5x faster in v1.6.2) |
| **JH-256** | **137 ms** | Bit-sliced + SSSE3 (~1.4x faster in v1.6.2) |

*Whirlpool, Grøstl, and JH significantly optimized with custom implementations, SIMD, and T-tables in v1.6.2*

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is released into the public domain under [The Unlicense](LICENSE). Do whatever you want with it.

## 🙏 Acknowledgments

StreamHash leverages several excellent libraries for cryptographic and high-performance hash implementations.

### Blake3.NET - BLAKE3 Native SIMD 🚀

**[Blake3](https://www.nuget.org/packages/Blake3)** - Native SIMD Rust wrapper for BLAKE3, 10-20x faster than pure C#.

**Algorithms from Blake3.NET (1):**
- **BLAKE3** (native SIMD via Rust bindings)

### SauceControl.Blake2Fast - BLAKE2 SIMD 🔥

**[SauceControl.Blake2Fast](https://www.nuget.org/packages/SauceControl.Blake2Fast)** - Fastest RFC 7693 BLAKE2 implementation for .NET with SSE2-AVX512 SIMD support.

**Algorithms from Blake2Fast (4):**
- **BLAKE-256, BLAKE-512** (BLAKE2b variants)
- **BLAKE2b** (512-bit)
- **BLAKE2s** (256-bit)

### nebulae.dotSHA3 - SHA-3 Native SIMD ⚡

**[nebulae.dotSHA3](https://www.nuget.org/packages/nebulae.dotSHA3)** - XKCP-based native SHA-3 implementation with AVX2/NEON acceleration.

**Algorithms from dotSHA3 (4):**
- **SHA3-224, SHA3-256, SHA3-384, SHA3-512**

### acryptohashnet - Pure Managed C# 💎

**[acryptohashnet](https://www.nuget.org/packages/acryptohashnet)** - Pure managed C# implementations with low memory footprint, compatible with `System.Security.Cryptography.HashAlgorithm`.

**Algorithms from acryptohashnet (5):**
- **Keccak-256, Keccak-512** (original Keccak, not SHA-3)
- **RIPEMD-128, RIPEMD-160**
- **Tiger-192**

### BouncyCastle - Cryptographic Foundation 🏰

**[BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography)** - Comprehensive cryptographic library (v2.6.2).

**Algorithms from BouncyCastle (12):**
- **MD Family:** MD2, MD4
- **SHA Family:** SHA-224, SHA-512/224, SHA-512/256
- **RIPEMD Family:** RIPEMD-256, RIPEMD-320
- **GOST/Streebog:** GOST R 34.11-94, Streebog-256, Streebog-512
- **Skein Family:** Skein-256, Skein-512, Skein-1024
- **Other:** SM3

**Links:**
- **[BouncyCastle C# GitHub](https://github.com/bcgit/bc-csharp)** - The Legion of the Bouncy Castle (C#/.NET)
- **[BouncyCastle Java GitHub](https://github.com/bcgit/bc-java)** - The original Java implementation
- **[NuGet: BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography)** - v2.6.2+, MIT License

### Native StreamHash Implementations

Custom optimized implementations built into StreamHash:
- **Grøstl-256/512** (AES-NI + T-tables)
- **JH-256/512** (bit-sliced + SSSE3)
- **Whirlpool** (custom T-tables, 3.2x faster than BouncyCastle)
- **SHA-0** (historical algorithm, not in BouncyCastle)
- **All checksums** (CRC32, CRC64, Adler, Fletcher)
- **All fast non-crypto hashes** (MurmurHash, CityHash, SpookyHash, etc.)
- **All .NET built-in algorithms** (MD5, SHA-1, SHA-256, SHA-384, SHA-512)

**Giving Back:** If our performance optimizations prove successful and stable, we plan to contribute them back to the upstream projects. Open source thrives when we all give back! 🌱

### Other References

- [SMHasher](https://github.com/aappleby/smhasher) - MurmurHash reference implementation
- [CityHash](https://github.com/google/cityhash) - Google's CityHash
- [SpookyHash](http://burtleburtle.net/bob/hash/spooky.html) - Bob Jenkins' SpookyHash
- [SipHash](https://github.com/veorq/SipHash) - Reference SipHash implementation
- [XKCP](https://github.com/XKCP/XKCP) - Keccak/SHA-3 reference implementations

