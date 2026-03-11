# StreamHash

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/)
[![.NET](https://img.shields.io/badge/.NET-10.0-blue.svg)](https://dotnet.microsoft.com/)
[![NuGet](https://img.shields.io/nuget/v/StreamHash)](https://www.nuget.org/packages/StreamHash)

**StreamHash** is a high-performance, memory-efficient streaming hash library for .NET 10+. All **70 hash algorithms** are implemented natively in pure C# with zero heavy dependencies — just one lightweight package (`System.IO.Hashing`) for CRC/xxHash acceleration.

## 🎯 Why StreamHash?

- **Single package, all algorithms**: One NuGet install gives you 70 hash algorithms — no BouncyCastle, no native binaries, no transitive dependency hell
- **Streaming everything**: Many popular algorithms (MurmurHash, CityHash, SpookyHash, etc.) lack streaming APIs. Hashing a 10GB file normally requires 10GB of RAM! StreamHash processes data in chunks using ~16MB regardless of file size
- **Competitive performance**: Native C# implementations match or beat external libraries for most algorithms, with extensive benchmarks to prove it

## ✨ Features

- **🚀 Memory Efficient**: Hash multi-gigabyte files with minimal memory footprint
- **⚡ High Performance**: Optimized implementations with SIMD where available (Grøstl AES-NI, JH SSSE3, HighwayHash AVX2)
- **🔄 Streaming API**: Process data incrementally with `Update()` and `Finalize()`
- **📦 Zero Allocations**: Hot paths are allocation-free using `Span<T>`
- **🎯 Unified API**: `HashFacade` provides access to all 70 algorithms through a single interface
- **🔐 All-Native Crypto**: Every cryptographic algorithm implemented in pure C# — no BouncyCastle dependency
- **⚡ Batch Streaming**: Process 70 algorithms in parallel with `CreateAllStreaming()`
- **🧪 Thoroughly Tested**: 1850+ tests validating against official test vectors
- **📖 Fully Documented**: XML docs, examples, and algorithm references
- **📦 Minimal Dependencies**: Only `System.IO.Hashing` — no large transitive dependency chains

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
dotnet add package StreamHash --version 1.10.0
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

## Markdown Quality Automation

Use these scripts to validate and benchmark markdown structure policy checks (`MD022`, `MD031`, `MD032`, `MD047`):

- `scripts/test-markdown-policy.ps1`
- `scripts/benchmark-markdown-policy.ps1`

Example:

```powershell
pwsh -File scripts/test-markdown-policy.ps1
pwsh -File scripts/benchmark-markdown-policy.ps1 -Runs 5
```

## 🏗️ Building

```bash
# Clone the repository
git clone https://github.com/TheAnsarya/StreamHash.git
cd StreamHash

# Build
dotnet build StreamHash.sln

# Run tests (1850+ tests)
dotnet test

# Run benchmarks
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks
```

## 📊 Benchmarks (v1.10.0)

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
| BLAKE2b | 1.34 ms | **3.9x faster** in v1.10.0 (fully unrolled) |
| BLAKE2s | 2.22 ms | **4.2x faster** in v1.10.0 (fully unrolled) |
| BLAKE3 | 8.49 ms | Native C# (no Rust P/Invoke) |
| **Whirlpool** | **16.5 ms** | Custom T-tables (3.2x faster in v1.6.2) |
| **Grøstl-256** | **61 ms** | AES-NI + T-tables (~2.5x faster in v1.6.2) |
| **JH-256** | **137 ms** | Bit-sliced + SSSE3 (~1.4x faster in v1.6.2) |

*All cryptographic algorithms are native C# since v1.10.0. Whirlpool, Grøstl, JH, and BLAKE2 have been extensively optimized.*

### Performance vs External Libraries (1MB data)

StreamHash's native implementations compared to the libraries they replaced:

| Algorithm | StreamHash | BouncyCastle | Ratio | Notes |
|-----------|----------:|-------------:|------:|-------|
| BLAKE2b | 1,337 µs | 826 µs | 1.62x | BC uses AVX2 SIMD |
| BLAKE2s | 2,216 µs | 1,320 µs | 1.68x | BC uses AVX2 SIMD |

*BLAKE2 improved from 6.3x/7.0x slower to just 1.6x via full round unrolling — pure safe C# vs BouncyCastle's AVX2 SIMD.*

**Full benchmark results**: Run `dotnet run -c Release --project benchmarks/StreamHash.Benchmarks -- --filter "*ComparisonBenchmarks*"` to see all comparisons.

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is released into the public domain under [The Unlicense](LICENSE). Do whatever you want with it.

## 🙏 Acknowledgments & References

As of v1.10.0, all 70 algorithms are implemented natively in StreamHash with no external hash library dependencies. The following projects were invaluable as reference implementations and inspiration:

### Reference Implementations

- **[BouncyCastle.Cryptography](https://github.com/bcgit/bc-csharp)** — Reference for MD2, MD4, SHA-224, SHA-512/224, SHA-512/256, RIPEMD-256/320, GOST-94, Streebog-256/512, Skein-256/512/1024, SM3, BLAKE2b/2s. MIT License.
- **[acryptohashnet](https://www.nuget.org/packages/acryptohashnet)** — Reference for Keccak-256/512, RIPEMD-128/160, Tiger-192, SHA-0. MIT License.
- **[SauceControl.Blake2Fast](https://github.com/saucecontrol/Blake2Fast)** — BLAKE2 SIMD reference with SSE2-AVX512. MIT License.
- **[Blake3.NET](https://www.nuget.org/packages/Blake3)** — BLAKE3 reference (Rust SIMD). Apache 2.0/MIT License.
- **[nebulae.dotSHA3](https://www.nuget.org/packages/nebulae.dotSHA3)** — SHA-3 XKCP reference with AVX2/NEON. MIT License.

### Algorithm References

- [SMHasher](https://github.com/aappleby/smhasher) — MurmurHash reference implementation
- [CityHash](https://github.com/google/cityhash) — Google's CityHash
- [SpookyHash](http://burtleburtle.net/bob/hash/spooky.html) — Bob Jenkins' SpookyHash
- [SipHash](https://github.com/veorq/SipHash) — Reference SipHash implementation
- [XKCP](https://github.com/XKCP/XKCP) — Keccak/SHA-3 reference implementations
- [RFC 7693](https://tools.ietf.org/html/rfc7693) — BLAKE2 specification
