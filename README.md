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
- **🧪 Thoroughly Tested**: 1853+ tests validating against official test vectors
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

- [📚 Algorithm Reference](docs/algorithms/README.md) — All 70 algorithms documented
- [🔧 API Documentation](docs/api/README.md)
- [📈 Performance Benchmarks](docs/benchmarks.md) — Detailed comparisons vs BouncyCastle, System.IO.Hashing, Blake2Fast, and more
- [📋 Reference Hash Values](docs/reference-hashes.md)

### Algorithm Documentation

| Category | Docs |
|----------|------|
| BLAKE2b/2s | [blake2.md](docs/algorithms/blake2.md) |
| BLAKE3 | [blake3.md](docs/algorithms/blake3.md) |
| Keccak/SHA-3 | [keccak-sha3.md](docs/algorithms/keccak-sha3.md) |
| SHA-0/224/512t | [sha-family.md](docs/algorithms/sha-family.md) |
| MD2/MD4/MD5 | [md-family.md](docs/algorithms/md-family.md) |
| RIPEMD-128/160/256/320 | [ripemd.md](docs/algorithms/ripemd.md) |
| Skein-256/512/1024 | [skein.md](docs/algorithms/skein.md) |
| Whirlpool | [Whirlpool.md](docs/algorithms/Whirlpool.md) |
| Tiger-192 | [tiger.md](docs/algorithms/tiger.md) |
| SM3 | [sm3.md](docs/algorithms/sm3.md) |
| Grøstl | [groestl.md](docs/algorithms/groestl.md) |
| JH | [jh.md](docs/algorithms/jh.md) |
| KangarooTwelve | [kangarootwelve.md](docs/algorithms/kangarootwelve.md) |
| Streebog | [streebog.md](docs/algorithms/streebog.md) |
| GOST-94 | [gost94.md](docs/algorithms/gost94.md) |
| xxHash family | [xxhash.md](docs/algorithms/xxhash.md) |
| MetroHash | [metrohash.md](docs/algorithms/metrohash.md) |
| wyhash | [wyhash.md](docs/algorithms/wyhash.md) |
| FNV-1a | [fnv1a.md](docs/algorithms/fnv1a.md) |
| CRC-16 | [crc16.md](docs/algorithms/crc16.md) |
| MurmurHash3 | [murmurhash3.md](docs/algorithms/murmurhash3.md) |
| CityHash | [cityhash.md](docs/algorithms/cityhash.md) |
| FarmHash | [farmhash.md](docs/algorithms/farmhash.md) |
| SipHash | [siphash.md](docs/algorithms/siphash.md) |
| SpookyHash | [spookyhash.md](docs/algorithms/spookyhash.md) |
| HighwayHash | [highwayhash.md](docs/algorithms/highwayhash.md) |

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
dotnet build StreamHash.slnx

# Run tests (1853+ tests)
dotnet test

# Run benchmarks
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks
```

## 📊 Benchmarks (Updated 2026-03-16)

Performance on Intel i7-8700K (Coffee Lake), .NET 10.0.4, Windows 10:

### Fast Non-Crypto Hashes (1MB data)

| Algorithm | Time | Throughput | vs Reference |
|-----------|-----:|------------|:------------:|
| xxHash128 | 34.7 µs | 30.2 GB/s | **0.98x** |
| xxHash3 | 35.6 µs | 29.4 GB/s | **0.99x** |
| CRC32 | 40.5 µs | 25.8 GB/s | 0.98x |
| CRC64 | 49.0 µs | 21.4 GB/s | 1.02x |
| xxHash64 | 115.2 µs | 9.1 GB/s | 1.25x |
| xxHash32 | 132.1 µs | 7.9 GB/s | **0.99x** |
| MurmurHash3-32 | 281.2 µs | 3.7 GB/s | 0.91x |
| SipHash-2-4 | 407.0 µs | 2.6 GB/s | 0.94x |
| HighwayHash64 | 759 µs | 1.4 GB/s | AVX2 SIMD |

### Cryptographic Hashes (1MB data)

| Algorithm | Time | vs BouncyCastle | Notes |
|-----------|-----:|:---------------:|-------|
| SHA-1 | 1.50 ms | **0.40x** | 2.5x faster (.NET HW) |
| Skein-512 | 1.61 ms | **0.73x** | 1.4x faster |
| MD5 | 1.66 ms | **0.65x** | 1.5x faster (.NET HW) |
| Tiger-192 | 1.89 ms | **0.86x** | At parity |
| SHA-512 | 2.18 ms | **0.79x** | 1.3x faster (.NET HW) |
| SHA-384 | 2.22 ms | **0.82x** | 1.2x faster (.NET HW) |
| Skein-256 | 2.28 ms | **0.83x** | 1.2x faster |
| Skein-1024 | 2.29 ms | **0.81x** | 1.2x faster |
| **RIPEMD-128** | **2.30 ms** | **0.56x** | **1.8x faster** (fully unrolled) |
| SHA-512/256 | 2.46 ms | **0.91x** | 1.1x faster |
| SHA-512/224 | 2.42 ms | **0.88x** | 1.1x faster |
| RIPEMD-160 | 2.96 ms | **0.70x** | 1.4x faster |
| SHA3-224 | 3.29 ms | **1.02x** | At parity |
| Keccak-256 | 3.39 ms | **1.02x** | At parity |
| RIPEMD-256 | 3.35 ms | **0.97x** | At parity |
| SHA3-256 | 3.43 ms | **1.03x** | At parity |
| SHA-256 | 3.90 ms | **0.87x** | 1.2x faster (.NET HW) |
| SHA-224 | 4.57 ms | **0.98x** | At parity |
| SHA3-384 | 4.33 ms | **1.00x** | At parity |
| RIPEMD-320 | 4.88 ms | **1.03x** | At parity |
| SM3 | 4.93 ms | **0.88x** | 1.1x faster |
| SHA3-512 | 6.30 ms | **0.97x** | Faster |
| Keccak-512 | 6.32 ms | **1.03x** | At parity |
| Whirlpool | 10.18 ms | **0.21x** | **4.9x faster** |
| Streebog-256 | 13.27 ms | **0.57x** | 1.8x faster |
| Streebog-512 | 13.39 ms | **0.60x** | 1.7x faster |
| MD2 | 94.83 ms | **0.96x** | At parity |
| GOST-94 | 113.6 ms | **0.75x** | 1.3x faster, 35000x less alloc |
| BLAKE2b | 0.97 ms | **1.14x** | BC has AVX2 SIMD |
| BLAKE2s | 1.38 ms | **1.05x** | At parity |
| BLAKE3 | 0.25 ms | **1.00x** | At parity with Rust native! |

*All cryptographic algorithms are native C# since v1.10.0. Zero true unsafe code in the entire codebase.*

### Algorithms Slower Than Reference Libraries

Only a few algorithms remain slower than their reference implementations:

| Algorithm | Ratio | Reference Library | Reason |
|-----------|:-----:|-------------------|--------|
| xxHash64 | 1.25x | System.IO.Hashing | Byte order conversion overhead |
| BLAKE2b | 1.14x | BouncyCastle | BC uses AVX2 SIMD (donated Blake2Fast code) |
| BLAKE2s | 1.05x | BouncyCastle | BC uses SSSE3 SIMD |
| RIPEMD-320 | 1.03x | BouncyCastle | Near parity |
| Keccak-512 | 1.03x | BouncyCastle | Near parity |
| SHA3-256 | 1.03x | BouncyCastle | Near parity |

### Performance vs External Libraries (1MB, Summary)

StreamHash's native C# implementations compared to external libraries:

| Category | Faster | At Parity | Slower | Notes |
|----------|:------:|:---------:|:------:|-------|
| **Crypto vs BouncyCastle** | **20** | **10** | **2** | Only BLAKE2b/2s meaningfully slower |
| **Non-Crypto vs System.IO** | **3** | **2** | **1** | xxHash32/3/128 at parity, xxHash64 slower |
| **Non-Crypto vs HashDepot** | **4** | **1** | **0** | MurmurHash, SipHash, xxHash faster |

**Highlights:**

- **4.9x faster**: Whirlpool (0.21x ratio — custom precomputed T-tables)
- **2.5x faster**: SHA-1 (0.40x — .NET hardware acceleration)
- **1.8x faster**: RIPEMD-128 (0.56x — fully unrolled), Streebog-256
- **1.5x faster**: MD5, Skein-512, SHA-512
- **At parity**: SHA3 family, Keccak, CRC, xxHash32/3/128, BLAKE3
- **Slightly slower**: BLAKE2b (1.14x), xxHash64 (1.25x)

Full results with all data sizes in [docs/benchmarks.md](docs/benchmarks.md).

*March 2026 optimizations: xxHash one-shot APIs (1.95x → 0.99x), RIPEMD-128 unrolling (1.05x → 0.56x), SHA-512/256 ReadOnlySpan K constants. Zero true unsafe code.*

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
