# StreamHash

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/)
[![.NET](https://img.shields.io/badge/.NET-10.0-blue.svg)](https://dotnet.microsoft.com/)
[![NuGet](https://img.shields.io/nuget/v/StreamHash)](https://www.nuget.org/packages/StreamHash)

**StreamHash** is a high-performance, memory-efficient streaming hash library for .NET 10+. All **70 hash algorithms** are implemented natively in pure C# with zero heavy dependencies — just one lightweight package (`System.IO.Hashing`) for CRC/xxHash acceleration.

## 🎯 Why StreamHash?

- **Single package, all algorithms**: One NuGet install gives you 70 hash algorithms — no BouncyCastle, no native binaries, no transitive dependency hell
- **Streaming everything**: Many popular algorithms (MurmurHash, CityHash, SpookyHash, etc.) lack streaming APIs. Hashing a 10GB file normally requires 10GB of RAM! StreamHash processes data in chunks using ~16MB regardless of file size
- **Competitive performance**: Native C# implementations match or beat external libraries for most algorithms — [see benchmarks](docs/benchmarks.md)

## ✨ Features

- **🚀 Memory Efficient**: Hash multi-gigabyte files with minimal memory footprint
- **⚡ High Performance**: Optimized implementations with SIMD where available (Grøstl AES-NI, JH SSSE3, HighwayHash AVX2)
- **🔄 Streaming API**: Process data incrementally with `Update()` and `Finalize()`
- **📦 Zero Allocations**: Hot paths are allocation-free using `Span<T>`
- **🎯 Unified API**: `HashFacade` provides access to all 70 algorithms through a single interface
- **🔐 All-Native Crypto**: Every cryptographic algorithm implemented in pure C# — no BouncyCastle dependency
- **⚡ Batch Streaming**: Process 70 algorithms in parallel with `CreateAllStreaming()`
- **🧪 Thoroughly Tested**: 1853+ tests validating against official test vectors
- **📦 Minimal Dependencies**: Only `System.IO.Hashing` — no large transitive dependency chains

## 🚀 Quick Start

### Installation

```bash
dotnet add package StreamHash --version 1.10.0
```

### One-Shot Hashing (Simplest)

```csharp
using StreamHash.Core;

byte[] data = File.ReadAllBytes("file.bin");

// Compute a single hash
string hex = HashFacade.ComputeHashHex(HashAlgorithm.Sha256, data);
byte[] hash = HashFacade.ComputeHash(HashAlgorithm.XxHash64, data);

// Get algorithm info
var info = HashFacade.GetInfo(HashAlgorithm.Sha256);
Console.WriteLine($"{info.DisplayName}: {info.DigestSize} bytes, Crypto: {info.IsCryptographic}");
```

### Streaming a Single Algorithm

For large files that don't fit in memory:

```csharp
using StreamHash.Core;

using var hasher = HashFacade.CreateStreaming(HashAlgorithm.MurmurHash3_128);
using var stream = File.OpenRead("large-file.bin");

byte[] buffer = new byte[1024 * 1024]; // 1MB buffer
int bytesRead;
while ((bytesRead = stream.Read(buffer)) > 0) {
	hasher.Update(buffer.AsSpan(0, bytesRead));
}

byte[] result = hasher.FinalizeBytes();
string hex = hasher.FinalizeHex();
```

### Batch Streaming — All 70 Algorithms at Once

Hash a file with all 70 algorithms in parallel, in a single pass:

```csharp
using StreamHash.Core;

using var multi = HashFacade.CreateAllStreaming();
using var stream = File.OpenRead("large-file.bin");

byte[] buffer = new byte[16 * 1024 * 1024]; // 16MB buffer recommended
int read;
while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) {
	multi.Update(buffer.AsSpan(0, read));
}

Dictionary<string, string> results = multi.FinalizeAll();
// results["SHA256"] = "abc123..."
// results["MD5"] = "def456..."
// ... all 70 algorithms
```

### Basic Hashes — The 4 Most Common

For the common case of verifying files with CRC32, MD5, SHA-1, and SHA-256:

```csharp
using StreamHash.Core;

using var basicHasher = HashFacade.CreateBasicHashesStreaming();
using var stream = File.OpenRead("download.zip");

var buffer = new byte[16 * 1024 * 1024];
int bytesRead;
while ((bytesRead = stream.Read(buffer)) > 0) {
	basicHasher.Update(buffer.AsSpan(0, bytesRead));
}

var results = basicHasher.FinalizeAll();
Console.WriteLine($"CRC32:   {results[HashAlgorithmNames.Crc32]}");
Console.WriteLine($"MD5:     {results[HashAlgorithmNames.Md5]}");
Console.WriteLine($"SHA-1:   {results[HashAlgorithmNames.Sha1]}");
Console.WriteLine($"SHA-256: {results[HashAlgorithmNames.Sha256]}");
```

**Tip**: Use `HashAlgorithmNames` constants instead of string literals to avoid typos!

### Direct Type API

You can also instantiate algorithm types directly:

```csharp
using StreamHash.Core;

using var hasher = new MurmurHash3_128();
hasher.Update(chunk1);
hasher.Update(chunk2);
UInt128 hash = hasher.Finalize();
```

## 📊 Algorithm Support (70 Algorithms)

| Category | Count | Algorithms |
|----------|:-----:|------------|
| **Checksums** | 9 | CRC32, CRC32C, CRC64, CRC-16 (CCITT/MODBUS/USB), Adler-32, Fletcher-16, Fletcher-32 |
| **Fast Non-Crypto** | 22 | xxHash (32/64/3/128), MurmurHash3 (32/128), CityHash (64/128), FarmHash64, SpookyV2, SipHash, HighwayHash64, MetroHash (64/128), wyhash64, FNV-1a (32/64), DJB2, DJB2a, SDBM, LoseLose |
| **MD Family** | 3 | MD2, MD4, MD5 |
| **SHA-1/2 Family** | 9 | SHA-0, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 |
| **SHA-3 & Keccak** | 6 | SHA3-224, SHA3-256, SHA3-384, SHA3-512, Keccak-256, Keccak-512 |
| **BLAKE Family** | 5 | BLAKE-256, BLAKE-512, BLAKE2b, BLAKE2s, BLAKE3 |
| **RIPEMD Family** | 4 | RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320 |
| **Other Crypto** | 12 | Whirlpool, Tiger-192, GOST-94, Streebog-256/512, Skein-256/512/1024, Grøstl-256/512, JH-256/512, KangarooTwelve, SM3 |

All algorithms are implemented in pure native C# with zero true unsafe code.

## ⚡ Performance Highlights

StreamHash's native C# matches or beats external libraries for most algorithms:

- **4.9x faster**: Whirlpool vs BouncyCastle
- **2.5x faster**: SHA-1 (.NET hardware acceleration)
- **1.8x faster**: RIPEMD-128, Streebog-256
- **At parity**: BLAKE3 (matches Rust native!), SHA3 family, CRC, xxHash
- **20 algorithms faster** than BouncyCastle, only 2 meaningfully slower (BLAKE2b/2s with AVX2 SIMD)

Full benchmark data with detailed comparisons at all data sizes: **[Performance Benchmarks](docs/benchmarks.md)**

## 📖 Documentation

- [📚 Algorithm Reference](docs/algorithms/README.md) — all 70 algorithms documented
- [📈 Performance Benchmarks](docs/benchmarks.md) — detailed comparisons vs BouncyCastle, System.IO.Hashing, Blake2Fast
- [📋 Reference Hash Values](docs/reference-hashes.md) — test vectors and expected outputs
- [📝 Changelog](CHANGELOG.md) — version history and release notes

### Algorithm Documentation

| Category | Docs |
|----------|------|
| BLAKE2b/2s | [blake2.md](docs/algorithms/blake2.md) |
| BLAKE3 | [blake3.md](docs/algorithms/blake3.md) |
| Keccak/SHA-3 | [keccak-sha3.md](docs/algorithms/keccak-sha3.md) |
| SHA-0/224/512t | [sha-family.md](docs/algorithms/sha-family.md) |
| MD2/MD4/MD5 | [md-family.md](docs/algorithms/md-family.md) |
| RIPEMD family | [ripemd.md](docs/algorithms/ripemd.md) |
| Skein family | [skein.md](docs/algorithms/skein.md) |
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

## 🏗️ Building

```bash
git clone https://github.com/TheAnsarya/StreamHash.git
cd StreamHash
dotnet build StreamHash.slnx
dotnet test    # 1853+ tests
```

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
