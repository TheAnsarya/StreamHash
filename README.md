# StreamHash

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/)
[![.NET](https://img.shields.io/badge/.NET-10.0-blue.svg)](https://dotnet.microsoft.com/)
[![NuGet](https://img.shields.io/nuget/v/StreamHash)](https://www.nuget.org/packages/StreamHash)

**StreamHash** is a high-performance, memory-efficient streaming hash library for .NET 10+. It provides incremental/streaming implementations of popular hash algorithms and a unified `HashFacade` API supporting **62 algorithms**.

## 🎯 Why StreamHash?

Many popular hash algorithms (MurmurHash, CityHash, SpookyHash, etc.) don't have official streaming APIs. This means hashing a 10GB file requires 10GB of RAM! StreamHash solves this by providing streaming implementations that process data in chunks, using only ~1MB of memory regardless of file size.

## ✨ Features

- **🚀 Memory Efficient**: Hash multi-gigabyte files with minimal memory footprint
- **⚡ High Performance**: SIMD-optimized implementations where available
- **🔄 Streaming API**: Process data incrementally with `Update()` and `Finalize()`
- **📦 Zero Allocations**: Hot paths are allocation-free using `Span<T>`
- **🎯 Unified API**: `HashFacade` provides access to 62 algorithms through a single interface
- **🧪 Thoroughly Tested**: 619+ tests validating against official test vectors
- **📖 Fully Documented**: XML docs, examples, and algorithm references

## 📊 Algorithm Support

### Streaming Implementations (16 native)

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

### HashFacade Unified API (62 algorithms)

The `HashFacade` class provides one-shot and streaming access to:
- **Checksums (6)**: CRC32, CRC32C, CRC64, Adler-32, Fletcher-16, Fletcher-32
- **Fast Non-Crypto (16)**: xxHash, MurmurHash3, CityHash, FarmHash, SpookyHash, SipHash, HighwayHash, MetroHash, wyhash
- **Cryptographic (26)**: MD family, SHA family, SHA-3, Keccak, BLAKE family, RIPEMD family
- **Other (14)**: Whirlpool, Tiger, GOST, Streebog, Skein, SM3

> **Note**: Cryptographic algorithms (SHA-3, BLAKE, etc.) require BouncyCastle. StreamHash.Core provides fast non-crypto hashes natively.

## 🚀 Quick Start

### Installation

```bash
dotnet add package StreamHash --version 1.3.0
```

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

# Run tests (619+ tests)
dotnet test

# Run benchmarks
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks
```

## 📊 Benchmarks

Benchmarks comparing StreamHash to reference implementations:

```
| Method              | File Size | Memory    | Throughput |
|---------------------|-----------|-----------|------------|
| MurmurHash3 (ref)   | 1 GB      | 1,024 MB  | 3.2 GB/s   |
| MurmurHash3 (stream)| 1 GB      | 1 MB      | 3.1 GB/s   |
| CityHash (ref)      | 1 GB      | 1,024 MB  | 4.5 GB/s   |
| CityHash (stream)   | 1 GB      | 1 MB      | 4.3 GB/s   |
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is released into the public domain under [The Unlicense](LICENSE). Do whatever you want with it.

## 🙏 Acknowledgments

- [SMHasher](https://github.com/aappleby/smhasher) - MurmurHash reference implementation
- [CityHash](https://github.com/google/cityhash) - Google's CityHash
- [SpookyHash](http://burtleburtle.net/bob/hash/spooky.html) - Bob Jenkins' SpookyHash
- [SipHash](https://github.com/veorq/SipHash) - Reference SipHash implementation

