# Performance Benchmarks

All benchmarks run on Intel Core i7-8700K (Coffee Lake), .NET 10.0, Windows 10.
Tests use `BenchmarkDotNet` with `MemoryDiagnoser` and `RankColumn`.

## Test Environment

- **CPU**: Intel Core i7-8700K 3.70GHz (Coffee Lake), 6 cores / 12 threads
- **RAM**: DDR4
- **OS**: Windows 10 22H2
- **Runtime**: .NET 10.0.4, X64 RyuJIT x86-64-v3
- **SIMD**: AVX2+BMI1+BMI2+FMA+SSE4.2+POPCNT

## Fast Non-Crypto Hashes (1MB data)

| Algorithm | Time | Throughput | Allocated |
|-----------|-----:|------------|----------:|
| CRC32 | 36 µs | 27.8 GB/s | 32 B |
| XxHash3 | 43 µs | 23.3 GB/s | 32 B |
| XxHash128 | 51 µs | 19.6 GB/s | 32 B |
| XxHash64 | 83 µs | 12.0 GB/s | 32 B |
| Wyhash64 | 130 µs | 7.7 GB/s | 32 B |
| CityHash128 | 133 µs | 7.5 GB/s | 32 B |
| FarmHash64 | 160 µs | 6.3 GB/s | 32 B |
| CityHash64 | 199 µs | 5.0 GB/s | 32 B |
| MurmurHash3_128 | 257 µs | 3.9 GB/s | 32 B |
| SpookyHash128 | 341 µs | 2.9 GB/s | 32 B |
| MurmurHash3_32 | 545 µs | 1.8 GB/s | 32 B |
| **HighwayHash64** | **756 µs** | **1.4 GB/s** | 32 B |

*HighwayHash uses AVX2 SIMD acceleration.*

## Cryptographic Hashes (1MB data)

| Algorithm | Time | Notes |
|-----------|-----:|-------|
| SHA-1 | 1.48 ms | .NET built-in |
| MD5 | 1.63 ms | .NET built-in |
| SHA-512 | 2.15 ms | .NET built-in |
| Tiger-192 | 2.19 ms | Native C# |
| BLAKE2b | 1.34 ms | Native, fully unrolled (v1.10.0) |
| BLAKE2s | 2.22 ms | Native, fully unrolled (v1.10.0) |
| SHA3-256 | 3.18 ms | Native Keccak-f[1600] |
| SHA-256 | 3.67 ms | .NET built-in |
| SM3 | 5.43 ms | Native C# |
| SHA3-512 | 6.22 ms | Native Keccak-f[1600] |
| BLAKE3 | 8.49 ms | Native C# (no Rust P/Invoke) |
| Whirlpool | 16.5 ms | Custom T-tables |
| Grøstl-256 | 61 ms | AES-NI + T-tables |
| JH-256 | 137 ms | Bit-sliced + SSSE3 |

## Performance vs External Libraries (1MB data)

StreamHash v1.10.0 implements all 70 algorithms natively in pure C#. Below are comparisons against the external libraries they replaced, at the 1MB data size.

### Cryptographic Hash Comparisons

Ratio is relative to BouncyCastle (1.00x) unless noted. Lower ratio = faster.

| Algorithm | StreamHash | Baseline | Ratio | Winner |
|-----------|----------:|---------:|------:|--------|
| **Whirlpool** | **11.72 ms** | **57.89 ms** | **0.20x** | **StreamHash 5x faster** |
| **SHA-1** | **1.51 ms** | **3.92 ms** | **0.39x** | **StreamHash 2.6x faster** |
| **Skein-512** | **1.76 ms** | **3.07 ms** | **0.57x** | **StreamHash 1.8x faster** |
| **GOST-94** | **106.82 ms** | **175.72 ms** | **0.61x** | **StreamHash 1.6x faster** |
| **MD5** | **1.71 ms** | **2.60 ms** | **0.66x** | **StreamHash 1.5x faster** |
| **SHA-512** | **2.29 ms** | **3.43 ms** | **0.67x** | **StreamHash 1.5x faster** |
| **Streebog-512** | **18.96 ms** | **26.96 ms** | **0.70x** | **StreamHash 1.4x faster** |
| **Streebog-256** | **19.58 ms** | **27.76 ms** | **0.71x** | **StreamHash 1.4x faster** |
| **Skein-256** | **2.61 ms** | **3.31 ms** | **0.79x** | **StreamHash 1.3x faster** |
| **RIPEMD-128** | **3.46 ms** | **4.33 ms** | **0.80x** | **StreamHash 1.2x faster** |
| **SHA-384** | **2.25 ms** | **2.78 ms** | **0.81x** | **StreamHash 1.2x faster** |
| MD4 | 1.56 ms | 1.72 ms | 0.91x | StreamHash faster |
| Tiger-192 | 2.28 ms | 2.51 ms | 0.91x | StreamHash faster |
| SHA-256 | 4.22 ms | 4.59 ms | 0.92x | StreamHash faster |
| SM3 | 5.67 ms | 6.12 ms | 0.93x | StreamHash faster |
| MD2 | 98.35 ms | 104.10 ms | 0.95x | ~Equal |
| RIPEMD-256 | 3.35 ms | 3.73 ms | 0.90x | StreamHash faster |
| RIPEMD-320 | 5.00 ms | 4.81 ms | 1.04x | ~Equal |
| SHA-224 | 5.22 ms | 4.75 ms | 1.10x | ~Equal |
| RIPEMD-160 | 5.87 ms | 4.70 ms | 1.25x | BouncyCastle faster |
| SHA-512/256 | 3.75 ms | 2.88 ms | 1.30x | BouncyCastle faster |
| SHA-512/224 | 3.82 ms | 2.88 ms | 1.33x | BouncyCastle faster |
| Keccak-512 | 9.86 ms | 6.61 ms | 1.49x | BouncyCastle faster |
| SHA3-256 | 5.21 ms | 3.47 ms | 1.50x | BouncyCastle faster |
| Keccak-256 | 5.18 ms | 3.40 ms | 1.52x | BouncyCastle faster |
| SHA3-512 | 10.00 ms | 6.63 ms | 1.52x | BouncyCastle faster |
| SHA3-384 | 7.02 ms | 4.58 ms | 1.53x | BouncyCastle faster |
| BLAKE2b | 1.31 ms | 0.83 ms | 1.59x | BouncyCastle (AVX2) |
| BLAKE2s | 2.21 ms | 1.37 ms | 1.61x | BouncyCastle (AVX2) |
| SHA3-224 | 5.23 ms | 3.20 ms | 1.63x | BouncyCastle faster |
| SipHash | 1.19 ms | 0.62 ms | 1.93x | BouncyCastle faster |
| Skein-1024 | 24.80 ms | 3.32 ms | 7.49x | BouncyCastle faster |
| BLAKE3 | 4.28 ms | 0.26 ms | 16.65x | Rust native (SIMD) |

**Summary**: StreamHash is **faster** for 16 of 33 algorithms, within 10% for 4 algorithms, and slower for 13 — mostly SHA-3/Keccak (where BouncyCastle benefits from a more optimized permutation) and algorithms with dedicated SIMD implementations (BLAKE2, BLAKE3).

### Non-Crypto Hash Comparisons

Ratio is relative to System.IO.Hashing baseline (or HashDepot where noted).

| Algorithm | StreamHash | Baseline | Ratio | Winner |
|-----------|----------:|---------:|------:|--------|
| **CRC64** | **52.02 µs** | **217.80 µs** | **0.24x** | **StreamHash 4.2x faster** |
| xxHash3 | 39.05 µs | 49.44 µs | 0.80x | StreamHash faster |
| xxHash64 | 103.62 µs | 106.66 µs | 0.97x | ~Equal |
| CRC32 | 41.85 µs | 41.76 µs | 1.00x | Equal |
| xxHash128 | 41.62 µs | 39.64 µs | 1.05x | ~Equal |
| xxHash32 | 163.16 µs | 146.13 µs | 1.12x | ~Equal |
| MurmurHash3-32 | 699.91 µs | 346.17 µs | 2.02x | HashDepot faster |
| SipHash-2-4 | 1,189.87 µs | 475.60 µs | 2.51x | HashDepot faster |

**Summary**: StreamHash matches or beats `System.IO.Hashing` for most xxHash variants. CRC64 is 4.2x faster. The streaming overhead for MurmurHash3 and SipHash shows vs one-shot HashDepot implementations.

### BLAKE2 vs BouncyCastle + Blake2Fast (1MB data)

| Implementation | BLAKE2b | BLAKE2s |
|---|---:|---:|
| Blake2Fast (SSE2-AVX512 SIMD) | 732 µs (0.88x) | 1,205 µs (0.88x) |
| BouncyCastle (AVX2 SIMD) | 827 µs (1.00x) | 1,372 µs (1.00x) |
| **StreamHash (safe C#)** | **1,314 µs (1.59x)** | **2,206 µs (1.61x)** |

**Key insight**: BouncyCastle's BLAKE2 advantage is entirely from AVX2 SIMD intrinsics (via their `Blake2b_X86` class, donated from Blake2Fast). StreamHash achieves 1.6x without any SIMD — pure safe C# with fully unrolled compression rounds.

**Optimization history**: 6.29x → 4.42x (local variables) → **1.59x** (full round unrolling).

### Biggest Wins

- **Whirlpool**: 5x faster — custom precomputed T-tables vs BouncyCastle's runtime computation
- **SHA-1**: 2.6x faster — uses .NET hardware-accelerated implementation
- **Skein-512**: 1.8x faster — optimized Threefish block cipher
- **GOST-94**: 1.6x faster with **35,000x less memory** (728 B vs 25 MB!)
- **MD5**: 1.5x faster — uses .NET hardware-accelerated implementation
- **SHA-512**: 1.5x faster — uses .NET hardware-accelerated implementation
- **CRC64**: 4.2x faster than System.IO.Hashing

### Memory Allocations

| Implementation | BLAKE2b Alloc | BLAKE2s Alloc |
|---|---:|---:|
| Blake2Fast | 88 B | 56 B |
| BouncyCastle | 416 B | 304 B |
| **StreamHash** | **384 B** | **248 B** |

StreamHash allocates less than BouncyCastle for both BLAKE2 variants.

## Running Benchmarks

```bash
# All comparison benchmarks (StreamHash vs external libraries)
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks -- --filter "*ComparisonBenchmarks*" --job short

# BLAKE2 only
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks -- --filter "*Blake2*" --job short

# All benchmarks (takes ~30 minutes)
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks
```

## Benchmark Classes

| Class | Purpose |
|---|---|
| `ComparisonBenchmarks` | 33 crypto algorithms vs BouncyCastle, acryptohashnet, Blake2Fast, Blake3, dotSHA3 |
| `NonCryptoComparisonBenchmarks` | 8 non-crypto algorithms vs System.IO.Hashing, HashDepot |
| `AllocationComparisonBenchmarks` | One-shot vs streaming allocation comparison |
| `HashFacadeBenchmarks` | Individual algorithm performance via HashFacade API |

## Methodology

- **Data sizes**: 1 KB, 64 KB, 1 MB (captures small message overhead and large file throughput)
- **Job**: ShortRun (3 iterations, 1 launch, 3 warmup) for quick comparisons
- **Ratio**: Always relative to BouncyCastle as baseline (1.00x)
- **Memory**: Tracked via `MemoryDiagnoser` (Gen0/Gen1/Gen2 and allocated bytes)
