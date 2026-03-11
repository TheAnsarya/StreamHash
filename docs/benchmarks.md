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

## Performance vs External Libraries

StreamHash v1.10.0 implements all 70 algorithms natively in pure C#. Below are comparisons against the external libraries previously used.

### BLAKE2 vs BouncyCastle + Blake2Fast (1MB data)

| Implementation | BLAKE2b | BLAKE2s |
|---|---:|---:|
| Blake2Fast (SSE2-AVX512 SIMD) | 718 µs (0.87x) | 1,216 µs (0.92x) |
| BouncyCastle (AVX2 SIMD) | 826 µs (1.00x) | 1,320 µs (1.00x) |
| **StreamHash (safe C#)** | **1,337 µs (1.62x)** | **2,216 µs (1.68x)** |

**Key insight**: BouncyCastle's BLAKE2 advantage is entirely from AVX2 SIMD intrinsics (via their `Blake2b_X86` class, donated from Blake2Fast). StreamHash achieves 1.6x without any SIMD — pure safe C# with fully unrolled compression rounds.

**Optimization history**: 6.29x → 4.42x (local variables) → **1.62x** (full round unrolling).

### Memory Allocations

| Implementation | BLAKE2b Alloc | BLAKE2s Alloc |
|---|---:|---:|
| Blake2Fast | 100 B | 56 B |
| BouncyCastle | 416 B | 304 B |
| **StreamHash** | **384 B** | **296 B** |

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
