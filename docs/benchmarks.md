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

| Algorithm | Time | Throughput | Allocated | vs Reference |
|-----------|-----:|------------|----------:|:------------:|
| xxHash3 | 35.9 µs | 29.2 GB/s | 600 B | 1.04x |
| xxHash128 | 36.4 µs | 28.7 GB/s | 608 B | 1.05x |
| CRC32 | 37.6 µs | 27.8 GB/s | 32 B | 1.01x |
| CRC64 | 46.9 µs | 22.3 GB/s | 32 B | 1.00x |
| xxHash64 | 92.0 µs | 11.4 GB/s | 128 B | 1.05x |
| xxHash32 | 146.1 µs | 7.2 GB/s | 96 B | 1.09x |
| MurmurHash3-32 | 280.5 µs | 3.7 GB/s | 88 B | 0.96x |
| SipHash-2-4 | 386.2 µs | 2.7 GB/s | 120 B | 0.66x (vs BC) |
| HighwayHash64 | 759 µs | 1.4 GB/s | 360 B | AVX2 SIMD |

*HighwayHash uses AVX2 SIMD acceleration (managed Unsafe.As, zero true unsafe code).*

## Cryptographic Hashes (1MB data)

| Algorithm | Time | vs BouncyCastle | Notes |
|-----------|-----:|:---------------:|-------|
| BLAKE2b | 1.06 ms | 1.26x | Native C#, AVX2 SIMD path |
| MD4 | 1.42 ms | 0.85x | Faster |
| SHA-1 | 1.52 ms | 0.40x | 2.5x faster (.NET HW) |
| Skein-512 | 1.52 ms | 0.66x | 1.5x faster |
| BLAKE2s | 1.59 ms | 1.19x | Native C#, SSSE3 SIMD path |
| MD5 | 1.66 ms | 0.64x | 1.5x faster (.NET HW) |
| Tiger-192 | 1.98 ms | 0.89x | At parity |
| BLAKE3 | 2.16 ms | 8.08x | vs Rust native SIMD |
| Skein-1024 | 2.21 ms | 0.78x | 1.3x faster |
| SHA-384 | 2.25 ms | 0.79x | 1.3x faster (.NET HW) |
| Skein-256 | 2.26 ms | 0.80x | 1.3x faster |
| SHA-512 | 2.26 ms | 0.81x | 1.2x faster (.NET HW) |
| SHA-512/224 | 2.73 ms | 1.00x | At parity |
| SHA-512/256 | 2.75 ms | 0.99x | At parity |
| RIPEMD-160 | 3.02 ms | 0.70x | 1.4x faster |
| SHA3-224 | 3.13 ms | 1.01x | At parity (Keccak optimized) |
| RIPEMD-256 | 3.43 ms | 0.97x | At parity |
| Keccak-256 | 3.45 ms | 1.02x | At parity (Keccak optimized) |
| RIPEMD-128 | 3.49 ms | 0.82x | 1.2x faster |
| SHA3-256 | 3.51 ms | 1.06x | Near parity |
| SHA-256 | 3.77 ms | 0.86x | 1.2x faster (.NET HW) |
| SHA-224 | 4.40 ms | 0.96x | At parity |
| SHA3-384 | 4.35 ms | 1.00x | At parity |
| SM3 | 4.88 ms | 0.87x | 1.2x faster |
| RIPEMD-320 | 5.36 ms | 1.11x | Slightly slower |
| SHA3-512 | 6.32 ms | 1.02x | At parity |
| Keccak-512 | 6.53 ms | 0.95x | Faster (Keccak optimized) |
| Whirlpool | 10.77 ms | 0.20x | **5x faster** |
| Streebog-512 | 14.52 ms | 0.62x | 1.6x faster |
| Streebog-256 | 14.74 ms | 0.63x | 1.6x faster |
| MD2 | 97.70 ms | 0.96x | At parity |
| GOST-94 | 107.6 ms | 0.70x | 1.4x faster, 35000x less alloc |

## Performance vs External Libraries (1MB data)

StreamHash implements all 70 algorithms natively in pure C#. Below are comparisons against external libraries at the 1MB data size (2026-03-15 benchmarks).

### Cryptographic Hash Comparisons

Ratio is relative to BouncyCastle (1.00x). Lower ratio = faster.

| Algorithm | StreamHash | BouncyCastle | Ratio | Winner |
|-----------|----------:|-----------:|------:|--------|
| **Whirlpool** | **10.77 ms** | **53.30 ms** | **0.20x** | **StreamHash 5x faster** |
| **SHA-1** | **1.52 ms** | **3.77 ms** | **0.40x** | **StreamHash 2.5x faster** |
| **SipHash** | **0.39 ms** | **0.59 ms** | **0.66x** | **StreamHash 1.5x faster** |
| **Skein-512** | **1.52 ms** | **2.28 ms** | **0.66x** | **StreamHash 1.5x faster** |
| **MD5** | **1.66 ms** | **2.58 ms** | **0.64x** | **StreamHash 1.6x faster** |
| **Streebog-512** | **14.52 ms** | **23.30 ms** | **0.62x** | **StreamHash 1.6x faster** |
| **Streebog-256** | **14.74 ms** | **23.29 ms** | **0.63x** | **StreamHash 1.6x faster** |
| **GOST-94** | **107.6 ms** | **154.7 ms** | **0.70x** | **StreamHash 1.4x faster** |
| **RIPEMD-160** | **3.02 ms** | **4.33 ms** | **0.70x** | **StreamHash 1.4x faster** |
| **Skein-1024** | **2.21 ms** | **2.84 ms** | **0.78x** | **StreamHash 1.3x faster** |
| **SHA-384** | **2.25 ms** | **2.86 ms** | **0.79x** | **StreamHash 1.3x faster** |
| **Skein-256** | **2.26 ms** | **2.83 ms** | **0.80x** | **StreamHash 1.3x faster** |
| **SHA-512** | **2.26 ms** | **2.78 ms** | **0.81x** | **StreamHash 1.2x faster** |
| **RIPEMD-128** | **3.49 ms** | **4.25 ms** | **0.82x** | **StreamHash 1.2x faster** |
| **MD4** | **1.42 ms** | **1.68 ms** | **0.85x** | **StreamHash 1.2x faster** |
| **SHA-256** | **3.77 ms** | **4.37 ms** | **0.86x** | **StreamHash 1.2x faster** |
| **SM3** | **4.88 ms** | **5.64 ms** | **0.87x** | **StreamHash 1.1x faster** |
| Tiger-192 | 1.98 ms | 2.21 ms | 0.89x | StreamHash faster |
| Keccak-512 | 6.53 ms | 6.87 ms | 0.95x | ~Equal |
| SHA-224 | 4.40 ms | 4.60 ms | 0.96x | ~Equal |
| MD2 | 97.70 ms | 101.7 ms | 0.96x | ~Equal |
| RIPEMD-256 | 3.43 ms | 3.52 ms | 0.97x | ~Equal |
| SHA-512/256 | 2.75 ms | 2.80 ms | 0.99x | ~Equal |
| SHA3-384 | 4.35 ms | 4.34 ms | 1.00x | Equal |
| SHA-512/224 | 2.73 ms | 2.74 ms | 1.00x | Equal |
| SHA3-224 | 3.13 ms | 3.09 ms | 1.01x | Equal |
| Keccak-256 | 3.45 ms | 3.40 ms | 1.02x | ~Equal |
| SHA3-512 | 6.32 ms | 6.19 ms | 1.02x | ~Equal |
| SHA3-256 | 3.51 ms | 3.30 ms | 1.06x | Slightly slower |
| RIPEMD-320 | 5.36 ms | 4.81 ms | 1.11x | Slightly slower |
| BLAKE2s | 1.59 ms | 1.34 ms | 1.19x | BC has SSSE3 SIMD |
| BLAKE2b | 1.06 ms | 0.84 ms | 1.26x | BC has AVX2 SIMD |
| BLAKE3 | 2.16 ms | 0.27 ms | 8.08x | Rust native SIMD |

**Summary**: StreamHash is **faster for 18 of 33** crypto algorithms, at parity for 8, and slower for only 7. The only algorithms where StreamHash is meaningfully slower are BLAKE2 (BouncyCastle uses donated SIMD code from Blake2Fast) and BLAKE3 (compared against Rust native with full AVX2/SSE4).

### Non-Crypto Hash Comparisons vs System.IO.Hashing

| Algorithm | StreamHash | System.IO.Hashing | Ratio | Notes |
|-----------|----------:|------------------:|------:|-------|
| CRC64 | 46.9 µs | 47.1 µs | 1.00x | Equal |
| CRC32 | 37.6 µs | 37.3 µs | 1.01x | Equal |
| xxHash3 | 35.9 µs | 34.5 µs | 1.04x | ~Equal |
| xxHash128 | 36.4 µs | 34.9 µs | 1.05x | ~Equal |
| xxHash64 | 92.0 µs | 87.9 µs | 1.05x | ~Equal |
| xxHash32 | 146.1 µs | 134.7 µs | 1.09x | Near parity |

### Non-Crypto Hash Comparisons vs HashDepot

| Algorithm | StreamHash | HashDepot | Ratio | Notes |
|-----------|----------:|---------:|------:|-------|
| MurmurHash3-32 | 280.5 µs | 292.1 µs | 0.96x | StreamHash faster |
| SipHash-2-4 | 409.7 µs | 420.1 µs | 0.98x | StreamHash faster |
| xxHash32 | 146.1 µs | 182.2 µs | 0.80x | StreamHash faster |
| xxHash64 | 92.0 µs | 195.7 µs | 0.47x | StreamHash 2.1x faster |

### BLAKE2 vs BouncyCastle + Blake2Fast (1MB data)

| Implementation | BLAKE2b | BLAKE2s |
|---|---:|---:|
| Blake2Fast (SSE2-AVX512 SIMD) | 732 µs (0.87x) | 1,220 µs (0.91x) |
| BouncyCastle (AVX2/SSSE3 SIMD) | 840 µs (1.00x) | 1,337 µs (1.00x) |
| **StreamHash (safe C#)** | **1,060 µs (1.26x)** | **1,586 µs (1.19x)** |

**Key insight**: BouncyCastle's BLAKE2 advantage is entirely from AVX2/SSSE3 SIMD intrinsics (via their `Blake2b_X86` class, donated from Blake2Fast). StreamHash achieves 1.2-1.3x without any SIMD in BLAKE2 — pure safe C# with fully unrolled compression rounds.

**Optimization history**: 6.29x → 4.42x (local variables) → 1.59x (full round unrolling) → **1.19-1.26x** (Keccak loop opt + BLAKE2 safe refactor).

### Biggest Wins

- **Whirlpool**: 5x faster (0.20x) — custom precomputed T-tables vs BouncyCastle's runtime computation
- **SHA-1**: 2.5x faster (0.40x) — uses .NET hardware-accelerated implementation
- **xxHash64**: 2.1x faster (0.47x) vs HashDepot — optimized streaming
- **MD5**: 1.6x faster (0.64x) — uses .NET hardware-accelerated implementation
- **Streebog**: 1.6x faster (0.62x) — optimized S-box and linear transformation
- **Skein-512**: 1.5x faster (0.66x) — optimized Threefish block cipher
- **SipHash**: 1.5x faster (0.66x) — optimized streaming vs BouncyCastle
- **GOST-94**: 1.4x faster (0.70x) with **35,000x less memory** (728 B vs 25 MB!)
- **RIPEMD-160**: 1.4x faster (0.70x) — optimized round functions
- **Keccak/SHA-3**: At parity (0.95-1.06x) — massive improvement from 1.49-1.63x after loop unrolling optimization

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
