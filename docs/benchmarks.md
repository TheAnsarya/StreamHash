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
| xxHash128 | 34.7 µs | 30.2 GB/s | 40 B | **0.98x** |
| xxHash3 | 35.6 µs | 29.4 GB/s | 32 B | **0.99x** |
| CRC32 | 40.5 µs | 25.8 GB/s | 32 B | 0.98x |
| CRC64 | 49.0 µs | 21.4 GB/s | 32 B | 1.02x |
| xxHash64 | 115.2 µs | 9.1 GB/s | 32 B | 1.25x |
| xxHash32 | 132.1 µs | 7.9 GB/s | 32 B | **0.99x** |
| MurmurHash3-32 | 281.2 µs | 3.7 GB/s | 88 B | 0.91x |
| SipHash-2-4 | 407.0 µs | 2.6 GB/s | 120 B | 0.94x |
| HighwayHash64 | 759 µs | 1.4 GB/s | 360 B | AVX2 SIMD |

*HighwayHash uses AVX2 SIMD acceleration (managed Unsafe.As, zero true unsafe code).*

## Cryptographic Hashes (1MB data)

| Algorithm | Time | vs BouncyCastle | Notes |
|-----------|-----:|:---------------:|-------|
| BLAKE3 | 0.25 ms | **1.00x** | At parity with Rust native! |
| BLAKE2b | 0.97 ms | 1.14x | BC has AVX2 SIMD |
| BLAKE2s | 1.38 ms | 1.05x | Near parity |
| MD4 | 1.44 ms | 0.85x | Faster |
| SHA-1 | 1.50 ms | **0.40x** | 2.5x faster (.NET HW) |
| Skein-512 | 1.61 ms | **0.73x** | 1.4x faster |
| MD5 | 1.66 ms | **0.65x** | 1.5x faster (.NET HW) |
| Tiger-192 | 1.89 ms | 0.86x | Faster |
| SHA-512 | 2.18 ms | **0.79x** | 1.3x faster (.NET HW) |
| SHA-384 | 2.22 ms | **0.82x** | 1.2x faster (.NET HW) |
| Skein-256 | 2.28 ms | 0.83x | 1.2x faster |
| Skein-1024 | 2.29 ms | 0.81x | 1.2x faster |
| **RIPEMD-128** | **2.30 ms** | **0.56x** | **1.8x faster** (fully unrolled) |
| SHA-512/224 | 2.42 ms | **0.88x** | 1.1x faster |
| SHA-512/256 | 2.46 ms | **0.91x** | 1.1x faster |
| RIPEMD-160 | 2.96 ms | **0.70x** | 1.4x faster |
| SHA3-224 | 3.29 ms | 1.02x | At parity |
| RIPEMD-256 | 3.35 ms | 0.97x | Faster |
| Keccak-256 | 3.39 ms | 1.02x | At parity |
| SHA3-256 | 3.43 ms | 1.03x | At parity |
| SHA-256 | 3.90 ms | 0.87x | 1.2x faster (.NET HW) |
| SHA3-384 | 4.33 ms | 1.00x | At parity |
| SHA-224 | 4.57 ms | 0.98x | At parity |
| RIPEMD-320 | 4.88 ms | 1.03x | At parity |
| SM3 | 4.93 ms | 0.88x | 1.1x faster |
| SHA3-512 | 6.30 ms | 0.97x | Faster |
| Keccak-512 | 6.32 ms | 1.03x | At parity |
| Whirlpool | 10.18 ms | **0.21x** | **4.9x faster** |
| Streebog-256 | 13.27 ms | **0.57x** | 1.8x faster |
| Streebog-512 | 13.39 ms | **0.60x** | 1.7x faster |
| MD2 | 94.83 ms | 0.96x | At parity |
| GOST-94 | 113.6 ms | 0.75x | 1.3x faster, 35000x less alloc |

## Performance vs External Libraries (1MB data)

StreamHash implements all 70 algorithms natively in pure C#. Below are comparisons against external libraries at the 1MB data size (2026-03-16 benchmarks).

### Cryptographic Hash Comparisons

Ratio is relative to BouncyCastle (1.00x). Lower ratio = faster.

| Algorithm | StreamHash | BouncyCastle | Ratio | Winner |
|-----------|----------:|-----------:|------:|--------|
| **Whirlpool** | **10.18 ms** | **49.52 ms** | **0.21x** | **StreamHash 4.9x faster** |
| **SHA-1** | **1.50 ms** | **3.72 ms** | **0.40x** | **StreamHash 2.5x faster** |
| **RIPEMD-128** | **2.30 ms** | **4.14 ms** | **0.56x** | **StreamHash 1.8x faster** |
| **Streebog-256** | **13.27 ms** | **23.35 ms** | **0.57x** | **StreamHash 1.8x faster** |
| **Streebog-512** | **13.39 ms** | **22.38 ms** | **0.60x** | **StreamHash 1.7x faster** |
| **MD5** | **1.66 ms** | **2.55 ms** | **0.65x** | **StreamHash 1.5x faster** |
| **SipHash** | **0.39 ms** | **0.60 ms** | **0.66x** | **StreamHash 1.5x faster** |
| **RIPEMD-160** | **2.96 ms** | **4.23 ms** | **0.70x** | **StreamHash 1.4x faster** |
| **Skein-512** | **1.61 ms** | **2.22 ms** | **0.73x** | **StreamHash 1.4x faster** |
| **GOST-94** | **113.6 ms** | **150.8 ms** | **0.75x** | **StreamHash 1.3x faster** |
| **SHA-512** | **2.18 ms** | **2.77 ms** | **0.79x** | **StreamHash 1.3x faster** |
| **Skein-1024** | **2.29 ms** | **2.82 ms** | **0.81x** | **StreamHash 1.2x faster** |
| **SHA-384** | **2.22 ms** | **2.71 ms** | **0.82x** | **StreamHash 1.2x faster** |
| **Skein-256** | **2.28 ms** | **2.73 ms** | **0.83x** | **StreamHash 1.2x faster** |
| **MD4** | **1.44 ms** | **1.69 ms** | **0.85x** | **StreamHash 1.2x faster** |
| Tiger-192 | 1.89 ms | 2.19 ms | 0.86x | StreamHash faster |
| SHA-256 | 3.90 ms | 4.49 ms | 0.87x | StreamHash faster |
| SHA-512/224 | 2.42 ms | 2.75 ms | 0.88x | StreamHash faster |
| SM3 | 4.93 ms | 5.62 ms | 0.88x | StreamHash faster |
| SHA-512/256 | 2.46 ms | 2.71 ms | 0.91x | StreamHash faster |
| MD2 | 94.83 ms | 98.62 ms | 0.96x | ~Equal |
| RIPEMD-256 | 3.35 ms | 3.46 ms | 0.97x | ~Equal |
| SHA3-512 | 6.30 ms | 6.46 ms | 0.97x | ~Equal |
| SHA-224 | 4.57 ms | 4.65 ms | 0.98x | ~Equal |
| SHA3-384 | 4.33 ms | 4.33 ms | 1.00x | Equal |
| BLAKE3 | 0.25 ms | 0.25 ms | 1.00x | Equal (vs Rust native!) |
| SHA3-224 | 3.29 ms | 3.22 ms | 1.02x | ~Equal |
| Keccak-256 | 3.39 ms | 3.32 ms | 1.02x | ~Equal |
| SHA3-256 | 3.43 ms | 3.32 ms | 1.03x | ~Equal |
| Keccak-512 | 6.32 ms | 6.11 ms | 1.03x | ~Equal |
| RIPEMD-320 | 4.88 ms | 4.72 ms | 1.03x | ~Equal |
| BLAKE2s | 1.38 ms | 1.32 ms | 1.05x | Near parity |
| BLAKE2b | 0.97 ms | 0.85 ms | 1.14x | BC has AVX2 SIMD |

**Summary**: StreamHash is **faster for 20 of 33** crypto algorithms, at parity for 11, and slower for only 2 (BLAKE2b/2s where BouncyCastle uses SIMD). BLAKE3 now matches Rust native performance!

### Non-Crypto Hash Comparisons vs System.IO.Hashing

| Algorithm | StreamHash | System.IO.Hashing | Ratio | Notes |
|-----------|----------:|------------------:|------:|-------|
| xxHash128 | 34.7 µs | 35.4 µs | **0.98x** | Faster! |
| CRC32 | 40.5 µs | 41.3 µs | 0.98x | ~Equal |
| xxHash3 | 35.6 µs | 35.9 µs | **0.99x** | At parity |
| xxHash32 | 132.1 µs | 133.3 µs | **0.99x** | At parity |
| CRC64 | 49.0 µs | 48.1 µs | 1.02x | ~Equal |
| xxHash64 | 115.2 µs | 92.0 µs | 1.25x | Byte order overhead |

### Non-Crypto Hash Comparisons vs HashDepot

| Algorithm | StreamHash | HashDepot | Ratio | Notes |
|-----------|----------:|---------:|------:|-------|
| xxHash32 | 132.1 µs | 191.5 µs | 0.69x | StreamHash 1.4x faster |
| MurmurHash3-32 | 281.2 µs | 310.4 µs | 0.91x | StreamHash faster |
| SipHash-2-4 | 407.0 µs | 432.9 µs | 0.94x | StreamHash faster |

### BLAKE2 vs BouncyCastle + Blake2Fast (1MB data)

| Implementation | BLAKE2b | BLAKE2s |
|---|---:|---:|
| Blake2Fast (SSE2-AVX512 SIMD) | 721 µs (0.85x) | 1,202 µs (0.91x) |
| BouncyCastle (AVX2/SSSE3 SIMD) | 848 µs (1.00x) | 1,316 µs (1.00x) |
| **StreamHash (safe C#)** | **968 µs (1.14x)** | **1,377 µs (1.05x)** |

**Key insight**: BouncyCastle's BLAKE2 advantage is entirely from AVX2/SSSE3 SIMD intrinsics (via their `Blake2b_X86` class, donated from Blake2Fast). StreamHash achieves 1.05-1.14x without any SIMD in BLAKE2 — pure safe C# with fully unrolled compression rounds.

**Optimization history**: 6.29x → 4.42x (local variables) → 1.59x (full round unrolling) → 1.19-1.26x (Keccak loop opt) → **1.05-1.14x** (continued optimization).

### Biggest Wins

- **Whirlpool**: 4.9x faster (0.21x) — custom precomputed T-tables vs BouncyCastle's runtime computation
- **SHA-1**: 2.5x faster (0.40x) — uses .NET hardware-accelerated implementation
- **RIPEMD-128**: 1.8x faster (0.56x) — fully unrolled compression function
- **Streebog**: 1.7-1.8x faster (0.57-0.60x) — optimized S-box and linear transformation
- **MD5**: 1.5x faster (0.65x) — uses .NET hardware-accelerated implementation
- **RIPEMD-160**: 1.4x faster (0.70x) — optimized round functions
- **Skein-512**: 1.4x faster (0.73x) — optimized Threefish block cipher
- **xxHash32**: Now at parity (0.99x) — switched to one-shot API
- **BLAKE3**: Now at parity (1.00x) — matches Rust native performance!
- **GOST-94**: 1.3x faster (0.75x) with **35,000x less memory** (728 B vs 25 MB!)
- **Keccak/SHA-3**: At parity (0.97-1.03x) — massive improvement from 1.49-1.63x after loop unrolling optimization

### Memory Allocations

| Implementation | BLAKE2b Alloc | BLAKE2s Alloc |
|---|---:|---:|
| Blake2Fast | 88 B | 56 B |
| BouncyCastle | 416 B | 304 B |
| **StreamHash** | **384 B** | **248 B** |

StreamHash allocates less than BouncyCastle for both BLAKE2 variants.

## Very Large File Benchmarks (10 MB, 100 MB, 1 GB)

Tests how performance scales with data size. All ratios relative to the external reference (BouncyCastle for crypto, System.IO.Hashing for non-crypto).

### Crypto Algorithms vs BouncyCastle

| Algorithm | 10 MB (SH) | 10 MB (BC) | 10 MB Ratio | 100 MB (SH) | 100 MB (BC) | 100 MB Ratio | 1 GB (SH) | 1 GB (BC) | 1 GB Ratio |
|-----------|----------:|---------:|------:|----------:|---------:|------:|----------:|---------:|------:|
| **Whirlpool** | **122 ms** | **564 ms** | **0.22x** | **1.27 s** | **5.97 s** | **0.21x** | **13.0 s** | **56.6 s** | **0.23x** |
| **SHA-1** | **18.8 ms** | **39.6 ms** | **0.47x** | **248 ms** | **471 ms** | **0.53x** | **1.81 s** | **5.19 s** | **0.35x** |
| **RIPEMD-128** | **23.9 ms** | **44.4 ms** | **0.54x** | **236 ms** | **456 ms** | **0.52x** | **2.43 s** | **4.52 s** | **0.54x** |
| **MD5** | **17.9 ms** | **26.9 ms** | **0.67x** | **175 ms** | **260 ms** | **0.67x** | **1.77 s** | **2.72 s** | **0.65x** |
| **RIPEMD-160** | **32.2 ms** | **47.6 ms** | **0.68x** | **309 ms** | **434 ms** | **0.71x** | **3.13 s** | **4.61 s** | **0.68x** |
| **Skein-512** | **16.5 ms** | **23.7 ms** | **0.70x** | **159 ms** | **269 ms** | **0.59x** | **1.65 s** | **2.39 s** | **0.69x** |
| SHA-512 | 24.7 ms | 30.5 ms | 0.81x | 228 ms | 291 ms | 0.78x | 2.43 s | 2.92 s | 0.83x |
| SHA-256 | 41.3 ms | 51.7 ms | 0.80x | 430 ms | 500 ms | 0.86x | 4.19 s | 5.19 s | 0.81x |
| SHA-512/256 | 26.1 ms | 29.0 ms | 0.90x | 248 ms | 283 ms | 0.88x | 2.68 s | 2.91 s | 0.92x |
| SHA3-256 | 35.1 ms | 38.6 ms | 0.91x | 349 ms | 370 ms | 0.94x | 4.01 s | 3.78 s | 1.06x |
| RIPEMD-320 | 53.7 ms | 49.5 ms | 1.08x | 498 ms | 472 ms | 1.05x | 5.11 s | 5.05 s | 1.01x |
| Keccak-256 | 39.2 ms | 36.1 ms | 1.08x | 360 ms | 386 ms | 0.93x | 3.76 s | 4.31 s | 0.87x |
| BLAKE2b | 10.0 ms | 8.8 ms | 1.13x | 97.0 ms | 86.3 ms | 1.12x | 1.01 s | 859 ms | 1.18x |
| BLAKE2s | 14.0 ms | 13.5 ms | 1.04x | 136 ms | 134 ms | 1.02x | 1.44 s | 1.43 s | 1.00x |

### BLAKE3 vs Rust Native

| Size | StreamHash | Rust Native | Ratio |
|-----:|----------:|----------:|------:|
| 10 MB | 2.77 ms | 2.75 ms | 1.01x |
| 100 MB | 30.6 ms | 27.2 ms | 1.13x |
| 1 GB | 345 ms | 276 ms | 1.25x |

BLAKE3 remains within 1.01-1.25x of the Rust native library at scale.

### Non-Crypto Algorithms vs System.IO.Hashing

| Algorithm | 10 MB (SH) | 10 MB (SIO) | 10 MB Ratio | 100 MB (SH) | 100 MB (SIO) | 100 MB Ratio | 1 GB (SH) | 1 GB (SIO) | 1 GB Ratio |
|-----------|----------:|----------:|------:|----------:|----------:|------:|----------:|----------:|------:|
| **xxHash128** | **1.19 ms** | **1.00 ms** | **1.19x** | **11.1 ms** | **8.62 ms** | **1.28x** | **97.3 ms** | **138 ms** | **0.70x** |
| xxHash3 | 786 µs | 708 µs | 1.11x | 12.4 ms | 8.07 ms | 1.54x | 82.9 ms | 83.3 ms | 0.99x |
| xxHash64 | 1.35 ms | 1.42 ms | 0.95x | 11.3 ms | 12.0 ms | 0.94x | 103 ms | 102 ms | 1.02x |
| xxHash32 | 1.47 ms | 1.42 ms | 1.03x | 14.4 ms | 17.6 ms | 0.82x | 191 ms | 161 ms | 1.19x |
| CRC32 | 848 µs | 881 µs | 0.96x | 8.66 ms | 9.36 ms | 0.92x | 107 ms | 94.7 ms | 1.13x |
| CRC64 | 1.07 ms | 892 µs | 1.20x | 9.64 ms | 15.1 ms | 0.64x | 91.1 ms | 93.7 ms | 0.97x |

### Scaling Insights

- **Whirlpool**: Consistently 4-5x faster across all sizes — the largest sustained advantage
- **SHA-1**: Advantage *grows* at 1 GB (2.9x faster) due to .NET hardware acceleration scaling
- **RIPEMD-128**: Stable 1.8-1.9x advantage from fully unrolled compression
- **MD5**: Rock-solid 1.5x advantage at all sizes
- **Skein-512**: 1.4-1.7x faster, advantage grows at larger sizes
- **Keccak-256**: Crosses from slower (10 MB) to 1.15x faster (1 GB) — unrolling shines at scale
- **BLAKE2b/2s**: BouncyCastle maintains SIMD advantage, but gap narrows at scale for BLAKE2s
- **xxHash128**: Interesting reversal — slower at small sizes but **1.4x faster at 1 GB** due to one-shot optimization
- **BLAKE3**: Rust native advantage grows with data size (1.01x → 1.25x)

## Running Benchmarks

```bash
# All comparison benchmarks (StreamHash vs external libraries)
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks -- --filter "*ComparisonBenchmarks*" --job short

# Very large file benchmarks (10MB, 100MB, 1GB) - run separately
dotnet run -c Release --project benchmarks/StreamHash.Benchmarks -- --filter "*VeryLarge*" --job short

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
| `VeryLargeFileBenchmarks` | 10MB, 100MB, 1GB data sizes for scale testing (run separately) |

## Methodology

- **Data sizes**: 1 KB, 64 KB, 1 MB (captures small message overhead and large file throughput)
- **Very large data sizes**: 10 MB, 100 MB, 1 GB (for scale testing, run separately)
- **Job**: ShortRun (3 iterations, 1 launch, 3 warmup) for quick comparisons
- **Ratio**: Always relative to BouncyCastle as baseline (1.00x)
- **Memory**: Tracked via `MemoryDiagnoser` (Gen0/Gen1/Gen2 and allocated bytes)
