# StreamHash Performance Optimization Plan

## Current State

- **70 streaming hash algorithms** with batch API
- **SIMD optimizations** for HighwayHash64 (AVX2), Groestl (AES-NI), JH (SSSE3), Whirlpool (custom)
- **Native implementations** replacing BouncyCastle for MD2, MD4, SHA-0, SHA-224, Tiger-192, GOST-94
- **788+ tests** with comprehensive coverage

## Identified Optimization Opportunities

### Priority 1: Complete BouncyCastle Removal (Epic 26)

**Problem:** Several algorithms still delegate to acryptohashnet/BouncyCastle adapters, which:

- Add unnecessary heap allocations per hash operation
- Prevent SIMD optimization
- Increase package dependencies

**Remaining algorithms using adapters:**

- RIPEMD-128, RIPEMD-256, RIPEMD-320 (acryptohashnet adapter)
- SHA-0 (acryptohashnet adapter)
- Potentially others via AcryptohashnetAdapter

**Solution:** Implement these natively with streaming support, replacing adapter wrappers.

### Priority 2: SIMD Expansion

**Problem:** Only HighwayHash64, Groestl, JH, and Whirlpool have SIMD optimizations.

**Candidates for SIMD optimization:**

- **Skein-256/512/1024:** Threefish block cipher benefits heavily from AVX2
- **Streebog-256/512:** GOST R 34.11-2012 can use AES-NI for S-box operations
- **BLAKE-256/512:** The original BLAKE (not BLAKE2/3) could benefit from SSE2/AVX2
- **Keccak/SHA-3:** Keccak-f[1600] permutation has known vectorization strategies

**Expected Impact:** 2-5x throughput improvement for targeted algorithms.

### Priority 3: Memory Allocation Reduction

**Problem:** Some algorithm implementations still allocate temp arrays in hot paths.

**Solution:**

- Audit all `new byte[]` in hash computation paths
- Replace with `stackalloc` for < 1KB
- Replace with `ArrayPool<byte>` for > 1KB
- Use `Span<T>` slicing instead of array copies

### Priority 4: Batch API Optimization

**Problem:** Batch streaming creates all 70 hash instances upfront, even if caller only needs a subset.

**Solution:**

- Add `CreateStreamingBatch(params string[] algorithmNames)` for selective batching
- Lazy-initialize hash states only when first Update() is called
- Pool batch instances for reuse

### Priority 5: Benchmark Regression Infrastructure

**Problem:** No automated way to detect performance regressions between releases.

**Solution:**

- Store baseline benchmark results as JSON artifacts
- Add comparison benchmarks that fail if throughput drops > 5%
- Track per-algorithm throughput across versions

## Benchmark Matrix

| Category | Algorithms | Data Sizes | Metric |
|----------|------------|------------|--------|
| Checksums | CRC32, CRC64, Adler-32 | 1KB, 1MB, 100MB | MB/s |
| Fast non-crypto | xxHash64, MurmurHash3, CityHash64 | 1KB, 1MB, 100MB | MB/s |
| Cryptographic | SHA-256, SHA-512, SHA3-256, BLAKE3 | 1KB, 1MB, 100MB | MB/s |
| SIMD vs scalar | HighwayHash, Groestl, JH | 1MB, 100MB | MB/s |
| Batch all 70 | All algorithms | 1MB, 10MB, 100MB | MB/s aggregate |
| Memory | All algorithms | 10MB | Peak allocations (bytes) |

## Acceptance Criteria

1. All 788+ tests pass after every change
2. No hash output changes (accuracy is sacred)
3. BenchmarkDotNet shows measurable improvement
4. No increase in peak memory allocation
5. SIMD implementations have correct scalar fallbacks
