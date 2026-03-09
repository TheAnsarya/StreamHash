# StreamHash Performance Optimization Plan

**Updated:** March 2026

## Memory Allocation Optimization (Completed March 2026)

- Reduced `MultiStreamingHashBytes` initial buffer from 16MB to 2MB (grows dynamically if needed)
- Typical callers send 1MB chunks, so 16MB was 16x over-allocated
- Buffer still grows via ArrayPool if a larger chunk is ever sent

## Benchmark Summary (38MB data, Feb 2026)

### Fast Algorithms (< 50ms for 38MB)

| Algorithm | Time | Ratio vs MD5 | Status |
|-----------|------|--------------|--------|
| xxHash3 | 4.4 ms | 0.07x | ✅ Built-in |
| xxHash64 | 4.6 ms | 0.07x | ✅ Built-in |
| wyhash64 | 5.9 ms | 0.09x | ✅ HashDepot |
| FarmHash64 | 7.1 ms | 0.11x | ✅ Native streaming |
| CityHash128 | 8.9 ms | 0.14x | ✅ Native streaming |
| BLAKE3 | 10.3 ms | 0.16x | ✅ Blake3.NET |
| MurmurHash3 | 10.6 ms | 0.17x | ✅ Native streaming |
| SpookyHash128 | 14.4 ms | 0.23x | ✅ Native streaming |
| BLAKE2b | 29.9 ms | 0.47x | ✅ Blake2Fast |
| HighwayHash64 | 30.1 ms | 0.48x | ✅ Native streaming |
| SipHash-2-4 | 42.8 ms | 0.68x | ✅ Native streaming |

### Medium Algorithms (50-500ms for 38MB)

| Algorithm | Time | Ratio vs MD5 | Status |
|-----------|------|--------------|--------|
| MD5 | 62.9 ms | 1.00x | ✅ Built-in |
| Tiger-192 | 85.0 ms | 1.35x | ✅ acryptohashnet |
| SHA-512 | 92.8 ms | 1.48x | ✅ Built-in |
| Skein-256 | 110.2 ms | 1.75x | ⚠️ BouncyCastle |
| RIPEMD-256 | 126.5 ms | 2.01x | ✅ Native |
| SHA-256 | 162.0 ms | 2.58x | ✅ Built-in |
| SM3 | 195.0 ms | 3.10x | ✅ Native |
| Keccak/SHA3 | ~200 ms | 3.14x | ✅ Native |
| Whirlpool | 427.6 ms | 6.80x | ⚠️ Custom impl |

### Slow Algorithms (> 500ms for 38MB) - Need Optimization

| Algorithm | Time | Ratio vs MD5 | Status |
|-----------|------|--------------|--------|
| RIPEMD-160 | 621.7 ms | 9.89x | ⚠️ acryptohashnet |
| Streebog-256 | 904.8 ms | 14.39x | ⚠️ BouncyCastle |
| GOST-94 | 4,065 ms | 64.64x | ⚠️ Native - inherently slow |
| Groestl-256 | 4,534 ms | 72.10x | ❌ Needs optimization |
| JH-256 | 6,107 ms | 97.12x | ❌ Needs optimization |

## Optimization Priorities

### High Priority (Large Impact)

1. **Native RIPEMD-160** - Replace acryptohashnet
   - Current: 621.7 ms (9.89x MD5)
   - Target: ~150 ms (2.5x MD5)
   - Approach: Port RIPEMD-256/320 implementation approach

2. **Optimize Groestl** - SHA-3 finalist
   - Current: 4,534 ms (72.10x MD5)
   - Target: ~400 ms (6x MD5)
   - Approach: Optimize permutation, use lookup tables

3. **Optimize JH** - SHA-3 finalist
   - Current: 6,107 ms (97.12x MD5)
   - Target: ~500 ms (8x MD5)
   - Approach: Optimize bijective function, pre-compute round constants

### Medium Priority

1. **Native Streebog** - Replace BouncyCastle
   - Current: 904.8 ms (14.39x MD5)
   - Target: ~300 ms (5x MD5)
   - Approach: Optimized GOST R 34.11-2012 implementation

2. **Native Skein** - Replace BouncyCastle
   - Current: 110.2 ms (1.75x MD5) - already decent
   - Target: ~80 ms (1.3x MD5)
   - Approach: Threefish block cipher optimization

### Low Priority (Inherently Slow)

1. **GOST-94 optimization** - Limited gain possible
   - Current: 4,065 ms (64.64x MD5)
   - Note: Uses 32-round block cipher per block - inherently O(n*32)
   - Max possible: ~2,000 ms with lookup table optimization
   - May not be worth significant effort

## Future Benchmarking

### Multi-Gigabyte File Testing (TODO)

- Test with 1GB, 5GB, 10GB files
- Measure memory pressure and GC impact
- Verify streaming doesn't accumulate allocations
- Test file-based streaming vs memory-based

### Real-World Scenarios

- ISO file hashing (~700MB-4.7GB)
- Video file verification (1-50GB)
- Archive verification (variable)
- ROM file hashing (1KB-64MB typical)

## Memory Allocation Goals

All algorithms should have:

- < 1KB allocation per hash operation
- Zero allocation growth with file size (streaming)
- ArrayPool usage for internal buffers

### Current Status

- ✅ GOST-94: 728 B (down from 1.5 MB!)
- ✅ Native algorithms: 40-200 B
- ⚠️ BouncyCastle: 900-1000 B (acceptable)
- ❌ Some custom: 500-800 B (could improve)

## Test Coverage Requirements

Every algorithm must have:

1. Empty input test
2. "abc" test vector (if available)
3. Large input consistency test
4. Streaming vs one-shot match test
5. Reset functionality test
6. Chunk size independence test
