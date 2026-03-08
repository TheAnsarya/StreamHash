# StreamHash Implementation Plan

## 🎯 Project Goal

Create a high-performance, memory-efficient streaming hash library for .NET 10+ that converts 8 non-streaming hash algorithms to fully streaming implementations.

## 📊 Algorithm Analysis

### Why These Algorithms Need Streaming

Traditional implementations of these algorithms require the entire input in memory:

| Algorithm | Original Approach | Why Non-Streaming |
|-----------|------------------|-------------------|
| MurmurHash3 | Full buffer processing | Tail handling assumes full data |
| CityHash | Multiple passes for optimization | Length-dependent code paths |
| SpookyHash | Block + remainder processing | Short/long message distinction |
| SipHash | Finalization needs total length | Length encoded in final block |
| FarmHash | CRC intrinsics on full data | Hardware CRC needs alignment |
| HighwayHash | SIMD state accumulation | State vectors need careful management |

### Streaming Conversion Strategy

For each algorithm:

1. **Identify Block Size**: Determine the natural processing unit
2. **State Variables**: Extract and maintain intermediate hash state
3. **Buffer Management**: Handle partial blocks between updates
4. **Finalization**: Separate tail processing from block processing
5. **Length Tracking**: Accumulate total bytes for finalization

## 🏗️ Architecture Decisions

### Interface Design

```csharp
public interface IStreamingHash<TResult> : IDisposable
{
    int BlockSize { get; }
    int DigestSize { get; }
    long TotalBytesProcessed { get; }
    
    void Update(ReadOnlySpan<byte> data);
    TResult Finalize();
    void Reset();
}
```

**Rationale**:

- Generic result type supports uint, ulong, UInt128, byte[]
- `IDisposable` for ArrayPool buffer cleanup
- `Reset()` allows hasher reuse without reallocation
- `TotalBytesProcessed` needed for finalization formulas

### Base Class Benefits

`StreamingHashBase<T>` provides:

- Automatic buffer management with ArrayPool
- Block accumulation and dispatch
- State tracking (finalized, disposed)
- Exception handling patterns

### Memory Strategy

1. **ArrayPool Buffers**: Internal buffer from shared pool
2. **Stackalloc**: For small temporary operations (<1KB)
3. **No Allocations**: In Update() hot path after initialization
4. **Span-Based API**: Zero-copy data passing

## 📝 Implementation Details by Algorithm

### MurmurHash3-32

**Block Size**: 4 bytes (one uint)
**State**: Single uint (h1) + processed block count
**Complexity**: Low - straightforward block processing

```
ProcessBlock: k1 *= c1; rotl(k1,15); k1 *= c2; h1 ^= k1; ...
Finalize: Handle 1-3 tail bytes, mix with length
```

### MurmurHash3-128

**Block Size**: 16 bytes (two ulongs)
**State**: Two ulongs (h1, h2)
**Complexity**: Medium - dual state management

```
ProcessBlock: Process k1 and k2 independently, mix together
Finalize: Handle 1-15 tail bytes, final mixing
```

### SipHash-2-4

**Block Size**: 8 bytes (one ulong)
**State**: Four ulongs (v0-v3) initialized from key
**Complexity**: Medium - keyed hash with PRF security

```
ProcessBlock: v3 ^= m; 2 SipRounds; v0 ^= m
Finalize: Encode length in high byte, 4 final rounds
```

### SpookyHash V2

**Block Size**: 96 bytes (12 ulongs)
**State**: 12 ulongs (s0-s11)
**Complexity**: High - short vs long message paths

```
Short (<192 bytes): Different 4-state algorithm
Long (>=192 bytes): Full 12-state mixing
ProcessBlock: Mix all 12 words with state
Finalize: EndPartial mixing 3x
```

### CityHash64 (TODO)

**Block Size**: 32 bytes recommended
**State**: Multiple ulongs for accumulation
**Complexity**: High - many special cases

```
Short messages: Direct computation with shifts/muls
Long messages: Accumulate in 32-byte chunks
CRC optimization: SSE4.2 CRC32C when available
```

### CityHash128 (TODO)

**Block Size**: 16 bytes
**State**: UInt128 accumulator
**Complexity**: Medium-High

```
Similar to CityHash64 but with 128-bit state
```

### FarmHash64 (TODO)

**Block Size**: 64 bytes
**State**: Multiple ulongs
**Complexity**: High - evolved from CityHash

```
Uses CRC intrinsics when available
Multiple mixing functions based on length
Platform-specific optimizations
```

### HighwayHash64 (TODO)

**Block Size**: 32 bytes
**State**: Four 256-bit vectors (or scalar fallback)
**Complexity**: Very High - SIMD-first design

```
SIMD path: AVX2/SSE4.1 vector operations
Scalar path: Emulate with ulongs
Key-based initialization
```

## 🧪 Testing Strategy

### Test Categories

1. **Correctness Tests**
   - Official test vectors where available
   - Streaming vs one-shot equivalence
   - Various chunk sizes
   - Edge cases (empty, 1 byte, block boundaries)

2. **Property Tests**
   - Reset produces clean state
   - Same input → same output (determinism)
   - Different seeds → different outputs

3. **Error Handling Tests**
   - Update after Finalize throws
   - Finalize twice throws
   - Operations after Dispose throw

4. **Integration Tests**
   - File hashing scenarios
   - Network stream hashing
   - Large data handling

### Test Vector Sources

- MurmurHash3: SMHasher test suite
- SipHash: Official paper appendix
- SpookyHash: Bob Jenkins' test suite
- CityHash: Google's test data
- FarmHash: Google's test data
- HighwayHash: Google's test vectors

## 📈 Performance Optimization Plan

### Phase 1: Correctness First

- Implement algorithms correctly
- Verify against test vectors
- Ensure streaming consistency

### Phase 2: Profile and Measure

- BenchmarkDotNet baseline measurements
- Memory allocation profiling
- Hot path identification

### Phase 3: Micro-Optimizations

- Inline critical methods
- Use `[MethodImpl(AggressiveInlining)]`
- Optimize tail handling
- Reduce branching in hot paths

### Phase 4: SIMD Implementation

- HighwayHash SIMD (required for performance)
- Optional SIMD for other algorithms
- Runtime feature detection
- Scalar fallbacks

## 📦 Package Structure

```
StreamHash (meta-package)
├── StreamHash.Core (all implementations)
├── StreamHash.MurmurHash (just MurmurHash)
├── StreamHash.SipHash (just SipHash)
└── ...
```

**Decision**: Start with single package, split later if needed.

## 🔗 Dependencies

### Required

- None (pure .NET)

### Development

- xunit (testing)
- FluentAssertions (test assertions)
- BenchmarkDotNet (performance)
- coverlet (coverage)

## 📅 Timeline

| Week | Focus |
|------|-------|
| 1 | Infrastructure + MurmurHash3 |
| 2 | SipHash + SpookyHash |
| 3 | CityHash family |
| 4 | FarmHash |
| 5 | HighwayHash + SIMD |
| 6 | Documentation + Release |

## 🎯 Success Criteria

1. **Functional**: All 8 algorithms produce correct hashes
2. **Streaming**: Chunked processing equals one-shot
3. **Performance**: Within 20% of reference implementations
4. **Memory**: Zero allocations per Update() call
5. **Quality**: 95%+ code coverage, full XML docs
