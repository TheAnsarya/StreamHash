# StreamHash Batch API Design

**Created:** January 26, 2026  
**Status:** Design / Planning  
**GitHub Issue:** #17  
**Related:** HashNow #12

## 🎯 Problem Statement

Current usage pattern in HashNow:

```csharp
// Creates 70 separate streaming hashers
var hashers = new Dictionary<string, IStreamingHashBytes>();
foreach (var algo in allAlgorithms) {
	hashers[algo] = HashFacade.CreateStreaming(algo);
}

// Updates each hasher 70 times per buffer chunk
foreach (var hasher in hashers.Values) {
	hasher.Update(buffer);  // 70 sequential calls!
}
```

**Performance Impact:**
- 70x function call overhead per chunk
- 70x memory copies of shared buffer
- No parallelization (sequential loop)
- Cache thrashing (switching between 70 states)
- Result: 0.95 MB/s throughput, 24x memory overhead

## 🚀 Proposed Solution: Batch Update API

### New Interface

```csharp
namespace StreamHash;

/// <summary>
/// Represents a streaming hash context for multiple algorithms.
/// Efficiently updates all selected algorithms with a single memory pass.
/// </summary>
public interface IMultiStreamingHashBytes : IDisposable {
	/// <summary>
	/// Updates all hash states with the provided data.
	/// </summary>
	/// <param name="data">The data to process.</param>
	/// <remarks>
	/// This method updates ALL algorithms in parallel, using a single
	/// memory pass to maximize cache efficiency and CPU utilization.
	/// </remarks>
	void Update(ReadOnlySpan<byte> data);
	
	/// <summary>
	/// Finalizes all hash computations and returns the results.
	/// </summary>
	/// <returns>
	/// Dictionary mapping algorithm name to hex-encoded hash value.
	/// </returns>
	Dictionary<string, string> FinalizeAll();
	
	/// <summary>
	/// Resets all hash states to initial values.
	/// </summary>
	void Reset();
	
	/// <summary>
	/// Gets the number of algorithms in this batch context.
	/// </summary>
	int AlgorithmCount { get; }
	
	/// <summary>
	/// Gets the names of all algorithms in this batch context.
	/// </summary>
	IReadOnlyList<string> AlgorithmNames { get; }
}

/// <summary>
/// Flags for selecting which algorithm categories to include.
/// </summary>
[Flags]
public enum HashAlgorithmSet {
	None = 0,
	Checksums = 1 << 0,          // CRC32, Adler-32, etc.
	FastNonCrypto = 1 << 1,      // xxHash, MurmurHash, etc.
	Cryptographic = 1 << 2,      // SHA-256, BLAKE3, etc.
	Experimental = 1 << 3,       // KangarooTwelve, etc.
	All = Checksums | FastNonCrypto | Cryptographic | Experimental
}
```

### HashFacade API Extension

```csharp
public static class HashFacade {
	// Existing methods...
	public static IStreamingHashBytes CreateStreaming(string algorithmName);
	public static byte[] ComputeHash(string algorithmName, ReadOnlySpan<byte> data);
	
	// NEW: Batch streaming API
	/// <summary>
	/// Creates a batch streaming context for multiple algorithms.
	/// </summary>
	/// <param name="algorithms">Flags indicating which algorithm sets to include.</param>
	/// <returns>A streaming context that updates all selected algorithms efficiently.</returns>
	public static IMultiStreamingHashBytes CreateAllStreaming(
		HashAlgorithmSet algorithms = HashAlgorithmSet.All);
	
	/// <summary>
	/// Creates a batch streaming context for specific algorithms.
	/// </summary>
	/// <param name="algorithmNames">Names of specific algorithms to include.</param>
	/// <returns>A streaming context that updates the selected algorithms efficiently.</returns>
	public static IMultiStreamingHashBytes CreateBatchStreaming(
		params string[] algorithmNames);
}
```

### Usage Examples

```csharp
// Example 1: Hash all 71 algorithms at once
using var batchHasher = HashFacade.CreateAllStreaming();
using var stream = File.OpenRead("large-file.bin");
var buffer = new byte[1024 * 1024];  // 1MB buffer
int bytesRead;
while ((bytesRead = stream.Read(buffer)) > 0) {
	batchHasher.Update(buffer.AsSpan(0, bytesRead));
}
var results = batchHasher.FinalizeAll();
// results["SHA-256"] = "abc123..."
// results["BLAKE3"] = "def456..."
// ... all 71 results

// Example 2: Hash specific algorithm sets
using var cryptoHasher = HashFacade.CreateAllStreaming(
	HashAlgorithmSet.Cryptographic | HashAlgorithmSet.Checksums);
cryptoHasher.Update(data);
var hashes = cryptoHasher.FinalizeAll();
// Only crypto + checksum algorithms

// Example 3: Hash specific algorithms
using var customHasher = HashFacade.CreateBatchStreaming(
	"SHA-256", "BLAKE3", "xxHash64");
customHasher.Update(data);
var specificHashes = customHasher.FinalizeAll();
// Only these 3 algorithms
```

## 🏗️ Implementation Design

### Class Structure

```csharp
internal class MultiStreamingHashBytes : IMultiStreamingHashBytes {
	private readonly Dictionary<string, IStreamingHashBytes> _hashers;
	private readonly object _syncLock = new object();
	private bool _disposed;
	
	public MultiStreamingHashBytes(IEnumerable<string> algorithmNames) {
		_hashers = new Dictionary<string, IStreamingHashBytes>();
		foreach (var name in algorithmNames) {
			_hashers[name] = HashFacade.CreateStreaming(name);
		}
	}
	
	public void Update(ReadOnlySpan<byte> data) {
		if (_disposed) throw new ObjectDisposedException(nameof(MultiStreamingHashBytes));
		
		// OPTION 1: Parallel processing (best for 8+ cores)
		Parallel.ForEach(_hashers.Values, hasher => {
			lock (hasher) {  // Each hasher has its own lock
				hasher.Update(data);
			}
		});
		
		// OPTION 2: Sequential with better cache locality (best for 2-4 cores)
		// foreach (var hasher in _hashers.Values) {
		//     hasher.Update(data);
		// }
		
		// OPTION 3: SIMD multi-hash (future optimization)
		// UpdateAllSimd(data, _hashers.Values);
	}
	
	public Dictionary<string, string> FinalizeAll() {
		if (_disposed) throw new ObjectDisposedException(nameof(MultiStreamingHashBytes));
		
		var results = new Dictionary<string, string>(_hashers.Count);
		foreach (var (name, hasher) in _hashers) {
			results[name] = hasher.FinalizeToHex();
		}
		return results;
	}
	
	public void Reset() {
		if (_disposed) throw new ObjectDisposedException(nameof(MultiStreamingHashBytes));
		
		foreach (var hasher in _hashers.Values) {
			hasher.Reset();
		}
	}
	
	public void Dispose() {
		if (_disposed) return;
		
		foreach (var hasher in _hashers.Values) {
			hasher.Dispose();
		}
		_disposed = true;
	}
	
	public int AlgorithmCount => _hashers.Count;
	public IReadOnlyList<string> AlgorithmNames => _hashers.Keys.ToList().AsReadOnly();
}
```

## 🎯 Optimization Strategies

### Strategy 1: Parallel Processing

```csharp
public void Update(ReadOnlySpan<byte> data) {
	// Use TPL to process hashers in parallel
	Parallel.ForEach(_hashers.Values, hasher => hasher.Update(data));
}
```

**Pros:**
- ✅ Simple to implement
- ✅ Scales with CPU cores (8 cores = ~8x speedup)
- ✅ No algorithm-specific changes needed

**Cons:**
- ❌ Thread overhead for small chunks
- ❌ Less efficient on CPUs with <4 cores
- ❌ Still 70x memory copies

**Expected Performance:**
- 8-core CPU: 8x faster (~7.6 MB/s → ~60 MB/s)
- 4-core CPU: 4x faster (~7.6 MB/s → ~30 MB/s)
- 2-core CPU: 2x faster (~7.6 MB/s → ~15 MB/s)

### Strategy 2: Cache-Friendly Sequential (with Prefetching)

```csharp
public void Update(ReadOnlySpan<byte> data) {
	// Process hashers in order optimized for cache locality
	// Group similar algorithms together (e.g., all SHA variants)
	foreach (var hasher in _cachedOrderedHashers) {
		hasher.Update(data);
	}
}
```

**Pros:**
- ✅ Better cache utilization
- ✅ Predictable performance
- ✅ No threading overhead

**Cons:**
- ❌ Doesn't scale with cores
- ❌ Still 70x function calls

**Expected Performance:**
- Slightly faster than current (~1.5x) due to better cache locality

### Strategy 3: SIMD Multi-Hash (Future)

```csharp
// Process 4-8 hashers simultaneously using AVX2/AVX-512
unsafe void UpdateAllSimd(ReadOnlySpan<byte> data, Span<IStreamingHashBytes> hashers) {
	// Load multiple hasher states into SIMD registers
	// Process data in parallel using vector instructions
	// Store updated states back
}
```

**Pros:**
- ✅ Massive speedup (16-32x possible)
- ✅ Single memory pass
- ✅ Maximum CPU utilization

**Cons:**
- ❌ Very complex to implement
- ❌ Algorithm-specific SIMD code needed
- ❌ Requires CPU with AVX2/AVX-512

**Expected Performance:**
- 16-32x faster (~15-30 MB/s → ~300-500 MB/s)

## 📊 Performance Targets

### Minimum Viable Performance (Strategy 1: Parallel)

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| 50MB File Time | 52.58s | 6-7s | 8x faster |
| Throughput | 0.95 MB/s | 60-70 MB/s | 60x faster |
| Memory | 1.18 GB | < 300 MB | 4x reduction |
| Gen0 GC | 201,000 | < 25,000 | 8x reduction |

### Stretch Goals (Strategy 3: SIMD)

| Metric | Current | Stretch | Improvement |
|--------|---------|---------|-------------|
| 50MB File Time | 52.58s | < 1s | 50x faster |
| Throughput | 0.95 MB/s | 300+ MB/s | 300x faster |
| Memory | 1.18 GB | < 150 MB | 8x reduction |

## 🧪 Testing Requirements

### Unit Tests

```csharp
[Fact]
public void BatchHasher_ProducesSameResults_AsIndividualHashers() {
	var data = RandomData(1024 * 1024);  // 1MB
	
	// Hash with individual hashers
	var individual = new Dictionary<string, string>();
	foreach (var algo in HashFacade.GetAllAlgorithms()) {
		using var hasher = HashFacade.CreateStreaming(algo);
		hasher.Update(data);
		individual[algo] = hasher.FinalizeToHex();
	}
	
	// Hash with batch hasher
	using var batchHasher = HashFacade.CreateAllStreaming();
	batchHasher.Update(data);
	var batch = batchHasher.FinalizeAll();
	
	// Results must match exactly
	Assert.Equal(individual.Count, batch.Count);
	foreach (var (algo, hash) in individual) {
		Assert.Equal(hash, batch[algo]);
	}
}

[Fact]
public void BatchHasher_SupportsReset() {
	var data1 = RandomData(1024);
	var data2 = RandomData(1024);
	
	using var hasher = HashFacade.CreateAllStreaming();
	
	hasher.Update(data1);
	var results1 = hasher.FinalizeAll();
	
	hasher.Reset();
	
	hasher.Update(data2);
	var results2 = hasher.FinalizeAll();
	
	Assert.NotEqual(results1["SHA-256"], results2["SHA-256"]);
}

[Fact]
public void BatchHasher_ChunkedUpdate_MatchesFullUpdate() {
	var data = RandomData(10 * 1024 * 1024);  // 10MB
	
	// Full update
	using var fullHasher = HashFacade.CreateAllStreaming();
	fullHasher.Update(data);
	var fullResults = fullHasher.FinalizeAll();
	
	// Chunked update (1MB chunks)
	using var chunkHasher = HashFacade.CreateAllStreaming();
	for (int i = 0; i < data.Length; i += 1024 * 1024) {
		int size = Math.Min(1024 * 1024, data.Length - i);
		chunkHasher.Update(data.AsSpan(i, size));
	}
	var chunkResults = chunkHasher.FinalizeAll();
	
	// Results must match
	Assert.Equal(fullResults, chunkResults);
}
```

### Performance Benchmarks

```csharp
[MemoryDiagnoser]
public class BatchHasherBenchmarks {
	private byte[] _data100KB;
	private byte[] _data1MB;
	private byte[] _data50MB;
	
	[GlobalSetup]
	public void Setup() {
		_data100KB = RandomData(100 * 1024);
		_data1MB = RandomData(1024 * 1024);
		_data50MB = RandomData(50 * 1024 * 1024);
	}
	
	[Benchmark]
	public void Sequential_100KB() {
		foreach (var algo in HashFacade.GetAllAlgorithms()) {
			using var hasher = HashFacade.CreateStreaming(algo);
			hasher.Update(_data100KB);
			_ = hasher.FinalizeToHex();
		}
	}
	
	[Benchmark]
	public void Batch_100KB() {
		using var hasher = HashFacade.CreateAllStreaming();
		hasher.Update(_data100KB);
		_ = hasher.FinalizeAll();
	}
	
	[Benchmark]
	public void Sequential_50MB() {
		foreach (var algo in HashFacade.GetAllAlgorithms()) {
			using var hasher = HashFacade.CreateStreaming(algo);
			hasher.Update(_data50MB);
			_ = hasher.FinalizeToHex();
		}
	}
	
	[Benchmark]
	public void Batch_50MB() {
		using var hasher = HashFacade.CreateAllStreaming();
		hasher.Update(_data50MB);
		_ = hasher.FinalizeAll();
	}
}
```

## 📋 Implementation Checklist

- [ ] Design `IMultiStreamingHashBytes` interface
- [ ] Implement `MultiStreamingHashBytes` class with parallel processing
- [ ] Add `HashFacade.CreateAllStreaming()` method
- [ ] Add `HashFacade.CreateBatchStreaming()` method
- [ ] Implement `HashAlgorithmSet` enum
- [ ] Write unit tests (all 71 algorithms match individual results)
- [ ] Write benchmark comparisons (sequential vs batch)
- [ ] Optimize parallel processing (test 2/4/8/16 core systems)
- [ ] Document API with XML comments and examples
- [ ] Update README with batch API usage
- [ ] Release StreamHash v1.7.0

## 🔗 Integration with HashNow

Once StreamHash v1.7.0 is released with batch API:

1. **Update HashNow dependency:**
   ```xml
   <PackageReference Include="StreamHash" Version="1.7.0" />
   ```

2. **Simplify StreamingHasher.cs:**
   ```csharp
   public class StreamingHasher : IDisposable {
       private readonly IMultiStreamingHashBytes _batchHasher;
       
       public StreamingHasher() {
           _batchHasher = HashFacade.CreateAllStreaming();
       }
       
       public void ProcessChunk(ReadOnlySpan<byte> data) {
           _batchHasher.Update(data);  // Single call!
       }
       
       public FileHashResult GetResult(FileInfo fileInfo) {
           var hashes = _batchHasher.FinalizeAll();
           return new FileHashResult { Hashes = hashes, ... };
       }
   }
   ```

3. **Verify performance improvement:**
   - Run HashNow benchmarks
   - Expect 8-16x speedup on 8+ core systems
   - Expect 4-6x memory reduction

---

**Last Updated:** January 26, 2026  
**Next Steps:** Begin implementation of `IMultiStreamingHashBytes` interface
