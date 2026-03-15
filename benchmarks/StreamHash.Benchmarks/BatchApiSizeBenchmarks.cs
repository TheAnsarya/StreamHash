using BenchmarkDotNet.Attributes;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Benchmarks for the batch streaming API, comparing full-suite vs category-specific
/// hashing to measure overhead of different algorithm set sizes.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 5)]
public class BatchApiSizeBenchmarks {
	private byte[] _data = null!;

	[Params(1024, 65536, 1024 * 1024)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		Random.Shared.NextBytes(_data);
	}

	[Benchmark(Description = "CreateAllStreaming (70 algorithms)")]
	public Dictionary<string, string> AllAlgorithms() {
		using var hasher = HashFacade.CreateAllStreaming();
		hasher.Update(_data.AsSpan());
		return hasher.FinalizeAll();
	}

	[Benchmark(Description = "Checksums only (9)")]
	public Dictionary<string, string> ChecksumsOnly() {
		using var hasher = HashFacade.CreateAllStreaming(HashAlgorithmSet.Checksums);
		hasher.Update(_data.AsSpan());
		return hasher.FinalizeAll();
	}

	[Benchmark(Description = "BasicHashes only (4)")]
	public Dictionary<string, string> BasicHashesOnly() {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		hasher.Update(_data.AsSpan());
		return hasher.FinalizeAll();
	}

	[Benchmark(Description = "SHA-256 + BLAKE3 only (2)")]
	public Dictionary<string, string> TwoAlgorithms() {
		using var hasher = HashFacade.CreateBatchStreaming(
			HashAlgorithmNames.Sha256,
			HashAlgorithmNames.Blake3);
		hasher.Update(_data.AsSpan());
		return hasher.FinalizeAll();
	}
}

/// <summary>
/// Benchmarks comparing one-shot vs streaming for memory allocation patterns.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 5)]
public class AllocationComparisonBenchmarks {
	private byte[] _data = null!;

	[Params(1024, 65536)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		Random.Shared.NextBytes(_data);
	}

	[Benchmark(Baseline = true, Description = "One-shot SHA-256")]
	public string OneShotSha256() {
		return HashFacade.ComputeHashHex(HashAlgorithm.Sha256, _data);
	}

	[Benchmark(Description = "Streaming SHA-256")]
	public string StreamingSha256() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Sha256);
		hasher.Update(_data.AsSpan());
		return Convert.ToHexStringLower(hasher.FinalizeBytes());
	}

	[Benchmark(Description = "One-shot BLAKE3")]
	public string OneShotBlake3() {
		return HashFacade.ComputeHashHex(HashAlgorithm.Blake3, _data);
	}

	[Benchmark(Description = "Streaming BLAKE3")]
	public string StreamingBlake3() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Blake3);
		hasher.Update(_data.AsSpan());
		return Convert.ToHexStringLower(hasher.FinalizeBytes());
	}
}
