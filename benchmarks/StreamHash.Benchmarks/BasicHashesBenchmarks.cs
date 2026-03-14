using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Benchmarks comparing CreateBasicHashesStreaming() (4 algorithms)
/// vs CreateAllStreaming() (70 algorithms) to demonstrate performance benefits.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public sealed class BasicHashesBenchmarks {
	private byte[] _smallData = null!;
	private byte[] _mediumData = null!;
	private byte[] _largeData = null!;

	[GlobalSetup]
	public void Setup() {
		var random = new Random(42);

		// 1MB - typical small file
		_smallData = new byte[1024 * 1024];
		random.NextBytes(_smallData);

		// 10MB - typical medium file
		_mediumData = new byte[10 * 1024 * 1024];
		random.NextBytes(_mediumData);

		// 100MB - large file
		_largeData = new byte[100 * 1024 * 1024];
		random.NextBytes(_largeData);
	}

	#region 1MB File Benchmarks

	[Benchmark]
	[BenchmarkCategory("1MB")]
	public Dictionary<string, string> BasicHashes_1MB() {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		hasher.Update(_smallData);
		return hasher.FinalizeAll();
	}

	[Benchmark]
	[BenchmarkCategory("1MB")]
	public Dictionary<string, string> AllHashes_1MB() {
		using var hasher = HashFacade.CreateAllStreaming();
		hasher.Update(_smallData);
		return hasher.FinalizeAll();
	}

	#endregion

	#region 10MB File Benchmarks

	[Benchmark]
	[BenchmarkCategory("10MB")]
	public Dictionary<string, string> BasicHashes_10MB() {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		hasher.Update(_mediumData);
		return hasher.FinalizeAll();
	}

	[Benchmark]
	[BenchmarkCategory("10MB")]
	public Dictionary<string, string> AllHashes_10MB() {
		using var hasher = HashFacade.CreateAllStreaming();
		hasher.Update(_mediumData);
		return hasher.FinalizeAll();
	}

	#endregion

	#region 100MB File Benchmarks

	[Benchmark]
	[BenchmarkCategory("100MB")]
	public Dictionary<string, string> BasicHashes_100MB() {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		hasher.Update(_largeData);
		return hasher.FinalizeAll();
	}

	[Benchmark]
	[BenchmarkCategory("100MB")]
	public Dictionary<string, string> AllHashes_100MB() {
		using var hasher = HashFacade.CreateAllStreaming();
		hasher.Update(_largeData);
		return hasher.FinalizeAll();
	}

	#endregion

	#region Chunked Streaming (Real-World File I/O Pattern)

	[Benchmark]
	[BenchmarkCategory("Streaming")]
	public Dictionary<string, string> BasicHashes_Chunked_10MB() {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		const int chunkSize = 16 * 1024 * 1024; // 16MB chunks (typical buffer size)
		for (int i = 0; i < _mediumData.Length; i += chunkSize) {
			int size = Math.Min(chunkSize, _mediumData.Length - i);
			hasher.Update(_mediumData.AsSpan(i, size));
		}
		return hasher.FinalizeAll();
	}

	[Benchmark]
	[BenchmarkCategory("Streaming")]
	public Dictionary<string, string> AllHashes_Chunked_10MB() {
		using var hasher = HashFacade.CreateAllStreaming();
		const int chunkSize = 16 * 1024 * 1024; // 16MB chunks
		for (int i = 0; i < _mediumData.Length; i += chunkSize) {
			int size = Math.Min(chunkSize, _mediumData.Length - i);
			hasher.Update(_mediumData.AsSpan(i, size));
		}
		return hasher.FinalizeAll();
	}

	#endregion

	#region Individual Algorithm Comparison

	[Benchmark]
	[BenchmarkCategory("Individual")]
	public byte[] SHA256_Only_1MB() {
		return HashFacade.ComputeHash(HashAlgorithm.Sha256, _smallData);
	}

	[Benchmark]
	[BenchmarkCategory("Individual")]
	public byte[] MD5_Only_1MB() {
		return HashFacade.ComputeHash(HashAlgorithm.Md5, _smallData);
	}

	[Benchmark]
	[BenchmarkCategory("Individual")]
	public byte[] SHA1_Only_1MB() {
		return HashFacade.ComputeHash(HashAlgorithm.Sha1, _smallData);
	}

	[Benchmark]
	[BenchmarkCategory("Individual")]
	public byte[] CRC32_Only_1MB() {
		return HashFacade.ComputeHash(HashAlgorithm.Crc32, _smallData);
	}

	#endregion
}
