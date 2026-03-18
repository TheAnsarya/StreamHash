using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Benchmarks to determine optimal chunk size for different file sizes.
/// Tests both CreateBasicHashesStreaming (4 algorithms) and CreateAllStreaming (70 algorithms)
/// across a matrix of file sizes and chunk sizes.
/// </summary>
/// <remarks>
/// <para>
/// The key question: does a 16MB chunk make sense for a 16KB file? This benchmark
/// generates the data to answer that question empirically.
/// </para>
/// <para>
/// Run with: dotnet run -c Release -- --filter "*ChunkSizeMatrix*" --job short
/// </para>
/// </remarks>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByParams)]
public class ChunkSizeMatrixBenchmarks {
	private byte[] _data = null!;

	/// <summary>
	/// File sizes to test: 16KB, 64KB, 256KB, 1MB, 10MB, 100MB.
	/// </summary>
	[Params(
		16 * 1024,          // 16KB - tiny file
		64 * 1024,          // 64KB - small file
		256 * 1024,         // 256KB - medium-small file
		1024 * 1024,        // 1MB - typical file
		10 * 1024 * 1024,   // 10MB - large file
		100 * 1024 * 1024   // 100MB - very large file
	)]
	public int FileSize { get; set; }

	/// <summary>
	/// Chunk sizes to test: 4KB, 8KB, 16KB, 64KB, 256KB, 1MB, 4MB.
	/// </summary>
	[Params(
		4 * 1024,       // 4KB - small I/O block
		8 * 1024,       // 8KB - typical read size
		16 * 1024,      // 16KB
		64 * 1024,      // 64KB - common buffer size
		256 * 1024,     // 256KB
		1024 * 1024,    // 1MB - large buffer
		4 * 1024 * 1024 // 4MB - very large buffer
	)]
	public int ChunkSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[FileSize];
		new Random(42).NextBytes(_data);
	}

	/// <summary>
	/// 4 basic algorithms (CRC32, MD5, SHA-1, SHA-256) with chunked streaming.
	/// </summary>
	[Benchmark]
	public Dictionary<string, string> Basic4_Chunked() {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		for (int i = 0; i < _data.Length; i += ChunkSize) {
			int size = Math.Min(ChunkSize, _data.Length - i);
			hasher.Update(_data.AsSpan(i, size));
		}
		return hasher.FinalizeAll();
	}

	/// <summary>
	/// All 70 algorithms with chunked streaming.
	/// </summary>
	[Benchmark]
	public Dictionary<string, string> All70_Chunked() {
		using var hasher = HashFacade.CreateAllStreaming();
		for (int i = 0; i < _data.Length; i += ChunkSize) {
			int size = Math.Min(ChunkSize, _data.Length - i);
			hasher.Update(_data.AsSpan(i, size));
		}
		return hasher.FinalizeAll();
	}
}

/// <summary>
/// Focused smaller benchmark for quick iteration — tests the most interesting
/// file size / chunk size combinations to avoid the full O(N*M) matrix.
/// </summary>
/// <remarks>
/// <para>
/// Run with: dotnet run -c Release -- --filter "*ChunkSizeQuick*" --job short
/// </para>
/// </remarks>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByParams)]
[SimpleJob(warmupCount: 3, iterationCount: 5)]
public class ChunkSizeQuickBenchmarks {
	private byte[] _16kData = null!;
	private byte[] _64kData = null!;
	private byte[] _1mData = null!;
	private byte[] _10mData = null!;

	[GlobalSetup]
	public void Setup() {
		var random = new Random(42);

		_16kData = new byte[16 * 1024];
		random.NextBytes(_16kData);

		_64kData = new byte[64 * 1024];
		random.NextBytes(_64kData);

		_1mData = new byte[1024 * 1024];
		random.NextBytes(_1mData);

		_10mData = new byte[10 * 1024 * 1024];
		random.NextBytes(_10mData);
	}

	#region 16KB file - does chunk size matter at all?

	[Benchmark]
	[BenchmarkCategory("16KB")]
	public Dictionary<string, string> All70_16KB_Chunk4KB() => ChunkedAll(_16kData, 4 * 1024);

	[Benchmark]
	[BenchmarkCategory("16KB")]
	public Dictionary<string, string> All70_16KB_Chunk8KB() => ChunkedAll(_16kData, 8 * 1024);

	[Benchmark]
	[BenchmarkCategory("16KB")]
	public Dictionary<string, string> All70_16KB_Chunk16KB() => ChunkedAll(_16kData, 16 * 1024);

	[Benchmark]
	[BenchmarkCategory("16KB")]
	public Dictionary<string, string> All70_16KB_SingleUpdate() => SingleUpdateAll(_16kData);

	#endregion

	#region 64KB file

	[Benchmark]
	[BenchmarkCategory("64KB")]
	public Dictionary<string, string> All70_64KB_Chunk4KB() => ChunkedAll(_64kData, 4 * 1024);

	[Benchmark]
	[BenchmarkCategory("64KB")]
	public Dictionary<string, string> All70_64KB_Chunk8KB() => ChunkedAll(_64kData, 8 * 1024);

	[Benchmark]
	[BenchmarkCategory("64KB")]
	public Dictionary<string, string> All70_64KB_Chunk16KB() => ChunkedAll(_64kData, 16 * 1024);

	[Benchmark]
	[BenchmarkCategory("64KB")]
	public Dictionary<string, string> All70_64KB_Chunk64KB() => ChunkedAll(_64kData, 64 * 1024);

	[Benchmark]
	[BenchmarkCategory("64KB")]
	public Dictionary<string, string> All70_64KB_SingleUpdate() => SingleUpdateAll(_64kData);

	#endregion

	#region 1MB file

	[Benchmark]
	[BenchmarkCategory("1MB")]
	public Dictionary<string, string> All70_1MB_Chunk8KB() => ChunkedAll(_1mData, 8 * 1024);

	[Benchmark]
	[BenchmarkCategory("1MB")]
	public Dictionary<string, string> All70_1MB_Chunk64KB() => ChunkedAll(_1mData, 64 * 1024);

	[Benchmark]
	[BenchmarkCategory("1MB")]
	public Dictionary<string, string> All70_1MB_Chunk256KB() => ChunkedAll(_1mData, 256 * 1024);

	[Benchmark]
	[BenchmarkCategory("1MB")]
	public Dictionary<string, string> All70_1MB_Chunk1MB() => ChunkedAll(_1mData, 1024 * 1024);

	[Benchmark]
	[BenchmarkCategory("1MB")]
	public Dictionary<string, string> All70_1MB_SingleUpdate() => SingleUpdateAll(_1mData);

	#endregion

	#region 10MB file

	[Benchmark]
	[BenchmarkCategory("10MB")]
	public Dictionary<string, string> All70_10MB_Chunk64KB() => ChunkedAll(_10mData, 64 * 1024);

	[Benchmark]
	[BenchmarkCategory("10MB")]
	public Dictionary<string, string> All70_10MB_Chunk256KB() => ChunkedAll(_10mData, 256 * 1024);

	[Benchmark]
	[BenchmarkCategory("10MB")]
	public Dictionary<string, string> All70_10MB_Chunk1MB() => ChunkedAll(_10mData, 1024 * 1024);

	[Benchmark]
	[BenchmarkCategory("10MB")]
	public Dictionary<string, string> All70_10MB_Chunk4MB() => ChunkedAll(_10mData, 4 * 1024 * 1024);

	[Benchmark]
	[BenchmarkCategory("10MB")]
	public Dictionary<string, string> All70_10MB_SingleUpdate() => SingleUpdateAll(_10mData);

	#endregion

	#region Basic4 comparison at key sizes

	[Benchmark]
	[BenchmarkCategory("Basic4")]
	public Dictionary<string, string> Basic4_16KB_Chunk4KB() => ChunkedBasic(_16kData, 4 * 1024);

	[Benchmark]
	[BenchmarkCategory("Basic4")]
	public Dictionary<string, string> Basic4_16KB_SingleUpdate() => SingleUpdateBasic(_16kData);

	[Benchmark]
	[BenchmarkCategory("Basic4")]
	public Dictionary<string, string> Basic4_1MB_Chunk64KB() => ChunkedBasic(_1mData, 64 * 1024);

	[Benchmark]
	[BenchmarkCategory("Basic4")]
	public Dictionary<string, string> Basic4_1MB_Chunk1MB() => ChunkedBasic(_1mData, 1024 * 1024);

	[Benchmark]
	[BenchmarkCategory("Basic4")]
	public Dictionary<string, string> Basic4_1MB_SingleUpdate() => SingleUpdateBasic(_1mData);

	[Benchmark]
	[BenchmarkCategory("Basic4")]
	public Dictionary<string, string> Basic4_10MB_Chunk256KB() => ChunkedBasic(_10mData, 256 * 1024);

	[Benchmark]
	[BenchmarkCategory("Basic4")]
	public Dictionary<string, string> Basic4_10MB_Chunk1MB() => ChunkedBasic(_10mData, 1024 * 1024);

	[Benchmark]
	[BenchmarkCategory("Basic4")]
	public Dictionary<string, string> Basic4_10MB_SingleUpdate() => SingleUpdateBasic(_10mData);

	#endregion

	private static Dictionary<string, string> ChunkedAll(byte[] data, int chunkSize) {
		using var hasher = HashFacade.CreateAllStreaming();
		for (int i = 0; i < data.Length; i += chunkSize) {
			int size = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, size));
		}
		return hasher.FinalizeAll();
	}

	private static Dictionary<string, string> SingleUpdateAll(byte[] data) {
		using var hasher = HashFacade.CreateAllStreaming();
		hasher.Update(data);
		return hasher.FinalizeAll();
	}

	private static Dictionary<string, string> ChunkedBasic(byte[] data, int chunkSize) {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		for (int i = 0; i < data.Length; i += chunkSize) {
			int size = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, size));
		}
		return hasher.FinalizeAll();
	}

	private static Dictionary<string, string> SingleUpdateBasic(byte[] data) {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		hasher.Update(data);
		return hasher.FinalizeAll();
	}
}
