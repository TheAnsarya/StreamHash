using BenchmarkDotNet.Attributes;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Benchmarks for streaming hash algorithms processing data in chunks.
/// Simulates real-world file streaming scenarios with both individual
/// and multi-hash (batch) configurations.
/// </summary>
[MemoryDiagnoser]
public class StreamingChunkBenchmarks {
	private byte[] _data = null!;

	[Params(16 * 1024, 1024 * 1024, 10 * 1024 * 1024)] // 16KB, 1MB, 10MB
	public int TotalSize { get; set; }

	[Params(4096, 8192, 65536, 262144, 1048576)] // 4KB, 8KB, 64KB, 256KB, 1MB
	public int ChunkSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[TotalSize];
		new Random(42).NextBytes(_data);
	}

	[Benchmark(Baseline = true)]
	public uint MurmurHash3_32_Chunked() {
		using var hasher = new MurmurHash3_32(0);
		for (int i = 0; i < _data.Length; i += ChunkSize) {
			int count = Math.Min(ChunkSize, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.Finalize();
	}

	[Benchmark]
	public UInt128 MurmurHash3_128_Chunked() {
		using var hasher = new MurmurHash3_128(0);
		for (int i = 0; i < _data.Length; i += ChunkSize) {
			int count = Math.Min(ChunkSize, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.Finalize();
	}

	[Benchmark]
	public ulong SipHash24_Chunked() {
		using var hasher = new SipHash24(0, 0);
		for (int i = 0; i < _data.Length; i += ChunkSize) {
			int count = Math.Min(ChunkSize, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.Finalize();
	}

	[Benchmark]
	public UInt128 SpookyHash128_Chunked() {
		using var hasher = new SpookyHash128(0, 0);
		for (int i = 0; i < _data.Length; i += ChunkSize) {
			int count = Math.Min(ChunkSize, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.Finalize();
	}

	[Benchmark]
	public Dictionary<string, string> Basic4_Chunked() {
		using var hasher = HashFacade.CreateBasicHashesStreaming();
		for (int i = 0; i < _data.Length; i += ChunkSize) {
			int count = Math.Min(ChunkSize, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.FinalizeAll();
	}

	[Benchmark]
	public Dictionary<string, string> All70_Chunked() {
		using var hasher = HashFacade.CreateAllStreaming();
		for (int i = 0; i < _data.Length; i += ChunkSize) {
			int count = Math.Min(ChunkSize, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.FinalizeAll();
	}
}
