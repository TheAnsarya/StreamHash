using BenchmarkDotNet.Attributes;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Throughput benchmarks for all streaming hash algorithms.
/// Measures GB/s throughput for various data sizes.
/// </summary>
[MemoryDiagnoser]
[DisassemblyDiagnoser(maxDepth: 3)]
public class ThroughputBenchmarks {
	private byte[] _data = null!;

	[Params(64, 1024, 4096, 65536, 1048576)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		new Random(42).NextBytes(_data);
	}

	[Benchmark(Baseline = true)]
	public uint MurmurHash3_32_OneShot() {
		return MurmurHash3_32.Hash(_data, 0);
	}

	[Benchmark]
	public uint MurmurHash3_32_Streaming() {
		using var hasher = new MurmurHash3_32(0);
		hasher.Update(_data);
		return hasher.Finalize();
	}

	[Benchmark]
	public UInt128 MurmurHash3_128_OneShot() {
		return MurmurHash3_128.Hash(_data, 0);
	}

	[Benchmark]
	public UInt128 MurmurHash3_128_Streaming() {
		using var hasher = new MurmurHash3_128(0);
		hasher.Update(_data);
		return hasher.Finalize();
	}

	[Benchmark]
	public ulong SipHash24_OneShot() {
		return SipHash24.Hash(_data, 0, 0);
	}

	[Benchmark]
	public ulong SipHash24_Streaming() {
		using var hasher = new SipHash24(0, 0);
		hasher.Update(_data);
		return hasher.Finalize();
	}

	[Benchmark]
	public UInt128 SpookyHash128_OneShot() {
		return SpookyHash128.Hash(_data, 0, 0);
	}

	[Benchmark]
	public UInt128 SpookyHash128_Streaming() {
		using var hasher = new SpookyHash128(0, 0);
		hasher.Update(_data);
		return hasher.Finalize();
	}
}
