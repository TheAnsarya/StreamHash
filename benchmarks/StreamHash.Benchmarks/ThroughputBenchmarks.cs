using BenchmarkDotNet.Attributes;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Throughput benchmarks for all streaming hash algorithms.
/// Measures GB/s throughput for various data sizes.
/// </summary>
[MemoryDiagnoser]
[DisassemblyDiagnoser(maxDepth: 3)]
public sealed class ThroughputBenchmarks {
	private byte[] _data = null!;
	private static readonly ulong[] HighwayKey = [
		0x0706050403020100UL,
		0x0f0e0d0c0b0a0908UL,
		0x1716151413121110UL,
		0x1f1e1d1c1b1a1918UL
	];

	[Params(64, 1024, 4096, 65536, 1048576)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		new Random(42).NextBytes(_data);
	}

	#region MurmurHash3

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

	#endregion

	#region SipHash

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

	#endregion

	#region SpookyHash

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

	#endregion

	#region CityHash

	[Benchmark]
	public ulong CityHash64_OneShot() {
		return CityHash64.Hash(_data);
	}

	[Benchmark]
	public ulong CityHash64_Streaming() {
		using var hasher = new CityHash64();
		hasher.Update(_data);
		return hasher.Finalize();
	}

	[Benchmark]
	public UInt128 CityHash128_OneShot() {
		return CityHash128.Hash(_data);
	}

	[Benchmark]
	public UInt128 CityHash128_Streaming() {
		using var hasher = new CityHash128();
		hasher.Update(_data);
		return hasher.Finalize();
	}

	#endregion

	#region FarmHash

	[Benchmark]
	public ulong FarmHash64_OneShot() {
		return FarmHash64.Hash(_data);
	}

	[Benchmark]
	public ulong FarmHash64_Streaming() {
		using var hasher = new FarmHash64();
		hasher.Update(_data);
		return hasher.Finalize();
	}

	#endregion

	#region HighwayHash

	[Benchmark]
	public ulong HighwayHash64_OneShot() {
		return HighwayHash64.Hash(_data, HighwayKey);
	}

	[Benchmark]
	public ulong HighwayHash64_Streaming() {
		using var hasher = new HighwayHash64(HighwayKey);
		hasher.Update(_data);
		return hasher.Finalize();
	}

	#endregion
}
