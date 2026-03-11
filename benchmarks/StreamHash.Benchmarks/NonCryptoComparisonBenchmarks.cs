using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Compares StreamHash non-crypto hash implementations against the external libraries
/// they wrap or replace: System.IO.Hashing (Microsoft BCL) and HashDepot.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class NonCryptoComparisonBenchmarks {
	private byte[] _data = null!;

	[Params(1024, 65536, 1048576)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		new Random(42).NextBytes(_data);
	}

	#region CRC32

	[Benchmark]
	[BenchmarkCategory("CRC32")]
	public byte[] Crc32_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Crc32, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("CRC32")]
	public uint Crc32_SystemIOHashing() {
		return System.IO.Hashing.Crc32.HashToUInt32(_data);
	}

	#endregion

	#region CRC64

	[Benchmark]
	[BenchmarkCategory("CRC64")]
	public byte[] Crc64_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Crc64, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("CRC64")]
	public ulong Crc64_SystemIOHashing() {
		return System.IO.Hashing.Crc64.HashToUInt64(_data);
	}

	#endregion

	#region xxHash32

	[Benchmark]
	[BenchmarkCategory("xxHash32")]
	public byte[] XxHash32_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.XxHash32, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("xxHash32")]
	public uint XxHash32_SystemIOHashing() {
		return System.IO.Hashing.XxHash32.HashToUInt32(_data);
	}

	[Benchmark]
	[BenchmarkCategory("xxHash32")]
	public uint XxHash32_HashDepot() {
		return HashDepot.XXHash.Hash32(_data);
	}

	#endregion

	#region xxHash64

	[Benchmark]
	[BenchmarkCategory("xxHash64")]
	public byte[] XxHash64_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("xxHash64")]
	public ulong XxHash64_SystemIOHashing() {
		return System.IO.Hashing.XxHash64.HashToUInt64(_data);
	}

	[Benchmark]
	[BenchmarkCategory("xxHash64")]
	public ulong XxHash64_HashDepot() {
		return HashDepot.XXHash.Hash64(_data);
	}

	#endregion

	#region xxHash3

	[Benchmark]
	[BenchmarkCategory("xxHash3")]
	public byte[] XxHash3_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.XxHash3, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("xxHash3")]
	public byte[] XxHash3_SystemIOHashing() {
		return System.IO.Hashing.XxHash3.Hash(_data);
	}

	#endregion

	#region xxHash128

	[Benchmark]
	[BenchmarkCategory("xxHash128")]
	public byte[] XxHash128_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.XxHash128, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("xxHash128")]
	public byte[] XxHash128_SystemIOHashing() {
		return System.IO.Hashing.XxHash128.Hash(_data);
	}

	#endregion

	#region MurmurHash3-32

	[Benchmark]
	[BenchmarkCategory("MurmurHash3-32")]
	public byte[] MurmurHash3_32_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.MurmurHash3_32, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("MurmurHash3-32")]
	public uint MurmurHash3_32_HashDepot() {
		return HashDepot.MurmurHash3.Hash32(_data, 0);
	}

	#endregion

	#region SipHash-2-4

	[Benchmark]
	[BenchmarkCategory("SipHash24")]
	public byte[] SipHash24_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.SipHash24, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SipHash24")]
	public ulong SipHash24_HashDepot() {
		return HashDepot.SipHash24.Hash64(_data, new byte[16]);
	}

	#endregion
}
