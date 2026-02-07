using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Benchmarks comparing native StreamHash implementations vs BouncyCastle.
/// This measures the performance improvements from Epic #26.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class NativeVsBouncyCastleBenchmarks {
	private byte[] _smallData = null!;
	private byte[] _mediumData = null!;
	private byte[] _largeData = null!;

	[GlobalSetup]
	public void Setup() {
		_smallData = new byte[1024];       // 1 KB
		_mediumData = new byte[65536];     // 64 KB
		_largeData = new byte[1048576];    // 1 MB
		var rng = new Random(42);
		rng.NextBytes(_smallData);
		rng.NextBytes(_mediumData);
		rng.NextBytes(_largeData);
	}

	#region SM3 (Native Implementation)

	[Benchmark]
	[BenchmarkCategory("SM3", "Native", "1KB")]
	public byte[] SM3_Native_1KB() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _smallData);

	[Benchmark]
	[BenchmarkCategory("SM3", "Native", "64KB")]
	public byte[] SM3_Native_64KB() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _mediumData);

	[Benchmark]
	[BenchmarkCategory("SM3", "Native", "1MB")]
	public byte[] SM3_Native_1MB() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _largeData);

	#endregion

	#region RIPEMD Family (Native Implementations)

	[Benchmark]
	[BenchmarkCategory("RIPEMD", "Native", "64KB")]
	public byte[] Ripemd160_64KB() => HashFacade.ComputeHash(HashAlgorithm.Ripemd160, _mediumData);

	[Benchmark]
	[BenchmarkCategory("RIPEMD", "Native", "64KB")]
	public byte[] Ripemd256_64KB() => HashFacade.ComputeHash(HashAlgorithm.Ripemd256, _mediumData);

	[Benchmark]
	[BenchmarkCategory("RIPEMD", "Native", "64KB")]
	public byte[] Ripemd320_64KB() => HashFacade.ComputeHash(HashAlgorithm.Ripemd320, _mediumData);

	#endregion

	#region Keccak/SHA3 (Native Implementation)

	[Benchmark]
	[BenchmarkCategory("Keccak", "Native", "1KB")]
	public byte[] Keccak256_Native_1KB() => HashFacade.ComputeHash(HashAlgorithm.Keccak256, _smallData);

	[Benchmark]
	[BenchmarkCategory("Keccak", "Native", "64KB")]
	public byte[] Keccak256_Native_64KB() => HashFacade.ComputeHash(HashAlgorithm.Keccak256, _mediumData);

	[Benchmark]
	[BenchmarkCategory("Keccak", "Native", "1MB")]
	public byte[] Keccak256_Native_1MB() => HashFacade.ComputeHash(HashAlgorithm.Keccak256, _largeData);

	[Benchmark]
	[BenchmarkCategory("SHA3", "Native", "64KB")]
	public byte[] Sha3_256_Native_64KB() => HashFacade.ComputeHash(HashAlgorithm.Sha3_256, _mediumData);

	[Benchmark]
	[BenchmarkCategory("SHA3", "Native", "64KB")]
	public byte[] Sha3_512_Native_64KB() => HashFacade.ComputeHash(HashAlgorithm.Sha3_512, _mediumData);

	#endregion

	#region SHA-512/t (Native Implementation)

	[Benchmark]
	[BenchmarkCategory("SHA512t", "Native", "64KB")]
	public byte[] Sha512_224_Native_64KB() => HashFacade.ComputeHash(HashAlgorithm.Sha512_224, _mediumData);

	[Benchmark]
	[BenchmarkCategory("SHA512t", "Native", "64KB")]
	public byte[] Sha512_256_Native_64KB() => HashFacade.ComputeHash(HashAlgorithm.Sha512_256, _mediumData);

	#endregion

	#region Custom Implementations (Groestl, JH, Whirlpool)

	[Benchmark]
	[BenchmarkCategory("Custom", "64KB")]
	public byte[] Groestl256_64KB() => HashFacade.ComputeHash(HashAlgorithm.Groestl256, _mediumData);

	[Benchmark]
	[BenchmarkCategory("Custom", "64KB")]
	public byte[] Jh256_64KB() => HashFacade.ComputeHash(HashAlgorithm.Jh256, _mediumData);

	[Benchmark]
	[BenchmarkCategory("Custom", "64KB")]
	public byte[] Whirlpool_64KB() => HashFacade.ComputeHash(HashAlgorithm.Whirlpool, _mediumData);

	#endregion

	#region Baseline Comparisons (Built-in .NET)

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Baseline", "64KB")]
	public byte[] Sha256_Builtin_64KB() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _mediumData);

	[Benchmark]
	[BenchmarkCategory("Baseline", "64KB")]
	public byte[] Sha512_Builtin_64KB() => HashFacade.ComputeHash(HashAlgorithm.Sha512, _mediumData);

	[Benchmark]
	[BenchmarkCategory("Baseline", "64KB")]
	public byte[] XxHash64_Builtin_64KB() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _mediumData);

	#endregion

	#region BouncyCastle Remaining (GOST, Streebog, Skein)

	[Benchmark]
	[BenchmarkCategory("BouncyCastle", "64KB")]
	public byte[] Gost94_BC_64KB() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _mediumData);

	[Benchmark]
	[BenchmarkCategory("BouncyCastle", "64KB")]
	public byte[] Streebog256_BC_64KB() => HashFacade.ComputeHash(HashAlgorithm.Streebog256, _mediumData);

	[Benchmark]
	[BenchmarkCategory("BouncyCastle", "64KB")]
	public byte[] Skein256_BC_64KB() => HashFacade.ComputeHash(HashAlgorithm.Skein256, _mediumData);

	#endregion
}

/// <summary>
/// Focused benchmark for allocation analysis of our native implementations.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
public class NativeAllocationBenchmarks {
	private byte[] _data = null!;

	[GlobalSetup]
	public void Setup() {
		_data = new byte[65536]; // 64 KB
		new Random(42).NextBytes(_data);
	}

	// Native implementations - should have minimal allocations
	[Benchmark]
	public byte[] SM3_Native() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _data);

	[Benchmark]
	public byte[] Keccak256_Native() => HashFacade.ComputeHash(HashAlgorithm.Keccak256, _data);

	[Benchmark]
	public byte[] Sha3_256_Native() => HashFacade.ComputeHash(HashAlgorithm.Sha3_256, _data);

	[Benchmark]
	public byte[] Ripemd256_Native() => HashFacade.ComputeHash(HashAlgorithm.Ripemd256, _data);

	[Benchmark]
	public byte[] Ripemd320_Native() => HashFacade.ComputeHash(HashAlgorithm.Ripemd320, _data);

	[Benchmark]
	public byte[] Sha512_224_Native() => HashFacade.ComputeHash(HashAlgorithm.Sha512_224, _data);

	[Benchmark]
	public byte[] Sha512_256_Native() => HashFacade.ComputeHash(HashAlgorithm.Sha512_256, _data);

	// Custom implementations
	[Benchmark]
	public byte[] Groestl256_Custom() => HashFacade.ComputeHash(HashAlgorithm.Groestl256, _data);

	[Benchmark]
	public byte[] Jh256_Custom() => HashFacade.ComputeHash(HashAlgorithm.Jh256, _data);

	[Benchmark]
	public byte[] Whirlpool_Custom() => HashFacade.ComputeHash(HashAlgorithm.Whirlpool, _data);

	// BouncyCastle - for comparison
	[Benchmark(Baseline = true)]
	public byte[] Sha256_Builtin() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _data);

	[Benchmark]
	public byte[] Skein256_BC() => HashFacade.ComputeHash(HashAlgorithm.Skein256, _data);

	[Benchmark]
	public byte[] Gost94_BC() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _data);
}

