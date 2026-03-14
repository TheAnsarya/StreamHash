using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Comprehensive benchmark comparing all algorithms at different data sizes.
/// Groups algorithms by category to identify best performers per use case.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public sealed class AllAlgorithmsBenchmarks {
	private byte[] _data = null!;

	[Params(1024, 65536, 1048576)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		new Random(42).NextBytes(_data);
	}

	#region Checksums (expected to be fastest)

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Crc32() => HashFacade.ComputeHash(HashAlgorithm.Crc32, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Crc32C() => HashFacade.ComputeHash(HashAlgorithm.Crc32C, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Adler32() => HashFacade.ComputeHash(HashAlgorithm.Adler32, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] XxHash32() => HashFacade.ComputeHash(HashAlgorithm.XxHash32, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] XxHash64() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] XxHash3() => HashFacade.ComputeHash(HashAlgorithm.XxHash3, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] XxHash128() => HashFacade.ComputeHash(HashAlgorithm.XxHash128, _data);

	#endregion

	#region Non-Crypto Fast Hashes

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] MurmurHash3_32() => HashFacade.ComputeHash(HashAlgorithm.MurmurHash3_32, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] MurmurHash3_128() => HashFacade.ComputeHash(HashAlgorithm.MurmurHash3_128, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] CityHash64() => HashFacade.ComputeHash(HashAlgorithm.CityHash64, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] CityHash128() => HashFacade.ComputeHash(HashAlgorithm.CityHash128, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] FarmHash64() => HashFacade.ComputeHash(HashAlgorithm.FarmHash64, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] SipHash24() => HashFacade.ComputeHash(HashAlgorithm.SipHash24, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] SpookyHash128() => HashFacade.ComputeHash(HashAlgorithm.SpookyHash128, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] Wyhash64() => HashFacade.ComputeHash(HashAlgorithm.Wyhash64, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] HighwayHash64() => HashFacade.ComputeHash(HashAlgorithm.HighwayHash64, _data);

	#endregion

	#region Simple/String Hashes

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] Fnv1a32() => HashFacade.ComputeHash(HashAlgorithm.Fnv1a32, _data);

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] Fnv1a64() => HashFacade.ComputeHash(HashAlgorithm.Fnv1a64, _data);

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] Djb2() => HashFacade.ComputeHash(HashAlgorithm.Djb2, _data);

	#endregion

	#region Cryptographic - MD Family

	[Benchmark]
	[BenchmarkCategory("Crypto-MD")]
	public byte[] Md5() => HashFacade.ComputeHash(HashAlgorithm.Md5, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-MD")]
	public byte[] Md4() => HashFacade.ComputeHash(HashAlgorithm.Md4, _data);

	#endregion

	#region Cryptographic - SHA-1/2 Family

	[Benchmark]
	[BenchmarkCategory("Crypto-SHA")]
	public byte[] Sha1() => HashFacade.ComputeHash(HashAlgorithm.Sha1, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-SHA")]
	public byte[] Sha256() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-SHA")]
	public byte[] Sha384() => HashFacade.ComputeHash(HashAlgorithm.Sha384, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-SHA")]
	public byte[] Sha512() => HashFacade.ComputeHash(HashAlgorithm.Sha512, _data);

	#endregion

	#region Cryptographic - SHA-3 Family

	[Benchmark]
	[BenchmarkCategory("Crypto-SHA3")]
	public byte[] Sha3_256() => HashFacade.ComputeHash(HashAlgorithm.Sha3_256, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-SHA3")]
	public byte[] Sha3_512() => HashFacade.ComputeHash(HashAlgorithm.Sha3_512, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-SHA3")]
	public byte[] Keccak256() => HashFacade.ComputeHash(HashAlgorithm.Keccak256, _data);

	#endregion

	#region Cryptographic - BLAKE Family

	[Benchmark]
	[BenchmarkCategory("Crypto-BLAKE")]
	public byte[] Blake2b() => HashFacade.ComputeHash(HashAlgorithm.Blake2b, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-BLAKE")]
	public byte[] Blake2s() => HashFacade.ComputeHash(HashAlgorithm.Blake2s, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-BLAKE")]
	public byte[] Blake3() => HashFacade.ComputeHash(HashAlgorithm.Blake3, _data);

	#endregion

	#region Cryptographic - Other

	[Benchmark]
	[BenchmarkCategory("Crypto-Other")]
	public byte[] Ripemd160() => HashFacade.ComputeHash(HashAlgorithm.Ripemd160, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-Other")]
	public byte[] Ripemd256() => HashFacade.ComputeHash(HashAlgorithm.Ripemd256, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-Other")]
	public byte[] Ripemd320() => HashFacade.ComputeHash(HashAlgorithm.Ripemd320, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-Other")]
	public byte[] Whirlpool() => HashFacade.ComputeHash(HashAlgorithm.Whirlpool, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-Other")]
	public byte[] Tiger192() => HashFacade.ComputeHash(HashAlgorithm.Tiger192, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-Other")]
	public byte[] Groestl256() => HashFacade.ComputeHash(HashAlgorithm.Groestl256, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-Other")]
	public byte[] Jh256() => HashFacade.ComputeHash(HashAlgorithm.Jh256, _data);

	[Benchmark]
	[BenchmarkCategory("Crypto-Other")]
	public byte[] Sm3() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _data);

	#endregion
}

/// <summary>
/// Benchmarks for streaming vs one-shot performance comparison.
/// </summary>
[MemoryDiagnoser]
public sealed class StreamingVsOneShotBenchmarks {
	private byte[] _data = null!;

	[Params(4096, 65536, 1048576)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		new Random(42).NextBytes(_data);
	}

	#region xxHash64 - Streaming vs One-Shot

	[Benchmark(Baseline = true)]
	public byte[] XxHash64_OneShot() {
		return HashFacade.ComputeHash(HashAlgorithm.XxHash64, _data);
	}

	[Benchmark]
	public byte[] XxHash64_Streaming_FullData() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.XxHash64);
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] XxHash64_Streaming_4K_Chunks() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.XxHash64);
		for (int i = 0; i < _data.Length; i += 4096) {
			int count = Math.Min(4096, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.FinalizeBytes();
	}

	#endregion

	#region SHA-256 - Streaming vs One-Shot

	[Benchmark]
	public byte[] Sha256_OneShot() {
		return HashFacade.ComputeHash(HashAlgorithm.Sha256, _data);
	}

	[Benchmark]
	public byte[] Sha256_Streaming_FullData() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Sha256);
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] Sha256_Streaming_4K_Chunks() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Sha256);
		for (int i = 0; i < _data.Length; i += 4096) {
			int count = Math.Min(4096, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.FinalizeBytes();
	}

	#endregion

	#region MurmurHash3-128 - Streaming vs One-Shot

	[Benchmark]
	public byte[] MurmurHash3_128_OneShot() {
		return HashFacade.ComputeHash(HashAlgorithm.MurmurHash3_128, _data);
	}

	[Benchmark]
	public byte[] MurmurHash3_128_Streaming_FullData() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.MurmurHash3_128);
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] MurmurHash3_128_Streaming_4K_Chunks() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.MurmurHash3_128);
		for (int i = 0; i < _data.Length; i += 4096) {
			int count = Math.Min(4096, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.FinalizeBytes();
	}

	#endregion

	#region Blake3 - Streaming vs One-Shot

	[Benchmark]
	public byte[] Blake3_OneShot() {
		return HashFacade.ComputeHash(HashAlgorithm.Blake3, _data);
	}

	[Benchmark]
	public byte[] Blake3_Streaming_FullData() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Blake3);
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] Blake3_Streaming_4K_Chunks() {
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Blake3);
		for (int i = 0; i < _data.Length; i += 4096) {
			int count = Math.Min(4096, _data.Length - i);
			hasher.Update(_data.AsSpan(i, count));
		}
		return hasher.FinalizeBytes();
	}

	#endregion
}

/// <summary>
/// Memory allocation benchmarks for different algorithms.
/// </summary>
[MemoryDiagnoser]
public sealed class MemoryAllocationBenchmarks {
	private byte[] _data = null!;

	[GlobalSetup]
	public void Setup() {
		_data = new byte[65536];
		new Random(42).NextBytes(_data);
	}

	// Zero-allocation expected (uses .NET built-in)
	[Benchmark(Baseline = true)]
	public byte[] XxHash64_ZeroAlloc() {
		return HashFacade.ComputeHash(HashAlgorithm.XxHash64, _data);
	}

	// Zero-allocation expected (uses .NET built-in)
	[Benchmark]
	public byte[] Sha256_ZeroAlloc() {
		return HashFacade.ComputeHash(HashAlgorithm.Sha256, _data);
	}

	// Streaming custom implementation
	[Benchmark]
	public byte[] MurmurHash3_128_Custom() {
		return HashFacade.ComputeHash(HashAlgorithm.MurmurHash3_128, _data);
	}

	// BouncyCastle implementation
	[Benchmark]
	public byte[] Blake2b_BouncyCastle() {
		return HashFacade.ComputeHash(HashAlgorithm.Blake2b, _data);
	}

	// Custom streaming
	[Benchmark]
	public byte[] SipHash24_Custom() {
		return HashFacade.ComputeHash(HashAlgorithm.SipHash24, _data);
	}

	// Custom JH implementation
	[Benchmark]
	public byte[] Jh256_Custom() {
		return HashFacade.ComputeHash(HashAlgorithm.Jh256, _data);
	}

	// Custom Groestl implementation
	[Benchmark]
	public byte[] Groestl256_Custom() {
		return HashFacade.ComputeHash(HashAlgorithm.Groestl256, _data);
	}
}
