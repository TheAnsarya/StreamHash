using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Benchmarks for large file sizes to test streaming performance.
/// Sizes: 64KB, 760KB, 3MB, 38MB
/// </summary>
/// <remarks>
/// These benchmarks test how algorithms handle larger data that requires
/// multiple update cycles in streaming mode. Important for real-world
/// file hashing scenarios.
/// </remarks>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class LargeFileBenchmarks {
	private byte[] _64KB = null!;
	private byte[] _760KB = null!;
	private byte[] _3MB = null!;
	private byte[] _38MB = null!;

	[GlobalSetup]
	public void Setup() {
		var rng = new Random(42);

		_64KB = new byte[65_536];          // 64 KB
		_760KB = new byte[778_240];        // 760 KB
		_3MB = new byte[3_145_728];        // 3 MB
		_38MB = new byte[39_845_888];      // 38 MB

		rng.NextBytes(_64KB);
		rng.NextBytes(_760KB);
		rng.NextBytes(_3MB);
		rng.NextBytes(_38MB);
	}

	#region Fast Hashes - xxHash Family

	[Benchmark]
	[BenchmarkCategory("Fast", "xxHash", "64KB")]
	public byte[] XxHash64_64KB() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _64KB);

	[Benchmark]
	[BenchmarkCategory("Fast", "xxHash", "760KB")]
	public byte[] XxHash64_760KB() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _760KB);

	[Benchmark]
	[BenchmarkCategory("Fast", "xxHash", "3MB")]
	public byte[] XxHash64_3MB() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _3MB);

	[Benchmark]
	[BenchmarkCategory("Fast", "xxHash", "38MB")]
	public byte[] XxHash64_38MB() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _38MB);

	[Benchmark]
	[BenchmarkCategory("Fast", "xxHash3", "38MB")]
	public byte[] XxHash3_38MB() => HashFacade.ComputeHash(HashAlgorithm.XxHash3, _38MB);

	[Benchmark]
	[BenchmarkCategory("Fast", "BLAKE3", "38MB")]
	public byte[] Blake3_38MB() => HashFacade.ComputeHash(HashAlgorithm.Blake3, _38MB);

	#endregion

	#region Cryptographic - SHA Family

	[Benchmark]
	[BenchmarkCategory("Crypto", "SHA256", "64KB")]
	public byte[] Sha256_64KB() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _64KB);

	[Benchmark]
	[BenchmarkCategory("Crypto", "SHA256", "760KB")]
	public byte[] Sha256_760KB() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _760KB);

	[Benchmark]
	[BenchmarkCategory("Crypto", "SHA256", "3MB")]
	public byte[] Sha256_3MB() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _3MB);

	[Benchmark]
	[BenchmarkCategory("Crypto", "SHA256", "38MB")]
	public byte[] Sha256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _38MB);

	[Benchmark]
	[BenchmarkCategory("Crypto", "SHA512", "38MB")]
	public byte[] Sha512_38MB() => HashFacade.ComputeHash(HashAlgorithm.Sha512, _38MB);

	[Benchmark]
	[BenchmarkCategory("Crypto", "SHA3", "38MB")]
	public byte[] Sha3_256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Sha3_256, _38MB);

	#endregion

	#region MD5 (Reference Baseline)

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Baseline", "MD5", "38MB")]
	public byte[] Md5_38MB() => HashFacade.ComputeHash(HashAlgorithm.Md5, _38MB);

	#endregion

	#region Custom/Native Implementations - Large File Performance

	[Benchmark]
	[BenchmarkCategory("Custom", "MurmurHash3", "38MB")]
	public byte[] MurmurHash3_128_38MB() => HashFacade.ComputeHash(HashAlgorithm.MurmurHash3_128, _38MB);

	[Benchmark]
	[BenchmarkCategory("Custom", "CityHash", "38MB")]
	public byte[] CityHash128_38MB() => HashFacade.ComputeHash(HashAlgorithm.CityHash128, _38MB);

	[Benchmark]
	[BenchmarkCategory("Custom", "SpookyHash", "38MB")]
	public byte[] SpookyHash128_38MB() => HashFacade.ComputeHash(HashAlgorithm.SpookyHash128, _38MB);

	[Benchmark]
	[BenchmarkCategory("Custom", "SipHash", "38MB")]
	public byte[] SipHash24_38MB() => HashFacade.ComputeHash(HashAlgorithm.SipHash24, _38MB);

	[Benchmark]
	[BenchmarkCategory("Custom", "FarmHash", "38MB")]
	public byte[] FarmHash64_38MB() => HashFacade.ComputeHash(HashAlgorithm.FarmHash64, _38MB);

	[Benchmark]
	[BenchmarkCategory("Custom", "HighwayHash", "38MB")]
	public byte[] HighwayHash64_38MB() => HashFacade.ComputeHash(HashAlgorithm.HighwayHash64, _38MB);

	[Benchmark]
	[BenchmarkCategory("Custom", "Wyhash", "38MB")]
	public byte[] Wyhash64_38MB() => HashFacade.ComputeHash(HashAlgorithm.Wyhash64, _38MB);

	#endregion

	#region Native Crypto - Large File Performance

	[Benchmark]
	[BenchmarkCategory("Native", "GOST94", "38MB")]
	public byte[] Gost94_38MB() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _38MB);

	[Benchmark]
	[BenchmarkCategory("Native", "SM3", "38MB")]
	public byte[] Sm3_38MB() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _38MB);

	[Benchmark]
	[BenchmarkCategory("Native", "RIPEMD256", "38MB")]
	public byte[] Ripemd256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Ripemd256, _38MB);

	[Benchmark]
	[BenchmarkCategory("Native", "Keccak256", "38MB")]
	public byte[] Keccak256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Keccak256, _38MB);

	#endregion

	#region BouncyCastle - Large File Performance (Compare)

	[Benchmark]
	[BenchmarkCategory("BouncyCastle", "Streebog", "38MB")]
	public byte[] Streebog256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Streebog256, _38MB);

	[Benchmark]
	[BenchmarkCategory("BouncyCastle", "Skein", "38MB")]
	public byte[] Skein256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Skein256, _38MB);

	#endregion

	#region SHA-3 Finalists - Large File Performance

	[Benchmark]
	[BenchmarkCategory("SHA3Finalist", "Groestl", "38MB")]
	public byte[] Groestl256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Groestl256, _38MB);

	[Benchmark]
	[BenchmarkCategory("SHA3Finalist", "JH", "38MB")]
	public byte[] Jh256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Jh256, _38MB);

	[Benchmark]
	[BenchmarkCategory("SHA3Finalist", "BLAKE2b", "38MB")]
	public byte[] Blake2b_38MB() => HashFacade.ComputeHash(HashAlgorithm.Blake2b, _38MB);

	#endregion

	#region Other Crypto - Large File Performance

	[Benchmark]
	[BenchmarkCategory("OtherCrypto", "Whirlpool", "38MB")]
	public byte[] Whirlpool_38MB() => HashFacade.ComputeHash(HashAlgorithm.Whirlpool, _38MB);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto", "Tiger", "38MB")]
	public byte[] Tiger192_38MB() => HashFacade.ComputeHash(HashAlgorithm.Tiger192, _38MB);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto", "RIPEMD160", "38MB")]
	public byte[] Ripemd160_38MB() => HashFacade.ComputeHash(HashAlgorithm.Ripemd160, _38MB);

	#endregion
}

/// <summary>
/// Benchmarks running ALL 70+ algorithms at once on 38MB data.
/// Use with caution - takes significant time to complete.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class AllAlgorithms38MBBenchmarks {
	private byte[] _data = null!;

	[GlobalSetup]
	public void Setup() {
		_data = new byte[39_845_888];  // 38 MB
		new Random(42).NextBytes(_data);
	}

	// ========== Checksums & CRCs ==========

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Crc32() => HashFacade.ComputeHash(HashAlgorithm.Crc32, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Crc32C() => HashFacade.ComputeHash(HashAlgorithm.Crc32C, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Crc64() => HashFacade.ComputeHash(HashAlgorithm.Crc64, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Adler32() => HashFacade.ComputeHash(HashAlgorithm.Adler32, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Fletcher16() => HashFacade.ComputeHash(HashAlgorithm.Fletcher16, _data);

	[Benchmark]
	[BenchmarkCategory("Checksum")]
	public byte[] Fletcher32() => HashFacade.ComputeHash(HashAlgorithm.Fletcher32, _data);

	// ========== xxHash Family ==========

	[Benchmark]
	[BenchmarkCategory("xxHash")]
	public byte[] XxHash32() => HashFacade.ComputeHash(HashAlgorithm.XxHash32, _data);

	[Benchmark]
	[BenchmarkCategory("xxHash")]
	public byte[] XxHash64() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _data);

	[Benchmark]
	[BenchmarkCategory("xxHash")]
	public byte[] XxHash3() => HashFacade.ComputeHash(HashAlgorithm.XxHash3, _data);

	[Benchmark]
	[BenchmarkCategory("xxHash")]
	public byte[] XxHash128() => HashFacade.ComputeHash(HashAlgorithm.XxHash128, _data);

	// ========== Fast Non-Crypto ==========

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
	public byte[] SpookyHash128() => HashFacade.ComputeHash(HashAlgorithm.SpookyHash128, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] SipHash24() => HashFacade.ComputeHash(HashAlgorithm.SipHash24, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] HighwayHash64() => HashFacade.ComputeHash(HashAlgorithm.HighwayHash64, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] MetroHash64() => HashFacade.ComputeHash(HashAlgorithm.MetroHash64, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] MetroHash128() => HashFacade.ComputeHash(HashAlgorithm.MetroHash128, _data);

	[Benchmark]
	[BenchmarkCategory("FastHash")]
	public byte[] Wyhash64() => HashFacade.ComputeHash(HashAlgorithm.Wyhash64, _data);

	// ========== Simple Hashes ==========

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] Fnv1a32() => HashFacade.ComputeHash(HashAlgorithm.Fnv1a32, _data);

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] Fnv1a64() => HashFacade.ComputeHash(HashAlgorithm.Fnv1a64, _data);

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] Djb2() => HashFacade.ComputeHash(HashAlgorithm.Djb2, _data);

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] Djb2a() => HashFacade.ComputeHash(HashAlgorithm.Djb2a, _data);

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] Sdbm() => HashFacade.ComputeHash(HashAlgorithm.Sdbm, _data);

	[Benchmark]
	[BenchmarkCategory("SimpleHash")]
	public byte[] LoseLose() => HashFacade.ComputeHash(HashAlgorithm.LoseLose, _data);

	// ========== MD Family ==========

	[Benchmark]
	[BenchmarkCategory("MD")]
	public byte[] Md2() => HashFacade.ComputeHash(HashAlgorithm.Md2, _data);

	[Benchmark]
	[BenchmarkCategory("MD")]
	public byte[] Md4() => HashFacade.ComputeHash(HashAlgorithm.Md4, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("MD")]
	public byte[] Md5() => HashFacade.ComputeHash(HashAlgorithm.Md5, _data);

	// ========== SHA-1/2 Family ==========

	[Benchmark]
	[BenchmarkCategory("SHA")]
	public byte[] Sha1() => HashFacade.ComputeHash(HashAlgorithm.Sha1, _data);

	[Benchmark]
	[BenchmarkCategory("SHA")]
	public byte[] Sha224() => HashFacade.ComputeHash(HashAlgorithm.Sha224, _data);

	[Benchmark]
	[BenchmarkCategory("SHA")]
	public byte[] Sha256() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _data);

	[Benchmark]
	[BenchmarkCategory("SHA")]
	public byte[] Sha384() => HashFacade.ComputeHash(HashAlgorithm.Sha384, _data);

	[Benchmark]
	[BenchmarkCategory("SHA")]
	public byte[] Sha512() => HashFacade.ComputeHash(HashAlgorithm.Sha512, _data);

	[Benchmark]
	[BenchmarkCategory("SHA")]
	public byte[] Sha512_224() => HashFacade.ComputeHash(HashAlgorithm.Sha512_224, _data);

	[Benchmark]
	[BenchmarkCategory("SHA")]
	public byte[] Sha512_256() => HashFacade.ComputeHash(HashAlgorithm.Sha512_256, _data);

	// ========== SHA-3 & Keccak ==========

	[Benchmark]
	[BenchmarkCategory("SHA3")]
	public byte[] Sha3_224() => HashFacade.ComputeHash(HashAlgorithm.Sha3_224, _data);

	[Benchmark]
	[BenchmarkCategory("SHA3")]
	public byte[] Sha3_256() => HashFacade.ComputeHash(HashAlgorithm.Sha3_256, _data);

	[Benchmark]
	[BenchmarkCategory("SHA3")]
	public byte[] Sha3_384() => HashFacade.ComputeHash(HashAlgorithm.Sha3_384, _data);

	[Benchmark]
	[BenchmarkCategory("SHA3")]
	public byte[] Sha3_512() => HashFacade.ComputeHash(HashAlgorithm.Sha3_512, _data);

	[Benchmark]
	[BenchmarkCategory("SHA3")]
	public byte[] Keccak256() => HashFacade.ComputeHash(HashAlgorithm.Keccak256, _data);

	[Benchmark]
	[BenchmarkCategory("SHA3")]
	public byte[] Keccak512() => HashFacade.ComputeHash(HashAlgorithm.Keccak512, _data);

	// ========== BLAKE Family ==========

	[Benchmark]
	[BenchmarkCategory("BLAKE")]
	public byte[] Blake256() => HashFacade.ComputeHash(HashAlgorithm.Blake256, _data);

	[Benchmark]
	[BenchmarkCategory("BLAKE")]
	public byte[] Blake512() => HashFacade.ComputeHash(HashAlgorithm.Blake512, _data);

	[Benchmark]
	[BenchmarkCategory("BLAKE")]
	public byte[] Blake2b() => HashFacade.ComputeHash(HashAlgorithm.Blake2b, _data);

	[Benchmark]
	[BenchmarkCategory("BLAKE")]
	public byte[] Blake2s() => HashFacade.ComputeHash(HashAlgorithm.Blake2s, _data);

	[Benchmark]
	[BenchmarkCategory("BLAKE")]
	public byte[] Blake3() => HashFacade.ComputeHash(HashAlgorithm.Blake3, _data);

	// ========== RIPEMD Family ==========

	[Benchmark]
	[BenchmarkCategory("RIPEMD")]
	public byte[] Ripemd128() => HashFacade.ComputeHash(HashAlgorithm.Ripemd128, _data);

	[Benchmark]
	[BenchmarkCategory("RIPEMD")]
	public byte[] Ripemd160() => HashFacade.ComputeHash(HashAlgorithm.Ripemd160, _data);

	[Benchmark]
	[BenchmarkCategory("RIPEMD")]
	public byte[] Ripemd256() => HashFacade.ComputeHash(HashAlgorithm.Ripemd256, _data);

	[Benchmark]
	[BenchmarkCategory("RIPEMD")]
	public byte[] Ripemd320() => HashFacade.ComputeHash(HashAlgorithm.Ripemd320, _data);

	// ========== Other Crypto ==========

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Whirlpool() => HashFacade.ComputeHash(HashAlgorithm.Whirlpool, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Tiger192() => HashFacade.ComputeHash(HashAlgorithm.Tiger192, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Gost94() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Streebog256() => HashFacade.ComputeHash(HashAlgorithm.Streebog256, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Streebog512() => HashFacade.ComputeHash(HashAlgorithm.Streebog512, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Skein256() => HashFacade.ComputeHash(HashAlgorithm.Skein256, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Skein512() => HashFacade.ComputeHash(HashAlgorithm.Skein512, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Skein1024() => HashFacade.ComputeHash(HashAlgorithm.Skein1024, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Groestl256() => HashFacade.ComputeHash(HashAlgorithm.Groestl256, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Groestl512() => HashFacade.ComputeHash(HashAlgorithm.Groestl512, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Jh256() => HashFacade.ComputeHash(HashAlgorithm.Jh256, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Jh512() => HashFacade.ComputeHash(HashAlgorithm.Jh512, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] KangarooTwelve() => HashFacade.ComputeHash(HashAlgorithm.KangarooTwelve, _data);

	[Benchmark]
	[BenchmarkCategory("OtherCrypto")]
	public byte[] Sm3() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _data);
}

/// <summary>
/// Quick benchmark for selected algorithms at multiple sizes.
/// Useful for rapid iteration when optimizing.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
public class QuickMultiSizeBenchmarks {
	private byte[] _64KB = null!;
	private byte[] _760KB = null!;
	private byte[] _3MB = null!;
	private byte[] _38MB = null!;

	[GlobalSetup]
	public void Setup() {
		var rng = new Random(42);
		_64KB = new byte[65_536];
		_760KB = new byte[778_240];
		_3MB = new byte[3_145_728];
		_38MB = new byte[39_845_888];
		rng.NextBytes(_64KB);
		rng.NextBytes(_760KB);
		rng.NextBytes(_3MB);
		rng.NextBytes(_38MB);
	}

	// GOST-94 at all sizes - the algorithm we just optimized
	[Benchmark]
	public byte[] Gost94_64KB() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _64KB);

	[Benchmark]
	public byte[] Gost94_760KB() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _760KB);

	[Benchmark]
	public byte[] Gost94_3MB() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _3MB);

	[Benchmark]
	public byte[] Gost94_38MB() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _38MB);

	// SHA-256 as baseline reference
	[Benchmark(Baseline = true)]
	public byte[] Sha256_38MB() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _38MB);

	// xxHash3 - fastest expected
	[Benchmark]
	public byte[] XxHash3_38MB() => HashFacade.ComputeHash(HashAlgorithm.XxHash3, _38MB);

	// BLAKE3 - modern fast crypto
	[Benchmark]
	public byte[] Blake3_38MB() => HashFacade.ComputeHash(HashAlgorithm.Blake3, _38MB);

	// SM3 - another native implementation
	[Benchmark]
	public byte[] Sm3_38MB() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _38MB);
}
