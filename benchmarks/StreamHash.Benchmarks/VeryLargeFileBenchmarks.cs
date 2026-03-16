using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using Org.BouncyCastle.Crypto.Digests;
using StreamHash.Core;
using System.IO.Hashing;
using BC = Org.BouncyCastle.Crypto.Digests;

namespace StreamHash.Benchmarks;

/// <summary>
/// Benchmarks for very large data sizes: 10MB, 100MB, and 1GB.
/// NOT included in regular benchmark runs - must be explicitly requested.
/// </summary>
/// <remarks>
/// <para>
/// These benchmarks test performance at scale to identify algorithms that
/// degrade with large data sizes. The 1GB tests take a long time and should
/// be run as a background process.
/// </para>
/// <para>
/// Run with: dotnet run -c Release -- --filter "*VeryLargeBenchmarks*" --job short
/// </para>
/// </remarks>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class VeryLargeFileBenchmarks {
	private byte[] _data = null!;

	/// <summary>
	/// Data sizes: 10MB, 100MB, 1GB
	/// </summary>
	[Params(10_485_760, 104_857_600, 1_073_741_824)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		// Use a simple pattern for large data to avoid long RNG time
		// Pattern is deterministic and compressible, but that's fine for hash benchmarks
		for (int i = 0; i < _data.Length; i++) {
			_data[i] = (byte)(i ^ (i >> 8) ^ (i >> 16));
		}
	}

	#region Fast Non-Crypto - xxHash

	[Benchmark]
	[BenchmarkCategory("xxHash32")]
	public byte[] XxHash32_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.XxHash32, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("xxHash32")]
	public byte[] XxHash32_SystemIO() {
		Span<byte> result = stackalloc byte[4];
		XxHash32.Hash(_data, result);
		return result.ToArray();
	}

	[Benchmark]
	[BenchmarkCategory("xxHash64")]
	public byte[] XxHash64_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.XxHash64, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("xxHash64")]
	public byte[] XxHash64_SystemIO() {
		Span<byte> result = stackalloc byte[8];
		XxHash64.Hash(_data, result);
		return result.ToArray();
	}

	[Benchmark]
	[BenchmarkCategory("xxHash3")]
	public byte[] XxHash3_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.XxHash3, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("xxHash3")]
	public byte[] XxHash3_SystemIO() {
		Span<byte> result = stackalloc byte[8];
		XxHash3.Hash(_data, result);
		return result.ToArray();
	}

	[Benchmark]
	[BenchmarkCategory("xxHash128")]
	public byte[] XxHash128_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.XxHash128, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("xxHash128")]
	public byte[] XxHash128_SystemIO() {
		Span<byte> result = stackalloc byte[16];
		XxHash128.Hash(_data, result);
		return result.ToArray();
	}

	#endregion

	#region Fast Non-Crypto - CRC

	[Benchmark]
	[BenchmarkCategory("CRC32")]
	public byte[] Crc32_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Crc32, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("CRC32")]
	public byte[] Crc32_SystemIO() {
		Span<byte> result = stackalloc byte[4];
		Crc32.Hash(_data, result);
		return result.ToArray();
	}

	[Benchmark]
	[BenchmarkCategory("CRC64")]
	public byte[] Crc64_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Crc64, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("CRC64")]
	public byte[] Crc64_SystemIO() {
		Span<byte> result = stackalloc byte[8];
		Crc64.Hash(_data, result);
		return result.ToArray();
	}

	#endregion

	#region BLAKE Family

	[Benchmark]
	[BenchmarkCategory("BLAKE2b")]
	public byte[] Blake2b_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Blake2b, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("BLAKE2b")]
	public byte[] Blake2b_BouncyCastle() {
		var digest = new Blake2bDigest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("BLAKE2b")]
	public byte[] Blake2b_Blake2Fast() => Blake2Fast.Blake2b.ComputeHash(64, _data);

	[Benchmark]
	[BenchmarkCategory("BLAKE2s")]
	public byte[] Blake2s_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Blake2s, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("BLAKE2s")]
	public byte[] Blake2s_BouncyCastle() {
		var digest = new Blake2sDigest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("BLAKE2s")]
	public byte[] Blake2s_Blake2Fast() => Blake2Fast.Blake2s.ComputeHash(32, _data);

	[Benchmark]
	[BenchmarkCategory("BLAKE3")]
	public byte[] Blake3_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Blake3, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("BLAKE3")]
	public byte[] Blake3_RustNative() {
		using var hasher = Blake3.Hasher.New();
		hasher.Update(_data);
		return hasher.Finalize().AsSpan().ToArray();
	}

	#endregion

	#region SHA Family

	[Benchmark]
	[BenchmarkCategory("SHA256")]
	public byte[] Sha256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA256")]
	public byte[] Sha256_BouncyCastle() {
		var digest = new Sha256Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA512")]
	public byte[] Sha512_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha512, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA512")]
	public byte[] Sha512_BouncyCastle() {
		var digest = new Sha512Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA512-256")]
	public byte[] Sha512_256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha512_256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA512-256")]
	public byte[] Sha512_256_BouncyCastle() {
		var digest = new Sha512tDigest(256);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA3-256")]
	public byte[] Sha3_256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha3_256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA3-256")]
	public byte[] Sha3_256_BouncyCastle() {
		var digest = new Sha3Digest(256);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region RIPEMD Family

	[Benchmark]
	[BenchmarkCategory("RIPEMD128")]
	public byte[] Ripemd128_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Ripemd128, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("RIPEMD128")]
	public byte[] Ripemd128_BouncyCastle() {
		var digest = new RipeMD128Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("RIPEMD160")]
	public byte[] Ripemd160_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Ripemd160, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("RIPEMD160")]
	public byte[] Ripemd160_BouncyCastle() {
		var digest = new RipeMD160Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("RIPEMD320")]
	public byte[] Ripemd320_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Ripemd320, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("RIPEMD320")]
	public byte[] Ripemd320_BouncyCastle() {
		var digest = new RipeMD320Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region Other Crypto

	[Benchmark]
	[BenchmarkCategory("Keccak256")]
	public byte[] Keccak256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Keccak256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Keccak256")]
	public byte[] Keccak256_BouncyCastle() {
		var digest = new KeccakDigest(256);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("Skein512")]
	public byte[] Skein512_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Skein512, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Skein512")]
	public byte[] Skein512_BouncyCastle() {
		var digest = new SkeinDigest(512, 512);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("Whirlpool")]
	public byte[] Whirlpool_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Whirlpool, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Whirlpool")]
	public byte[] Whirlpool_BouncyCastle() {
		var digest = new BC.WhirlpoolDigest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("MD5")]
	public byte[] Md5_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Md5, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("MD5")]
	public byte[] Md5_BouncyCastle() {
		var digest = new MD5Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA1")]
	public byte[] Sha1_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha1, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA1")]
	public byte[] Sha1_BouncyCastle() {
		var digest = new Sha1Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion
}
