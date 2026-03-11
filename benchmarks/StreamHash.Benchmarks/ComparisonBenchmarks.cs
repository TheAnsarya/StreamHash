using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using Org.BouncyCastle.Crypto.Digests;
using StreamHash.Core;
using BC = Org.BouncyCastle.Crypto.Digests;

namespace StreamHash.Benchmarks;

/// <summary>
/// Compares StreamHash native implementations against the external libraries they replaced.
/// Each benchmark group tests the same algorithm from both StreamHash and the original library.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class ComparisonBenchmarks {
	private byte[] _data = null!;

	[Params(1024, 65536, 1048576)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		new Random(42).NextBytes(_data);
	}

	#region MD2

	[Benchmark]
	[BenchmarkCategory("MD2")]
	public byte[] MD2_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Md2, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("MD2")]
	public byte[] MD2_BouncyCastle() {
		var digest = new MD2Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("MD2")]
	public byte[] MD2_Acryptohashnet() {
		using var hasher = new acryptohashnet.MD2();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region MD4

	[Benchmark]
	[BenchmarkCategory("MD4")]
	public byte[] MD4_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Md4, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("MD4")]
	public byte[] MD4_BouncyCastle() {
		var digest = new MD4Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("MD4")]
	public byte[] MD4_Acryptohashnet() {
		using var hasher = new acryptohashnet.MD4();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region MD5

	[Benchmark]
	[BenchmarkCategory("MD5")]
	public byte[] MD5_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Md5, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("MD5")]
	public byte[] MD5_BouncyCastle() {
		var digest = new MD5Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("MD5")]
	public byte[] MD5_Acryptohashnet() {
		using var hasher = new acryptohashnet.MD5();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region SHA-1

	[Benchmark]
	[BenchmarkCategory("SHA1")]
	public byte[] SHA1_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha1, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA1")]
	public byte[] SHA1_BouncyCastle() {
		var digest = new Sha1Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA1")]
	public byte[] SHA1_Acryptohashnet() {
		using var hasher = new acryptohashnet.SHA1();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region SHA-224

	[Benchmark]
	[BenchmarkCategory("SHA224")]
	public byte[] SHA224_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha224, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA224")]
	public byte[] SHA224_BouncyCastle() {
		var digest = new Sha224Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region SHA-256

	[Benchmark]
	[BenchmarkCategory("SHA256")]
	public byte[] SHA256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA256")]
	public byte[] SHA256_BouncyCastle() {
		var digest = new Sha256Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA256")]
	public byte[] SHA256_Acryptohashnet() {
		using var hasher = new acryptohashnet.SHA256();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region SHA-384

	[Benchmark]
	[BenchmarkCategory("SHA384")]
	public byte[] SHA384_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha384, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA384")]
	public byte[] SHA384_BouncyCastle() {
		var digest = new Sha384Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA384")]
	public byte[] SHA384_Acryptohashnet() {
		using var hasher = new acryptohashnet.SHA384();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region SHA-512

	[Benchmark]
	[BenchmarkCategory("SHA512")]
	public byte[] SHA512_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha512, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA512")]
	public byte[] SHA512_BouncyCastle() {
		var digest = new Sha512Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA512")]
	public byte[] SHA512_Acryptohashnet() {
		using var hasher = new acryptohashnet.SHA512();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region SHA-512/224

	[Benchmark]
	[BenchmarkCategory("SHA512-224")]
	public byte[] SHA512_224_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha512_224, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA512-224")]
	public byte[] SHA512_224_BouncyCastle() {
		var digest = new Sha512tDigest(224);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region SHA-512/256

	[Benchmark]
	[BenchmarkCategory("SHA512-256")]
	public byte[] SHA512_256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha512_256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA512-256")]
	public byte[] SHA512_256_BouncyCastle() {
		var digest = new Sha512tDigest(256);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region SHA3-224

	[Benchmark]
	[BenchmarkCategory("SHA3-224")]
	public byte[] SHA3_224_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha3_224, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA3-224")]
	public byte[] SHA3_224_BouncyCastle() {
		var digest = new Sha3Digest(224);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region SHA3-256

	[Benchmark]
	[BenchmarkCategory("SHA3-256")]
	public byte[] SHA3_256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha3_256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA3-256")]
	public byte[] SHA3_256_BouncyCastle() {
		var digest = new Sha3Digest(256);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA3-256")]
	public byte[] SHA3_256_DotSha3() {
		using var hasher = new SHA3(nebulae.dotSHA3.SHA3Algorithm.Sha3_256);
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region SHA3-384

	[Benchmark]
	[BenchmarkCategory("SHA3-384")]
	public byte[] SHA3_384_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha3_384, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA3-384")]
	public byte[] SHA3_384_BouncyCastle() {
		var digest = new Sha3Digest(384);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("SHA3-384")]
	public byte[] SHA3_384_DotSha3() {
		using var hasher = new SHA3(nebulae.dotSHA3.SHA3Algorithm.Sha3_384);
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region SHA3-512

	[Benchmark]
	[BenchmarkCategory("SHA3-512")]
	public byte[] SHA3_512_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sha3_512, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA3-512")]
	public byte[] SHA3_512_BouncyCastle() {
		var digest = new Sha3Digest(512);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	// NOTE: dotSHA3 does not support SHA3-512, only up to SHA3-384

	#endregion

	#region Keccak-256

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
	[BenchmarkCategory("Keccak256")]
	public byte[] Keccak256_Acryptohashnet() {
		using var hasher = new acryptohashnet.Keccak256();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region Keccak-512

	[Benchmark]
	[BenchmarkCategory("Keccak512")]
	public byte[] Keccak512_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Keccak512, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Keccak512")]
	public byte[] Keccak512_BouncyCastle() {
		var digest = new KeccakDigest(512);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("Keccak512")]
	public byte[] Keccak512_Acryptohashnet() {
		using var hasher = new acryptohashnet.Keccak512();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region BLAKE2b

	[Benchmark]
	[BenchmarkCategory("BLAKE2b")]
	public byte[] Blake2b_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Blake2b, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("BLAKE2b")]
	public byte[] Blake2b_BouncyCastle() {
		var digest = new Blake2bDigest(512);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("BLAKE2b")]
	public byte[] Blake2b_Blake2Fast() {
		return Blake2Fast.Blake2b.ComputeHash(64, _data);
	}

	#endregion

	#region BLAKE2s

	[Benchmark]
	[BenchmarkCategory("BLAKE2s")]
	public byte[] Blake2s_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Blake2s, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("BLAKE2s")]
	public byte[] Blake2s_BouncyCastle() {
		var digest = new Blake2sDigest(256);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("BLAKE2s")]
	public byte[] Blake2s_Blake2Fast() {
		return Blake2Fast.Blake2s.ComputeHash(32, _data);
	}

	#endregion

	#region BLAKE3

	[Benchmark]
	[BenchmarkCategory("BLAKE3")]
	public byte[] Blake3_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Blake3, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("BLAKE3")]
	public byte[] Blake3_RustNative() {
		using var hasher = Blake3.Hasher.New();
		hasher.Update(_data);
		var hash = hasher.Finalize();
		return hash.AsSpan().ToArray();
	}

	#endregion

	#region RIPEMD-128

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
	[BenchmarkCategory("RIPEMD128")]
	public byte[] Ripemd128_Acryptohashnet() {
		using var hasher = new acryptohashnet.RIPEMD128();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region RIPEMD-160

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
	[BenchmarkCategory("RIPEMD160")]
	public byte[] Ripemd160_Acryptohashnet() {
		using var hasher = new acryptohashnet.RIPEMD160();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region RIPEMD-256

	[Benchmark]
	[BenchmarkCategory("RIPEMD256")]
	public byte[] Ripemd256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Ripemd256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("RIPEMD256")]
	public byte[] Ripemd256_BouncyCastle() {
		var digest = new RipeMD256Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region RIPEMD-320

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

	#region Tiger-192

	[Benchmark]
	[BenchmarkCategory("Tiger192")]
	public byte[] Tiger192_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Tiger192, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Tiger192")]
	public byte[] Tiger192_BouncyCastle() {
		var digest = new TigerDigest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	[Benchmark]
	[BenchmarkCategory("Tiger192")]
	public byte[] Tiger192_Acryptohashnet() {
		using var hasher = new acryptohashnet.Tiger();
		return hasher.ComputeHash(_data);
	}

	#endregion

	#region Whirlpool

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

	#endregion

	#region SM3

	[Benchmark]
	[BenchmarkCategory("SM3")]
	public byte[] SM3_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Sm3, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SM3")]
	public byte[] SM3_BouncyCastle() {
		var digest = new SM3Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region GOST R 34.11-94

	[Benchmark]
	[BenchmarkCategory("GOST94")]
	public byte[] Gost94_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Gost94, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("GOST94")]
	public byte[] Gost94_BouncyCastle() {
		var digest = new Gost3411Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region Streebog-256

	[Benchmark]
	[BenchmarkCategory("Streebog256")]
	public byte[] Streebog256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Streebog256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Streebog256")]
	public byte[] Streebog256_BouncyCastle() {
		var digest = new Gost3411_2012_256Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region Streebog-512

	[Benchmark]
	[BenchmarkCategory("Streebog512")]
	public byte[] Streebog512_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Streebog512, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Streebog512")]
	public byte[] Streebog512_BouncyCastle() {
		var digest = new Gost3411_2012_512Digest();
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region Skein-256

	[Benchmark]
	[BenchmarkCategory("Skein256")]
	public byte[] Skein256_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Skein256, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Skein256")]
	public byte[] Skein256_BouncyCastle() {
		var digest = new SkeinDigest(256, 256);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	#region Skein-512

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

	#endregion

	#region Skein-1024

	[Benchmark]
	[BenchmarkCategory("Skein1024")]
	public byte[] Skein1024_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.Skein1024, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Skein1024")]
	public byte[] Skein1024_BouncyCastle() {
		var digest = new SkeinDigest(1024, 1024);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}

	#endregion

	// NOTE: Groestl and JH have no BouncyCastle equivalents - they are StreamHash-only
	// custom implementations with AES-NI and SSSE3 SIMD optimizations

	#region SipHash-2-4

	[Benchmark]
	[BenchmarkCategory("SipHash")]
	public byte[] SipHash24_StreamHash() => HashFacade.ComputeHash(HashAlgorithm.SipHash24, _data);

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SipHash")]
	public byte[] SipHash24_BouncyCastle() {
		// BouncyCastle SipHash is a MAC, not directly comparable
		var digest = new Org.BouncyCastle.Crypto.Macs.SipHash();
		var keyParam = new Org.BouncyCastle.Crypto.Parameters.KeyParameter(new byte[16]);
		digest.Init(keyParam);
		digest.BlockUpdate(_data, 0, _data.Length);
		var result = digest.DoFinal();
		return BitConverter.GetBytes(result);
	}

	[Benchmark]
	[BenchmarkCategory("SipHash")]
	public byte[] SipHash24_HashDepot() {
		var result = HashDepot.SipHash24.Hash64(_data, new byte[16]);
		return BitConverter.GetBytes(result);
	}

	#endregion
}
