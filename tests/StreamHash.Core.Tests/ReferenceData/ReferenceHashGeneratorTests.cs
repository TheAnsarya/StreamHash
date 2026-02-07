using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using StreamHash.Core;
using StreamHash.Core.Testing;
using Xunit.Abstractions;
using SysCrypto = System.Security.Cryptography;

namespace StreamHash.Core.Tests.ReferenceData;

/// <summary>
/// Test class that generates reference hash values for documentation.
/// Run these tests to regenerate reference values when the canonical seed changes.
/// </summary>
public class ReferenceHashGeneratorTests(ITestOutputHelper output) {

	[Fact]
	public void GenerateReferenceHashes_64KB() {
		var data = TestDataGenerator.File64KB;

		output.WriteLine("=== 64 KB Reference Hashes ===");
		output.WriteLine($"Canonical Seed: 0x{TestDataGenerator.CanonicalSeed:x16}");
		output.WriteLine($"Seed as Int: 0x{TestDataGenerator.SeedAsInt:x8}");
		output.WriteLine($"Size: {data.Length:N0} bytes");
		output.WriteLine($"First 16 bytes: {Convert.ToHexStringLower(data.AsSpan(0, 16))}");
		output.WriteLine($"Last 16 bytes: {Convert.ToHexStringLower(data.AsSpan(data.Length - 16, 16))}");
		output.WriteLine("");

		GenerateAllHashes(data);
	}

	[Fact]
	public void GenerateReferenceHashes_69KB() {
		var data = TestDataGenerator.File69KB;
		output.WriteLine($"=== 69 KB Reference Hashes === ({data.Length:N0} bytes)");
		GenerateAllHashes(data);
	}

	[Fact]
	public void GenerateReferenceHashes_767KB() {
		var data = TestDataGenerator.File767KB;
		output.WriteLine($"=== 767 KB Reference Hashes === ({data.Length:N0} bytes)");
		GenerateAllHashes(data);
	}

	[Fact]
	public void GenerateReferenceHashes_3MB() {
		var data = TestDataGenerator.File3MB;
		output.WriteLine($"=== 3 MB Reference Hashes === ({data.Length:N0} bytes)");
		GenerateAllHashes(data);
	}

	[Fact]
	public void GenerateReferenceHashes_38MB() {
		var data = TestDataGenerator.File38MB;
		output.WriteLine($"=== 38 MB Reference Hashes === ({data.Length:N0} bytes)");
		GenerateAllHashes(data);
	}

	private void GenerateAllHashes(byte[] data) {
		// .NET Built-in
		output.WriteLine("// .NET Built-in");
		output.WriteLine($"public const string MD5 = \"{ComputeSystem(SysCrypto.MD5.Create(), data)}\";");
		output.WriteLine($"public const string SHA1 = \"{ComputeSystem(SysCrypto.SHA1.Create(), data)}\";");
		output.WriteLine($"public const string SHA256 = \"{ComputeSystem(SysCrypto.SHA256.Create(), data)}\";");
		output.WriteLine($"public const string SHA384 = \"{ComputeSystem(SysCrypto.SHA384.Create(), data)}\";");
		output.WriteLine($"public const string SHA512 = \"{ComputeSystem(SysCrypto.SHA512.Create(), data)}\";");
		output.WriteLine("");

		// SHA-2 variants
		output.WriteLine("// SHA-2 variants");
		output.WriteLine($"public const string SHA224 = \"{ComputeBC(new Sha224Digest(), data)}\";");
		output.WriteLine($"public const string SHA512_224 = \"{ComputeBC(new Sha512tDigest(224), data)}\";");
		output.WriteLine($"public const string SHA512_256 = \"{ComputeBC(new Sha512tDigest(256), data)}\";");
		output.WriteLine("");

		// SHA-3 family
		output.WriteLine("// SHA-3 family");
		output.WriteLine($"public const string SHA3_224 = \"{ComputeBC(new Sha3Digest(224), data)}\";");
		output.WriteLine($"public const string SHA3_256 = \"{ComputeBC(new Sha3Digest(256), data)}\";");
		output.WriteLine($"public const string SHA3_384 = \"{ComputeBC(new Sha3Digest(384), data)}\";");
		output.WriteLine($"public const string SHA3_512 = \"{ComputeBC(new Sha3Digest(512), data)}\";");
		output.WriteLine("");

		// Keccak
		output.WriteLine("// Keccak");
		output.WriteLine($"public const string Keccak256 = \"{ComputeBC(new KeccakDigest(256), data)}\";");
		output.WriteLine($"public const string Keccak512 = \"{ComputeBC(new KeccakDigest(512), data)}\";");
		output.WriteLine("");

		// MD family
		output.WriteLine("// MD family");
		output.WriteLine($"public const string MD2 = \"{ComputeBC(new MD2Digest(), data)}\";");
		output.WriteLine($"public const string MD4 = \"{ComputeBC(new MD4Digest(), data)}\";");
		output.WriteLine("");

		// BLAKE family
		output.WriteLine("// BLAKE family");
		output.WriteLine($"public const string Blake2b_256 = \"{ComputeBC(new Blake2bDigest(256), data)}\";");
		output.WriteLine($"public const string Blake2b_512 = \"{ComputeBC(new Blake2bDigest(512), data)}\";");
		output.WriteLine($"public const string Blake2s_256 = \"{ComputeBC(new Blake2sDigest(256), data)}\";");
		output.WriteLine("");

		// RIPEMD family
		output.WriteLine("// RIPEMD family");
		output.WriteLine($"public const string RIPEMD128 = \"{ComputeBC(new RipeMD128Digest(), data)}\";");
		output.WriteLine($"public const string RIPEMD160 = \"{ComputeBC(new RipeMD160Digest(), data)}\";");
		output.WriteLine($"public const string RIPEMD256 = \"{ComputeBC(new RipeMD256Digest(), data)}\";");
		output.WriteLine($"public const string RIPEMD320 = \"{ComputeBC(new RipeMD320Digest(), data)}\";");
		output.WriteLine("");

		// Whirlpool
		output.WriteLine("// Whirlpool");
		output.WriteLine($"public const string Whirlpool = \"{ComputeBC(new Org.BouncyCastle.Crypto.Digests.WhirlpoolDigest(), data)}\";");
		output.WriteLine("");

		// Tiger
		output.WriteLine("// Tiger");
		output.WriteLine($"public const string Tiger = \"{ComputeBC(new TigerDigest(), data)}\";");
		output.WriteLine("");

		// GOST
		output.WriteLine("// GOST");
		output.WriteLine($"public const string GOST3411 = \"{ComputeBC(new Gost3411Digest(), data)}\";");
		output.WriteLine($"public const string Streebog256 = \"{ComputeBC(new Gost3411_2012_256Digest(), data)}\";");
		output.WriteLine($"public const string Streebog512 = \"{ComputeBC(new Gost3411_2012_512Digest(), data)}\";");
		output.WriteLine("");

		// Skein
		output.WriteLine("// Skein");
		output.WriteLine($"public const string Skein256 = \"{ComputeBC(new SkeinDigest(256, 256), data)}\";");
		output.WriteLine($"public const string Skein512 = \"{ComputeBC(new SkeinDigest(512, 512), data)}\";");
		output.WriteLine($"public const string Skein1024 = \"{ComputeBC(new SkeinDigest(1024, 1024), data)}\";");
		output.WriteLine("");

		// SM3
		output.WriteLine("// SM3");
		output.WriteLine($"public const string SM3 = \"{ComputeBC(new SM3Digest(), data)}\";");
		output.WriteLine("");

		// System.IO.Hashing
		output.WriteLine("// System.IO.Hashing");
		output.WriteLine($"public const string CRC32 = \"{System.IO.Hashing.Crc32.HashToUInt32(data):x8}\";");
		output.WriteLine($"public const string CRC64 = \"{System.IO.Hashing.Crc64.HashToUInt64(data):x16}\";");
		output.WriteLine($"public const string XxHash32 = \"{System.IO.Hashing.XxHash32.HashToUInt32(data):x8}\";");
		output.WriteLine($"public const string XxHash64 = \"{System.IO.Hashing.XxHash64.HashToUInt64(data):x16}\";");
		output.WriteLine($"public const string XxHash3 = \"{System.IO.Hashing.XxHash3.HashToUInt64(data):x16}\";");
		output.WriteLine($"public const string XxHash128 = \"{System.IO.Hashing.XxHash128.HashToUInt128(data):x32}\";");
		output.WriteLine("");

		// StreamHash native
		output.WriteLine("// StreamHash native (Groestl, JH)");
		output.WriteLine($"public const string Groestl256 = \"{ComputeStreamHash(() => new GroestlDigest(256), data)}\";");
		output.WriteLine($"public const string Groestl512 = \"{ComputeStreamHash(() => new GroestlDigest(512), data)}\";");
		output.WriteLine($"public const string JH256 = \"{ComputeStreamHash(() => new JHDigest(256), data)}\";");
		output.WriteLine($"public const string JH512 = \"{ComputeStreamHash(() => new JHDigest(512), data)}\";");
	}

	private static string ComputeSystem(SysCrypto.HashAlgorithm alg, byte[] data) {
		using (alg) return Convert.ToHexStringLower(alg.ComputeHash(data));
	}

	private static string ComputeBC(IDigest digest, byte[] data) {
		digest.BlockUpdate(data, 0, data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return Convert.ToHexStringLower(result);
	}

	private static string ComputeStreamHash(Func<IStreamingHashBytes> factory, byte[] data) {
		using var hasher = factory();
		hasher.Update(data);
		return Convert.ToHexStringLower(hasher.FinalizeBytes());
	}
}
