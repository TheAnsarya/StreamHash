using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using StreamHash.Core.Testing;
using SysCrypto = System.Security.Cryptography;

namespace StreamHash.Core.Tests.ReferenceData;

/// <summary>
/// Generates reference hash values for all test files using BouncyCastle and .NET built-in implementations.
/// This ensures we have verified expected values for all algorithms across all file sizes.
/// </summary>
/// <remarks>
/// Run this once to generate the reference data file, then use <see cref="ReferenceHashValues"/>
/// in tests to verify StreamHash implementations produce correct results.
/// </remarks>
public static class ReferenceHashGenerator {
	/// <summary>
	/// Generates reference hash values for all standard test files and saves to JSON.
	/// </summary>
	public static void GenerateAndSaveReferenceData(string outputPath) {
		var referenceData = new Dictionary<string, Dictionary<string, string>>();

		// Generate for each standard file size
		foreach (var size in TestDataGenerator.StandardSizes) {
			var data = TestDataGenerator.GetFile(size);
			var sizeName = size.ToString();
			referenceData[sizeName] = GenerateAllHashes(data);
			Console.WriteLine($"Generated hashes for {sizeName} ({data.Length:N0} bytes)");
		}

		// Save to JSON
		var options = new JsonSerializerOptions {
			WriteIndented = true,
			PropertyNamingPolicy = null
		};

		var json = JsonSerializer.Serialize(referenceData, options);
		File.WriteAllText(outputPath, json);
		Console.WriteLine($"\nSaved reference data to: {outputPath}");
	}

	/// <summary>
	/// Generates hash values for all algorithms using BouncyCastle and .NET.
	/// </summary>
	private static Dictionary<string, string> GenerateAllHashes(byte[] data) {
		var hashes = new Dictionary<string, string>();

		// ========== .NET Built-in ==========
		hashes["MD5"] = ComputeSystemHash(SysCrypto.MD5.Create(), data);
		hashes["SHA1"] = ComputeSystemHash(SysCrypto.SHA1.Create(), data);
		hashes["SHA256"] = ComputeSystemHash(SysCrypto.SHA256.Create(), data);
		hashes["SHA384"] = ComputeSystemHash(SysCrypto.SHA384.Create(), data);
		hashes["SHA512"] = ComputeSystemHash(SysCrypto.SHA512.Create(), data);

		// ========== BouncyCastle Cryptographic ==========
		hashes["MD2"] = ComputeBouncyCastle(new MD2Digest(), data);
		hashes["MD4"] = ComputeBouncyCastle(new MD4Digest(), data);
		hashes["SHA224"] = ComputeBouncyCastle(new Sha224Digest(), data);
		hashes["SHA512_224"] = ComputeBouncyCastle(new Sha512tDigest(224), data);
		hashes["SHA512_256"] = ComputeBouncyCastle(new Sha512tDigest(256), data);

		// SHA-3 family
		hashes["SHA3_224"] = ComputeBouncyCastle(new Sha3Digest(224), data);
		hashes["SHA3_256"] = ComputeBouncyCastle(new Sha3Digest(256), data);
		hashes["SHA3_384"] = ComputeBouncyCastle(new Sha3Digest(384), data);
		hashes["SHA3_512"] = ComputeBouncyCastle(new Sha3Digest(512), data);

		// Keccak
		hashes["Keccak256"] = ComputeBouncyCastle(new KeccakDigest(256), data);
		hashes["Keccak512"] = ComputeBouncyCastle(new KeccakDigest(512), data);

		// BLAKE family
		hashes["Blake2b_256"] = ComputeBouncyCastle(new Blake2bDigest(256), data);
		hashes["Blake2b_512"] = ComputeBouncyCastle(new Blake2bDigest(512), data);
		hashes["Blake2s_256"] = ComputeBouncyCastle(new Blake2sDigest(256), data);

		// RIPEMD family
		hashes["RIPEMD128"] = ComputeBouncyCastle(new RipeMD128Digest(), data);
		hashes["RIPEMD160"] = ComputeBouncyCastle(new RipeMD160Digest(), data);
		hashes["RIPEMD256"] = ComputeBouncyCastle(new RipeMD256Digest(), data);
		hashes["RIPEMD320"] = ComputeBouncyCastle(new RipeMD320Digest(), data);

		// Whirlpool (use BouncyCastle)
		hashes["Whirlpool"] = ComputeBouncyCastle(new Org.BouncyCastle.Crypto.Digests.WhirlpoolDigest(), data);

		// Tiger
		hashes["Tiger"] = ComputeBouncyCastle(new TigerDigest(), data);

		// GOST
		hashes["GOST3411"] = ComputeBouncyCastle(new Gost3411Digest(), data);

		// Streebog (GOST R 34.11-2012)
		hashes["Streebog256"] = ComputeBouncyCastle(new Gost3411_2012_256Digest(), data);
		hashes["Streebog512"] = ComputeBouncyCastle(new Gost3411_2012_512Digest(), data);

		// Skein
		hashes["Skein256_256"] = ComputeBouncyCastle(new SkeinDigest(256, 256), data);
		hashes["Skein512_512"] = ComputeBouncyCastle(new SkeinDigest(512, 512), data);
		hashes["Skein1024_1024"] = ComputeBouncyCastle(new SkeinDigest(1024, 1024), data);

		// SM3
		hashes["SM3"] = ComputeBouncyCastle(new SM3Digest(), data);

		// ========== System.IO.Hashing ==========
		hashes["CRC32"] = ComputeCrc32(data);
		hashes["CRC64"] = ComputeCrc64(data);
		hashes["XxHash32"] = ComputeXxHash32(data);
		hashes["XxHash64"] = ComputeXxHash64(data);
		hashes["XxHash3"] = ComputeXxHash3(data);
		hashes["XxHash128"] = ComputeXxHash128(data);

		return hashes;
	}

	private static string ComputeSystemHash(SysCrypto.HashAlgorithm algorithm, byte[] data) {
		using (algorithm) {
			var hash = algorithm.ComputeHash(data);
			return Convert.ToHexStringLower(hash);
		}
	}

	private static string ComputeBouncyCastle(IDigest digest, byte[] data) {
		digest.BlockUpdate(data, 0, data.Length);
		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return Convert.ToHexStringLower(result);
	}

	private static string ComputeCrc32(byte[] data) {
		var crc = new System.IO.Hashing.Crc32();
		crc.Append(data);
		var hash = crc.GetCurrentHashAsUInt32();
		return hash.ToString("x8");
	}

	private static string ComputeCrc64(byte[] data) {
		var crc = new System.IO.Hashing.Crc64();
		crc.Append(data);
		var hash = crc.GetCurrentHashAsUInt64();
		return hash.ToString("x16");
	}

	private static string ComputeXxHash32(byte[] data) {
		var hash = System.IO.Hashing.XxHash32.HashToUInt32(data);
		return hash.ToString("x8");
	}

	private static string ComputeXxHash64(byte[] data) {
		var hash = System.IO.Hashing.XxHash64.HashToUInt64(data);
		return hash.ToString("x16");
	}

	private static string ComputeXxHash3(byte[] data) {
		var hash = System.IO.Hashing.XxHash3.HashToUInt64(data);
		return hash.ToString("x16");
	}

	private static string ComputeXxHash128(byte[] data) {
		var hash = System.IO.Hashing.XxHash128.HashToUInt128(data);
		return hash.ToString("x32");
	}
}
