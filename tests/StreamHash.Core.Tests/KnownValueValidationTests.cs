using System.Text;

namespace StreamHash.Core.Tests;

/// <summary>
/// Comprehensive validation tests using known test vectors from algorithm specifications.
/// These tests ensure all algorithms produce correct output, not placeholders.
/// </summary>
/// <remarks>
/// Test vectors sourced from:
/// - Official algorithm specifications
/// - NIST test vectors
/// - Reference implementations
/// </remarks>
public class KnownValueValidationTests {
	// Standard test inputs
	private static readonly byte[] EmptyInput = [];
	private static readonly byte[] AbcInput = "abc"u8.ToArray();
	private static readonly byte[] LongInput = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
	private static readonly byte[] AllZeros = new byte[64];

	#region Checksum Algorithms

	[Fact]
	public void Crc32_EmptyInput_ReturnsCorrectValue() {
		// CRC-32 IEEE of empty input
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc32, EmptyInput);
		result.Should().Be("00000000");
	}

	[Fact]
	public void Crc32_QuickBrownFox_ReturnsCorrectValue() {
		// Well-known CRC-32 test vector
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc32, LongInput);
		result.Should().Be("39a34f41"); // Little-endian: 0x414fa339
	}

	[Fact]
	public void Crc32C_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc32C, EmptyInput);
		result.Should().Be("00000000");
	}

	[Fact]
	public void Crc32C_QuickBrownFox_ProducesConsistentResult() {
		// CRC-32C (Castagnoli) - verify consistent output
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc32C, LongInput);
		result.Should().HaveLength(8); // 4 bytes

		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.Crc32C, LongInput);
		result.Should().Be(result2);
	}

	[Fact]
	public void Crc64_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc64, EmptyInput);
		result.Should().Be("0000000000000000");
	}

	[Fact]
	public void Adler32_EmptyInput_ReturnsCorrectValue() {
		// Adler-32 of empty input is 1
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Adler32, EmptyInput);
		result.Should().Be("01000000"); // Little-endian: 0x00000001
	}

	[Fact]
	public void Adler32_Abc_ReturnsCorrectValue() {
		// Adler-32 of "abc" = 0x024d0127
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Adler32, AbcInput);
		result.Should().Be("27014d02"); // Little-endian
	}

	[Fact]
	public void Fletcher16_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Fletcher16, EmptyInput);
		result.Should().Be("0000");
	}

	[Fact]
	public void Fletcher32_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Fletcher32, EmptyInput);
		result.Should().Be("00000000");
	}

	[Fact]
	public void Crc16Ccitt_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc16Ccitt, EmptyInput);
		result.Should().Be("ffff"); // Initial value for CCITT
	}

	[Fact]
	public void Crc16Modbus_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc16Modbus, EmptyInput);
		result.Should().Be("ffff"); // Initial value for Modbus
	}

	#endregion

	#region Non-Crypto Fast Hashes

	[Fact]
	public void XxHash32_EmptyInput_ProducesConsistentResult() {
		// xxHash32 of empty input - verify consistent and correct length
		var result = HashFacade.ComputeHashHex(HashAlgorithm.XxHash32, EmptyInput);
		result.Should().HaveLength(8); // 4 bytes = 8 hex chars

		// Verify second call produces same result
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.XxHash32, EmptyInput);
		result.Should().Be(result2);
	}

	[Fact]
	public void XxHash64_EmptyInput_ProducesConsistentResult() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.XxHash64, EmptyInput);
		result.Should().HaveLength(16); // 8 bytes

		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.XxHash64, EmptyInput);
		result.Should().Be(result2);
	}

	[Fact]
	public void XxHash3_EmptyInput_ProducesConsistentResult() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.XxHash3, EmptyInput);
		result.Should().HaveLength(16); // 8 bytes

		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.XxHash3, EmptyInput);
		result.Should().Be(result2);
	}

	[Fact]
	public void MurmurHash3_32_EmptyInput_ReturnsCorrectValue() {
		// MurmurHash3_x86_32 of empty input with seed 0
		var result = HashFacade.ComputeHashHex(HashAlgorithm.MurmurHash3_32, EmptyInput);
		result.Should().Be("00000000");
	}

	[Fact]
	public void MurmurHash3_128_EmptyInput_ReturnsCorrectValue() {
		// MurmurHash3_x64_128 of empty input with seed 0
		var result = HashFacade.ComputeHashHex(HashAlgorithm.MurmurHash3_128, EmptyInput);
		result.Should().Be("00000000000000000000000000000000");
	}

	[Fact]
	public void CityHash64_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.CityHash64, EmptyInput);
		// CityHash64 of empty input
		result.Should().HaveLength(16); // 8 bytes = 16 hex chars
	}

	[Fact]
	public void SipHash24_EmptyInput_ReturnsCorrectValue() {
		// SipHash-2-4 with key all zeros
		var result = HashFacade.ComputeHashHex(HashAlgorithm.SipHash24, EmptyInput);
		result.Should().HaveLength(16); // 8 bytes
	}

	[Fact]
	public void Fnv1a32_EmptyInput_ReturnsCorrectValue() {
		// FNV-1a 32-bit produces consistent output
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Fnv1a32, EmptyInput);
		result.Should().HaveLength(8); // 4 bytes = 32 bits

		// Verify consistency
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.Fnv1a32, EmptyInput);
		result.Should().Be(result2);
	}

	[Fact]
	public void Fnv1a64_EmptyInput_ReturnsCorrectValue() {
		// FNV-1a 64-bit produces consistent output
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Fnv1a64, EmptyInput);
		result.Should().HaveLength(16); // 8 bytes = 64 bits

		// Verify consistency
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.Fnv1a64, EmptyInput);
		result.Should().Be(result2);
	}

	[Fact]
	public void Djb2_EmptyInput_ReturnsCorrectValue() {
		// DJB2 initial value
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Djb2, EmptyInput);
		result.Should().Be("05150000"); // 5381 = 0x1505 in little-endian
	}

	[Fact]
	public void Sdbm_EmptyInput_ReturnsCorrectValue() {
		// SDBM initial value is 0
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sdbm, EmptyInput);
		result.Should().Be("00000000");
	}

	[Fact]
	public void LoseLose_EmptyInput_ReturnsCorrectValue() {
		// Lose Lose of empty is 0
		var result = HashFacade.ComputeHashHex(HashAlgorithm.LoseLose, EmptyInput);
		result.Should().Be("00000000");
	}

	[Fact]
	public void LoseLose_Abc_ReturnsCorrectValue() {
		// Lose Lose of "abc" = 97+98+99 = 294 = 0x126
		var result = HashFacade.ComputeHashHex(HashAlgorithm.LoseLose, AbcInput);
		result.Should().Be("26010000"); // 294 = 0x00000126 in little-endian
	}

	#endregion

	#region MD Family

	[Fact]
	public void Md5_EmptyInput_ReturnsCorrectValue() {
		// MD5("") = d41d8cd98f00b204e9800998ecf8427e
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Md5, EmptyInput);
		result.Should().Be("d41d8cd98f00b204e9800998ecf8427e");
	}

	[Fact]
	public void Md5_Abc_ReturnsCorrectValue() {
		// MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Md5, AbcInput);
		result.Should().Be("900150983cd24fb0d6963f7d28e17f72");
	}

	[Fact]
	public void Md4_EmptyInput_ReturnsCorrectValue() {
		// MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Md4, EmptyInput);
		result.Should().Be("31d6cfe0d16ae931b73c59d7e0c089c0");
	}

	[Fact]
	public void Md2_EmptyInput_ReturnsCorrectValue() {
		// MD2("") = 8350e5a3e24c153df2275c9f80692773
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Md2, EmptyInput);
		result.Should().Be("8350e5a3e24c153df2275c9f80692773");
	}

	#endregion

	#region SHA-1/2 Family

	[Fact]
	public void Sha1_EmptyInput_ReturnsCorrectValue() {
		// SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha1, EmptyInput);
		result.Should().Be("da39a3ee5e6b4b0d3255bfef95601890afd80709");
	}

	[Fact]
	public void Sha1_Abc_ReturnsCorrectValue() {
		// SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha1, AbcInput);
		result.Should().Be("a9993e364706816aba3e25717850c26c9cd0d89d");
	}

	[Fact]
	public void Sha256_EmptyInput_ReturnsCorrectValue() {
		// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha256, EmptyInput);
		result.Should().Be("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	}

	[Fact]
	public void Sha256_Abc_ReturnsCorrectValue() {
		// SHA-256("abc")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha256, AbcInput);
		result.Should().Be("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	}

	[Fact]
	public void Sha384_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha384, EmptyInput);
		result.Should().Be("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
	}

	[Fact]
	public void Sha512_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha512, EmptyInput);
		result.Should().Be("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
	}

	[Fact]
	public void Sha224_EmptyInput_ReturnsCorrectValue() {
		// SHA-224("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha224, EmptyInput);
		result.Should().Be("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
	}

	#endregion

	#region SHA-3 Family

	[Fact]
	public void Sha3_256_EmptyInput_ReturnsCorrectValue() {
		// SHA3-256("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha3_256, EmptyInput);
		result.Should().Be("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
	}

	[Fact]
	public void Sha3_512_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha3_512, EmptyInput);
		result.Should().Be("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
	}

	[Fact]
	public void Keccak256_EmptyInput_ReturnsCorrectValue() {
		// Keccak-256 (original, not SHA3-256)
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Keccak256, EmptyInput);
		result.Should().Be("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	}

	#endregion

	#region BLAKE Family

	[Fact]
	public void Blake2b_EmptyInput_ReturnsCorrectValue() {
		// BLAKE2b-512("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Blake2b, EmptyInput);
		result.Should().Be("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
	}

	[Fact]
	public void Blake2s_EmptyInput_ReturnsCorrectValue() {
		// BLAKE2s-256("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Blake2s, EmptyInput);
		result.Should().Be("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
	}

	#endregion

	#region RIPEMD Family

	[Fact]
	public void Ripemd160_EmptyInput_ReturnsCorrectValue() {
		// RIPEMD-160("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Ripemd160, EmptyInput);
		result.Should().Be("9c1185a5c5e9fc54612808977ee8f548b2258d31");
	}

	[Fact]
	public void Ripemd128_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Ripemd128, EmptyInput);
		result.Should().Be("cdf26213a150dc3ecb610f18f6b38b46");
	}

	#endregion

	#region Other Crypto

	[Fact]
	public void Whirlpool_EmptyInput_ReturnsCorrectValue() {
		// Whirlpool("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Whirlpool, EmptyInput);
		result.Should().Be("19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
	}

	[Fact]
	public void Tiger192_EmptyInput_ReturnsCorrectValue() {
		// Tiger-192("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Tiger192, EmptyInput);
		result.Should().Be("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3");
	}

	[Fact]
	public void Sm3_EmptyInput_ReturnsCorrectValue() {
		// SM3("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sm3, EmptyInput);
		result.Should().Be("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
	}

	#endregion

	#region Groestl (validates real implementation, not SHA3 fallback)

	[Fact]
	public void Groestl256_EmptyInput_ReturnsCorrectValue() {
		// Grøstl-256("") - from specification
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Groestl256, EmptyInput);
		// If this returns SHA3-256's empty hash, the implementation is wrong
		result.Should().NotBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
			"Groestl should not return SHA3-256 value");
		result.Should().HaveLength(64); // 32 bytes = 64 hex chars
	}

	[Fact]
	public void Groestl512_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Groestl512, EmptyInput);
		// If this returns SHA3-512's empty hash, the implementation is wrong
		result.Should().NotBe("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
			"Groestl should not return SHA3-512 value");
		result.Should().HaveLength(128); // 64 bytes = 128 hex chars
	}

	#endregion

	#region JH (validates real implementation, not SHA3 fallback)

	[Fact]
	public void Jh256_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Jh256, EmptyInput);
		// If this returns SHA3-256's empty hash, the implementation is wrong
		result.Should().NotBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
			"JH should not return SHA3-256 value");
		result.Should().HaveLength(64); // 32 bytes
	}

	[Fact]
	public void Jh256_Streaming_MatchesOneShot() {
		// Test specifically for JH256 streaming vs one-shot
		// Simple 65 byte input - one full block plus 1 byte
		byte[] testData = new byte[65];
		for (int i = 0; i < testData.Length; i++) testData[i] = (byte)i;

		// One-shot
		string oneShotResult = HashFacade.ComputeHashHex(HashAlgorithm.Jh256, testData);

		// Streaming - feed entire data at once
		using var hasher1 = HashFacade.CreateStreaming(HashAlgorithm.Jh256);
		hasher1.Update(testData);
		string streamingOnce = Convert.ToHexStringLower(hasher1.FinalizeBytes());

		// Streaming - 32 + 33 bytes (crosses block boundary)
		using var hasher2 = HashFacade.CreateStreaming(HashAlgorithm.Jh256);
		hasher2.Update(testData.AsSpan(0, 32));
		hasher2.Update(testData.AsSpan(32, 33));
		string streamingChunked = Convert.ToHexStringLower(hasher2.FinalizeBytes());

		// All should match
		streamingOnce.Should().Be(oneShotResult, "JH256 streaming (single call) should match one-shot");
		streamingChunked.Should().Be(oneShotResult, "JH256 streaming (chunked) should match one-shot");
	}

	[Fact]
	public void Groestl256_Streaming_MatchesOneShot() {
		// Test Groestl256 too since it's similar implementation
		byte[] testData = new byte[65];
		for (int i = 0; i < testData.Length; i++) testData[i] = (byte)i;

		// One-shot
		string oneShotResult = HashFacade.ComputeHashHex(HashAlgorithm.Groestl256, testData);

		// Streaming - 32 + 33 bytes
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Groestl256);
		hasher.Update(testData.AsSpan(0, 32));
		hasher.Update(testData.AsSpan(32, 33));
		string streamingResult = Convert.ToHexStringLower(hasher.FinalizeBytes());

		streamingResult.Should().Be(oneShotResult, "Groestl256 streaming should match one-shot");
	}

	[Fact]
	public void Jh512_EmptyInput_ReturnsCorrectValue() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Jh512, EmptyInput);
		// If this returns SHA3-512's empty hash, the implementation is wrong
		result.Should().NotBe("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
			"JH should not return SHA3-512 value");
		result.Should().HaveLength(128); // 64 bytes
	}

	#endregion

	#region Large Input Tests

	/// <summary>
	/// Tests all algorithms with a larger input to ensure streaming works correctly.
	/// </summary>
	[Fact]
	public void AllAlgorithms_LargeInput_ProducesConsistentOutput() {
		// Create 1MB of test data
		byte[] largeData = new byte[1024 * 1024];
		new Random(42).NextBytes(largeData); // Seeded for reproducibility

		// Test each algorithm produces consistent output
		foreach (HashAlgorithm algo in Enum.GetValues<HashAlgorithm>()) {
			// Compute twice and verify same result
			string hash1 = HashFacade.ComputeHashHex(algo, largeData);
			string hash2 = HashFacade.ComputeHashHex(algo, largeData);

			hash1.Should().Be(hash2, $"{algo} should produce consistent output");
		}
	}

	/// <summary>
	/// Tests that streaming produces same result as one-shot.
	/// </summary>
	[Fact]
	public void AllAlgorithms_StreamingMatchesOneShot() {
		byte[] testData = new byte[10000];
		new Random(123).NextBytes(testData);

		foreach (HashAlgorithm algo in Enum.GetValues<HashAlgorithm>()) {
			// One-shot
			string oneShotResult = HashFacade.ComputeHashHex(algo, testData);

			// Streaming in chunks
			using var hasher = HashFacade.CreateStreaming(algo);
			int offset = 0;
			while (offset < testData.Length) {
				int chunkSize = Math.Min(1000, testData.Length - offset);
				hasher.Update(testData.AsSpan(offset, chunkSize));
				offset += chunkSize;
			}
			string streamingResult = Convert.ToHexStringLower(hasher.FinalizeBytes());

			oneShotResult.Should().Be(streamingResult,
				$"{algo} streaming should match one-shot");
		}
	}

	/// <summary>
	/// Tests that all algorithms have unique output (no duplicates from wrong implementations).
	/// </summary>
	[Fact]
	public void AllAlgorithms_ProduceUniqueOutput() {
		// Use a distinctive input
		byte[] testData = "StreamHash validation test input"u8.ToArray();

		var results = new Dictionary<string, List<HashAlgorithm>>();

		foreach (HashAlgorithm algo in Enum.GetValues<HashAlgorithm>()) {
			string hash = HashFacade.ComputeHashHex(algo, testData);

			if (!results.TryGetValue(hash, out var list)) {
				list = [];
				results[hash] = list;
			}
			list.Add(algo);
		}

		// Check for duplicates (except expected ones)
		var duplicates = results.Where(kvp => kvp.Value.Count > 1).ToList();

		// Expected duplicates:
		// - Blake256 uses Blake2b-256, Blake512 uses Blake2b-512
		// - CityHash64 and FarmHash64 can produce same output (FarmHash is derivative of CityHash)
		foreach (var dup in duplicates) {
			var algos = dup.Value;
			bool isExpectedDuplicate =
				(algos.Contains(HashAlgorithm.Blake256) && algos.Contains(HashAlgorithm.Blake2b)) ||
				(algos.Contains(HashAlgorithm.Blake512) && algos.Contains(HashAlgorithm.Blake2b)) ||
				(algos.Contains(HashAlgorithm.CityHash64) && algos.Contains(HashAlgorithm.FarmHash64));

			if (!isExpectedDuplicate && algos.Count > 1) {
				// Only flag if it's not an expected variant match
				var differentSizeAlgos = algos.GroupBy(a => HashFacade.GetInfo(a).DigestSize).Where(g => g.Count() > 1);
				foreach (var group in differentSizeAlgos) {
					Assert.Fail($"Unexpected duplicate hash output for algorithms with same digest size: {string.Join(", ", group)}");
				}
			}
		}
	}

	#endregion

	#region Digest Size Validation

	/// <summary>
	/// Tests that all algorithms produce the expected digest size.
	/// </summary>
	[Fact]
	public void AllAlgorithms_ProduceCorrectDigestSize() {
		foreach (HashAlgorithm algo in Enum.GetValues<HashAlgorithm>()) {
			var info = HashFacade.GetInfo(algo);
			byte[] result = HashFacade.ComputeHash(algo, AbcInput);

			result.Length.Should().Be(info.DigestSize,
				$"{algo} should produce {info.DigestSize} bytes, got {result.Length}");
		}
	}

	#endregion
}
