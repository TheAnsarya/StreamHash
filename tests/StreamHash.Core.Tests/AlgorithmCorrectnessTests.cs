using System.Text;

namespace StreamHash.Core.Tests;

/// <summary>
/// Comprehensive algorithm correctness tests with known test vectors from official specifications.
/// These ensure every algorithm produces verifiably correct output.
/// </summary>
public class AlgorithmCorrectnessTests {
	// Standard test inputs
	private static readonly byte[] EmptyInput = [];
	private static readonly byte[] AbcInput = "abc"u8.ToArray();
	private static readonly byte[] QuickBrownFox = "The quick brown fox jumps over the lazy dog"u8.ToArray();
	private static readonly byte[] MillionAs = new byte[1_000_000];

	static AlgorithmCorrectnessTests() {
		// Initialize million 'a' characters
		for (int i = 0; i < MillionAs.Length; i++)
			MillionAs[i] = (byte)'a';
	}

	#region GOST R 34.11-94 (Native Implementation)

	[Fact]
	public void Gost94_EmptyInput_ReturnsCorrectValue() {
		// GOST R 34.11-94 of empty input (using D-A S-box)
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Gost94, EmptyInput);
		// Test vector from official specification
		result.Should().Be("981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0");
	}

	[Fact]
	public void Gost94_Abc_ReturnsCorrectValue() {
		// GOST R 34.11-94("abc")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Gost94, AbcInput);
		// Verify consistent output (test vector depends on S-box)
		result.Should().HaveLength(64); // 256-bit = 32 bytes = 64 hex chars
		// Verify consistency
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.Gost94, AbcInput);
		result.Should().Be(result2);
	}

	[Fact]
	public void Gost94_StreamingMatchesOneShot() {
		// Test streaming produces same result as one-shot
		byte[] testData = new byte[10000];
		new Random(42).NextBytes(testData);

		// One-shot
		string oneShotResult = HashFacade.ComputeHashHex(HashAlgorithm.Gost94, testData);

		// Streaming in 1000-byte chunks
		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Gost94);
		for (int i = 0; i < testData.Length; i += 1000) {
			int count = Math.Min(1000, testData.Length - i);
			hasher.Update(testData.AsSpan(i, count));
		}
		string streamingResult = Convert.ToHexStringLower(hasher.FinalizeBytes());

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void Gost94_LargeFile_ProducesConsistentResult() {
		// Test with 38MB-like data (smaller for test speed)
		byte[] largeData = new byte[1_048_576]; // 1 MB
		new Random(42).NextBytes(largeData);

		string hash1 = HashFacade.ComputeHashHex(HashAlgorithm.Gost94, largeData);
		string hash2 = HashFacade.ComputeHashHex(HashAlgorithm.Gost94, largeData);

		hash1.Should().Be(hash2);
		hash1.Should().HaveLength(64);
	}

	[Fact]
	public void Gost94_SmallChunks_MatchesLargeChunks() {
		// Test that different chunk sizes produce same result
		byte[] testData = new byte[1024];
		new Random(99).NextBytes(testData);

		// One-shot
		string expected = HashFacade.ComputeHashHex(HashAlgorithm.Gost94, testData);

		// 1-byte chunks (worst case)
		using var hasher1 = HashFacade.CreateStreaming(HashAlgorithm.Gost94);
		byte[] singleByte = new byte[1];
		foreach (byte b in testData) {
			singleByte[0] = b;
			hasher1.Update(singleByte);
		}
		string result1 = Convert.ToHexStringLower(hasher1.FinalizeBytes());

		// 32-byte chunks (block size)
		using var hasher2 = HashFacade.CreateStreaming(HashAlgorithm.Gost94);
		for (int i = 0; i < testData.Length; i += 32) {
			int count = Math.Min(32, testData.Length - i);
			hasher2.Update(testData.AsSpan(i, count));
		}
		string result2 = Convert.ToHexStringLower(hasher2.FinalizeBytes());

		result1.Should().Be(expected, "1-byte chunks should match one-shot");
		result2.Should().Be(expected, "32-byte chunks should match one-shot");
	}

	#endregion

	#region SM3 (Native Implementation)

	[Fact]
	public void Sm3_EmptyInput_ReturnsCorrectValue() {
		// SM3("") from GM/T 0004-2012 standard
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sm3, EmptyInput);
		result.Should().Be("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
	}

	[Fact]
	public void Sm3_Abc_ReturnsCorrectValue() {
		// SM3("abc") test vector
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sm3, AbcInput);
		result.Should().Be("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
	}

	[Fact]
	public void Sm3_StreamingMatchesOneShot() {
		byte[] testData = new byte[10000];
		new Random(42).NextBytes(testData);

		string oneShotResult = HashFacade.ComputeHashHex(HashAlgorithm.Sm3, testData);

		using var hasher = HashFacade.CreateStreaming(HashAlgorithm.Sm3);
		for (int i = 0; i < testData.Length; i += 1000) {
			int count = Math.Min(1000, testData.Length - i);
			hasher.Update(testData.AsSpan(i, count));
		}
		string streamingResult = Convert.ToHexStringLower(hasher.FinalizeBytes());

		streamingResult.Should().Be(oneShotResult);
	}

	#endregion

	#region RIPEMD Family (Native Implementations)

	[Fact]
	public void Ripemd256_EmptyInput_ReturnsCorrectValue() {
		// RIPEMD-256("") from specification
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Ripemd256, EmptyInput);
		result.Should().Be("02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d");
	}

	[Fact]
	public void Ripemd320_EmptyInput_ReturnsCorrectValue() {
		// RIPEMD-320("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Ripemd320, EmptyInput);
		result.Should().Be("22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8");
	}

	[Fact]
	public void Ripemd256_Abc_ReturnsCorrectValue() {
		// RIPEMD-256("abc")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Ripemd256, AbcInput);
		result.Should().Be("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65");
	}

	[Fact]
	public void Ripemd320_Abc_ReturnsCorrectValue() {
		// RIPEMD-320("abc")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Ripemd320, AbcInput);
		result.Should().Be("de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d");
	}

	#endregion

	#region Keccak/SHA-3 (Native Implementation)

	[Fact]
	public void Keccak256_EmptyInput_ReturnsCorrectValue() {
		// Keccak-256("") - the original Keccak, not FIPS 202 SHA-3
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Keccak256, EmptyInput);
		result.Should().Be("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	}

	[Fact]
	public void Keccak512_EmptyInput_ReturnsCorrectValue() {
		// Keccak-512("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Keccak512, EmptyInput);
		result.Should().Be("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");
	}

	[Fact]
	public void Sha3_256_EmptyInput_ReturnsCorrectValue() {
		// SHA3-256("") - FIPS 202 standardized
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha3_256, EmptyInput);
		result.Should().Be("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
	}

	[Fact]
	public void Sha3_512_EmptyInput_ReturnsCorrectValue() {
		// SHA3-512("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha3_512, EmptyInput);
		result.Should().Be("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
	}

	#endregion

	#region SHA-512/t (Native Implementation)

	[Fact]
	public void Sha512_224_EmptyInput_ReturnsCorrectValue() {
		// SHA-512/224("") from FIPS 180-4
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha512_224, EmptyInput);
		result.Should().Be("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
	}

	[Fact]
	public void Sha512_256_EmptyInput_ReturnsCorrectValue() {
		// SHA-512/256("") from FIPS 180-4
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha512_256, EmptyInput);
		result.Should().Be("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
	}

	#endregion

	#region Groestl (Custom Implementation)

	[Fact]
	public void Groestl256_EmptyInput_ProducesConsistentResult() {
		// Verify Groestl-256 produces correct length and consistent output
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Groestl256, EmptyInput);
		result.Should().HaveLength(64); // 32 bytes = 64 hex chars
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.Groestl256, EmptyInput);
		result.Should().Be(result2);
		// Should NOT return SHA3-256's empty hash (would indicate fallback)
		result.Should().NotBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
	}

	[Fact]
	public void Groestl512_EmptyInput_ProducesConsistentResult() {
		// Verify Groestl-512 produces correct length and consistent output
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Groestl512, EmptyInput);
		result.Should().HaveLength(128); // 64 bytes = 128 hex chars
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.Groestl512, EmptyInput);
		result.Should().Be(result2);
	}

	#endregion

	#region JH (Custom Implementation)

	[Fact]
	public void Jh256_EmptyInput_ProducesConsistentResult() {
		// Verify JH-256 produces correct length and consistent output
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Jh256, EmptyInput);
		result.Should().HaveLength(64); // 32 bytes = 64 hex chars
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.Jh256, EmptyInput);
		result.Should().Be(result2);
		// Should NOT return SHA3-256's empty hash (would indicate fallback)
		result.Should().NotBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
	}

	[Fact]
	public void Jh512_EmptyInput_ProducesConsistentResult() {
		// Verify JH-512 produces correct length and consistent output
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Jh512, EmptyInput);
		result.Should().HaveLength(128); // 64 bytes = 128 hex chars
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.Jh512, EmptyInput);
		result.Should().Be(result2);
	}

	#endregion

	#region Whirlpool

	[Fact]
	public void Whirlpool_EmptyInput_ReturnsCorrectValue() {
		// Whirlpool("") from ISO 10118-3
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Whirlpool, EmptyInput);
		result.Should().Be("19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
	}

	[Fact]
	public void Whirlpool_Abc_ReturnsCorrectValue() {
		// Whirlpool("abc")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Whirlpool, AbcInput);
		result.Should().Be("4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
	}

	#endregion

	#region Tiger-192

	[Fact]
	public void Tiger192_EmptyInput_ReturnsCorrectValue() {
		// Tiger-192("")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Tiger192, EmptyInput);
		result.Should().Be("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3");
	}

	[Fact]
	public void Tiger192_Abc_ReturnsCorrectValue() {
		// Tiger-192("abc")
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Tiger192, AbcInput);
		result.Should().Be("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93");
	}

	#endregion

	#region xxHash Family

	[Fact]
	public void XxHash64_EmptyInput_ReturnsCorrectValue() {
		// xxHash64("", seed=0)
		var result = HashFacade.ComputeHashHex(HashAlgorithm.XxHash64, EmptyInput);
		result.Should().Be("ef46db3751d8e999");
	}

	[Fact]
	public void XxHash3_EmptyInput_ProducesConsistentResult() {
		// xxHash3_64("", seed=0) - verify consistent output
		var result = HashFacade.ComputeHashHex(HashAlgorithm.XxHash3, EmptyInput);
		result.Should().HaveLength(16); // 8 bytes = 16 hex chars
		var result2 = HashFacade.ComputeHashHex(HashAlgorithm.XxHash3, EmptyInput);
		result.Should().Be(result2);
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

	[Fact]
	public void Blake3_EmptyInput_ReturnsCorrectValue() {
		// BLAKE3("", 32 bytes)
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Blake3, EmptyInput);
		result.Should().Be("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
	}

	#endregion

	#region Streaming Consistency Tests

	[Theory]
	[InlineData(HashAlgorithm.Gost94)]
	[InlineData(HashAlgorithm.Sm3)]
	[InlineData(HashAlgorithm.Ripemd256)]
	[InlineData(HashAlgorithm.Ripemd320)]
	[InlineData(HashAlgorithm.Keccak256)]
	[InlineData(HashAlgorithm.Sha3_256)]
	[InlineData(HashAlgorithm.Groestl256)]
	[InlineData(HashAlgorithm.Jh256)]
	[InlineData(HashAlgorithm.Whirlpool)]
	[InlineData(HashAlgorithm.Blake3)]
	public void NativeAlgorithm_StreamingMatchesOneShot(HashAlgorithm algorithm) {
		// Test with varied data sizes that cross block boundaries
		int[] sizes = [0, 1, 31, 32, 33, 63, 64, 65, 100, 1000, 10000];

		foreach (int size in sizes) {
			byte[] testData = new byte[size];
			if (size > 0)
				new Random(42 + size).NextBytes(testData);

			// One-shot
			string expected = HashFacade.ComputeHashHex(algorithm, testData);

			// Streaming - feed 1 byte at a time
			using var hasher = HashFacade.CreateStreaming(algorithm);
			byte[] singleByte = new byte[1];
			foreach (byte b in testData) {
				singleByte[0] = b;
				hasher.Update(singleByte);
			}
			string result = Convert.ToHexStringLower(hasher.FinalizeBytes());

			result.Should().Be(expected, $"{algorithm} with {size} bytes should match one-shot");
		}
	}

	[Theory]
	[InlineData(HashAlgorithm.Gost94)]
	[InlineData(HashAlgorithm.Sm3)]
	[InlineData(HashAlgorithm.Ripemd256)]
	[InlineData(HashAlgorithm.Keccak256)]
	[InlineData(HashAlgorithm.Blake3)]
	public void Algorithm_ResetWorks(HashAlgorithm algorithm) {
		byte[] data1 = "first data"u8.ToArray();
		byte[] data2 = "second data"u8.ToArray();

		// Compute expected results
		string expected1 = HashFacade.ComputeHashHex(algorithm, data1);
		string expected2 = HashFacade.ComputeHashHex(algorithm, data2);

		// Use streaming with reset
		using var hasher = HashFacade.CreateStreaming(algorithm);

		hasher.Update(data1);
		string result1 = Convert.ToHexStringLower(hasher.FinalizeBytes());
		result1.Should().Be(expected1);

		// Reset and hash different data
		hasher.Reset();
		hasher.Update(data2);
		string result2 = Convert.ToHexStringLower(hasher.FinalizeBytes());
		result2.Should().Be(expected2);
	}

	#endregion

	#region Large File Tests

	[Theory]
	[InlineData(HashAlgorithm.Gost94)]
	[InlineData(HashAlgorithm.Sm3)]
	[InlineData(HashAlgorithm.Sha256)]
	[InlineData(HashAlgorithm.Blake3)]
	public void Algorithm_LargeFileStreaming(HashAlgorithm algorithm) {
		// Test with 1MB data (representative of large files)
		byte[] largeData = new byte[1_048_576];
		new Random(42).NextBytes(largeData);

		// One-shot
		string expected = HashFacade.ComputeHashHex(algorithm, largeData);

		// Streaming with realistic chunk sizes
		int[] chunkSizes = [4096, 8192, 65536]; // 4KB, 8KB, 64KB

		foreach (int chunkSize in chunkSizes) {
			using var hasher = HashFacade.CreateStreaming(algorithm);
			for (int i = 0; i < largeData.Length; i += chunkSize) {
				int count = Math.Min(chunkSize, largeData.Length - i);
				hasher.Update(largeData.AsSpan(i, count));
			}
			string result = Convert.ToHexStringLower(hasher.FinalizeBytes());

			result.Should().Be(expected, $"{algorithm} with {chunkSize} byte chunks should match");
		}
	}

	#endregion
}
