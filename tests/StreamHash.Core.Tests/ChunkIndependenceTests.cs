using StreamHash.Core.Abstractions;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests verifying that streaming hash implementations produce identical results
/// regardless of how input data is chunked. This is critical for correctness
/// because the streaming API must be chunk-size-independent.
/// </summary>
public class ChunkIndependenceTests {
	private static readonly byte[] TestData = CreateTestData(4096);
	private static readonly byte[] SmallData = "Hello, World!"u8.ToArray();

	private static byte[] CreateTestData(int size) {
		var data = new byte[size];
		for (int i = 0; i < size; i++) {
			data[i] = (byte)(i % 251); // Prime modulus avoids trivial patterns
		}
		return data;
	}

	#region Individual Algorithm Chunk Independence

	[Theory]
	[InlineData(HashAlgorithm.Md2)]
	[InlineData(HashAlgorithm.Md4)]
	[InlineData(HashAlgorithm.Md5)]
	[InlineData(HashAlgorithm.Sha0)]
	[InlineData(HashAlgorithm.Sha1)]
	[InlineData(HashAlgorithm.Sha224)]
	[InlineData(HashAlgorithm.Sha256)]
	[InlineData(HashAlgorithm.Sha384)]
	[InlineData(HashAlgorithm.Sha512)]
	[InlineData(HashAlgorithm.Sha512_224)]
	[InlineData(HashAlgorithm.Sha512_256)]
	[InlineData(HashAlgorithm.Sha3_224)]
	[InlineData(HashAlgorithm.Sha3_256)]
	[InlineData(HashAlgorithm.Sha3_384)]
	[InlineData(HashAlgorithm.Sha3_512)]
	[InlineData(HashAlgorithm.Keccak256)]
	[InlineData(HashAlgorithm.Keccak512)]
	[InlineData(HashAlgorithm.Blake256)]
	[InlineData(HashAlgorithm.Blake512)]
	[InlineData(HashAlgorithm.Blake2b)]
	[InlineData(HashAlgorithm.Blake2s)]
	[InlineData(HashAlgorithm.Blake3)]
	[InlineData(HashAlgorithm.Ripemd128)]
	[InlineData(HashAlgorithm.Ripemd160)]
	[InlineData(HashAlgorithm.Ripemd256)]
	[InlineData(HashAlgorithm.Ripemd320)]
	[InlineData(HashAlgorithm.Whirlpool)]
	[InlineData(HashAlgorithm.Tiger192)]
	[InlineData(HashAlgorithm.Gost94)]
	[InlineData(HashAlgorithm.Streebog256)]
	[InlineData(HashAlgorithm.Streebog512)]
	[InlineData(HashAlgorithm.Skein256)]
	[InlineData(HashAlgorithm.Skein512)]
	[InlineData(HashAlgorithm.Skein1024)]
	[InlineData(HashAlgorithm.Groestl256)]
	[InlineData(HashAlgorithm.Groestl512)]
	[InlineData(HashAlgorithm.Jh256)]
	[InlineData(HashAlgorithm.Jh512)]
	[InlineData(HashAlgorithm.KangarooTwelve)]
	[InlineData(HashAlgorithm.Sm3)]
	public void StreamingHash_ChunkSizeIndependent_CryptoAlgorithms(HashAlgorithm algorithm) {
		VerifyChunkIndependence(algorithm, TestData);
	}

	[Theory]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.Crc32C)]
	[InlineData(HashAlgorithm.Crc64)]
	[InlineData(HashAlgorithm.Crc16Ccitt)]
	[InlineData(HashAlgorithm.Crc16Modbus)]
	[InlineData(HashAlgorithm.Crc16Usb)]
	[InlineData(HashAlgorithm.Adler32)]
	[InlineData(HashAlgorithm.Fletcher16)]
	[InlineData(HashAlgorithm.Fletcher32)]
	[InlineData(HashAlgorithm.XxHash32)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.XxHash3)]
	[InlineData(HashAlgorithm.XxHash128)]
	[InlineData(HashAlgorithm.MurmurHash3_32)]
	[InlineData(HashAlgorithm.MurmurHash3_128)]
	[InlineData(HashAlgorithm.CityHash64)]
	[InlineData(HashAlgorithm.CityHash128)]
	[InlineData(HashAlgorithm.FarmHash64)]
	[InlineData(HashAlgorithm.SpookyHash128)]
	[InlineData(HashAlgorithm.SipHash24)]
	[InlineData(HashAlgorithm.HighwayHash64)]
	[InlineData(HashAlgorithm.MetroHash64)]
	[InlineData(HashAlgorithm.MetroHash128)]
	[InlineData(HashAlgorithm.Wyhash64)]
	[InlineData(HashAlgorithm.Fnv1a32)]
	[InlineData(HashAlgorithm.Fnv1a64)]
	[InlineData(HashAlgorithm.Djb2)]
	[InlineData(HashAlgorithm.Djb2a)]
	[InlineData(HashAlgorithm.Sdbm)]
	[InlineData(HashAlgorithm.LoseLose)]
	public void StreamingHash_ChunkSizeIndependent_NonCryptoAlgorithms(HashAlgorithm algorithm) {
		VerifyChunkIndependence(algorithm, TestData);
	}

	#endregion

	#region Extreme Chunk Sizes

	[Theory]
	[InlineData(HashAlgorithm.Sha256)]
	[InlineData(HashAlgorithm.Blake3)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.MurmurHash3_128)]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.Fletcher16)]
	[InlineData(HashAlgorithm.Adler32)]
	[InlineData(HashAlgorithm.Sha3_512)]
	[InlineData(HashAlgorithm.Whirlpool)]
	[InlineData(HashAlgorithm.Gost94)]
	[InlineData(HashAlgorithm.SipHash24)]
	[InlineData(HashAlgorithm.Fnv1a64)]
	public void StreamingHash_SingleByteChunks_MatchesOneShot(HashAlgorithm algorithm) {
		// Feed data one byte at a time - most extreme case
		var oneShotResult = Convert.ToHexStringLower(HashFacade.ComputeHash(algorithm, SmallData));

		using var hasher = HashFacade.CreateStreaming(algorithm);
		for (int i = 0; i < SmallData.Length; i++) {
			hasher.Update(SmallData.AsSpan(i, 1));
		}
		var streamingResult = Convert.ToHexStringLower(hasher.FinalizeBytes());

		streamingResult.Should().Be(oneShotResult, $"{algorithm} single-byte chunks should match one-shot");
	}

	[Theory]
	[InlineData(HashAlgorithm.Sha256)]
	[InlineData(HashAlgorithm.Blake3)]
	[InlineData(HashAlgorithm.Md5)]
	[InlineData(HashAlgorithm.CityHash128)]
	[InlineData(HashAlgorithm.Fletcher32)]
	[InlineData(HashAlgorithm.Crc64)]
	[InlineData(HashAlgorithm.Streebog512)]
	[InlineData(HashAlgorithm.Skein1024)]
	[InlineData(HashAlgorithm.HighwayHash64)]
	[InlineData(HashAlgorithm.Djb2)]
	public void StreamingHash_WholeInputAsOneChunk_MatchesOneShot(HashAlgorithm algorithm) {
		var oneShotResult = Convert.ToHexStringLower(HashFacade.ComputeHash(algorithm, TestData));

		using var hasher = HashFacade.CreateStreaming(algorithm);
		hasher.Update(TestData.AsSpan());
		var streamingResult = Convert.ToHexStringLower(hasher.FinalizeBytes());

		streamingResult.Should().Be(oneShotResult);
	}

	#endregion

	#region Batch API Chunk Independence

	[Fact]
	public void BatchStreaming_ChunkSizeIndependent() {
		// Compute one-shot results
		var oneShotSha256 = HashFacade.ComputeHashHex(HashAlgorithm.Sha256, TestData);
		var oneShotBlake3 = HashFacade.ComputeHashHex(HashAlgorithm.Blake3, TestData);
		var oneShotMd5 = HashFacade.ComputeHashHex(HashAlgorithm.Md5, TestData);

		// Feed in various chunk sizes via batch API
		int[] chunkSizes = [1, 7, 64, 128, 1000, TestData.Length];

		foreach (var chunkSize in chunkSizes) {
			using var batch = HashFacade.CreateBatchStreaming(
				HashAlgorithmNames.Sha256,
				HashAlgorithmNames.Blake3,
				HashAlgorithmNames.Md5);

			int offset = 0;
			while (offset < TestData.Length) {
				int len = Math.Min(chunkSize, TestData.Length - offset);
				batch.Update(TestData.AsSpan(offset, len));
				offset += len;
			}

			var results = batch.FinalizeAll();

			results[HashAlgorithmNames.Sha256].Should().Be(oneShotSha256,
				$"SHA-256 with chunk size {chunkSize} should match one-shot");
			results[HashAlgorithmNames.Blake3].Should().Be(oneShotBlake3,
				$"BLAKE3 with chunk size {chunkSize} should match one-shot");
			results[HashAlgorithmNames.Md5].Should().Be(oneShotMd5,
				$"MD5 with chunk size {chunkSize} should match one-shot");
		}
	}

	#endregion

	#region Reset Behavior

	[Theory]
	[InlineData(HashAlgorithm.Blake3)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.Sha256)]
	[InlineData(HashAlgorithm.Md5)]
	[InlineData(HashAlgorithm.Sha384)]
	[InlineData(HashAlgorithm.Sha512)]
	[InlineData(HashAlgorithm.Sha1)]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.Fletcher16)]
	[InlineData(HashAlgorithm.Adler32)]
	[InlineData(HashAlgorithm.MurmurHash3_128)]
	[InlineData(HashAlgorithm.CityHash64)]
	[InlineData(HashAlgorithm.Gost94)]
	[InlineData(HashAlgorithm.Whirlpool)]
	[InlineData(HashAlgorithm.Fnv1a32)]
	public void StreamingHash_Reset_ProducesSameResultAgain(HashAlgorithm algorithm) {
		using var hasher = HashFacade.CreateStreaming(algorithm);

		hasher.Update(TestData.AsSpan());
		var firstResult = Convert.ToHexStringLower(hasher.FinalizeBytes());

		hasher.Reset();

		hasher.Update(TestData.AsSpan());
		var secondResult = Convert.ToHexStringLower(hasher.FinalizeBytes());

		secondResult.Should().Be(firstResult, $"{algorithm} should produce same result after Reset()");
	}

	#endregion

	#region Alternating Chunk Sizes

	[Theory]
	[InlineData(HashAlgorithm.Sha256)]
	[InlineData(HashAlgorithm.Blake3)]
	[InlineData(HashAlgorithm.Md5)]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.MurmurHash3_128)]
	[InlineData(HashAlgorithm.Fletcher16)]
	[InlineData(HashAlgorithm.SipHash24)]
	[InlineData(HashAlgorithm.Gost94)]
	[InlineData(HashAlgorithm.Groestl256)]
	[InlineData(HashAlgorithm.Fnv1a64)]
	[InlineData(HashAlgorithm.Adler32)]
	public void StreamingHash_AlternatingChunkSizes_MatchesOneShot(HashAlgorithm algorithm) {
		var oneShotResult = Convert.ToHexStringLower(HashFacade.ComputeHash(algorithm, TestData));

		// Alternate between small and large chunk sizes
		int[] chunkPattern = [1, 1024, 7, 256, 63, 512, 3, 128];

		using var hasher = HashFacade.CreateStreaming(algorithm);
		int offset = 0;
		int patternIndex = 0;
		while (offset < TestData.Length) {
			int chunkSize = chunkPattern[patternIndex % chunkPattern.Length];
			int len = Math.Min(chunkSize, TestData.Length - offset);
			hasher.Update(TestData.AsSpan(offset, len));
			offset += len;
			patternIndex++;
		}

		var streamingResult = Convert.ToHexStringLower(hasher.FinalizeBytes());
		streamingResult.Should().Be(oneShotResult,
			$"{algorithm} with alternating chunk sizes should match one-shot result");
	}

	#endregion

	#region Helper Methods

	/// <summary>
	/// Verifies that hashing the same data with different chunk sizes produces identical results.
	/// Compares against one-shot result as ground truth.
	/// </summary>
	private static void VerifyChunkIndependence(HashAlgorithm algorithm, byte[] data) {
		var oneShotResult = Convert.ToHexStringLower(HashFacade.ComputeHash(algorithm, data));

		// Test various chunk sizes
		int[] chunkSizes = [1, 3, 7, 16, 63, 64, 65, 128, 255, 256, 512, 1024, data.Length];

		foreach (var chunkSize in chunkSizes) {
			using var hasher = HashFacade.CreateStreaming(algorithm);
			int offset = 0;
			while (offset < data.Length) {
				int len = Math.Min(chunkSize, data.Length - offset);
				hasher.Update(data.AsSpan(offset, len));
				offset += len;
			}

			var streamingResult = Convert.ToHexStringLower(hasher.FinalizeBytes());
			streamingResult.Should().Be(oneShotResult,
				$"{algorithm} with chunk size {chunkSize} should match one-shot result");
		}
	}

	#endregion
}
