using FluentAssertions;
using StreamHash.Core;
using Xunit;

namespace StreamHash.Tests;

/// <summary>
/// Tests for batch streaming API (<see cref="IMultiStreamingHashBytes"/>).
/// </summary>
public class BatchStreamingTests {
	[Fact]
	public void CreateAllStreaming_WithAllAlgorithms_CreatesAllHashers() {
		// Arrange & Act
		using var batchHasher = HashFacade.CreateAllStreaming();

		// Assert
		batchHasher.AlgorithmCount.Should().Be(70, "all 70 algorithms should be included");
		batchHasher.AlgorithmNames.Should().HaveCount(70);
	}

	[Fact]
	public void CreateAllStreaming_WithChecksums_CreatesOnlyChecksums() {
		// Arrange & Act
		using var batchHasher = HashFacade.CreateAllStreaming(HashAlgorithmSet.Checksums);

		// Assert
		batchHasher.AlgorithmCount.Should().Be(9, "9 checksum algorithms should be included");
	}

	[Fact]
	public void CreateBatchStreaming_WithSpecificAlgorithms_CreatesSelectedHashers() {
		// Arrange & Act
		using var batchHasher = HashFacade.CreateBatchStreaming(
			HashAlgorithmNames.Sha256,
			HashAlgorithmNames.Blake3,
			HashAlgorithmNames.XxHash64);

		// Assert
		batchHasher.AlgorithmCount.Should().Be(3);
		batchHasher.AlgorithmNames.Should().Contain(new[] {
			HashAlgorithmNames.Sha256,
			HashAlgorithmNames.Blake3,
			HashAlgorithmNames.XxHash64
		});
	}

	[Fact]
	public void CreateBasicCommonHashesStreaming_CreatesExactlyFiveHashers() {
		// Arrange & Act
		using var batchHasher = HashFacade.CreateBasicCommonHashesStreaming();

		// Assert
		batchHasher.AlgorithmCount.Should().Be(5, "basic common hashes should include exactly 5 algorithms");
		batchHasher.AlgorithmNames.Should().BeEquivalentTo(HashAlgorithmNames.BasicHashes);
	}

	[Fact]
	public void CreateBasicCommonHashesStreaming_ProducesCorrectHashes() {
		// Arrange
		var data = new byte[1024 * 1024];  // 1MB
		new Random(42).NextBytes(data);

		// Compute expected hashes individually
		var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
			[HashAlgorithmNames.Crc32] = HashFacade.ComputeHashHex(HashAlgorithm.Crc32, data),
			[HashAlgorithmNames.Md5] = HashFacade.ComputeHashHex(HashAlgorithm.Md5, data),
			[HashAlgorithmNames.Sha1] = HashFacade.ComputeHashHex(HashAlgorithm.Sha1, data),
			[HashAlgorithmNames.Sha256] = HashFacade.ComputeHashHex(HashAlgorithm.Sha256, data),
			[HashAlgorithmNames.Sha512] = HashFacade.ComputeHashHex(HashAlgorithm.Sha512, data)
		};

		// Act - Hash with basic hashes streaming
		using var basicHasher = HashFacade.CreateBasicCommonHashesStreaming();
		basicHasher.Update(data);
		var results = basicHasher.FinalizeAll();

		// Assert
		results.Should().HaveCount(5);
		foreach (var (algo, expectedHash) in expected) {
			results.Should().ContainKey(algo);
			results[algo].Should().Be(expectedHash, $"{algo} hash should match individual result");
		}
	}

	[Fact]
	public void CreateBasicCommonHashesStreaming_ChunkedUpdate_MatchesFullUpdate() {
		// Arrange
		var data = new byte[10 * 1024 * 1024];  // 10MB
		new Random(42).NextBytes(data);

		// Full update
		using var fullHasher = HashFacade.CreateBasicCommonHashesStreaming();
		fullHasher.Update(data);
		var fullResults = fullHasher.FinalizeAll();

		// Chunked update (1MB chunks)
		using var chunkHasher = HashFacade.CreateBasicCommonHashesStreaming();
		for (int i = 0; i < data.Length; i += 1024 * 1024) {
			int size = Math.Min(1024 * 1024, data.Length - i);
			chunkHasher.Update(data.AsSpan(i, size));
		}
		var chunkResults = chunkHasher.FinalizeAll();

		// Assert
		chunkResults.Should().HaveCount(5);
		chunkResults[HashAlgorithmNames.Crc32].Should().Be(fullResults[HashAlgorithmNames.Crc32]);
		chunkResults[HashAlgorithmNames.Md5].Should().Be(fullResults[HashAlgorithmNames.Md5]);
		chunkResults[HashAlgorithmNames.Sha1].Should().Be(fullResults[HashAlgorithmNames.Sha1]);
		chunkResults[HashAlgorithmNames.Sha256].Should().Be(fullResults[HashAlgorithmNames.Sha256]);
		chunkResults[HashAlgorithmNames.Sha512].Should().Be(fullResults[HashAlgorithmNames.Sha512]);
	}

	[Fact]
	public void CreateBasicHashesStreaming_BackwardCompatibleAlias_UsesBasicCommonSet() {
		using var batchHasher = HashFacade.CreateBasicHashesStreaming();

		batchHasher.AlgorithmCount.Should().Be(5);
		batchHasher.AlgorithmNames.Should().BeEquivalentTo(HashAlgorithmNames.BasicHashes);
	}

	[Fact]
	public void BatchHasher_ProducesSameResults_AsIndividualHashers() {
		// Arrange
		var data = new byte[1024 * 1024];  // 1MB
		new Random(42).NextBytes(data);

		// Hash with individual hashers (small sample for speed)
		var testAlgorithms = new[] { "SHA-256", "BLAKE3", "xxHash64", "MurmurHash3-128", "CRC32" };
		var individual = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		foreach (var algoName in testAlgorithms) {
			var algo = ParseAlgorithmName(algoName);
			using var hasher = HashFacade.CreateStreaming(algo);
			hasher.Update(data);
			individual[algoName] = Convert.ToHexStringLower(hasher.FinalizeBytes());
		}

		// Hash with batch hasher
		using var batchHasher = HashFacade.CreateBatchStreaming(testAlgorithms);
		batchHasher.Update(data);
		var batch = batchHasher.FinalizeAll();

		// Assert
		batch.Should().HaveCount(individual.Count);
		foreach (var (algo, hash) in individual) {
			batch.Should().ContainKey(algo);
			batch[algo].Should().Be(hash, $"{algo} hash should match individual result");
		}
	}

	[Fact]
	public void BatchHasher_ChunkedUpdate_MatchesFullUpdate() {
		// Arrange
		var data = new byte[10 * 1024 * 1024];  // 10MB
		new Random(42).NextBytes(data);

		var testAlgorithms = new[] { "SHA-256", "xxHash64", "MurmurHash3-128" };

		// Full update
		using var fullHasher = HashFacade.CreateBatchStreaming(testAlgorithms);
		fullHasher.Update(data);
		var fullResults = fullHasher.FinalizeAll();

		// Chunked update (1MB chunks)
		using var chunkHasher = HashFacade.CreateBatchStreaming(testAlgorithms);
		for (int i = 0; i < data.Length; i += 1024 * 1024) {
			int size = Math.Min(1024 * 1024, data.Length - i);
			chunkHasher.Update(data.AsSpan(i, size));
		}
		var chunkResults = chunkHasher.FinalizeAll();

		// Assert
		chunkResults.Should().HaveCount(fullResults.Count);
		foreach (var algo in testAlgorithms) {
			chunkResults[algo].Should().Be(fullResults[algo],
				$"{algo} chunked result should match full update");
		}
	}

	[Fact]
	public void BatchHasher_Reset_AllowsReuse() {
		// Arrange
		var data1 = new byte[1024];
		var data2 = new byte[1024];
		new Random(1).NextBytes(data1);
		new Random(2).NextBytes(data2);

		using var hasher = HashFacade.CreateBatchStreaming("SHA-256", "xxHash64");

		// Act
		hasher.Update(data1);
		var results1 = hasher.FinalizeAll();

		hasher.Reset();

		hasher.Update(data2);
		var results2 = hasher.FinalizeAll();

		// Assert
		results2["SHA-256"].Should().NotBe(results1["SHA-256"],
			"hashes should differ after reset with different data");
		results2["xxHash64"].Should().NotBe(results1["xxHash64"],
			"hashes should differ after reset with different data");
	}

	[Fact]
	public void BatchHasher_UpdateAfterFinalize_ThrowsException() {
		// Arrange
		var data = new byte[100];
		using var hasher = HashFacade.CreateBatchStreaming("SHA-256");
		hasher.Update(data);
		_ = hasher.FinalizeAll();

		// Act & Assert
		var act = () => hasher.Update(data);
		act.Should().Throw<InvalidOperationException>()
			.WithMessage("*Cannot update after FinalizeAll()*");
	}

	[Fact]
	public void BatchHasher_UpdateAfterDispose_ThrowsException() {
		// Arrange
		var data = new byte[100];
		var hasher = HashFacade.CreateBatchStreaming("SHA-256");
		hasher.Dispose();

		// Act & Assert
		var act = () => hasher.Update(data);
		act.Should().Throw<ObjectDisposedException>();
	}

	[Fact]
	public void BatchHasher_EmptyData_ProducesValidHashes() {
		// Arrange
		var emptyData = Array.Empty<byte>();

		// Act
		using var hasher = HashFacade.CreateBatchStreaming("SHA-256", "MD5");
		hasher.Update(emptyData);
		var results = hasher.FinalizeAll();

		// Assert
		results.Should().HaveCount(2);
		results["SHA-256"].Should().Be("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"SHA-256 of empty data should match expected value");
		results["MD5"].Should().Be("d41d8cd98f00b204e9800998ecf8427e",
			"MD5 of empty data should match expected value");
	}

	[Fact]
	public void GetAllAlgorithmNames_ReturnsAll71Algorithms() {
		// Act
		var names = HashFacade.GetAllAlgorithmNames();

		// Assert
		names.Should().HaveCount(70, "should return all 70 algorithm names");
		names.Should().Contain("SHA-256");
		names.Should().Contain("BLAKE3");
		names.Should().Contain("xxHash64");
		names.Should().Contain("MurmurHash3-128");
	}

	/// <summary>
	/// Helper to parse algorithm names to enum values.
	/// </summary>
	private static HashAlgorithm ParseAlgorithmName(string name) {
		return name.ToUpperInvariant().Replace("-", "").Replace("/", "") switch {
			"SHA256" => HashAlgorithm.Sha256,
			"BLAKE3" => HashAlgorithm.Blake3,
			"XXHASH64" => HashAlgorithm.XxHash64,
			"MURMURHASH3128" => HashAlgorithm.MurmurHash3_128,
			"CRC32" => HashAlgorithm.Crc32,
			_ => throw new NotSupportedException($"Unknown algorithm: {name}")
		};
	}
}
