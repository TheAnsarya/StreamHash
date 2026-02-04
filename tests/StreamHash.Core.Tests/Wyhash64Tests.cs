using System.Buffers.Binary;
using System.Text;
using FluentAssertions;
using StreamHash.Core;
using Xunit;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for Wyhash64 streaming implementation.
/// </summary>
public class Wyhash64Tests {
	// Known test vectors - using one-shot for reference since wyhash doesn't publish streaming vectors
	private static readonly byte[] EmptyData = [];
	private static readonly byte[] SingleByte = [(byte)'a'];
	private static readonly byte[] SmallData = Encoding.UTF8.GetBytes("Hello");
	private static readonly byte[] MediumData = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

	[Fact]
	public void Hash_EmptyInput_ProducesConsistentResult() {
		using var hasher = new Wyhash64();
		var result = hasher.Finalize();

		var expected = Wyhash64.Hash([]);
		result.Should().Be(expected);
	}

	[Fact]
	public void Hash_SingleByte_MatchesStaticMethod() {
		using var hasher = new Wyhash64();
		hasher.Update(SingleByte);
		var result = hasher.Finalize();

		var expected = Wyhash64.Hash(SingleByte);
		result.Should().Be(expected);
	}

	[Fact]
	public void Hash_SmallData_MatchesStaticMethod() {
		using var hasher = new Wyhash64();
		hasher.Update(SmallData);
		var result = hasher.Finalize();

		var expected = Wyhash64.Hash(SmallData);
		result.Should().Be(expected);
	}

	[Fact]
	public void Hash_MediumData_MatchesStaticMethod() {
		using var hasher = new Wyhash64();
		hasher.Update(MediumData);
		var result = hasher.Finalize();

		var expected = Wyhash64.Hash(MediumData);
		result.Should().Be(expected);
	}

	[Fact]
	public void StreamingHash_SingleByteChunks_MatchesOneShotHash() {
		var data = MediumData;

		var oneShotResult = Wyhash64.Hash(data);

		using var hasher = new Wyhash64();
		foreach (var b in data) {
			hasher.Update([b]);
		}
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void StreamingHash_VariousChunkSizes_MatchesOneShotHash() {
		var data = new byte[1000];
		Random.Shared.NextBytes(data);

		var oneShotResult = Wyhash64.Hash(data);

		// Test with various chunk sizes
		int[] chunkSizes = [1, 7, 13, 16, 17, 32, 47, 48, 49, 64, 100, 128, 256];

		foreach (var chunkSize in chunkSizes) {
			using var hasher = new Wyhash64();
			for (int i = 0; i < data.Length; i += chunkSize) {
				int len = Math.Min(chunkSize, data.Length - i);
				hasher.Update(data.AsSpan(i, len));
			}
			var streamingResult = hasher.Finalize();

			streamingResult.Should().Be(oneShotResult, $"chunk size {chunkSize}");
		}
	}

	[Fact]
	public void Hash_WithSeed_ProducesDifferentResult() {
		var data = SmallData;

		using var hasher1 = new Wyhash64(0);
		hasher1.Update(data);
		var result1 = hasher1.Finalize();

		using var hasher2 = new Wyhash64(12345);
		hasher2.Update(data);
		var result2 = hasher2.Finalize();

		result1.Should().NotBe(result2);
	}

	[Fact]
	public void Reset_AllowsReuseOfHasher() {
		var data1 = Encoding.UTF8.GetBytes("first");
		var data2 = Encoding.UTF8.GetBytes("second");

		using var hasher = new Wyhash64();

		hasher.Update(data1);
		var result1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		var result2 = hasher.Finalize();

		var expected1 = Wyhash64.Hash(data1);
		var expected2 = Wyhash64.Hash(data2);

		result1.Should().Be(expected1);
		result2.Should().Be(expected2);
		result1.Should().NotBe(result2);
	}

	[Fact]
	public void TotalBytesProcessed_TracksInputSize() {
		using var hasher = new Wyhash64();

		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(new byte[10]);
		hasher.TotalBytesProcessed.Should().Be(10);

		hasher.Update(new byte[20]);
		hasher.TotalBytesProcessed.Should().Be(30);
	}

	[Fact]
	public void FinalizeToBytes_ReturnsCorrectLength() {
		using var hasher = new Wyhash64();
		hasher.Update(SmallData);
		var result = hasher.FinalizeToBytes();
		result.Should().HaveCount(8);
	}

	[Fact]
	public void FinalizeToBytes_MatchesFinalize() {
		using var hasher = new Wyhash64();
		hasher.Update(MediumData);
		var hashValue = hasher.Finalize();

		hasher.Reset();
		hasher.Update(MediumData);
		var hashBytes = hasher.FinalizeToBytes();

		var reconstructed = BinaryPrimitives.ReadUInt64LittleEndian(hashBytes);
		reconstructed.Should().Be(hashValue);
	}

	[Fact]
	public void Update_AfterFinalize_ThrowsException() {
		using var hasher = new Wyhash64();
		hasher.Update([1, 2, 3]);
		hasher.Finalize();

		Action act = () => hasher.Update([4, 5, 6]);
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Finalize_CalledTwice_ThrowsException() {
		using var hasher = new Wyhash64();
		hasher.Update([1, 2, 3]);
		hasher.Finalize();

		Action act = () => hasher.Finalize();
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterDispose_ThrowsException() {
		var hasher = new Wyhash64();
		hasher.Dispose();

		Action act = () => hasher.Update([1, 2, 3]);
		act.Should().Throw<ObjectDisposedException>();
	}

	[Fact]
	public void BlockSize_Returns48() {
		using var hasher = new Wyhash64();
		hasher.BlockSize.Should().Be(48);
	}

	[Fact]
	public void DigestSize_Returns8() {
		using var hasher = new Wyhash64();
		hasher.DigestSize.Should().Be(8);
	}

	[Fact]
	public void HashToBytes_ReturnsCorrectLength() {
		var result = Wyhash64.HashToBytes([1, 2, 3, 4]);
		result.Should().HaveCount(8);
	}

	[Fact]
	public void Update_WithArrayOffset_HashesCorrectly() {
		var fullData = new byte[] { 0, 0, 1, 2, 3, 4, 5, 0, 0 };
		var subData = new byte[] { 1, 2, 3, 4, 5 };

		using var hasher = new Wyhash64();
		hasher.Update(fullData, 2, 5);
		var result = hasher.Finalize();

		var expected = Wyhash64.Hash(subData);
		result.Should().Be(expected);
	}

	[Theory]
	[InlineData(0)]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(3)]
	[InlineData(4)]
	[InlineData(8)]
	[InlineData(15)]
	[InlineData(16)]
	[InlineData(17)]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(47)]
	[InlineData(48)]
	[InlineData(49)]
	[InlineData(63)]
	[InlineData(64)]
	[InlineData(95)]
	[InlineData(96)]
	[InlineData(97)]
	[InlineData(100)]
	[InlineData(127)]
	[InlineData(128)]
	[InlineData(143)]
	[InlineData(144)]
	[InlineData(145)]
	[InlineData(200)]
	[InlineData(256)]
	[InlineData(500)]
	[InlineData(1000)]
	[InlineData(4096)]
	[InlineData(10000)]
	public void VariousLengths_StreamingMatchesOneShot(int length) {
		var data = new byte[length];
		if (length > 0) {
			Random.Shared.NextBytes(data);
		}

		// One-shot
		var oneShotResult = Wyhash64.Hash(data);

		// Streaming - single update
		using var hasher1 = new Wyhash64();
		hasher1.Update(data);
		var streaming1 = hasher1.Finalize();

		streaming1.Should().Be(oneShotResult, $"single update at length={length}");

		// Streaming - byte-by-byte
		using var hasher2 = new Wyhash64();
		foreach (var b in data) {
			hasher2.Update([b]);
		}
		var streaming2 = hasher2.Finalize();

		streaming2.Should().Be(oneShotResult, $"byte-by-byte at length={length}");
	}

	[Fact]
	public void LargeData_StreamingMatchesOneShot() {
		var data = new byte[100_000];
		Random.Shared.NextBytes(data);

		var oneShotResult = Wyhash64.Hash(data);

		using var hasher = new Wyhash64();
		int chunkSize = 4096;
		for (int i = 0; i < data.Length; i += chunkSize) {
			int len = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, len));
		}
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void ExactlyOneBlock_StreamingMatchesOneShot() {
		// Exactly 48 bytes (one block)
		var data = new byte[48];
		Random.Shared.NextBytes(data);

		var oneShotResult = Wyhash64.Hash(data);

		using var hasher = new Wyhash64();
		hasher.Update(data);
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void ExactlyTwoBlocks_StreamingMatchesOneShot() {
		// Exactly 96 bytes (two blocks)
		var data = new byte[96];
		Random.Shared.NextBytes(data);

		var oneShotResult = Wyhash64.Hash(data);

		using var hasher = new Wyhash64();
		hasher.Update(data);
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void MultipleSmallUpdates_MatchesOneShot() {
		var part1 = new byte[10];
		var part2 = new byte[15];
		var part3 = new byte[25];
		Random.Shared.NextBytes(part1);
		Random.Shared.NextBytes(part2);
		Random.Shared.NextBytes(part3);

		var combined = new byte[50];
		part1.CopyTo(combined, 0);
		part2.CopyTo(combined, 10);
		part3.CopyTo(combined, 25);

		var oneShotResult = Wyhash64.Hash(combined);

		using var hasher = new Wyhash64();
		hasher.Update(part1);
		hasher.Update(part2);
		hasher.Update(part3);
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void Constructor_WithInvalidSecret_ThrowsException() {
		Action act = () => new Wyhash64(0, [1ul, 2ul, 3ul]); // Only 3 elements
		act.Should().Throw<ArgumentException>();
	}

	[Fact]
	public void Constructor_WithNullSecret_ThrowsException() {
		Action act = () => new Wyhash64(0, null!);
		act.Should().Throw<ArgumentNullException>();
	}

	[Fact]
	public void Hash_DifferentDataProducesDifferentHashes() {
		var hash1 = Wyhash64.Hash(Encoding.UTF8.GetBytes("hello"));
		var hash2 = Wyhash64.Hash(Encoding.UTF8.GetBytes("world"));
		var hash3 = Wyhash64.Hash(Encoding.UTF8.GetBytes("hello!")); // One char difference

		hash1.Should().NotBe(hash2);
		hash1.Should().NotBe(hash3);
		hash2.Should().NotBe(hash3);
	}

	[Fact]
	public void Hash_SameDataProducesSameHash() {
		var data = Encoding.UTF8.GetBytes("test data");

		var hash1 = Wyhash64.Hash(data);
		var hash2 = Wyhash64.Hash(data);

		hash1.Should().Be(hash2);
	}

	[Theory]
	[InlineData(17)] // Just over 16, enters different code path
	[InlineData(32)] // 2x16 bytes
	[InlineData(33)] // 2x16 + 1
	[InlineData(47)] // Just under block size
	public void BoundaryLengths_StreamingMatchesOneShot(int length) {
		var data = new byte[length];
		Random.Shared.NextBytes(data);

		var oneShotResult = Wyhash64.Hash(data);

		// Try different split points
		for (int split = 1; split < length; split++) {
			using var hasher = new Wyhash64();
			hasher.Update(data.AsSpan(0, split));
			hasher.Update(data.AsSpan(split));
			var streamingResult = hasher.Finalize();

			streamingResult.Should().Be(oneShotResult, $"split at {split} for length {length}");
		}
	}
}
