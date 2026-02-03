namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for MurmurHash3 128-bit streaming implementation.
/// </summary>
public class MurmurHash3_128Tests {
	/// <summary>
	/// Test vector: Empty input with seed 0.
	/// </summary>
	[Fact]
	public void Hash_EmptyInput_Seed0_ReturnsExpected() {
		UInt128 result = MurmurHash3_128.Hash([], 0);
		// Verified against reference implementation
		result.Should().Be(UInt128.Zero);
	}

	/// <summary>
	/// Streaming should produce same result as one-shot.
	/// </summary>
	[Fact]
	public void Streaming_ProducesSameResultAsOneShot() {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		UInt128 oneShotResult = MurmurHash3_128.Hash(data, 0);

		using var hasher = new MurmurHash3_128(0);
		hasher.Update(data);
		UInt128 streamResult = hasher.Finalize();

		streamResult.Should().Be(oneShotResult);
	}

	/// <summary>
	/// Streaming in various chunk sizes should produce same result.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(7)]
	[InlineData(8)]
	[InlineData(15)]
	[InlineData(16)]
	[InlineData(17)]
	[InlineData(32)]
	public void Streaming_InChunks_ProducesSameResult(int chunkSize) {
		byte[] data = "The quick brown fox jumps over the lazy dog and more text to make it longer"u8.ToArray();
		UInt128 expected = MurmurHash3_128.Hash(data, 0);

		using var hasher = new MurmurHash3_128(0);

		int offset = 0;
		while (offset < data.Length) {
			int count = Math.Min(chunkSize, data.Length - offset);
			hasher.Update(data.AsSpan(offset, count));
			offset += count;
		}

		UInt128 result = hasher.Finalize();
		result.Should().Be(expected);
	}

	/// <summary>
	/// Different seeds should produce different results.
	/// </summary>
	[Fact]
	public void DifferentSeeds_ProduceDifferentResults() {
		byte[] data = "Test data for hashing"u8.ToArray();

		UInt128 hash0 = MurmurHash3_128.Hash(data, 0);
		UInt128 hash1 = MurmurHash3_128.Hash(data, 1);
		UInt128 hash42 = MurmurHash3_128.Hash(data, 42);

		hash0.Should().NotBe(hash1);
		hash0.Should().NotBe(hash42);
		hash1.Should().NotBe(hash42);
	}

	/// <summary>
	/// Block size should be 16 bytes.
	/// </summary>
	[Fact]
	public void BlockSize_Is16() {
		using var hasher = new MurmurHash3_128();
		hasher.BlockSize.Should().Be(16);
	}

	/// <summary>
	/// Digest size should be 16 bytes.
	/// </summary>
	[Fact]
	public void DigestSize_Is16() {
		using var hasher = new MurmurHash3_128();
		hasher.DigestSize.Should().Be(16);
	}

	/// <summary>
	/// Large data should hash correctly with streaming.
	/// </summary>
	[Fact]
	public void Hash_LargeData_StreamingMatchesOneShot() {
		byte[] data = new byte[100_000];
		new Random(42).NextBytes(data);

		UInt128 oneShot = MurmurHash3_128.Hash(data, 0);

		using var hasher = new MurmurHash3_128(0);

		int chunkSize = 8192;
		for (int i = 0; i < data.Length; i += chunkSize) {
			int count = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, count));
		}

		UInt128 streamed = hasher.Finalize();
		streamed.Should().Be(oneShot);
	}

	/// <summary>
	/// Reset should work correctly.
	/// </summary>
	[Fact]
	public void Reset_AllowsNewHash() {
		byte[] data1 = "First message"u8.ToArray();
		byte[] data2 = "Second message"u8.ToArray();

		using var hasher = new MurmurHash3_128(0);

		hasher.Update(data1);
		UInt128 hash1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		UInt128 hash2 = hasher.Finalize();

		hash1.Should().Be(MurmurHash3_128.Hash(data1, 0));
		hash2.Should().Be(MurmurHash3_128.Hash(data2, 0));
	}

	/// <summary>
	/// Various tail lengths should be handled correctly.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(3)]
	[InlineData(4)]
	[InlineData(5)]
	[InlineData(6)]
	[InlineData(7)]
	[InlineData(8)]
	[InlineData(9)]
	[InlineData(10)]
	[InlineData(11)]
	[InlineData(12)]
	[InlineData(13)]
	[InlineData(14)]
	[InlineData(15)]
	public void Hash_VariousTailLengths_HandledCorrectly(int tailLength) {
		// Create data that has exactly tailLength bytes after last complete block
		byte[] data = new byte[16 + tailLength]; // One complete block + tail
		new Random(tailLength).NextBytes(data);

		UInt128 oneShot = MurmurHash3_128.Hash(data, 0);

		using var hasher = new MurmurHash3_128(0);
		hasher.Update(data);
		UInt128 streamed = hasher.Finalize();

		streamed.Should().Be(oneShot);
	}
}
