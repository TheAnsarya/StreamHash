namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for SpookyHash V2 128-bit streaming implementation.
/// </summary>
public class SpookyHash128Tests {
	/// <summary>
	/// Empty input test.
	/// </summary>
	[Fact]
	public void Hash_EmptyInput_ReturnsConsistentValue() {
		UInt128 result1 = SpookyHash128.Hash([], 0, 0);
		UInt128 result2 = SpookyHash128.Hash([], 0, 0);

		result1.Should().Be(result2);
	}

	/// <summary>
	/// Streaming should produce same result as one-shot.
	/// </summary>
	[Fact]
	public void Streaming_ProducesSameResultAsOneShot() {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		UInt128 oneShotResult = SpookyHash128.Hash(data, 0, 0);

		using var hasher = new SpookyHash128(0, 0);
		hasher.Update(data);
		UInt128 streamResult = hasher.Finalize();

		streamResult.Should().Be(oneShotResult);
	}

	/// <summary>
	/// Streaming in various chunk sizes should produce same result.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(7)]
	[InlineData(8)]
	[InlineData(15)]
	[InlineData(16)]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(48)]
	[InlineData(96)]
	[InlineData(97)]
	public void Streaming_InChunks_ProducesSameResult(int chunkSize) {
		// Use a longer message to ensure we exercise the block processing
		byte[] data = new byte[1000];
		new Random(42).NextBytes(data);

		UInt128 expected = SpookyHash128.Hash(data, 0, 0);

		using var hasher = new SpookyHash128(0, 0);

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

		UInt128 hash00 = SpookyHash128.Hash(data, 0, 0);
		UInt128 hash10 = SpookyHash128.Hash(data, 1, 0);
		UInt128 hash01 = SpookyHash128.Hash(data, 0, 1);

		hash00.Should().NotBe(hash10);
		hash00.Should().NotBe(hash01);
		hash10.Should().NotBe(hash01);
	}

	/// <summary>
	/// Block size should be 96 bytes.
	/// </summary>
	[Fact]
	public void BlockSize_Is96() {
		using var hasher = new SpookyHash128();
		hasher.BlockSize.Should().Be(96);
	}

	/// <summary>
	/// Digest size should be 16 bytes.
	/// </summary>
	[Fact]
	public void DigestSize_Is16() {
		using var hasher = new SpookyHash128();
		hasher.DigestSize.Should().Be(16);
	}

	/// <summary>
	/// Reset should work correctly.
	/// </summary>
	[Fact]
	public void Reset_AllowsNewHash() {
		byte[] data1 = "First message"u8.ToArray();
		byte[] data2 = "Second message"u8.ToArray();

		using var hasher = new SpookyHash128(0, 0);

		hasher.Update(data1);
		UInt128 hash1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		UInt128 hash2 = hasher.Finalize();

		hash1.Should().Be(SpookyHash128.Hash(data1, 0, 0));
		hash2.Should().Be(SpookyHash128.Hash(data2, 0, 0));
	}

	/// <summary>
	/// Short messages (< 192 bytes) use different code path.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(10)]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(33)]
	[InlineData(64)]
	[InlineData(100)]
	[InlineData(191)]
	public void ShortMessage_StreamingMatchesOneShot(int length) {
		byte[] data = new byte[length];
		new Random(length).NextBytes(data);

		UInt128 oneShot = SpookyHash128.Hash(data, 42, 17);

		using var hasher = new SpookyHash128(42, 17);
		hasher.Update(data);
		UInt128 streamed = hasher.Finalize();

		streamed.Should().Be(oneShot);
	}

	/// <summary>
	/// Long messages (>= 192 bytes) use full mixing.
	/// </summary>
	[Theory]
	[InlineData(192)]
	[InlineData(193)]
	[InlineData(256)]
	[InlineData(500)]
	[InlineData(1000)]
	[InlineData(10000)]
	public void LongMessage_StreamingMatchesOneShot(int length) {
		byte[] data = new byte[length];
		new Random(length).NextBytes(data);

		UInt128 oneShot = SpookyHash128.Hash(data, 0xdeadbeef, 0xcafebabe);

		using var hasher = new SpookyHash128(0xdeadbeef, 0xcafebabe);
		hasher.Update(data);
		UInt128 streamed = hasher.Finalize();

		streamed.Should().Be(oneShot);
	}

	/// <summary>
	/// Verify consistency across multiple runs.
	/// </summary>
	[Fact]
	public void Hash_SameInput_AlwaysSameOutput() {
		byte[] data = "Consistency test data"u8.ToArray();

		var hashes = new UInt128[100];
		for (int i = 0; i < 100; i++) {
			hashes[i] = SpookyHash128.Hash(data, 0, 0);
		}

		hashes.Should().AllBeEquivalentTo(hashes[0]);
	}
}
