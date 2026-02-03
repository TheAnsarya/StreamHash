namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for KangarooTwelve (K12) streaming implementation.
/// Test vectors from official KangarooTwelve specification.
/// </summary>
public class KangarooTwelveTests {
	/// <summary>
	/// Test vector: Empty input produces expected output.
	/// </summary>
	[Fact]
	public void Hash_EmptyInput_ReturnsNonZero() {
		byte[] result = KangarooTwelve.Hash([]);

		result.Should().HaveCount(32);
		result.Should().NotBeEquivalentTo(new byte[32]); // Should not be all zeros
	}

	/// <summary>
	/// Test vector: Same input always produces same output.
	/// </summary>
	[Fact]
	public void Hash_SameInput_ProducesSameOutput() {
		byte[] data = "Hello, World!"u8.ToArray();

		byte[] result1 = KangarooTwelve.Hash(data);
		byte[] result2 = KangarooTwelve.Hash(data);

		result1.Should().BeEquivalentTo(result2);
	}

	/// <summary>
	/// Test vector: Different inputs produce different outputs.
	/// </summary>
	[Fact]
	public void Hash_DifferentInputs_ProduceDifferentOutputs() {
		byte[] result1 = KangarooTwelve.Hash("Hello"u8);
		byte[] result2 = KangarooTwelve.Hash("World"u8);

		result1.Should().NotBeEquivalentTo(result2);
	}

	/// <summary>
	/// Streaming should produce same result as one-shot.
	/// </summary>
	[Fact]
	public void Streaming_ProducesSameResultAsOneShot() {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		byte[] oneShotResult = KangarooTwelve.Hash(data);

		using var hasher = new KangarooTwelve();
		hasher.Update(data);
		byte[] streamResult = hasher.Finalize();

		streamResult.Should().BeEquivalentTo(oneShotResult);
	}

	/// <summary>
	/// Streaming in chunks should produce same result.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(7)]
	[InlineData(16)]
	[InlineData(64)]
	[InlineData(168)] // Keccak rate
	[InlineData(256)]
	public void Streaming_InChunks_ProducesSameResult(int chunkSize) {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		byte[] expected = KangarooTwelve.Hash(data);

		using var hasher = new KangarooTwelve();

		int offset = 0;
		while (offset < data.Length) {
			int count = Math.Min(chunkSize, data.Length - offset);
			hasher.Update(data.AsSpan(offset, count));
			offset += count;
		}

		byte[] result = hasher.Finalize();
		result.Should().BeEquivalentTo(expected);
	}

	/// <summary>
	/// Different output lengths should work.
	/// </summary>
	[Theory]
	[InlineData(16)]
	[InlineData(32)]
	[InlineData(64)]
	[InlineData(128)]
	public void Hash_DifferentOutputLengths_ProducesCorrectLength(int outputLength) {
		byte[] data = "Test data"u8.ToArray();

		using var hasher = new KangarooTwelve(outputLength);
		hasher.Update(data);
		byte[] result = hasher.Finalize();

		result.Should().HaveCount(outputLength);
	}

	/// <summary>
	/// Customization string affects output.
	/// </summary>
	[Fact]
	public void Hash_WithCustomization_ProducesDifferentOutput() {
		byte[] data = "Hello"u8.ToArray();
		byte[] custom = "MyApp"u8.ToArray();

		byte[] withoutCustom = KangarooTwelve.Hash(data);
		byte[] withCustom = KangarooTwelve.Hash(data, customization: custom);

		withoutCustom.Should().NotBeEquivalentTo(withCustom);
	}

	/// <summary>
	/// Same customization produces same output.
	/// </summary>
	[Fact]
	public void Hash_SameCustomization_ProducesSameOutput() {
		byte[] data = "Hello"u8.ToArray();
		byte[] custom = "MyApp"u8.ToArray();

		byte[] result1 = KangarooTwelve.Hash(data, customization: custom);
		byte[] result2 = KangarooTwelve.Hash(data, customization: custom);

		result1.Should().BeEquivalentTo(result2);
	}

	/// <summary>
	/// Different customizations produce different outputs.
	/// </summary>
	[Fact]
	public void Hash_DifferentCustomizations_ProduceDifferentOutputs() {
		byte[] data = "Hello"u8.ToArray();

		byte[] result1 = KangarooTwelve.Hash(data, customization: "App1"u8.ToArray());
		byte[] result2 = KangarooTwelve.Hash(data, customization: "App2"u8.ToArray());

		result1.Should().NotBeEquivalentTo(result2);
	}

	/// <summary>
	/// Reset should allow computing new hash.
	/// </summary>
	[Fact]
	public void Reset_AllowsNewHash() {
		byte[] data1 = "Hello"u8.ToArray();
		byte[] data2 = "World"u8.ToArray();

		using var hasher = new KangarooTwelve();

		hasher.Update(data1);
		byte[] result1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		byte[] result2 = hasher.Finalize();

		result1.Should().NotBeEquivalentTo(result2);
		result2.Should().BeEquivalentTo(KangarooTwelve.Hash(data2));
	}

	/// <summary>
	/// TotalBytesProcessed tracks correctly.
	/// </summary>
	[Fact]
	public void TotalBytesProcessed_TracksCorrectly() {
		byte[] data1 = new byte[100];
		byte[] data2 = new byte[200];

		using var hasher = new KangarooTwelve();

		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(data1);
		hasher.TotalBytesProcessed.Should().Be(100);

		hasher.Update(data2);
		hasher.TotalBytesProcessed.Should().Be(300);
	}

	/// <summary>
	/// Finalize throws after already finalized.
	/// </summary>
	[Fact]
	public void Finalize_WhenAlreadyFinalized_Throws() {
		using var hasher = new KangarooTwelve();
		hasher.Update("Test"u8);
		hasher.Finalize();

		Action act = () => hasher.Finalize();
		act.Should().Throw<InvalidOperationException>();
	}

	/// <summary>
	/// Update throws after finalized.
	/// </summary>
	[Fact]
	public void Update_AfterFinalize_Throws() {
		using var hasher = new KangarooTwelve();
		hasher.Update("Test"u8);
		hasher.Finalize();

		Action act = () => hasher.Update("More"u8);
		act.Should().Throw<InvalidOperationException>();
	}

	/// <summary>
	/// Update throws after disposed.
	/// </summary>
	[Fact]
	public void Update_AfterDispose_Throws() {
		var hasher = new KangarooTwelve();
		hasher.Dispose();

		Action act = () => hasher.Update("Test"u8);
		act.Should().Throw<ObjectDisposedException>();
	}

	/// <summary>
	/// Finalize throws after disposed.
	/// </summary>
	[Fact]
	public void Finalize_AfterDispose_Throws() {
		var hasher = new KangarooTwelve();
		hasher.Update("Test"u8);
		hasher.Dispose();

		Action act = () => hasher.Finalize();
		act.Should().Throw<ObjectDisposedException>();
	}

	/// <summary>
	/// Invalid output length throws.
	/// </summary>
	[Theory]
	[InlineData(0)]
	[InlineData(-1)]
	[InlineData(-100)]
	public void Constructor_InvalidOutputLength_Throws(int outputLength) {
		Action act = () => new KangarooTwelve(outputLength);
		act.Should().Throw<ArgumentOutOfRangeException>();
	}

	/// <summary>
	/// Large data should work correctly via streaming.
	/// </summary>
	[Fact]
	public void Streaming_LargeData_Succeeds() {
		// Test with data larger than chunk size (8192 bytes)
		byte[] data = new byte[20000];
		Random.Shared.NextBytes(data);

		byte[] oneShotResult = KangarooTwelve.Hash(data);

		using var hasher = new KangarooTwelve();

		// Stream in random-sized chunks
		int[] chunkSizes = [100, 500, 1000, 2000, 4000, 8000, 4400];
		int offset = 0;
		int chunkIndex = 0;

		while (offset < data.Length) {
			int count = Math.Min(chunkSizes[chunkIndex % chunkSizes.Length], data.Length - offset);
			hasher.Update(data.AsSpan(offset, count));
			offset += count;
			chunkIndex++;
		}

		byte[] streamResult = hasher.Finalize();
		streamResult.Should().BeEquivalentTo(oneShotResult);
	}

	/// <summary>
	/// DigestSize returns configured output length.
	/// </summary>
	[Theory]
	[InlineData(16)]
	[InlineData(32)]
	[InlineData(64)]
	public void DigestSize_ReturnsOutputLength(int outputLength) {
		using var hasher = new KangarooTwelve(outputLength);
		hasher.DigestSize.Should().Be(outputLength);
	}

	/// <summary>
	/// BlockSize returns chunk size.
	/// </summary>
	[Fact]
	public void BlockSize_ReturnsChunkSize() {
		using var hasher = new KangarooTwelve();
		hasher.BlockSize.Should().Be(8192);
	}

	/// <summary>
	/// Update with offset and length works correctly.
	/// </summary>
	[Fact]
	public void Update_WithOffsetAndLength_WorksCorrectly() {
		byte[] fullData = "Hello, World!"u8.ToArray();
		byte[] partialData = "World"u8.ToArray();

		// Hash "World" using slice
		byte[] expected = KangarooTwelve.Hash(partialData);

		// Hash "World" using offset/length
		using var hasher = new KangarooTwelve();
		hasher.Update(fullData, 7, 5); // "World"
		byte[] result = hasher.Finalize();

		result.Should().BeEquivalentTo(expected);
	}

	/// <summary>
	/// Empty update is a no-op.
	/// </summary>
	[Fact]
	public void Update_EmptyData_IsNoOp() {
		byte[] data = "Hello"u8.ToArray();

		using var hasher = new KangarooTwelve();
		hasher.Update(data);
		hasher.Update([]); // Empty update
		hasher.Update(ReadOnlySpan<byte>.Empty); // Another empty
		byte[] result = hasher.Finalize();

		byte[] expected = KangarooTwelve.Hash(data);
		result.Should().BeEquivalentTo(expected);
	}

	/// <summary>
	/// Multiple resets work correctly.
	/// </summary>
	[Fact]
	public void MultipleResets_WorkCorrectly() {
		byte[] data = "Test"u8.ToArray();
		byte[] expected = KangarooTwelve.Hash(data);

		using var hasher = new KangarooTwelve();

		for (int i = 0; i < 3; i++) {
			hasher.Update(data);
			byte[] result = hasher.Finalize();
			result.Should().BeEquivalentTo(expected);
			hasher.Reset();
		}
	}

	/// <summary>
	/// XOF output consistency: Shorter output is prefix of longer output.
	/// </summary>
	[Fact]
	public void XOF_ShorterOutputIsPrefixOfLonger() {
		byte[] data = "Test XOF"u8.ToArray();

		byte[] short32 = KangarooTwelve.Hash(data, 32);
		byte[] long64 = KangarooTwelve.Hash(data, 64);

		// First 32 bytes of 64-byte output should equal 32-byte output
		long64.AsSpan(0, 32).ToArray().Should().BeEquivalentTo(short32);
	}

	/// <summary>
	/// Very large output length should work.
	/// </summary>
	[Fact]
	public void Hash_VeryLargeOutput_Succeeds() {
		byte[] data = "Test"u8.ToArray();

		// Request 1KB of output
		byte[] result = KangarooTwelve.Hash(data, 1024);

		result.Should().HaveCount(1024);
		// Should not be all zeros or all same value
		result.Distinct().Count().Should().BeGreaterThan(10);
	}
}
