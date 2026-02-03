namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for MetroHash64 streaming implementation.
/// </summary>
public class MetroHash64Tests {
	/// <summary>
	/// Test vector: Empty input with seed 0.
	/// </summary>
	[Fact]
	public void Hash_EmptyInput_Seed0_ReturnsNonZero() {
		ulong result = MetroHash64.Hash([], 0);
		// MetroHash of empty input should be non-zero (deterministic)
		result.Should().NotBe(0UL);
	}

	/// <summary>
	/// Test vector: Same input produces same output.
	/// </summary>
	[Fact]
	public void Hash_SameInput_ProducesSameOutput() {
		byte[] data = "Hello, World!"u8.ToArray();

		ulong result1 = MetroHash64.Hash(data);
		ulong result2 = MetroHash64.Hash(data);

		result1.Should().Be(result2);
	}

	/// <summary>
	/// Test vector: Different inputs produce different outputs.
	/// </summary>
	[Fact]
	public void Hash_DifferentInputs_ProduceDifferentOutputs() {
		ulong result1 = MetroHash64.Hash("Hello"u8);
		ulong result2 = MetroHash64.Hash("World"u8);

		result1.Should().NotBe(result2);
	}

	/// <summary>
	/// Streaming should produce same result as one-shot.
	/// </summary>
	[Fact]
	public void Streaming_ProducesSameResultAsOneShot() {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		ulong oneShotResult = MetroHash64.Hash(data);

		using var hasher = new MetroHash64();
		hasher.Update(data);
		ulong streamResult = hasher.Finalize();

		streamResult.Should().Be(oneShotResult);
	}

	/// <summary>
	/// Streaming in chunks should produce same result.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(4)]
	[InlineData(7)]
	[InlineData(8)]
	[InlineData(16)]
	[InlineData(32)]
	[InlineData(64)]
	public void Streaming_InChunks_ProducesSameResult(int chunkSize) {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		ulong expected = MetroHash64.Hash(data);

		using var hasher = new MetroHash64();

		int offset = 0;
		while (offset < data.Length) {
			int count = Math.Min(chunkSize, data.Length - offset);
			hasher.Update(data.AsSpan(offset, count));
			offset += count;
		}

		ulong result = hasher.Finalize();
		result.Should().Be(expected);
	}

	/// <summary>
	/// Different seeds produce different outputs.
	/// </summary>
	[Fact]
	public void Hash_DifferentSeeds_ProduceDifferentOutputs() {
		byte[] data = "Test"u8.ToArray();

		ulong result1 = MetroHash64.Hash(data, 0);
		ulong result2 = MetroHash64.Hash(data, 12345);

		result1.Should().NotBe(result2);
	}

	/// <summary>
	/// Same seed produces same output.
	/// </summary>
	[Fact]
	public void Hash_SameSeed_ProducesSameOutput() {
		byte[] data = "Test"u8.ToArray();

		ulong result1 = MetroHash64.Hash(data, 12345);
		ulong result2 = MetroHash64.Hash(data, 12345);

		result1.Should().Be(result2);
	}

	/// <summary>
	/// Reset should allow computing new hash.
	/// </summary>
	[Fact]
	public void Reset_AllowsNewHash() {
		byte[] data1 = "Hello"u8.ToArray();
		byte[] data2 = "World"u8.ToArray();

		using var hasher = new MetroHash64();

		hasher.Update(data1);
		ulong result1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		ulong result2 = hasher.Finalize();

		result1.Should().NotBe(result2);
		result2.Should().Be(MetroHash64.Hash(data2));
	}

	/// <summary>
	/// TotalBytesProcessed tracks correctly.
	/// </summary>
	[Fact]
	public void TotalBytesProcessed_TracksCorrectly() {
		byte[] data1 = new byte[100];
		byte[] data2 = new byte[200];

		using var hasher = new MetroHash64();

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
		using var hasher = new MetroHash64();
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
		using var hasher = new MetroHash64();
		hasher.Update("Test"u8);
		hasher.Finalize();

		Action act = () => hasher.Update("More"u8);
		act.Should().Throw<InvalidOperationException>();
	}

	/// <summary>
	/// DigestSize returns 8.
	/// </summary>
	[Fact]
	public void DigestSize_Returns8() {
		using var hasher = new MetroHash64();
		hasher.DigestSize.Should().Be(8);
	}

	/// <summary>
	/// BlockSize returns 32.
	/// </summary>
	[Fact]
	public void BlockSize_Returns32() {
		using var hasher = new MetroHash64();
		hasher.BlockSize.Should().Be(32);
	}

	/// <summary>
	/// Large data should work correctly.
	/// </summary>
	[Fact]
	public void Streaming_LargeData_Succeeds() {
		byte[] data = new byte[100_000];
		Random.Shared.NextBytes(data);

		ulong oneShotResult = MetroHash64.Hash(data);

		using var hasher = new MetroHash64();

		// Stream in random-sized chunks
		int[] chunkSizes = [100, 500, 1000, 2000, 4000, 8000, 10000];
		int offset = 0;
		int chunkIndex = 0;

		while (offset < data.Length) {
			int count = Math.Min(chunkSizes[chunkIndex % chunkSizes.Length], data.Length - offset);
			hasher.Update(data.AsSpan(offset, count));
			offset += count;
			chunkIndex++;
		}

		ulong streamResult = hasher.Finalize();
		streamResult.Should().Be(oneShotResult);
	}

	/// <summary>
	/// Short inputs (less than block size) work correctly.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(4)]
	[InlineData(7)]
	[InlineData(8)]
	[InlineData(15)]
	[InlineData(16)]
	[InlineData(31)]
	public void Hash_ShortInputs_WorkCorrectly(int length) {
		byte[] data = new byte[length];
		Random.Shared.NextBytes(data);

		ulong oneShotResult = MetroHash64.Hash(data);

		using var hasher = new MetroHash64();
		hasher.Update(data);
		ulong streamResult = hasher.Finalize();

		streamResult.Should().Be(oneShotResult);
	}
}
