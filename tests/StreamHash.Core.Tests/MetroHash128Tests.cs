using System.Buffers.Binary;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for MetroHash128 streaming implementation.
/// </summary>
public class MetroHash128Tests {
	/// <summary>
	/// Test vector: Empty input with seed 0.
	/// </summary>
	[Fact]
	public void Hash_EmptyInput_Seed0_ReturnsNonZero() {
		UInt128 result = MetroHash128.Hash([], 0);
		// MetroHash of empty input should be non-zero (deterministic)
		result.Should().NotBe(UInt128.Zero);
	}

	/// <summary>
	/// Test vector: Same input produces same output.
	/// </summary>
	[Fact]
	public void Hash_SameInput_ProducesSameOutput() {
		byte[] data = "Hello, World!"u8.ToArray();

		UInt128 result1 = MetroHash128.Hash(data);
		UInt128 result2 = MetroHash128.Hash(data);

		result1.Should().Be(result2);
	}

	/// <summary>
	/// Test vector: Different inputs produce different outputs.
	/// </summary>
	[Fact]
	public void Hash_DifferentInputs_ProduceDifferentOutputs() {
		UInt128 result1 = MetroHash128.Hash("Hello"u8);
		UInt128 result2 = MetroHash128.Hash("World"u8);

		result1.Should().NotBe(result2);
	}

	/// <summary>
	/// Streaming should produce same result as one-shot.
	/// </summary>
	[Fact]
	public void Streaming_ProducesSameResultAsOneShot() {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		UInt128 oneShotResult = MetroHash128.Hash(data);

		using var hasher = new MetroHash128();
		hasher.Update(data);
		UInt128 streamResult = hasher.Finalize();

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
		UInt128 expected = MetroHash128.Hash(data);

		using var hasher = new MetroHash128();

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
	/// Different seeds produce different outputs.
	/// </summary>
	[Fact]
	public void Hash_DifferentSeeds_ProduceDifferentOutputs() {
		byte[] data = "Test"u8.ToArray();

		UInt128 result1 = MetroHash128.Hash(data, 0);
		UInt128 result2 = MetroHash128.Hash(data, 12345);

		result1.Should().NotBe(result2);
	}

	/// <summary>
	/// Same seed produces same output.
	/// </summary>
	[Fact]
	public void Hash_SameSeed_ProducesSameOutput() {
		byte[] data = "Test"u8.ToArray();

		UInt128 result1 = MetroHash128.Hash(data, 12345);
		UInt128 result2 = MetroHash128.Hash(data, 12345);

		result1.Should().Be(result2);
	}

	/// <summary>
	/// Reset should allow computing new hash.
	/// </summary>
	[Fact]
	public void Reset_AllowsNewHash() {
		byte[] data1 = "Hello"u8.ToArray();
		byte[] data2 = "World"u8.ToArray();

		using var hasher = new MetroHash128();

		hasher.Update(data1);
		UInt128 result1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		UInt128 result2 = hasher.Finalize();

		result1.Should().NotBe(result2);
		result2.Should().Be(MetroHash128.Hash(data2));
	}

	/// <summary>
	/// TotalBytesProcessed tracks correctly.
	/// </summary>
	[Fact]
	public void TotalBytesProcessed_TracksCorrectly() {
		byte[] data1 = new byte[100];
		byte[] data2 = new byte[200];

		using var hasher = new MetroHash128();

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
		using var hasher = new MetroHash128();
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
		using var hasher = new MetroHash128();
		hasher.Update("Test"u8);
		hasher.Finalize();

		Action act = () => hasher.Update("More"u8);
		act.Should().Throw<InvalidOperationException>();
	}

	/// <summary>
	/// DigestSize returns 16.
	/// </summary>
	[Fact]
	public void DigestSize_Returns16() {
		using var hasher = new MetroHash128();
		hasher.DigestSize.Should().Be(16);
	}

	/// <summary>
	/// BlockSize returns 32.
	/// </summary>
	[Fact]
	public void BlockSize_Returns32() {
		using var hasher = new MetroHash128();
		hasher.BlockSize.Should().Be(32);
	}

	/// <summary>
	/// Large data should work correctly.
	/// </summary>
	[Fact]
	public void Streaming_LargeData_Succeeds() {
		byte[] data = new byte[100_000];
		Random.Shared.NextBytes(data);

		UInt128 oneShotResult = MetroHash128.Hash(data);

		using var hasher = new MetroHash128();

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

		UInt128 streamResult = hasher.Finalize();
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

		UInt128 oneShotResult = MetroHash128.Hash(data);

		using var hasher = new MetroHash128();
		hasher.Update(data);
		UInt128 streamResult = hasher.Finalize();

		streamResult.Should().Be(oneShotResult);
	}

	/// <summary>
	/// HashToBytes returns correct bytes.
	/// </summary>
	[Fact]
	public void HashToBytes_ReturnsCorrectBytes() {
		byte[] data = "Test data"u8.ToArray();

		byte[] result = MetroHash128.HashToBytes(data);

		result.Should().HaveCount(16);
		// Should be little-endian encoded
		UInt128 hashValue = MetroHash128.Hash(data);
		byte[] expected = new byte[16];
		BinaryPrimitives.WriteUInt64LittleEndian(expected, (ulong)(hashValue & ulong.MaxValue));
		BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(8), (ulong)(hashValue >> 64));
		result.Should().BeEquivalentTo(expected);
	}
}
