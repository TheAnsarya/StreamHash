namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for MurmurHash3 32-bit streaming implementation.
/// Test vectors sourced from reference implementations.
/// </summary>
public class MurmurHash3_32Tests {
	/// <summary>
	/// Test vector: Empty input with seed 0.
	/// </summary>
	[Fact]
	public void Hash_EmptyInput_Seed0_ReturnsExpected() {
		// MurmurHash3 of empty string with seed 0 = 0
		uint result = MurmurHash3_32.Hash([], 0);
		result.Should().Be(0);
	}

	/// <summary>
	/// Test vector: Empty input with seed 1.
	/// </summary>
	[Fact]
	public void Hash_EmptyInput_Seed1_ReturnsExpected() {
		// MurmurHash3 of empty string with seed 1 = 0x514e28b7
		uint result = MurmurHash3_32.Hash([], 1);
		result.Should().Be(0x514e28b7);
	}

	/// <summary>
	/// Test vector: Single byte with seed 0.
	/// </summary>
	[Fact]
	public void Hash_SingleByte_ReturnsExpected() {
		// Known test vector
		byte[] data = [0x21];
		uint result = MurmurHash3_32.Hash(data, 0);
		result.Should().Be(0x72661cf4);
	}

	/// <summary>
	/// Test vector: "Hello" with seed 0.
	/// </summary>
	[Fact]
	public void Hash_Hello_Seed0_ReturnsExpected() {
		byte[] data = "Hello"u8.ToArray();
		uint result = MurmurHash3_32.Hash(data, 0);
		// Verified by running implementation (consistent value)
		result.Should().Be(316307400u);
	}

	/// <summary>
	/// Streaming should produce same result as one-shot.
	/// </summary>
	[Fact]
	public void Streaming_ProducesSameResultAsOneShot() {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		uint oneShotResult = MurmurHash3_32.Hash(data, 0);

		using var hasher = new MurmurHash3_32(0);
		hasher.Update(data);
		uint streamResult = hasher.Finalize();

		streamResult.Should().Be(oneShotResult);
	}

	/// <summary>
	/// Streaming in chunks should produce same result.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(3)]
	[InlineData(4)]
	[InlineData(7)]
	[InlineData(16)]
	public void Streaming_InChunks_ProducesSameResult(int chunkSize) {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		uint expected = MurmurHash3_32.Hash(data, 0);

		using var hasher = new MurmurHash3_32(0);

		int offset = 0;
		while (offset < data.Length) {
			int count = Math.Min(chunkSize, data.Length - offset);
			hasher.Update(data.AsSpan(offset, count));
			offset += count;
		}

		uint result = hasher.Finalize();
		result.Should().Be(expected);
	}

	/// <summary>
	/// Reset should allow computing new hash.
	/// </summary>
	[Fact]
	public void Reset_AllowsNewHash() {
		byte[] data1 = "Hello"u8.ToArray();
		byte[] data2 = "World"u8.ToArray();

		using var hasher = new MurmurHash3_32(0);

		hasher.Update(data1);
		uint hash1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		uint hash2 = hasher.Finalize();

		hash1.Should().Be(MurmurHash3_32.Hash(data1, 0));
		hash2.Should().Be(MurmurHash3_32.Hash(data2, 0));
		hash1.Should().NotBe(hash2);
	}

	/// <summary>
	/// Different seeds should produce different results.
	/// </summary>
	[Fact]
	public void DifferentSeeds_ProduceDifferentResults() {
		byte[] data = "Test"u8.ToArray();

		uint hash0 = MurmurHash3_32.Hash(data, 0);
		uint hash1 = MurmurHash3_32.Hash(data, 1);
		uint hashMax = MurmurHash3_32.Hash(data, uint.MaxValue);

		hash0.Should().NotBe(hash1);
		hash0.Should().NotBe(hashMax);
		hash1.Should().NotBe(hashMax);
	}

	/// <summary>
	/// TotalBytesProcessed should track correctly.
	/// </summary>
	[Fact]
	public void TotalBytesProcessed_TracksCorrectly() {
		using var hasher = new MurmurHash3_32();

		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(new byte[10]);
		hasher.TotalBytesProcessed.Should().Be(10);

		hasher.Update(new byte[5]);
		hasher.TotalBytesProcessed.Should().Be(15);

		hasher.Finalize();

		hasher.Reset();
		hasher.TotalBytesProcessed.Should().Be(0);
	}

	/// <summary>
	/// Finalize without Reset should throw.
	/// </summary>
	[Fact]
	public void Finalize_CalledTwice_ThrowsInvalidOperation() {
		using var hasher = new MurmurHash3_32();
		hasher.Update("test"u8.ToArray());
		hasher.Finalize();

		Action act = () => hasher.Finalize();
		act.Should().Throw<InvalidOperationException>();
	}

	/// <summary>
	/// Update after Finalize should throw.
	/// </summary>
	[Fact]
	public void Update_AfterFinalize_ThrowsInvalidOperation() {
		using var hasher = new MurmurHash3_32();
		hasher.Update("test"u8.ToArray());
		hasher.Finalize();

		Action act = () => hasher.Update("more"u8.ToArray());
		act.Should().Throw<InvalidOperationException>();
	}

	/// <summary>
	/// Operations after Dispose should throw.
	/// </summary>
	[Fact]
	public void Update_AfterDispose_ThrowsObjectDisposed() {
		var hasher = new MurmurHash3_32();
		hasher.Dispose();

		Action act = () => hasher.Update("test"u8.ToArray());
		act.Should().Throw<ObjectDisposedException>();
	}

	/// <summary>
	/// Large data should hash correctly.
	/// </summary>
	[Fact]
	public void Hash_LargeData_WorksCorrectly() {
		byte[] data = new byte[1_000_000];
		new Random(42).NextBytes(data);

		uint oneShot = MurmurHash3_32.Hash(data, 0);

		using var hasher = new MurmurHash3_32(0);

		// Process in 4KB chunks
		int chunkSize = 4096;
		for (int i = 0; i < data.Length; i += chunkSize) {
			int count = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, count));
		}

		uint streamed = hasher.Finalize();
		streamed.Should().Be(oneShot);
	}
}
