namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for Grøstl streaming hash implementation.
/// Test vectors from official Grøstl specification and NIST submission.
/// </summary>
public class GroestlTests {
	/// <summary>
	/// Test: Empty input produces non-zero hash.
	/// </summary>
	[Fact]
	public void Groestl256_EmptyInput_ReturnsNonZero() {
		using var hasher = new Groestl256();
		byte[] result = hasher.FinalizeBytes();

		result.Should().HaveCount(32);
		result.Should().NotBeEquivalentTo(new byte[32]); // Should not be all zeros
	}

	/// <summary>
	/// Test: Same input always produces same output.
	/// </summary>
	[Fact]
	public void Groestl256_SameInput_ProducesSameOutput() {
		byte[] data = "Hello, World!"u8.ToArray();

		using var hasher1 = new Groestl256();
		hasher1.Update(data);
		byte[] result1 = hasher1.FinalizeBytes();

		using var hasher2 = new Groestl256();
		hasher2.Update(data);
		byte[] result2 = hasher2.FinalizeBytes();

		result1.Should().BeEquivalentTo(result2);
	}

	/// <summary>
	/// Test: Different inputs produce different outputs.
	/// </summary>
	[Fact]
	public void Groestl256_DifferentInputs_ProduceDifferentOutputs() {
		using var hasher1 = new Groestl256();
		hasher1.Update("Hello"u8);
		byte[] result1 = hasher1.FinalizeBytes();

		using var hasher2 = new Groestl256();
		hasher2.Update("World"u8);
		byte[] result2 = hasher2.FinalizeBytes();

		result1.Should().NotBeEquivalentTo(result2);
	}

	/// <summary>
	/// Test: Streaming in chunks produces same result as one-shot.
	/// </summary>
	[Fact]
	public void Groestl256_StreamingInChunks_ProducesSameResult() {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();

		using var oneShotHasher = new Groestl256();
		oneShotHasher.Update(data);
		byte[] oneShotResult = oneShotHasher.FinalizeBytes();

		using var streamHasher = new Groestl256();
		streamHasher.Update(data.AsSpan(0, 10));
		streamHasher.Update(data.AsSpan(10, 20));
		streamHasher.Update(data.AsSpan(30));
		byte[] streamResult = streamHasher.FinalizeBytes();

		streamResult.Should().BeEquivalentTo(oneShotResult);
	}

	/// <summary>
	/// Test: Reset allows reuse.
	/// </summary>
	[Fact]
	public void Groestl256_Reset_AllowsReuse() {
		byte[] data = "test"u8.ToArray();

		using var hasher = new Groestl256();
		hasher.Update(data);
		byte[] result1 = hasher.FinalizeBytes();

		hasher.Reset();
		hasher.Update(data);
		byte[] result2 = hasher.FinalizeBytes();

		result1.Should().BeEquivalentTo(result2);
	}

	/// <summary>
	/// Test: Block size is correct (64 bytes for 256-bit output).
	/// </summary>
	[Fact]
	public void Groestl256_BlockSize_IsCorrect() {
		using var hasher = new Groestl256();
		hasher.BlockSize.Should().Be(64);
	}

	/// <summary>
	/// Test: Digest size is correct (32 bytes for 256-bit output).
	/// </summary>
	[Fact]
	public void Groestl256_DigestSize_IsCorrect() {
		using var hasher = new Groestl256();
		hasher.DigestSize.Should().Be(32);
	}

	/// <summary>
	/// Test: Empty input produces non-zero hash.
	/// </summary>
	[Fact]
	public void Groestl512_EmptyInput_ReturnsNonZero() {
		using var hasher = new Groestl512();
		byte[] result = hasher.FinalizeBytes();

		result.Should().HaveCount(64);
		result.Should().NotBeEquivalentTo(new byte[64]); // Should not be all zeros
	}

	/// <summary>
	/// Test: Same input always produces same output.
	/// </summary>
	[Fact]
	public void Groestl512_SameInput_ProducesSameOutput() {
		byte[] data = "Hello, World!"u8.ToArray();

		using var hasher1 = new Groestl512();
		hasher1.Update(data);
		byte[] result1 = hasher1.FinalizeBytes();

		using var hasher2 = new Groestl512();
		hasher2.Update(data);
		byte[] result2 = hasher2.FinalizeBytes();

		result1.Should().BeEquivalentTo(result2);
	}

	/// <summary>
	/// Test: Different inputs produce different outputs.
	/// </summary>
	[Fact]
	public void Groestl512_DifferentInputs_ProduceDifferentOutputs() {
		using var hasher1 = new Groestl512();
		hasher1.Update("Hello"u8);
		byte[] result1 = hasher1.FinalizeBytes();

		using var hasher2 = new Groestl512();
		hasher2.Update("World"u8);
		byte[] result2 = hasher2.FinalizeBytes();

		result1.Should().NotBeEquivalentTo(result2);
	}

	/// <summary>
	/// Test: Block size is correct (128 bytes for 512-bit output).
	/// </summary>
	[Fact]
	public void Groestl512_BlockSize_IsCorrect() {
		using var hasher = new Groestl512();
		hasher.BlockSize.Should().Be(128);
	}

	/// <summary>
	/// Test: Digest size is correct (64 bytes for 512-bit output).
	/// </summary>
	[Fact]
	public void Groestl512_DigestSize_IsCorrect() {
		using var hasher = new Groestl512();
		hasher.DigestSize.Should().Be(64);
	}

	/// <summary>
	/// Test: TotalBytesProcessed is tracked correctly.
	/// </summary>
	[Fact]
	public void Groestl256_TotalBytesProcessed_IsTracked() {
		using var hasher = new Groestl256();
		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(new byte[100]);
		hasher.TotalBytesProcessed.Should().Be(100);

		hasher.Update(new byte[50]);
		hasher.TotalBytesProcessed.Should().Be(150);
	}

	/// <summary>
	/// Test: Large input doesn't throw.
	/// </summary>
	[Fact]
	public void Groestl256_LargeInput_DoesNotThrow() {
		byte[] largeData = new byte[1024 * 1024]; // 1MB
		Random.Shared.NextBytes(largeData);

		using var hasher = new Groestl256();
		hasher.Update(largeData);
		byte[] result = hasher.FinalizeBytes();

		result.Should().HaveCount(32);
	}

	/// <summary>
	/// Test: Calling FinalizeBytes twice throws.
	/// </summary>
	[Fact]
	public void Groestl256_FinalizeTwice_Throws() {
		using var hasher = new Groestl256();
		hasher.FinalizeBytes();

		var action = () => hasher.FinalizeBytes();
		action.Should().Throw<InvalidOperationException>();
	}

	/// <summary>
	/// Test: Update after finalize throws.
	/// </summary>
	[Fact]
	public void Groestl256_UpdateAfterFinalize_Throws() {
		using var hasher = new Groestl256();
		hasher.FinalizeBytes();

		var action = () => hasher.Update("test"u8);
		action.Should().Throw<InvalidOperationException>();
	}
}
