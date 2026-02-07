using StreamHash.Core;
using Xunit;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for native SM3 streaming implementation.
/// Test vectors from GB/T 32905-2016 and various online sources.
/// </summary>
public class Sm3Tests {
	// ========== Official Test Vectors (GB/T 32905-2016) ==========

	/// <summary>SM3 empty string test vector.</summary>
	[Fact]
	public void Sm3_Empty() {
		// SM3("") - Empty string hash
		var expected = Convert.FromHexString("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
		using var sm3 = Sm3Factory.CreateSm3();
		var hash = sm3.FinalizeBytes();
		Assert.Equal(expected, hash);
	}

	/// <summary>SM3 "abc" test vector (official).</summary>
	[Fact]
	public void Sm3_Abc() {
		// From GB/T 32905-2016 Example 1
		var expected = Convert.FromHexString("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
		var input = "abc"u8.ToArray();
		var hash = Sm3Factory.ComputeSm3(input);
		Assert.Equal(expected, hash);
	}

	/// <summary>SM3 repeated "abcd" test vector (official 64-byte message).</summary>
	[Fact]
	public void Sm3_AbcdRepeated() {
		// From GB/T 32905-2016 Example 2
		// Message: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" (64 bytes)
		var expected = Convert.FromHexString("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
		var input = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"u8.ToArray();
		var hash = Sm3Factory.ComputeSm3(input);
		Assert.Equal(expected, hash);
	}

	// ========== Additional Test Vectors ==========

	/// <summary>SM3 single character test.</summary>
	[Fact]
	public void Sm3_SingleChar() {
		// SM3("a")
		var expected = Convert.FromHexString("623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88");
		var input = "a"u8.ToArray();
		var hash = Sm3Factory.ComputeSm3(input);
		Assert.Equal(expected, hash);
	}

	/// <summary>SM3 message exactly one block (56 bytes before padding).</summary>
	[Fact]
	public void Sm3_NearBlockBoundary() {
		// 55 bytes: "0123456789" × 5 + "01234"
		var input = "01234567890123456789012345678901234567890123456789012345"u8.ToArray();
		Assert.Equal(56, input.Length);

		using var sm3 = Sm3Factory.CreateSm3();
		sm3.Update(input);
		var hash = sm3.FinalizeBytes();

		// Verify it's deterministic
		Assert.Equal(hash, Sm3Factory.ComputeSm3(input));
	}

	/// <summary>SM3 message requiring two padding blocks.</summary>
	[Fact]
	public void Sm3_TwoPaddingBlocks() {
		// 57 bytes - requires extra padding block
		var input = new byte[57];
		Array.Fill(input, (byte)'x');

		using var sm3 = Sm3Factory.CreateSm3();
		sm3.Update(input);
		var hash = sm3.FinalizeBytes();

		Assert.Equal(32, hash.Length);
		Assert.Equal(hash, Sm3Factory.ComputeSm3(input));
	}

	// ========== Streaming Tests ==========

	/// <summary>Test incremental update produces same result as one-shot.</summary>
	[Fact]
	public void Sm3_Streaming_MatchesOneShot() {
		var input = new byte[10000];
		Random.Shared.NextBytes(input);

		// One-shot
		var expected = Sm3Factory.ComputeSm3(input);

		// Streaming in various chunk sizes
		foreach (var chunkSize in new[] { 1, 7, 17, 63, 64, 65, 128, 1000 }) {
			using var sm3 = Sm3Factory.CreateSm3();
			for (int i = 0; i < input.Length; i += chunkSize) {
				int len = Math.Min(chunkSize, input.Length - i);
				sm3.Update(input.AsSpan(i, len));
			}
			var hash = sm3.FinalizeBytes();
			Assert.Equal(expected, hash);
		}
	}

	/// <summary>Test Reset() allows reuse.</summary>
	[Fact]
	public void Sm3_Reset_AllowsReuse() {
		using var sm3 = Sm3Factory.CreateSm3();

		// First computation
		sm3.Update("abc"u8);
		var hash1 = sm3.FinalizeBytes();

		// Reset and compute again
		sm3.Reset();
		sm3.Update("abc"u8);
		var hash2 = sm3.FinalizeBytes();

		Assert.Equal(hash1, hash2);
	}

	/// <summary>Test different inputs produce different outputs.</summary>
	[Fact]
	public void Sm3_DifferentInputs_DifferentOutputs() {
		var hash1 = Sm3Factory.ComputeSm3("abc"u8);
		var hash2 = Sm3Factory.ComputeSm3("abd"u8);
		Assert.NotEqual(hash1, hash2);
	}

	/// <summary>Test BlockSize and DigestSize properties.</summary>
	[Fact]
	public void Sm3_Properties_ReturnCorrectValues() {
		using var sm3 = Sm3Factory.CreateSm3();
		Assert.Equal(32, sm3.DigestSize);
		Assert.Equal(64, sm3.BlockSize);
	}

	/// <summary>Test TotalBytesProcessed is tracked correctly.</summary>
	[Fact]
	public void Sm3_TotalBytesProcessed_IsTracked() {
		using var sm3 = Sm3Factory.CreateSm3();
		Assert.Equal(0, sm3.TotalBytesProcessed);

		sm3.Update(new byte[100]);
		Assert.Equal(100, sm3.TotalBytesProcessed);

		sm3.Update(new byte[200]);
		Assert.Equal(300, sm3.TotalBytesProcessed);

		sm3.Reset();
		Assert.Equal(0, sm3.TotalBytesProcessed);
	}

	// ========== Edge Cases ==========

	/// <summary>Test exact block size boundary.</summary>
	[Fact]
	public void Sm3_ExactBlockSize() {
		var input = new byte[64]; // Exactly one block
		for (int i = 0; i < input.Length; i++) input[i] = (byte)(i & 0xff);

		using var sm3 = Sm3Factory.CreateSm3();
		sm3.Update(input);
		var hash = sm3.FinalizeBytes();

		Assert.Equal(32, hash.Length);
	}

	/// <summary>Test multiple exact blocks.</summary>
	[Fact]
	public void Sm3_MultipleExactBlocks() {
		var input = new byte[64 * 10]; // Exactly 10 blocks
		Random.Shared.NextBytes(input);

		var expected = Sm3Factory.ComputeSm3(input);

		// Also test streaming
		using var sm3 = Sm3Factory.CreateSm3();
		for (int i = 0; i < 10; i++) {
			sm3.Update(input.AsSpan(i * 64, 64));
		}
		var hash = sm3.FinalizeBytes();

		Assert.Equal(expected, hash);
	}

	/// <summary>Test large input (1 MB).</summary>
	[Fact]
	public void Sm3_LargeInput() {
		var input = new byte[1024 * 1024];
		Array.Fill(input, (byte)'a');

		using var sm3 = Sm3Factory.CreateSm3();
		sm3.Update(input);
		var hash = sm3.FinalizeBytes();

		Assert.Equal(32, hash.Length);
		// Verify it's deterministic
		Assert.Equal(hash, Sm3Factory.ComputeSm3(input));
	}

	// ========== Error Handling ==========

	/// <summary>Test finalize twice throws.</summary>
	[Fact]
	public void Sm3_FinalizeTwice_Throws() {
		using var sm3 = Sm3Factory.CreateSm3();
		sm3.FinalizeBytes();
		Assert.Throws<InvalidOperationException>(() => sm3.FinalizeBytes());
	}

	/// <summary>Test update after finalize throws.</summary>
	[Fact]
	public void Sm3_UpdateAfterFinalize_Throws() {
		using var sm3 = Sm3Factory.CreateSm3();
		sm3.FinalizeBytes();
		Assert.Throws<InvalidOperationException>(() => sm3.Update(new byte[1]));
	}

	/// <summary>Test disposed throws.</summary>
	[Fact]
	public void Sm3_DisposedOperations_Throw() {
		var sm3 = Sm3Factory.CreateSm3();
		sm3.Dispose();

		Assert.Throws<ObjectDisposedException>(() => sm3.Update(new byte[1]));
		Assert.Throws<ObjectDisposedException>(() => sm3.FinalizeBytes());
		Assert.Throws<ObjectDisposedException>(() => sm3.Reset());
	}

	// ========== Cross-Validation via HashFacade ==========

	/// <summary>Verify native implementation matches HashFacade for random inputs.</summary>
	[Fact]
	public void Sm3_MatchesHashFacade() {
		// Test with various input sizes
		foreach (var size in new[] { 0, 1, 32, 55, 56, 57, 63, 64, 65, 128, 1000 }) {
			var input = new byte[size];
			Random.Shared.NextBytes(input);

			// Direct factory
			var factoryHash = Sm3Factory.ComputeSm3(input);

			// Via HashFacade
			var facadeHash = HashFacade.ComputeHash(HashAlgorithm.Sm3, input);

			Assert.Equal(facadeHash, factoryHash);
		}
	}
}
