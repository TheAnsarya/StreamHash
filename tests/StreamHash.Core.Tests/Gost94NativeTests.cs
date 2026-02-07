using Org.BouncyCastle.Crypto.Digests;
using StreamHash.Core;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for the native GOST R 34.11-94 implementation.
/// </summary>
public class Gost94NativeTests {
	/// <summary>
	/// Verifies that the native implementation matches BouncyCastle for various test vectors.
	/// </summary>
	[Theory]
	[InlineData("")]
	[InlineData("a")]
	[InlineData("abc")]
	[InlineData("message digest")]
	[InlineData("The quick brown fox jumps over the lazy dog")]
	[InlineData("abcdefghijklmnopqrstuvwxyz")]
	[InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")]
	public void ComputeGost94_MatchesBouncyCastle(string input) {
		// Arrange
		var data = System.Text.Encoding.UTF8.GetBytes(input);

		// BouncyCastle reference
		var bcDigest = new Gost3411Digest();
		bcDigest.BlockUpdate(data, 0, data.Length);
		var bcResult = new byte[bcDigest.GetDigestSize()];
		bcDigest.DoFinal(bcResult, 0);

		// Act - Native implementation
		var nativeResult = Gost94Factory.ComputeGost94(data);

		// Assert
		nativeResult.Should().Equal(bcResult, $"Input: \"{input}\"");
	}

	/// <summary>
	/// Verifies that the streaming native implementation produces same result as one-shot.
	/// </summary>
	[Theory]
	[InlineData("")]
	[InlineData("a")]
	[InlineData("abc")]
	[InlineData("message digest")]
	[InlineData("The quick brown fox jumps over the lazy dog")]
	public void NativeGost94_Streaming_MatchesOneShot(string input) {
		// Arrange
		var data = System.Text.Encoding.UTF8.GetBytes(input);
		var oneShot = Gost94Factory.ComputeGost94(data);

		// Act - Streaming
		using var hasher = new NativeGost94();
		hasher.Update(data);
		var streaming = hasher.FinalizeBytes();

		// Assert
		streaming.Should().Equal(oneShot);
	}

	/// <summary>
	/// Verifies that the streaming implementation works with chunked data.
	/// </summary>
	[Fact]
	public void NativeGost94_ChunkedUpdate_ProducesSameResult() {
		// Arrange
		var data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
		var oneShot = Gost94Factory.ComputeGost94(data);

		// Act - Process in chunks
		using var hasher = new NativeGost94();
		hasher.Update(data.AsSpan(0, 10));
		hasher.Update(data.AsSpan(10, 15));
		hasher.Update(data.AsSpan(25, data.Length - 25));
		var chunked = hasher.FinalizeBytes();

		// Assert
		chunked.Should().Equal(oneShot);
	}

	/// <summary>
	/// Verifies Reset() works correctly.
	/// </summary>
	[Fact]
	public void NativeGost94_Reset_AllowsReuse() {
		// Arrange
		var data1 = "abc"u8.ToArray();
		var data2 = "xyz"u8.ToArray();

		using var hasher = new NativeGost94();
		hasher.Update(data1);
		hasher.Reset();
		hasher.Update(data2);
		var result = hasher.FinalizeBytes();

		var expected = Gost94Factory.ComputeGost94(data2);

		// Assert
		result.Should().Equal(expected);
	}

	/// <summary>
	/// Verifies that hash output length is 32 bytes.
	/// </summary>
	[Fact]
	public void NativeGost94_DigestSize_Is32Bytes() {
		using var hasher = new NativeGost94();
		hasher.DigestSize.Should().Be(32);
	}

	/// <summary>
	/// Verifies that block size is 32 bytes.
	/// </summary>
	[Fact]
	public void NativeGost94_BlockSize_Is32Bytes() {
		using var hasher = new NativeGost94();
		hasher.BlockSize.Should().Be(32);
	}

	/// <summary>
	/// Verifies TotalBytesProcessed tracks correctly.
	/// </summary>
	[Fact]
	public void NativeGost94_TotalBytesProcessed_TracksCorrectly() {
		using var hasher = new NativeGost94();
		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update("abc"u8);
		hasher.TotalBytesProcessed.Should().Be(3);

		hasher.Update("defgh"u8);
		hasher.TotalBytesProcessed.Should().Be(8);
	}

	/// <summary>
	/// Tests processing a larger amount of data spanning multiple blocks.
	/// </summary>
	[Fact]
	public void NativeGost94_LargeData_MatchesBouncyCastle() {
		// Arrange - 1KB of test data
		var data = new byte[1024];
		for (int i = 0; i < data.Length; i++) {
			data[i] = (byte)(i & 0xff);
		}

		// BouncyCastle reference
		var bcDigest = new Gost3411Digest();
		bcDigest.BlockUpdate(data, 0, data.Length);
		var bcResult = new byte[bcDigest.GetDigestSize()];
		bcDigest.DoFinal(bcResult, 0);

		// Act - Native
		var nativeResult = Gost94Factory.ComputeGost94(data);

		// Assert
		nativeResult.Should().Equal(bcResult);
	}

	/// <summary>
	/// Tests the static method version for minimal allocations.
	/// </summary>
	[Theory]
	[InlineData("")]
	[InlineData("a")]
	[InlineData("abc")]
	[InlineData("The quick brown fox jumps over the lazy dog")]
	public void ComputeGost94Static_MatchesStreamingVersion(string input) {
		// Arrange
		var data = System.Text.Encoding.UTF8.GetBytes(input);

		// Act
		var streaming = Gost94Factory.ComputeGost94(data);
		var staticResult = Gost94Factory.ComputeGost94Static(data);

		// Assert
		staticResult.Should().Equal(streaming);
	}
}
