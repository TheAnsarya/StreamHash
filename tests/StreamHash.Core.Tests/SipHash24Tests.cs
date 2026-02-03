namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for SipHash-2-4 streaming implementation.
/// Test vectors from the official SipHash paper.
/// </summary>
/// <remarks>
/// Reference: https://131002.net/siphash/siphash.pdf
/// </remarks>
public class SipHash24Tests {
	/// <summary>
	/// Official test vector from SipHash paper (Appendix A).
	/// Key: 00 01 02 ... 0f
	/// Message: 00 01 02 ... 0e (15 bytes)
	/// Expected: a129ca61 49be45e5
	/// </summary>
	[Fact]
	public void Hash_OfficialTestVector_ReturnsExpected() {
		byte[] key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
		byte[] message = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e];

		ulong result = SipHash24.Hash(message, key);

		// Expected from paper: a129ca6149be45e5 (little endian)
		result.Should().Be(0xa129ca6149be45e5);
	}

	/// <summary>
	/// Empty input test.
	/// </summary>
	[Fact]
	public void Hash_EmptyInput_ReturnsConsistentValue() {
		byte[] key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

		ulong result = SipHash24.Hash([], key);

		// Should be consistent (non-zero due to finalization)
		result.Should().NotBe(0UL);

		// Same key should always produce same result
		ulong result2 = SipHash24.Hash([], key);
		result2.Should().Be(result);
	}

	/// <summary>
	/// Key must be 16 bytes.
	/// </summary>
	[Fact]
	public void Constructor_WrongKeySize_ThrowsArgumentException() {
		byte[] shortKey = [0x00, 0x01, 0x02];
		byte[] longKey = new byte[32];

		Action shortAct = () => new SipHash24(shortKey);
		Action longAct = () => new SipHash24(longKey);

		shortAct.Should().Throw<ArgumentException>().WithMessage("*16 bytes*");
		longAct.Should().Throw<ArgumentException>().WithMessage("*16 bytes*");
	}

	/// <summary>
	/// Streaming should produce same result as one-shot.
	/// </summary>
	[Fact]
	public void Streaming_ProducesSameResultAsOneShot() {
		byte[] key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();

		ulong oneShotResult = SipHash24.Hash(data, key);

		using var hasher = new SipHash24(key);
		hasher.Update(data);
		ulong streamResult = hasher.Finalize();

		streamResult.Should().Be(oneShotResult);
	}

	/// <summary>
	/// Streaming in various chunk sizes should produce same result.
	/// </summary>
	[Theory]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(3)]
	[InlineData(7)]
	[InlineData(8)]
	[InlineData(9)]
	[InlineData(16)]
	public void Streaming_InChunks_ProducesSameResult(int chunkSize) {
		byte[] key = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
					  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
		byte[] data = "This is a test message for streaming SipHash"u8.ToArray();

		ulong expected = SipHash24.Hash(data, key);

		using var hasher = new SipHash24(key);

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
	/// Different keys should produce different results.
	/// </summary>
	[Fact]
	public void DifferentKeys_ProduceDifferentResults() {
		byte[] key1 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
		byte[] key2 = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
		byte[] data = "Same data, different keys"u8.ToArray();

		ulong hash1 = SipHash24.Hash(data, key1);
		ulong hash2 = SipHash24.Hash(data, key2);

		hash1.Should().NotBe(hash2);
	}

	/// <summary>
	/// Block size should be 8 bytes.
	/// </summary>
	[Fact]
	public void BlockSize_Is8() {
		using var hasher = new SipHash24();
		hasher.BlockSize.Should().Be(8);
	}

	/// <summary>
	/// Digest size should be 8 bytes.
	/// </summary>
	[Fact]
	public void DigestSize_Is8() {
		using var hasher = new SipHash24();
		hasher.DigestSize.Should().Be(8);
	}

	/// <summary>
	/// Reset should work correctly.
	/// </summary>
	[Fact]
	public void Reset_AllowsNewHash() {
		byte[] key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
		byte[] data1 = "First message"u8.ToArray();
		byte[] data2 = "Second message"u8.ToArray();

		using var hasher = new SipHash24(key);

		hasher.Update(data1);
		ulong hash1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		ulong hash2 = hasher.Finalize();

		hash1.Should().Be(SipHash24.Hash(data1, key));
		hash2.Should().Be(SipHash24.Hash(data2, key));
	}

	/// <summary>
	/// Various message lengths covering all tail cases (0-7 bytes).
	/// </summary>
	[Theory]
	[InlineData(0)]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(3)]
	[InlineData(4)]
	[InlineData(5)]
	[InlineData(6)]
	[InlineData(7)]
	[InlineData(8)]
	[InlineData(9)]
	[InlineData(15)]
	[InlineData(16)]
	[InlineData(17)]
	public void Hash_VariousLengths_StreamingMatchesOneShot(int length) {
		byte[] key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
		byte[] data = new byte[length];
		new Random(length).NextBytes(data);

		ulong oneShot = SipHash24.Hash(data, key);

		using var hasher = new SipHash24(key);
		hasher.Update(data);
		ulong streamed = hasher.Finalize();

		streamed.Should().Be(oneShot);
	}

	/// <summary>
	/// Alternative constructor with k0/k1 should work.
	/// </summary>
	[Fact]
	public void Constructor_WithK0K1_WorksCorrectly() {
		ulong k0 = 0x0706050403020100;
		ulong k1 = 0x0f0e0d0c0b0a0908;

		byte[] key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

		byte[] data = "Test data"u8.ToArray();

		ulong hashFromBytes = SipHash24.Hash(data, key);
		ulong hashFromUlongs = SipHash24.Hash(data, k0, k1);

		hashFromUlongs.Should().Be(hashFromBytes);
	}
}
