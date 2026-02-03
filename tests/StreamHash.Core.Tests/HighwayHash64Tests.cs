namespace StreamHash.Core.Tests;

/// <summary>
/// Unit tests for <see cref="HighwayHash64"/> streaming hash implementation.
/// </summary>
public class HighwayHash64Tests {
	/// <summary>
	/// Default test key for consistent test results.
	/// </summary>
	private static readonly ulong[] TestKey = [
		0x0706050403020100UL,
		0x0f0e0d0c0b0a0908UL,
		0x1716151413121110UL,
		0x1f1e1d1c1b1a1918UL
	];

	#region Basic Functionality

	[Fact]
	public void EmptyInput_ReturnsConsistentHash() {
		using var hasher = new HighwayHash64(TestKey);
		var hash = hasher.Finalize();

		hash.Should().Be(HighwayHash64.Hash([], TestKey));
	}

	[Fact]
	public void SingleByte_ReturnsConsistentHash() {
		using var hasher = new HighwayHash64(TestKey);
		hasher.Update([0x42]);
		var hash = hasher.Finalize();

		hash.Should().Be(HighwayHash64.Hash([0x42], TestKey));
	}

	[Fact]
	public void KnownInput_HelloWorld_ReturnsConsistentHash() {
		byte[] data = "Hello, World!"u8.ToArray();

		using var hasher = new HighwayHash64(TestKey);
		hasher.Update(data);
		var hash = hasher.Finalize();

		hash.Should().Be(HighwayHash64.Hash(data, TestKey));
	}

	[Fact]
	public void DefaultKey_CreatesWithoutError() {
		using var hasher = new HighwayHash64();
		hasher.Update("test"u8.ToArray());
		var hash = hasher.Finalize();

		// Should produce some hash value
		hash.Should().NotBe(0UL);
	}

	#endregion

	#region Streaming Consistency

	[Theory]
	[InlineData(1)]
	[InlineData(7)]
	[InlineData(16)]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(64)]
	[InlineData(100)]
	[InlineData(1000)]
	public void VariousLengths_OneShot_Matches_Streaming(int length) {
		byte[] data = new byte[length];
		Random.Shared.NextBytes(data);

		var oneShotHash = HighwayHash64.Hash(data, TestKey);

		using var hasher = new HighwayHash64(TestKey);
		hasher.Update(data);
		var streamingHash = hasher.Finalize();

		streamingHash.Should().Be(oneShotHash);
	}

	[Theory]
	[InlineData(1)]
	[InlineData(8)]
	[InlineData(16)]
	[InlineData(32)]
	[InlineData(64)]
	public void ChunkedProcessing_MatchesOneShot(int chunkSize) {
		byte[] data = new byte[500];
		Random.Shared.NextBytes(data);

		var oneShotHash = HighwayHash64.Hash(data, TestKey);

		using var hasher = new HighwayHash64(TestKey);
		for (int i = 0; i < data.Length; i += chunkSize) {
			int size = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, size));
		}
		var chunkedHash = hasher.Finalize();

		chunkedHash.Should().Be(oneShotHash);
	}

	[Fact]
	public void ByteByByte_MatchesOneShot() {
		byte[] data = "HighwayHash test"u8.ToArray();

		var oneShotHash = HighwayHash64.Hash(data, TestKey);

		using var hasher = new HighwayHash64(TestKey);
		foreach (byte b in data) {
			hasher.Update([b]);
		}
		var byteByByteHash = hasher.Finalize();

		byteByByteHash.Should().Be(oneShotHash);
	}

	#endregion

	#region Key Handling

	[Fact]
	public void DifferentKeys_ProduceDifferentHashes() {
		byte[] data = "Same data, different keys"u8.ToArray();

		ulong[] key1 = [1UL, 2UL, 3UL, 4UL];
		ulong[] key2 = [5UL, 6UL, 7UL, 8UL];

		var hash1 = HighwayHash64.Hash(data, key1);
		var hash2 = HighwayHash64.Hash(data, key2);

		hash1.Should().NotBe(hash2);
	}

	[Fact]
	public void ByteSpanKey_MatchesUlongArrayKey() {
		byte[] data = "Test data"u8.ToArray();

		// Create key as byte array (32 bytes = 256 bits)
		byte[] keyBytes = new byte[32];
		for (int i = 0; i < 32; i++) {
			keyBytes[i] = (byte)i;
		}

		// Same key as ulong array
		ulong[] keyUlongs = [
			0x0706050403020100UL,
			0x0f0e0d0c0b0a0908UL,
			0x1716151413121110UL,
			0x1f1e1d1c1b1a1918UL
		];

		using var hasher1 = new HighwayHash64(keyBytes);
		hasher1.Update(data);
		var hash1 = hasher1.Finalize();

		using var hasher2 = new HighwayHash64(keyUlongs);
		hasher2.Update(data);
		var hash2 = hasher2.Finalize();

		hash1.Should().Be(hash2);
	}

	[Fact]
	public void InvalidKeyLength_Throws() {
		ulong[] shortKey = [1UL, 2UL, 3UL];

		Action act = () => new HighwayHash64(shortKey);
		act.Should().Throw<ArgumentException>();
	}

	[Fact]
	public void InvalidByteKeyLength_Throws() {
		byte[] shortKey = new byte[16]; // Should be 32

		Action act = () => new HighwayHash64(shortKey);
		act.Should().Throw<ArgumentException>();
	}

	[Fact]
	public void NullKey_Throws() {
		Action act = () => new HighwayHash64((ulong[])null!);
		act.Should().Throw<ArgumentNullException>();
	}

	#endregion

	#region Properties

	[Fact]
	public void BlockSize_Is32() {
		using var hasher = new HighwayHash64(TestKey);
		hasher.BlockSize.Should().Be(32);
	}

	[Fact]
	public void DigestSize_Is8() {
		using var hasher = new HighwayHash64(TestKey);
		hasher.DigestSize.Should().Be(8);
	}

	[Fact]
	public void TotalBytesProcessed_TracksCorrectly() {
		using var hasher = new HighwayHash64(TestKey);

		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(new byte[100]);
		hasher.TotalBytesProcessed.Should().Be(100);

		hasher.Update(new byte[50]);
		hasher.TotalBytesProcessed.Should().Be(150);
	}

	#endregion

	#region Reset

	[Fact]
	public void Reset_AllowsReuse() {
		byte[] data1 = "First"u8.ToArray();
		byte[] data2 = "Second"u8.ToArray();

		using var hasher = new HighwayHash64(TestKey);

		hasher.Update(data1);
		var hash1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		var hash2 = hasher.Finalize();

		hash1.Should().Be(HighwayHash64.Hash(data1, TestKey));
		hash2.Should().Be(HighwayHash64.Hash(data2, TestKey));
		hash1.Should().NotBe(hash2);
	}

	[Fact]
	public void Reset_PreservesKey() {
		byte[] data = "Test"u8.ToArray();

		using var hasher = new HighwayHash64(TestKey);

		hasher.Update(data);
		var hash1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data);
		var hash2 = hasher.Finalize();

		// Same key should produce same hash for same data
		hash1.Should().Be(hash2);
	}

	#endregion

	#region Error Handling

	[Fact]
	public void Finalize_TwiceWithoutReset_Throws() {
		using var hasher = new HighwayHash64(TestKey);
		hasher.Finalize();

		Action act = () => hasher.Finalize();
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterFinalize_Throws() {
		using var hasher = new HighwayHash64(TestKey);
		hasher.Finalize();

		Action act = () => hasher.Update([0x00]);
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterDispose_Throws() {
		var hasher = new HighwayHash64(TestKey);
		hasher.Dispose();

		Action act = () => hasher.Update([0x00]);
		act.Should().Throw<ObjectDisposedException>();
	}

	#endregion

	#region Edge Cases

	[Fact]
	public void LargeInput_ProcessesCorrectly() {
		byte[] data = new byte[100_000];
		Random.Shared.NextBytes(data);

		using var hasher = new HighwayHash64(TestKey);
		hasher.Update(data);
		var hash = hasher.Finalize();

		hash.Should().Be(HighwayHash64.Hash(data, TestKey));
	}

	[Theory]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(33)]
	[InlineData(63)]
	[InlineData(64)]
	[InlineData(65)]
	public void BoundaryLengths_ProcessCorrectly(int length) {
		byte[] data = new byte[length];
		Random.Shared.NextBytes(data);

		var oneShotHash = HighwayHash64.Hash(data, TestKey);

		using var hasher = new HighwayHash64(TestKey);
		hasher.Update(data);
		var streamingHash = hasher.Finalize();

		streamingHash.Should().Be(oneShotHash);
	}

	#endregion
}
