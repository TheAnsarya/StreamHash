namespace StreamHash.Core.Tests;

/// <summary>
/// Unit tests for <see cref="CityHash64"/> streaming hash implementation.
/// </summary>
public class CityHash64Tests {
	#region Basic Functionality

	[Fact]
	public void EmptyInput_ReturnsConsistentHash() {
		using var hasher = new CityHash64();
		var hash = hasher.Finalize();

		// Should return consistent value for empty input
		hash.Should().Be(CityHash64.Hash([]));
	}

	[Fact]
	public void SingleByte_ReturnsConsistentHash() {
		using var hasher = new CityHash64();
		hasher.Update([0x42]);
		var hash = hasher.Finalize();

		hash.Should().Be(CityHash64.Hash([0x42]));
	}

	[Fact]
	public void KnownInput_HelloWorld_ReturnsConsistentHash() {
		byte[] data = "Hello, World!"u8.ToArray();

		using var hasher = new CityHash64();
		hasher.Update(data);
		var hash = hasher.Finalize();

		// Verify consistency
		hash.Should().Be(CityHash64.Hash(data));
	}

	#endregion

	#region Streaming Consistency

	[Theory]
	[InlineData(1)]
	[InlineData(7)]
	[InlineData(13)]
	[InlineData(32)]
	[InlineData(64)]
	[InlineData(100)]
	[InlineData(1000)]
	public void VariousLengths_OneShot_Matches_Streaming(int length) {
		byte[] data = new byte[length];
		Random.Shared.NextBytes(data);

		// One-shot
		var oneShotHash = CityHash64.Hash(data);

		// Streaming
		using var hasher = new CityHash64();
		hasher.Update(data);
		var streamingHash = hasher.Finalize();

		streamingHash.Should().Be(oneShotHash);
	}

	[Theory]
	[InlineData(1)]
	[InlineData(7)]
	[InlineData(16)]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(64)]
	[InlineData(128)]
	public void ChunkedProcessing_MatchesOneShot(int chunkSize) {
		byte[] data = new byte[1000];
		Random.Shared.NextBytes(data);

		// One-shot
		var oneShotHash = CityHash64.Hash(data);

		// Chunked
		using var hasher = new CityHash64();
		for (int i = 0; i < data.Length; i += chunkSize) {
			int size = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, size));
		}
		var chunkedHash = hasher.Finalize();

		chunkedHash.Should().Be(oneShotHash);
	}

	[Fact]
	public void ByteByByte_MatchesOneShot() {
		byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();

		var oneShotHash = CityHash64.Hash(data);

		using var hasher = new CityHash64();
		foreach (byte b in data) {
			hasher.Update([b]);
		}
		var byteByByteHash = hasher.Finalize();

		byteByByteHash.Should().Be(oneShotHash);
	}

	#endregion

	#region Properties

	[Fact]
	public void BlockSize_Is64() {
		using var hasher = new CityHash64();
		hasher.BlockSize.Should().Be(64);
	}

	[Fact]
	public void DigestSize_Is8() {
		using var hasher = new CityHash64();
		hasher.DigestSize.Should().Be(8);
	}

	[Fact]
	public void TotalBytesProcessed_TracksCorrectly() {
		using var hasher = new CityHash64();

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

		using var hasher = new CityHash64();

		hasher.Update(data1);
		var hash1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		var hash2 = hasher.Finalize();

		hash1.Should().Be(CityHash64.Hash(data1));
		hash2.Should().Be(CityHash64.Hash(data2));
		hash1.Should().NotBe(hash2);
	}

	[Fact]
	public void Reset_AfterPartialUpdate_WorksCorrectly() {
		using var hasher = new CityHash64();

		hasher.Update(new byte[100]);
		hasher.Reset();

		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update("test"u8.ToArray());
		var hash = hasher.Finalize();

		hash.Should().Be(CityHash64.Hash("test"u8.ToArray()));
	}

	#endregion

	#region Error Handling

	[Fact]
	public void Finalize_TwiceWithoutReset_Throws() {
		using var hasher = new CityHash64();
		hasher.Finalize();

		Action act = () => hasher.Finalize();
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterFinalize_Throws() {
		using var hasher = new CityHash64();
		hasher.Finalize();

		Action act = () => hasher.Update([0x00]);
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterDispose_Throws() {
		var hasher = new CityHash64();
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

		using var hasher = new CityHash64();
		hasher.Update(data);
		var hash = hasher.Finalize();

		hash.Should().Be(CityHash64.Hash(data));
	}

	[Theory]
	[InlineData(63)]
	[InlineData(64)]
	[InlineData(65)]
	[InlineData(127)]
	[InlineData(128)]
	[InlineData(129)]
	public void BoundaryLengths_ProcessCorrectly(int length) {
		byte[] data = new byte[length];
		Random.Shared.NextBytes(data);

		var oneShotHash = CityHash64.Hash(data);

		using var hasher = new CityHash64();
		hasher.Update(data);
		var streamingHash = hasher.Finalize();

		streamingHash.Should().Be(oneShotHash);
	}

	#endregion
}
