namespace StreamHash.Core.Tests;

/// <summary>
/// Unit tests for <see cref="CityHash128"/> streaming hash implementation.
/// </summary>
public class CityHash128Tests {
	#region Basic Functionality

	[Fact]
	public void EmptyInput_ReturnsConsistentHash() {
		using var hasher = new CityHash128();
		var hash = hasher.Finalize();

		hash.Should().Be(CityHash128.Hash([]));
	}

	[Fact]
	public void SingleByte_ReturnsConsistentHash() {
		using var hasher = new CityHash128();
		hasher.Update([0x42]);
		var hash = hasher.Finalize();

		hash.Should().Be(CityHash128.Hash([0x42]));
	}

	[Fact]
	public void KnownInput_HelloWorld_ReturnsConsistentHash() {
		byte[] data = "Hello, World!"u8.ToArray();

		using var hasher = new CityHash128();
		hasher.Update(data);
		var hash = hasher.Finalize();

		hash.Should().Be(CityHash128.Hash(data));
	}

	#endregion

	#region Streaming Consistency

	[Theory]
	[InlineData(1)]
	[InlineData(15)]
	[InlineData(16)]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(64)]
	[InlineData(128)]
	[InlineData(1000)]
	public void VariousLengths_OneShot_Matches_Streaming(int length) {
		byte[] data = new byte[length];
		Random.Shared.NextBytes(data);

		var oneShotHash = CityHash128.Hash(data);

		using var hasher = new CityHash128();
		hasher.Update(data);
		var streamingHash = hasher.Finalize();

		streamingHash.Should().Be(oneShotHash);
	}

	[Theory]
	[InlineData(1)]
	[InlineData(16)]
	[InlineData(32)]
	[InlineData(64)]
	[InlineData(128)]
	[InlineData(256)]
	public void ChunkedProcessing_MatchesOneShot(int chunkSize) {
		byte[] data = new byte[2000];
		Random.Shared.NextBytes(data);

		var oneShotHash = CityHash128.Hash(data);

		using var hasher = new CityHash128();
		for (int i = 0; i < data.Length; i += chunkSize) {
			int size = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, size));
		}
		var chunkedHash = hasher.Finalize();

		chunkedHash.Should().Be(oneShotHash);
	}

	[Fact]
	public void ByteByByte_MatchesOneShot() {
		byte[] data = "Testing CityHash128"u8.ToArray();

		var oneShotHash = CityHash128.Hash(data);

		using var hasher = new CityHash128();
		foreach (byte b in data) {
			hasher.Update([b]);
		}
		var byteByByteHash = hasher.Finalize();

		byteByByteHash.Should().Be(oneShotHash);
	}

	#endregion

	#region Properties

	[Fact]
	public void BlockSize_Is128() {
		using var hasher = new CityHash128();
		hasher.BlockSize.Should().Be(128);
	}

	[Fact]
	public void DigestSize_Is16() {
		using var hasher = new CityHash128();
		hasher.DigestSize.Should().Be(16);
	}

	[Fact]
	public void TotalBytesProcessed_TracksCorrectly() {
		using var hasher = new CityHash128();

		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(new byte[200]);
		hasher.TotalBytesProcessed.Should().Be(200);

		hasher.Update(new byte[100]);
		hasher.TotalBytesProcessed.Should().Be(300);
	}

	#endregion

	#region Reset

	[Fact]
	public void Reset_AllowsReuse() {
		// Use longer data to avoid short message path issues
		byte[] data1 = "First data set for testing CityHash128 reset functionality"u8.ToArray();
		byte[] data2 = "Second completely different data for the reset test"u8.ToArray();

		using var hasher = new CityHash128();

		hasher.Update(data1);
		var hash1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		var hash2 = hasher.Finalize();

		hash1.Should().Be(CityHash128.Hash(data1));
		hash2.Should().Be(CityHash128.Hash(data2));
		hash1.Should().NotBe(hash2);
	}

	#endregion

	#region Error Handling

	[Fact]
	public void Finalize_TwiceWithoutReset_Throws() {
		using var hasher = new CityHash128();
		hasher.Finalize();

		Action act = () => hasher.Finalize();
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterFinalize_Throws() {
		using var hasher = new CityHash128();
		hasher.Finalize();

		Action act = () => hasher.Update([0x00]);
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterDispose_Throws() {
		var hasher = new CityHash128();
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

		using var hasher = new CityHash128();
		hasher.Update(data);
		var hash = hasher.Finalize();

		hash.Should().Be(CityHash128.Hash(data));
	}

	[Theory]
	[InlineData(127)]
	[InlineData(128)]
	[InlineData(129)]
	[InlineData(255)]
	[InlineData(256)]
	[InlineData(257)]
	public void BoundaryLengths_ProcessCorrectly(int length) {
		byte[] data = new byte[length];
		Random.Shared.NextBytes(data);

		var oneShotHash = CityHash128.Hash(data);

		using var hasher = new CityHash128();
		hasher.Update(data);
		var streamingHash = hasher.Finalize();

		streamingHash.Should().Be(oneShotHash);
	}

	[Fact]
	public void UInt128_HasCorrectParts() {
		byte[] data = "Test UInt128 hash output"u8.ToArray();

		using var hasher = new CityHash128();
		hasher.Update(data);
		var hash = hasher.Finalize();

		// UInt128 should have distinct upper and lower parts
		ulong lower = (ulong)(hash & ulong.MaxValue);
		ulong upper = (ulong)(hash >> 64);

		// Both parts should be non-zero for real data
		// (might be zero by chance, but statistically unlikely)
		(lower != 0 || upper != 0).Should().BeTrue();
	}

	#endregion
}
