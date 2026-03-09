namespace StreamHash.Core.Tests;

/// <summary>
/// Edge case tests covering boundary conditions, unusual inputs,
/// and stress scenarios for hash algorithm implementations.
/// </summary>
public class EdgeCaseTests {
	#region Empty Input

	[Theory]
	[MemberData(nameof(AllAlgorithms))]
	public void EmptyInput_ProducesNonEmptyHash(HashAlgorithm algorithm) {
		byte[] empty = [];
		var result = HashFacade.ComputeHash(algorithm, empty);
		result.Should().NotBeNullOrEmpty($"{algorithm} should produce a hash for empty input");
	}

	[Theory]
	[MemberData(nameof(AllAlgorithms))]
	public void EmptyInput_ProducesCorrectDigestSize(HashAlgorithm algorithm) {
		byte[] empty = [];
		var info = HashFacade.GetInfo(algorithm);
		var result = HashFacade.ComputeHash(algorithm, empty);
		result.Should().HaveCount(info.DigestSize, $"{algorithm} empty hash should be {info.DigestSize} bytes");
	}

	#endregion

	#region Determinism

	[Theory]
	[MemberData(nameof(AllAlgorithms))]
	public void SameInput_ProducesSameOutput(HashAlgorithm algorithm) {
		byte[] data = "determinism test"u8.ToArray();
		var hash1 = HashFacade.ComputeHashHex(algorithm, data);
		var hash2 = HashFacade.ComputeHashHex(algorithm, data);
		hash2.Should().Be(hash1, $"{algorithm} must be deterministic");
	}

	[Theory]
	[MemberData(nameof(AllAlgorithms))]
	public void RepeatedCalls_AreDeterministic(HashAlgorithm algorithm) {
		byte[] data = "repeat test"u8.ToArray();
		var first = HashFacade.ComputeHashHex(algorithm, data);

		for (int i = 0; i < 50; i++) {
			HashFacade.ComputeHashHex(algorithm, data).Should().Be(first);
		}
	}

	#endregion

	#region Avalanche Effect

	[Theory]
	[MemberData(nameof(CryptoAlgorithms))]
	public void SingleBitFlip_ChangesCryptoHash(HashAlgorithm algorithm) {
		byte[] data1 = "avalanche test input data"u8.ToArray();
		byte[] data2 = (byte[])data1.Clone();
		data2[0] ^= 0x01; // flip one bit

		var hash1 = HashFacade.ComputeHashHex(algorithm, data1);
		var hash2 = HashFacade.ComputeHashHex(algorithm, data2);

		hash2.Should().NotBe(hash1, $"{algorithm} should change output on single bit flip");
	}

	#endregion

	#region Hex Output Format

	[Theory]
	[MemberData(nameof(AllAlgorithms))]
	public void HexOutput_IsLowercase(HashAlgorithm algorithm) {
		byte[] data = "hex format test"u8.ToArray();
		var hex = HashFacade.ComputeHashHex(algorithm, data);
		hex.Should().MatchRegex("^[0-9a-f]+$", $"{algorithm} hex must be lowercase");
	}

	#endregion

	#region Block Boundary Data Sizes

	[Theory]
	[InlineData(1)]
	[InlineData(15)]
	[InlineData(16)]
	[InlineData(17)]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(33)]
	[InlineData(63)]
	[InlineData(64)]
	[InlineData(65)]
	[InlineData(127)]
	[InlineData(128)]
	[InlineData(129)]
	[InlineData(255)]
	[InlineData(256)]
	[InlineData(512)]
	[InlineData(1024)]
	public void Sha256_VariousDataSizes_ProducesValidHash(int size) {
		var data = new byte[size];
		for (int i = 0; i < size; i++) data[i] = (byte)(i & 0xff);

		var hash = HashFacade.ComputeHash(HashAlgorithm.Sha256, data);
		hash.Should().HaveCount(32);
	}

	[Theory]
	[InlineData(1)]
	[InlineData(63)]
	[InlineData(64)]
	[InlineData(65)]
	[InlineData(135)]
	[InlineData(136)]
	[InlineData(137)]
	[InlineData(1024)]
	public void Sha3_256_VariousDataSizes_ProducesValidHash(int size) {
		var data = new byte[size];
		for (int i = 0; i < size; i++) data[i] = (byte)(i & 0xff);

		var hash = HashFacade.ComputeHash(HashAlgorithm.Sha3_256, data);
		hash.Should().HaveCount(32);
	}

	#endregion

	#region All Single Byte Values

	[Fact]
	public void Sha256_All256ByteValues_ProduceUniqueHashes() {
		var hashes = new HashSet<string>();
		for (int i = 0; i < 256; i++) {
			byte[] data = [(byte)i];
			hashes.Add(HashFacade.ComputeHashHex(HashAlgorithm.Sha256, data));
		}
		hashes.Should().HaveCount(256, "all single-byte SHA-256 hashes should be unique");
	}

	#endregion

	#region Streaming Edge Cases

	[Theory]
	[MemberData(nameof(AllAlgorithms))]
	public void Streaming_EmptyInput_MatchesOneShot(HashAlgorithm algorithm) {
		byte[] empty = [];
		var oneShotHex = HashFacade.ComputeHashHex(algorithm, empty);

		using var hasher = HashFacade.CreateStreaming(algorithm);
		// Don't call Update at all - just finalize
		var streamingHex = Convert.ToHexStringLower(hasher.FinalizeBytes());

		streamingHex.Should().Be(oneShotHex,
			$"{algorithm} streaming empty should match one-shot empty");
	}

	[Theory]
	[MemberData(nameof(AllAlgorithms))]
	public void Streaming_ZeroLengthUpdate_DoesNotAffectResult(HashAlgorithm algorithm) {
		byte[] data = "test"u8.ToArray();
		byte[] empty = [];

		var oneShotHex = HashFacade.ComputeHashHex(algorithm, data);

		using var hasher = HashFacade.CreateStreaming(algorithm);
		hasher.Update(ReadOnlySpan<byte>.Empty); // zero-length update before
		hasher.Update(data.AsSpan());
		hasher.Update(ReadOnlySpan<byte>.Empty); // zero-length update after
		var streamingHex = Convert.ToHexStringLower(hasher.FinalizeBytes());

		streamingHex.Should().Be(oneShotHex,
			$"{algorithm} zero-length Updates should not affect result");
	}

	#endregion

	#region Test Data Providers

	public static TheoryData<HashAlgorithm> AllAlgorithms() {
		var data = new TheoryData<HashAlgorithm>();
		foreach (var algo in Enum.GetValues<HashAlgorithm>()) {
			data.Add(algo);
		}
		return data;
	}

	public static TheoryData<HashAlgorithm> CryptoAlgorithms() => new() {
		HashAlgorithm.Md5,
		HashAlgorithm.Sha1,
		HashAlgorithm.Sha256,
		HashAlgorithm.Sha384,
		HashAlgorithm.Sha512,
		HashAlgorithm.Sha3_256,
		HashAlgorithm.Sha3_512,
		HashAlgorithm.Blake2b,
		HashAlgorithm.Blake2s,
		HashAlgorithm.Blake3,
		HashAlgorithm.Ripemd160,
		HashAlgorithm.Whirlpool,
		HashAlgorithm.Sm3,
		HashAlgorithm.Tiger192,
		HashAlgorithm.Keccak256,
		HashAlgorithm.Streebog256,
	};

	#endregion
}
