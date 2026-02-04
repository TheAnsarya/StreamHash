using FluentAssertions;
using StreamHash.Core;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for <see cref="HashFacade"/> unified hash API.
/// </summary>
public class HashFacadeTests {
	#region One-Shot Hashing Tests

	[Theory]
	[InlineData(HashAlgorithm.Crc32, 4)]
	[InlineData(HashAlgorithm.Crc32C, 4)]
	[InlineData(HashAlgorithm.Crc64, 8)]
	[InlineData(HashAlgorithm.Adler32, 4)]
	[InlineData(HashAlgorithm.Fletcher16, 2)]
	[InlineData(HashAlgorithm.Fletcher32, 4)]
	[InlineData(HashAlgorithm.XxHash32, 4)]
	[InlineData(HashAlgorithm.XxHash64, 8)]
	[InlineData(HashAlgorithm.XxHash3, 8)]
	[InlineData(HashAlgorithm.XxHash128, 16)]
	[InlineData(HashAlgorithm.MurmurHash3_32, 4)]
	[InlineData(HashAlgorithm.MurmurHash3_128, 16)]
	[InlineData(HashAlgorithm.CityHash64, 8)]
	[InlineData(HashAlgorithm.CityHash128, 16)]
	[InlineData(HashAlgorithm.FarmHash64, 8)]
	[InlineData(HashAlgorithm.SpookyHash128, 16)]
	[InlineData(HashAlgorithm.SipHash24, 8)]
	[InlineData(HashAlgorithm.HighwayHash64, 8)]
	[InlineData(HashAlgorithm.MetroHash64, 8)]
	[InlineData(HashAlgorithm.MetroHash128, 16)]
	[InlineData(HashAlgorithm.Wyhash64, 8)]
	[InlineData(HashAlgorithm.Md5, 16)]
	[InlineData(HashAlgorithm.Sha1, 20)]
	[InlineData(HashAlgorithm.Sha256, 32)]
	[InlineData(HashAlgorithm.Sha384, 48)]
	[InlineData(HashAlgorithm.Sha512, 64)]
	public void ComputeHash_ReturnsCorrectDigestSize(HashAlgorithm algorithm, int expectedSize) {
		// Arrange
		byte[] data = "Hello, World!"u8.ToArray();

		// Act
		byte[] hash = HashFacade.ComputeHash(algorithm, data);

		// Assert
		hash.Should().HaveCount(expectedSize, $"because {algorithm} should produce {expectedSize} bytes");
	}

	[Theory]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.MurmurHash3_128)]
	[InlineData(HashAlgorithm.CityHash64)]
	[InlineData(HashAlgorithm.Sha256)]
	public void ComputeHash_SameInputProducesSameHash(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = "Test data for deterministic hashing"u8.ToArray();

		// Act
		byte[] hash1 = HashFacade.ComputeHash(algorithm, data);
		byte[] hash2 = HashFacade.ComputeHash(algorithm, data);

		// Assert
		hash1.Should().BeEquivalentTo(hash2, $"because {algorithm} should be deterministic");
	}

	[Theory]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.MurmurHash3_32)]
	[InlineData(HashAlgorithm.Sha256)]
	public void ComputeHash_DifferentInputProducesDifferentHash(HashAlgorithm algorithm) {
		// Arrange
		byte[] data1 = "Hello"u8.ToArray();
		byte[] data2 = "World"u8.ToArray();

		// Act
		byte[] hash1 = HashFacade.ComputeHash(algorithm, data1);
		byte[] hash2 = HashFacade.ComputeHash(algorithm, data2);

		// Assert
		hash1.Should().NotBeEquivalentTo(hash2, $"because {algorithm} should differentiate inputs");
	}

	[Theory]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.Sha256)]
	public void ComputeHash_EmptyInput_ReturnsValidHash(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = [];

		// Act
		byte[] hash = HashFacade.ComputeHash(algorithm, data);

		// Assert
		hash.Should().NotBeNull();
		hash.Should().NotBeEmpty();
	}

	#endregion

	#region Hex String Tests

	[Theory]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.Sha256)]
	public void ComputeHashHex_ReturnsLowercaseHex(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = "Test"u8.ToArray();

		// Act
		string hex = HashFacade.ComputeHashHex(algorithm, data);

		// Assert
		hex.Should().MatchRegex(@"^[0-9a-f]+$", "because hex output should be lowercase");
	}

	[Theory]
	[InlineData(HashAlgorithm.Crc32, 8)]   // 4 bytes * 2
	[InlineData(HashAlgorithm.XxHash64, 16)] // 8 bytes * 2
	[InlineData(HashAlgorithm.Sha256, 64)]  // 32 bytes * 2
	public void ComputeHashHex_ReturnsCorrectLength(HashAlgorithm algorithm, int expectedLength) {
		// Arrange
		byte[] data = "Test"u8.ToArray();

		// Act
		string hex = HashFacade.ComputeHashHex(algorithm, data);

		// Assert
		hex.Should().HaveLength(expectedLength);
	}

	#endregion

	#region Streaming Hash Tests

	[Theory]
	[InlineData(HashAlgorithm.Crc32)]
	[InlineData(HashAlgorithm.Crc64)]
	[InlineData(HashAlgorithm.XxHash32)]
	[InlineData(HashAlgorithm.XxHash64)]
	[InlineData(HashAlgorithm.XxHash3)]
	[InlineData(HashAlgorithm.XxHash128)]
	[InlineData(HashAlgorithm.MurmurHash3_32)]
	[InlineData(HashAlgorithm.MurmurHash3_128)]
	[InlineData(HashAlgorithm.CityHash64)]
	[InlineData(HashAlgorithm.CityHash128)]
	[InlineData(HashAlgorithm.FarmHash64)]
	[InlineData(HashAlgorithm.SpookyHash128)]
	[InlineData(HashAlgorithm.SipHash24)]
	[InlineData(HashAlgorithm.HighwayHash64)]
	[InlineData(HashAlgorithm.MetroHash64)]
	[InlineData(HashAlgorithm.MetroHash128)]
	[InlineData(HashAlgorithm.Wyhash64)]
	[InlineData(HashAlgorithm.KangarooTwelve)]
	public void CreateStreaming_ReturnsWorkingHasher(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = "Hello, World!"u8.ToArray();

		// Act
		using var hasher = HashFacade.CreateStreaming(algorithm);
		hasher.Update(data);
		byte[] hash = hasher.FinalizeBytes();

		// Assert
		hash.Should().NotBeNull();
		hash.Should().NotBeEmpty();
	}

	[Theory]
	[InlineData(HashAlgorithm.MurmurHash3_128)]
	[InlineData(HashAlgorithm.CityHash64)]
	[InlineData(HashAlgorithm.Wyhash64)]
	public void StreamingHash_MatchesOneShotHash(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = "Test data for streaming vs one-shot comparison"u8.ToArray();

		// Act
		byte[] oneShotHash = HashFacade.ComputeHash(algorithm, data);

		using var hasher = HashFacade.CreateStreaming(algorithm);
		hasher.Update(data);
		byte[] streamingHash = hasher.FinalizeBytes();

		// Assert
		streamingHash.Should().BeEquivalentTo(oneShotHash,
			$"because streaming and one-shot should produce identical results for {algorithm}");
	}

	[Theory]
	[InlineData(HashAlgorithm.MurmurHash3_128)]
	[InlineData(HashAlgorithm.CityHash64)]
	[InlineData(HashAlgorithm.XxHash64)]
	public void StreamingHash_ChunkedMatchesSingleUpdate(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"u8.ToArray();

		// Act - Single update
		using var hasher1 = HashFacade.CreateStreaming(algorithm);
		hasher1.Update(data);
		byte[] singleHash = hasher1.FinalizeBytes();

		// Act - Chunked updates
		using var hasher2 = HashFacade.CreateStreaming(algorithm);
		hasher2.Update(data.AsSpan(0, 10));
		hasher2.Update(data.AsSpan(10, 20));
		hasher2.Update(data.AsSpan(30));
		byte[] chunkedHash = hasher2.FinalizeBytes();

		// Assert
		chunkedHash.Should().BeEquivalentTo(singleHash,
			$"because chunked updates should match single update for {algorithm}");
	}

	[Theory]
	[InlineData(HashAlgorithm.MurmurHash3_32)]
	[InlineData(HashAlgorithm.CityHash64)]
	public void StreamingHash_Reset_AllowsReuse(HashAlgorithm algorithm) {
		// Arrange
		byte[] data1 = "First data"u8.ToArray();
		byte[] data2 = "Second data"u8.ToArray();

		// Act
		using var hasher = HashFacade.CreateStreaming(algorithm);

		hasher.Update(data1);
		byte[] hash1 = hasher.FinalizeBytes();

		hasher.Reset();

		hasher.Update(data2);
		byte[] hash2 = hasher.FinalizeBytes();

		// Assert
		hash1.Should().NotBeEquivalentTo(hash2, "because different data should produce different hashes");
	}

	#endregion

	#region Algorithm Info Tests

	[Theory]
	[InlineData(HashAlgorithm.Crc32, 4, false)]
	[InlineData(HashAlgorithm.Sha256, 32, true)]
	[InlineData(HashAlgorithm.MurmurHash3_128, 16, false)]
	[InlineData(HashAlgorithm.Blake3, 32, true)]
	public void GetInfo_ReturnsCorrectMetadata(HashAlgorithm algorithm, int expectedDigestSize, bool expectedCrypto) {
		// Act
		var info = HashFacade.GetInfo(algorithm);

		// Assert
		info.DigestSize.Should().Be(expectedDigestSize);
		info.IsCryptographic.Should().Be(expectedCrypto);
		info.DisplayName.Should().NotBeNullOrWhiteSpace();
	}

	[Fact]
	public void GetInfo_AllAlgorithmsHaveInfo() {
		// Arrange
		var algorithms = Enum.GetValues<HashAlgorithm>();

		// Act & Assert
		foreach (var algorithm in algorithms) {
			var info = HashFacade.GetInfo(algorithm);
			info.DigestSize.Should().BeGreaterThan(0, $"because {algorithm} should have a positive digest size");
			info.DisplayName.Should().NotBeNullOrWhiteSpace($"because {algorithm} should have a display name");
		}
	}

	#endregion

	#region Checksum Verification Tests

	[Fact]
	public void ComputeAdler32_MatchesKnownValue() {
		// "Wikipedia" => 0x11e60398
		byte[] data = "Wikipedia"u8.ToArray();

		byte[] hash = HashFacade.ComputeAdler32(data);

		// Adler-32 is stored as big-endian (b << 16 | a)
		uint result = BitConverter.ToUInt32(hash);
		result.Should().Be(0x11e60398);
	}

	[Fact]
	public void ComputeFletcher16_ReturnsValidResult() {
		byte[] data = "abcde"u8.ToArray();

		byte[] hash = HashFacade.ComputeFletcher16(data);

		hash.Should().HaveCount(2);
	}

	[Fact]
	public void ComputeFletcher32_ReturnsValidResult() {
		byte[] data = "abcdefgh"u8.ToArray();

		byte[] hash = HashFacade.ComputeFletcher32(data);

		hash.Should().HaveCount(4);
	}

	#endregion

	#region Crypto Algorithm Boundary Tests

	[Theory]
	[InlineData(HashAlgorithm.Md2)]
	[InlineData(HashAlgorithm.Sha3_256)]
	[InlineData(HashAlgorithm.Blake2b)]
	[InlineData(HashAlgorithm.Ripemd160)]
	public void ComputeHash_CryptoAlgorithms_ThrowsNotSupported(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = "Test"u8.ToArray();

		// Act
		Action act = () => HashFacade.ComputeHash(algorithm, data);

		// Assert
		act.Should().Throw<NotSupportedException>()
			.WithMessage("*BouncyCastle*");
	}

	[Theory]
	[InlineData(HashAlgorithm.Sha3_256)]
	[InlineData(HashAlgorithm.Blake2b)]
	public void CreateStreaming_CryptoAlgorithms_ThrowsNotSupported(HashAlgorithm algorithm) {
		// Act
		Action act = () => HashFacade.CreateStreaming(algorithm);

		// Assert
		act.Should().Throw<NotSupportedException>();
	}

	#endregion

	#region FinalizeHex Tests

	[Theory]
	[InlineData(HashAlgorithm.MurmurHash3_32)]
	[InlineData(HashAlgorithm.CityHash64)]
	[InlineData(HashAlgorithm.XxHash128)]
	public void StreamingHash_FinalizeHex_ReturnsLowercaseHex(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = "Test"u8.ToArray();

		// Act
		using var hasher = HashFacade.CreateStreaming(algorithm);
		hasher.Update(data);
		string hex = hasher.FinalizeHex();

		// Assert
		hex.Should().MatchRegex(@"^[0-9a-f]+$");
	}

	#endregion
}
