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
	public void ComputeFletcher16_MatchesReferenceImplementation() {
		var random = new Random(24680);
		for (var size = 0; size <= 65536; size += 1021) {
			var data = new byte[size];
			random.NextBytes(data);

			var actual = BitConverter.ToUInt16(HashFacade.ComputeFletcher16(data));
			var expected = ComputeFletcher16Reference(data);

			actual.Should().Be(expected, $"because Fletcher16 must match the reference calculation for payload size {size}");
		}
	}

	[Fact]
	public void ComputeFletcher32_ReturnsValidResult() {
		byte[] data = "abcdefgh"u8.ToArray();

		byte[] hash = HashFacade.ComputeFletcher32(data);

		hash.Should().HaveCount(4);
	}

	[Fact]
	public void ComputeFletcher32_MatchesReferenceImplementation() {
		var random = new Random(97531);
		for (var size = 0; size <= 65536; size += 1019) {
			var data = new byte[size];
			random.NextBytes(data);

			var actual = BitConverter.ToUInt32(HashFacade.ComputeFletcher32(data));
			var expected = ComputeFletcher32Reference(data);

			actual.Should().Be(expected, $"because Fletcher32 must match the reference calculation for payload size {size}");
		}
	}

	#endregion

	#region Crypto Algorithm Tests (BouncyCastle Integration)

	[Theory]
	[InlineData(HashAlgorithm.Md2, 16)]
	[InlineData(HashAlgorithm.Md4, 16)]
	[InlineData(HashAlgorithm.Sha0, 20)]
	[InlineData(HashAlgorithm.Sha224, 28)]
	[InlineData(HashAlgorithm.Sha3_224, 28)]
	[InlineData(HashAlgorithm.Sha3_256, 32)]
	[InlineData(HashAlgorithm.Sha3_384, 48)]
	[InlineData(HashAlgorithm.Sha3_512, 64)]
	[InlineData(HashAlgorithm.Keccak256, 32)]
	[InlineData(HashAlgorithm.Keccak512, 64)]
	[InlineData(HashAlgorithm.Blake256, 32)]
	[InlineData(HashAlgorithm.Blake512, 64)]
	[InlineData(HashAlgorithm.Blake2b, 64)]
	[InlineData(HashAlgorithm.Blake2s, 32)]
	[InlineData(HashAlgorithm.Blake3, 32)]
	[InlineData(HashAlgorithm.Ripemd128, 16)]
	[InlineData(HashAlgorithm.Ripemd160, 20)]
	[InlineData(HashAlgorithm.Ripemd256, 32)]
	[InlineData(HashAlgorithm.Ripemd320, 40)]
	[InlineData(HashAlgorithm.Whirlpool, 64)]
	[InlineData(HashAlgorithm.Tiger192, 24)]
	[InlineData(HashAlgorithm.Gost94, 32)]
	[InlineData(HashAlgorithm.Streebog256, 32)]
	[InlineData(HashAlgorithm.Streebog512, 64)]
	[InlineData(HashAlgorithm.Skein256, 32)]
	[InlineData(HashAlgorithm.Skein512, 64)]
	[InlineData(HashAlgorithm.Skein1024, 128)]
	[InlineData(HashAlgorithm.Sm3, 32)]
	public void ComputeHash_CryptoAlgorithms_ProducesCorrectLength(HashAlgorithm algorithm, int expectedLength) {
		// Arrange
		byte[] data = "Test"u8.ToArray();

		// Act
		byte[] hash = HashFacade.ComputeHash(algorithm, data);

		// Assert
		hash.Should().HaveCount(expectedLength);
	}

	[Theory]
	[InlineData(HashAlgorithm.Sha3_256)]
	[InlineData(HashAlgorithm.Blake2b)]
	[InlineData(HashAlgorithm.Ripemd160)]
	[InlineData(HashAlgorithm.Md2)]
	[InlineData(HashAlgorithm.Whirlpool)]
	public void CreateStreaming_CryptoAlgorithms_Works(HashAlgorithm algorithm) {
		// Arrange
		byte[] data = "Test"u8.ToArray();

		// Act
		using var hasher = HashFacade.CreateStreaming(algorithm);
		hasher.Update(data);
		byte[] hash = hasher.FinalizeBytes();

		// Assert - verify we get some bytes out
		hash.Should().NotBeEmpty();
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

	[Fact]
	public void ComputeAdler32_MatchesReferenceImplementation() {
		var random = new Random(12345);
		for (var size = 0; size <= 8192; size += 257) {
			var data = new byte[size];
			random.NextBytes(data);

			var actual = BitConverter.ToUInt32(HashFacade.ComputeAdler32(data));
			var expected = ComputeAdler32Reference(data);

			actual.Should().Be(expected, $"because Adler32 must match the reference calculation for payload size {size}");
		}
	}

	private static uint ComputeAdler32Reference(ReadOnlySpan<byte> data) {
		const uint mod = 65521;
		uint a = 1;
		uint b = 0;

		foreach (var value in data) {
			a = (a + value) % mod;
			b = (b + a) % mod;
		}

		return (b << 16) | a;
	}

	private static ushort ComputeFletcher16Reference(ReadOnlySpan<byte> data) {
		ushort sum1 = 0;
		ushort sum2 = 0;

		foreach (var value in data) {
			sum1 = (ushort)((sum1 + value) % 255);
			sum2 = (ushort)((sum2 + sum1) % 255);
		}

		return (ushort)((sum2 << 8) | sum1);
	}

	private static uint ComputeFletcher32Reference(ReadOnlySpan<byte> data) {
		uint sum1 = 0;
		uint sum2 = 0;

		foreach (var value in data) {
			sum1 = (sum1 + value) % 65535;
			sum2 = (sum2 + sum1) % 65535;
		}

		return (sum2 << 16) | sum1;
	}

	#endregion
}
