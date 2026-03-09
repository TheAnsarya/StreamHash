using System.IO.Hashing;
using System.Security.Cryptography;

namespace StreamHash.Core.Tests;

/// <summary>
/// Cross-validates StreamHash implementations against .NET BCL and System.IO.Hashing
/// reference implementations. These serve as an independent source of truth.
/// </summary>
public class CrossImplementationValidationTests {
	private static readonly byte[] EmptyData = [];
	private static readonly byte[] SmallData = "Hello, World!"u8.ToArray();
	private static readonly byte[] MediumData = CreateMediumData();

	private static byte[] CreateMediumData() {
		var data = new byte[100_000];
		Random.Shared.NextBytes(data);
		return data;
	}

	#region System.Security.Cryptography Cross-Validation

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void Md5_MatchesBclImplementation(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(MD5.HashData(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.Md5, data);
		streamHash.Should().Be(bclHash, $"MD5 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void Sha1_MatchesBclImplementation(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(SHA1.HashData(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.Sha1, data);
		streamHash.Should().Be(bclHash, $"SHA-1 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void Sha256_MatchesBclImplementation(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(SHA256.HashData(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.Sha256, data);
		streamHash.Should().Be(bclHash, $"SHA-256 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void Sha384_MatchesBclImplementation(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(SHA384.HashData(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.Sha384, data);
		streamHash.Should().Be(bclHash, $"SHA-384 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void Sha512_MatchesBclImplementation(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(SHA512.HashData(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.Sha512, data);
		streamHash.Should().Be(bclHash, $"SHA-512 mismatch for {description}");
	}

	#endregion

	#region System.IO.Hashing Cross-Validation

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void Crc32_MatchesSystemIOHashing(byte[] data, string description) {
		var bclCrc = new Crc32();
		bclCrc.Append(data);
		var bclHash = Convert.ToHexStringLower(bclCrc.GetCurrentHash());
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.Crc32, data);
		streamHash.Should().Be(bclHash, $"CRC32 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void Crc64_MatchesSystemIOHashing(byte[] data, string description) {
		var bclCrc = new Crc64();
		bclCrc.Append(data);
		var bclHash = Convert.ToHexStringLower(bclCrc.GetCurrentHash());
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.Crc64, data);
		streamHash.Should().Be(bclHash, $"CRC64 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void XxHash32_MatchesSystemIOHashing(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(XxHash32.Hash(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.XxHash32, data);
		streamHash.Should().Be(bclHash, $"xxHash32 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void XxHash64_MatchesSystemIOHashing(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(XxHash64.Hash(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.XxHash64, data);
		streamHash.Should().Be(bclHash, $"xxHash64 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void XxHash3_MatchesSystemIOHashing(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(XxHash3.Hash(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.XxHash3, data);
		streamHash.Should().Be(bclHash, $"xxHash3 mismatch for {description}");
	}

	[Theory]
	[MemberData(nameof(TestDataSets))]
	public void XxHash128_MatchesSystemIOHashing(byte[] data, string description) {
		var bclHash = Convert.ToHexStringLower(XxHash128.Hash(data));
		var streamHash = HashFacade.ComputeHashHex(HashAlgorithm.XxHash128, data);
		streamHash.Should().Be(bclHash, $"xxHash128 mismatch for {description}");
	}

	#endregion

	#region Streaming vs One-Shot Cross-Validation

	[Theory]
	[MemberData(nameof(AllAlgorithms))]
	public void StreamingResult_MatchesOneShotResult(HashAlgorithm algorithm) {
		var oneShotResult = HashFacade.ComputeHashHex(algorithm, MediumData);

		using var streaming = HashFacade.CreateStreaming(algorithm);
		// Feed data in 1KB chunks
		int offset = 0;
		while (offset < MediumData.Length) {
			int len = Math.Min(1024, MediumData.Length - offset);
			streaming.Update(MediumData.AsSpan(offset, len));
			offset += len;
		}
		var streamingResult = Convert.ToHexStringLower(streaming.FinalizeBytes());

		streamingResult.Should().Be(oneShotResult,
			$"{algorithm} streaming should match one-shot for 100KB data");
	}

	#endregion

	#region Test Data

	public static TheoryData<byte[], string> TestDataSets() => new() {
		{ EmptyData, "empty" },
		{ SmallData, "Hello, World!" },
		{ new byte[] { 0x00 }, "single zero byte" },
		{ new byte[] { 0xff }, "single 0xFF byte" },
		{ Encoding.ASCII.GetBytes("abc"), "abc" },
		{ Encoding.ASCII.GetBytes("123456789"), "123456789" },
		{ MediumData, "100KB random" },
	};

	public static TheoryData<HashAlgorithm> AllAlgorithms() {
		var data = new TheoryData<HashAlgorithm>();
		foreach (var algo in Enum.GetValues<HashAlgorithm>()) {
			data.Add(algo);
		}
		return data;
	}

	#endregion
}
