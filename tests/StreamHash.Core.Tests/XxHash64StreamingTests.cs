using System.IO.Hashing;
using System.Text;
using FluentAssertions;
using StreamHash.Core;
using Xunit;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for XxHash64Streaming wrapper around System.IO.Hashing.XxHash64.
/// </summary>
public class XxHash64StreamingTests {
	[Fact]
	public void Hash_EmptyInput_ReturnsExpectedValue() {
		// xxHash64("") with seed 0 = 0xef46db3751d8e999
		using var hasher = new XxHash64Streaming();
		var result = hasher.Finalize();
		result.Should().Be(0xef46db3751d8e999);
	}

	[Fact]
	public void Hash_SingleByte_MatchesStaticMethod() {
		using var hasher = new XxHash64Streaming();
		hasher.Update([(byte)'a']);
		var result = hasher.Finalize();

		var expected = XxHash64Streaming.Hash([(byte)'a']);
		result.Should().Be(expected);
	}

	[Fact]
	public void Hash_HelloWorld_MatchesStaticMethod() {
		var data = Encoding.UTF8.GetBytes("Hello, World!");

		using var hasher = new XxHash64Streaming();
		hasher.Update(data);
		var result = hasher.Finalize();

		var expected = XxHash64Streaming.Hash(data);
		result.Should().Be(expected);
	}

	[Fact]
	public void StreamingHash_MatchesOneShotHash() {
		var data = new byte[1000];
		Random.Shared.NextBytes(data);

		var oneShotResult = XxHash64Streaming.Hash(data);

		using var hasher = new XxHash64Streaming();
		for (int i = 0; i < data.Length; i += 100) {
			int len = Math.Min(100, data.Length - i);
			hasher.Update(data.AsSpan(i, len));
		}
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void StreamingHash_SingleByteChunks_MatchesOneShotHash() {
		var data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

		var oneShotResult = XxHash64Streaming.Hash(data);

		using var hasher = new XxHash64Streaming();
		foreach (var b in data) {
			hasher.Update([b]);
		}
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void Hash_WithSeed_ProducesDifferentResult() {
		var data = Encoding.UTF8.GetBytes("test");

		using var hasher1 = new XxHash64Streaming(0);
		hasher1.Update(data);
		var result1 = hasher1.Finalize();

		using var hasher2 = new XxHash64Streaming(12345);
		hasher2.Update(data);
		var result2 = hasher2.Finalize();

		result1.Should().NotBe(result2);
	}

	[Fact]
	public void Reset_AllowsReuseOfHasher() {
		var data1 = Encoding.UTF8.GetBytes("first");
		var data2 = Encoding.UTF8.GetBytes("second");

		using var hasher = new XxHash64Streaming();

		hasher.Update(data1);
		var result1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		var result2 = hasher.Finalize();

		var expected1 = XxHash64Streaming.Hash(data1);
		var expected2 = XxHash64Streaming.Hash(data2);

		result1.Should().Be(expected1);
		result2.Should().Be(expected2);
		result1.Should().NotBe(result2);
	}

	[Fact]
	public void TotalBytesProcessed_TracksInputSize() {
		using var hasher = new XxHash64Streaming();

		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(new byte[10]);
		hasher.TotalBytesProcessed.Should().Be(10);

		hasher.Update(new byte[20]);
		hasher.TotalBytesProcessed.Should().Be(30);
	}

	[Fact]
	public void FinalizeToBytes_ReturnsCorrectLength() {
		using var hasher = new XxHash64Streaming();
		hasher.Update(Encoding.UTF8.GetBytes("test"));
		var result = hasher.FinalizeToBytes();
		result.Should().HaveCount(8);
	}

	[Fact]
	public void Update_AfterFinalize_ThrowsException() {
		using var hasher = new XxHash64Streaming();
		hasher.Update([1, 2, 3]);
		hasher.Finalize();

		Action act = () => hasher.Update([4, 5, 6]);
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Finalize_CalledTwice_ThrowsException() {
		using var hasher = new XxHash64Streaming();
		hasher.Update([1, 2, 3]);
		hasher.Finalize();

		Action act = () => hasher.Finalize();
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterDispose_ThrowsException() {
		var hasher = new XxHash64Streaming();
		hasher.Dispose();

		Action act = () => hasher.Update([1, 2, 3]);
		act.Should().Throw<ObjectDisposedException>();
	}

	[Fact]
	public void BlockSize_Returns32() {
		using var hasher = new XxHash64Streaming();
		hasher.BlockSize.Should().Be(32);
	}

	[Fact]
	public void DigestSize_Returns8() {
		using var hasher = new XxHash64Streaming();
		hasher.DigestSize.Should().Be(8);
	}

	[Fact]
	public void HashToBytes_ReturnsCorrectLength() {
		var result = XxHash64Streaming.HashToBytes([1, 2, 3, 4]);
		result.Should().HaveCount(8);
	}

	[Fact]
	public void Update_WithArrayOffset_HashesCorrectly() {
		var fullData = new byte[] { 0, 0, 1, 2, 3, 4, 5, 0, 0 };
		var subData = new byte[] { 1, 2, 3, 4, 5 };

		using var hasher = new XxHash64Streaming();
		hasher.Update(fullData, 2, 5);
		var result = hasher.Finalize();

		var expected = XxHash64Streaming.Hash(subData);
		result.Should().Be(expected);
	}

	[Fact]
	public void MatchesBuiltInXxHash64() {
		var data = new byte[500];
		Random.Shared.NextBytes(data);

		using var hasher = new XxHash64Streaming();
		hasher.Update(data);
		var ourResult = hasher.Finalize();

		var builtInResult = XxHash64.HashToUInt64(data);

		ourResult.Should().Be(builtInResult);
	}

	[Theory]
	[InlineData(0)]
	[InlineData(1)]
	[InlineData(7)]
	[InlineData(8)]
	[InlineData(9)]
	[InlineData(31)]
	[InlineData(32)]
	[InlineData(33)]
	[InlineData(63)]
	[InlineData(64)]
	[InlineData(100)]
	[InlineData(256)]
	[InlineData(1000)]
	public void VariousLengths_MatchBuiltIn(int length) {
		var data = new byte[length];
		if (length > 0) {
			Random.Shared.NextBytes(data);
		}

		using var hasher = new XxHash64Streaming();
		hasher.Update(data);
		var result = hasher.Finalize();

		var expected = XxHash64.HashToUInt64(data);
		result.Should().Be(expected, $"length={length}");
	}

	[Fact]
	public void LargeData_StreamingMatchesOneShot() {
		var data = new byte[100_000];
		Random.Shared.NextBytes(data);

		var oneShotResult = XxHash64Streaming.Hash(data);

		using var hasher = new XxHash64Streaming();
		int chunkSize = 4096;
		for (int i = 0; i < data.Length; i += chunkSize) {
			int len = Math.Min(chunkSize, data.Length - i);
			hasher.Update(data.AsSpan(i, len));
		}
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}
}
