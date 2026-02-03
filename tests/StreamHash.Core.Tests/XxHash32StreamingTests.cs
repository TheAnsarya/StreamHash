using System.IO.Hashing;
using System.Text;
using FluentAssertions;
using StreamHash.Core;
using Xunit;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for XxHash32Streaming wrapper around System.IO.Hashing.XxHash32.
/// </summary>
public class XxHash32StreamingTests {
	// Known test vectors from xxHash specification
	// Using seed 0

	[Fact]
	public void Hash_EmptyInput_ReturnsExpectedValue() {
		// xxHash32("") with seed 0 = 0x02cc5d05
		using var hasher = new XxHash32Streaming();
		var result = hasher.Finalize();
		result.Should().Be(0x02cc5d05);
	}

	[Fact]
	public void Hash_SingleByte_ReturnsExpectedValue() {
		// Hash of single byte 'a' (0x61)
		using var hasher = new XxHash32Streaming();
		hasher.Update([(byte)'a']);
		var result = hasher.Finalize();

		// Verify against static method
		var expected = XxHash32Streaming.Hash([(byte)'a']);
		result.Should().Be(expected);
	}

	[Fact]
	public void Hash_HelloWorld_MatchesStaticMethod() {
		var data = Encoding.UTF8.GetBytes("Hello, World!");

		using var hasher = new XxHash32Streaming();
		hasher.Update(data);
		var result = hasher.Finalize();

		var expected = XxHash32Streaming.Hash(data);
		result.Should().Be(expected);
	}

	[Fact]
	public void StreamingHash_MatchesOneShotHash() {
		var data = new byte[1000];
		Random.Shared.NextBytes(data);

		// One-shot
		var oneShotResult = XxHash32Streaming.Hash(data);

		// Streaming in chunks
		using var hasher = new XxHash32Streaming();
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

		var oneShotResult = XxHash32Streaming.Hash(data);

		using var hasher = new XxHash32Streaming();
		foreach (var b in data) {
			hasher.Update([b]);
		}
		var streamingResult = hasher.Finalize();

		streamingResult.Should().Be(oneShotResult);
	}

	[Fact]
	public void Hash_WithSeed_ProducesDifferentResult() {
		var data = Encoding.UTF8.GetBytes("test");

		using var hasher1 = new XxHash32Streaming(0);
		hasher1.Update(data);
		var result1 = hasher1.Finalize();

		using var hasher2 = new XxHash32Streaming(12345);
		hasher2.Update(data);
		var result2 = hasher2.Finalize();

		result1.Should().NotBe(result2);
	}

	[Fact]
	public void Reset_AllowsReuseOfHasher() {
		var data1 = Encoding.UTF8.GetBytes("first");
		var data2 = Encoding.UTF8.GetBytes("second");

		using var hasher = new XxHash32Streaming();

		hasher.Update(data1);
		var result1 = hasher.Finalize();

		hasher.Reset();

		hasher.Update(data2);
		var result2 = hasher.Finalize();

		var expected1 = XxHash32Streaming.Hash(data1);
		var expected2 = XxHash32Streaming.Hash(data2);

		result1.Should().Be(expected1);
		result2.Should().Be(expected2);
		result1.Should().NotBe(result2);
	}

	[Fact]
	public void TotalBytesProcessed_TracksInputSize() {
		using var hasher = new XxHash32Streaming();

		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(new byte[10]);
		hasher.TotalBytesProcessed.Should().Be(10);

		hasher.Update(new byte[20]);
		hasher.TotalBytesProcessed.Should().Be(30);
	}

	[Fact]
	public void FinalizeToBytes_ReturnsCorrectLength() {
		using var hasher = new XxHash32Streaming();
		hasher.Update(Encoding.UTF8.GetBytes("test"));
		var result = hasher.FinalizeToBytes();
		result.Should().HaveCount(4);
	}

	[Fact]
	public void Update_AfterFinalize_ThrowsException() {
		using var hasher = new XxHash32Streaming();
		hasher.Update([1, 2, 3]);
		hasher.Finalize();

		Action act = () => hasher.Update([4, 5, 6]);
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Finalize_CalledTwice_ThrowsException() {
		using var hasher = new XxHash32Streaming();
		hasher.Update([1, 2, 3]);
		hasher.Finalize();

		Action act = () => hasher.Finalize();
		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Update_AfterDispose_ThrowsException() {
		var hasher = new XxHash32Streaming();
		hasher.Dispose();

		Action act = () => hasher.Update([1, 2, 3]);
		act.Should().Throw<ObjectDisposedException>();
	}

	[Fact]
	public void BlockSize_Returns4() {
		using var hasher = new XxHash32Streaming();
		hasher.BlockSize.Should().Be(4);
	}

	[Fact]
	public void DigestSize_Returns4() {
		using var hasher = new XxHash32Streaming();
		hasher.DigestSize.Should().Be(4);
	}

	[Fact]
	public void HashToBytes_ReturnsCorrectLength() {
		var result = XxHash32Streaming.HashToBytes([1, 2, 3, 4]);
		result.Should().HaveCount(4);
	}

	[Fact]
	public void Update_WithArrayOffset_HashesCorrectly() {
		var fullData = new byte[] { 0, 0, 1, 2, 3, 4, 5, 0, 0 };
		var subData = new byte[] { 1, 2, 3, 4, 5 };

		using var hasher = new XxHash32Streaming();
		hasher.Update(fullData, 2, 5);
		var result = hasher.Finalize();

		var expected = XxHash32Streaming.Hash(subData);
		result.Should().Be(expected);
	}

	[Fact]
	public void MatchesBuiltInXxHash32() {
		var data = new byte[500];
		Random.Shared.NextBytes(data);

		// Our wrapper
		using var hasher = new XxHash32Streaming();
		hasher.Update(data);
		var ourResult = hasher.Finalize();

		// Built-in
		var builtInResult = XxHash32.HashToUInt32(data);

		ourResult.Should().Be(builtInResult);
	}

	[Theory]
	[InlineData(0)]
	[InlineData(1)]
	[InlineData(3)]
	[InlineData(4)]
	[InlineData(5)]
	[InlineData(15)]
	[InlineData(16)]
	[InlineData(17)]
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

		using var hasher = new XxHash32Streaming();
		hasher.Update(data);
		var result = hasher.Finalize();

		var expected = XxHash32.HashToUInt32(data);
		result.Should().Be(expected, $"length={length}");
	}
}
