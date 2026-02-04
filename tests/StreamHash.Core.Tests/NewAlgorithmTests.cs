using FluentAssertions;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for CRC-16 streaming implementation.
/// </summary>
public class Crc16Tests {
	private static readonly byte[] TestData = "123456789"u8.ToArray();

	[Fact]
	public void Crc16Ccitt_TestVector_ReturnsExpectedHash() {
		// CRC-16-CCITT for "123456789" should be 0x29B1
		ushort result = Crc16Streaming.Hash(TestData, Crc16Variant.Ccitt);
		result.Should().Be(0x29b1);
	}

	[Fact]
	public void Crc16Xmodem_TestVector_ReturnsExpectedHash() {
		// CRC-16-XMODEM for "123456789" should be 0x31C3
		ushort result = Crc16Streaming.Hash(TestData, Crc16Variant.Xmodem);
		result.Should().Be(0x31c3);
	}

	[Fact]
	public void Crc16Modbus_TestVector_ReturnsExpectedHash() {
		// CRC-16-MODBUS for "123456789" should be 0x4B37
		ushort result = Crc16Streaming.Hash(TestData, Crc16Variant.Modbus);
		result.Should().Be(0x4b37);
	}

	[Fact]
	public void Crc16Usb_TestVector_ReturnsExpectedHash() {
		// CRC-16-USB for "123456789" should be 0xB4C8
		ushort result = Crc16Streaming.Hash(TestData, Crc16Variant.Usb);
		result.Should().Be(0xb4c8);
	}

	[Fact]
	public void Crc16_StreamingMatchesOneShot() {
		using var hasher = new Crc16Streaming(Crc16Variant.Modbus);
		hasher.Update(TestData[..4]);
		hasher.Update(TestData[4..]);
		ushort streaming = hasher.Finalize();

		ushort oneShot = Crc16Streaming.Hash(TestData, Crc16Variant.Modbus);

		streaming.Should().Be(oneShot);
	}

	[Fact]
	public void Crc16_Reset_AllowsReuse() {
		using var hasher = new Crc16Streaming();
		hasher.Update(TestData);
		hasher.Finalize();

		hasher.Reset();
		hasher.Update(TestData);
		ushort result = hasher.Finalize();

		result.Should().Be(Crc16Streaming.Hash(TestData));
	}

	[Fact]
	public void Crc16_EmptyInput_ReturnsInitialXorOut() {
		using var hasher = new Crc16Streaming(Crc16Variant.Ccitt);
		ushort result = hasher.Finalize();
		// CCITT: init=0xFFFF, xorOut=0x0000, no reflection
		result.Should().Be(0xffff);
	}

	[Fact]
	public void Crc16_Properties_AreCorrect() {
		using var hasher = new Crc16Streaming();
		hasher.BlockSize.Should().Be(1);
		hasher.DigestSize.Should().Be(2);
		hasher.TotalBytesProcessed.Should().Be(0);

		hasher.Update(TestData);
		hasher.TotalBytesProcessed.Should().Be(9);
	}
}

/// <summary>
/// Tests for FNV-1a streaming implementation.
/// </summary>
public class Fnv1aTests {
	private static readonly byte[] TestData = "Hello"u8.ToArray();
	private static readonly byte[] EmptyData = [];

	[Fact]
	public void Fnv1a32_EmptyInput_ReturnsOffsetBasis() {
		uint result = Fnv1a32Streaming.Hash(EmptyData);
		result.Should().Be(Fnv1a32Streaming.FnvOffsetBasis32);
	}

	[Fact]
	public void Fnv1a32_StreamingMatchesOneShot() {
		using var hasher = new Fnv1a32Streaming();
		hasher.Update(TestData[..2]);
		hasher.Update(TestData[2..]);
		uint streaming = hasher.Finalize();

		uint oneShot = Fnv1a32Streaming.Hash(TestData);

		streaming.Should().Be(oneShot);
	}

	[Fact]
	public void Fnv1a64_EmptyInput_ReturnsOffsetBasis() {
		ulong result = Fnv1a64Streaming.Hash(EmptyData);
		result.Should().Be(Fnv1a64Streaming.FnvOffsetBasis64);
	}

	[Fact]
	public void Fnv1a64_StreamingMatchesOneShot() {
		using var hasher = new Fnv1a64Streaming();
		hasher.Update(TestData[..2]);
		hasher.Update(TestData[2..]);
		ulong streaming = hasher.Finalize();

		ulong oneShot = Fnv1a64Streaming.Hash(TestData);

		streaming.Should().Be(oneShot);
	}

	[Fact]
	public void Fnv1a32_Properties_AreCorrect() {
		using var hasher = new Fnv1a32Streaming();
		hasher.BlockSize.Should().Be(1);
		hasher.DigestSize.Should().Be(4);
	}

	[Fact]
	public void Fnv1a64_Properties_AreCorrect() {
		using var hasher = new Fnv1a64Streaming();
		hasher.BlockSize.Should().Be(1);
		hasher.DigestSize.Should().Be(8);
	}
}

/// <summary>
/// Tests for DJB2 streaming implementation.
/// </summary>
public class Djb2Tests {
	private static readonly byte[] TestData = "Hello"u8.ToArray();

	[Fact]
	public void Djb2_EmptyInput_ReturnsInitialValue() {
		uint result = Djb2Streaming.Hash([]);
		result.Should().Be(Djb2Streaming.InitialValue);
	}

	[Fact]
	public void Djb2_StreamingMatchesOneShot() {
		using var hasher = new Djb2Streaming();
		hasher.Update(TestData[..2]);
		hasher.Update(TestData[2..]);
		uint streaming = hasher.Finalize();

		uint oneShot = Djb2Streaming.Hash(TestData);

		streaming.Should().Be(oneShot);
	}

	[Fact]
	public void Djb2a_XorVariant_DifferentFromAddition() {
		uint add = Djb2Streaming.Hash(TestData, useXor: false);
		uint xor = Djb2Streaming.Hash(TestData, useXor: true);

		add.Should().NotBe(xor);
	}

	[Fact]
	public void Sdbm_StreamingMatchesOneShot() {
		using var hasher = new SdbmStreaming();
		hasher.Update(TestData[..2]);
		hasher.Update(TestData[2..]);
		uint streaming = hasher.Finalize();

		uint oneShot = SdbmStreaming.Hash(TestData);

		streaming.Should().Be(oneShot);
	}

	[Fact]
	public void LoseLose_IsByteSum() {
		byte[] data = [1, 2, 3, 4, 5];
		uint result = LoseLoseStreaming.Hash(data);
		result.Should().Be(15u); // 1+2+3+4+5
	}
}
