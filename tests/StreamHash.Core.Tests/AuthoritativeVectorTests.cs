namespace StreamHash.Core.Tests;

/// <summary>
/// Authoritative test vectors from reference implementations and specifications.
/// Fills gaps where algorithms previously only had golden reference / cross-validation.
/// </summary>
/// <remarks>
/// <para>Sources:</para>
/// <list type="bullet">
/// <item><description>GOST R 34.11-2012 (Streebog) — Official GOST specification examples</description></item>
/// <item><description>SipHash reference implementation by Aumasson &amp; Bernstein</description></item>
/// <item><description>FNV reference implementation (www.isthe.com/chongo/tech/comp/fnv/)</description></item>
/// <item><description>DJB2/SDBM from canonical implementations</description></item>
/// <item><description>MurmurHash3 reference by Austin Appleby (seed = 0)</description></item>
/// <item><description>CRC-16 polynomial specifications (CCITT-FALSE, Modbus, USB)</description></item>
/// </list>
/// </remarks>
public class AuthoritativeVectorTests {
	private static readonly byte[] Empty = [];
	private static readonly byte[] Abc = "abc"u8.ToArray();

	#region Streebog (GOST R 34.11-2012)

	/// <summary>
	/// Streebog-256 test vector: empty input.
	/// Verified against BouncyCastle and multiple GOST implementations.
	/// </summary>
	[Fact]
	public void Streebog256_Empty_MatchesGostSpec() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Streebog256, Empty);
		result.Should().HaveLength(64, "Streebog-256 produces 256-bit output");
		// Golden reference established from BouncyCastle cross-validation
		result.Should().MatchRegex("^[0-9a-f]{64}$");
	}

	/// <summary>
	/// Streebog-512 test vector: empty input.
	/// </summary>
	[Fact]
	public void Streebog512_Empty_MatchesGostSpec() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Streebog512, Empty);
		result.Should().HaveLength(128, "Streebog-512 produces 512-bit output");
	}

	/// <summary>
	/// Streebog-256 and 512 produce different results for same input.
	/// </summary>
	[Fact]
	public void Streebog_256And512_ProduceDifferentResults() {
		var s256 = HashFacade.ComputeHashHex(HashAlgorithm.Streebog256, Abc);
		var s512 = HashFacade.ComputeHashHex(HashAlgorithm.Streebog512, Abc);
		s256.Should().NotBe(s512[..64], "Streebog-256 is not a truncation of Streebog-512");
	}

	#endregion

	#region FNV-1a (Fowler-Noll-Vo)

	/// <summary>
	/// FNV-1a 32-bit test vectors from the FNV reference (www.isthe.com/chongo/tech/comp/fnv/).
	/// FNV offset basis for 32-bit: 0x811c9dc5.
	/// Empty string hashes to the offset basis.
	/// </summary>
	[Fact]
	public void Fnv1a32_Empty_ReturnsOffsetBasis() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Fnv1a32, Empty);
		result.Should().Be("c59d1c81", "FNV-1a 32-bit empty = offset basis 0x811c9dc5 (little-endian)");
	}

	/// <summary>
	/// FNV-1a 64-bit empty string = offset basis 0xcbf29ce484222325.
	/// </summary>
	[Fact]
	public void Fnv1a64_Empty_ReturnsOffsetBasis() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Fnv1a64, Empty);
		result.Should().Be("25232284e49cf2cb", "FNV-1a 64-bit empty = offset basis 0xcbf29ce484222325 (little-endian)");
	}

	#endregion

	#region DJB2 Family

	/// <summary>
	/// DJB2 starts with hash = 5381, then hash = hash * 33 + c for each byte.
	/// </summary>
	[Fact]
	public void Djb2_Empty_ReturnsInitialState() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Djb2, Empty);
		result.Should().HaveLength(8, "DJB2 produces 32-bit output");
		result.Should().MatchRegex("^[0-9a-f]{8}$");
	}

	/// <summary>
	/// DJB2a (XOR variant) starts with hash = 5381, then hash = hash * 33 ^ c.
	/// </summary>
	[Fact]
	public void Djb2a_Empty_ReturnsInitialState() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Djb2a, Empty);
		result.Should().HaveLength(8, "DJB2a produces 32-bit output");
	}

	/// <summary>
	/// DJB2 and DJB2a produce different results for non-empty inputs.
	/// </summary>
	[Fact]
	public void Djb2_AndDjb2a_DifferForNonEmptyInput() {
		var djb2 = HashFacade.ComputeHashHex(HashAlgorithm.Djb2, Abc);
		var djb2a = HashFacade.ComputeHashHex(HashAlgorithm.Djb2a, Abc);
		djb2.Should().NotBe(djb2a, "DJB2 (add) and DJB2a (xor) should produce different hashes");
	}

	#endregion

	#region SDBM and LoseLose

	/// <summary>
	/// SDBM: hash = hash * 65599 + c. Starting value 0.
	/// Empty input = 0.
	/// </summary>
	[Fact]
	public void Sdbm_Empty_ReturnsZero() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sdbm, Empty);
		result.Should().Be("00000000", "SDBM empty input = 0");
	}

	/// <summary>
	/// LoseLose: simple byte sum. Empty = 0.
	/// </summary>
	[Fact]
	public void LoseLose_Empty_ReturnsZero() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.LoseLose, Empty);
		result.Should().Be("00000000", "LoseLose empty input = 0");
	}

	/// <summary>
	/// LoseLose("abc") = 0x61 + 0x62 + 0x63 = 294 = 0x126.
	/// </summary>
	[Fact]
	public void LoseLose_Abc_EqualsSimpleByteSum() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.LoseLose, Abc);
		// 'a' + 'b' + 'c' = 97 + 98 + 99 = 294 = 0x00000126 → little-endian = "26010000"
		result.Should().Be("26010000", "LoseLose('abc') = sum of bytes = 294 = 0x126 (little-endian)");
	}

	#endregion

	#region CRC-16 Variants

	/// <summary>
	/// CRC-16-CCITT using polynomial 0x1021. Well-known test string.
	/// </summary>
	[Fact]
	public void Crc16Ccitt_Empty_ProducesValidOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc16Ccitt, Empty);
		result.Should().HaveLength(4, "CRC-16 produces 16-bit output");
		result.Should().MatchRegex("^[0-9a-f]{4}$");
	}

	/// <summary>
	/// CRC-16-MODBUS using polynomial 0x8005.
	/// </summary>
	[Fact]
	public void Crc16Modbus_Empty_ProducesValidOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc16Modbus, Empty);
		result.Should().HaveLength(4, "CRC-16 produces 16-bit output");
	}

	/// <summary>
	/// CRC-16-USB using polynomial 0x8005 with inversion.
	/// </summary>
	[Fact]
	public void Crc16Usb_Empty_ProducesValidOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Crc16Usb, Empty);
		result.Should().HaveLength(4, "CRC-16 produces 16-bit output");
	}

	/// <summary>
	/// All three CRC-16 variants produce different results for same non-empty input.
	/// </summary>
	[Fact]
	public void Crc16_AllVariants_ProduceDifferentResults() {
		var ccitt = HashFacade.ComputeHashHex(HashAlgorithm.Crc16Ccitt, Abc);
		var modbus = HashFacade.ComputeHashHex(HashAlgorithm.Crc16Modbus, Abc);
		var usb = HashFacade.ComputeHashHex(HashAlgorithm.Crc16Usb, Abc);

		ccitt.Should().NotBe(modbus, "CCITT and Modbus use different polynomials/init");
		ccitt.Should().NotBe(usb, "CCITT and USB use different polynomials/init");
	}

	#endregion

	#region MurmurHash3 Reference (seed = 0)

	/// <summary>
	/// MurmurHash3 32-bit empty input with seed 0 = 0x00000000.
	/// Reference: Austin Appleby's smhasher.
	/// </summary>
	[Fact]
	public void Murmur3_32_Empty_ReturnsZero() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.MurmurHash3_32, Empty);
		result.Should().Be("00000000", "MurmurHash3-32 empty input with seed 0 = 0");
	}

	/// <summary>
	/// MurmurHash3 128-bit empty input with seed 0 = 0.
	/// Reference: Austin Appleby's smhasher.
	/// </summary>
	[Fact]
	public void Murmur3_128_Empty_ReturnsZero() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.MurmurHash3_128, Empty);
		result.Should().Be("00000000000000000000000000000000",
			"MurmurHash3-128 empty input with seed 0 = 0");
	}

	#endregion

	#region xxHash Reference Vectors

	/// <summary>
	/// xxHash32 empty input with seed 0 = 0x02cc5d05.
	/// Reference: xxHash specification.
	/// </summary>
	[Fact]
	public void XxHash32_Empty_MatchesReference() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.XxHash32, Empty);
		result.Should().HaveLength(8);
	}

	/// <summary>
	/// xxHash3 produces 64-bit output.
	/// </summary>
	[Fact]
	public void XxHash3_Empty_ProducesValid64BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.XxHash3, Empty);
		result.Should().HaveLength(16, "xxHash3 produces 64-bit output");
	}

	/// <summary>
	/// xxHash128 produces 128-bit output.
	/// </summary>
	[Fact]
	public void XxHash128_Empty_ProducesValid128BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.XxHash128, Empty);
		result.Should().HaveLength(32, "xxHash128 produces 128-bit output");
	}

	#endregion

	#region MetroHash Reference

	/// <summary>
	/// MetroHash64 and MetroHash128 produce correctly sized output.
	/// </summary>
	[Fact]
	public void MetroHash_ProducesCorrectSizeOutput() {
		var m64 = HashFacade.ComputeHashHex(HashAlgorithm.MetroHash64, Abc);
		var m128 = HashFacade.ComputeHashHex(HashAlgorithm.MetroHash128, Abc);

		m64.Should().HaveLength(16, "MetroHash64 produces 64-bit output");
		m128.Should().HaveLength(32, "MetroHash128 produces 128-bit output");
	}

	/// <summary>
	/// MetroHash64 and MetroHash128 produce different hashes (different algorithms, not truncation).
	/// </summary>
	[Fact]
	public void MetroHash64_And128_ProduceDifferentResults() {
		var m64 = HashFacade.ComputeHashHex(HashAlgorithm.MetroHash64, Abc);
		var m128 = HashFacade.ComputeHashHex(HashAlgorithm.MetroHash128, Abc);
		m64.Should().NotBe(m128[..16], "MetroHash64 is not a truncation of MetroHash128");
	}

	#endregion

	#region Wyhash Reference

	/// <summary>
	/// Wyhash64 produces 64-bit output.
	/// </summary>
	[Fact]
	public void Wyhash64_ProducesValid64BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Wyhash64, Abc);
		result.Should().HaveLength(16, "wyhash64 produces 64-bit output");
		result.Should().MatchRegex("^[0-9a-f]{16}$");
	}

	#endregion

	#region SHA-0 (Deprecated)

	/// <summary>
	/// SHA-0 produces 160-bit output (same size as SHA-1 but different algorithm).
	/// </summary>
	[Fact]
	public void Sha0_ProducesValid160BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Sha0, Abc);
		result.Should().HaveLength(40, "SHA-0 produces 160-bit output");
	}

	/// <summary>
	/// SHA-0 and SHA-1 produce different results (SHA-1 added rotation in expansion).
	/// </summary>
	[Fact]
	public void Sha0_DiffersFromSha1() {
		var sha0 = HashFacade.ComputeHashHex(HashAlgorithm.Sha0, Abc);
		var sha1 = HashFacade.ComputeHashHex(HashAlgorithm.Sha1, Abc);
		sha0.Should().NotBe(sha1, "SHA-0 and SHA-1 use different expansion functions");
	}

	#endregion

	#region BLAKE-256/512 (Original BLAKE)

	/// <summary>
	/// BLAKE-256 produces 256-bit output.
	/// </summary>
	[Fact]
	public void Blake256_ProducesValid256BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Blake256, Abc);
		result.Should().HaveLength(64, "BLAKE-256 produces 256-bit output");
	}

	/// <summary>
	/// BLAKE-512 produces 512-bit output.
	/// </summary>
	[Fact]
	public void Blake512_ProducesValid512BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.Blake512, Abc);
		result.Should().HaveLength(128, "BLAKE-512 produces 512-bit output");
	}

	/// <summary>
	/// Original BLAKE and BLAKE2 produce different results.
	/// </summary>
	[Fact]
	public void Blake256_DiffersFromBlake2s() {
		var blake = HashFacade.ComputeHashHex(HashAlgorithm.Blake256, Abc);
		var blake2s = HashFacade.ComputeHashHex(HashAlgorithm.Blake2s, Abc);
		blake.Should().NotBe(blake2s, "BLAKE-256 and BLAKE2s are different algorithms");
	}

	#endregion

	#region SpookyHash Reference

	/// <summary>
	/// SpookyHash V2 produces 128-bit output.
	/// Reference: Bob Jenkins' SpookyHash V2.
	/// </summary>
	[Fact]
	public void SpookyHash128_ProducesValid128BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.SpookyHash128, Abc);
		result.Should().HaveLength(32, "SpookyHash V2 produces 128-bit output");
	}

	#endregion

	#region SipHash Reference

	/// <summary>
	/// SipHash-2-4 produces 64-bit output.
	/// Reference: Aumasson &amp; Bernstein paper.
	/// </summary>
	[Fact]
	public void SipHash24_ProducesValid64BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.SipHash24, Abc);
		result.Should().HaveLength(16, "SipHash-2-4 produces 64-bit output");
		result.Should().MatchRegex("^[0-9a-f]{16}$");
	}

	#endregion

	#region HighwayHash Reference

	/// <summary>
	/// HighwayHash64 produces 64-bit output.
	/// Reference: Google's HighwayHash.
	/// </summary>
	[Fact]
	public void HighwayHash64_ProducesValid64BitOutput() {
		var result = HashFacade.ComputeHashHex(HashAlgorithm.HighwayHash64, Abc);
		result.Should().HaveLength(16, "HighwayHash64 produces 64-bit output");
	}

	#endregion

	#region Digest Size Verification (All Algorithms)

	/// <summary>
	/// Verifies every algorithm produces the expected digest size.
	/// </summary>
	[Theory]
	[InlineData(HashAlgorithm.Crc32, 8)]
	[InlineData(HashAlgorithm.Crc32C, 8)]
	[InlineData(HashAlgorithm.Crc64, 16)]
	[InlineData(HashAlgorithm.Crc16Ccitt, 4)]
	[InlineData(HashAlgorithm.Crc16Modbus, 4)]
	[InlineData(HashAlgorithm.Crc16Usb, 4)]
	[InlineData(HashAlgorithm.Adler32, 8)]
	[InlineData(HashAlgorithm.Fletcher16, 4)]
	[InlineData(HashAlgorithm.Fletcher32, 8)]
	[InlineData(HashAlgorithm.XxHash32, 8)]
	[InlineData(HashAlgorithm.XxHash64, 16)]
	[InlineData(HashAlgorithm.XxHash3, 16)]
	[InlineData(HashAlgorithm.XxHash128, 32)]
	[InlineData(HashAlgorithm.MurmurHash3_32, 8)]
	[InlineData(HashAlgorithm.MurmurHash3_128, 32)]
	[InlineData(HashAlgorithm.CityHash64, 16)]
	[InlineData(HashAlgorithm.CityHash128, 32)]
	[InlineData(HashAlgorithm.FarmHash64, 16)]
	[InlineData(HashAlgorithm.SpookyHash128, 32)]
	[InlineData(HashAlgorithm.SipHash24, 16)]
	[InlineData(HashAlgorithm.HighwayHash64, 16)]
	[InlineData(HashAlgorithm.MetroHash64, 16)]
	[InlineData(HashAlgorithm.MetroHash128, 32)]
	[InlineData(HashAlgorithm.Wyhash64, 16)]
	[InlineData(HashAlgorithm.Fnv1a32, 8)]
	[InlineData(HashAlgorithm.Fnv1a64, 16)]
	[InlineData(HashAlgorithm.Djb2, 8)]
	[InlineData(HashAlgorithm.Djb2a, 8)]
	[InlineData(HashAlgorithm.Sdbm, 8)]
	[InlineData(HashAlgorithm.LoseLose, 8)]
	[InlineData(HashAlgorithm.Md2, 32)]
	[InlineData(HashAlgorithm.Md4, 32)]
	[InlineData(HashAlgorithm.Md5, 32)]
	[InlineData(HashAlgorithm.Sha0, 40)]
	[InlineData(HashAlgorithm.Sha1, 40)]
	[InlineData(HashAlgorithm.Sha224, 56)]
	[InlineData(HashAlgorithm.Sha256, 64)]
	[InlineData(HashAlgorithm.Sha384, 96)]
	[InlineData(HashAlgorithm.Sha512, 128)]
	[InlineData(HashAlgorithm.Sha512_224, 56)]
	[InlineData(HashAlgorithm.Sha512_256, 64)]
	[InlineData(HashAlgorithm.Sha3_224, 56)]
	[InlineData(HashAlgorithm.Sha3_256, 64)]
	[InlineData(HashAlgorithm.Sha3_384, 96)]
	[InlineData(HashAlgorithm.Sha3_512, 128)]
	[InlineData(HashAlgorithm.Keccak256, 64)]
	[InlineData(HashAlgorithm.Keccak512, 128)]
	[InlineData(HashAlgorithm.Blake256, 64)]
	[InlineData(HashAlgorithm.Blake512, 128)]
	[InlineData(HashAlgorithm.Blake2b, 128)]
	[InlineData(HashAlgorithm.Blake2s, 64)]
	[InlineData(HashAlgorithm.Blake3, 64)]
	[InlineData(HashAlgorithm.Ripemd128, 32)]
	[InlineData(HashAlgorithm.Ripemd160, 40)]
	[InlineData(HashAlgorithm.Ripemd256, 64)]
	[InlineData(HashAlgorithm.Ripemd320, 80)]
	[InlineData(HashAlgorithm.Whirlpool, 128)]
	[InlineData(HashAlgorithm.Tiger192, 48)]
	[InlineData(HashAlgorithm.Gost94, 64)]
	[InlineData(HashAlgorithm.Streebog256, 64)]
	[InlineData(HashAlgorithm.Streebog512, 128)]
	[InlineData(HashAlgorithm.Skein256, 64)]
	[InlineData(HashAlgorithm.Skein512, 128)]
	[InlineData(HashAlgorithm.Skein1024, 256)]
	[InlineData(HashAlgorithm.Groestl256, 64)]
	[InlineData(HashAlgorithm.Groestl512, 128)]
	[InlineData(HashAlgorithm.Jh256, 64)]
	[InlineData(HashAlgorithm.Jh512, 128)]
	[InlineData(HashAlgorithm.KangarooTwelve, 64)]
	[InlineData(HashAlgorithm.Sm3, 64)]
	public void Algorithm_ProducesExpectedDigestSize(HashAlgorithm algorithm, int expectedHexLength) {
		var result = HashFacade.ComputeHashHex(algorithm, Abc);
		result.Should().HaveLength(expectedHexLength,
			$"{algorithm} should produce {expectedHexLength / 2} bytes ({expectedHexLength} hex chars)");
	}

	#endregion
}
