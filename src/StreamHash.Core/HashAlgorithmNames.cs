namespace StreamHash.Core;

/// <summary>
/// Public constants for all 70 hash algorithm names.
/// Use these constants when calling batch streaming APIs to avoid typos and enable refactoring.
/// </summary>
/// <remarks>
/// <para>
/// These constants match the exact string identifiers used by the batch streaming API
/// (<see cref="HashFacade.CreateBatchStreaming(string[])"/>).
/// Using these constants instead of string literals provides compile-time safety and IntelliSense support.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Using constants instead of magic strings
/// using var hasher = HashFacade.CreateBatchStreaming(
///     HashAlgorithmNames.Sha256,
///     HashAlgorithmNames.Blake3,
///     HashAlgorithmNames.XxHash64);
///
/// hasher.Update(data);
/// var results = hasher.FinalizeAll();
/// string sha256Hash = results[HashAlgorithmNames.Sha256];
/// </code>
/// </example>
public static class HashAlgorithmNames {
	#region Checksums (9)

	/// <summary>CRC-32 (IEEE polynomial)</summary>
	public const string Crc32 = "CRC32";

	/// <summary>CRC-32C (Castagnoli polynomial, hardware accelerated)</summary>
	public const string Crc32C = "CRC32C";

	/// <summary>CRC-64 (ECMA polynomial)</summary>
	public const string Crc64 = "CRC64";

	/// <summary>CRC-16-CCITT</summary>
	public const string Crc16Ccitt = "CRC16-CCITT";

	/// <summary>CRC-16-MODBUS</summary>
	public const string Crc16Modbus = "CRC16-MODBUS";

	/// <summary>CRC-16-USB</summary>
	public const string Crc16Usb = "CRC16-USB";

	/// <summary>Adler-32 checksum</summary>
	public const string Adler32 = "Adler-32";

	/// <summary>Fletcher-16 checksum</summary>
	public const string Fletcher16 = "Fletcher-16";

	/// <summary>Fletcher-32 checksum</summary>
	public const string Fletcher32 = "Fletcher-32";

	#endregion

	#region Fast Non-Crypto (22)

	/// <summary>xxHash32 (32-bit)</summary>
	public const string XxHash32 = "xxHash32";

	/// <summary>xxHash64 (64-bit)</summary>
	public const string XxHash64 = "xxHash64";

	/// <summary>xxHash3 (XXH3, 64-bit)</summary>
	public const string XxHash3 = "xxHash3";

	/// <summary>xxHash128 (128-bit)</summary>
	public const string XxHash128 = "xxHash128";

	/// <summary>MurmurHash3 (32-bit variant)</summary>
	public const string MurmurHash3_32 = "MurmurHash3-32";

	/// <summary>MurmurHash3 (128-bit variant)</summary>
	public const string MurmurHash3_128 = "MurmurHash3-128";

	/// <summary>CityHash64 (64-bit)</summary>
	public const string CityHash64 = "CityHash64";

	/// <summary>CityHash128 (128-bit)</summary>
	public const string CityHash128 = "CityHash128";

	/// <summary>FarmHash64 (64-bit)</summary>
	public const string FarmHash64 = "FarmHash64";

	/// <summary>SpookyHash V2 (128-bit)</summary>
	public const string SpookyHash128 = "SpookyHash128";

	/// <summary>SipHash-2-4 (64-bit)</summary>
	public const string SipHash24 = "SipHash-2-4";

	/// <summary>HighwayHash64 (64-bit, SIMD optimized)</summary>
	public const string HighwayHash64 = "HighwayHash64";

	/// <summary>MetroHash64 (64-bit)</summary>
	public const string MetroHash64 = "MetroHash64";

	/// <summary>MetroHash128 (128-bit)</summary>
	public const string MetroHash128 = "MetroHash128";

	/// <summary>wyhash64 (64-bit)</summary>
	public const string Wyhash64 = "wyhash64";

	/// <summary>FNV-1a (32-bit)</summary>
	public const string Fnv1a32 = "FNV-1a-32";

	/// <summary>FNV-1a (64-bit)</summary>
	public const string Fnv1a64 = "FNV-1a-64";

	/// <summary>DJB2 hash</summary>
	public const string Djb2 = "DJB2";

	/// <summary>DJB2a (XOR variant)</summary>
	public const string Djb2a = "DJB2a";

	/// <summary>SDBM hash</summary>
	public const string Sdbm = "SDBM";

	/// <summary>Lose Lose hash</summary>
	public const string LoseLose = "lose-lose";

	#endregion

	#region MD Family (3)

	/// <summary>MD2 (128-bit, legacy)</summary>
	public const string Md2 = "MD2";

	/// <summary>MD4 (128-bit, legacy)</summary>
	public const string Md4 = "MD4";

	/// <summary>MD5 (128-bit, legacy)</summary>
	public const string Md5 = "MD5";

	#endregion

	#region SHA-1/2 Family (9)

	/// <summary>SHA-0 (160-bit, broken)</summary>
	public const string Sha0 = "SHA-0";

	/// <summary>SHA-1 (160-bit, legacy)</summary>
	public const string Sha1 = "SHA-1";

	/// <summary>SHA-224 (224-bit)</summary>
	public const string Sha224 = "SHA-224";

	/// <summary>SHA-256 (256-bit, widely used)</summary>
	public const string Sha256 = "SHA-256";

	/// <summary>SHA-384 (384-bit)</summary>
	public const string Sha384 = "SHA-384";

	/// <summary>SHA-512 (512-bit)</summary>
	public const string Sha512 = "SHA-512";

	/// <summary>SHA-512/224 (224-bit output from SHA-512)</summary>
	public const string Sha512_224 = "SHA-512/224";

	/// <summary>SHA-512/256 (256-bit output from SHA-512)</summary>
	public const string Sha512_256 = "SHA-512/256";

	#endregion

	#region SHA-3 & Keccak (6)

	/// <summary>SHA3-224 (224-bit)</summary>
	public const string Sha3_224 = "SHA3-224";

	/// <summary>SHA3-256 (256-bit)</summary>
	public const string Sha3_256 = "SHA3-256";

	/// <summary>SHA3-384 (384-bit)</summary>
	public const string Sha3_384 = "SHA3-384";

	/// <summary>SHA3-512 (512-bit)</summary>
	public const string Sha3_512 = "SHA3-512";

	/// <summary>Keccak-256 (256-bit, Ethereum)</summary>
	public const string Keccak256 = "Keccak-256";

	/// <summary>Keccak-512 (512-bit)</summary>
	public const string Keccak512 = "Keccak-512";

	#endregion

	#region BLAKE Family (5)

	/// <summary>BLAKE-256 (256-bit)</summary>
	public const string Blake256 = "BLAKE-256";

	/// <summary>BLAKE-512 (512-bit)</summary>
	public const string Blake512 = "BLAKE-512";

	/// <summary>BLAKE2b (512-bit default)</summary>
	public const string Blake2b = "BLAKE2b";

	/// <summary>BLAKE2s (256-bit default)</summary>
	public const string Blake2s = "BLAKE2s";

	/// <summary>BLAKE3 (256-bit, modern)</summary>
	public const string Blake3 = "BLAKE3";

	#endregion

	#region RIPEMD Family (4)

	/// <summary>RIPEMD-128 (128-bit)</summary>
	public const string Ripemd128 = "RIPEMD-128";

	/// <summary>RIPEMD-160 (160-bit, Bitcoin)</summary>
	public const string Ripemd160 = "RIPEMD-160";

	/// <summary>RIPEMD-256 (256-bit)</summary>
	public const string Ripemd256 = "RIPEMD-256";

	/// <summary>RIPEMD-320 (320-bit)</summary>
	public const string Ripemd320 = "RIPEMD-320";

	#endregion

	#region Other Cryptographic (14)

	/// <summary>Whirlpool (512-bit)</summary>
	public const string Whirlpool = "Whirlpool";

	/// <summary>Tiger-192 (192-bit)</summary>
	public const string Tiger192 = "Tiger-192";

	/// <summary>GOST R 34.11-94 (256-bit, Russian standard)</summary>
	public const string Gost94 = "GOST-94";

	/// <summary>Streebog-256 (256-bit, Russian standard)</summary>
	public const string Streebog256 = "Streebog-256";

	/// <summary>Streebog-512 (512-bit, Russian standard)</summary>
	public const string Streebog512 = "Streebog-512";

	/// <summary>Skein-256 (256-bit)</summary>
	public const string Skein256 = "Skein-256";

	/// <summary>Skein-512 (512-bit)</summary>
	public const string Skein512 = "Skein-512";

	/// <summary>Skein-1024 (1024-bit)</summary>
	public const string Skein1024 = "Skein-1024";

	/// <summary>Grøstl-256 (256-bit)</summary>
	public const string Groestl256 = "Grøstl-256";

	/// <summary>Grøstl-512 (512-bit)</summary>
	public const string Groestl512 = "Grøstl-512";

	/// <summary>JH-256 (256-bit)</summary>
	public const string Jh256 = "JH-256";

	/// <summary>JH-512 (512-bit)</summary>
	public const string Jh512 = "JH-512";

	/// <summary>KangarooTwelve (variable output, XOF)</summary>
	public const string KangarooTwelve = "KangarooTwelve";

	/// <summary>SM3 (256-bit, Chinese standard)</summary>
	public const string Sm3 = "SM3";

	#endregion

	#region Helper Arrays

	/// <summary>
	/// All checksum algorithm names (9 algorithms).
	/// </summary>
	public static readonly string[] Checksums = [
		Crc32, Crc32C, Crc64, Crc16Ccitt, Crc16Modbus, Crc16Usb,
		Adler32, Fletcher16, Fletcher32
	];

	/// <summary>
	/// All fast non-cryptographic hash algorithm names (22 algorithms).
	/// </summary>
	public static readonly string[] FastNonCrypto = [
		XxHash32, XxHash64, XxHash3, XxHash128,
		MurmurHash3_32, MurmurHash3_128,
		CityHash64, CityHash128,
		FarmHash64, SpookyHash128, SipHash24,
		HighwayHash64, MetroHash64, MetroHash128, Wyhash64,
		Fnv1a32, Fnv1a64, Djb2, Djb2a, Sdbm, LoseLose
	];

	/// <summary>
	/// All cryptographic hash algorithm names (39 algorithms).
	/// </summary>
	public static readonly string[] Cryptographic = [
		// MD family
		Md2, Md4, Md5,
		// SHA-1/2 family
		Sha0, Sha1, Sha224, Sha256, Sha384, Sha512,
		Sha512_224, Sha512_256,
		// SHA-3 & Keccak
		Sha3_224, Sha3_256, Sha3_384, Sha3_512,
		Keccak256, Keccak512,
		// BLAKE family
		Blake256, Blake512, Blake2b, Blake2s, Blake3,
		// RIPEMD family
		Ripemd128, Ripemd160, Ripemd256, Ripemd320,
		// Other cryptographic
		Whirlpool, Tiger192, Gost94,
		Streebog256, Streebog512,
		Skein256, Skein512, Skein1024,
		Groestl256, Groestl512,
		Jh256, Jh512,
		KangarooTwelve, Sm3
	];

	/// <summary>
	/// The five most common hash algorithms for file verification.
	/// Used by <see cref="HashFacade.CreateBasicCommonHashesStreaming()"/>.
	/// </summary>
	public static readonly string[] BasicHashes = [
		Crc32, Md5, Sha1, Sha256, Sha512
	];

	/// <summary>
	/// All 70 hash algorithm names.
	/// </summary>
	public static readonly string[] All = [
		..Checksums,
		..FastNonCrypto,
		..Cryptographic
	];

	#endregion
}
