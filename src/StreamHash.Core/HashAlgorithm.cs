namespace StreamHash.Core;

/// <summary>
/// Enumeration of all hash algorithms supported by StreamHash.
/// </summary>
/// <remarks>
/// <para>
/// StreamHash supports 58+ hash algorithms organized into categories:
/// </para>
/// <list type="bullet">
/// <item><description><strong>Checksums (6):</strong> CRC32, CRC32C, CRC64, Adler-32, Fletcher-16, Fletcher-32</description></item>
/// <item><description><strong>Fast Non-Crypto (16):</strong> xxHash family, MurmurHash3, CityHash, FarmHash, SpookyHash, SipHash, HighwayHash, MetroHash, wyhash</description></item>
/// <item><description><strong>Cryptographic (26):</strong> MD family, SHA family, SHA-3, Keccak, BLAKE family, RIPEMD family</description></item>
/// <item><description><strong>Other Crypto (14):</strong> Whirlpool, Tiger, GOST, Streebog, Skein, SM3</description></item>
/// </list>
/// </remarks>
public enum HashAlgorithm {
	// ========== Checksums & CRCs (6) ==========

	/// <summary>CRC-32 using the IEEE polynomial (0x04C11DB7).</summary>
	Crc32,

	/// <summary>CRC-32C using the Castagnoli polynomial (0x1EDC6F41) with hardware acceleration.</summary>
	Crc32C,

	/// <summary>CRC-64 using the ECMA polynomial.</summary>
	Crc64,

	/// <summary>Adler-32 checksum (faster than CRC-32 but weaker).</summary>
	Adler32,

	/// <summary>Fletcher-16 checksum (2 bytes).</summary>
	Fletcher16,

	/// <summary>Fletcher-32 checksum (4 bytes).</summary>
	Fletcher32,

	// ========== Non-Crypto Fast Hashes (16) ==========

	/// <summary>xxHash32 - 32-bit hash by Yann Collet.</summary>
	XxHash32,

	/// <summary>xxHash64 - 64-bit hash by Yann Collet.</summary>
	XxHash64,

	/// <summary>xxHash3 - Latest xxHash variant (64-bit).</summary>
	XxHash3,

	/// <summary>xxHash128 - 128-bit xxHash variant.</summary>
	XxHash128,

	/// <summary>MurmurHash3 32-bit variant.</summary>
	MurmurHash3_32,

	/// <summary>MurmurHash3 128-bit variant (x64).</summary>
	MurmurHash3_128,

	/// <summary>CityHash64 by Google.</summary>
	CityHash64,

	/// <summary>CityHash128 by Google.</summary>
	CityHash128,

	/// <summary>FarmHash64 by Google (successor to CityHash).</summary>
	FarmHash64,

	/// <summary>SpookyHash V2 128-bit by Bob Jenkins.</summary>
	SpookyHash128,

	/// <summary>SipHash-2-4 - keyed hash for hash table security.</summary>
	SipHash24,

	/// <summary>HighwayHash64 - SIMD-accelerated hash by Google.</summary>
	HighwayHash64,

	/// <summary>MetroHash64 - fast hash by J. Andrew Rogers.</summary>
	MetroHash64,

	/// <summary>MetroHash128 - 128-bit MetroHash variant.</summary>
	MetroHash128,

	/// <summary>wyhash64 - extremely fast hash by Wang Yi.</summary>
	Wyhash64,

	// ========== MD Family (3) ==========

	/// <summary>MD2 hash (128-bit). Cryptographically broken.</summary>
	Md2,

	/// <summary>MD4 hash (128-bit). Cryptographically broken.</summary>
	Md4,

	/// <summary>MD5 hash (128-bit). Cryptographically weak.</summary>
	Md5,

	// ========== SHA-1/2 Family (9) ==========

	/// <summary>SHA-0 (deprecated, use SHA-1).</summary>
	Sha0,

	/// <summary>SHA-1 hash (160-bit). Cryptographically weak.</summary>
	Sha1,

	/// <summary>SHA-224 hash (224-bit, truncated SHA-256).</summary>
	Sha224,

	/// <summary>SHA-256 hash (256-bit). Recommended for security.</summary>
	Sha256,

	/// <summary>SHA-384 hash (384-bit, truncated SHA-512).</summary>
	Sha384,

	/// <summary>SHA-512 hash (512-bit).</summary>
	Sha512,

	/// <summary>SHA-512/224 hash (224-bit truncation of SHA-512).</summary>
	Sha512_224,

	/// <summary>SHA-512/256 hash (256-bit truncation of SHA-512).</summary>
	Sha512_256,

	// ========== SHA-3 & Keccak (6) ==========

	/// <summary>SHA3-224 (224-bit).</summary>
	Sha3_224,

	/// <summary>SHA3-256 (256-bit).</summary>
	Sha3_256,

	/// <summary>SHA3-384 (384-bit).</summary>
	Sha3_384,

	/// <summary>SHA3-512 (512-bit).</summary>
	Sha3_512,

	/// <summary>Keccak-256 (256-bit). Used in Ethereum.</summary>
	Keccak256,

	/// <summary>Keccak-512 (512-bit).</summary>
	Keccak512,

	// ========== BLAKE Family (5) ==========

	/// <summary>BLAKE-256 (256-bit).</summary>
	Blake256,

	/// <summary>BLAKE-512 (512-bit).</summary>
	Blake512,

	/// <summary>BLAKE2b (512-bit). Optimized for 64-bit platforms.</summary>
	Blake2b,

	/// <summary>BLAKE2s (256-bit). Optimized for 8-32 bit platforms.</summary>
	Blake2s,

	/// <summary>BLAKE3 (256-bit). Extremely fast with parallelism support.</summary>
	Blake3,

	// ========== RIPEMD Family (4) ==========

	/// <summary>RIPEMD-128 (128-bit).</summary>
	Ripemd128,

	/// <summary>RIPEMD-160 (160-bit). Used in Bitcoin addresses.</summary>
	Ripemd160,

	/// <summary>RIPEMD-256 (256-bit).</summary>
	Ripemd256,

	/// <summary>RIPEMD-320 (320-bit).</summary>
	Ripemd320,

	// ========== Other Crypto Hashes (14) ==========

	/// <summary>Whirlpool (512-bit).</summary>
	Whirlpool,

	/// <summary>Tiger-192 (192-bit).</summary>
	Tiger192,

	/// <summary>GOST R 34.11-94 (256-bit). Russian standard.</summary>
	Gost94,

	/// <summary>Streebog-256 (256-bit). GOST R 34.11-2012.</summary>
	Streebog256,

	/// <summary>Streebog-512 (512-bit). GOST R 34.11-2012.</summary>
	Streebog512,

	/// <summary>Skein-256 (256-bit). SHA-3 finalist.</summary>
	Skein256,

	/// <summary>Skein-512 (512-bit). SHA-3 finalist.</summary>
	Skein512,

	/// <summary>Skein-1024 (1024-bit). SHA-3 finalist.</summary>
	Skein1024,

	/// <summary>Grøstl-256 (256-bit). SHA-3 finalist.</summary>
	Groestl256,

	/// <summary>Grøstl-512 (512-bit). SHA-3 finalist.</summary>
	Groestl512,

	/// <summary>JH-256 (256-bit). SHA-3 finalist.</summary>
	Jh256,

	/// <summary>JH-512 (512-bit). SHA-3 finalist.</summary>
	Jh512,

	/// <summary>KangarooTwelve (K12) - fast Keccak variant.</summary>
	KangarooTwelve,

	/// <summary>SM3 (256-bit). Chinese cryptographic standard.</summary>
	Sm3,
}
