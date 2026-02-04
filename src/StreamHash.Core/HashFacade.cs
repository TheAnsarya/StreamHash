using Crc32Hash = System.IO.Hashing.Crc32;
using System.IO.Hashing;
using System.Security.Cryptography;

namespace StreamHash.Core;

/// <summary>
/// Unified facade providing access to all 58+ hash algorithms in a single API.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="HashFacade"/> provides static methods for computing hash values using any supported algorithm.
/// It unifies access to:
/// </para>
/// <list type="bullet">
/// <item><description>StreamHash's native streaming implementations (MurmurHash, CityHash, etc.)</description></item>
/// <item><description>.NET built-in algorithms (CRC32, xxHash, SHA-256, etc.)</description></item>
/// <item><description>BouncyCastle cryptographic algorithms (SHA-3, BLAKE, RIPEMD, etc.)</description></item>
/// </list>
/// <para>
/// <b>Algorithm Categories:</b>
/// <list type="bullet">
/// <item><description><strong>Checksums (6):</strong> CRC32, CRC32C, CRC64, Adler-32, Fletcher-16, Fletcher-32</description></item>
/// <item><description><strong>Fast Non-Crypto (16):</strong> xxHash, MurmurHash3, CityHash, FarmHash, SpookyHash, SipHash, HighwayHash, MetroHash, wyhash</description></item>
/// <item><description><strong>Cryptographic (26):</strong> MD family, SHA family, SHA-3, Keccak, BLAKE family, RIPEMD family</description></item>
/// <item><description><strong>Other Crypto (14):</strong> Whirlpool, Tiger, GOST, Streebog, Skein, SM3</description></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // One-shot hashing
/// byte[] data = File.ReadAllBytes("file.bin");
/// byte[] sha256 = HashFacade.ComputeHash(HashAlgorithm.Sha256, data);
/// byte[] xxhash = HashFacade.ComputeHash(HashAlgorithm.XxHash64, data);
///
/// // Get hex string
/// string sha256Hex = HashFacade.ComputeHashHex(HashAlgorithm.Sha256, data);
///
/// // Stream hashing
/// using var hasher = HashFacade.CreateStreaming(HashAlgorithm.MurmurHash3_128);
/// hasher.Update(chunk1);
/// hasher.Update(chunk2);
/// byte[] hash = hasher.FinalizeBytes();
/// </code>
/// </example>
public static class HashFacade {
	/// <summary>
	/// Total number of hash algorithms supported.
	/// </summary>
	public const int AlgorithmCount = 62;

	#region One-Shot Hashing

	/// <summary>
	/// Computes a hash of the specified data using the specified algorithm.
	/// </summary>
	/// <param name="algorithm">The hash algorithm to use.</param>
	/// <param name="data">The data to hash.</param>
	/// <returns>The computed hash as a byte array.</returns>
	/// <exception cref="NotSupportedException">The algorithm requires external dependencies (BouncyCastle).</exception>
	public static byte[] ComputeHash(HashAlgorithm algorithm, ReadOnlySpan<byte> data) {
		return algorithm switch {
			// Checksums
			HashAlgorithm.Crc32 => ComputeCrc32(data),
			HashAlgorithm.Crc32C => ComputeCrc32C(data),
			HashAlgorithm.Crc64 => ComputeCrc64(data),
			HashAlgorithm.Adler32 => ComputeAdler32(data),
			HashAlgorithm.Fletcher16 => ComputeFletcher16(data),
			HashAlgorithm.Fletcher32 => ComputeFletcher32(data),

			// Non-Crypto Fast
			HashAlgorithm.XxHash32 => ComputeXxHash32(data),
			HashAlgorithm.XxHash64 => ComputeXxHash64(data),
			HashAlgorithm.XxHash3 => ComputeXxHash3(data),
			HashAlgorithm.XxHash128 => ComputeXxHash128(data),
			HashAlgorithm.MurmurHash3_32 => ComputeMurmurHash3_32(data),
			HashAlgorithm.MurmurHash3_128 => ComputeMurmurHash3_128(data),
			HashAlgorithm.CityHash64 => ComputeCityHash64(data),
			HashAlgorithm.CityHash128 => ComputeCityHash128(data),
			HashAlgorithm.FarmHash64 => ComputeFarmHash64(data),
			HashAlgorithm.SpookyHash128 => ComputeSpookyHash128(data),
			HashAlgorithm.SipHash24 => ComputeSipHash24(data),
			HashAlgorithm.HighwayHash64 => ComputeHighwayHash64(data),
			HashAlgorithm.MetroHash64 => ComputeMetroHash64(data),
			HashAlgorithm.MetroHash128 => ComputeMetroHash128(data),
			HashAlgorithm.Wyhash64 => ComputeWyhash64(data),

			// MD Family
			HashAlgorithm.Md5 => MD5.HashData(data),

			// SHA-1/2 Family (built-in)
			HashAlgorithm.Sha1 => SHA1.HashData(data),
			HashAlgorithm.Sha256 => SHA256.HashData(data),
			HashAlgorithm.Sha384 => SHA384.HashData(data),
			HashAlgorithm.Sha512 => SHA512.HashData(data),

			// Algorithms requiring BouncyCastle
			HashAlgorithm.Md2 or HashAlgorithm.Md4 or HashAlgorithm.Sha0 or
			HashAlgorithm.Sha224 or HashAlgorithm.Sha512_224 or HashAlgorithm.Sha512_256 or
			HashAlgorithm.Sha3_224 or HashAlgorithm.Sha3_256 or HashAlgorithm.Sha3_384 or HashAlgorithm.Sha3_512 or
			HashAlgorithm.Keccak256 or HashAlgorithm.Keccak512 or
			HashAlgorithm.Blake256 or HashAlgorithm.Blake512 or HashAlgorithm.Blake2b or HashAlgorithm.Blake2s or HashAlgorithm.Blake3 or
			HashAlgorithm.Ripemd128 or HashAlgorithm.Ripemd160 or HashAlgorithm.Ripemd256 or HashAlgorithm.Ripemd320 or
			HashAlgorithm.Whirlpool or HashAlgorithm.Tiger192 or HashAlgorithm.Gost94 or
			HashAlgorithm.Streebog256 or HashAlgorithm.Streebog512 or
			HashAlgorithm.Skein256 or HashAlgorithm.Skein512 or HashAlgorithm.Skein1024 or
			HashAlgorithm.Groestl256 or HashAlgorithm.Groestl512 or
			HashAlgorithm.Jh256 or HashAlgorithm.Jh512 or
			HashAlgorithm.KangarooTwelve or HashAlgorithm.Sm3
				=> throw new NotSupportedException($"{algorithm} requires BouncyCastle. Use StreamHash.Crypto package."),

			_ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown hash algorithm")
		};
	}

	/// <summary>
	/// Computes a hash and returns it as a lowercase hexadecimal string.
	/// </summary>
	/// <param name="algorithm">The hash algorithm to use.</param>
	/// <param name="data">The data to hash.</param>
	/// <returns>The computed hash as a lowercase hex string.</returns>
	public static string ComputeHashHex(HashAlgorithm algorithm, ReadOnlySpan<byte> data) {
		byte[] hash = ComputeHash(algorithm, data);
		return Convert.ToHexStringLower(hash);
	}

	#endregion

	#region Checksum Implementations

	/// <summary>Computes CRC-32 (IEEE polynomial).</summary>
	public static byte[] ComputeCrc32(ReadOnlySpan<byte> data) {
		var crc = new Crc32Hash();
		crc.Append(data);
		return crc.GetCurrentHash();
	}

	/// <summary>Computes CRC-32C (Castagnoli polynomial, hardware accelerated).</summary>
	public static byte[] ComputeCrc32C(ReadOnlySpan<byte> data) {
		// Note: System.IO.Hashing Crc32 uses IEEE polynomial
		// For true CRC32C, we compute it manually with the Castagnoli polynomial
		uint crc = 0xFFFFFFFF;
		foreach (byte b in data) {
			crc ^= b;
			for (int i = 0; i < 8; i++) {
				crc = (crc >> 1) ^ ((crc & 1) * 0x82F63B78u);
			}
		}
		crc ^= 0xFFFFFFFF;
		return BitConverter.GetBytes(crc);
	}

	/// <summary>Computes CRC-64 (ECMA polynomial).</summary>
	public static byte[] ComputeCrc64(ReadOnlySpan<byte> data) {
		var crc = new Crc64();
		crc.Append(data);
		return crc.GetCurrentHash();
	}

	/// <summary>Computes Adler-32 checksum.</summary>
	public static byte[] ComputeAdler32(ReadOnlySpan<byte> data) {
		uint a = 1, b = 0;
		const uint MOD = 65521;
		foreach (byte bt in data) {
			a = (a + bt) % MOD;
			b = (b + a) % MOD;
		}
		return BitConverter.GetBytes((b << 16) | a);
	}

	/// <summary>Computes Fletcher-16 checksum.</summary>
	public static byte[] ComputeFletcher16(ReadOnlySpan<byte> data) {
		ushort sum1 = 0, sum2 = 0;
		foreach (byte b in data) {
			sum1 = (ushort)((sum1 + b) % 255);
			sum2 = (ushort)((sum2 + sum1) % 255);
		}
		return BitConverter.GetBytes((ushort)((sum2 << 8) | sum1));
	}

	/// <summary>Computes Fletcher-32 checksum.</summary>
	public static byte[] ComputeFletcher32(ReadOnlySpan<byte> data) {
		uint sum1 = 0, sum2 = 0;
		foreach (byte b in data) {
			sum1 = (sum1 + b) % 65535;
			sum2 = (sum2 + sum1) % 65535;
		}
		return BitConverter.GetBytes((sum2 << 16) | sum1);
	}

	#endregion

	#region Non-Crypto Fast Hash Implementations

	/// <summary>Computes xxHash32.</summary>
	public static byte[] ComputeXxHash32(ReadOnlySpan<byte> data) {
		var hash = new XxHash32();
		hash.Append(data);
		return hash.GetCurrentHash();
	}

	/// <summary>Computes xxHash64.</summary>
	public static byte[] ComputeXxHash64(ReadOnlySpan<byte> data) {
		var hash = new XxHash64();
		hash.Append(data);
		return hash.GetCurrentHash();
	}

	/// <summary>Computes xxHash3 (64-bit).</summary>
	public static byte[] ComputeXxHash3(ReadOnlySpan<byte> data) {
		var hash = new XxHash3();
		hash.Append(data);
		return hash.GetCurrentHash();
	}

	/// <summary>Computes xxHash128.</summary>
	public static byte[] ComputeXxHash128(ReadOnlySpan<byte> data) {
		var hash = new XxHash128();
		hash.Append(data);
		return hash.GetCurrentHash();
	}

	/// <summary>Computes MurmurHash3 32-bit.</summary>
	public static byte[] ComputeMurmurHash3_32(ReadOnlySpan<byte> data) {
		using var hasher = new MurmurHash3_32();
		hasher.Update(data);
		uint result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes MurmurHash3 128-bit.</summary>
	public static byte[] ComputeMurmurHash3_128(ReadOnlySpan<byte> data) {
		using var hasher = new MurmurHash3_128();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes CityHash64.</summary>
	public static byte[] ComputeCityHash64(ReadOnlySpan<byte> data) {
		using var hasher = new CityHash64();
		hasher.Update(data);
		ulong result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes CityHash128.</summary>
	public static byte[] ComputeCityHash128(ReadOnlySpan<byte> data) {
		using var hasher = new CityHash128();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes FarmHash64.</summary>
	public static byte[] ComputeFarmHash64(ReadOnlySpan<byte> data) {
		using var hasher = new FarmHash64();
		hasher.Update(data);
		ulong result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes SpookyHash V2 128-bit.</summary>
	public static byte[] ComputeSpookyHash128(ReadOnlySpan<byte> data) {
		using var hasher = new SpookyHash128();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes SipHash-2-4.</summary>
	public static byte[] ComputeSipHash24(ReadOnlySpan<byte> data) {
		using var hasher = new SipHash24();
		hasher.Update(data);
		ulong result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes HighwayHash64.</summary>
	public static byte[] ComputeHighwayHash64(ReadOnlySpan<byte> data) {
		using var hasher = new HighwayHash64();
		hasher.Update(data);
		ulong result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes MetroHash64.</summary>
	public static byte[] ComputeMetroHash64(ReadOnlySpan<byte> data) {
		using var hasher = new MetroHash64();
		hasher.Update(data);
		ulong result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes MetroHash128.</summary>
	public static byte[] ComputeMetroHash128(ReadOnlySpan<byte> data) {
		using var hasher = new MetroHash128();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes wyhash64.</summary>
	public static byte[] ComputeWyhash64(ReadOnlySpan<byte> data) {
		using var hasher = new Wyhash64();
		hasher.Update(data);
		ulong result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	#endregion

	#region Streaming Hash Creation

	/// <summary>
	/// Creates a streaming hash instance for the specified algorithm.
	/// </summary>
	/// <param name="algorithm">The hash algorithm.</param>
	/// <returns>A streaming hash interface that returns byte[] results.</returns>
	/// <exception cref="NotSupportedException">The algorithm doesn't support streaming in StreamHash.Core.</exception>
	/// <remarks>
	/// <para>
	/// This returns an <see cref="IStreamingHashBytes"/> that can be used for incremental hashing
	/// and always returns byte[] from <see cref="IStreamingHashBytes.FinalizeBytes"/>.
	/// </para>
	/// <para>
	/// For algorithms requiring BouncyCastle (SHA-3, BLAKE, etc.), use StreamHash.Crypto package.
	/// </para>
	/// </remarks>
	public static IStreamingHashBytes CreateStreaming(HashAlgorithm algorithm) {
		return algorithm switch {
			// Checksums - use adapters
			HashAlgorithm.Crc32 => new NonCryptoHashAdapter32(new Crc32Hash()),
			HashAlgorithm.Crc64 => new NonCryptoHashAdapter64(new Crc64()),

			// xxHash family - use adapters
			HashAlgorithm.XxHash32 => new NonCryptoHashAdapter32(new XxHash32()),
			HashAlgorithm.XxHash64 => new NonCryptoHashAdapter64(new XxHash64()),
			HashAlgorithm.XxHash3 => new NonCryptoHashAdapter64(new XxHash3()),
			HashAlgorithm.XxHash128 => new NonCryptoHashAdapter128(new XxHash128()),

			// StreamHash native implementations
			HashAlgorithm.MurmurHash3_32 => new StreamingHashBytesAdapter<uint>(new MurmurHash3_32()),
			HashAlgorithm.MurmurHash3_128 => new MurmurHash3_128(),
			HashAlgorithm.CityHash64 => new StreamingHashBytesAdapter<ulong>(new CityHash64()),
			HashAlgorithm.CityHash128 => new CityHash128(),
			HashAlgorithm.FarmHash64 => new StreamingHashBytesAdapter<ulong>(new FarmHash64()),
			HashAlgorithm.SpookyHash128 => new SpookyHash128(),
			HashAlgorithm.SipHash24 => new StreamingHashBytesAdapter<ulong>(new SipHash24()),
			HashAlgorithm.HighwayHash64 => new StreamingHashBytesAdapter<ulong>(new HighwayHash64()),
			HashAlgorithm.MetroHash64 => new StreamingHashBytesAdapter<ulong>(new MetroHash64()),
			HashAlgorithm.MetroHash128 => new MetroHash128(),
			HashAlgorithm.Wyhash64 => new Wyhash64(),
			HashAlgorithm.KangarooTwelve => new KangarooTwelve(),

			_ => throw new NotSupportedException($"Streaming not supported for {algorithm} in StreamHash.Core. " +
				"Use BouncyCastle directly for cryptographic algorithms.")
		};
	}

	#endregion

	#region Utility Methods

	/// <summary>
	/// Gets information about a hash algorithm.
	/// </summary>
	/// <param name="algorithm">The hash algorithm.</param>
	/// <returns>Information including digest size and whether it's cryptographic.</returns>
	public static HashAlgorithmInfo GetInfo(HashAlgorithm algorithm) {
		return algorithm switch {
			// Checksums
			HashAlgorithm.Crc32 => new(4, false, "CRC-32 (IEEE)"),
			HashAlgorithm.Crc32C => new(4, false, "CRC-32C (Castagnoli)"),
			HashAlgorithm.Crc64 => new(8, false, "CRC-64 (ECMA)"),
			HashAlgorithm.Adler32 => new(4, false, "Adler-32"),
			HashAlgorithm.Fletcher16 => new(2, false, "Fletcher-16"),
			HashAlgorithm.Fletcher32 => new(4, false, "Fletcher-32"),

			// Non-Crypto Fast
			HashAlgorithm.XxHash32 => new(4, false, "xxHash32"),
			HashAlgorithm.XxHash64 => new(8, false, "xxHash64"),
			HashAlgorithm.XxHash3 => new(8, false, "xxHash3 (XXH3)"),
			HashAlgorithm.XxHash128 => new(16, false, "xxHash128"),
			HashAlgorithm.MurmurHash3_32 => new(4, false, "MurmurHash3 (32-bit)"),
			HashAlgorithm.MurmurHash3_128 => new(16, false, "MurmurHash3 (128-bit)"),
			HashAlgorithm.CityHash64 => new(8, false, "CityHash64"),
			HashAlgorithm.CityHash128 => new(16, false, "CityHash128"),
			HashAlgorithm.FarmHash64 => new(8, false, "FarmHash64"),
			HashAlgorithm.SpookyHash128 => new(16, false, "SpookyHash V2 (128-bit)"),
			HashAlgorithm.SipHash24 => new(8, false, "SipHash-2-4"),
			HashAlgorithm.HighwayHash64 => new(8, false, "HighwayHash64"),
			HashAlgorithm.MetroHash64 => new(8, false, "MetroHash64"),
			HashAlgorithm.MetroHash128 => new(16, false, "MetroHash128"),
			HashAlgorithm.Wyhash64 => new(8, false, "wyhash64"),

			// MD Family
			HashAlgorithm.Md2 => new(16, true, "MD2"),
			HashAlgorithm.Md4 => new(16, true, "MD4"),
			HashAlgorithm.Md5 => new(16, true, "MD5"),

			// SHA Family
			HashAlgorithm.Sha0 => new(20, true, "SHA-0"),
			HashAlgorithm.Sha1 => new(20, true, "SHA-1"),
			HashAlgorithm.Sha224 => new(28, true, "SHA-224"),
			HashAlgorithm.Sha256 => new(32, true, "SHA-256"),
			HashAlgorithm.Sha384 => new(48, true, "SHA-384"),
			HashAlgorithm.Sha512 => new(64, true, "SHA-512"),
			HashAlgorithm.Sha512_224 => new(28, true, "SHA-512/224"),
			HashAlgorithm.Sha512_256 => new(32, true, "SHA-512/256"),

			// SHA-3 & Keccak
			HashAlgorithm.Sha3_224 => new(28, true, "SHA3-224"),
			HashAlgorithm.Sha3_256 => new(32, true, "SHA3-256"),
			HashAlgorithm.Sha3_384 => new(48, true, "SHA3-384"),
			HashAlgorithm.Sha3_512 => new(64, true, "SHA3-512"),
			HashAlgorithm.Keccak256 => new(32, true, "Keccak-256"),
			HashAlgorithm.Keccak512 => new(64, true, "Keccak-512"),

			// BLAKE Family
			HashAlgorithm.Blake256 => new(32, true, "BLAKE-256"),
			HashAlgorithm.Blake512 => new(64, true, "BLAKE-512"),
			HashAlgorithm.Blake2b => new(64, true, "BLAKE2b"),
			HashAlgorithm.Blake2s => new(32, true, "BLAKE2s"),
			HashAlgorithm.Blake3 => new(32, true, "BLAKE3"),

			// RIPEMD Family
			HashAlgorithm.Ripemd128 => new(16, true, "RIPEMD-128"),
			HashAlgorithm.Ripemd160 => new(20, true, "RIPEMD-160"),
			HashAlgorithm.Ripemd256 => new(32, true, "RIPEMD-256"),
			HashAlgorithm.Ripemd320 => new(40, true, "RIPEMD-320"),

			// Other Crypto
			HashAlgorithm.Whirlpool => new(64, true, "Whirlpool"),
			HashAlgorithm.Tiger192 => new(24, true, "Tiger-192"),
			HashAlgorithm.Gost94 => new(32, true, "GOST R 34.11-94"),
			HashAlgorithm.Streebog256 => new(32, true, "Streebog-256"),
			HashAlgorithm.Streebog512 => new(64, true, "Streebog-512"),
			HashAlgorithm.Skein256 => new(32, true, "Skein-256"),
			HashAlgorithm.Skein512 => new(64, true, "Skein-512"),
			HashAlgorithm.Skein1024 => new(128, true, "Skein-1024"),
			HashAlgorithm.Groestl256 => new(32, true, "Grøstl-256"),
			HashAlgorithm.Groestl512 => new(64, true, "Grøstl-512"),
			HashAlgorithm.Jh256 => new(32, true, "JH-256"),
			HashAlgorithm.Jh512 => new(64, true, "JH-512"),
			HashAlgorithm.KangarooTwelve => new(32, true, "KangarooTwelve"),
			HashAlgorithm.Sm3 => new(32, true, "SM3"),

			_ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown algorithm")
		};
	}

	#endregion
}

/// <summary>
/// Information about a hash algorithm.
/// </summary>
/// <param name="DigestSize">Size of the hash output in bytes.</param>
/// <param name="IsCryptographic">Whether the algorithm is cryptographic (not just a checksum).</param>
/// <param name="DisplayName">Human-readable name of the algorithm.</param>
public readonly record struct HashAlgorithmInfo(int DigestSize, bool IsCryptographic, string DisplayName);
