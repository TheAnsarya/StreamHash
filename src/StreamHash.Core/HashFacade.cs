using Crc32Hash = System.IO.Hashing.Crc32;
using System.IO.Hashing;
using System.Security.Cryptography;
using StreamHash.Core.Abstractions;

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
/// <item><description>StreamHash's native streaming implementations (MurmurHash, CityHash, Skein, etc.)</description></item>
/// <item><description>.NET built-in algorithms (CRC32, xxHash, SHA-256, etc.)</description></item>
/// <item><description>Native cryptographic algorithms (SHA-3, BLAKE, RIPEMD, Whirlpool, Groestl, JH)</description></item>
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
	public const int AlgorithmCount = 70;

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
			HashAlgorithm.Crc16Ccitt => ComputeCrc16Ccitt(data),
			HashAlgorithm.Crc16Modbus => ComputeCrc16Modbus(data),
			HashAlgorithm.Crc16Usb => ComputeCrc16Usb(data),
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
			HashAlgorithm.Fnv1a32 => ComputeFnv1a32(data),
			HashAlgorithm.Fnv1a64 => ComputeFnv1a64(data),
			HashAlgorithm.Djb2 => ComputeDjb2(data),
			HashAlgorithm.Djb2a => ComputeDjb2a(data),
			HashAlgorithm.Sdbm => ComputeSdbm(data),
			HashAlgorithm.LoseLose => ComputeLoseLose(data),

			// MD Family (acryptohashnet for MD2/MD4, .NET for MD5)
			HashAlgorithm.Md2 => AcryptohashnetFactory.ComputeMd2(data),
			HashAlgorithm.Md4 => AcryptohashnetFactory.ComputeMd4(data),
			HashAlgorithm.Md5 => MD5.HashData(data),

			// SHA-1/2 Family (acryptohashnet for SHA-0/224, .NET for rest)
			HashAlgorithm.Sha0 => AcryptohashnetFactory.ComputeSha0(data),
			HashAlgorithm.Sha1 => SHA1.HashData(data),
			HashAlgorithm.Sha224 => AcryptohashnetFactory.ComputeSha224(data),
			HashAlgorithm.Sha256 => SHA256.HashData(data),
			HashAlgorithm.Sha384 => SHA384.HashData(data),
			HashAlgorithm.Sha512 => SHA512.HashData(data),
			HashAlgorithm.Sha512_224 => Sha512tFactory.ComputeSha512_224(data),
			HashAlgorithm.Sha512_256 => Sha512tFactory.ComputeSha512_256(data),

			// SHA-3 (Native implementation) & Keccak (Native implementation)
			HashAlgorithm.Sha3_224 => NativeSha3Factory.ComputeSha3_224(data),
			HashAlgorithm.Sha3_256 => NativeSha3Factory.ComputeSha3_256(data),
			HashAlgorithm.Sha3_384 => NativeSha3Factory.ComputeSha3_384(data),
			HashAlgorithm.Sha3_512 => NativeSha3Factory.ComputeSha3_512(data),
			HashAlgorithm.Keccak256 => NativeSha3Factory.ComputeKeccak256(data),
			HashAlgorithm.Keccak512 => NativeSha3Factory.ComputeKeccak512(data),

			// BLAKE Family (Blake2Fast for BLAKE2, Blake3.NET for BLAKE3)
			HashAlgorithm.Blake256 => Blake2Factory.ComputeBlake256(data),
			HashAlgorithm.Blake512 => Blake2Factory.ComputeBlake512(data),
			HashAlgorithm.Blake2b => Blake2Factory.ComputeBlake2b(data),
			HashAlgorithm.Blake2s => Blake2Factory.ComputeBlake2s(data),
			HashAlgorithm.Blake3 => Blake3Factory.ComputeHash(data),

			// RIPEMD Family (acryptohashnet for 128/160, native for 256/320)
			HashAlgorithm.Ripemd128 => AcryptohashnetFactory.ComputeRipemd128(data),
			HashAlgorithm.Ripemd160 => AcryptohashnetFactory.ComputeRipemd160(data),
			HashAlgorithm.Ripemd256 => Ripemd256Factory.ComputeRipemd256(data),
			HashAlgorithm.Ripemd320 => Ripemd320Factory.ComputeRipemd320(data),

			// Other Crypto (acryptohashnet for Tiger192, native for GOST-94, Streebog, Skein)
			HashAlgorithm.Whirlpool => ComputeWhirlpool(data),
			HashAlgorithm.Tiger192 => AcryptohashnetFactory.ComputeTiger192(data),
			HashAlgorithm.Gost94 => Gost94Factory.ComputeGost94(data),
			HashAlgorithm.Streebog256 => StreebogFactory.ComputeStreebog256(data),
			HashAlgorithm.Streebog512 => StreebogFactory.ComputeStreebog512(data),
			HashAlgorithm.Skein256 => SkeinOptimizedFactory.ComputeSkein256(data),
			HashAlgorithm.Skein512 => SkeinOptimizedFactory.ComputeSkein512(data),
			HashAlgorithm.Skein1024 => SkeinOptimizedFactory.ComputeSkein1024(data),
			HashAlgorithm.Groestl256 => ComputeGroestl256(data),
			HashAlgorithm.Groestl512 => ComputeGroestl512(data),
			HashAlgorithm.Jh256 => ComputeJh256(data),
			HashAlgorithm.Jh512 => ComputeJh512(data),
			HashAlgorithm.KangarooTwelve => ComputeKangarooTwelveHash(data),
			HashAlgorithm.Sm3 => Sm3Factory.ComputeSm3(data),

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
		const uint Mod = 65521;
		const int ChunkSize = 5552;

		uint a = 1;
		uint b = 0;
		var offset = 0;

		while (offset < data.Length) {
			var chunkLength = Math.Min(ChunkSize, data.Length - offset);
			for (var i = 0; i < chunkLength; i++) {
				a += data[offset + i];
				b += a;
			}

			a %= Mod;
			b %= Mod;
			offset += chunkLength;
		}

		return BitConverter.GetBytes((b << 16) | a);
	}

	/// <summary>Computes Fletcher-16 checksum.</summary>
	public static byte[] ComputeFletcher16(ReadOnlySpan<byte> data) {
		const uint mod = 255;
		const int chunkSize = 5802;

		uint sum1 = 0;
		uint sum2 = 0;
		var offset = 0;

		while (offset < data.Length) {
			var chunkLength = Math.Min(chunkSize, data.Length - offset);
			var i = 0;
			for (; i <= chunkLength - 4; i += 4) {
				sum1 += data[offset + i];
				sum2 += sum1;
				sum1 += data[offset + i + 1];
				sum2 += sum1;
				sum1 += data[offset + i + 2];
				sum2 += sum1;
				sum1 += data[offset + i + 3];
				sum2 += sum1;
			}

			for (; i < chunkLength; i++) {
				sum1 += data[offset + i];
				sum2 += sum1;
			}

			sum1 %= mod;
			sum2 %= mod;
			offset += chunkLength;
		}

		return BitConverter.GetBytes((ushort)((sum2 << 8) | sum1));
	}

	/// <summary>Computes Fletcher-32 checksum.</summary>
	public static byte[] ComputeFletcher32(ReadOnlySpan<byte> data) {
		const uint mod = 65535;
		const int chunkSize = 5802;

		uint sum1 = 0;
		uint sum2 = 0;
		var offset = 0;

		while (offset < data.Length) {
			var chunkLength = Math.Min(chunkSize, data.Length - offset);
			var i = 0;
			for (; i <= chunkLength - 4; i += 4) {
				sum1 += data[offset + i];
				sum2 += sum1;
				sum1 += data[offset + i + 1];
				sum2 += sum1;
				sum1 += data[offset + i + 2];
				sum2 += sum1;
				sum1 += data[offset + i + 3];
				sum2 += sum1;
			}

			for (; i < chunkLength; i++) {
				sum1 += data[offset + i];
				sum2 += sum1;
			}

			sum1 %= mod;
			sum2 %= mod;
			offset += chunkLength;
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

	/// <summary>Computes CRC-16-CCITT.</summary>
	public static byte[] ComputeCrc16Ccitt(ReadOnlySpan<byte> data) {
		using var hasher = new Crc16Streaming(Crc16Variant.Ccitt);
		hasher.Update(data);
		ushort result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes CRC-16-MODBUS.</summary>
	public static byte[] ComputeCrc16Modbus(ReadOnlySpan<byte> data) {
		using var hasher = new Crc16Streaming(Crc16Variant.Modbus);
		hasher.Update(data);
		ushort result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes CRC-16-USB.</summary>
	public static byte[] ComputeCrc16Usb(ReadOnlySpan<byte> data) {
		using var hasher = new Crc16Streaming(Crc16Variant.Usb);
		hasher.Update(data);
		ushort result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes FNV-1a 32-bit hash.</summary>
	public static byte[] ComputeFnv1a32(ReadOnlySpan<byte> data) {
		using var hasher = new Fnv1a32Streaming();
		hasher.Update(data);
		uint result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes FNV-1a 64-bit hash.</summary>
	public static byte[] ComputeFnv1a64(ReadOnlySpan<byte> data) {
		using var hasher = new Fnv1a64Streaming();
		hasher.Update(data);
		ulong result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes DJB2 hash.</summary>
	public static byte[] ComputeDjb2(ReadOnlySpan<byte> data) {
		using var hasher = new Djb2Streaming();
		hasher.Update(data);
		uint result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes DJB2a (XOR variant) hash.</summary>
	public static byte[] ComputeDjb2a(ReadOnlySpan<byte> data) {
		using var hasher = new Djb2Streaming(useXor: true);
		hasher.Update(data);
		uint result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes SDBM hash.</summary>
	public static byte[] ComputeSdbm(ReadOnlySpan<byte> data) {
		using var hasher = new SdbmStreaming();
		hasher.Update(data);
		uint result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes Lose Lose hash (K&amp;R).</summary>
	public static byte[] ComputeLoseLose(ReadOnlySpan<byte> data) {
		using var hasher = new LoseLoseStreaming();
		hasher.Update(data);
		uint result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	/// <summary>Computes SHA-0 hash (legacy, cryptographically broken).</summary>
	public static byte[] ComputeSha0(ReadOnlySpan<byte> data) {
		using var hasher = new Sha0StreamingHash();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes Groestl-256 hash.</summary>
	public static byte[] ComputeGroestl256(ReadOnlySpan<byte> data) {
		using var hasher = new GroestlDigest(256);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes Groestl-512 hash.</summary>
	public static byte[] ComputeGroestl512(ReadOnlySpan<byte> data) {
		using var hasher = new GroestlDigest(512);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes JH-256 hash.</summary>
	public static byte[] ComputeJh256(ReadOnlySpan<byte> data) {
		using var hasher = new JHDigest(256);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes JH-512 hash.</summary>
	public static byte[] ComputeJh512(ReadOnlySpan<byte> data) {
		using var hasher = new JHDigest(512);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>Computes Whirlpool hash.</summary>
	public static byte[] ComputeWhirlpool(ReadOnlySpan<byte> data) {
		using var hasher = new WhirlpoolDigest();
		hasher.Update(data);
		return hasher.Finalize();
	}

	/// <summary>Computes KangarooTwelve hash.</summary>
	public static byte[] ComputeKangarooTwelveHash(ReadOnlySpan<byte> data) {
		using var hasher = new KangarooTwelve();
		hasher.Update(data);
		return hasher.Finalize();
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
			HashAlgorithm.Crc32C => new Crc32CStreamingAdapter(),
			HashAlgorithm.Crc64 => new NonCryptoHashAdapter64(new Crc64()),
			HashAlgorithm.Crc16Ccitt => new StreamingHashBytesAdapter<ushort>(new Crc16Streaming(Crc16Variant.Ccitt)),
			HashAlgorithm.Crc16Modbus => new StreamingHashBytesAdapter<ushort>(new Crc16Streaming(Crc16Variant.Modbus)),
			HashAlgorithm.Crc16Usb => new StreamingHashBytesAdapter<ushort>(new Crc16Streaming(Crc16Variant.Usb)),
			HashAlgorithm.Adler32 => new Adler32StreamingAdapter(),
			HashAlgorithm.Fletcher16 => new Fletcher16StreamingAdapter(),
			HashAlgorithm.Fletcher32 => new Fletcher32StreamingAdapter(),

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
			HashAlgorithm.Fnv1a32 => new StreamingHashBytesAdapter<uint>(new Fnv1a32Streaming()),
			HashAlgorithm.Fnv1a64 => new StreamingHashBytesAdapter<ulong>(new Fnv1a64Streaming()),
			HashAlgorithm.Djb2 => new StreamingHashBytesAdapter<uint>(new Djb2Streaming()),
			HashAlgorithm.Djb2a => new StreamingHashBytesAdapter<uint>(new Djb2Streaming(useXor: true)),
			HashAlgorithm.Sdbm => new StreamingHashBytesAdapter<uint>(new SdbmStreaming()),
			HashAlgorithm.LoseLose => new StreamingHashBytesAdapter<uint>(new LoseLoseStreaming()),

			// MD Family (acryptohashnet for MD2/MD4, .NET for MD5)
			HashAlgorithm.Md2 => AcryptohashnetFactory.CreateMd2(),
			HashAlgorithm.Md4 => AcryptohashnetFactory.CreateMd4(),
			HashAlgorithm.Md5 => new IncrementalHashAdapter(System.Security.Cryptography.HashAlgorithmName.MD5),

			// SHA-1/2 Family (acryptohashnet for SHA-0/224, .NET for rest)
			HashAlgorithm.Sha0 => AcryptohashnetFactory.CreateSha0(),
			HashAlgorithm.Sha1 => new IncrementalHashAdapter(System.Security.Cryptography.HashAlgorithmName.SHA1),
			HashAlgorithm.Sha224 => AcryptohashnetFactory.CreateSha224(),
			HashAlgorithm.Sha256 => new IncrementalHashAdapter(System.Security.Cryptography.HashAlgorithmName.SHA256),
			HashAlgorithm.Sha384 => new IncrementalHashAdapter(System.Security.Cryptography.HashAlgorithmName.SHA384),
			HashAlgorithm.Sha512 => new IncrementalHashAdapter(System.Security.Cryptography.HashAlgorithmName.SHA512),
			HashAlgorithm.Sha512_224 => Sha512tFactory.CreateSha512_224(),
			HashAlgorithm.Sha512_256 => Sha512tFactory.CreateSha512_256(),

			// SHA-3 (Native implementation) & Keccak (Native implementation)
			HashAlgorithm.Sha3_224 => NativeSha3Factory.CreateSha3_224(),
			HashAlgorithm.Sha3_256 => NativeSha3Factory.CreateSha3_256(),
			HashAlgorithm.Sha3_384 => NativeSha3Factory.CreateSha3_384(),
			HashAlgorithm.Sha3_512 => NativeSha3Factory.CreateSha3_512(),
			HashAlgorithm.Keccak256 => NativeSha3Factory.CreateKeccak256(),
			HashAlgorithm.Keccak512 => NativeSha3Factory.CreateKeccak512(),

			// BLAKE Family (Blake2Fast for BLAKE2, Blake3.NET for BLAKE3)
			HashAlgorithm.Blake256 => Blake2Factory.CreateBlake256(),
			HashAlgorithm.Blake512 => Blake2Factory.CreateBlake512(),
			HashAlgorithm.Blake2b => Blake2Factory.CreateBlake2b(),
			HashAlgorithm.Blake2s => Blake2Factory.CreateBlake2s(),
			HashAlgorithm.Blake3 => Blake3Factory.CreateBlake3(),

			// RIPEMD Family (acryptohashnet for 128/160, native for 256/320)
			HashAlgorithm.Ripemd128 => AcryptohashnetFactory.CreateRipemd128(),
			HashAlgorithm.Ripemd160 => AcryptohashnetFactory.CreateRipemd160(),
			HashAlgorithm.Ripemd256 => Ripemd256Factory.CreateRipemd256(),
			HashAlgorithm.Ripemd320 => Ripemd320Factory.CreateRipemd320(),

			// Other Crypto (native for GOST-94, Streebog, Skein)
			HashAlgorithm.Whirlpool => new WhirlpoolDigest(),
			HashAlgorithm.Tiger192 => AcryptohashnetFactory.CreateTiger192(),
			HashAlgorithm.Gost94 => new NativeGost94(),
			HashAlgorithm.Streebog256 => StreebogFactory.CreateStreebog256(),
			HashAlgorithm.Streebog512 => StreebogFactory.CreateStreebog512(),
			HashAlgorithm.Skein256 => SkeinOptimizedFactory.CreateSkein256(),
			HashAlgorithm.Skein512 => SkeinOptimizedFactory.CreateSkein512(),
			HashAlgorithm.Skein1024 => SkeinOptimizedFactory.CreateSkein1024(),
			HashAlgorithm.Groestl256 => new Groestl256(),
			HashAlgorithm.Groestl512 => new Groestl512(),
			HashAlgorithm.Jh256 => new JH256(),
			HashAlgorithm.Jh512 => new JH512(),
			HashAlgorithm.Sm3 => Sm3Factory.CreateSm3(),

			_ => throw new NotSupportedException($"Streaming not supported for {algorithm}.")
		};
	}

	/// <summary>
	/// Creates a batch streaming context for multiple algorithms.
	/// Efficiently processes all selected algorithms with a single memory pass.
	/// </summary>
	/// <param name="algorithms">Flags indicating which algorithm sets to include.</param>
	/// <returns>A streaming context that updates all selected algorithms efficiently.</returns>
	/// <remarks>
	/// <para>
	/// This method creates a streaming context that can update multiple hash algorithms
	/// simultaneously using parallel processing. On multi-core systems, this provides
	/// significant performance improvements (8-16x faster) compared to computing each
	/// hash sequentially.
	/// </para>
	/// <para>
	/// The batch context uses parallel processing for efficient multi-core utilization.
	/// All algorithms are updated with a single memory pass to maximize cache efficiency.
	/// </para>
	/// </remarks>
	/// <example>
	/// <code>
	/// // Hash all 71 algorithms at once
	/// using var batchHasher = HashFacade.CreateAllStreaming();
	/// using var stream = File.OpenRead("large-file.bin");
	/// var buffer = new byte[1024 * 1024];  // 1MB buffer
	/// int bytesRead;
	/// while ((bytesRead = stream.Read(buffer)) > 0) {
	///     batchHasher.Update(buffer.AsSpan(0, bytesRead));
	/// }
	/// var results = batchHasher.FinalizeAll();
	/// // results["SHA-256"] = "abc123..."
	/// // results["BLAKE3"] = "def456..."
	/// // ... all 71 results
	/// </code>
	/// </example>
	public static IMultiStreamingHashBytes CreateAllStreaming(HashAlgorithmSet algorithms = HashAlgorithmSet.All) {
		var selectedAlgorithms = new List<string>();

		// Add checksums
		if (algorithms.HasFlag(HashAlgorithmSet.Checksums)) {
			selectedAlgorithms.AddRange(HashAlgorithmNames.Checksums);
		}

		// Add fast non-crypto
		if (algorithms.HasFlag(HashAlgorithmSet.FastNonCrypto)) {
			selectedAlgorithms.AddRange(HashAlgorithmNames.FastNonCrypto);
		}

		// Add cryptographic
		if (algorithms.HasFlag(HashAlgorithmSet.Cryptographic)) {
			selectedAlgorithms.AddRange(HashAlgorithmNames.Cryptographic);
		}

		// Add experimental/other crypto (Note: These are included in Cryptographic array)
		if (algorithms.HasFlag(HashAlgorithmSet.Experimental)) {
			selectedAlgorithms.AddRange(new[] {
				HashAlgorithmNames.Whirlpool, HashAlgorithmNames.Tiger192, HashAlgorithmNames.Gost94,
				HashAlgorithmNames.Streebog256, HashAlgorithmNames.Streebog512,
				HashAlgorithmNames.Skein256, HashAlgorithmNames.Skein512, HashAlgorithmNames.Skein1024,
				HashAlgorithmNames.Groestl256, HashAlgorithmNames.Groestl512,
				HashAlgorithmNames.Jh256, HashAlgorithmNames.Jh512,
				HashAlgorithmNames.KangarooTwelve, HashAlgorithmNames.Sm3
			});
		}

		return new Implementation.MultiStreamingHashBytes(selectedAlgorithms);
	}

	/// <summary>
	/// Creates a batch streaming context for specific algorithms.
	/// </summary>
	/// <param name="algorithmNames">Names of specific algorithms to include (case-insensitive).</param>
	/// <returns>A streaming context that updates the selected algorithms efficiently.</returns>
	/// <remarks>
	/// <para>
	/// Use this method when you need a specific subset of algorithms rather than
	/// entire categories. Algorithm names are case-insensitive.
	/// </para>
	/// <para>
	/// Valid algorithm names include: "SHA-256", "BLAKE3", "xxHash64", "MurmurHash3-128", etc.
	/// </para>
	/// </remarks>
	/// <example>
	/// <code>
	/// // Hash with just SHA-256, BLAKE3, and xxHash64
	/// using var customHasher = HashFacade.CreateBatchStreaming(
	///     "SHA-256", "BLAKE3", "xxHash64");
	/// customHasher.Update(data);
	/// var hashes = customHasher.FinalizeAll();
	/// </code>
	/// </example>
	/// <exception cref="NotSupportedException">Thrown if an algorithm name is not recognized.</exception>
	public static IMultiStreamingHashBytes CreateBatchStreaming(params string[] algorithmNames) {
		if (algorithmNames == null || algorithmNames.Length == 0) {
			throw new ArgumentException("At least one algorithm name must be specified.", nameof(algorithmNames));
		}
		return new Implementation.MultiStreamingHashBytes(algorithmNames);
	}

	/// <summary>
	/// Creates a specialized batch streaming context for the four most common hash algorithms.
	/// This is optimized for the common use case of verifying file integrity with standard hashes.
	/// </summary>
	/// <returns>A streaming context for CRC32, MD5, SHA-1, and SHA-256.</returns>
	/// <remarks>
	/// <para>
	/// This method provides a convenient way to compute the four most commonly used hash algorithms
	/// for file verification and integrity checking: CRC32, MD5, SHA-1, and SHA-256.
	/// It's significantly faster than computing all 70 algorithms when you only need these basic hashes.
	/// </para>
	/// <para>
	/// Common use cases:
	/// <list type="bullet">
	/// <item><description>File integrity verification (SHA-256)</description></item>
	/// <item><description>Legacy compatibility (MD5, SHA-1)</description></item>
	/// <item><description>Corruption detection (CRC32)</description></item>
	/// <item><description>Download verification</description></item>
	/// <item><description>Archive validation</description></item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <example>
	/// <code>
	/// // Hash a file with the 4 basic algorithms
	/// using var basicHasher = HashFacade.CreateBasicHashesStreaming();
	/// using var stream = File.OpenRead("download.zip");
	/// var buffer = new byte[16 * 1024 * 1024];  // 16MB buffer
	/// int bytesRead;
	/// while ((bytesRead = stream.Read(buffer)) > 0) {
	///     basicHasher.Update(buffer.AsSpan(0, bytesRead));
	/// }
	/// var results = basicHasher.FinalizeAll();
	/// Console.WriteLine($"CRC32:  {results["CRC32"]}");
	/// Console.WriteLine($"MD5:    {results["MD5"]}");
	/// Console.WriteLine($"SHA-1:  {results["SHA-1"]}");
	/// Console.WriteLine($"SHA-256: {results["SHA-256"]}");
	/// </code>
	/// </example>
	public static IMultiStreamingHashBytes CreateBasicHashesStreaming() {
		return new Implementation.MultiStreamingHashBytes(HashAlgorithmNames.BasicHashes);
	}

	#endregion

	#region Algorithm Information

	/// <summary>
	/// Gets a list of all supported algorithm names.
	/// </summary>
	/// <returns>Array of all 70 algorithm names.</returns>
	public static string[] GetAllAlgorithmNames() {
		return HashAlgorithmNames.All;
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
			HashAlgorithm.Crc16Ccitt => new(2, false, "CRC-16-CCITT"),
			HashAlgorithm.Crc16Modbus => new(2, false, "CRC-16-MODBUS"),
			HashAlgorithm.Crc16Usb => new(2, false, "CRC-16-USB"),
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
			HashAlgorithm.Fnv1a32 => new(4, false, "FNV-1a (32-bit)"),
			HashAlgorithm.Fnv1a64 => new(8, false, "FNV-1a (64-bit)"),
			HashAlgorithm.Djb2 => new(4, false, "DJB2"),
			HashAlgorithm.Djb2a => new(4, false, "DJB2a (XOR variant)"),
			HashAlgorithm.Sdbm => new(4, false, "SDBM"),
			HashAlgorithm.LoseLose => new(4, false, "Lose Lose"),

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
