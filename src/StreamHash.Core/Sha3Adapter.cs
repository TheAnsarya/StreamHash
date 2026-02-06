using nebulae.dotSHA3;
using StreamHash.Core.Abstractions;

namespace StreamHash.Core;

/// <summary>
/// Streaming adapter for SHA-3 using nebulae.dotSHA3 (XKCP native implementation).
/// </summary>
/// <remarks>
/// <para>
/// nebulae.dotSHA3 wraps the XKCP (eXtended Keccak Code Package) optimized SHA-3 C implementation
/// with SIMD acceleration (AVX2 on x64, NEON on ARM64).
/// </para>
/// <para>
/// This adapter replaces BouncyCastle's Sha3Digest for:
/// <list type="bullet">
/// <item><description>Native SIMD-accelerated Keccak permutation</description></item>
/// <item><description>Cross-platform (Windows x64, Linux x64, macOS x64/ARM64)</description></item>
/// <item><description>Same speed as System.Security.Cryptography SHA3 but with streaming support</description></item>
/// </list>
/// </para>
/// <para>
/// <b>Note:</b> This adapter only supports SHA-3 (FIPS 202 padding: 0x06).
/// For Keccak (original padding: 0x01), use BouncyCastle's KeccakDigest.
/// </para>
/// </remarks>
internal sealed class Sha3StreamingAdapter : IStreamingHashBytes, IDisposable {
	/// <summary>
	/// The SHA-3 digest size in bytes.
	/// </summary>
	private readonly int _digestSize;

	/// <summary>
	/// The SHA-3 algorithm variant.
	/// </summary>
	private readonly SHA3Algorithm _algorithm;

	/// <summary>
	/// SHA-3 rate (block size) in bytes for the specified digest size.
	/// </summary>
	public int BlockSize => _algorithm switch {
		SHA3Algorithm.Sha3_224 => 144, // 1152 bits
		SHA3Algorithm.Sha3_256 => 136, // 1088 bits
		SHA3Algorithm.Sha3_384 => 104, // 832 bits
		SHA3Algorithm.Sha3_512 => 72,  // 576 bits
		_ => 136 // Default to SHA3-256
	};

	/// <summary>
	/// The digest size in bytes.
	/// </summary>
	public int DigestSize => _digestSize;

	/// <summary>
	/// Total bytes processed (for diagnostics).
	/// </summary>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// The underlying dotSHA3 hasher instance.
	/// </summary>
	private SHA3 _hasher;

	/// <summary>
	/// Total bytes processed.
	/// </summary>
	private long _totalBytes;

	/// <summary>
	/// Creates a new SHA-3 streaming adapter with specified digest size.
	/// </summary>
	/// <param name="digestSize">The digest size in bits (224, 256, 384, or 512).</param>
	public Sha3StreamingAdapter(int digestSize) {
		_algorithm = digestSize switch {
			224 => SHA3Algorithm.Sha3_224,
			256 => SHA3Algorithm.Sha3_256,
			384 => SHA3Algorithm.Sha3_384,
			512 => SHA3Algorithm.Sha3_512,
			_ => throw new ArgumentException($"Invalid SHA-3 digest size: {digestSize}. Must be 224, 256, 384, or 512.", nameof(digestSize))
		};

		_digestSize = digestSize / 8; // Convert bits to bytes
		_hasher = new SHA3(_algorithm);
	}

	/// <inheritdoc />
	public void Update(ReadOnlySpan<byte> data) {
		_hasher.Update(data);
		_totalBytes += data.Length;
	}

	/// <inheritdoc />
	public byte[] FinalizeBytes() {
		return _hasher.FinalizeHash();
	}

	/// <inheritdoc />
	public void Reset() {
		// Dispose and recreate the hasher for reset
		_hasher.Dispose();
		_hasher = new SHA3(_algorithm);
		_totalBytes = 0;
	}

	/// <inheritdoc />
	public void Dispose() {
		_hasher.Dispose();
	}
}

/// <summary>
/// Static factory methods for nebulae.dotSHA3 integration.
/// </summary>
internal static class Sha3Factory {
	/// <summary>
	/// Creates a new SHA3-224 streaming adapter (28 bytes / 224 bits).
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for SHA3-224.</returns>
	public static IStreamingHashBytes CreateSha3_224() => new Sha3StreamingAdapter(224);

	/// <summary>
	/// Creates a new SHA3-256 streaming adapter (32 bytes / 256 bits).
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for SHA3-256.</returns>
	public static IStreamingHashBytes CreateSha3_256() => new Sha3StreamingAdapter(256);

	/// <summary>
	/// Creates a new SHA3-384 streaming adapter (48 bytes / 384 bits).
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for SHA3-384.</returns>
	public static IStreamingHashBytes CreateSha3_384() => new Sha3StreamingAdapter(384);

	/// <summary>
	/// Creates a new SHA3-512 streaming adapter (64 bytes / 512 bits).
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for SHA3-512.</returns>
	public static IStreamingHashBytes CreateSha3_512() => new Sha3StreamingAdapter(512);

	/// <summary>
	/// Computes SHA3-224 hash in one shot using SIMD-accelerated implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 224-bit SHA3 hash as a byte array.</returns>
	public static byte[] ComputeSha3_224(ReadOnlySpan<byte> data) {
		using var sha3 = new SHA3(SHA3Algorithm.Sha3_224);
		return sha3.ComputeHash(data);
	}

	/// <summary>
	/// Computes SHA3-256 hash in one shot using SIMD-accelerated implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 256-bit SHA3 hash as a byte array.</returns>
	public static byte[] ComputeSha3_256(ReadOnlySpan<byte> data) {
		using var sha3 = new SHA3(SHA3Algorithm.Sha3_256);
		return sha3.ComputeHash(data);
	}

	/// <summary>
	/// Computes SHA3-384 hash in one shot using SIMD-accelerated implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 384-bit SHA3 hash as a byte array.</returns>
	public static byte[] ComputeSha3_384(ReadOnlySpan<byte> data) {
		using var sha3 = new SHA3(SHA3Algorithm.Sha3_384);
		return sha3.ComputeHash(data);
	}

	/// <summary>
	/// Computes SHA3-512 hash in one shot using SIMD-accelerated implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 512-bit SHA3 hash as a byte array.</returns>
	public static byte[] ComputeSha3_512(ReadOnlySpan<byte> data) {
		using var sha3 = new SHA3(SHA3Algorithm.Sha3_512);
		return sha3.ComputeHash(data);
	}
}
