using Blake2Fast;
using StreamHash.Core.Abstractions;

namespace StreamHash.Core;

/// <summary>
/// Streaming adapter for BLAKE2b using SauceControl.Blake2Fast.
/// </summary>
/// <remarks>
/// <para>
/// SauceControl.Blake2Fast provides the fastest RFC 7693-compliant BLAKE2 implementation for .NET,
/// with SIMD acceleration (SSE2, SSE4.1, AVX2, AVX-512) and minimal memory allocation (32 bytes).
/// </para>
/// <para>
/// This adapter replaces BouncyCastle's Blake2bDigest for:
/// <list type="bullet">
/// <item><description>Zero-copy incremental hashing via spans</description></item>
/// <item><description>5-10x faster hashing with SIMD acceleration</description></item>
/// <item><description>~100MB allocation reduction per 50MB file vs BouncyCastle</description></item>
/// </list>
/// </para>
/// </remarks>
internal sealed class Blake2bStreamingAdapter : IStreamingHashBytes {
	/// <summary>
	/// The BLAKE2b digest size in bytes.
	/// </summary>
	private readonly int _digestSize;

	/// <summary>
	/// BLAKE2b block size in bytes (128 bytes = 1024 bits).
	/// </summary>
	public int BlockSize => 128;

	/// <summary>
	/// The digest size in bytes.
	/// </summary>
	public int DigestSize => _digestSize;

	/// <summary>
	/// Total bytes processed (for diagnostics).
	/// </summary>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// The underlying Blake2Fast incremental hasher.
	/// </summary>
	private IBlake2Incremental _hasher;

	/// <summary>
	/// Total bytes processed.
	/// </summary>
	private long _totalBytes;

	/// <summary>
	/// Creates a new BLAKE2b streaming adapter with specified digest size.
	/// </summary>
	/// <param name="digestSize">The digest size in bytes (1-64). Default is 64 (512 bits).</param>
	public Blake2bStreamingAdapter(int digestSize = 64) {
		ArgumentOutOfRangeException.ThrowIfLessThan(digestSize, 1);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSize, 64);

		_digestSize = digestSize;
		_hasher = Blake2b.CreateIncrementalHasher(digestSize);
	}

	/// <inheritdoc />
	public void Update(ReadOnlySpan<byte> data) {
		_hasher.Update(data);
		_totalBytes += data.Length;
	}

	/// <inheritdoc />
	public byte[] FinalizeBytes() {
		return _hasher.Finish();
	}

	/// <inheritdoc />
	public void Reset() {
		// Blake2Fast doesn't support reset, recreate the hasher
		_hasher = Blake2b.CreateIncrementalHasher(_digestSize);
		_totalBytes = 0;
	}

	/// <inheritdoc />
	public void Dispose() {
		// Blake2Fast incremental hasher is a struct, no disposal needed
	}
}

/// <summary>
/// Streaming adapter for BLAKE2s using SauceControl.Blake2Fast.
/// </summary>
/// <remarks>
/// <para>
/// BLAKE2s is optimized for 8-bit to 32-bit platforms, with a smaller state size than BLAKE2b.
/// SauceControl.Blake2Fast provides SIMD-accelerated implementation with minimal allocations.
/// </para>
/// </remarks>
internal sealed class Blake2sStreamingAdapter : IStreamingHashBytes {
	/// <summary>
	/// The BLAKE2s digest size in bytes.
	/// </summary>
	private readonly int _digestSize;

	/// <summary>
	/// BLAKE2s block size in bytes (64 bytes = 512 bits).
	/// </summary>
	public int BlockSize => 64;

	/// <summary>
	/// The digest size in bytes.
	/// </summary>
	public int DigestSize => _digestSize;

	/// <summary>
	/// Total bytes processed (for diagnostics).
	/// </summary>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// The underlying Blake2Fast incremental hasher.
	/// </summary>
	private IBlake2Incremental _hasher;

	/// <summary>
	/// Total bytes processed.
	/// </summary>
	private long _totalBytes;

	/// <summary>
	/// Creates a new BLAKE2s streaming adapter with specified digest size.
	/// </summary>
	/// <param name="digestSize">The digest size in bytes (1-32). Default is 32 (256 bits).</param>
	public Blake2sStreamingAdapter(int digestSize = 32) {
		ArgumentOutOfRangeException.ThrowIfLessThan(digestSize, 1);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSize, 32);

		_digestSize = digestSize;
		_hasher = Blake2s.CreateIncrementalHasher(digestSize);
	}

	/// <inheritdoc />
	public void Update(ReadOnlySpan<byte> data) {
		_hasher.Update(data);
		_totalBytes += data.Length;
	}

	/// <inheritdoc />
	public byte[] FinalizeBytes() {
		return _hasher.Finish();
	}

	/// <inheritdoc />
	public void Reset() {
		// Blake2Fast doesn't support reset, recreate the hasher
		_hasher = Blake2s.CreateIncrementalHasher(_digestSize);
		_totalBytes = 0;
	}

	/// <inheritdoc />
	public void Dispose() {
		// Blake2Fast incremental hasher is a struct, no disposal needed
	}
}

/// <summary>
/// Static factory methods for Blake2Fast integration.
/// </summary>
internal static class Blake2Factory {
	/// <summary>
	/// Creates a new BLAKE2b streaming adapter with 512-bit (64 byte) digest.
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for BLAKE2b-512.</returns>
	public static IStreamingHashBytes CreateBlake2b() => new Blake2bStreamingAdapter(64);

	/// <summary>
	/// Creates a new BLAKE2b streaming adapter with 256-bit (32 byte) digest.
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for BLAKE2b-256 (BLAKE-256).</returns>
	public static IStreamingHashBytes CreateBlake256() => new Blake2bStreamingAdapter(32);

	/// <summary>
	/// Creates a new BLAKE2b streaming adapter with 512-bit (64 byte) digest.
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for BLAKE2b-512 (BLAKE-512).</returns>
	public static IStreamingHashBytes CreateBlake512() => new Blake2bStreamingAdapter(64);

	/// <summary>
	/// Creates a new BLAKE2s streaming adapter with 256-bit (32 byte) digest.
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for BLAKE2s-256.</returns>
	public static IStreamingHashBytes CreateBlake2s() => new Blake2sStreamingAdapter(32);

	/// <summary>
	/// Computes BLAKE2b-512 hash in one shot using SIMD-accelerated implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 512-bit BLAKE2b hash as a byte array.</returns>
	public static byte[] ComputeBlake2b(ReadOnlySpan<byte> data) {
		return Blake2b.ComputeHash(data);
	}

	/// <summary>
	/// Computes BLAKE2b-256 (BLAKE-256) hash in one shot using SIMD-accelerated implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 256-bit BLAKE2b hash as a byte array.</returns>
	public static byte[] ComputeBlake256(ReadOnlySpan<byte> data) {
		return Blake2b.ComputeHash(32, data);
	}

	/// <summary>
	/// Computes BLAKE2b-512 (BLAKE-512) hash in one shot using SIMD-accelerated implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 512-bit BLAKE2b hash as a byte array.</returns>
	public static byte[] ComputeBlake512(ReadOnlySpan<byte> data) {
		return Blake2b.ComputeHash(64, data);
	}

	/// <summary>
	/// Computes BLAKE2s-256 hash in one shot using SIMD-accelerated implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 256-bit BLAKE2s hash as a byte array.</returns>
	public static byte[] ComputeBlake2s(ReadOnlySpan<byte> data) {
		return Blake2s.ComputeHash(data);
	}
}
