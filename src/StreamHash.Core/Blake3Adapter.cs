using Blake3;

namespace StreamHash.Core;

/// <summary>
/// Streaming adapter for Blake3.NET providing <see cref="IStreamingHashBytes"/> interface.
/// </summary>
/// <remarks>
/// <para>
/// Blake3.NET is a managed wrapper around the native SIMD Rust implementation of BLAKE3,
/// providing exceptional performance with hardware acceleration (AVX2/SSE4.1/SSE2).
/// </para>
/// <para>
/// This adapter replaces the BouncyCastle Blake3Digest with Blake3.NET for:
/// <list type="bullet">
/// <item><description>Zero-allocation streaming via <see cref="Hasher"/></description></item>
/// <item><description>10-20x faster hashing than BouncyCastle</description></item>
/// <item><description>SIMD hardware acceleration on all platforms</description></item>
/// </list>
/// </para>
/// </remarks>
internal sealed class Blake3StreamingAdapter : IStreamingHashBytes {
	/// <summary>
	/// BLAKE3 output size in bytes (256 bits = 32 bytes).
	/// </summary>
	private const int DigestLength = 32;

	/// <summary>
	/// BLAKE3 block size in bytes (64 bytes = 512 bits).
	/// </summary>
	private const int BlockLength = 64;

	/// <summary>
	/// The underlying Blake3.NET hasher instance.
	/// </summary>
	private Hasher _hasher;

	/// <summary>
	/// Tracks total bytes processed for statistics.
	/// </summary>
	private long _totalBytes;

	/// <summary>
	/// Creates a new Blake3 streaming adapter.
	/// </summary>
	public Blake3StreamingAdapter() {
		_hasher = Hasher.New();
		_totalBytes = 0;
	}

	/// <inheritdoc />
	public int BlockSize => BlockLength;

	/// <inheritdoc />
	public int DigestSize => DigestLength;

	/// <inheritdoc />
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc />
	public void Update(ReadOnlySpan<byte> data) {
		_hasher.Update(data);
		_totalBytes += data.Length;
	}

	/// <inheritdoc />
	public byte[] FinalizeBytes() {
		// Finalize returns a Hash struct, which we convert to bytes
		Hash hash = _hasher.Finalize();
		return hash.AsSpan().ToArray();
	}

	/// <inheritdoc />
	public void Reset() {
		// Dispose and recreate the hasher for reset
		_hasher.Dispose();
		_hasher = Hasher.New();
		_totalBytes = 0;
	}

	/// <inheritdoc />
	public void Dispose() {
		_hasher.Dispose();
	}
}

/// <summary>
/// Static factory methods for Blake3.NET integration.
/// </summary>
internal static class Blake3Factory {
	/// <summary>
	/// Creates a new Blake3 streaming adapter.
	/// </summary>
	/// <returns>A new <see cref="IStreamingHashBytes"/> instance for BLAKE3.</returns>
	public static IStreamingHashBytes CreateBlake3() => new Blake3StreamingAdapter();

	/// <summary>
	/// Computes BLAKE3 hash in one shot using native SIMD implementation.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 256-bit BLAKE3 hash as a byte array.</returns>
	public static byte[] ComputeHash(ReadOnlySpan<byte> data) {
		// Blake3.NET provides a static Hash method for one-shot hashing
		Hash hash = Hasher.Hash(data);
		return hash.AsSpan().ToArray();
	}
}
