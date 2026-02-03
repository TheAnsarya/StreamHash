using System.IO.Hashing;

namespace StreamHash.Core;

/// <summary>
/// Streaming wrapper for xxHash3 (XXH3) using System.IO.Hashing.XxHash3.
/// </summary>
/// <remarks>
/// <para>
/// xxHash3 is the latest generation of the xxHash family, designed by Yann Collet.
/// It offers excellent performance across all input sizes, with particularly
/// strong performance on small inputs where previous xxHash versions were slower.
/// </para>
/// <para>
/// This wrapper provides <see cref="IStreamingHash{TResult}"/> compatibility around
/// the built-in .NET implementation.
/// </para>
/// <para>
/// <b>Performance:</b> State-of-the-art performance, typically 20-50+ GB/s on modern hardware
/// with SIMD support. Excellent for both small and large inputs.
/// </para>
/// <para>
/// <b>Example:</b>
/// <code>
/// using var hasher = new XxHash3Streaming();
/// hasher.Update(data1);
/// hasher.Update(data2);
/// ulong hash = hasher.Finalize();
/// </code>
/// </para>
/// </remarks>
/// <seealso href="https://xxhash.com/">xxHash official site</seealso>
/// <seealso href="https://github.com/Cyan4973/xxHash">xxHash GitHub repository</seealso>
public sealed class XxHash3Streaming : IStreamingHash<ulong> {
	private XxHash3 _hasher;
	private bool _finalized;
	private bool _disposed;
	private long _totalBytes;

	/// <summary>
	/// The internal block size for xxHash3 (256 bytes for vectorized processing).
	/// </summary>
	public const int BlockSizeValue = 256;

	/// <summary>
	/// The digest size for xxHash3 64-bit (8 bytes).
	/// </summary>
	public const int DigestSizeValue = 8;

	/// <inheritdoc/>
	public int BlockSize => BlockSizeValue;

	/// <inheritdoc/>
	public int DigestSize => DigestSizeValue;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// Initializes a new instance with default seed (0).
	/// </summary>
	public XxHash3Streaming() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	public XxHash3Streaming(long seed) {
		_hasher = new XxHash3(seed);
		_finalized = false;
		_disposed = false;
		_totalBytes = 0;
	}

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Cannot update after Finalize() has been called. Call Reset() first.");
		}

		_hasher.Append(data);
		_totalBytes += data.Length;
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		ArgumentNullException.ThrowIfNull(data);
		Update(data.AsSpan(offset, length));
	}

	/// <inheritdoc/>
	public ulong Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Finalize() has already been called. Call Reset() before computing a new hash.");
		}

		_finalized = true;
		return _hasher.GetCurrentHashAsUInt64();
	}

	/// <summary>
	/// Finalizes and returns the hash as a byte array.
	/// </summary>
	/// <returns>The 8-byte hash value.</returns>
	public byte[] FinalizeToBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Finalize() has already been called. Call Reset() before computing a new hash.");
		}

		_finalized = true;
		return _hasher.GetCurrentHash();
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		_hasher.Reset();
		_finalized = false;
		_totalBytes = 0;
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (!_disposed) {
			_disposed = true;
		}
	}

	/// <summary>
	/// Computes xxHash3 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong Hash(ReadOnlySpan<byte> data, long seed = 0) {
		return XxHash3.HashToUInt64(data, seed);
	}

	/// <summary>
	/// Computes xxHash3 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array.</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, long seed = 0) {
		var result = new byte[8];
		XxHash3.Hash(data, result, seed);
		return result;
	}
}
