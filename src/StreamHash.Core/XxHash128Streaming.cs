using System.IO.Hashing;

namespace StreamHash.Core;

/// <summary>
/// Streaming wrapper for xxHash128 using System.IO.Hashing.XxHash128.
/// </summary>
/// <remarks>
/// <para>
/// xxHash128 is the 128-bit variant of xxHash3, designed by Yann Collet.
/// It provides higher collision resistance while maintaining excellent performance.
/// </para>
/// <para>
/// This wrapper provides <see cref="IStreamingHash{TResult}"/> compatibility around
/// the built-in .NET implementation.
/// </para>
/// <para>
/// <b>Performance:</b> State-of-the-art performance, typically 20-50+ GB/s on modern hardware
/// with SIMD support. The 128-bit variant has minimal overhead compared to 64-bit.
/// </para>
/// <para>
/// <b>Example:</b>
/// <code>
/// using var hasher = new XxHash128Streaming();
/// hasher.Update(data1);
/// hasher.Update(data2);
/// UInt128 hash = hasher.Finalize();
/// </code>
/// </para>
/// </remarks>
/// <seealso href="https://xxhash.com/">xxHash official site</seealso>
/// <seealso href="https://github.com/Cyan4973/xxHash">xxHash GitHub repository</seealso>
public sealed class XxHash128Streaming : IStreamingHash<UInt128> {
	private XxHash128 _hasher;
	private bool _finalized;
	private bool _disposed;
	private long _totalBytes;

	/// <summary>
	/// The internal block size for xxHash128 (256 bytes for vectorized processing).
	/// </summary>
	public const int BlockSizeValue = 256;

	/// <summary>
	/// The digest size for xxHash128 (16 bytes).
	/// </summary>
	public const int DigestSizeValue = 16;

	/// <inheritdoc/>
	public int BlockSize => BlockSizeValue;

	/// <inheritdoc/>
	public int DigestSize => DigestSizeValue;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// Initializes a new instance with default seed (0).
	/// </summary>
	public XxHash128Streaming() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	public XxHash128Streaming(long seed) {
		_hasher = new XxHash128(seed);
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
	public UInt128 Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Finalize() has already been called. Call Reset() before computing a new hash.");
		}

		_finalized = true;
		Span<byte> hashBytes = stackalloc byte[16];
		_hasher.GetCurrentHash(hashBytes);

		// Convert to UInt128 (little-endian)
		ulong low = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(hashBytes);
		ulong high = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(hashBytes[8..]);
		return new UInt128(high, low);
	}

	/// <summary>
	/// Finalizes and returns the hash as a byte array.
	/// </summary>
	/// <returns>The 16-byte hash value.</returns>
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
	/// Computes xxHash128 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 128-bit hash value.</returns>
	public static UInt128 Hash(ReadOnlySpan<byte> data, long seed = 0) {
		Span<byte> hashBytes = stackalloc byte[16];
		XxHash128.Hash(data, hashBytes, seed);

		ulong low = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(hashBytes);
		ulong high = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(hashBytes[8..]);
		return new UInt128(high, low);
	}

	/// <summary>
	/// Computes xxHash128 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array.</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, long seed = 0) {
		var result = new byte[16];
		XxHash128.Hash(data, result, seed);
		return result;
	}
}
