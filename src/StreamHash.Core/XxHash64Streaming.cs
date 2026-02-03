using System.IO.Hashing;

namespace StreamHash.Core;

/// <summary>
/// Streaming wrapper for xxHash64 using System.IO.Hashing.XxHash64.
/// </summary>
/// <remarks>
/// <para>
/// xxHash is a non-cryptographic hash algorithm created by Yann Collet, focusing on
/// speed and quality. xxHash64 produces a 64-bit hash value.
/// </para>
/// <para>
/// This wrapper provides <see cref="IStreamingHash{TResult}"/> compatibility around
/// the built-in .NET implementation.
/// </para>
/// <para>
/// <b>Performance:</b> Extremely fast, typically 15-30 GB/s on modern 64-bit hardware.
/// </para>
/// <para>
/// <b>Example:</b>
/// <code>
/// using var hasher = new XxHash64Streaming();
/// hasher.Update(data1);
/// hasher.Update(data2);
/// ulong hash = hasher.Finalize();
/// </code>
/// </para>
/// </remarks>
/// <seealso href="https://xxhash.com/">xxHash official site</seealso>
public sealed class XxHash64Streaming : IStreamingHash<ulong> {
	private XxHash64 _hasher;
	private bool _finalized;
	private bool _disposed;
	private long _totalBytes;

	/// <summary>
	/// The block size for xxHash64 (32 bytes).
	/// </summary>
	public const int BlockSizeValue = 32;

	/// <summary>
	/// The digest size for xxHash64 (8 bytes).
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
	public XxHash64Streaming() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	public XxHash64Streaming(long seed) {
		_hasher = new XxHash64(seed);
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
	/// Computes xxHash64 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong Hash(ReadOnlySpan<byte> data, long seed = 0) {
		return XxHash64.HashToUInt64(data, seed);
	}

	/// <summary>
	/// Computes xxHash64 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array.</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, long seed = 0) {
		var result = new byte[8];
		XxHash64.Hash(data, result, seed);
		return result;
	}
}
