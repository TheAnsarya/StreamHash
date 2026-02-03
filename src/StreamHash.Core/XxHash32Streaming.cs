using System.IO.Hashing;

namespace StreamHash.Core;

/// <summary>
/// Streaming wrapper for xxHash32 using System.IO.Hashing.XxHash32.
/// </summary>
/// <remarks>
/// <para>
/// xxHash is a non-cryptographic hash algorithm created by Yann Collet, focusing on
/// speed and quality. xxHash32 produces a 32-bit hash value.
/// </para>
/// <para>
/// This wrapper provides <see cref="IStreamingHash{TResult}"/> compatibility around
/// the built-in .NET implementation.
/// </para>
/// <para>
/// <b>Performance:</b> Extremely fast, typically 10-20 GB/s on modern hardware.
/// </para>
/// <para>
/// <b>Example:</b>
/// <code>
/// using var hasher = new XxHash32Streaming();
/// hasher.Update(data1);
/// hasher.Update(data2);
/// uint hash = hasher.Finalize();
/// </code>
/// </para>
/// </remarks>
/// <seealso href="https://xxhash.com/">xxHash official site</seealso>
public sealed class XxHash32Streaming : IStreamingHash<uint> {
	private XxHash32 _hasher;
	private bool _finalized;
	private bool _disposed;
	private long _totalBytes;

	/// <summary>
	/// The block size for xxHash32 (4 bytes).
	/// </summary>
	public const int BlockSizeValue = 4;

	/// <summary>
	/// The digest size for xxHash32 (4 bytes).
	/// </summary>
	public const int DigestSizeValue = 4;

	/// <inheritdoc/>
	public int BlockSize => BlockSizeValue;

	/// <inheritdoc/>
	public int DigestSize => DigestSizeValue;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// Initializes a new instance with default seed (0).
	/// </summary>
	public XxHash32Streaming() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	public XxHash32Streaming(int seed) {
		_hasher = new XxHash32(seed);
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
	public uint Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Finalize() has already been called. Call Reset() before computing a new hash.");
		}

		_finalized = true;
		return _hasher.GetCurrentHashAsUInt32();
	}

	/// <summary>
	/// Finalizes and returns the hash as a byte array.
	/// </summary>
	/// <returns>The 4-byte hash value.</returns>
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
	/// Computes xxHash32 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 32-bit hash value.</returns>
	public static uint Hash(ReadOnlySpan<byte> data, int seed = 0) {
		return XxHash32.HashToUInt32(data, seed);
	}

	/// <summary>
	/// Computes xxHash32 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array.</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, int seed = 0) {
		var result = new byte[4];
		XxHash32.Hash(data, result, seed);
		return result;
	}
}
