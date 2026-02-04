using System.IO.Hashing;
using System.Runtime.Intrinsics.X86;

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
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 32-bit hash value</item>
/// <item><b>Block Size:</b> 16 bytes (4 × 32-bit lanes)</item>
/// <item><b>Speed:</b> ~10-15 GB/s on modern hardware</item>
/// <item><b>Quality:</b> Passes SMHasher suite</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// xxHash32 uses 4 parallel 32-bit accumulators that are mixed after processing.
/// It uses prime numbers for multiplication (P1-P5) and bit rotation for mixing.
/// </para>
/// <para>
/// This wrapper provides <see cref="IStreamingHash{TResult}"/> compatibility around
/// the built-in .NET implementation, which is highly optimized and may use SIMD.
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
/// <seealso href="https://github.com/Cyan4973/xxHash">xxHash GitHub repository</seealso>
public sealed class XxHash32Streaming : IStreamingHash<uint> {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════
	// The underlying System.IO.Hashing implementation may use SIMD internally.
	// These properties indicate what's available on the current CPU.

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>The underlying .NET xxHash32 implementation.</summary>
	private XxHash32 _hasher;

	/// <summary>True if Finalize() has been called.</summary>
	private bool _finalized;

	/// <summary>True if Dispose() has been called.</summary>
	private bool _disposed;

	/// <summary>Total bytes processed across all Update calls.</summary>
	private long _totalBytes;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constants
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// The block size for xxHash32 (4 bytes).
	/// </summary>
	/// <remarks>
	/// While xxHash32 processes 16 bytes (4 lanes) internally, we report 4 bytes
	/// as the minimum meaningful unit for a 32-bit hash.
	/// </remarks>
	public const int BlockSizeValue = 4;

	/// <summary>
	/// The digest size for xxHash32 (4 bytes / 32 bits).
	/// </summary>
	public const int DigestSizeValue = 4;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public int BlockSize => BlockSizeValue;

	/// <inheritdoc/>
	public int DigestSize => DigestSizeValue;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Initializes a new instance with default seed (0).
	/// </summary>
	public XxHash32Streaming() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	/// <remarks>
	/// The seed affects all 4 internal accumulators through addition with primes.
	/// Different seeds produce completely different hash values.
	/// </remarks>
	public XxHash32Streaming(int seed) {
		_hasher = new XxHash32(seed);
		_finalized = false;
		_disposed = false;
		_totalBytes = 0;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Update Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// Data is passed directly to the underlying System.IO.Hashing implementation
	/// which handles buffering and block processing internally.
	/// </remarks>
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

	// ═══════════════════════════════════════════════════════════════════════════
	// Finalization
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// The underlying xxHash32 finalization:
	/// <list type="number">
	/// <item>Merges 4 accumulators using rotation and multiplication</item>
	/// <item>Adds total length</item>
	/// <item>Processes remaining bytes (1-15)</item>
	/// <item>Applies final avalanche mixing (3 rounds)</item>
	/// </list>
	/// </remarks>
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

	// ═══════════════════════════════════════════════════════════════════════════
	// Reset and Dispose
	// ═══════════════════════════════════════════════════════════════════════════

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

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Hash Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes xxHash32 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 32-bit hash value.</returns>
	/// <example>
	/// <code>
	/// byte[] data = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
	/// uint hash = XxHash32Streaming.Hash(data);
	/// </code>
	/// </example>
	public static uint Hash(ReadOnlySpan<byte> data, int seed = 0) {
		return XxHash32.HashToUInt32(data, seed);
	}

	/// <summary>
	/// Computes xxHash32 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array (4 bytes).</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, int seed = 0) {
		var result = new byte[4];
		XxHash32.Hash(data, result, seed);
		return result;
	}
}
