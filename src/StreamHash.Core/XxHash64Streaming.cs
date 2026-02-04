using System.IO.Hashing;
using System.Runtime.Intrinsics.X86;

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
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 64-bit hash value</item>
/// <item><b>Block Size:</b> 32 bytes (4 × 64-bit lanes)</item>
/// <item><b>Speed:</b> ~15-30 GB/s on modern 64-bit hardware</item>
/// <item><b>Quality:</b> Passes SMHasher suite, excellent avalanche</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// xxHash64 uses 4 parallel 64-bit accumulators that are independently updated
/// with data words. It uses prime numbers (P1-P5) for multiplication and
/// rotation for mixing. The 64-bit version is optimized for 64-bit CPUs and
/// typically faster than xxHash32 on such hardware.
/// </para>
/// <para>
/// This wrapper provides <see cref="IStreamingHash{TResult}"/> compatibility around
/// the built-in .NET implementation, which is highly optimized.
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
/// <seealso href="https://github.com/Cyan4973/xxHash">xxHash GitHub repository</seealso>
public sealed class XxHash64Streaming : IStreamingHash<ulong> {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════

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

	/// <summary>The underlying .NET xxHash64 implementation.</summary>
	private XxHash64 _hasher;

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
	/// The block size for xxHash64 (32 bytes = 4 × 64-bit lanes).
	/// </summary>
	public const int BlockSizeValue = 32;

	/// <summary>
	/// The digest size for xxHash64 (8 bytes / 64 bits).
	/// </summary>
	public const int DigestSizeValue = 8;

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
	public XxHash64Streaming() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	/// <remarks>
	/// The seed affects all 4 internal accumulators through addition with primes.
	/// </remarks>
	public XxHash64Streaming(long seed) {
		_hasher = new XxHash64(seed);
		_finalized = false;
		_disposed = false;
		_totalBytes = 0;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Update Methods
	// ═══════════════════════════════════════════════════════════════════════════

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

	// ═══════════════════════════════════════════════════════════════════════════
	// Finalization
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// xxHash64 finalization merges 4 accumulators using rotation and XOR,
	/// adds the total length, processes remaining bytes, then applies
	/// final avalanche mixing.
	/// </remarks>
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
	/// Computes xxHash64 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <example>
	/// <code>
	/// byte[] data = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
	/// ulong hash = XxHash64Streaming.Hash(data);
	/// </code>
	/// </example>
	public static ulong Hash(ReadOnlySpan<byte> data, long seed = 0) {
		return XxHash64.HashToUInt64(data, seed);
	}

	/// <summary>
	/// Computes xxHash64 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array (8 bytes).</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, long seed = 0) {
		var result = new byte[8];
		XxHash64.Hash(data, result, seed);
		return result;
	}
}
