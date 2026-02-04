using System.IO.Hashing;
using System.Runtime.Intrinsics.X86;

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
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 128-bit hash value</item>
/// <item><b>Block Size:</b> 256 bytes for vectorized processing</item>
/// <item><b>Speed:</b> ~20-50+ GB/s with SIMD, nearly identical to xxHash3-64</item>
/// <item><b>Quality:</b> 128-bit output provides ~2^64 collision resistance</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// xxHash128 uses the same algorithm as xxHash3 but produces both halves of
/// the 128-bit internal state as output. This provides double the collision
/// resistance with minimal performance impact since the work is already done.
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Content addressing (file deduplication)</item>
/// <item>Data integrity verification</item>
/// <item>Hash tables where 64-bit might have collisions</item>
/// <item>Checksums for large datasets</item>
/// </list>
/// </para>
/// <para>
/// This wrapper provides <see cref="IStreamingHash{TResult}"/> compatibility around
/// the built-in .NET implementation, which automatically uses available SIMD.
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
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════
	// xxHash128 shares xxHash3's SIMD-optimized implementation.

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	/// <remarks>
	/// AVX2 enables processing 32 bytes per iteration for maximum throughput.
	/// </remarks>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>The underlying .NET xxHash128 implementation.</summary>
	private XxHash128 _hasher;

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
	/// The internal block size for xxHash128 (256 bytes for vectorized processing).
	/// </summary>
	/// <remarks>
	/// Same as xxHash3 - processes 256 bytes per stripe in the main loop.
	/// </remarks>
	public const int BlockSizeValue = 256;

	/// <summary>
	/// The digest size for xxHash128 (16 bytes / 128 bits).
	/// </summary>
	public const int DigestSizeValue = 16;

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
	public XxHash128Streaming() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	/// <remarks>
	/// The seed modifies the internal secret table, affecting both halves
	/// of the 128-bit output.
	/// </remarks>
	public XxHash128Streaming(long seed) {
		_hasher = new XxHash128(seed);
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
	/// xxHash128 finalization produces both 64-bit halves of the internal state.
	/// The low 64 bits are identical to xxHash3-64, and the high 64 bits
	/// come from the additional mixing done during finalization.
	/// </remarks>
	public UInt128 Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Finalize() has already been called. Call Reset() before computing a new hash.");
		}

		_finalized = true;
		Span<byte> hashBytes = stackalloc byte[16];
		_hasher.GetCurrentHash(hashBytes);

		// Convert to UInt128 (little-endian byte order)
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
	/// Computes xxHash128 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 128-bit hash value.</returns>
	/// <example>
	/// <code>
	/// byte[] data = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
	/// UInt128 hash = XxHash128Streaming.Hash(data);
	/// Console.WriteLine($"Hash: {hash:X32}");
	/// </code>
	/// </example>
	public static UInt128 Hash(ReadOnlySpan<byte> data, long seed = 0) {
		Span<byte> hashBytes = stackalloc byte[16];
		XxHash128.Hash(data, hashBytes, seed);

		// Convert to UInt128 (little-endian byte order)
		ulong low = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(hashBytes);
		ulong high = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(hashBytes[8..]);
		return new UInt128(high, low);
	}

	/// <summary>
	/// Computes xxHash128 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array (16 bytes).</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, long seed = 0) {
		var result = new byte[16];
		XxHash128.Hash(data, result, seed);
		return result;
	}
}
