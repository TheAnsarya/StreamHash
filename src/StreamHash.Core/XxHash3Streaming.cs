using System.IO.Hashing;
using System.Runtime.Intrinsics.X86;

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
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 64-bit hash value (128-bit variant available via XxHash128)</item>
/// <item><b>Block Size:</b> 256 bytes for vectorized processing</item>
/// <item><b>Speed:</b> ~20-50+ GB/s with SIMD, fastest of the xxHash family</item>
/// <item><b>Quality:</b> Excellent quality, passes all SMHasher tests</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// xxHash3 is designed from scratch to leverage modern CPU features:
/// <list type="bullet">
/// <item>Uses 512-bit internal state (8 × 64-bit accumulators)</item>
/// <item>Optimized for SIMD: AVX2, SSE2, NEON</item>
/// <item>Special fast paths for small inputs (1-16, 17-128, 129-240 bytes)</item>
/// <item>Secret-based scrambling for additional entropy</item>
/// </list>
/// </para>
/// <para>
/// This wrapper provides <see cref="IStreamingHash{TResult}"/> compatibility around
/// the built-in .NET implementation, which automatically uses available SIMD.
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
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════
	// xxHash3 is heavily SIMD-optimized. The .NET implementation automatically
	// uses AVX2, SSE2, or scalar code based on CPU capabilities.

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	/// <remarks>
	/// When AVX2 is available, xxHash3 can process 32 bytes per iteration,
	/// achieving maximum throughput (~50+ GB/s on modern CPUs).
	/// </remarks>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>The underlying .NET xxHash3 implementation.</summary>
	private XxHash3 _hasher;

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
	/// The internal block size for xxHash3 (256 bytes for vectorized processing).
	/// </summary>
	/// <remarks>
	/// xxHash3 processes 256 bytes (1024 bits) per stripe in the main loop.
	/// This aligns with AVX2's 256-bit registers for optimal SIMD usage.
	/// </remarks>
	public const int BlockSizeValue = 256;

	/// <summary>
	/// The digest size for xxHash3 64-bit (8 bytes).
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
	public XxHash3Streaming() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	/// <remarks>
	/// The seed modifies the internal secret table used for scrambling,
	/// producing completely different hash values for different seeds.
	/// </remarks>
	public XxHash3Streaming(long seed) {
		_hasher = new XxHash3(seed);
		_finalized = false;
		_disposed = false;
		_totalBytes = 0;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Update Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// xxHash3 uses different code paths based on accumulated data size:
	/// <list type="bullet">
	/// <item><b>1-16 bytes:</b> Direct mixing without accumulator</item>
	/// <item><b>17-128 bytes:</b> Single-pass accumulation</item>
	/// <item><b>129-240 bytes:</b> Mid-size path with partial stripes</item>
	/// <item><b>241+ bytes:</b> Full stripe processing with 8 accumulators</item>
	/// </list>
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
	/// xxHash3 finalization depends on total length:
	/// <list type="bullet">
	/// <item><b>Small inputs:</b> Direct avalanche mixing</item>
	/// <item><b>Large inputs:</b> Merge 8 accumulators, then avalanche</item>
	/// </list>
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
	/// Computes xxHash3 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <example>
	/// <code>
	/// byte[] data = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
	/// ulong hash = XxHash3Streaming.Hash(data);
	/// // With SIMD on modern CPUs, this can exceed 50 GB/s
	/// </code>
	/// </example>
	public static ulong Hash(ReadOnlySpan<byte> data, long seed = 0) {
		return XxHash3.HashToUInt64(data, seed);
	}

	/// <summary>
	/// Computes xxHash3 of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array (8 bytes).</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, long seed = 0) {
		var result = new byte[8];
		XxHash3.Hash(data, result, seed);
		return result;
	}
}
