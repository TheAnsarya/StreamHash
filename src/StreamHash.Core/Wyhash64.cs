using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of wyhash - one of the fastest hash functions available.
/// </summary>
/// <remarks>
/// <para>
/// wyhash is a non-cryptographic hash function created by Wang Yi (王一). It's designed
/// for maximum speed while maintaining excellent quality (passes SMHasher, BigCrush, PractRand).
/// </para>
/// <para>
/// <b>Algorithm Details:</b>
/// <list type="bullet">
/// <item>Uses 128-bit multiply for mixing (MUM - MUltiply and Mix)</item>
/// <item>Processes data in 48-byte blocks using 3 parallel accumulators</item>
/// <item>Excellent avalanche properties and collision resistance</item>
/// <item>Public domain (The Unlicense)</item>
/// </list>
/// </para>
/// <para>
/// <b>Performance:</b> 15-25 GB/s on modern hardware - one of the fastest hash functions available.
/// </para>
/// <para>
/// <b>Streaming Implementation Notes:</b>
/// wyhash processes data in 48-byte blocks for large inputs. This streaming implementation
/// buffers data until a complete 48-byte block is available, then processes it.
/// For inputs less than 48 bytes, special handling is used in finalization.
/// </para>
/// <para>
/// <b>Example:</b>
/// <code>
/// using var hasher = new Wyhash64();
/// hasher.Update(chunk1);
/// hasher.Update(chunk2);
/// ulong hash = hasher.Finalize();
/// </code>
/// </para>
/// </remarks>
/// <seealso href="https://github.com/wangyi-fudan/wyhash">wyhash GitHub repository</seealso>
public sealed class Wyhash64 : IStreamingHash<ulong>, IStreamingHashBytes {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════
	// wyhash uses 128-bit multiply (UInt128) which compiles to hardware MUL on x64.
	// SIMD could accelerate the 3-lane parallel processing in ProcessBlock.

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// Default Secret Parameters
	// ═══════════════════════════════════════════════════════════════════════════
	// These are the default secret values from the wyhash reference implementation.
	// Secrets are used to XOR with input before mixing, providing flexibility
	// for custom hash table implementations to use different secrets.

	/// <summary>
	/// Default secret parameters from wyhash reference implementation.
	/// </summary>
	/// <remarks>
	/// These values are carefully chosen pseudo-random constants that provide
	/// good mixing properties. Custom secrets can be provided for keyed hashing.
	/// </remarks>
	private static readonly ulong[] DefaultSecret = [
		0x2d358dccaa6c78a5ul,  // Secret[0] - XOR'd with length in final mix
		0x8bb84b93962eacc9ul,  // Secret[1] - XOR'd with input data
		0x4b33a62ed433d4a3ul,  // Secret[2] - XOR'd with second lane
		0x4d5a2da51de1aa47ul   // Secret[3] - XOR'd with third lane
	];

	// ═══════════════════════════════════════════════════════════════════════════
	// Block Size Constants
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// The block size for wyhash (48 bytes for main loop).
	/// </summary>
	/// <remarks>
	/// wyhash processes 48 bytes (6 × 64-bit words) per iteration in the main loop.
	/// This allows 3 parallel accumulators, each processing 16 bytes.
	/// </remarks>
	public const int BlockSizeValue = 48;

	/// <summary>
	/// The digest size for wyhash (8 bytes / 64 bits).
	/// </summary>
	public const int DigestSizeValue = 8;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>Custom or default secret parameters.</summary>
	private readonly ulong[] _secret;

	/// <summary>Initial seed value provided at construction.</summary>
	private readonly ulong _initialSeed;

	// ═══════════════════════════════════════════════════════════════════════════
	// Streaming State
	// ═══════════════════════════════════════════════════════════════════════════
	// wyhash's finalization reads from the END of data, making true streaming complex.
	// We use a chunked approach: process 48-byte blocks but keep tail for finalization.

	/// <summary>Primary accumulator (seed with mixing applied).</summary>
	private ulong _seed;

	/// <summary>Secondary accumulator for lane 2.</summary>
	private ulong _see1;

	/// <summary>Tertiary accumulator for lane 3.</summary>
	private ulong _see2;

	/// <summary>Buffer for incomplete blocks.</summary>
	private readonly byte[] _buffer;

	/// <summary>Current position within the buffer.</summary>
	private int _bufferPosition;

	/// <summary>Total bytes processed across all Update calls.</summary>
	private long _totalBytes;

	/// <summary>True if at least one 48-byte block was processed.</summary>
	private bool _processedLargeBlock;

	/// <summary>True if Finalize() has been called.</summary>
	private bool _finalized;

	/// <summary>True if Dispose() has been called.</summary>
	private bool _disposed;

	// ═══════════════════════════════════════════════════════════════════════════
	// Last 16 Bytes Tracking
	// ═══════════════════════════════════════════════════════════════════════════
	// wyhash reads the last 16 bytes of input for finalization.
	// We track these as data streams in.

	/// <summary>Storage for last 16 bytes of input data.</summary>
	private readonly byte[] _last16;

	/// <summary>How many bytes of _last16 are valid.</summary>
	private int _last16Len;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>wyhash processes 48 bytes (384 bits) per block.</remarks>
	public int BlockSize => BlockSizeValue;

	/// <inheritdoc/>
	/// <remarks>wyhash produces an 8-byte (64-bit) hash value.</remarks>
	public int DigestSize => DigestSizeValue;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Initializes a new instance with default seed (0) and default secret.
	/// </summary>
	public Wyhash64() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed and default secret.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	/// <remarks>
	/// The seed is mixed with Secret[0] and Secret[1] during initialization
	/// to provide a well-distributed starting state.
	/// </remarks>
	public Wyhash64(ulong seed) : this(seed, DefaultSecret) { }

	/// <summary>
	/// Initializes a new instance with the specified seed and custom secret.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	/// <param name="secret">Custom secret parameters (must be 4 elements).</param>
	/// <exception cref="ArgumentNullException">Thrown if secret is null.</exception>
	/// <exception cref="ArgumentException">Thrown if secret doesn't contain exactly 4 elements.</exception>
	/// <remarks>
	/// Custom secrets can be used for keyed hashing or to create independent
	/// hash functions for double hashing in hash tables.
	/// </remarks>
	public Wyhash64(ulong seed, ulong[] secret) {
		ArgumentNullException.ThrowIfNull(secret);
		if (secret.Length != 4) {
			throw new ArgumentException("Secret must contain exactly 4 elements.", nameof(secret));
		}

		_secret = secret;
		_initialSeed = seed;
		_buffer = new byte[BlockSizeValue];
		_last16 = new byte[16];
		Reset();
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Update Method
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// Data is buffered until 48-byte blocks can be processed. The last 16 bytes
	/// are tracked separately for finalization (wyhash reads from end of data).
	/// </remarks>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Cannot update after Finalize() has been called. Call Reset() first.");
		}

		if (data.IsEmpty) {
			return;
		}

		_totalBytes += data.Length;
		int offset = 0;

		// If we have buffered data, try to complete a 48-byte block
		if (_bufferPosition > 0) {
			int needed = BlockSizeValue - _bufferPosition;
			if (data.Length >= needed) {
				// Complete the block
				data[..needed].CopyTo(_buffer.AsSpan(_bufferPosition));
				ProcessBlock(_buffer);
				_bufferPosition = 0;
				offset = needed;
			} else {
				// Not enough data to complete block, just buffer it
				data.CopyTo(_buffer.AsSpan(_bufferPosition));
				_bufferPosition += data.Length;
				// Update last16 tracking for finalization
				UpdateLast16(data);
				return;
			}
		}

		// Process complete 48-byte blocks directly from input
		while (offset + BlockSizeValue <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockSizeValue));
			offset += BlockSizeValue;
		}

		// Buffer remaining bytes (less than 48)
		int remaining = data.Length - offset;
		if (remaining > 0) {
			data.Slice(offset, remaining).CopyTo(_buffer.AsSpan());
			_bufferPosition = remaining;
		}

		// Always update last16 with the end of the incoming data
		UpdateLast16(data);
	}

	/// <summary>
	/// Updates the last 16 bytes tracking for finalization.
	/// </summary>
	/// <param name="data">New data being added.</param>
	/// <remarks>
	/// wyhash reads the last 16 bytes of input during finalization.
	/// This method keeps track of those bytes as data streams in.
	/// </remarks>
	private void UpdateLast16(ReadOnlySpan<byte> data) {
		if (data.Length >= 16) {
			// Take last 16 bytes from this chunk
			data[^16..].CopyTo(_last16);
			_last16Len = 16;
		} else {
			// Shift existing and append new
			int shift = data.Length;
			if (_last16Len + shift <= 16) {
				// Just append
				data.CopyTo(_last16.AsSpan(_last16Len));
				_last16Len += shift;
			} else {
				// Shift left and append
				int keep = 16 - shift;
				_last16.AsSpan(_last16Len - keep, keep).CopyTo(_last16);
				data.CopyTo(_last16.AsSpan(keep));
				_last16Len = 16;
			}
		}
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		ArgumentNullException.ThrowIfNull(data);
		Update(data.AsSpan(offset, length));
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Block Processing
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Processes a single 48-byte block through the 3-lane parallel mixer.
	/// </summary>
	/// <param name="block">A 48-byte data block.</param>
	/// <remarks>
	/// <para>
	/// <b>Algorithm:</b>
	/// Reads 6 × 64-bit words and processes them in 3 parallel lanes:
	/// <list type="bullet">
	/// <item><b>Lane 1:</b> XOR v0 with Secret[1], v1 with seed, MUM, update seed</item>
	/// <item><b>Lane 2:</b> XOR v2 with Secret[2], v3 with see1, MUM, update see1</item>
	/// <item><b>Lane 3:</b> XOR v4 with Secret[3], v5 with see2, MUM, update see2</item>
	/// </list>
	/// </para>
	/// <para>
	/// The three lanes are independent and could be parallelized with SIMD.
	/// They're combined during finalization.
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		_processedLargeBlock = true;

		// Read 6 × 64-bit values (48 bytes total)
		ulong v0 = BinaryPrimitives.ReadUInt64LittleEndian(block);        // bytes 0-7
		ulong v1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);   // bytes 8-15
		ulong v2 = BinaryPrimitives.ReadUInt64LittleEndian(block[16..]);  // bytes 16-23
		ulong v3 = BinaryPrimitives.ReadUInt64LittleEndian(block[24..]);  // bytes 24-31
		ulong v4 = BinaryPrimitives.ReadUInt64LittleEndian(block[32..]);  // bytes 32-39
		ulong v5 = BinaryPrimitives.ReadUInt64LittleEndian(block[40..]);  // bytes 40-47

		// Process 3 parallel lanes using WyMix (128-bit multiply + XOR)
		// Each lane: XOR data with secret, XOR data with accumulator, MUM, result is new accumulator
		_seed = WyMix(v0 ^ _secret[1], v1 ^ _seed);   // Lane 1
		_see1 = WyMix(v2 ^ _secret[2], v3 ^ _see1);   // Lane 2
		_see2 = WyMix(v4 ^ _secret[3], v5 ^ _see2);   // Lane 3
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Finalization
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// <b>Finalization Process:</b>
	/// <list type="number">
	/// <item>For small inputs (≤16 bytes), use FinalizeSmall()</item>
	/// <item>For large inputs, merge the 3 accumulators: seed ^= see1 ^= see2</item>
	/// <item>Process remaining 16-byte chunks from buffer</item>
	/// <item>Read last 16 bytes as two 64-bit values (a, b)</item>
	/// <item>Apply final mixing: a ^= Secret[1], b ^= seed, WyMum(a, b)</item>
	/// <item>Return WyMix(a ^ Secret[0] ^ length, b ^ Secret[1])</item>
	/// </list>
	/// </para>
	/// </remarks>
	public ulong Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Finalize() has already been called. Call Reset() before computing a new hash.");
		}

		_finalized = true;

		int len = (int)_totalBytes;

		// Handle small inputs (≤16 bytes) - no blocks processed
		if (len <= 16) {
			return FinalizeSmall();
		}

		// For larger inputs, merge accumulators if we processed blocks
		// This combines the 3 parallel lanes into a single value
		ulong seed = _processedLargeBlock ? (_seed ^ _see1 ^ _see2) : _seed;

		// Process any remaining 16-byte chunks from buffer
		int remaining = _bufferPosition;
		int pos = 0;
		while (remaining > 16) {
			// Process 16 bytes at a time
			seed = WyMix(
				BinaryPrimitives.ReadUInt64LittleEndian(_buffer.AsSpan(pos)) ^ _secret[1],
				BinaryPrimitives.ReadUInt64LittleEndian(_buffer.AsSpan(pos + 8)) ^ seed);
			pos += 16;
			remaining -= 16;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Final 16 bytes - the critical wyhash finalization
		// wyhash reads the last 16 bytes as two overlapping 8-byte reads
		// ═══════════════════════════════════════════════════════════════════════
		ulong a = BinaryPrimitives.ReadUInt64LittleEndian(_last16.AsSpan(0));   // bytes [len-16..len-8]
		ulong b = BinaryPrimitives.ReadUInt64LittleEndian(_last16.AsSpan(8));   // bytes [len-8..len]

		// Final mixing with length encoding
		a ^= _secret[1];
		b ^= seed;
		WyMum(ref a, ref b);
		return WyMix(a ^ _secret[0] ^ (ulong)len, b ^ _secret[1]);
	}

	/// <summary>
	/// Finalizes for small inputs (0-16 bytes).
	/// </summary>
	/// <returns>The 64-bit hash value.</returns>
	/// <remarks>
	/// <para>
	/// wyhash has special handling for small inputs to avoid unnecessary work:
	/// <list type="bullet">
	/// <item><b>0 bytes:</b> a = 0, b = 0</item>
	/// <item><b>1-3 bytes:</b> Pack 3 bytes (with overlap) into 'a', b = 0</item>
	/// <item><b>4-16 bytes:</b> Pack 4 bytes from start+middle into 'a', 4 bytes from end+middle into 'b'</item>
	/// </list>
	/// </para>
	/// <para>
	/// The "half" calculation for 4-16 bytes selects overlap points:
	/// half = (len &gt;&gt; 3) &lt;&lt; 2 = either 0 (for 4-7 bytes) or 4 (for 8-16 bytes)
	/// </para>
	/// </remarks>
	private ulong FinalizeSmall() {
		int len = (int)_totalBytes;
		ulong a, b;

		if (len >= 4) {
			// For 4-16 bytes: read overlapping 32-bit values to capture all bytes
			// half = 0 for 4-7 bytes, 4 for 8-16 bytes
			int half = len >> 3 << 2;

			// 'a' = (first 4 bytes << 32) | (4 bytes at 'half' offset)
			a = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(0)) << 32) |
				BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(half));

			// 'b' = (last 4 bytes << 32) | (4 bytes before last at 'half' offset)
			b = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(len - 4)) << 32) |
				BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(len - 4 - half));
		} else if (len > 0) {
			// For 1-3 bytes: pack first, middle, and last bytes
			// This captures all bytes with overlap for very short inputs
			a = ((ulong)_buffer[0] << 16) |         // first byte in bits 16-23
				((ulong)_buffer[len >> 1] << 8) |   // middle byte in bits 8-15
				_buffer[len - 1];                    // last byte in bits 0-7
			b = 0;
		} else {
			// Empty input
			a = 0;
			b = 0;
		}

		// Final mixing with length encoding
		a ^= _secret[1];
		b ^= _seed;
		WyMum(ref a, ref b);
		return WyMix(a ^ _secret[0] ^ (ulong)len, b ^ _secret[1]);
	}

	/// <summary>
	/// Finalizes and returns the hash as a byte array.
	/// </summary>
	/// <returns>The 8-byte hash value in little-endian format.</returns>
	public byte[] FinalizeToBytes() {
		var hash = Finalize();
		var result = new byte[8];
		BinaryPrimitives.WriteUInt64LittleEndian(result, hash);
		return result;
	}

	/// <inheritdoc/>
	byte[] IStreamingHashBytes.FinalizeBytes() => FinalizeToBytes();

	/// <summary>
	/// Finalizes and returns the hash as a lowercase hexadecimal string.
	/// </summary>
	/// <returns>The 16-character hex string.</returns>
	public string FinalizeHex() => Convert.ToHexStringLower(FinalizeToBytes());

	// ═══════════════════════════════════════════════════════════════════════════
	// Reset and Dispose
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// Reinitializes all state for a new hash computation.
	/// The seed is mixed with Secret[0] and Secret[1] to provide
	/// a well-distributed starting state.
	/// </remarks>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		// Initialize seed with secret mixing (as per wyhash spec)
		// This provides good starting distribution even for seed = 0
		_seed = _initialSeed ^ WyMix(_initialSeed ^ _secret[0], _secret[1]);
		_see1 = _seed;
		_see2 = _seed;
		_bufferPosition = 0;
		_totalBytes = 0;
		_processedLargeBlock = false;
		_finalized = false;
		_last16Len = 0;
		Array.Clear(_last16);
		Array.Clear(_buffer);
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (!_disposed) {
			_disposed = true;
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Core Mixing Functions (MUM - MUltiply and Mix)
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// MUM (MUltiply and Mix) - the core mixing function of wyhash.
	/// </summary>
	/// <param name="a">First 64-bit input, receives low 64 bits of product.</param>
	/// <param name="b">Second 64-bit input, receives high 64 bits of product.</param>
	/// <remarks>
	/// <para>
	/// Computes a 128-bit product of two 64-bit values, then stores:
	/// <list type="bullet">
	/// <item>a = low 64 bits of product</item>
	/// <item>b = high 64 bits of product</item>
	/// </list>
	/// </para>
	/// <para>
	/// On x64, this compiles to a single MULQ instruction which produces
	/// 128-bit result in RDX:RAX registers. .NET's UInt128 multiplication
	/// maps directly to this hardware operation.
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WyMum(ref ulong a, ref ulong b) {
		// 128-bit multiply: (a * b) → 128-bit result
		UInt128 r = (UInt128)a * b;
		// Split into high and low 64-bit halves
		a = (ulong)r;         // Low 64 bits
		b = (ulong)(r >> 64); // High 64 bits
	}

	/// <summary>
	/// Mix function combining MUM and XOR for maximum diffusion.
	/// </summary>
	/// <param name="a">First 64-bit input.</param>
	/// <param name="b">Second 64-bit input.</param>
	/// <returns>XOR of high and low 64-bit halves of 128-bit product.</returns>
	/// <remarks>
	/// WyMix(a, b) = low(a*b) ^ high(a*b)
	/// This provides excellent avalanche - every input bit affects every output bit.
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong WyMix(ulong a, ulong b) {
		WyMum(ref a, ref b);
		return a ^ b;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Hash Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes wyhash of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <example>
	/// <code>
	/// byte[] data = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
	/// ulong hash = Wyhash64.Hash(data);
	/// // With seed:
	/// ulong seededHash = Wyhash64.Hash(data, seed: 12345);
	/// </code>
	/// </example>
	public static ulong Hash(ReadOnlySpan<byte> data, ulong seed = 0) {
		return HashWithSecret(data, seed, DefaultSecret);
	}

	/// <summary>
	/// Computes wyhash of the input data with custom secret.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value.</param>
	/// <param name="secret">Custom secret parameters (must be 4 elements).</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <remarks>
	/// <para>
	/// This is the one-shot implementation that mirrors the reference wyhash.
	/// It's optimized for non-streaming use cases.
	/// </para>
	/// <para>
	/// <b>Algorithm Flow:</b>
	/// <list type="number">
	/// <item>Initialize seed: seed ^= WyMix(seed ^ secret[0], secret[1])</item>
	/// <item>For small inputs (≤16 bytes): pack bytes into a, b directly</item>
	/// <item>For large inputs: process 48-byte blocks with 3 accumulators</item>
	/// <item>Process remaining 16-byte chunks</item>
	/// <item>Final mix with last 16 bytes and length</item>
	/// </list>
	/// </para>
	/// </remarks>
	public static ulong HashWithSecret(ReadOnlySpan<byte> data, ulong seed, ulong[] secret) {
		int len = data.Length;

		// Initialize seed with secret mixing
		seed ^= WyMix(seed ^ secret[0], secret[1]);

		ulong a, b;

		// ═══════════════════════════════════════════════════════════════════════
		// Small input handling (≤16 bytes)
		// ═══════════════════════════════════════════════════════════════════════
		if (len <= 16) {
			if (len >= 4) {
				// 4-16 bytes: read overlapping 32-bit values
				int half = len >> 3 << 2;  // 0 for 4-7 bytes, 4 for 8-16 bytes
				a = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(data) << 32) |
					BinaryPrimitives.ReadUInt32LittleEndian(data[half..]);
				b = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(data[(len - 4)..]) << 32) |
					BinaryPrimitives.ReadUInt32LittleEndian(data[(len - 4 - half)..]);
			} else if (len > 0) {
				// 1-3 bytes: pack first, middle, last
				a = ((ulong)data[0] << 16) | ((ulong)data[len >> 1] << 8) | data[len - 1];
				b = 0;
			} else {
				// 0 bytes
				a = 0;
				b = 0;
			}
		} else {
			// ═══════════════════════════════════════════════════════════════════
			// Large input handling (>16 bytes)
			// ═══════════════════════════════════════════════════════════════════
			int i = len;
			int p = 0;

			// Process 48-byte blocks with 3 parallel accumulators
			if (i >= 48) {
				ulong see1 = seed, see2 = seed;
				do {
					// Lane 1
					seed = WyMix(BinaryPrimitives.ReadUInt64LittleEndian(data[p..]) ^ secret[1],
						BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 8)..]) ^ seed);
					// Lane 2
					see1 = WyMix(BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 16)..]) ^ secret[2],
						BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 24)..]) ^ see1);
					// Lane 3
					see2 = WyMix(BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 32)..]) ^ secret[3],
						BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 40)..]) ^ see2);
					p += 48;
					i -= 48;
				} while (i >= 48);

				// Combine 3 lanes
				seed ^= see1 ^ see2;
			}

			// Process remaining 16-byte chunks
			while (i > 16) {
				seed = WyMix(BinaryPrimitives.ReadUInt64LittleEndian(data[p..]) ^ secret[1],
					BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 8)..]) ^ seed);
				i -= 16;
				p += 16;
			}

			// Read last 16 bytes (overlapping read from end)
			a = BinaryPrimitives.ReadUInt64LittleEndian(data[(len - 16)..]);
			b = BinaryPrimitives.ReadUInt64LittleEndian(data[(len - 8)..]);
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Final mixing
		// ═══════════════════════════════════════════════════════════════════════
		a ^= secret[1];
		b ^= seed;
		WyMum(ref a, ref b);
		return WyMix(a ^ secret[0] ^ (ulong)len, b ^ secret[1]);
	}

	/// <summary>
	/// Computes wyhash of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array (8 bytes, little-endian).</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, ulong seed = 0) {
		var result = new byte[8];
		BinaryPrimitives.WriteUInt64LittleEndian(result, Hash(data, seed));
		return result;
	}
}
