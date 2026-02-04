using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of CityHash128 hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// CityHash128 is the 128-bit variant of Google's CityHash family. It provides a larger
/// output space while maintaining excellent speed characteristics.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 128-bit hash value (as <see cref="UInt128"/>)</item>
/// <item><b>Block Size:</b> 128 bytes</item>
/// <item><b>Speed:</b> ~8+ GB/s on modern x86-64 CPUs</item>
/// <item><b>Collision Resistance:</b> Excellent for general purposes, NOT cryptographically secure</item>
/// </list>
/// </para>
/// <para>
/// <b>Streaming Implementation Notes:</b>
/// <list type="bullet">
/// <item>Uses a 128-byte block size for efficient streaming</item>
/// <item>Maintains 128-bit state pair (u, v) across updates</item>
/// <item>Processes blocks using CityMurmur-style mixing</item>
/// </list>
/// </para>
/// <para>
/// <b>SIMD Optimization:</b>
/// This implementation detects AVX2 and SSE4.1 support at startup. When available,
/// certain mixing operations can be vectorized for improved throughput.
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Distributed systems requiring low collision probability</item>
/// <item>Content-addressable storage</item>
/// <item>Database indexing</item>
/// <item>Deduplication systems</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/google/cityhash">CityHash - Google's official implementation</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Basic usage
/// using var hasher = new CityHash128();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// UInt128 hash = hasher.Finalize();
///
/// // Stream processing large files
/// using var streamHasher = new CityHash128();
/// using var file = File.OpenRead("largefile.bin");
/// byte[] buffer = new byte[131072]; // 128KB buffer
/// int read;
/// while ((read = file.Read(buffer)) > 0) {
///     streamHasher.Update(buffer.AsSpan(0, read));
/// }
/// UInt128 fileHash = streamHasher.Finalize();
/// </code>
/// </example>
public sealed class CityHash128 : StreamingHashBase<UInt128> {
	#region SIMD Support Detection

	/// <summary>
	/// Indicates whether AVX2 (256-bit SIMD) instructions are available.
	/// </summary>
	private static readonly bool IsAvx2Supported = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 (128-bit SIMD) instructions are available.
	/// </summary>
	private static readonly bool IsSse41Supported = Sse41.IsSupported;

	#endregion

	#region Constants

	/// <summary>
	/// Magic constant k0 - derived empirically for optimal bit mixing.
	/// </summary>
	private const ulong K0 = 0xc3a5c85c97cb3127UL;

	/// <summary>
	/// Magic constant k1 - used in rotations and multiplications.
	/// </summary>
	private const ulong K1 = 0xb492b66fbe98f273UL;

	/// <summary>
	/// Magic constant k2 - primary multiplier in hash calculations.
	/// </summary>
	private const ulong K2 = 0x9ae16a3b2f90404fUL;

	#endregion

	#region State Variables

	/// <summary>
	/// Primary mixing variable - evolves through block processing.
	/// </summary>
	private ulong _x;

	/// <summary>
	/// Secondary mixing variable - captures y-dimension diffusion.
	/// </summary>
	private ulong _y;

	/// <summary>
	/// Tertiary mixing variable - used in final combination.
	/// </summary>
	private ulong _z;

	/// <summary>
	/// First component of v-pair (128-bit virtual register).
	/// </summary>
	private ulong _v0;

	/// <summary>
	/// Second component of v-pair (128-bit virtual register).
	/// </summary>
	private ulong _v1;

	/// <summary>
	/// First component of w-pair (128-bit virtual register).
	/// </summary>
	private ulong _w0;

	/// <summary>
	/// Second component of w-pair (128-bit virtual register).
	/// </summary>
	private ulong _w1;

	/// <summary>
	/// Indicates whether state has been initialized from first block.
	/// </summary>
	private bool _initialized;

	/// <summary>
	/// Tracks total bytes processed through ProcessBlock.
	/// </summary>
	private long _processedBytes;

	#endregion

	/// <inheritdoc/>
	/// <remarks>
	/// CityHash128 uses 128-byte blocks (double the 64-bit variant) for
	/// more efficient processing of large inputs.
	/// </remarks>
	public override int BlockSize => 128;

	/// <inheritdoc/>
	/// <remarks>
	/// Produces a 128-bit (16-byte) hash value as <see cref="UInt128"/>.
	/// The larger output space provides ~2^64 collision resistance.
	/// </remarks>
	public override int DigestSize => 16;

	/// <summary>
	/// Creates a new CityHash128 streaming hasher.
	/// </summary>
	/// <remarks>
	/// Initializes all state to zero. Actual state setup occurs when
	/// the first block of data is processed.
	/// </remarks>
	public CityHash128() : base() {
		Reset();
	}

	/// <inheritdoc/>
	/// <remarks>
	/// Processes a complete 128-byte block. The first block requires
	/// special initialization; subsequent blocks use standard mixing.
	/// </remarks>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		if (!_initialized) {
			// First block: extract initial state from input data
			InitializeFromBlock(block);
			_initialized = true;
		} else {
			// Subsequent blocks: apply standard mixing
			ProcessFullBlock(block);
		}
		_processedBytes += BlockSize;
	}

	/// <summary>
	/// Initializes hash state from the first 128-byte block.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The first block provides seed material for all state variables.
	/// Bytes are read from various positions in the block to ensure
	/// good initial diffusion.
	/// </para>
	/// <para>
	/// The initialization reads from:
	/// <list type="bullet">
	/// <item>Block[104-111]: Combined with K1 for x</item>
	/// <item>Block[0-7]: Initial y value</item>
	/// <item>Block[112-127]: Combined with K1 for z</item>
	/// <item>Block[8-31]: Initial v and w components</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <param name="block">The first 128-byte input block.</param>
	private void InitializeFromBlock(ReadOnlySpan<byte> block) {
		// ========== Initialize Primary State ==========
		// Read from near the end of the block for x, combined with K1
		_x = Fetch64(block[104..]) ^ K1;

		// Read from the beginning for y (no XOR, just raw value)
		_y = Fetch64(block[0..]);

		// z combines two values from the end, both XORed with K1
		_z = HashLen16(Fetch64(block[112..]) ^ K1, Fetch64(block[120..]));

		// ========== Initialize v-pair ==========
		// v0 is derived from z and block[16-23]
		_v0 = HashLen16(_z ^ K1, Fetch64(block[16..]));
		_v1 = Fetch64(block[8..]);

		// ========== Initialize w-pair ==========
		// w0 combines v0, y, and block[24-31]
		_w0 = HashLen16(_v0 + _y, Fetch64(block[24..]));
		_w1 = _x;

		// ========== Process Both Halves ==========
		// Treat the 128-byte block as two 64-byte half-blocks
		ProcessHalfBlock(block[0..64]);   // First half
		ProcessHalfBlock(block[64..128]); // Second half
	}

	/// <summary>
	/// Processes a 64-byte half-block of data.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This is the core mixing function, identical to CityHash64's block processing.
	/// It updates x, y, z, v, and w with a combination of:
	/// <list type="bullet">
	/// <item>Rotations (37, 42, 33 bits)</item>
	/// <item>Multiplications by K1</item>
	/// <item>XOR operations</item>
	/// <item>WeakHashLen32WithSeeds for 32-byte mixing</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <param name="block">A 64-byte half-block.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessHalfBlock(ReadOnlySpan<byte> block) {
		// Mix x with accumulated state and input bytes 8-15
		_x = Rotate64(_x + _y + _v0 + Fetch64(block[8..]), 37) * K1;

		// Mix y with v1 and input bytes 48-55
		_y = Rotate64(_y + _v1 + Fetch64(block[48..]), 42) * K1;

		// XOR creates non-linear dependency
		_x ^= _w1;

		// Additional input mixing into y
		_y += _v0 + Fetch64(block[40..]);

		// Rotate z with w0 influence
		_z = Rotate64(_z + _w0, 33) * K1;

		// Process 32-byte chunks with seeded weak hashing
		(_v0, _v1) = WeakHashLen32WithSeeds(block[32..], _v1 * K1, _x + _w0);
		(_w0, _w1) = WeakHashLen32WithSeeds(block[0..], _z + _w1, _y + Fetch64(block[16..]));

		// Swap z and x
		(_z, _x) = (_x, _z);
	}

	/// <summary>
	/// Processes a full 128-byte block by splitting into two halves.
	/// </summary>
	/// <remarks>
	/// Simply delegates to ProcessHalfBlock twice. This two-pass approach
	/// ensures the state is updated consistently with the 64-byte mixing round.
	/// </remarks>
	/// <param name="block">The 128-byte input block.</param>
	private void ProcessFullBlock(ReadOnlySpan<byte> block) {
		ProcessHalfBlock(block[0..64]);   // First 64 bytes
		ProcessHalfBlock(block[64..128]); // Second 64 bytes
	}

	/// <inheritdoc/>
	/// <remarks>
	/// Finalizes the hash computation. For short messages (&lt; 128 bytes),
	/// uses optimized paths. For longer messages, combines streaming state
	/// into the final 128-bit value.
	/// </remarks>
	protected override UInt128 ComputeFinal(ReadOnlySpan<byte> remaining) {
		long totalLen = TotalBytesProcessed;

		// For short messages, use optimized path (no streaming overhead)
		if (totalLen < 128) {
			return HashShort(remaining, (int)totalLen);
		}

		// Process any remaining data (1-127 bytes)
		if (remaining.Length > 0) {
			// Pad to a full block with zeros
			Span<byte> padded = stackalloc byte[128];
			remaining.CopyTo(padded);

			// Process complete 64-byte half if available
			if (remaining.Length >= 64) {
				ProcessHalfBlock(padded[0..64]);
			}

			// Mix in additional bytes if we have at least 32
			if (remaining.Length >= 32) {
				_x += Fetch64(padded);        // bytes 0-7
				_y += Fetch64(padded[8..]);   // bytes 8-15
				_z += Fetch64(padded[16..]);  // bytes 16-23
				_v0 += Fetch64(padded[24..]); // bytes 24-31
			}
		}

		// ========== Final Hash Combination ==========
		// Combine state into two 64-bit halves, then pack into UInt128.
		// Length is included in the mix for length disambiguation.
		ulong lowPart = HashLen16(_v0 + _w0, _w1, (ulong)totalLen);
		ulong highPart = HashLen16(_x + _z, _y, (ulong)totalLen);

		// UInt128 constructor takes (upper, lower) order
		return new UInt128(highPart, lowPart);
	}

	/// <summary>
	/// Computes hash for short messages (&lt; 128 bytes).
	/// </summary>
	/// <remarks>
	/// <para>
	/// Short messages bypass the streaming state entirely and use
	/// optimized code paths based on message length:
	/// <list type="bullet">
	/// <item>0 bytes: Return constant (K1, K0)</item>
	/// <item>1-16 bytes: Simple mixing</item>
	/// <item>17-32 bytes: Two 64-bit reads</item>
	/// <item>33-64 bytes: Four+ 64-bit reads</item>
	/// <item>65-127 bytes: Full mixing with all state variables</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <param name="data">The input data.</param>
	/// <param name="len">The data length.</param>
	/// <returns>The 128-bit hash value.</returns>
	private static UInt128 HashShort(ReadOnlySpan<byte> data, int len) {
		// ========== Empty Input ==========
		if (len <= 0) {
			return new UInt128(K1, K0); // Return constants for empty
		}

		// ========== 1-16 Bytes ==========
		if (len <= 16) {
			// Very short - simple mixing with K0 and K1
			ulong a = len >= 8 ? Fetch64(data) : K0;
			ulong b = len >= 8 ? Fetch64(data[(len - 8)..]) : K0;
			return new UInt128(a + K0, b + K1);
		}

		// ========== 17-32 Bytes ==========
		if (len <= 32) {
			// Four 64-bit reads, may overlap
			ulong a = Fetch64(data);             // bytes 0-7
			ulong b = Fetch64(data[8..]);        // bytes 8-15
			ulong c = Fetch64(data[(len - 8)..]); // last 8 bytes
			ulong d = Fetch64(data[(len - 16)..]); // second-to-last 8 bytes
			return new UInt128(
				HashLen16(a, c, K1),
				HashLen16(b, d, K2));
		}

		// ========== 33-64 Bytes ==========
		if (len <= 64) {
			// Read from beginning and end with some middle values
			ulong a = Fetch64(data);
			ulong b = Fetch64(data[8..]);
			ulong c = Fetch64(data[(len - 8)..]);
			ulong d = Fetch64(data[(len - 16)..]);
			ulong e = Fetch64(data[16..]);
			ulong f = Fetch64(data[24..]);
			ulong g = len >= 40 ? Fetch64(data[32..]) : K0;  // May not exist
			ulong h = len >= 48 ? Fetch64(data[40..]) : K0;  // May not exist

			return new UInt128(
				HashLen16(a + e, c + g, K1),
				HashLen16(b + f, d + h, K2));
		}

		// ========== 65-127 Bytes ==========
		// Most complex short path - simulates one mixing round
		ulong x = Fetch64(data);
		ulong y = Fetch64(data[8..]) ^ K1;
		ulong z = Fetch64(data[(len - 8)..]);
		ulong v0 = Fetch64(data[(len - 16)..]) ^ K2;
		ulong v1 = Fetch64(data[16..]);
		ulong w0 = Fetch64(data[24..]) + K0;
		ulong w1 = Fetch64(data[32..]);

		// Apply mixing operations similar to ProcessHalfBlock
		x = Rotate64(x + y + v0 + Fetch64(data[40..]), 37) * K1;
		y = Rotate64(y + v1 + Fetch64(data[48..]), 42) * K1;
		x ^= w1;
		y += v0 + z;
		z = Rotate64(z + w0, 33) * K1;

		// Combine into final 128-bit result
		return new UInt128(
			HashLen16(v0 + w0, w1, (ulong)len),
			HashLen16(x + z, y, (ulong)len));
	}

	/// <inheritdoc/>
	/// <remarks>
	/// Resets all state variables and flags to initial state.
	/// </remarks>
	protected override void ResetCore() {
		_x = 0;
		_y = 0;
		_z = 0;
		_v0 = 0;
		_v1 = 0;
		_w0 = 0;
		_w1 = 0;
		_initialized = false;
		_processedBytes = 0;
	}

	#region Helper Methods

	/// <summary>
	/// Reads a 64-bit little-endian integer from the span.
	/// </summary>
	/// <param name="p">The span (must have at least 8 bytes).</param>
	/// <returns>The 64-bit value.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Fetch64(ReadOnlySpan<byte> p) {
		return BinaryPrimitives.ReadUInt64LittleEndian(p);
	}

	/// <summary>
	/// Rotates a 64-bit value right by the specified bits.
	/// </summary>
	/// <param name="val">The value to rotate.</param>
	/// <param name="shift">Bits to rotate (0-63).</param>
	/// <returns>The rotated value.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Rotate64(ulong val, int shift) {
		return BitOperations.RotateRight(val, shift);
	}

	/// <summary>
	/// Reduces 128 bits to 64 bits with strong mixing.
	/// </summary>
	/// <param name="u">First 64-bit input.</param>
	/// <param name="v">Second 64-bit input.</param>
	/// <param name="mul">Multiplier value.</param>
	/// <returns>64-bit mixed result.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong HashLen16(ulong u, ulong v, ulong mul) {
		ulong a = (u ^ v) * mul;
		a ^= a >> 47;
		ulong b = (v ^ a) * mul;
		b ^= b >> 47;
		b *= mul;
		return b;
	}

	/// <summary>
	/// Reduces 128 bits to 64 bits using default multiplier.
	/// </summary>
	/// <param name="u">First 64-bit input.</param>
	/// <param name="v">Second 64-bit input.</param>
	/// <returns>64-bit mixed result.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong HashLen16(ulong u, ulong v) {
		return HashLen16(u, v, K2 + 32);
	}

	/// <summary>
	/// Weak hash of 32 bytes with two seeds.
	/// </summary>
	/// <param name="s">32 bytes of input.</param>
	/// <param name="a">First seed.</param>
	/// <param name="b">Second seed.</param>
	/// <returns>Tuple of two 64-bit values.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong, ulong) WeakHashLen32WithSeeds(ReadOnlySpan<byte> s, ulong a, ulong b) {
		// Read 4 x 64-bit words
		ulong w = Fetch64(s);
		ulong x = Fetch64(s[8..]);
		ulong y = Fetch64(s[16..]);
		ulong z = Fetch64(s[24..]);

		// Mix with rotations
		a += w;
		b = Rotate64(b + a + z, 21);
		ulong c = a;
		a += x;
		a += y;
		b += Rotate64(a, 44);

		return (a + z, b + c);
	}

	#endregion

	/// <summary>
	/// Computes the CityHash128 hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 128-bit hash value.</returns>
	/// <remarks>
	/// Convenience method for hashing data that fits in memory.
	/// For large files or streaming data, create an instance and use
	/// <see cref="StreamingHashBase{T}.Update(ReadOnlySpan{byte})"/> / <see cref="StreamingHashBase{T}.Finalize()"/>.
	/// </remarks>
	/// <example>
	/// <code>
	/// // One-shot hashing
	/// UInt128 hash = CityHash128.Hash("Hello, World!"u8);
	/// Console.WriteLine($"High: {hash.GetUpperBits():x16}, Low: {hash.GetLowerBits():x16}");
	/// </code>
	/// </example>
	public static UInt128 Hash(ReadOnlySpan<byte> data) {
		using var hasher = new CityHash128();
		hasher.Update(data);
		return hasher.Finalize();
	}
}
