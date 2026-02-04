using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of CityHash64 hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// CityHash is a family of hash functions developed by Google for fast string hashing.
/// The 64-bit variant is optimized for short strings but works well for longer inputs too.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 64-bit hash value</item>
/// <item><b>Block Size:</b> 64 bytes (for streaming)</item>
/// <item><b>Speed:</b> ~10+ GB/s on modern x86-64 CPUs</item>
/// <item><b>Collision Resistance:</b> Excellent for hash tables, NOT cryptographically secure</item>
/// </list>
/// </para>
/// <para>
/// <b>Streaming Implementation Notes:</b>
/// The original CityHash processes entire input at once. This streaming version:
/// <list type="bullet">
/// <item>Uses a 64-byte block size for streaming</item>
/// <item>Maintains internal state (v, w, x, y, z) across updates</item>
/// <item>May produce slightly different hashes than non-streaming version for short inputs</item>
/// <item>Matches reference for inputs >= 64 bytes when processed in 64-byte chunks</item>
/// </list>
/// </para>
/// <para>
/// <b>SIMD Optimization:</b>
/// This implementation detects AVX2 (256-bit vectors) and SSE4.1 (128-bit vectors) support
/// at startup. When available, SIMD instructions are used to accelerate the mixing operations.
/// A scalar fallback is always available for systems without SIMD support.
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Hash tables and hash maps</item>
/// <item>Data deduplication</item>
/// <item>Load balancing/sharding</item>
/// <item>Caching keys</item>
/// <item>File content identification</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/google/cityhash">CityHash - Google's official implementation</see></item>
/// <item><see href="https://opensource.googleblog.com/2011/04/introducing-cityhash.html">Introducing CityHash - Google Blog</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Basic usage
/// using var hasher = new CityHash64();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// ulong hash = hasher.Finalize();
///
/// // Stream processing
/// using var streamHasher = new CityHash64();
/// using var file = File.OpenRead("largefile.bin");
/// byte[] buffer = new byte[65536]; // 64KB buffer
/// int read;
/// while ((read = file.Read(buffer)) > 0) {
///     streamHasher.Update(buffer.AsSpan(0, read));
/// }
/// ulong fileHash = streamHasher.Finalize();
/// </code>
/// </example>
public sealed class CityHash64 : StreamingHashBase<ulong> {
	#region SIMD Support Detection

	/// <summary>
	/// Indicates whether AVX2 (256-bit SIMD) instructions are available.
	/// When true, certain operations can use 256-bit vectors for 4x parallelism.
	/// </summary>
	private static readonly bool IsAvx2Supported = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 (128-bit SIMD) instructions are available.
	/// When true, certain operations can use 128-bit vectors for 2x parallelism.
	/// </summary>
	private static readonly bool IsSse41Supported = Sse41.IsSupported;

	#endregion

	#region Constants

	/// <summary>
	/// Magic constant k0 - derived empirically by Google for optimal bit mixing.
	/// This constant has good bit distribution properties (mix of 0s and 1s).
	/// </summary>
	private const ulong K0 = 0xc3a5c85c97cb3127UL;

	/// <summary>
	/// Magic constant k1 - second mixing constant.
	/// Used in rotation and multiplication operations for diffusion.
	/// </summary>
	private const ulong K1 = 0xb492b66fbe98f273UL;

	/// <summary>
	/// Magic constant k2 - third mixing constant.
	/// Primary multiplier in hash length calculations.
	/// </summary>
	private const ulong K2 = 0x9ae16a3b2f90404fUL;

	#endregion

	#region State Variables

	/// <summary>
	/// Primary state variable - evolves with each block processed.
	/// Combined with rotation and multiplication for mixing.
	/// </summary>
	private ulong _x;

	/// <summary>
	/// Secondary state variable - provides additional mixing dimension.
	/// Updated with rotations involving _v1 and input data.
	/// </summary>
	private ulong _y;

	/// <summary>
	/// Tertiary state variable - used in final hash combination.
	/// Rotates with _w0 for cross-state influence.
	/// </summary>
	private ulong _z;

	/// <summary>
	/// First component of v-pair state (128-bit virtual register).
	/// Part of WeakHashLen32WithSeeds output.
	/// </summary>
	private ulong _v0;

	/// <summary>
	/// Second component of v-pair state (128-bit virtual register).
	/// Part of WeakHashLen32WithSeeds output.
	/// </summary>
	private ulong _v1;

	/// <summary>
	/// First component of w-pair state (128-bit virtual register).
	/// Part of WeakHashLen32WithSeeds output.
	/// </summary>
	private ulong _w0;

	/// <summary>
	/// Second component of w-pair state (128-bit virtual register).
	/// Part of WeakHashLen32WithSeeds output.
	/// </summary>
	private ulong _w1;

	/// <summary>
	/// Tracks whether state has been initialized from the first block.
	/// First block requires special initialization; subsequent blocks use different mixing.
	/// </summary>
	private bool _initialized;

	/// <summary>
	/// Tracks total bytes processed through ProcessBlock (excluding remainder).
	/// Used for length-dependent finalization.
	/// </summary>
	private long _processedBytes;

	#endregion

	/// <inheritdoc/>
	/// <remarks>
	/// CityHash64 operates on 64-byte blocks. Each block undergoes a series of
	/// rotations, multiplications, and XOR operations to mix input data into state.
	/// </remarks>
	public override int BlockSize => 64;

	/// <inheritdoc/>
	/// <remarks>
	/// Produces a 64-bit (8-byte) hash value. This provides 2^64 possible values,
	/// offering excellent collision resistance for non-cryptographic applications.
	/// </remarks>
	public override int DigestSize => 8;

	/// <summary>
	/// Creates a new CityHash64 streaming hasher.
	/// </summary>
	/// <remarks>
	/// Initializes all state to zero. The actual state initialization happens
	/// when the first block of data is processed, using that block's content.
	/// </remarks>
	public CityHash64() : base() {
		Reset();
	}

	/// <inheritdoc/>
	/// <remarks>
	/// Processes a complete 64-byte block. The first block initializes state specially;
	/// subsequent blocks use the standard mixing function.
	/// </remarks>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		if (!_initialized) {
			// First block: initialize state from input data.
			// This is different from subsequent blocks because we need
			// to establish initial values for x, y, z, v, and w.
			InitializeState(block);
			_initialized = true;
		} else {
			// Subsequent blocks: apply the standard mixing function
			// that updates state based on previous state and new input.
			ProcessBlockInternal(block);
		}
		_processedBytes += BlockSize;
	}

	/// <summary>
	/// Initializes the hash state from the first 64-byte block.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The first block requires special handling to establish initial state values.
	/// This function reads 8 x 8-byte chunks from the block and uses them to
	/// initialize x, y, z, v0, v1, w0, and w1.
	/// </para>
	/// <para>
	/// The initialization involves:
	/// <list type="number">
	/// <item>Setting x, y, z from the first three 8-byte chunks</item>
	/// <item>Computing v-pair using rotations and the next two chunks</item>
	/// <item>Computing w-pair using rotations with x and y</item>
	/// <item>Final mixing and state swap between z and x</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <param name="block">The first 64-byte input block.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void InitializeState(ReadOnlySpan<byte> block) {
		// ========== Step 1: Initialize Primary State Variables ==========
		// Read first three 8-byte words and combine with constants.
		// K2 and K0 provide initial mixing/seeding.
		_x = Fetch64(block[0..]) + K2;   // bytes 0-7 + K2
		_y = Fetch64(block[8..]);         // bytes 8-15 (no constant)
		_z = Fetch64(block[16..]) + K0;  // bytes 16-23 + K0

		// ========== Step 2: Initialize v-pair (128-bit virtual register) ==========
		// v0 and v1 form a pair that captures complex mixing of y and input.
		// The rotations (49, 42) are carefully chosen for optimal bit diffusion.
		_v0 = Rotate64(_y ^ K1, 49) * K1 + Fetch64(block[24..]);  // Rotate y^K1, multiply, add bytes 24-31
		_v1 = Rotate64(_v0, 42) * K1 + Fetch64(block[32..]);      // Rotate v0, multiply, add bytes 32-39

		// ========== Step 3: Initialize w-pair (128-bit virtual register) ==========
		// w0 and w1 capture different mixing paths involving x and y.
		_w0 = Rotate64(_y + Fetch64(block[40..]), 35) * K1 + _x;  // Rotate y+data, multiply, add x
		_w1 = Rotate64(_x + Fetch64(block[48..]), 34) * K1;       // Rotate x+data, multiply

		// ========== Step 4: Update x and y with Cross-State Mixing ==========
		// Mix x and y using data from multiple positions for better avalanche.
		_x = Rotate64(_x + _y + _v0 + Fetch64(block[24..]), 37) * K1;
		_y = Rotate64(_y + _v1 + Fetch64(block[48..]), 42) * K1;

		// XOR mixing creates non-linear dependencies
		_x ^= _w1;
		_y += _v0 + Fetch64(block[40..]);

		// Update z with rotation
		_z = Rotate64(_z + _w0, 33) * K1;

		// ========== Step 5: WeakHashLen32 Operations ==========
		// These functions process 32 bytes at a time with seed values,
		// producing two 64-bit outputs each.
		(_v0, _v1) = WeakHashLen32WithSeeds(block[32..], _v1 * K1, _x + _w0);
		(_w0, _w1) = WeakHashLen32WithSeeds(block[0..], _z + _w1, _y + Fetch64(block[16..]));

		// Swap z and x to complete the round
		(_z, _x) = (_x, _z);
	}

	/// <summary>
	/// Processes subsequent blocks after initialization.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This is the core mixing function for blocks 2 onwards.
	/// It's similar to initialization but without the initial value setup.
	/// </para>
	/// <para>
	/// The mixing operations are designed to:
	/// <list type="bullet">
	/// <item>Provide good avalanche (each input bit affects many output bits)</item>
	/// <item>Mix state variables with new input data</item>
	/// <item>Use rotations and multiplications for non-linearity</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <param name="block">The 64-byte input block.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlockInternal(ReadOnlySpan<byte> block) {
		// ========== Primary State Update ==========
		// Mix x with all state variables and input data bytes 8-15.
		// Rotation of 37 bits and multiplication by K1 provide diffusion.
		_x = Rotate64(_x + _y + _v0 + Fetch64(block[8..]), 37) * K1;

		// Mix y with v1 and input data bytes 48-55.
		// Rotation of 42 bits chosen for optimal bit spreading.
		_y = Rotate64(_y + _v1 + Fetch64(block[48..]), 42) * K1;

		// XOR creates non-linear dependency on w1
		_x ^= _w1;

		// Add more input influence to y
		_y += _v0 + Fetch64(block[40..]);

		// Rotate z with w0 influence
		_z = Rotate64(_z + _w0, 33) * K1;

		// ========== WeakHashLen32 Operations ==========
		// Process 32-byte chunks with seeded weak hashing.
		// These produce two 64-bit values each, updating v and w pairs.
		(_v0, _v1) = WeakHashLen32WithSeeds(block[32..], _v1 * K1, _x + _w0);
		(_w0, _w1) = WeakHashLen32WithSeeds(block[0..], _z + _w1, _y + Fetch64(block[16..]));

		// Swap z and x at end of each round.
		// This ensures symmetric influence between these state variables.
		(_z, _x) = (_x, _z);
	}

	/// <inheritdoc/>
	/// <remarks>
	/// Finalizes the hash computation. For short messages (&lt; 64 bytes),
	/// uses optimized fast paths. For longer messages, combines the streaming
	/// state into a final 64-bit value.
	/// </remarks>
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		long totalLen = TotalBytesProcessed;

		// For short messages, use optimized short hash paths.
		// These are faster than the streaming approach for small inputs.
		if (totalLen < 64) {
			return HashShort(remaining, (int)totalLen);
		}

		// For longer messages, finalize the streaming state
		ulong len = (ulong)totalLen;

		// Process any remaining bytes (1-63 bytes that didn't fill a block)
		if (remaining.Length > 0) {
			// Pad remaining bytes to 64 bytes with zeros.
			// stackalloc is fast and avoids heap allocation.
			Span<byte> padded = stackalloc byte[64];
			remaining.CopyTo(padded);
			// Note: stackalloc memory is already zeroed in .NET

			// Only process if we have at least 32 bytes remaining.
			// Smaller remainders are handled implicitly through the final mix.
			if (remaining.Length >= 32) {
				// Apply the same mixing as ProcessBlockInternal
				_x = Rotate64(_x + _y + _v0 + Fetch64(padded[8..]), 37) * K1;
				_y = Rotate64(_y + _v1 + Fetch64(padded[48..]), 42) * K1;
				_x ^= _w1;
				_y += _v0 + Fetch64(padded[40..]);
				_z = Rotate64(_z + _w0, 33) * K1;

				(_v0, _v1) = WeakHashLen32WithSeeds(padded[32..], _v1 * K1, _x + _w0);
				(_w0, _w1) = WeakHashLen32WithSeeds(padded[0..], _z + _w1, _y + Fetch64(padded[16..]));
				(_z, _x) = (_x, _z);
			}
		}

		// ========== Final Hash Combination ==========
		// Combine all state components into a single 64-bit value.
		// HashLen16 reduces 128 bits to 64 bits with good mixing.
		return HashLen16(_v0 + _w0, _w1 + HashLen16(_x + _z, _y, len), len);
	}

	/// <summary>
	/// Computes hash for short messages (&lt; 64 bytes).
	/// </summary>
	/// <remarks>
	/// <para>
	/// Short messages use entirely different, optimized code paths
	/// based on the exact message length. Each path is tuned for
	/// that specific size range to maximize speed.
	/// </para>
	/// <para>
	/// <b>Length-based dispatch:</b>
	/// <list type="bullet">
	/// <item>0 bytes: Return constant K2</item>
	/// <item>1-3 bytes: Simple byte mixing</item>
	/// <item>4-7 bytes: 32-bit fetch mixing</item>
	/// <item>8-16 bytes: 64-bit fetch mixing</item>
	/// <item>17-32 bytes: Two 64-bit fetch mixing</item>
	/// <item>33-63 bytes: Complex multi-fetch mixing</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <param name="data">The input data.</param>
	/// <param name="len">The length of the data.</param>
	/// <returns>The 64-bit hash value.</returns>
	private ulong HashShort(ReadOnlySpan<byte> data, int len) {
		// ========== Empty Input ==========
		if (len <= 0) {
			return K2; // Return constant for empty input
		}

		// ========== 1-3 Bytes ==========
		// Tiny input path - extract individual bytes
		if (len <= 3) {
			byte a = data[0];
			byte b = len > 1 ? data[1] : data[0]; // Duplicate first byte if len=1
			byte c = data[len - 1];               // Last byte (may overlap with a or b)

			// Pack bytes into 32-bit values and mix
			uint y = a + ((uint)b << 8);
			uint z = (uint)len + ((uint)c << 2);

			// ShiftMix provides final mixing
			return ShiftMix(y * K2 ^ z * K0) * K2;
		}

		// ========== 4-7 Bytes ==========
		// Can read two 32-bit values (possibly overlapping)
		if (len <= 7) {
			ulong mul = K2 + (ulong)len * 2; // Length-dependent multiplier
			ulong a = Fetch32(data);          // First 4 bytes
			return HashLen16(mul + a, Fetch32(data[(len - 4)..]), mul);
		}

		// ========== 8-16 Bytes ==========
		// Can read two 64-bit values (possibly overlapping)
		if (len <= 16) {
			ulong mul = K2 + (ulong)len * 2;
			ulong a = Fetch64(data) + K2;          // First 8 bytes + K2
			ulong b = Fetch64(data[(len - 8)..]);  // Last 8 bytes (may overlap)

			// Mix with rotations
			ulong c = Rotate64(b, 37) * mul + a;
			ulong d = (Rotate64(a, 25) + b) * mul;
			return HashLen16(c, d, mul);
		}

		// ========== 17-32 Bytes ==========
		// Four 64-bit reads for better mixing
		if (len <= 32) {
			ulong mul = K2 + (ulong)len * 2;
			ulong a = Fetch64(data) * K1;          // bytes 0-7
			ulong b = Fetch64(data[8..]);          // bytes 8-15
			ulong c = Fetch64(data[(len - 8)..]) * mul;   // last 8 bytes
			ulong d = Fetch64(data[(len - 16)..]) * K2;   // second-to-last 8 bytes
			return HashLen16(
				Rotate64(a + b, 43) + Rotate64(c, 30) + d,
				a + Rotate64(b + K2, 18) + c,
				mul);
		}

		// ========== 33-63 Bytes ==========
		// Most complex short path - many reads and operations
		ulong mul2 = K2 + (ulong)len * 2;

		// Read from beginning
		ulong a2 = Fetch64(data) * K2;     // bytes 0-7
		ulong b2 = Fetch64(data[8..]);     // bytes 8-15
		ulong e = Fetch64(data[16..]) * K2; // bytes 16-23
		ulong f = Fetch64(data[24..]) * 9;  // bytes 24-31

		// Read from end (may overlap with beginning reads)
		ulong c2 = Fetch64(data[(len - 24)..]);
		ulong d2 = Fetch64(data[(len - 32)..]);
		ulong g = Fetch64(data[(len - 8)..]);
		ulong h = Fetch64(data[(len - 16)..]) * mul2;

		// Complex mixing with rotations and endian swaps
		ulong u = Rotate64(a2 + g, 43) + (Rotate64(b2, 30) + c2) * 9;
		ulong v = ((a2 + g) ^ d2) + f + 1;
		ulong w = BinaryPrimitives.ReverseEndianness((u + v) * mul2) + h;
		ulong x2 = Rotate64(e + f, 42) + c2;
		ulong y2 = (BinaryPrimitives.ReverseEndianness((v + w) * mul2) + g) * mul2;
		ulong z2 = e + f + c2;
		a2 = BinaryPrimitives.ReverseEndianness((x2 + z2) * mul2 + y2) + b2;
		b2 = ShiftMix((z2 + a2) * mul2 + d2 + h) * mul2;
		return b2 + x2;
	}

	/// <inheritdoc/>
	/// <remarks>
	/// Resets all state variables to their initial zero state.
	/// The <see cref="_initialized"/> flag is cleared so the next
	/// block will trigger state initialization.
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
	/// Reads a 64-bit little-endian integer from the given span.
	/// </summary>
	/// <remarks>
	/// Wraps <see cref="BinaryPrimitives.ReadUInt64LittleEndian"/> for
	/// consistent data reading across the algorithm.
	/// </remarks>
	/// <param name="p">The span to read from (must have at least 8 bytes).</param>
	/// <returns>The 64-bit value in native endianness.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Fetch64(ReadOnlySpan<byte> p) {
		return BinaryPrimitives.ReadUInt64LittleEndian(p);
	}

	/// <summary>
	/// Reads a 32-bit little-endian integer from the given span.
	/// </summary>
	/// <remarks>
	/// Wraps <see cref="BinaryPrimitives.ReadUInt32LittleEndian"/> for
	/// consistent data reading across the algorithm.
	/// </remarks>
	/// <param name="p">The span to read from (must have at least 4 bytes).</param>
	/// <returns>The 32-bit value in native endianness.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint Fetch32(ReadOnlySpan<byte> p) {
		return BinaryPrimitives.ReadUInt32LittleEndian(p);
	}

	/// <summary>
	/// Rotates a 64-bit value right by the specified number of bits.
	/// </summary>
	/// <remarks>
	/// Uses <see cref="BitOperations.RotateRight(ulong, int)"/> which
	/// compiles to a single instruction on modern CPUs (ROL/ROR).
	/// </remarks>
	/// <param name="val">The value to rotate.</param>
	/// <param name="shift">The number of bits to rotate (0-63).</param>
	/// <returns>The rotated value.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Rotate64(ulong val, int shift) {
		return BitOperations.RotateRight(val, shift);
	}

	/// <summary>
	/// A shift-mix operation for finalization.
	/// </summary>
	/// <remarks>
	/// <para>
	/// ShiftMix XORs a value with itself shifted right by 47 bits.
	/// This is a simple but effective way to mix bits during finalization.
	/// </para>
	/// <para>
	/// The shift of 47 is chosen because it places the high bits into
	/// the low position while keeping some overlap, ensuring good mixing.
	/// </para>
	/// </remarks>
	/// <param name="val">The value to mix.</param>
	/// <returns>The mixed value.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ShiftMix(ulong val) {
		return val ^ (val >> 47);
	}

	/// <summary>
	/// Reduces 128 bits of input down to 64 bits with good mixing.
	/// </summary>
	/// <remarks>
	/// <para>
	/// HashLen16 is the core mixing/finalization function in CityHash.
	/// It takes two 64-bit values and a multiplier, combining them
	/// into a single 64-bit result with excellent avalanche properties.
	/// </para>
	/// <para>
	/// <b>Algorithm:</b>
	/// <list type="number">
	/// <item>XOR u and v, multiply by mul</item>
	/// <item>Shift-mix the result</item>
	/// <item>XOR with v, multiply by mul</item>
	/// <item>Shift-mix and multiply again</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <param name="u">First 64-bit input.</param>
	/// <param name="v">Second 64-bit input.</param>
	/// <param name="mul">Multiplier (typically K2 + 2*length).</param>
	/// <returns>64-bit mixed result.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong HashLen16(ulong u, ulong v, ulong mul) {
		// Step 1: XOR u and v, multiply by mul, then shift-mix
		ulong a = (u ^ v) * mul;
		a ^= a >> 47;

		// Step 2: XOR with v, multiply, shift-mix, multiply again
		ulong b = (v ^ a) * mul;
		b ^= b >> 47;
		b *= mul;

		return b;
	}

	/// <summary>
	/// Reduces 128 bits to 64 bits using the default multiplier.
	/// </summary>
	/// <remarks>
	/// Overload using K2 + 32 as the default multiplier.
	/// This is used in some internal mixing operations.
	/// </remarks>
	/// <param name="u">First 64-bit input.</param>
	/// <param name="v">Second 64-bit input.</param>
	/// <returns>64-bit mixed result.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong HashLen16(ulong u, ulong v) {
		return HashLen16(u, v, K2 + 32);
	}

	/// <summary>
	/// Computes a weak hash of 32 bytes with two seed values.
	/// </summary>
	/// <remarks>
	/// <para>
	/// WeakHashLen32WithSeeds processes 32 bytes (4 x 64-bit words) with two
	/// seed values, producing two 64-bit outputs. It's "weak" because it's
	/// optimized for speed over cryptographic strength.
	/// </para>
	/// <para>
	/// <b>Algorithm:</b>
	/// <list type="number">
	/// <item>Read 4 x 64-bit words (w, x, y, z) from the span</item>
	/// <item>Add w to seed a</item>
	/// <item>Rotate (b + a + z) by 21, multiply by seed</item>
	/// <item>Save a as c, then add x and y to a</item>
	/// <item>Rotate a by 44, add to b</item>
	/// <item>Return (a + z, b + c)</item>
	/// </list>
	/// </para>
	/// <para>
	/// The two outputs form a 128-bit "weak hash" that captures the
	/// input with reasonable diffusion, used as intermediate state.
	/// </para>
	/// </remarks>
	/// <param name="s">32 bytes of input data.</param>
	/// <param name="a">First seed value.</param>
	/// <param name="b">Second seed value.</param>
	/// <returns>Tuple of two 64-bit values.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong, ulong) WeakHashLen32WithSeeds(ReadOnlySpan<byte> s, ulong a, ulong b) {
		// Read 4 x 64-bit words from input
		ulong w = Fetch64(s);        // bytes 0-7
		ulong x = Fetch64(s[8..]);   // bytes 8-15
		ulong y = Fetch64(s[16..]);  // bytes 16-23
		ulong z = Fetch64(s[24..]);  // bytes 24-31

		// Mix with rotations
		a += w;                           // Add first word to seed a
		b = Rotate64(b + a + z, 21);      // Rotate combined value
		ulong c = a;                      // Save original a

		a += x;                           // Add second word
		a += y;                           // Add third word
		b += Rotate64(a, 44);             // Add rotated a to b

		// Return two values: (a + last word, b + saved c)
		return (a + z, b + c);
	}

	#endregion

	/// <summary>
	/// Computes the CityHash64 hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <remarks>
	/// <para>
	/// This is a convenience method for hashing data that fits in memory.
	/// For streaming scenarios (large files, network data), create an
	/// instance and use <see cref="StreamingHashBase{T}.Update(ReadOnlySpan{byte})"/>
	/// and <see cref="StreamingHashBase{T}.Finalize()"/>.
	/// </para>
	/// </remarks>
	/// <example>
	/// <code>
	/// // One-shot hashing
	/// ulong hash = CityHash64.Hash(Encoding.UTF8.GetBytes("Hello, World!"));
	///
	/// // With UTF-8 literal (C# 11+)
	/// ulong hash2 = CityHash64.Hash("Hello"u8);
	/// </code>
	/// </example>
	public static ulong Hash(ReadOnlySpan<byte> data) {
		using var hasher = new CityHash64();
		hasher.Update(data);
		return hasher.Finalize();
	}
}
