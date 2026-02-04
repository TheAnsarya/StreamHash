using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of MurmurHash3 128-bit x64 hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// MurmurHash3 128-bit x64 is optimized for 64-bit processors and produces
/// a 128-bit hash value, providing better collision resistance than the 32-bit variant.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 128-bit hash value (as <see cref="UInt128"/>)</item>
/// <item><b>Block Size:</b> 16 bytes</item>
/// <item><b>Speed:</b> ~5-7 GB/s on modern 64-bit CPUs</item>
/// <item><b>Collision Resistance:</b> Excellent for hash tables, NOT cryptographically secure</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// The 128-bit variant processes data in 16-byte blocks using two 64-bit accumulators (h1, h2).
/// Each block is split into two 8-byte halves (k1, k2) which are independently mixed before
/// being XORed into h1 and h2 respectively. The accumulators are also cross-mixed to ensure
/// all input bits influence all output bits.
/// </para>
/// <para>
/// <b>Performance Notes:</b>
/// <list type="bullet">
/// <item>Optimized for 64-bit processors; use 32-bit variant on 32-bit systems</item>
/// <item>Processes 16 bytes per iteration for maximum throughput</item>
/// <item>Uses rotation and multiplication for mixing</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/aappleby/smhasher">SMHasher - Original MurmurHash repository</see></item>
/// <item><see href="https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp">Original C++ Implementation</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class MurmurHash3_128 : StreamingHashBase<UInt128> {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	/// <remarks>
	/// AVX2 provides 256-bit vector operations that could process multiple blocks
	/// in parallel for batch hashing scenarios.
	/// </remarks>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// MurmurHash3-128 Constants
	// ═══════════════════════════════════════════════════════════════════════════
	// These 64-bit constants were carefully chosen to maximize avalanche behavior
	// and minimize collisions in the 128-bit x64 variant.

	/// <summary>
	/// First mixing constant C1 for the 128-bit x64 variant.
	/// </summary>
	/// <remarks>
	/// Value: 0x87c37b91114253d5 (9782968156834903509 decimal)
	/// Used to mix the first 64-bit block (k1).
	/// </remarks>
	private const ulong C1 = 0x87c37b91114253d5;

	/// <summary>
	/// Second mixing constant C2 for the 128-bit x64 variant.
	/// </summary>
	/// <remarks>
	/// Value: 0x4cf5ad432745937f (5545529020109919039 decimal)
	/// Used to mix the second 64-bit block (k2).
	/// </remarks>
	private const ulong C2 = 0x4cf5ad432745937f;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>The seed value used to initialize both hash accumulators.</summary>
	private readonly uint _seed;

	/// <summary>
	/// First 64-bit hash accumulator. Processes odd-numbered blocks (k1).
	/// Combined with h2 in finalization to produce bits 0-63 of the output.
	/// </summary>
	private ulong _h1;

	/// <summary>
	/// Second 64-bit hash accumulator. Processes even-numbered blocks (k2).
	/// Combined with h1 in finalization to produce bits 64-127 of the output.
	/// </summary>
	private ulong _h2;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>MurmurHash3-128 processes 16 bytes (128 bits) per block.</remarks>
	public override int BlockSize => 16;

	/// <inheritdoc/>
	/// <remarks>MurmurHash3-128 produces a 16-byte (128-bit) hash value.</remarks>
	public override int DigestSize => 16;

	/// <summary>
	/// Gets the seed value used for this hash instance.
	/// </summary>
	/// <remarks>
	/// The seed initializes both h1 and h2 accumulators.
	/// Different seeds produce completely different hashes.
	/// </remarks>
	public uint Seed => _seed;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new MurmurHash3 128-bit hasher with seed 0.
	/// </summary>
	public MurmurHash3_128() : this(0) { }

	/// <summary>
	/// Creates a new MurmurHash3 128-bit hasher with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for hash computation.</param>
	/// <remarks>
	/// The 32-bit seed is used to initialize both 64-bit hash accumulators.
	/// This provides different hash functions for techniques like Bloom filters.
	/// </remarks>
	public MurmurHash3_128(uint seed) {
		_seed = seed;
		// Both accumulators start with the same seed value
		_h1 = seed;
		_h2 = seed;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Core Algorithm Implementation
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Processes a 16-byte block through the MurmurHash3-128 mixing function.
	/// </para>
	/// <para>
	/// <b>Algorithm Steps for k1 (bytes 0-7):</b>
	/// <list type="number">
	/// <item>Read bytes 0-7 as little-endian uint64</item>
	/// <item>Multiply by C1, rotate left 31, multiply by C2</item>
	/// <item>XOR into h1, rotate h1 left 27, add h2</item>
	/// <item>Apply h1 = h1 * 5 + 0x52dce729</item>
	/// </list>
	/// </para>
	/// <para>
	/// <b>Algorithm Steps for k2 (bytes 8-15):</b>
	/// <list type="number">
	/// <item>Read bytes 8-15 as little-endian uint64</item>
	/// <item>Multiply by C2, rotate left 33, multiply by C1</item>
	/// <item>XOR into h2, rotate h2 left 31, add h1</item>
	/// <item>Apply h2 = h2 * 5 + 0x38495ab5</item>
	/// </list>
	/// Note: k2 uses C2 then C1 (opposite order from k1) for better mixing.
	/// </para>
	/// </remarks>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		// ═══════════════════════════════════════════════════════════════════════
		// Read the 16-byte block as two 64-bit values
		// ═══════════════════════════════════════════════════════════════════════
		ulong k1 = BinaryPrimitives.ReadUInt64LittleEndian(block);
		ulong k2 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);

		// ═══════════════════════════════════════════════════════════════════════
		// Mix k1 (first 8 bytes) into h1
		// ═══════════════════════════════════════════════════════════════════════
		// Multiply-rotate-multiply spreads bit influence
		k1 *= C1;
		k1 = BitOperations.RotateLeft(k1, 31);
		k1 *= C2;
		// XOR mixed k1 into accumulator h1
		_h1 ^= k1;

		// Cross-mix: rotate h1 and add h2 to couple the accumulators
		_h1 = BitOperations.RotateLeft(_h1, 27);
		_h1 += _h2;
		// Final mixing step with magic constant
		_h1 = _h1 * 5 + 0x52dce729;

		// ═══════════════════════════════════════════════════════════════════════
		// Mix k2 (second 8 bytes) into h2
		// ═══════════════════════════════════════════════════════════════════════
		// Note: Uses C2 then C1 (opposite order) for asymmetric mixing
		k2 *= C2;
		k2 = BitOperations.RotateLeft(k2, 33);  // Different rotation (33 vs 31)
		k2 *= C1;
		// XOR mixed k2 into accumulator h2
		_h2 ^= k2;

		// Cross-mix: rotate h2 and add h1
		_h2 = BitOperations.RotateLeft(_h2, 31);
		_h2 += _h1;
		// Final mixing step with different magic constant
		_h2 = _h2 * 5 + 0x38495ab5;
	}

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Handles remaining bytes (0-15) and applies the finalization mix.
	/// </para>
	/// <para>
	/// <b>Tail Processing:</b>
	/// Bytes 8-15 are accumulated into k2, bytes 0-7 into k1.
	/// Each is mixed with the appropriate constants before XOR into h1/h2.
	/// </para>
	/// <para>
	/// <b>Finalization:</b>
	/// <list type="number">
	/// <item>XOR total length into both h1 and h2</item>
	/// <item>Cross-add: h1 += h2, h2 += h1</item>
	/// <item>Apply fmix64 to both accumulators</item>
	/// <item>Final cross-add to complete mixing</item>
	/// </list>
	/// </para>
	/// </remarks>
	protected override UInt128 ComputeFinal(ReadOnlySpan<byte> remaining) {
		ulong k1 = 0;
		ulong k2 = 0;

		// ═══════════════════════════════════════════════════════════════════════
		// Tail Processing (remaining 1-15 bytes)
		// ═══════════════════════════════════════════════════════════════════════
		// Process bytes 8-14 into k2 (if present)
		int len = remaining.Length;

		if (len >= 15) k2 ^= (ulong)remaining[14] << 48;
		if (len >= 14) k2 ^= (ulong)remaining[13] << 40;
		if (len >= 13) k2 ^= (ulong)remaining[12] << 32;
		if (len >= 12) k2 ^= (ulong)remaining[11] << 24;
		if (len >= 11) k2 ^= (ulong)remaining[10] << 16;
		if (len >= 10) k2 ^= (ulong)remaining[9] << 8;
		if (len >= 9) {
			// Byte 8 is the first byte of k2
			k2 ^= remaining[8];
			// Mix k2 (using C2, rotate, C1 - same as full block)
			k2 *= C2;
			k2 = BitOperations.RotateLeft(k2, 33);
			k2 *= C1;
			_h2 ^= k2;
		}

		// Process bytes 0-7 into k1
		if (len >= 8) k1 ^= BinaryPrimitives.ReadUInt64LittleEndian(remaining);
		else {
			// Build k1 byte-by-byte for partial data
			if (len >= 7) k1 ^= (ulong)remaining[6] << 48;
			if (len >= 6) k1 ^= (ulong)remaining[5] << 40;
			if (len >= 5) k1 ^= (ulong)remaining[4] << 32;
			if (len >= 4) k1 ^= (ulong)remaining[3] << 24;
			if (len >= 3) k1 ^= (ulong)remaining[2] << 16;
			if (len >= 2) k1 ^= (ulong)remaining[1] << 8;
			if (len >= 1) k1 ^= remaining[0];
		}

		// Mix k1 if we have any bytes for it
		if (len > 0 && len < 9) {
			k1 *= C1;
			k1 = BitOperations.RotateLeft(k1, 31);
			k1 *= C2;
			_h1 ^= k1;
		} else if (len >= 9) {
			k1 *= C1;
			k1 = BitOperations.RotateLeft(k1, 31);
			k1 *= C2;
			_h1 ^= k1;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Finalization
		// ═══════════════════════════════════════════════════════════════════════
		// XOR in total length to ensure different lengths produce different hashes
		_h1 ^= (ulong)TotalBytesProcessed;
		_h2 ^= (ulong)TotalBytesProcessed;

		// Cross-add to couple h1 and h2 before finalization
		_h1 += _h2;
		_h2 += _h1;

		// Apply avalanche function to both accumulators
		_h1 = FMix64(_h1);
		_h2 = FMix64(_h2);

		// Final cross-add ensures all bits are fully mixed
		_h1 += _h2;
		_h2 += _h1;

		// Return as UInt128: h2 is high 64 bits, h1 is low 64 bits
		return new UInt128(_h2, _h1);
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		// Reset both accumulators to seed value
		_h1 = _seed;
		_h2 = _seed;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Helper Functions
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// MurmurHash3 64-bit finalization mix (fmix64) - forces all bits to avalanche.
	/// </summary>
	/// <param name="k">The 64-bit value to finalize.</param>
	/// <returns>The mixed value with full avalanche properties.</returns>
	/// <remarks>
	/// <para>
	/// The fmix64 function ensures that every bit of the input affects every bit
	/// of the output. This is essential for good hash distribution.
	/// </para>
	/// <para>
	/// <b>Algorithm:</b>
	/// <list type="number">
	/// <item>k ^= k >> 33 (mix high bits into low bits)</item>
	/// <item>k *= 0xff51afd7ed558ccd (magic constant 1)</item>
	/// <item>k ^= k >> 33 (further mixing)</item>
	/// <item>k *= 0xc4ceb9fe1a85ec53 (magic constant 2)</item>
	/// <item>k ^= k >> 33 (final mixing)</item>
	/// </list>
	/// </para>
	/// <para>
	/// Constants chosen through extensive testing to maximize avalanche behavior.
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong FMix64(ulong k) {
		// Mix with 33-bit shift (half of 64 bits, rounded up)
		k ^= k >> 33;
		// First magic multiplication constant
		k *= 0xff51afd7ed558ccd;
		// Second mixing shift
		k ^= k >> 33;
		// Second magic multiplication constant
		k *= 0xc4ceb9fe1a85ec53;
		// Final mixing shift
		k ^= k >> 33;
		return k;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Convenience Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes the MurmurHash3 128-bit hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">Optional seed value (default: 0).</param>
	/// <returns>The 128-bit hash value.</returns>
	/// <remarks>
	/// This is a convenience method for hashing data that fits in memory.
	/// For streaming scenarios, create an instance and use Update/Finalize.
	/// </remarks>
	public static UInt128 Hash(ReadOnlySpan<byte> data, uint seed = 0) {
		using var hasher = new MurmurHash3_128(seed);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
