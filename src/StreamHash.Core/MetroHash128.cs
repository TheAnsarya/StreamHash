using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of MetroHash128, an extremely fast non-cryptographic hash.
/// </summary>
/// <remarks>
/// <para>
/// MetroHash128 is the 128-bit variant of the MetroHash family.
/// It provides higher collision resistance while maintaining excellent speed.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 128-bit hash value</item>
/// <item><b>Block Size:</b> 32 bytes</item>
/// <item><b>Speed:</b> ~12+ GB/s on modern CPUs</item>
/// <item><b>Quality:</b> Excellent avalanche and distribution properties</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// MetroHash128 uses the same 4-lane parallel structure as MetroHash64, but with
/// different constants and a more complex finalization that preserves all 128 bits
/// of internal state. The four lanes (v0-v3) are initialized differently using
/// arithmetic operations with seed and constants, providing better initial dispersion.
/// </para>
/// <para>
/// <b>Security Warning:</b>
/// MetroHash is NOT cryptographically secure. Do not use it for:
/// <list type="bullet">
/// <item>Password hashing</item>
/// <item>Digital signatures</item>
/// <item>Message authentication codes (MACs)</item>
/// <item>Any security-sensitive application</item>
/// </list>
/// </para>
/// <para>
/// <b>Recommended Use Cases:</b>
/// <list type="bullet">
/// <item>Hash tables requiring low collision probability</item>
/// <item>Bloom filters with many hash functions</item>
/// <item>Content-addressable storage</item>
/// <item>Large-scale deduplication</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="http://www.jandrewrogers.com/2015/05/27/metrohash/">MetroHash Blog Post</see></item>
/// <item><see href="https://github.com/jandrewrogers/MetroHash">MetroHash GitHub</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// using var hasher = new MetroHash128();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// UInt128 hash = hasher.Finalize();
///
/// // Or use the static method
/// UInt128 hash = MetroHash128.Hash(data);
/// </code>
/// </example>
public sealed class MetroHash128 : StreamingHashBase<UInt128> {
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
	// MetroHash128 Constants
	// ═══════════════════════════════════════════════════════════════════════════
	// Different constants from MetroHash64 for the 128-bit variant.
	// These provide independent hash functions when used together.

	/// <summary>
	/// Mixing constant K0 for the 128-bit variant.
	/// </summary>
	/// <remarks>
	/// Value: 0xc83a91e1 (3359436257 decimal)
	/// Used for v0 initialization and block processing.
	/// </remarks>
	private const ulong K0 = 0xc83a91e1UL;

	/// <summary>
	/// Mixing constant K1 for the 128-bit variant.
	/// </summary>
	/// <remarks>
	/// Value: 0x8648dbdb (2252905435 decimal)
	/// Used for v1 initialization and block processing.
	/// </remarks>
	private const ulong K1 = 0x8648dbdbUL;

	/// <summary>
	/// Mixing constant K2 for the 128-bit variant.
	/// </summary>
	/// <remarks>
	/// Value: 0x7bdec03b (2078867515 decimal)
	/// Used extensively in remainder processing.
	/// </remarks>
	private const ulong K2 = 0x7bdec03bUL;

	/// <summary>
	/// Mixing constant K3 for the 128-bit variant.
	/// </summary>
	/// <remarks>
	/// Value: 0x2f5870a5 (794984613 decimal)
	/// Used for v3 initialization and block processing.
	/// </remarks>
	private const ulong K3 = 0x2f5870a5UL;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>The seed value used for initialization.</summary>
	private readonly ulong _seed;

	/// <summary>First state lane. Initialized with (seed - K0) * K3.</summary>
	private ulong _v0;

	/// <summary>Second state lane. Initialized with (seed + K1) * K2.</summary>
	private ulong _v1;

	/// <summary>Third state lane. Initialized with (seed + K0) * K2.</summary>
	private ulong _v2;

	/// <summary>Fourth state lane. Initialized with (seed - K1) * K3.</summary>
	private ulong _v3;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>MetroHash128 processes 32 bytes (256 bits) per block.</remarks>
	public override int BlockSize => 32;

	/// <inheritdoc/>
	/// <remarks>MetroHash128 produces a 16-byte (128-bit) hash value.</remarks>
	public override int DigestSize => 16;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new MetroHash128 hasher with seed 0.
	/// </summary>
	public MetroHash128() : this(0) { }

	/// <summary>
	/// Creates a new MetroHash128 hasher with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value.</param>
	/// <remarks>
	/// The seed is combined with constants using different arithmetic operations
	/// (+, -) to create four distinct initial lane values.
	/// </remarks>
	public MetroHash128(ulong seed) {
		_seed = seed;
		Initialize();
	}

	/// <summary>
	/// Initializes the four state lanes with seed-derived values.
	/// </summary>
	/// <remarks>
	/// Unlike MetroHash64 which uses the same initial value for all lanes,
	/// MetroHash128 uses different combinations of seed ± constants multiplied
	/// by different constants, providing better initial dispersion.
	/// </remarks>
	private void Initialize() {
		// Each lane gets a unique combination of seed and constants
		// This ensures even with seed=0, all lanes start differently
		_v0 = (_seed - K0) * K3;  // Subtract K0, multiply by K3
		_v1 = (_seed + K1) * K2;  // Add K1, multiply by K2
		_v2 = (_seed + K0) * K2;  // Add K0, multiply by K2
		_v3 = (_seed - K1) * K3;  // Subtract K1, multiply by K3
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Core Algorithm Implementation
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Processes a 32-byte block through the MetroHash128 mixing function.
	/// The block processing is identical to MetroHash64, but the different
	/// constants and initialization create a distinct hash function.
	/// </para>
	/// </remarks>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		// Read 32-byte block as four 64-bit values
		ulong b0 = BinaryPrimitives.ReadUInt64LittleEndian(block);
		ulong b1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);
		ulong b2 = BinaryPrimitives.ReadUInt64LittleEndian(block[16..]);
		ulong b3 = BinaryPrimitives.ReadUInt64LittleEndian(block[24..]);

		// Update each lane: multiply by K, rotate right 29, add cross-lane
		_v0 += b0 * K0;
		_v0 = BitOperations.RotateRight(_v0, 29) + _v2;
		_v1 += b1 * K1;
		_v1 = BitOperations.RotateRight(_v1, 29) + _v3;
		_v2 += b2 * K2;
		_v2 = BitOperations.RotateRight(_v2, 29) + _v0;
		_v3 += b3 * K3;
		_v3 = BitOperations.RotateRight(_v3, 29) + _v1;
	}

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Finalization for MetroHash128 is more complex than MetroHash64 to preserve
	/// all 128 bits. The remainder is processed in 16, 8, 4, 2, and 1 byte chunks,
	/// alternating updates between v0 and v1. The final hash uses both v0 and v1.
	/// </para>
	/// </remarks>
	protected override UInt128 ComputeFinal(ReadOnlySpan<byte> remaining) {
		// ═══════════════════════════════════════════════════════════════════════
		// Combine State Lanes (for inputs ≥32 bytes)
		// ═══════════════════════════════════════════════════════════════════════
		if (TotalBytesProcessed >= 32) {
			// Different rotation (21) compared to MetroHash64 (37)
			_v2 ^= BitOperations.RotateRight(((_v0 + _v3) * K0) + _v1, 21) * K1;
			_v3 ^= BitOperations.RotateRight(((_v1 + _v2) * K1) + _v0, 21) * K0;
			_v0 ^= BitOperations.RotateRight(((_v0 + _v2) * K0) + _v3, 21) * K1;
			_v1 ^= BitOperations.RotateRight(((_v1 + _v3) * K1) + _v2, 21) * K0;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Remaining 16-byte Chunk
		// ═══════════════════════════════════════════════════════════════════════
		int pos = 0;
		if (remaining.Length - pos >= 16) {
			ulong val0 = BinaryPrimitives.ReadUInt64LittleEndian(remaining[pos..]);
			ulong val1 = BinaryPrimitives.ReadUInt64LittleEndian(remaining[(pos + 8)..]);
			// Update v0 and v1 with the 16-byte chunk
			_v0 += val0 * K2;
			_v0 = BitOperations.RotateRight(_v0, 33) * K3;
			_v1 += val1 * K2;
			_v1 = BitOperations.RotateRight(_v1, 33) * K3;
			// Cross-mixing between v0 and v1
			_v0 ^= BitOperations.RotateRight((_v0 * K2) + _v1, 45) * K1;
			_v1 ^= BitOperations.RotateRight((_v1 * K3) + _v0, 45) * K0;
			pos += 16;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Remaining 8-byte Chunk
		// ═══════════════════════════════════════════════════════════════════════
		if (remaining.Length - pos >= 8) {
			ulong val = BinaryPrimitives.ReadUInt64LittleEndian(remaining[pos..]);
			_v0 += val * K2;
			_v0 = BitOperations.RotateRight(_v0, 33) * K3;
			_v0 ^= BitOperations.RotateRight((_v0 * K2) + _v1, 27) * K1;
			pos += 8;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Remaining 4-byte Chunk
		// ═══════════════════════════════════════════════════════════════════════
		if (remaining.Length - pos >= 4) {
			uint val = BinaryPrimitives.ReadUInt32LittleEndian(remaining[pos..]);
			// Note: 4-byte chunk goes to v1 (alternating)
			_v1 += val * K2;
			_v1 = BitOperations.RotateRight(_v1, 33) * K3;
			_v1 ^= BitOperations.RotateRight((_v1 * K3) + _v0, 46) * K0;
			pos += 4;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Remaining 2-byte Chunk
		// ═══════════════════════════════════════════════════════════════════════
		if (remaining.Length - pos >= 2) {
			ushort val = BinaryPrimitives.ReadUInt16LittleEndian(remaining[pos..]);
			// Note: 2-byte chunk goes to v0 (alternating)
			_v0 += val * K2;
			_v0 = BitOperations.RotateRight(_v0, 33) * K3;
			_v0 ^= BitOperations.RotateRight((_v0 * K2) + _v1, 22) * K1;
			pos += 2;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Final Byte
		// ═══════════════════════════════════════════════════════════════════════
		if (remaining.Length - pos >= 1) {
			// Note: final byte goes to v1 (alternating)
			_v1 += remaining[pos] * K2;
			_v1 = BitOperations.RotateRight(_v1, 33) * K3;
			_v1 ^= BitOperations.RotateRight((_v1 * K3) + _v0, 58) * K0;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Final Avalanche Mixing
		// ═══════════════════════════════════════════════════════════════════════
		// Four rounds of cross-mixing between v0 and v1
		// This ensures all input bits affect all 128 output bits
		_v0 += BitOperations.RotateRight((_v0 * K0) + _v1, 13);
		_v1 += BitOperations.RotateRight((_v1 * K1) + _v0, 37);
		_v0 += BitOperations.RotateRight((_v0 * K2) + _v1, 13);
		_v1 += BitOperations.RotateRight((_v1 * K3) + _v0, 37);

		// Return v1 as high 64 bits, v0 as low 64 bits
		return new UInt128(_v1, _v0);
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		Initialize();
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Convenience Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes MetroHash128 of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">Optional seed value.</param>
	/// <returns>The 128-bit hash value.</returns>
	/// <remarks>
	/// This is a convenience method for hashing data that fits in memory.
	/// For streaming scenarios, create an instance and use Update/Finalize.
	/// </remarks>
	public static UInt128 Hash(ReadOnlySpan<byte> data, ulong seed = 0) {
		using var hasher = new MetroHash128(seed);
		hasher.Update(data);
		return hasher.Finalize();
	}

	/// <summary>
	/// Computes MetroHash128 and returns the result as a byte array.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">Optional seed value.</param>
	/// <returns>The 128-bit hash as a 16-byte array.</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, ulong seed = 0) {
		var hash = Hash(data, seed);
		byte[] result = new byte[16];
		BinaryPrimitives.WriteUInt64LittleEndian(result, (ulong)(hash & ulong.MaxValue));
		BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(8), (ulong)(hash >> 64));
		return result;
	}
}
