using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of MetroHash64, an extremely fast non-cryptographic hash.
/// </summary>
/// <remarks>
/// <para>
/// MetroHash is a high-speed hash function created by J. Andrew Rogers.
/// It's designed for maximum throughput on modern CPUs while maintaining
/// excellent statistical properties.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 64-bit hash value</item>
/// <item><b>Block Size:</b> 32 bytes</item>
/// <item><b>Speed:</b> ~15+ GB/s on modern CPUs (one of the fastest)</item>
/// <item><b>Quality:</b> Excellent avalanche and distribution properties</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// MetroHash64 uses four 64-bit state variables (v0-v3) that are updated in parallel.
/// Each 32-byte block is split into four 8-byte chunks, each multiplied by a unique
/// constant (K0-K3) and rotated before being added to the state. The parallel structure
/// enables instruction-level parallelism on modern CPUs, achieving exceptional throughput.
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
/// <item>Hash tables and bloom filters</item>
/// <item>File integrity checking (non-security)</item>
/// <item>Data deduplication</item>
/// <item>Checksum calculations</item>
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
/// using var hasher = new MetroHash64();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// ulong hash = hasher.Finalize();
///
/// // Or use the static method
/// ulong hash = MetroHash64.Hash(data);
/// </code>
/// </example>
public sealed class MetroHash64 : StreamingHashBase<ulong> {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════
	// MetroHash's 4-lane parallel structure is well-suited for SIMD optimization.
	// With AVX2, all four state updates could be performed simultaneously.

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	/// <remarks>
	/// AVX2 provides 256-bit vectors, allowing all 4 MetroHash lanes to be
	/// processed in parallel with a single instruction.
	/// </remarks>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	/// <remarks>
	/// SSE4.1 provides 128-bit vectors for 2-lane parallel processing.
	/// </remarks>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// MetroHash Constants
	// ═══════════════════════════════════════════════════════════════════════════
	// These constants were chosen to provide good mixing properties.
	// They are relatively prime to each other and have good bit distribution.

	/// <summary>
	/// Mixing constant K0 used for the first state lane (v0).
	/// </summary>
	/// <remarks>
	/// Value: 0xd6d018f5 (3603119349 decimal, uses only 32 bits)
	/// Multiplied with input blocks before rotation and addition.
	/// </remarks>
	private const ulong K0 = 0xd6d018f5UL;

	/// <summary>
	/// Mixing constant K1 used for the second state lane (v1).
	/// </summary>
	/// <remarks>
	/// Value: 0xa2aa033b (2729738043 decimal, uses only 32 bits)
	/// Different from K0 to prevent symmetry in the hash function.
	/// </remarks>
	private const ulong K1 = 0xa2aa033bUL;

	/// <summary>
	/// Mixing constant K2 used for the third state lane (v2) and initialization.
	/// </summary>
	/// <remarks>
	/// Value: 0x62992fc1 (1654202305 decimal)
	/// Also used in seed initialization: (seed + K2) * K0.
	/// </remarks>
	private const ulong K2 = 0x62992fc1UL;

	/// <summary>
	/// Mixing constant K3 used for the fourth state lane (v3) and finalization.
	/// </summary>
	/// <remarks>
	/// Value: 0x30bc5b29 (817871657 decimal)
	/// Also used in finalization for processing remaining bytes.
	/// </remarks>
	private const ulong K3 = 0x30bc5b29UL;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>The seed value used for initialization.</summary>
	private readonly ulong _seed;

	/// <summary>
	/// First state lane. Processes bytes 0-7 of each block.
	/// Mixed with v2 during state updates for cross-lane diffusion.
	/// </summary>
	private ulong _v0;

	/// <summary>
	/// Second state lane. Processes bytes 8-15 of each block.
	/// Mixed with v3 during state updates for cross-lane diffusion.
	/// </summary>
	private ulong _v1;

	/// <summary>
	/// Third state lane. Processes bytes 16-23 of each block.
	/// Mixed with v0 during state updates for cross-lane diffusion.
	/// </summary>
	private ulong _v2;

	/// <summary>
	/// Fourth state lane. Processes bytes 24-31 of each block.
	/// Mixed with v1 during state updates for cross-lane diffusion.
	/// </summary>
	private ulong _v3;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>MetroHash64 processes 32 bytes (256 bits) per block.</remarks>
	public override int BlockSize => 32;

	/// <inheritdoc/>
	/// <remarks>MetroHash64 produces an 8-byte (64-bit) hash value.</remarks>
	public override int DigestSize => 8;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new MetroHash64 hasher with seed 0.
	/// </summary>
	public MetroHash64() : this(0) { }

	/// <summary>
	/// Creates a new MetroHash64 hasher with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value.</param>
	/// <remarks>
	/// The seed is combined with K2 and K0 during initialization to create
	/// the initial state values for all four lanes.
	/// </remarks>
	public MetroHash64(ulong seed) {
		_seed = seed;
		Initialize();
	}

	/// <summary>
	/// Initializes all four state lanes to the same starting value.
	/// </summary>
	/// <remarks>
	/// All lanes start with (seed + K2) * K0, providing a well-distributed
	/// initial state even with a seed of 0.
	/// </remarks>
	private void Initialize() {
		// Combine seed with constants to create initial state
		// The multiplication by K0 ensures good bit distribution
		ulong seedPlusK = (_seed + K2) * K0;
		_v0 = seedPlusK;
		_v1 = seedPlusK;
		_v2 = seedPlusK;
		_v3 = seedPlusK;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Core Algorithm Implementation
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Processes a 32-byte block through the MetroHash64 mixing function.
	/// </para>
	/// <para>
	/// <b>Algorithm Steps (for each lane i=0..3):</b>
	/// <list type="number">
	/// <item>Read 8 bytes as little-endian uint64 (b[i])</item>
	/// <item>Multiply by constant K[i]: v[i] += b[i] * K[i]</item>
	/// <item>Rotate right by 29 bits</item>
	/// <item>Add cross-lane value: v[i] += v[(i+2) mod 4]</item>
	/// </list>
	/// </para>
	/// <para>
	/// The cross-lane additions (v0 += v2, v1 += v3, etc.) ensure that changes
	/// in any input byte eventually affect all output bits.
	/// </para>
	/// </remarks>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		// ═══════════════════════════════════════════════════════════════════════
		// Read 32-byte block as four 64-bit values
		// ═══════════════════════════════════════════════════════════════════════
		ulong b0 = BinaryPrimitives.ReadUInt64LittleEndian(block);
		ulong b1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);
		ulong b2 = BinaryPrimitives.ReadUInt64LittleEndian(block[16..]);
		ulong b3 = BinaryPrimitives.ReadUInt64LittleEndian(block[24..]);

		// ═══════════════════════════════════════════════════════════════════════
		// Update state lanes with multiply-rotate-add pattern
		// ═══════════════════════════════════════════════════════════════════════
		// Lane 0: multiply by K0, rotate right 29, add v2 for cross-lane mixing
		_v0 += b0 * K0;
		_v0 = BitOperations.RotateRight(_v0, 29) + _v2;

		// Lane 1: multiply by K1, rotate right 29, add v3 for cross-lane mixing
		_v1 += b1 * K1;
		_v1 = BitOperations.RotateRight(_v1, 29) + _v3;

		// Lane 2: multiply by K2, rotate right 29, add v0 for cross-lane mixing
		_v2 += b2 * K2;
		_v2 = BitOperations.RotateRight(_v2, 29) + _v0;

		// Lane 3: multiply by K3, rotate right 29, add v1 for cross-lane mixing
		_v3 += b3 * K3;
		_v3 = BitOperations.RotateRight(_v3, 29) + _v1;
	}

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Combines the four state lanes and processes remaining bytes.
	/// </para>
	/// <para>
	/// <b>Long Input Finalization (≥32 bytes processed):</b>
	/// The four lanes are combined through a series of XOR, rotate, and multiply
	/// operations that ensure all bits of all lanes contribute to the final hash.
	/// </para>
	/// <para>
	/// <b>Short Input Finalization (&lt;32 bytes):</b>
	/// The hash is initialized fresh from seed and remaining bytes are processed directly.
	/// </para>
	/// <para>
	/// <b>Remainder Processing:</b>
	/// Remaining bytes are processed in 8-byte, 4-byte, 2-byte, and 1-byte chunks,
	/// each with its own mixing sequence to ensure good distribution.
	/// </para>
	/// </remarks>
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		ulong hash;

		// ═══════════════════════════════════════════════════════════════════════
		// Combine State Lanes (for inputs ≥32 bytes)
		// ═══════════════════════════════════════════════════════════════════════
		if (TotalBytesProcessed >= 32) {
			// Complex mixing to combine all four lanes
			// Each line combines two pairs of lanes with rotation and multiplication
			_v2 ^= BitOperations.RotateRight(((_v0 + _v3) * K0) + _v1, 37) * K1;
			_v3 ^= BitOperations.RotateRight(((_v1 + _v2) * K1) + _v0, 37) * K0;
			_v0 ^= BitOperations.RotateRight(((_v0 + _v2) * K0) + _v3, 37) * K1;
			_v1 ^= BitOperations.RotateRight(((_v1 + _v3) * K1) + _v2, 37) * K0;
			// Final combination: sum of v0 and v1
			hash = _v0 + _v1;
		} else {
			// Short input: use simple initialization
			hash = (_seed + K2) * K0;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Remaining 8-byte Chunks
		// ═══════════════════════════════════════════════════════════════════════
		int pos = 0;
		while (remaining.Length - pos >= 8) {
			ulong val = BinaryPrimitives.ReadUInt64LittleEndian(remaining[pos..]);
			// Multiply by K3, add to hash, rotate and multiply by K1
			hash += val * K3;
			pos += 8;
			hash ^= BitOperations.RotateRight(hash, 55) * K1;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Remaining 4-byte Chunk
		// ═══════════════════════════════════════════════════════════════════════
		if (remaining.Length - pos >= 4) {
			uint val = BinaryPrimitives.ReadUInt32LittleEndian(remaining[pos..]);
			hash += val * K3;
			pos += 4;
			// Different rotation (26) for 4-byte processing
			hash ^= BitOperations.RotateRight(hash, 26) * K1;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Remaining 2-byte Chunk
		// ═══════════════════════════════════════════════════════════════════════
		if (remaining.Length - pos >= 2) {
			ushort val = BinaryPrimitives.ReadUInt16LittleEndian(remaining[pos..]);
			hash += val * K3;
			pos += 2;
			// Different rotation (48) for 2-byte processing
			hash ^= BitOperations.RotateRight(hash, 48) * K1;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Process Final Byte (if present)
		// ═══════════════════════════════════════════════════════════════════════
		if (remaining.Length - pos >= 1) {
			hash += remaining[pos] * K3;
			// Different rotation (37) for single byte
			hash ^= BitOperations.RotateRight(hash, 37) * K1;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Final Avalanche Mixing
		// ═══════════════════════════════════════════════════════════════════════
		// Ensure all input bits affect all output bits
		hash ^= BitOperations.RotateRight(hash, 28);
		hash *= K0;
		hash ^= BitOperations.RotateRight(hash, 29);

		return hash;
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		Initialize();
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Convenience Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes MetroHash64 of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">Optional seed value.</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <remarks>
	/// This is a convenience method for hashing data that fits in memory.
	/// For streaming scenarios, create an instance and use Update/Finalize.
	/// </remarks>
	public static ulong Hash(ReadOnlySpan<byte> data, ulong seed = 0) {
		using var hasher = new MetroHash64(seed);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
