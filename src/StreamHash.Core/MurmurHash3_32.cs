using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of MurmurHash3 32-bit hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// MurmurHash3 is a non-cryptographic hash function created by Austin Appleby in 2008.
/// It is designed for fast hashing with excellent distribution properties.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 32-bit hash value</item>
/// <item><b>Block Size:</b> 4 bytes</item>
/// <item><b>Speed:</b> ~3-5 GB/s on modern CPUs</item>
/// <item><b>Collision Resistance:</b> Good for hash tables, NOT cryptographically secure</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// MurmurHash3 uses a two-phase approach:
/// <list type="number">
/// <item><b>Body Processing:</b> Process 4-byte blocks with multiply-rotate-XOR operations</item>
/// <item><b>Finalization:</b> Mix remaining bytes and apply avalanche function (fmix32)</item>
/// </list>
/// The algorithm achieves good distribution through carefully chosen constants and rotation amounts
/// that ensure all input bits affect the output hash value.
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Hash tables and hash maps</item>
/// <item>Bloom filters</item>
/// <item>Data partitioning/sharding</item>
/// <item>Checksums (non-security critical)</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/aappleby/smhasher">SMHasher - Original MurmurHash repository</see></item>
/// <item><see href="https://en.wikipedia.org/wiki/MurmurHash">Wikipedia - MurmurHash</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Basic usage
/// using var hasher = new MurmurHash3_32();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// uint hash = hasher.Finalize();
///
/// // With custom seed
/// using var seededHasher = new MurmurHash3_32(seed: 0xdeadbeef);
/// seededHasher.Update(data);
/// uint seededHash = seededHasher.Finalize();
///
/// // Stream processing
/// using var streamHasher = new MurmurHash3_32();
/// using var file = File.OpenRead("largefile.bin");
/// byte[] buffer = new byte[8192];
/// int read;
/// while ((read = file.Read(buffer)) > 0) {
///     streamHasher.Update(buffer.AsSpan(0, read));
/// }
/// uint fileHash = streamHasher.Finalize();
/// </code>
/// </example>
public sealed class MurmurHash3_32 : StreamingHashBase<uint> {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════
	// Check CPU support at startup for potential SIMD optimizations.
	// While MurmurHash3-32 processes only 4 bytes at a time (too small for SIMD benefit),
	// we include detection for consistency with other hash implementations.

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	/// <remarks>
	/// AVX2 provides 256-bit (32-byte) vector operations. While MurmurHash3-32
	/// processes 4 bytes at a time, batch processing could use SIMD.
	/// </remarks>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	/// <remarks>
	/// SSE4.1 provides 128-bit (16-byte) vector operations.
	/// </remarks>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// MurmurHash3 Constants
	// ═══════════════════════════════════════════════════════════════════════════
	// These constants were carefully chosen by Austin Appleby through extensive
	// testing to maximize avalanche behavior and minimize collisions.

	/// <summary>
	/// MurmurHash3 mixing constant c1 for 32-bit variant.
	/// </summary>
	/// <remarks>
	/// Value: 0xcc9e2d51 (3432918353 decimal)
	/// Used in the first multiplication step of block processing.
	/// This prime-like constant helps spread bit changes throughout the hash.
	/// </remarks>
	private const uint C1 = 0xcc9e2d51;

	/// <summary>
	/// MurmurHash3 mixing constant c2 for 32-bit variant.
	/// </summary>
	/// <remarks>
	/// Value: 0x1b873593 (461845907 decimal)
	/// Used in the second multiplication step of block processing.
	/// Together with C1, these constants ensure good bit mixing.
	/// </remarks>
	private const uint C2 = 0x1b873593;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>The seed value used to initialize the hash state.</summary>
	private readonly uint _seed;

	/// <summary>
	/// The running hash accumulator (h1).
	/// This is the primary state variable that accumulates the hash value.
	/// </summary>
	private uint _h1;

	/// <summary>
	/// Count of 4-byte blocks processed (used for length tracking).
	/// </summary>
	private int _processedBlocks;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>MurmurHash3-32 processes 4 bytes (32 bits) per block.</remarks>
	public override int BlockSize => 4;

	/// <inheritdoc/>
	/// <remarks>MurmurHash3-32 produces a 4-byte (32-bit) hash value.</remarks>
	public override int DigestSize => 4;

	/// <summary>
	/// Gets the seed value used for this hash instance.
	/// </summary>
	/// <remarks>
	/// The seed affects the initial state and thus the final hash value.
	/// Different seeds produce different hashes for the same input.
	/// </remarks>
	public uint Seed => _seed;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new MurmurHash3 32-bit hasher with seed 0.
	/// </summary>
	public MurmurHash3_32() : this(0) { }

	/// <summary>
	/// Creates a new MurmurHash3 32-bit hasher with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for hash computation.</param>
	/// <remarks>
	/// Using different seeds produces different hash values for the same input.
	/// This is useful for creating multiple independent hash functions for techniques
	/// like Bloom filters or double hashing.
	/// </remarks>
	public MurmurHash3_32(uint seed) {
		_seed = seed;
		// Initialize h1 with the seed value - this is the starting state
		_h1 = seed;
		_processedBlocks = 0;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Core Algorithm Implementation
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Processes a single 4-byte block through the MurmurHash3-32 mixing function.
	/// </para>
	/// <para>
	/// <b>Algorithm Steps:</b>
	/// <list type="number">
	/// <item>Read 4 bytes as little-endian uint32 (k1)</item>
	/// <item>Multiply k1 by constant C1</item>
	/// <item>Rotate k1 left by 15 bits</item>
	/// <item>Multiply k1 by constant C2</item>
	/// <item>XOR k1 into hash state h1</item>
	/// <item>Rotate h1 left by 13 bits</item>
	/// <item>Apply h1 = h1 * 5 + 0xe6546b64</item>
	/// </list>
	/// </para>
	/// </remarks>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		uint k1 = BinaryPrimitives.ReadUInt32LittleEndian(block);

		k1 *= C1;
		k1 = BitOperations.RotateLeft(k1, 15);
		k1 *= C2;

		_h1 ^= k1;
		_h1 = BitOperations.RotateLeft(_h1, 13);
		_h1 = _h1 * 5 + 0xe6546b64;

		_processedBlocks++;
	}

	/// <summary>
	/// Processes multiple complete 4-byte blocks in a single call, keeping h1 in a local
	/// register to avoid per-block field load/store overhead.
	/// </summary>
	/// <param name="data">Span containing only complete 4-byte blocks (length is a multiple of 4).</param>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	protected override void ProcessBlocks(ReadOnlySpan<byte> data) {
		uint h1 = _h1;
		int blocks = data.Length / 4;

		for (int i = 0; i < data.Length; i += 4) {
			uint k1 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i, 4));

			k1 *= C1;
			k1 = BitOperations.RotateLeft(k1, 15);
			k1 *= C2;

			h1 ^= k1;
			h1 = BitOperations.RotateLeft(h1, 13);
			h1 = h1 * 5 + 0xe6546b64;
		}

		_h1 = h1;
		_processedBlocks += blocks;
	}

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Handles remaining bytes (0-3) and applies the finalization mix.
	/// </para>
	/// <para>
	/// <b>Tail Processing:</b>
	/// Remaining bytes are accumulated into k1 using fall-through switch,
	/// then mixed with C1/rotate/C2 before XOR into h1.
	/// </para>
	/// <para>
	/// <b>Finalization (fmix32):</b>
	/// After XORing the total length, the avalanche function ensures
	/// all input bits affect all output bits.
	/// </para>
	/// </remarks>
	protected override uint ComputeFinal(ReadOnlySpan<byte> remaining) {
		uint k1 = 0;

		// ═══════════════════════════════════════════════════════════════════════
		// Tail Processing (remaining 1-3 bytes)
		// ═══════════════════════════════════════════════════════════════════════
		// Process remaining bytes using fall-through switch pattern.
		// Bytes are shifted into position: byte[2] at bits 16-23, byte[1] at 8-15, byte[0] at 0-7
		switch (remaining.Length) {
			case 3:
				// Third byte goes to bits 16-23
				k1 ^= (uint)remaining[2] << 16;
				goto case 2;
			case 2:
				// Second byte goes to bits 8-15
				k1 ^= (uint)remaining[1] << 8;
				goto case 1;
			case 1:
				// First byte goes to bits 0-7
				k1 ^= remaining[0];
				// Apply the same mixing as full blocks: C1 * rotate * C2
				k1 *= C1;
				k1 = BitOperations.RotateLeft(k1, 15);
				k1 *= C2;
				// XOR into hash state
				_h1 ^= k1;
				break;
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Finalization Mix (fmix32)
		// ═══════════════════════════════════════════════════════════════════════
		// XOR in the total length to ensure different-length inputs produce different hashes
		_h1 ^= (uint)TotalBytesProcessed;

		// Apply avalanche function to ensure all bits are well-mixed
		_h1 = FMix32(_h1);

		return _h1;
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		// Reset to initial state (seed value)
		_h1 = _seed;
		_processedBlocks = 0;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Helper Functions
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// MurmurHash3 32-bit finalization mix (fmix32) - forces all bits to avalanche.
	/// </summary>
	/// <param name="h">The hash value to finalize.</param>
	/// <returns>The mixed hash value with full avalanche properties.</returns>
	/// <remarks>
	/// <para>
	/// The fmix32 function ensures that every bit of the input affects every bit
	/// of the output. This is critical for good hash distribution.
	/// </para>
	/// <para>
	/// <b>Algorithm:</b>
	/// <list type="number">
	/// <item>h ^= h >> 16 (mix high bits into low bits)</item>
	/// <item>h *= 0x85ebca6b (multiply by magic constant)</item>
	/// <item>h ^= h >> 13 (further mixing)</item>
	/// <item>h *= 0xc2b2ae35 (second magic constant)</item>
	/// <item>h ^= h >> 16 (final mixing)</item>
	/// </list>
	/// </para>
	/// <para>
	/// The constants 0x85ebca6b and 0xc2b2ae35 were chosen through extensive
	/// testing to provide optimal avalanche behavior.
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FMix32(uint h) {
		// Step 1: Mix high 16 bits into low 16 bits
		h ^= h >> 16;
		// Step 2: Multiply by first magic constant
		h *= 0x85ebca6b;
		// Step 3: Mix with 13-bit shift (asymmetric to step 1)
		h ^= h >> 13;
		// Step 4: Multiply by second magic constant
		h *= 0xc2b2ae35;
		// Step 5: Final mix with 16-bit shift
		h ^= h >> 16;
		return h;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Convenience Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes the MurmurHash3 32-bit hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">Optional seed value (default: 0).</param>
	/// <returns>The 32-bit hash value.</returns>
	/// <remarks>
	/// This is a convenience method for hashing data that fits in memory.
	/// For streaming scenarios, create an instance and use Update/Finalize.
	/// </remarks>
	public static uint Hash(ReadOnlySpan<byte> data, uint seed = 0) {
		using var hasher = new MurmurHash3_32(seed);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
