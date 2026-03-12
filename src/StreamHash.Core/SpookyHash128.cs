using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of SpookyHash V2 128-bit hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// SpookyHash is a non-cryptographic hash function created by Bob Jenkins.
/// Version 2 fixes a weakness in Version 1 and is the recommended version.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 128-bit hash value (or 64-bit truncated)</item>
/// <item><b>Block Size:</b> 96 bytes (optimal), processes 8 bytes at a time</item>
/// <item><b>Speed:</b> ~8-10 GB/s on modern 64-bit CPUs</item>
/// <item><b>Collision Resistance:</b> Excellent for hash tables, NOT cryptographically secure</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// SpookyHash uses 12 parallel 64-bit state variables (s0-s11) that are updated
/// using a carefully designed mixing function. The large state provides excellent
/// avalanche properties. For short messages (&lt;192 bytes), a simpler 4-variable
/// mixing function is used for better performance.
/// </para>
/// <para>
/// <b>Design Goals:</b>
/// <list type="bullet">
/// <item>Fast for long keys (messages)</item>
/// <item>Produce well-distributed hash values</item>
/// <item>Every bit of the input affects every bit of the output</item>
/// </list>
/// </para>
/// <para>
/// <b>Short vs Long Input:</b>
/// SpookyHash uses different code paths for short (&lt;192 bytes) and long inputs
/// to optimize performance. This streaming implementation handles both cases.
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="http://burtleburtle.net/bob/hash/spooky.html">SpookyHash Official Page</see></item>
/// <item><see href="https://github.com/centaurean/spookyhash">SpookyHash GitHub</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class SpookyHash128 : StreamingHashBase<UInt128> {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════
	// SpookyHash's 12-lane parallel structure could benefit from SIMD,
	// but the complex mixing pattern makes vectorization challenging.

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// SpookyHash Constants
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Magic constant: the golden ratio as a 64-bit repeated pattern.
	/// </summary>
	/// <remarks>
	/// Value: 0xdeadbeefdeadbeef (16045690984503098095 decimal)
	/// Used to initialize state variables s2, s5, s8, s11 that aren't seeded.
	/// This provides a non-zero starting state even with zero seeds.
	/// </remarks>
	private const ulong SC = 0xdeadbeefdeadbeef;

	/// <summary>
	/// Number of 64-bit words in the internal state.
	/// </summary>
	/// <remarks>
	/// SpookyHash uses 12 state variables for maximum parallelism and avalanche.
	/// </remarks>
	private const int NumVars = 12;

	/// <summary>
	/// Block size in bytes (96 = NumVars * 8).
	/// </summary>
	/// <remarks>
	/// Each block provides one 64-bit word per state variable.
	/// </remarks>
	private const int BlockSizeBytes = NumVars * 8;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>First 64-bit seed value.</summary>
	private readonly ulong _seed1;

	/// <summary>Second 64-bit seed value.</summary>
	private readonly ulong _seed2;

	// 12 x 64-bit state variables
	// These form a ring structure where each variable affects its neighbors

	/// <summary>State variable 0. Initialized with seed1.</summary>
	private ulong _s0;
	/// <summary>State variable 1. Initialized with seed2.</summary>
	private ulong _s1;
	/// <summary>State variable 2. Initialized with magic constant SC.</summary>
	private ulong _s2;
	/// <summary>State variable 3. Initialized with seed1.</summary>
	private ulong _s3;
	/// <summary>State variable 4. Initialized with seed2.</summary>
	private ulong _s4;
	/// <summary>State variable 5. Initialized with magic constant SC.</summary>
	private ulong _s5;
	/// <summary>State variable 6. Initialized with seed1.</summary>
	private ulong _s6;
	/// <summary>State variable 7. Initialized with seed2.</summary>
	private ulong _s7;
	/// <summary>State variable 8. Initialized with magic constant SC.</summary>
	private ulong _s8;
	/// <summary>State variable 9. Initialized with seed1.</summary>
	private ulong _s9;
	/// <summary>State variable 10. Initialized with seed2.</summary>
	private ulong _s10;
	/// <summary>State variable 11. Initialized with magic constant SC.</summary>
	private ulong _s11;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>SpookyHash processes 96 bytes (768 bits) per block.</remarks>
	public override int BlockSize => BlockSizeBytes;

	/// <inheritdoc/>
	/// <remarks>SpookyHash produces a 16-byte (128-bit) hash value.</remarks>
	public override int DigestSize => 16;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new SpookyHash V2 hasher with zero seeds.
	/// </summary>
	public SpookyHash128() : this(0, 0) { }

	/// <summary>
	/// Creates a new SpookyHash V2 hasher with the specified seeds.
	/// </summary>
	/// <param name="seed1">First 64-bit seed.</param>
	/// <param name="seed2">Second 64-bit seed.</param>
	/// <remarks>
	/// The seeds are distributed across the 12 state variables in an alternating
	/// pattern: s0,s3,s6,s9 use seed1; s1,s4,s7,s10 use seed2; s2,s5,s8,s11 use SC.
	/// </remarks>
	public SpookyHash128(ulong seed1, ulong seed2) {
		_seed1 = seed1;
		_seed2 = seed2;
		InitializeState();
	}

	/// <summary>
	/// Initializes the 12 state variables with seeds and magic constant.
	/// </summary>
	private void InitializeState() {
		// Alternating pattern: seed1, seed2, SC (repeated 4 times)
		_s0 = _seed1;
		_s1 = _seed2;
		_s2 = SC;
		_s3 = _seed1;
		_s4 = _seed2;
		_s5 = SC;
		_s6 = _seed1;
		_s7 = _seed2;
		_s8 = SC;
		_s9 = _seed1;
		_s10 = _seed2;
		_s11 = SC;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Core Algorithm Implementation
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Processes a 96-byte block through the SpookyHash mixing function.
	/// </para>
	/// <para>
	/// <b>Algorithm Steps:</b>
	/// <list type="number">
	/// <item>Read 12 x 64-bit words from the block (d0-d11)</item>
	/// <item>Apply the Mix function which updates all 12 state variables</item>
	/// </list>
	/// </para>
	/// <para>
	/// The Mix function uses add-rotate-XOR operations in a ring pattern
	/// where each state variable is influenced by its neighbors.
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		// Read 12 x 64-bit words from the 96-byte block
		ulong d0 = BinaryPrimitives.ReadUInt64LittleEndian(block);
		ulong d1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);
		ulong d2 = BinaryPrimitives.ReadUInt64LittleEndian(block[16..]);
		ulong d3 = BinaryPrimitives.ReadUInt64LittleEndian(block[24..]);
		ulong d4 = BinaryPrimitives.ReadUInt64LittleEndian(block[32..]);
		ulong d5 = BinaryPrimitives.ReadUInt64LittleEndian(block[40..]);
		ulong d6 = BinaryPrimitives.ReadUInt64LittleEndian(block[48..]);
		ulong d7 = BinaryPrimitives.ReadUInt64LittleEndian(block[56..]);
		ulong d8 = BinaryPrimitives.ReadUInt64LittleEndian(block[64..]);
		ulong d9 = BinaryPrimitives.ReadUInt64LittleEndian(block[72..]);
		ulong d10 = BinaryPrimitives.ReadUInt64LittleEndian(block[80..]);
		ulong d11 = BinaryPrimitives.ReadUInt64LittleEndian(block[88..]);

		// Apply the main mixing function
		Mix(ref _s0, ref _s1, ref _s2, ref _s3, ref _s4, ref _s5,
			ref _s6, ref _s7, ref _s8, ref _s9, ref _s10, ref _s11,
			d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11);
	}

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Handles remaining bytes and applies finalization.
	/// </para>
	/// <para>
	/// <b>Short Message Path (&lt;192 bytes):</b>
	/// Uses a simpler 4-variable hash for better short-message performance.
	/// </para>
	/// <para>
	/// <b>Long Message Path (≥192 bytes):</b>
	/// Pads remaining bytes to 96 bytes, adds length marker, processes final block,
	/// then applies 3 rounds of EndPartial mixing.
	/// </para>
	/// </remarks>
	protected override UInt128 ComputeFinal(ReadOnlySpan<byte> remaining) {
		int length = (int)TotalBytesProcessed;

		// For short messages (< 192 bytes), use optimized short hash
		if (length < BlockSizeBytes * 2) {
			return ShortHash(remaining, length);
		}

		// ═══════════════════════════════════════════════════════════════════════
		// Long Message Finalization
		// ═══════════════════════════════════════════════════════════════════════
		// Pad remaining data to 96 bytes and add length marker
		Span<byte> lastBlock = stackalloc byte[BlockSizeBytes];
		lastBlock.Clear();

		if (remaining.Length > 0) {
			remaining.CopyTo(lastBlock);
		}

		// Put remainder length in last byte (for domain separation)
		lastBlock[BlockSizeBytes - 1] = (byte)(remaining.Length);

		// Process the final padded block
		ProcessLastBlock(lastBlock);

		// Apply 3 rounds of end mixing for full avalanche
		EndPartial(ref _s0, ref _s1, ref _s2, ref _s3, ref _s4, ref _s5,
				   ref _s6, ref _s7, ref _s8, ref _s9, ref _s10, ref _s11);
		EndPartial(ref _s0, ref _s1, ref _s2, ref _s3, ref _s4, ref _s5,
				   ref _s6, ref _s7, ref _s8, ref _s9, ref _s10, ref _s11);
		EndPartial(ref _s0, ref _s1, ref _s2, ref _s3, ref _s4, ref _s5,
				   ref _s6, ref _s7, ref _s8, ref _s9, ref _s10, ref _s11);

		// Return s1 as high 64 bits, s0 as low 64 bits
		return new UInt128(_s1, _s0);
	}

	/// <summary>
	/// Processes the final block by adding (not mixing) the data words to state.
	/// </summary>
	/// <param name="block">A 96-byte padded block.</param>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessLastBlock(ReadOnlySpan<byte> block) {
		// Read all 12 words
		ulong d0 = BinaryPrimitives.ReadUInt64LittleEndian(block);
		ulong d1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);
		ulong d2 = BinaryPrimitives.ReadUInt64LittleEndian(block[16..]);
		ulong d3 = BinaryPrimitives.ReadUInt64LittleEndian(block[24..]);
		ulong d4 = BinaryPrimitives.ReadUInt64LittleEndian(block[32..]);
		ulong d5 = BinaryPrimitives.ReadUInt64LittleEndian(block[40..]);
		ulong d6 = BinaryPrimitives.ReadUInt64LittleEndian(block[48..]);
		ulong d7 = BinaryPrimitives.ReadUInt64LittleEndian(block[56..]);
		ulong d8 = BinaryPrimitives.ReadUInt64LittleEndian(block[64..]);
		ulong d9 = BinaryPrimitives.ReadUInt64LittleEndian(block[72..]);
		ulong d10 = BinaryPrimitives.ReadUInt64LittleEndian(block[80..]);
		ulong d11 = BinaryPrimitives.ReadUInt64LittleEndian(block[88..]);

		// Simple addition (not full Mix) for final block
		_s0 += d0; _s1 += d1; _s2 += d2; _s3 += d3;
		_s4 += d4; _s5 += d5; _s6 += d6; _s7 += d7;
		_s8 += d8; _s9 += d9; _s10 += d10; _s11 += d11;
	}

	/// <summary>
	/// Short hash for messages less than 192 bytes.
	/// </summary>
	/// <param name="data">Remaining data to process.</param>
	/// <param name="totalLength">Total message length.</param>
	/// <returns>The 128-bit hash value.</returns>
	/// <remarks>
	/// Uses only 4 state variables (h0-h3) with a simpler mixing function
	/// optimized for short messages. This provides better performance when
	/// the full 12-variable mixing isn't needed.
	/// </remarks>
	private UInt128 ShortHash(ReadOnlySpan<byte> data, int totalLength) {
		// Initialize 4 state variables
		ulong h0 = _seed1;
		ulong h1 = _seed2;
		ulong h2 = SC;
		ulong h3 = SC;

		// Buffer for final 32-byte chunk
		Span<byte> buf = stackalloc byte[32];
		buf.Clear();

		int offset = 0;
		int remaining = data.Length;

		// Process 32-byte chunks
		while (remaining >= 32) {
			ulong d0 = BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]);
			ulong d1 = BinaryPrimitives.ReadUInt64LittleEndian(data[(offset + 8)..]);
			ulong d2 = BinaryPrimitives.ReadUInt64LittleEndian(data[(offset + 16)..]);
			ulong d3 = BinaryPrimitives.ReadUInt64LittleEndian(data[(offset + 24)..]);

			// Add first two words, mix, add last two words
			h2 += d0;
			h3 += d1;
			ShortMix(ref h0, ref h1, ref h2, ref h3);
			h0 += d2;
			h1 += d3;

			offset += 32;
			remaining -= 32;
		}

		// Handle remaining bytes (tail)
		if (remaining > 0) {
			data[offset..].CopyTo(buf);
		}

		// Encode total length in high 8 bits of h3
		// This provides domain separation for different message lengths
		h3 += (ulong)totalLength << 56;

		// Read final padded words
		ulong t0 = BinaryPrimitives.ReadUInt64LittleEndian(buf);
		ulong t1 = BinaryPrimitives.ReadUInt64LittleEndian(buf[8..]);
		ulong t2 = BinaryPrimitives.ReadUInt64LittleEndian(buf[16..]);
		ulong t3 = BinaryPrimitives.ReadUInt64LittleEndian(buf[24..]);

		// Final mixing
		h2 += t0;
		h3 += t1;
		ShortMix(ref h0, ref h1, ref h2, ref h3);
		h0 += t2;
		h1 += t3;

		// Apply finalization mixing
		ShortEnd(ref h0, ref h1, ref h2, ref h3);

		// Return h1 as high 64 bits, h0 as low 64 bits
		return new UInt128(h1, h0);
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		InitializeState();
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Mixing Functions
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// The main mixing function for long messages (12 state variables).
	/// </summary>
	/// <remarks>
	/// <para>
	/// <b>Algorithm:</b>
	/// Each of the 12 state variables is updated using:
	/// <list type="number">
	/// <item>Add input data word</item>
	/// <item>XOR with a non-adjacent state variable (ring pattern)</item>
	/// <item>XOR with adjacent state variable</item>
	/// <item>Rotate left by variable-specific amount</item>
	/// <item>Add to another adjacent variable</item>
	/// </list>
	/// </para>
	/// <para>
	/// <b>Rotation Amounts:</b>
	/// 11, 32, 43, 31, 17, 28, 39, 57, 55, 54, 22, 46
	/// These were chosen through extensive testing to maximize avalanche.
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Mix(
		ref ulong s0, ref ulong s1, ref ulong s2, ref ulong s3,
		ref ulong s4, ref ulong s5, ref ulong s6, ref ulong s7,
		ref ulong s8, ref ulong s9, ref ulong s10, ref ulong s11,
		ulong d0, ulong d1, ulong d2, ulong d3,
		ulong d4, ulong d5, ulong d6, ulong d7,
		ulong d8, ulong d9, ulong d10, ulong d11) {
		// Each line: add data, XOR with non-adjacent (ring), XOR with adjacent, rotate, add
		// The ring pattern wraps: s0↔s10, s1↔s11, s2↔s0, etc.
		s0 += d0; s2 ^= s10; s11 ^= s0; s0 = BitOperations.RotateLeft(s0, 11); s11 += s1;
		s1 += d1; s3 ^= s11; s0 ^= s1; s1 = BitOperations.RotateLeft(s1, 32); s0 += s2;
		s2 += d2; s4 ^= s0; s1 ^= s2; s2 = BitOperations.RotateLeft(s2, 43); s1 += s3;
		s3 += d3; s5 ^= s1; s2 ^= s3; s3 = BitOperations.RotateLeft(s3, 31); s2 += s4;
		s4 += d4; s6 ^= s2; s3 ^= s4; s4 = BitOperations.RotateLeft(s4, 17); s3 += s5;
		s5 += d5; s7 ^= s3; s4 ^= s5; s5 = BitOperations.RotateLeft(s5, 28); s4 += s6;
		s6 += d6; s8 ^= s4; s5 ^= s6; s6 = BitOperations.RotateLeft(s6, 39); s5 += s7;
		s7 += d7; s9 ^= s5; s6 ^= s7; s7 = BitOperations.RotateLeft(s7, 57); s6 += s8;
		s8 += d8; s10 ^= s6; s7 ^= s8; s8 = BitOperations.RotateLeft(s8, 55); s7 += s9;
		s9 += d9; s11 ^= s7; s8 ^= s9; s9 = BitOperations.RotateLeft(s9, 54); s8 += s10;
		s10 += d10; s0 ^= s8; s9 ^= s10; s10 = BitOperations.RotateLeft(s10, 22); s9 += s11;
		s11 += d11; s1 ^= s9; s10 ^= s11; s11 = BitOperations.RotateLeft(s11, 46); s10 += s0;
	}

	/// <summary>
	/// Finalization mixing applied after all input is processed.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Applied 3 times at the end to ensure full avalanche (every input bit
	/// affects every output bit). Uses different rotation amounts than Mix
	/// for additional entropy propagation.
	/// </para>
	/// <para>
	/// <b>Rotation Amounts:</b>
	/// 44, 15, 34, 21, 38, 33, 10, 13, 38, 53, 42, 54
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EndPartial(
		ref ulong s0, ref ulong s1, ref ulong s2, ref ulong s3,
		ref ulong s4, ref ulong s5, ref ulong s6, ref ulong s7,
		ref ulong s8, ref ulong s9, ref ulong s10, ref ulong s11) {
		// Similar ring structure to Mix but without data input
		s11 += s1; s2 ^= s11; s1 = BitOperations.RotateLeft(s1, 44);
		s0 += s2; s3 ^= s0; s2 = BitOperations.RotateLeft(s2, 15);
		s1 += s3; s4 ^= s1; s3 = BitOperations.RotateLeft(s3, 34);
		s2 += s4; s5 ^= s2; s4 = BitOperations.RotateLeft(s4, 21);
		s3 += s5; s6 ^= s3; s5 = BitOperations.RotateLeft(s5, 38);
		s4 += s6; s7 ^= s4; s6 = BitOperations.RotateLeft(s6, 33);
		s5 += s7; s8 ^= s5; s7 = BitOperations.RotateLeft(s7, 10);
		s6 += s8; s9 ^= s6; s8 = BitOperations.RotateLeft(s8, 13);
		s7 += s9; s10 ^= s7; s9 = BitOperations.RotateLeft(s9, 38);
		s8 += s10; s11 ^= s8; s10 = BitOperations.RotateLeft(s10, 53);
		s9 += s11; s0 ^= s9; s11 = BitOperations.RotateLeft(s11, 42);
		s10 += s0; s1 ^= s10; s0 = BitOperations.RotateLeft(s0, 54);
	}

	/// <summary>
	/// Short message mixing function (4 state variables).
	/// </summary>
	/// <remarks>
	/// <para>
	/// Simpler mixing for messages &lt;192 bytes. Uses only 4 variables
	/// with 12 rounds of rotate-add-XOR operations per call.
	/// </para>
	/// <para>
	/// <b>Rotation Amounts (12 rounds):</b>
	/// 50, 52, 30, 41, 54, 48, 38, 37, 62, 34, 5, 36
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ShortMix(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3) {
		// 12 rounds of rotate-add-XOR mixing
		h2 = BitOperations.RotateLeft(h2, 50); h2 += h3; h0 ^= h2;
		h3 = BitOperations.RotateLeft(h3, 52); h3 += h0; h1 ^= h3;
		h0 = BitOperations.RotateLeft(h0, 30); h0 += h1; h2 ^= h0;
		h1 = BitOperations.RotateLeft(h1, 41); h1 += h2; h3 ^= h1;
		h2 = BitOperations.RotateLeft(h2, 54); h2 += h3; h0 ^= h2;
		h3 = BitOperations.RotateLeft(h3, 48); h3 += h0; h1 ^= h3;
		h0 = BitOperations.RotateLeft(h0, 38); h0 += h1; h2 ^= h0;
		h1 = BitOperations.RotateLeft(h1, 37); h1 += h2; h3 ^= h1;
		h2 = BitOperations.RotateLeft(h2, 62); h2 += h3; h0 ^= h2;
		h3 = BitOperations.RotateLeft(h3, 34); h3 += h0; h1 ^= h3;
		h0 = BitOperations.RotateLeft(h0, 5); h0 += h1; h2 ^= h0;
		h1 = BitOperations.RotateLeft(h1, 36); h1 += h2; h3 ^= h1;
	}

	/// <summary>
	/// Short message finalization (4 state variables).
	/// </summary>
	/// <remarks>
	/// <para>
	/// Applied once after all short message data is processed.
	/// Uses XOR-rotate-add pattern for final avalanche.
	/// </para>
	/// <para>
	/// <b>Rotation Amounts (10 rounds):</b>
	/// 15, 52, 26, 51, 28, 9, 47, 54, 32, 25, 63
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ShortEnd(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3) {
		// 11 rounds of XOR-rotate-add finalization
		h3 ^= h2; h2 = BitOperations.RotateLeft(h2, 15); h3 += h2;
		h0 ^= h3; h3 = BitOperations.RotateLeft(h3, 52); h0 += h3;
		h1 ^= h0; h0 = BitOperations.RotateLeft(h0, 26); h1 += h0;
		h2 ^= h1; h1 = BitOperations.RotateLeft(h1, 51); h2 += h1;
		h3 ^= h2; h2 = BitOperations.RotateLeft(h2, 28); h3 += h2;
		h0 ^= h3; h3 = BitOperations.RotateLeft(h3, 9); h0 += h3;
		h1 ^= h0; h0 = BitOperations.RotateLeft(h0, 47); h1 += h0;
		h2 ^= h1; h1 = BitOperations.RotateLeft(h1, 54); h2 += h1;
		h3 ^= h2; h2 = BitOperations.RotateLeft(h2, 32); h3 += h2;
		h0 ^= h3; h3 = BitOperations.RotateLeft(h3, 25); h0 += h3;
		h1 ^= h0; h0 = BitOperations.RotateLeft(h0, 63); h1 += h0;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Hash Method
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes SpookyHash V2 128-bit hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed1">First 64-bit seed (default: 0).</param>
	/// <param name="seed2">Second 64-bit seed (default: 0).</param>
	/// <returns>The 128-bit hash value.</returns>
	/// <example>
	/// <code>
	/// byte[] data = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
	/// UInt128 hash = SpookyHash128.Hash(data);
	/// // With custom seeds:
	/// UInt128 seededHash = SpookyHash128.Hash(data, seed1: 12345, seed2: 67890);
	/// </code>
	/// </example>
	public static UInt128 Hash(ReadOnlySpan<byte> data, ulong seed1 = 0, ulong seed2 = 0) {
		using var hasher = new SpookyHash128(seed1, seed2);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
