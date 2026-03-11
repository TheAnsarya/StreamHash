using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of SipHash-2-4, a cryptographically secure PRF.
/// </summary>
/// <remarks>
/// <para>
/// SipHash is a family of pseudorandom functions (PRFs) optimized for short inputs.
/// SipHash-2-4 uses 2 compression rounds and 4 finalization rounds.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 64-bit hash value</item>
/// <item><b>Block Size:</b> 8 bytes</item>
/// <item><b>Key Size:</b> 128 bits (16 bytes)</item>
/// <item><b>Security:</b> Cryptographically secure PRF (keyed hash)</item>
/// <item><b>Speed:</b> ~2-4 GB/s on modern CPUs</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm Overview:</b>
/// SipHash uses an ARX (Add-Rotate-XOR) structure with four 64-bit state variables
/// (v0-v3). The state is initialized by XORing the 128-bit key with magic constants
/// derived from "somepseudorandomlygeneratedbytes". Each 8-byte message block is
/// XORed into v3, followed by compression rounds, then XORed into v0. Finalization
/// applies additional rounds before XORing all state variables for the output.
/// </para>
/// <para>
/// <b>Security Properties:</b>
/// <list type="bullet">
/// <item>PRF security: Output is indistinguishable from random given unknown key</item>
/// <item>Resistant to hash-flooding attacks on hash tables</item>
/// <item>NOT suitable for password hashing (use Argon2, bcrypt, etc.)</item>
/// <item>NOT collision-resistant without knowing the key</item>
/// </list>
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Hash table protection against algorithmic complexity attacks</item>
/// <item>Message authentication codes (MAC)</item>
/// <item>Network packet authentication</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://131002.net/siphash/">SipHash Official Website</see></item>
/// <item><see href="https://www.aumasson.jp/siphash/siphash.pdf">SipHash Paper (Aumasson &amp; Bernstein)</see></item>
/// <item><see href="https://github.com/veorq/SipHash">Reference Implementation</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Create a 128-bit key
/// ReadOnlySpan&lt;byte&gt; key = stackalloc byte[16] {
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
/// };
///
/// using var hasher = new SipHash24(key);
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// ulong hash = hasher.Finalize();
/// </code>
/// </example>
public sealed class SipHash24 : StreamingHashBase<ulong> {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════
	// SipHash's ARX structure doesn't benefit much from SIMD for single hashes,
	// but batch processing could use SIMD for parallel independent hashes.

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsAvx2Supported { get; } = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// </summary>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// Key and State Variables
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// First 64 bits of the 128-bit key.
	/// XORed into v0 and v2 during initialization.
	/// </summary>
	private readonly ulong _k0;

	/// <summary>
	/// Second 64 bits of the 128-bit key.
	/// XORed into v1 and v3 during initialization.
	/// </summary>
	private readonly ulong _k1;

	/// <summary>
	/// State variable v0. Initialized with k0 ^ "somepseu" (0x736f6d6570736575).
	/// Participates in odd-numbered ARX operations.
	/// </summary>
	private ulong _v0;

	/// <summary>
	/// State variable v1. Initialized with k1 ^ "dorandom" (0x646f72616e646f6d).
	/// Paired with v0 in the first half of SipRound.
	/// </summary>
	private ulong _v1;

	/// <summary>
	/// State variable v2. Initialized with k0 ^ "lygenera" (0x6c7967656e657261).
	/// Paired with v3 in the first half of SipRound.
	/// </summary>
	private ulong _v2;

	/// <summary>
	/// State variable v3. Initialized with k1 ^ "tedbytes" (0x7465646279746573).
	/// Message blocks are XORed here before compression rounds.
	/// </summary>
	private ulong _v3;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>SipHash-2-4 processes 8 bytes (64 bits) per block.</remarks>
	public override int BlockSize => 8;

	/// <inheritdoc/>
	/// <remarks>SipHash-2-4 produces an 8-byte (64-bit) hash value.</remarks>
	public override int DigestSize => 8;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new SipHash-2-4 hasher with a zero key.
	/// </summary>
	/// <remarks>
	/// Using a zero key provides no security benefits. Always use a random key
	/// in security-sensitive applications.
	/// </remarks>
	public SipHash24() : this(0, 0) { }

	/// <summary>
	/// Creates a new SipHash-2-4 hasher with the specified 128-bit key.
	/// </summary>
	/// <param name="key">A 16-byte key. Must be exactly 16 bytes.</param>
	/// <exception cref="ArgumentException">Key is not exactly 16 bytes.</exception>
	/// <remarks>
	/// The key is split into two 64-bit halves (k0, k1) and XORed with
	/// magic constants during state initialization.
	/// </remarks>
	public SipHash24(ReadOnlySpan<byte> key) {
		if (key.Length != 16) {
			throw new ArgumentException("SipHash key must be exactly 16 bytes.", nameof(key));
		}

		// Split 128-bit key into two 64-bit halves
		_k0 = BinaryPrimitives.ReadUInt64LittleEndian(key);
		_k1 = BinaryPrimitives.ReadUInt64LittleEndian(key[8..]);
		Initialize();
	}

	/// <summary>
	/// Creates a new SipHash-2-4 hasher with the specified key halves.
	/// </summary>
	/// <param name="k0">First 64 bits of the key.</param>
	/// <param name="k1">Second 64 bits of the key.</param>
	/// <remarks>
	/// This constructor is useful when the key is already split into 64-bit values.
	/// </remarks>
	public SipHash24(ulong k0, ulong k1) {
		_k0 = k0;
		_k1 = k1;
		Initialize();
	}

	/// <summary>
	/// Initializes the four state variables by XORing key halves with magic constants.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The magic constants are the ASCII encoding of "somepseudorandomlygeneratedbytes":
	/// <list type="bullet">
	/// <item>0x736f6d6570736575 = "somepseu"</item>
	/// <item>0x646f72616e646f6d = "dorandom"</item>
	/// <item>0x6c7967656e657261 = "lygenera"</item>
	/// <item>0x7465646279746573 = "tedbytes"</item>
	/// </list>
	/// </para>
	/// <para>
	/// v0 and v2 use k0, while v1 and v3 use k1, providing key diffusion.
	/// </para>
	/// </remarks>
	private void Initialize() {
		// XOR key halves with magic constants (ASCII of "somepseudorandomlygeneratedbytes")
		_v0 = _k0 ^ 0x736f6d6570736575;  // k0 XOR "somepseu"
		_v1 = _k1 ^ 0x646f72616e646f6d;  // k1 XOR "dorandom"
		_v2 = _k0 ^ 0x6c7967656e657261;  // k0 XOR "lygenera"
		_v3 = _k1 ^ 0x7465646279746573;  // k1 XOR "tedbytes"
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Core Algorithm Implementation
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Processes an 8-byte block through the SipHash-2-4 compression function.
	/// Uses local variables to keep state in registers during SipRound operations.
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		ulong m = BinaryPrimitives.ReadUInt64LittleEndian(block);

		// Load state into locals to keep in registers
		ulong v0 = _v0, v1 = _v1, v2 = _v2, v3 = _v3;

		v3 ^= m;

		// SipRound 1 (inlined)
		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		// SipRound 2 (inlined)
		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 ^= m;

		// Write state back
		_v0 = v0; _v1 = v1; _v2 = v2; _v3 = v3;
	}

	/// <inheritdoc/>
	/// <remarks>
	/// <para>
	/// Handles remaining bytes (0-7) and applies the finalization rounds.
	/// </para>
	/// <para>
	/// <b>Final Block Construction:</b>
	/// The total message length (mod 256) is placed in the high byte,
	/// and remaining bytes fill the low bytes. This ensures different-length
	/// messages produce different final blocks.
	/// </para>
	/// <para>
	/// <b>Finalization:</b>
	/// After processing the final block with 2 compression rounds,
	/// v2 is XORed with 0xff and 4 finalization rounds are applied
	/// (the "4" in SipHash-2-4). The output is v0 XOR v1 XOR v2 XOR v3.
	/// </para>
	/// </remarks>
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		// Construct final block: high byte = (length mod 256), low bytes = remaining data
		ulong b = (ulong)TotalBytesProcessed << 56;

		switch (remaining.Length) {
			case 7: b |= (ulong)remaining[6] << 48; goto case 6;
			case 6: b |= (ulong)remaining[5] << 40; goto case 5;
			case 5: b |= (ulong)remaining[4] << 32; goto case 4;
			case 4: b |= (ulong)remaining[3] << 24; goto case 3;
			case 3: b |= (ulong)remaining[2] << 16; goto case 2;
			case 2: b |= (ulong)remaining[1] << 8; goto case 1;
			case 1: b |= remaining[0]; break;
		}

		// Load state into locals for all remaining SipRounds
		ulong v0 = _v0, v1 = _v1, v2 = _v2, v3 = _v3;

		// Process final block (2 compression rounds)
		v3 ^= b;

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 ^= b;

		// Finalization: XOR 0xff into v2, apply 4 finalization rounds
		v2 ^= 0xff;

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		return v0 ^ v1 ^ v2 ^ v3;
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		Initialize();
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Convenience Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes SipHash-2-4 of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="key">A 16-byte key.</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <remarks>
	/// This is a convenience method for hashing data that fits in memory.
	/// For streaming scenarios, create an instance and use Update/Finalize.
	/// </remarks>
	public static ulong Hash(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key) {
		if (key.Length != 16)
			throw new ArgumentException("SipHash key must be exactly 16 bytes.", nameof(key));
		return ComputeHashStatic(data,
			BinaryPrimitives.ReadUInt64LittleEndian(key),
			BinaryPrimitives.ReadUInt64LittleEndian(key[8..]));
	}

	/// <summary>
	/// Computes SipHash-2-4 of the given data with key components.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="k0">First 64 bits of the key.</param>
	/// <param name="k1">Second 64 bits of the key.</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <remarks>
	/// This is a convenience method when the key is already split into 64-bit values.
	/// </remarks>
	public static ulong Hash(ReadOnlySpan<byte> data, ulong k0, ulong k1) =>
		ComputeHashStatic(data, k0, k1);

	/// <summary>
	/// High-performance static one-shot SipHash-2-4 computation.
	/// All state stays in local variables (registers) for the entire computation,
	/// avoiding per-block virtual dispatch and field load/store overhead.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="k0">First 64 bits of the key.</param>
	/// <param name="k1">Second 64 bits of the key.</param>
	/// <returns>The 64-bit hash value.</returns>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static ulong ComputeHashStatic(ReadOnlySpan<byte> data, ulong k0 = 0, ulong k1 = 0) {
		int length = data.Length;

		// Initialize state — all locals, no fields
		ulong v0 = k0 ^ 0x736f6d6570736575;
		ulong v1 = k1 ^ 0x646f72616e646f6d;
		ulong v2 = k0 ^ 0x6c7967656e657261;
		ulong v3 = k1 ^ 0x7465646279746573;

		// Process 8-byte blocks in a flat loop — no virtual dispatch, no field traffic
		int offset = 0;
		int end = length - 7;
		while (offset < end) {
			ulong m = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8));
			offset += 8;

			v3 ^= m;

			// SipRound 1
			v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
			v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
			v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
			v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

			// SipRound 2
			v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
			v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
			v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
			v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

			v0 ^= m;
		}

		// Construct final block: high byte = (length mod 256), remaining bytes fill low bytes
		ulong b = (ulong)length << 56;
		ReadOnlySpan<byte> remaining = data[offset..];
		switch (remaining.Length) {
			case 7: b |= (ulong)remaining[6] << 48; goto case 6;
			case 6: b |= (ulong)remaining[5] << 40; goto case 5;
			case 5: b |= (ulong)remaining[4] << 32; goto case 4;
			case 4: b |= (ulong)remaining[3] << 24; goto case 3;
			case 3: b |= (ulong)remaining[2] << 16; goto case 2;
			case 2: b |= (ulong)remaining[1] << 8; goto case 1;
			case 1: b |= remaining[0]; break;
		}

		// Process final block (2 compression rounds)
		v3 ^= b;

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 ^= b;

		// Finalization: XOR 0xff into v2, apply 4 finalization rounds
		v2 ^= 0xff;

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
		v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
		v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
		v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);

		return v0 ^ v1 ^ v2 ^ v3;
	}
}
