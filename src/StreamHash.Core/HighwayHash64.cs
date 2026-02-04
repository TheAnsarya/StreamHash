namespace StreamHash.Core;

using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// Streaming implementation of HighwayHash64 algorithm with SIMD optimization.
/// </summary>
/// <remarks>
/// <para>
/// HighwayHash is a fast keyed hash function designed for 64-bit CPUs with SIMD support.
/// It was developed by Google and provides strong avalanche behavior and DoS resistance.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 64-bit hash value</item>
/// <item><b>Block Size:</b> 32 bytes</item>
/// <item><b>Key Size:</b> 256 bits (4 × 64-bit values)</item>
/// <item><b>Speed:</b> ~10+ GB/s with SIMD, ~3+ GB/s scalar</item>
/// <item><b>Security:</b> Keyed, DoS-resistant, NOT cryptographic</item>
/// </list>
/// </para>
/// <para>
/// <b>SIMD Optimization:</b>
/// <list type="bullet">
/// <item>Uses AVX2 (256-bit vectors) when available for 4 lanes in parallel</item>
/// <item>Falls back to SSE4.2 (128-bit vectors) for 2 lanes at a time</item>
/// <item>Pure scalar fallback for maximum portability</item>
/// </list>
/// </para>
/// <para>
/// <b>Design Principles:</b>
/// <list type="bullet">
/// <item>SIMD-first design using AVX2/SSE4.1 intrinsics</item>
/// <item>Scalar fallback for portability</item>
/// <item>Strong avalanche properties</item>
/// <item>Keyed construction for DoS resistance</item>
/// </list>
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Network packet hashing (DoS protection)</item>
/// <item>High-throughput data processing</item>
/// <item>SipHash replacement for better performance</item>
/// <item>Content fingerprinting</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/google/highwayhash">HighwayHash - Google's official repository</see></item>
/// <item><see href="https://arxiv.org/abs/1612.06257">HighwayHash: Fast, Strong, Keyed Hash Function (arxiv)</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Create with default key
/// using var hasher = new HighwayHash64();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// ulong hash = hasher.Finalize();
///
/// // Create with custom 256-bit key (4 ulongs)
/// ulong[] key = { 0x0706050403020100UL, 0x0f0e0d0c0b0a0908UL,
///                 0x1716151413121110UL, 0x1f1e1d1c1b1a1918UL };
/// using var keyedHasher = new HighwayHash64(key);
/// keyedHasher.Update(data);
/// ulong keyedHash = keyedHasher.Finalize();
/// </code>
/// </example>
public sealed class HighwayHash64 : StreamingHashBase<ulong> {
	// ========== SIMD Feature Detection ==========

	/// <summary>
	/// Indicates whether AVX2 SIMD instructions are available on this CPU.
	/// AVX2 allows processing all 4 lanes (256 bits) simultaneously.
	/// </summary>
	private static readonly bool IsAvx2Supported = Avx2.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available on this CPU.
	/// SSE4.1 allows processing 2 lanes (128 bits) at a time.
	/// </summary>
	private static readonly bool IsSse41Supported = Sse41.IsSupported;

	/// <summary>
	/// Default key for convenience (should be replaced with a secret key for security).
	/// These are the first 32 bytes of the fractional part of pi.
	/// </summary>
	private static readonly ulong[] DefaultKey = [
		0x0706050403020100UL,  // Key lane 0: bytes 0-7
		0x0f0e0d0c0b0a0908UL,  // Key lane 1: bytes 8-15
		0x1716151413121110UL,  // Key lane 2: bytes 16-23
		0x1f1e1d1c1b1a1918UL   // Key lane 3: bytes 24-31
	];

	// ========== Internal State ==========
	// HighwayHash maintains 4 parallel "lanes" of state, each 64 bits.
	// This is perfectly suited for SIMD: 4 × 64-bit = 256 bits = one AVX2 register.

	/// <summary>State vector v0 - primary accumulator for mixing.</summary>
	private readonly ulong[] _v0 = new ulong[4];

	/// <summary>State vector v1 - secondary accumulator that receives input.</summary>
	private readonly ulong[] _v1 = new ulong[4];

	/// <summary>Multiplier vector mul0 - evolved through computation for non-linearity.</summary>
	private readonly ulong[] _mul0 = new ulong[4];

	/// <summary>Multiplier vector mul1 - second multiplier for additional mixing.</summary>
	private readonly ulong[] _mul1 = new ulong[4];

	/// <summary>Original key stored for reset capability.</summary>
	private readonly ulong[] _key;

	/// <inheritdoc/>
	public override int BlockSize => 32;  // 4 lanes × 8 bytes = 32 bytes per block

	/// <inheritdoc/>
	public override int DigestSize => 8;  // 64-bit output

	/// <summary>
	/// Creates a new HighwayHash64 hasher with the default key.
	/// </summary>
	/// <remarks>
	/// <b>Warning:</b> Using the default key provides no DoS protection.
	/// For security-sensitive applications, use a secret 256-bit key.
	/// </remarks>
	public HighwayHash64() : this(DefaultKey) { }

	/// <summary>
	/// Creates a new HighwayHash64 hasher with a custom 256-bit key.
	/// </summary>
	/// <param name="key">A 4-element array of ulong values (256 bits total).</param>
	/// <exception cref="ArgumentException">Thrown if key is not exactly 4 elements.</exception>
	public HighwayHash64(ulong[] key) : base() {
		ArgumentNullException.ThrowIfNull(key);
		if (key.Length != 4) {
			throw new ArgumentException("Key must be exactly 4 ulong values (256 bits).", nameof(key));
		}

		_key = new ulong[4];
		key.CopyTo(_key, 0);

		InitializeState();
	}

	/// <summary>
	/// Creates a new HighwayHash64 hasher with a 256-bit key from a span.
	/// </summary>
	/// <param name="key">A span of exactly 32 bytes (256 bits).</param>
	/// <exception cref="ArgumentException">Thrown if key is not exactly 32 bytes.</exception>
	public HighwayHash64(ReadOnlySpan<byte> key) : base() {
		if (key.Length != 32) {
			throw new ArgumentException("Key must be exactly 32 bytes (256 bits).", nameof(key));
		}

		_key = new ulong[4];
		_key[0] = BinaryPrimitives.ReadUInt64LittleEndian(key[0..8]);
		_key[1] = BinaryPrimitives.ReadUInt64LittleEndian(key[8..16]);
		_key[2] = BinaryPrimitives.ReadUInt64LittleEndian(key[16..24]);
		_key[3] = BinaryPrimitives.ReadUInt64LittleEndian(key[24..32]);

		InitializeState();
	}

	/// <summary>
	/// Initializes the internal state from the key.
	/// </summary>
	/// <remarks>
	/// The initialization uses specific constants derived from the fractional
	/// parts of mathematical constants to ensure good initial mixing.
	/// </remarks>
	private void InitializeState() {
		// ========== Initialize Multipliers ==========
		// These constants are derived from the fractional parts of mathematical
		// constants (pi, e, etc.) to provide good initial mixing properties.
		// They have high Hamming weight and no obvious patterns.

		// mul0: First set of mixing constants
		_mul0[0] = 0xdbe6d5d5fe4cce2fUL;  // From fractional part of sqrt(2)
		_mul0[1] = 0xa4093822299f31d0UL;  // From fractional part of sqrt(3)
		_mul0[2] = 0x13198a2e03707344UL;  // From fractional part of sqrt(5)
		_mul0[3] = 0x243f6a8885a308d3UL;  // From fractional part of pi

		// mul1: Second set of mixing constants
		_mul1[0] = 0x3bd39e10cb0ef593UL;  // From fractional part of e
		_mul1[1] = 0xc0acf169b5f18a8cUL;  // From fractional part of sqrt(7)
		_mul1[2] = 0xbe5466cf34e90c6cUL;  // From fractional part of sqrt(11)
		_mul1[3] = 0x452821e638d01377UL;  // From fractional part of sqrt(13)

		// ========== Initialize State Vectors from Key ==========
		// v0 is initialized by XORing mul0 with the key directly.
		// This establishes the initial "left" state dependent on the secret key.
		_v0[0] = _mul0[0] ^ _key[0];
		_v0[1] = _mul0[1] ^ _key[1];
		_v0[2] = _mul0[2] ^ _key[2];
		_v0[3] = _mul0[3] ^ _key[3];

		// v1 is initialized by XORing mul1 with a rotated version of the key.
		// The 32-bit rotation ensures v0 and v1 start with different key-derived values,
		// improving the initial diffusion of key material.
		_v1[0] = _mul1[0] ^ ((_key[0] >> 32) | (_key[0] << 32));  // Rotate key[0] by 32 bits
		_v1[1] = _mul1[1] ^ ((_key[1] >> 32) | (_key[1] << 32));  // Rotate key[1] by 32 bits
		_v1[2] = _mul1[2] ^ ((_key[2] >> 32) | (_key[2] << 32));  // Rotate key[2] by 32 bits
		_v1[3] = _mul1[3] ^ ((_key[3] >> 32) | (_key[3] << 32));  // Rotate key[3] by 32 bits
	}

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		if (IsAvx2Supported) {
			ProcessBlockAvx2(block);
		} else if (IsSse41Supported) {
			ProcessBlockSse41(block);
		} else {
			ProcessBlockScalar(block);
		}
	}

	/// <summary>
	/// Process a block using AVX2 SIMD (256-bit vectors).
	/// All 4 lanes are processed in parallel with a single vector.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private unsafe void ProcessBlockAvx2(ReadOnlySpan<byte> block) {
		// Load packet (4 × 64-bit lanes) from input
		fixed (byte* ptr = block) {
			Vector256<ulong> packet = Avx.LoadVector256((ulong*)ptr);

			// Load state vectors
			fixed (ulong* v0Ptr = _v0, v1Ptr = _v1, mul0Ptr = _mul0, mul1Ptr = _mul1) {
				Vector256<ulong> v0 = Avx.LoadVector256(v0Ptr);
				Vector256<ulong> v1 = Avx.LoadVector256(v1Ptr);
				Vector256<ulong> mul0 = Avx.LoadVector256(mul0Ptr);
				Vector256<ulong> mul1 = Avx.LoadVector256(mul1Ptr);

				// Step 1: v1 += packet
				v1 = Avx2.Add(v1, packet);

				// Step 2: v1 += mul0
				v1 = Avx2.Add(v1, mul0);

				// Step 3: mul0 ^= (v1 & 0xffffffff) * (v0 >> 32)
				Vector256<ulong> v1Low = Avx2.And(v1, Vector256.Create(0xffffffffUL));
				Vector256<ulong> v0High = Avx2.ShiftRightLogical(v0, 32);
				Vector256<ulong> product0 = Avx2.Multiply(v1Low.AsUInt32(), v0High.AsUInt32()).AsUInt64();
				mul0 = Avx2.Xor(mul0, product0);

				// Step 4: v0 += mul1
				v0 = Avx2.Add(v0, mul1);

				// Step 5: mul1 ^= (v0 & 0xffffffff) * (v1 >> 32)
				Vector256<ulong> v0Low = Avx2.And(v0, Vector256.Create(0xffffffffUL));
				Vector256<ulong> v1High = Avx2.ShiftRightLogical(v1, 32);
				Vector256<ulong> product1 = Avx2.Multiply(v0Low.AsUInt32(), v1High.AsUInt32()).AsUInt64();
				mul1 = Avx2.Xor(mul1, product1);

				// Step 6: ZipperMerge - requires extracting individual elements
				// Extract elements for ZipperMerge
				ulong v0_0 = v0.GetElement(0);
				ulong v0_1 = v0.GetElement(1);
				ulong v0_2 = v0.GetElement(2);
				ulong v0_3 = v0.GetElement(3);
				ulong v1_0 = v1.GetElement(0);
				ulong v1_1 = v1.GetElement(1);
				ulong v1_2 = v1.GetElement(2);
				ulong v1_3 = v1.GetElement(3);

				// ZipperMerge for v0
				v0 = Vector256.Create(
					v0_0 + ZipperMerge0(v1_1, v1_0),
					v0_1 + ZipperMerge1(v1_1, v1_0),
					v0_2 + ZipperMerge0(v1_3, v1_2),
					v0_3 + ZipperMerge1(v1_3, v1_2)
				);

				// Extract updated v0 elements
				v0_0 = v0.GetElement(0);
				v0_1 = v0.GetElement(1);
				v0_2 = v0.GetElement(2);
				v0_3 = v0.GetElement(3);

				// ZipperMerge for v1
				v1 = Vector256.Create(
					v1_0 + ZipperMerge0(v0_1, v0_0),
					v1_1 + ZipperMerge1(v0_1, v0_0),
					v1_2 + ZipperMerge0(v0_3, v0_2),
					v1_3 + ZipperMerge1(v0_3, v0_2)
				);

				// Store updated state
				Avx.Store(v0Ptr, v0);
				Avx.Store(v1Ptr, v1);
				Avx.Store(mul0Ptr, mul0);
				Avx.Store(mul1Ptr, mul1);
			}
		}
	}

	/// <summary>
	/// Process a block using SSE4.1 SIMD (128-bit vectors).
	/// Processes 2 lanes at a time.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private unsafe void ProcessBlockSse41(ReadOnlySpan<byte> block) {
		fixed (byte* ptr = block) {
			// Load packet as two 128-bit halves
			Vector128<ulong> packetLo = Sse2.LoadVector128((ulong*)ptr);
			Vector128<ulong> packetHi = Sse2.LoadVector128((ulong*)(ptr + 16));

			fixed (ulong* v0Ptr = _v0, v1Ptr = _v1, mul0Ptr = _mul0, mul1Ptr = _mul1) {
				Vector128<ulong> v0Lo = Sse2.LoadVector128(v0Ptr);
				Vector128<ulong> v0Hi = Sse2.LoadVector128(v0Ptr + 2);
				Vector128<ulong> v1Lo = Sse2.LoadVector128(v1Ptr);
				Vector128<ulong> v1Hi = Sse2.LoadVector128(v1Ptr + 2);
				Vector128<ulong> mul0Lo = Sse2.LoadVector128(mul0Ptr);
				Vector128<ulong> mul0Hi = Sse2.LoadVector128(mul0Ptr + 2);
				Vector128<ulong> mul1Lo = Sse2.LoadVector128(mul1Ptr);
				Vector128<ulong> mul1Hi = Sse2.LoadVector128(mul1Ptr + 2);

				// Step 1: v1 += packet
				v1Lo = Sse2.Add(v1Lo, packetLo);
				v1Hi = Sse2.Add(v1Hi, packetHi);

				// Step 2: v1 += mul0
				v1Lo = Sse2.Add(v1Lo, mul0Lo);
				v1Hi = Sse2.Add(v1Hi, mul0Hi);

				// Step 3: mul0 ^= (v1 & 0xffffffff) * (v0 >> 32)
				Vector128<ulong> mask32 = Vector128.Create(0xffffffffUL);
				Vector128<ulong> v1LowLo = Sse2.And(v1Lo, mask32);
				Vector128<ulong> v1LowHi = Sse2.And(v1Hi, mask32);
				Vector128<ulong> v0HighLo = Sse2.ShiftRightLogical(v0Lo, 32);
				Vector128<ulong> v0HighHi = Sse2.ShiftRightLogical(v0Hi, 32);
				Vector128<ulong> product0Lo = Sse41.Multiply(v1LowLo.AsUInt32(), v0HighLo.AsUInt32()).AsUInt64();
				Vector128<ulong> product0Hi = Sse41.Multiply(v1LowHi.AsUInt32(), v0HighHi.AsUInt32()).AsUInt64();
				mul0Lo = Sse2.Xor(mul0Lo, product0Lo);
				mul0Hi = Sse2.Xor(mul0Hi, product0Hi);

				// Step 4: v0 += mul1
				v0Lo = Sse2.Add(v0Lo, mul1Lo);
				v0Hi = Sse2.Add(v0Hi, mul1Hi);

				// Step 5: mul1 ^= (v0 & 0xffffffff) * (v1 >> 32)
				Vector128<ulong> v0LowLo = Sse2.And(v0Lo, mask32);
				Vector128<ulong> v0LowHi = Sse2.And(v0Hi, mask32);
				Vector128<ulong> v1HighLo = Sse2.ShiftRightLogical(v1Lo, 32);
				Vector128<ulong> v1HighHi = Sse2.ShiftRightLogical(v1Hi, 32);
				Vector128<ulong> product1Lo = Sse41.Multiply(v0LowLo.AsUInt32(), v1HighLo.AsUInt32()).AsUInt64();
				Vector128<ulong> product1Hi = Sse41.Multiply(v0LowHi.AsUInt32(), v1HighHi.AsUInt32()).AsUInt64();
				mul1Lo = Sse2.Xor(mul1Lo, product1Lo);
				mul1Hi = Sse2.Xor(mul1Hi, product1Hi);

				// Step 6: ZipperMerge - extract individual elements
				ulong v0_0 = v0Lo.GetElement(0);
				ulong v0_1 = v0Lo.GetElement(1);
				ulong v0_2 = v0Hi.GetElement(0);
				ulong v0_3 = v0Hi.GetElement(1);
				ulong v1_0 = v1Lo.GetElement(0);
				ulong v1_1 = v1Lo.GetElement(1);
				ulong v1_2 = v1Hi.GetElement(0);
				ulong v1_3 = v1Hi.GetElement(1);

				// ZipperMerge for v0
				v0Lo = Vector128.Create(
					v0_0 + ZipperMerge0(v1_1, v1_0),
					v0_1 + ZipperMerge1(v1_1, v1_0)
				);
				v0Hi = Vector128.Create(
					v0_2 + ZipperMerge0(v1_3, v1_2),
					v0_3 + ZipperMerge1(v1_3, v1_2)
				);

				// Update extracted v0 elements
				v0_0 = v0Lo.GetElement(0);
				v0_1 = v0Lo.GetElement(1);
				v0_2 = v0Hi.GetElement(0);
				v0_3 = v0Hi.GetElement(1);

				// ZipperMerge for v1
				v1Lo = Vector128.Create(
					v1_0 + ZipperMerge0(v0_1, v0_0),
					v1_1 + ZipperMerge1(v0_1, v0_0)
				);
				v1Hi = Vector128.Create(
					v1_2 + ZipperMerge0(v0_3, v0_2),
					v1_3 + ZipperMerge1(v0_3, v0_2)
				);

				// Store updated state
				Sse2.Store(v0Ptr, v0Lo);
				Sse2.Store(v0Ptr + 2, v0Hi);
				Sse2.Store(v1Ptr, v1Lo);
				Sse2.Store(v1Ptr + 2, v1Hi);
				Sse2.Store(mul0Ptr, mul0Lo);
				Sse2.Store(mul0Ptr + 2, mul0Hi);
				Sse2.Store(mul1Ptr, mul1Lo);
				Sse2.Store(mul1Ptr + 2, mul1Hi);
			}
		}
	}

	/// <summary>
	/// Process a block using scalar operations (fallback).
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlockScalar(ReadOnlySpan<byte> block) {
		// Read the 32-byte packet as 4 lanes
		ulong[] packet = [
			BinaryPrimitives.ReadUInt64LittleEndian(block[0..8]),
			BinaryPrimitives.ReadUInt64LittleEndian(block[8..16]),
			BinaryPrimitives.ReadUInt64LittleEndian(block[16..24]),
			BinaryPrimitives.ReadUInt64LittleEndian(block[24..32])
		];

		Update(packet);
	}

	/// <summary>
	/// Processes a packet of 4 lanes (32 bytes) through the HighwayHash mixing function.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This is the core mixing function of HighwayHash. It performs a series of operations
	/// designed to achieve fast, strong mixing with good avalanche properties.
	/// </para>
	/// <para>
	/// <b>Algorithm Steps:</b>
	/// <list type="number">
	/// <item>Add input packet to v1 (absorb input)</item>
	/// <item>Add mul0 to v1 (incorporate multiplier)</item>
	/// <item>Update mul0 using lower×upper multiplication (non-linear mixing)</item>
	/// <item>Add mul1 to v0 (cross-lane influence)</item>
	/// <item>Update mul1 using lower×upper multiplication</item>
	/// <item>Apply ZipperMerge to both v0 and v1 (byte-level diffusion)</item>
	/// </list>
	/// </para>
	/// <para>
	/// The multiplication of lower 32 bits by upper 32 bits provides strong
	/// non-linear mixing that's resistant to differential attacks.
	/// </para>
	/// </remarks>
	/// <param name="packet">Array of 4 ulong values representing the 32-byte input block.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Update(ulong[] packet) {
		// ========== Step 1: Absorb Input into v1 ==========
		// The input packet is added to v1, making v1 dependent on input data.
		// Addition is used because it's fast and mixes well with XOR.
		_v1[0] += packet[0];
		_v1[1] += packet[1];
		_v1[2] += packet[2];
		_v1[3] += packet[3];

		// ========== Step 2: Add Multiplier to v1 ==========
		// Adding mul0 to v1 incorporates the evolving multiplier state,
		// making the state dependent on all previous inputs.
		_v1[0] += _mul0[0];
		_v1[1] += _mul0[1];
		_v1[2] += _mul0[2];
		_v1[3] += _mul0[3];

		// ========== Step 3: Update mul0 with Non-linear Mixing ==========
		// The key operation: multiply lower 32 bits of v1 by upper 32 bits of v0.
		// This creates strong non-linear mixing:
		// - (v1 & 0xffffffff) extracts lower 32 bits
		// - (v0 >> 32) extracts upper 32 bits
		// - The 64-bit multiplication result is XORed into mul0
		// This operation provides avalanche: a single bit change in input
		// affects approximately half of the output bits.
		_mul0[0] ^= (_v1[0] & 0xffffffffUL) * (_v0[0] >> 32);
		_mul0[1] ^= (_v1[1] & 0xffffffffUL) * (_v0[1] >> 32);
		_mul0[2] ^= (_v1[2] & 0xffffffffUL) * (_v0[2] >> 32);
		_mul0[3] ^= (_v1[3] & 0xffffffffUL) * (_v0[3] >> 32);

		// ========== Step 4: Add Multiplier to v0 ==========
		// Now we update v0 by adding mul1, creating cross-dependency
		// between the two state vectors.
		_v0[0] += _mul1[0];
		_v0[1] += _mul1[1];
		_v0[2] += _mul1[2];
		_v0[3] += _mul1[3];

		// ========== Step 5: Update mul1 with Non-linear Mixing ==========
		// Same multiplication technique as Step 3, but with v0 and v1 swapped.
		// This creates symmetric mixing between the two state vectors.
		_mul1[0] ^= (_v0[0] & 0xffffffffUL) * (_v1[0] >> 32);
		_mul1[1] ^= (_v0[1] & 0xffffffffUL) * (_v1[1] >> 32);
		_mul1[2] ^= (_v0[2] & 0xffffffffUL) * (_v1[2] >> 32);
		_mul1[3] ^= (_v0[3] & 0xffffffffUL) * (_v1[3] >> 32);

		// ========== Step 6: ZipperMerge - Byte-Level Diffusion ==========
		// ZipperMerge interleaves bytes from adjacent lanes, providing diffusion
		// at the byte level. This ensures that bytes from one lane influence
		// bytes in neighboring lanes, spreading any changes across all lanes.
		//
		// The merge pattern extracts specific bytes from v1[i] and v0[i-1],
		// combines them in a specific order, and adds to v0[i].
		// This creates dependencies between adjacent lane pairs.

		// Merge lanes 0,1 into v0[0] and v0[1]
		_v0[0] += ZipperMerge0(_v1[1], _v1[0]);
		_v0[1] += ZipperMerge1(_v1[1], _v1[0]);

		// Merge lanes 2,3 into v0[2] and v0[3]
		_v0[2] += ZipperMerge0(_v1[3], _v1[2]);
		_v0[3] += ZipperMerge1(_v1[3], _v1[2]);

		// Apply same ZipperMerge to v1 using v0 values
		// This creates bidirectional diffusion between v0 and v1
		_v1[0] += ZipperMerge0(_v0[1], _v0[0]);
		_v1[1] += ZipperMerge1(_v0[1], _v0[0]);
		_v1[2] += ZipperMerge0(_v0[3], _v0[2]);
		_v1[3] += ZipperMerge1(_v0[3], _v0[2]);
	}

	/// <summary>
	/// ZipperMerge function - first output.
	/// Interleaves bytes from two 64-bit values to create diffusion across lanes.
	/// </summary>
	/// <remarks>
	/// <para>
	/// ZipperMerge is a key component of HighwayHash's diffusion strategy.
	/// It rearranges bytes from two adjacent lanes, similar to a zipper
	/// interlocking teeth from both sides.
	/// </para>
	/// <para>
	/// <b>Byte-Level Operation:</b>
	/// The function extracts bytes from specific positions in v0 and v1,
	/// then reassembles them in a new order. This ensures that any change
	/// to a single byte in one lane will affect multiple bytes in the output.
	/// </para>
	/// <para>
	/// This operation provides local diffusion (bytes influence neighbors)
	/// while the overall Update function provides global diffusion across all lanes.
	/// </para>
	/// </remarks>
	/// <param name="v1">Second input value (from adjacent lane).</param>
	/// <param name="v0">First input value (from current lane).</param>
	/// <returns>A 64-bit value with bytes interleaved from both inputs.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ZipperMerge0(ulong v1, ulong v0) {
		// Extract and position bytes from v0 and v1 into specific positions.
		// The pattern is designed so that every output byte depends on a byte
		// from either v0 or v1, spreading any bit changes across the state.
		//
		// Byte layout (0 = LSB, 7 = MSB):
		// - Bits 0-7 (byte 0):   v0 byte 7 (MSB of v0)
		// - Bits 8-15 (byte 1):  v1 byte 7 (MSB of v1)
		// - Bits 16-23 (byte 2): v0 byte 2
		// - Bits 24-31 (byte 3): v0 byte 3 OR v1 byte 4
		// - Bits 32-39 (byte 4): v0 byte 5 OR v1 byte 6
		// - Bits 40-47 (byte 5): v0 byte 1
		// - Bits 48-55 (byte 6): (derived from shift)
		// - Bits 56-63 (byte 7): v0 byte 0 (LSB of v0)
		return (((v0 & 0xff000000UL) | (v1 & 0xff00000000UL)) >> 24) |
			   (((v0 & 0xff0000000000UL) | (v1 & 0xff000000000000UL)) >> 16) |
			   (v0 & 0xff0000UL) |
			   ((v0 & 0xff00UL) << 32) |
			   ((v1 & 0xff00000000000000UL) >> 8) |
			   (v0 << 56);
	}

	/// <summary>
	/// ZipperMerge function - second output.
	/// Interleaves bytes from two 64-bit values using a complementary pattern.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This is the complementary function to <see cref="ZipperMerge0"/>.
	/// Together, they ensure complete mixing of bytes between adjacent lane pairs.
	/// </para>
	/// <para>
	/// <b>Complementary Pattern:</b>
	/// Where ZipperMerge0 takes certain bytes from v0, ZipperMerge1 takes them from v1,
	/// and vice versa. This ensures no information is lost during the merge process.
	/// </para>
	/// </remarks>
	/// <param name="v1">Second input value (from adjacent lane).</param>
	/// <param name="v0">First input value (from current lane).</param>
	/// <returns>A 64-bit value with bytes interleaved in the complementary pattern.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ZipperMerge1(ulong v1, ulong v0) {
		// Complementary byte extraction pattern to ZipperMerge0.
		// Uses bytes that ZipperMerge0 didn't use, ensuring complete coverage.
		//
		// This function extracts different byte positions than ZipperMerge0,
		// ensuring that when both are applied, all bytes from both inputs
		// contribute to the final merged state.
		return (((v1 & 0xff000000UL) | (v0 & 0xff00000000UL)) >> 24) |
			   (v1 & 0xff0000UL) |
			   ((v1 & 0xff0000000000UL) >> 16) |
			   ((v1 & 0xff00UL) << 24) |
			   ((v0 & 0xff000000000000UL) >> 8) |
			   ((v1 & 0xffUL) << 48) |
			   (v0 & 0xff00000000000000UL);
	}

	/// <inheritdoc/>
	/// <remarks>
	/// Computes the final 64-bit hash value after processing all input data.
	/// Any remaining bytes (less than 32) are processed with special padding,
	/// followed by finalization rounds to ensure complete mixing.
	/// </remarks>
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		// Process remaining bytes that don't fill a complete 32-byte block.
		// These are handled specially with rotation and padding.
		if (remaining.Length > 0) {
			ProcessRemainder(remaining);
		}

		// Run finalization permutation rounds to ensure complete mixing
		// of all state before producing the final hash value.
		PermuteAndFinalize();

		// Combine all state vectors and multipliers into final 64-bit hash.
		// Adding all components ensures the output depends on the full state.
		return _v0[0] + _v1[0] + _mul0[0] + _mul1[0];
	}

	/// <summary>
	/// Processes remaining bytes that don't fill a complete 32-byte block.
	/// </summary>
	/// <remarks>
	/// <para>
	/// When the input length is not a multiple of 32 bytes, the remaining
	/// bytes must be processed specially. This method:
	/// </para>
	/// <list type="number">
	/// <item>Initializes a packet with current v0 state (provides padding)</item>
	/// <item>Rotates the packet based on remainder size (ensures different lengths produce different results)</item>
	/// <item>Incorporates actual remainder bytes into the packet</item>
	/// <item>XORs the total remainder size into the final lane (length disambiguation)</item>
	/// <item>Runs a final Update with this modified packet</item>
	/// </list>
	/// <para>
	/// This approach ensures that messages of different lengths that share the same
	/// prefix will produce different hash values.
	/// </para>
	/// </remarks>
	/// <param name="remainder">The remaining bytes (1-31 bytes).</param>
	private void ProcessRemainder(ReadOnlySpan<byte> remainder) {
		int size = remainder.Length;
		int count = (size + 7) / 8; // Number of 8-byte chunks (ceiling division)

		// Initialize packet with current state - this provides padding
		// for any unfilled bytes and ensures dependency on previous state.
		ulong[] packet = [_v0[0], _v0[1], _v0[2], _v0[3]];

		// Rotate packet based on remainder size modulo 8.
		// This ensures that messages of length N and N+8 don't align
		// their bytes in the same positions, improving collision resistance.
		for (int i = 0; i < (uint)size % 8; i++) {
			ulong temp = packet[0];
			packet[0] = packet[1];
			packet[1] = packet[2];
			packet[2] = packet[3];
			packet[3] = temp;
		}

		// Incorporate actual remainder bytes, overwriting rotated state values.
		// Each 8-byte chunk is read as a little-endian 64-bit value.
		if (size >= 8) {
			packet[0] = BinaryPrimitives.ReadUInt64LittleEndian(remainder[0..8]);
		}
		if (size >= 16) {
			packet[1] = BinaryPrimitives.ReadUInt64LittleEndian(remainder[8..16]);
		}
		if (size >= 24) {
			packet[2] = BinaryPrimitives.ReadUInt64LittleEndian(remainder[16..24]);
		}

		// Handle final partial chunk (1-7 bytes) - read byte by byte.
		int remaining = size & 7; // Equivalent to size % 8
		if (remaining > 0) {
			int idx = (size / 8); // Which packet slot gets the partial data
			if (idx < 4) {
				// Build a 64-bit value from the remaining bytes.
				// Each byte is shifted to its correct position (little-endian).
				ulong last = 0;
				int offset = (size / 8) * 8; // Byte offset of partial chunk
				for (int i = 0; i < remaining; i++) {
					last |= (ulong)remainder[offset + i] << (i * 8);
				}
				packet[idx] = last;
			}
		}

		// XOR the total remainder size into the final lane.
		// This provides length disambiguation - two messages with the same
		// content but different padding will hash differently.
		packet[3] ^= (ulong)size;

		// Run standard Update with the prepared packet
		Update(packet);
	}

	/// <summary>
	/// Performs final permutation rounds to ensure complete state mixing.
	/// </summary>
	/// <remarks>
	/// <para>
	/// After all input has been processed, running additional permutation rounds
	/// ensures that every bit of input has a chance to influence every bit of output.
	/// </para>
	/// <para>
	/// The function runs 4 rounds where the current v0 state is fed back through
	/// the Update function. This is similar to finalization rounds in other hash
	/// functions (like the final squeezing in sponge constructions).
	/// </para>
	/// </remarks>
	private void PermuteAndFinalize() {
		// Run 4 additional permutation rounds.
		// Each round feeds the current v0 state back through Update,
		// allowing complete diffusion of all state bits.
		ulong[] packet = new ulong[4];
		for (int i = 0; i < 4; i++) {
			// Copy current v0 state to packet
			packet[0] = _v0[0];
			packet[1] = _v0[1];
			packet[2] = _v0[2];
			packet[3] = _v0[3];

			// Run through mixing function
			Update(packet);
		}
	}

	/// <inheritdoc/>
	/// <remarks>
	/// Reinitializes all state arrays with the key-derived values,
	/// allowing the same hasher instance to be reused for a new hash computation.
	/// </remarks>
	protected override void ResetCore() {
		InitializeState();
	}

	/// <summary>
	/// Computes the HighwayHash64 hash of the given data in one shot.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This is a convenience method for hashing data without explicitly
	/// managing a hasher instance. It creates a temporary hasher, processes
	/// all data, and returns the final hash value.
	/// </para>
	/// <para>
	/// For hashing multiple pieces of data or for streaming scenarios,
	/// create a <see cref="HighwayHash64"/> instance directly and call
	/// <see cref="StreamingHashBase{T}.Update(ReadOnlySpan{byte})"/> multiple times.
	/// </para>
	/// </remarks>
	/// <param name="data">The data to hash.</param>
	/// <param name="key">Optional 4-element key array. If null, uses default key (all zeros).</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <example>
	/// <code>
	/// // Hash with default key
	/// ulong hash1 = HighwayHash64.Hash("Hello"u8);
	///
	/// // Hash with custom key
	/// ulong[] key = [0x0706050403020100, 0x0f0e0d0c0b0a0908,
	///                0x1716151413121110, 0x1f1e1d1c1b1a1918];
	/// ulong hash2 = HighwayHash64.Hash("Hello"u8, key);
	/// </code>
	/// </example>
	public static ulong Hash(ReadOnlySpan<byte> data, ulong[]? key = null) {
		// Create a temporary hasher with the specified key (or default)
		using var hasher = key != null ? new HighwayHash64(key) : new HighwayHash64();

		// Process all input data
		hasher.Update(data);

		// Return the computed hash value
		return hasher.Finalize();
	}
}
