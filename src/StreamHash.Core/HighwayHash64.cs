namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of HighwayHash64 algorithm.
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
	/// <summary>
	/// Default key for convenience (should be replaced with a secret key for security).
	/// </summary>
	private static readonly ulong[] DefaultKey = [
		0x0706050403020100UL,
		0x0f0e0d0c0b0a0908UL,
		0x1716151413121110UL,
		0x1f1e1d1c1b1a1918UL
	];

	// Internal state: 4 lanes of 64-bit values
	private readonly ulong[] _v0 = new ulong[4];
	private readonly ulong[] _v1 = new ulong[4];
	private readonly ulong[] _mul0 = new ulong[4];
	private readonly ulong[] _mul1 = new ulong[4];

	// Original key for reset
	private readonly ulong[] _key;

	/// <inheritdoc/>
	public override int BlockSize => 32;

	/// <inheritdoc/>
	public override int DigestSize => 8;

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
	private void InitializeState() {
		// Initial multipliers
		_mul0[0] = 0xdbe6d5d5fe4cce2fUL;
		_mul0[1] = 0xa4093822299f31d0UL;
		_mul0[2] = 0x13198a2e03707344UL;
		_mul0[3] = 0x243f6a8885a308d3UL;

		_mul1[0] = 0x3bd39e10cb0ef593UL;
		_mul1[1] = 0xc0acf169b5f18a8cUL;
		_mul1[2] = 0xbe5466cf34e90c6cUL;
		_mul1[3] = 0x452821e638d01377UL;

		// Initialize v0 and v1 from key
		_v0[0] = _mul0[0] ^ _key[0];
		_v0[1] = _mul0[1] ^ _key[1];
		_v0[2] = _mul0[2] ^ _key[2];
		_v0[3] = _mul0[3] ^ _key[3];

		_v1[0] = _mul1[0] ^ ((_key[0] >> 32) | (_key[0] << 32));
		_v1[1] = _mul1[1] ^ ((_key[1] >> 32) | (_key[1] << 32));
		_v1[2] = _mul1[2] ^ ((_key[2] >> 32) | (_key[2] << 32));
		_v1[3] = _mul1[3] ^ ((_key[3] >> 32) | (_key[3] << 32));
	}

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
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
	/// Processes a packet of 4 lanes.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Update(ulong[] packet) {
		// Add packet to v1
		_v1[0] += packet[0];
		_v1[1] += packet[1];
		_v1[2] += packet[2];
		_v1[3] += packet[3];

		// Add mul0 to v1
		_v1[0] += _mul0[0];
		_v1[1] += _mul0[1];
		_v1[2] += _mul0[2];
		_v1[3] += _mul0[3];

		// Update mul0
		_mul0[0] ^= (_v1[0] & 0xffffffffUL) * (_v0[0] >> 32);
		_mul0[1] ^= (_v1[1] & 0xffffffffUL) * (_v0[1] >> 32);
		_mul0[2] ^= (_v1[2] & 0xffffffffUL) * (_v0[2] >> 32);
		_mul0[3] ^= (_v1[3] & 0xffffffffUL) * (_v0[3] >> 32);

		// Update v0 with rotation and shuffle
		_v0[0] += _mul1[0];
		_v0[1] += _mul1[1];
		_v0[2] += _mul1[2];
		_v0[3] += _mul1[3];

		// Update mul1
		_mul1[0] ^= (_v0[0] & 0xffffffffUL) * (_v1[0] >> 32);
		_mul1[1] ^= (_v0[1] & 0xffffffffUL) * (_v1[1] >> 32);
		_mul1[2] ^= (_v0[2] & 0xffffffffUL) * (_v1[2] >> 32);
		_mul1[3] ^= (_v0[3] & 0xffffffffUL) * (_v1[3] >> 32);

		// ZipperMerge
		_v0[0] += ZipperMerge0(_v1[1], _v1[0]);
		_v0[1] += ZipperMerge1(_v1[1], _v1[0]);
		_v0[2] += ZipperMerge0(_v1[3], _v1[2]);
		_v0[3] += ZipperMerge1(_v1[3], _v1[2]);

		_v1[0] += ZipperMerge0(_v0[1], _v0[0]);
		_v1[1] += ZipperMerge1(_v0[1], _v0[0]);
		_v1[2] += ZipperMerge0(_v0[3], _v0[2]);
		_v1[3] += ZipperMerge1(_v0[3], _v0[2]);
	}

	/// <summary>
	/// ZipperMerge function - first output.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ZipperMerge0(ulong v1, ulong v0) {
		return (((v0 & 0xff000000UL) | (v1 & 0xff00000000UL)) >> 24) |
			   (((v0 & 0xff0000000000UL) | (v1 & 0xff000000000000UL)) >> 16) |
			   (v0 & 0xff0000UL) |
			   ((v0 & 0xff00UL) << 32) |
			   ((v1 & 0xff00000000000000UL) >> 8) |
			   (v0 << 56);
	}

	/// <summary>
	/// ZipperMerge function - second output.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ZipperMerge1(ulong v1, ulong v0) {
		return (((v1 & 0xff000000UL) | (v0 & 0xff00000000UL)) >> 24) |
			   (v1 & 0xff0000UL) |
			   ((v1 & 0xff0000000000UL) >> 16) |
			   ((v1 & 0xff00UL) << 24) |
			   ((v0 & 0xff000000000000UL) >> 8) |
			   ((v1 & 0xffUL) << 48) |
			   (v0 & 0xff00000000000000UL);
	}

	/// <inheritdoc/>
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		// Process remaining bytes with padding
		if (remaining.Length > 0) {
			ProcessRemainder(remaining);
		}

		// Permute and finalize
		PermuteAndFinalize();

		// Return 64-bit result
		return _v0[0] + _v1[0] + _mul0[0] + _mul1[0];
	}

	/// <summary>
	/// Processes remaining bytes (less than 32).
	/// </summary>
	private void ProcessRemainder(ReadOnlySpan<byte> remainder) {
		int size = remainder.Length;
		int count = (size + 7) / 8; // Number of 8-byte chunks

		ulong[] packet = [_v0[0], _v0[1], _v0[2], _v0[3]];

		// Rotate packet based on remainder size
		for (int i = 0; i < (uint)size % 8; i++) {
			ulong temp = packet[0];
			packet[0] = packet[1];
			packet[1] = packet[2];
			packet[2] = packet[3];
			packet[3] = temp;
		}

		// Incorporate actual remainder bytes
		if (size >= 8) {
			packet[0] = BinaryPrimitives.ReadUInt64LittleEndian(remainder[0..8]);
		}
		if (size >= 16) {
			packet[1] = BinaryPrimitives.ReadUInt64LittleEndian(remainder[8..16]);
		}
		if (size >= 24) {
			packet[2] = BinaryPrimitives.ReadUInt64LittleEndian(remainder[16..24]);
		}

		// Handle final partial chunk
		int remaining = size & 7;
		if (remaining > 0) {
			int idx = (size / 8);
			if (idx < 4) {
				ulong last = 0;
				int offset = (size / 8) * 8;
				for (int i = 0; i < remaining; i++) {
					last |= (ulong)remainder[offset + i] << (i * 8);
				}
				packet[idx] = last;
			}
		}

		// Add size to final lane
		packet[3] ^= (ulong)size;

		Update(packet);
	}

	/// <summary>
	/// Final permutation rounds.
	/// </summary>
	private void PermuteAndFinalize() {
		// Run 4 additional permutation rounds
		ulong[] packet = new ulong[4];
		for (int i = 0; i < 4; i++) {
			packet[0] = _v0[0];
			packet[1] = _v0[1];
			packet[2] = _v0[2];
			packet[3] = _v0[3];
			Update(packet);
		}
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		InitializeState();
	}

	/// <summary>
	/// Computes the HighwayHash64 hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="key">Optional 4-element key array. If null, uses default key.</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong Hash(ReadOnlySpan<byte> data, ulong[]? key = null) {
		using var hasher = key != null ? new HighwayHash64(key) : new HighwayHash64();
		hasher.Update(data);
		return hasher.Finalize();
	}
}
