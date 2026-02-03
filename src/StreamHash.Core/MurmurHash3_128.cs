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
	private const ulong C1 = 0x87c37b91114253d5;
	private const ulong C2 = 0x4cf5ad432745937f;

	private readonly uint _seed;
	private ulong _h1;
	private ulong _h2;

	/// <inheritdoc/>
	public override int BlockSize => 16;

	/// <inheritdoc/>
	public override int DigestSize => 16;

	/// <summary>
	/// Gets the seed value used for this hash instance.
	/// </summary>
	public uint Seed => _seed;

	/// <summary>
	/// Creates a new MurmurHash3 128-bit hasher with seed 0.
	/// </summary>
	public MurmurHash3_128() : this(0) { }

	/// <summary>
	/// Creates a new MurmurHash3 128-bit hasher with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value for hash computation.</param>
	public MurmurHash3_128(uint seed) {
		_seed = seed;
		_h1 = seed;
		_h2 = seed;
	}

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		ulong k1 = BinaryPrimitives.ReadUInt64LittleEndian(block);
		ulong k2 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);

		k1 *= C1;
		k1 = BitOperations.RotateLeft(k1, 31);
		k1 *= C2;
		_h1 ^= k1;

		_h1 = BitOperations.RotateLeft(_h1, 27);
		_h1 += _h2;
		_h1 = _h1 * 5 + 0x52dce729;

		k2 *= C2;
		k2 = BitOperations.RotateLeft(k2, 33);
		k2 *= C1;
		_h2 ^= k2;

		_h2 = BitOperations.RotateLeft(_h2, 31);
		_h2 += _h1;
		_h2 = _h2 * 5 + 0x38495ab5;
	}

	/// <inheritdoc/>
	protected override UInt128 ComputeFinal(ReadOnlySpan<byte> remaining) {
		ulong k1 = 0;
		ulong k2 = 0;

		// Process remaining bytes
		int len = remaining.Length;

		if (len >= 15) k2 ^= (ulong)remaining[14] << 48;
		if (len >= 14) k2 ^= (ulong)remaining[13] << 40;
		if (len >= 13) k2 ^= (ulong)remaining[12] << 32;
		if (len >= 12) k2 ^= (ulong)remaining[11] << 24;
		if (len >= 11) k2 ^= (ulong)remaining[10] << 16;
		if (len >= 10) k2 ^= (ulong)remaining[9] << 8;
		if (len >= 9) {
			k2 ^= remaining[8];
			k2 *= C2;
			k2 = BitOperations.RotateLeft(k2, 33);
			k2 *= C1;
			_h2 ^= k2;
		}

		if (len >= 8) k1 ^= BinaryPrimitives.ReadUInt64LittleEndian(remaining);
		else {
			if (len >= 7) k1 ^= (ulong)remaining[6] << 48;
			if (len >= 6) k1 ^= (ulong)remaining[5] << 40;
			if (len >= 5) k1 ^= (ulong)remaining[4] << 32;
			if (len >= 4) k1 ^= (ulong)remaining[3] << 24;
			if (len >= 3) k1 ^= (ulong)remaining[2] << 16;
			if (len >= 2) k1 ^= (ulong)remaining[1] << 8;
			if (len >= 1) k1 ^= remaining[0];
		}

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

		// Finalization
		_h1 ^= (ulong)TotalBytesProcessed;
		_h2 ^= (ulong)TotalBytesProcessed;

		_h1 += _h2;
		_h2 += _h1;

		_h1 = FMix64(_h1);
		_h2 = FMix64(_h2);

		_h1 += _h2;
		_h2 += _h1;

		return new UInt128(_h2, _h1);
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		_h1 = _seed;
		_h2 = _seed;
	}

	/// <summary>
	/// MurmurHash3 64-bit finalization mix.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong FMix64(ulong k) {
		k ^= k >> 33;
		k *= 0xff51afd7ed558ccd;
		k ^= k >> 33;
		k *= 0xc4ceb9fe1a85ec53;
		k ^= k >> 33;
		return k;
	}

	/// <summary>
	/// Computes the MurmurHash3 128-bit hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">Optional seed value (default: 0).</param>
	/// <returns>The 128-bit hash value.</returns>
	public static UInt128 Hash(ReadOnlySpan<byte> data, uint seed = 0) {
		using var hasher = new MurmurHash3_128(seed);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
