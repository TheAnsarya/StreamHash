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
	/// <summary>
	/// MurmurHash3 constant c1 for 32-bit variant.
	/// </summary>
	private const uint C1 = 0xcc9e2d51;

	/// <summary>
	/// MurmurHash3 constant c2 for 32-bit variant.
	/// </summary>
	private const uint C2 = 0x1b873593;

	private readonly uint _seed;
	private uint _h1;
	private int _processedBlocks;

	/// <inheritdoc/>
	public override int BlockSize => 4;

	/// <inheritdoc/>
	public override int DigestSize => 4;

	/// <summary>
	/// Gets the seed value used for this hash instance.
	/// </summary>
	public uint Seed => _seed;

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
		_h1 = seed;
		_processedBlocks = 0;
	}

	/// <inheritdoc/>
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

	/// <inheritdoc/>
	protected override uint ComputeFinal(ReadOnlySpan<byte> remaining) {
		uint k1 = 0;

		// Process remaining bytes (tail)
		switch (remaining.Length) {
			case 3:
				k1 ^= (uint)remaining[2] << 16;
				goto case 2;
			case 2:
				k1 ^= (uint)remaining[1] << 8;
				goto case 1;
			case 1:
				k1 ^= remaining[0];
				k1 *= C1;
				k1 = BitOperations.RotateLeft(k1, 15);
				k1 *= C2;
				_h1 ^= k1;
				break;
		}

		// Finalization mix
		_h1 ^= (uint)TotalBytesProcessed;
		_h1 = FMix32(_h1);

		return _h1;
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		_h1 = _seed;
		_processedBlocks = 0;
	}

	/// <summary>
	/// MurmurHash3 finalization mix - force all bits to avalanche.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FMix32(uint h) {
		h ^= h >> 16;
		h *= 0x85ebca6b;
		h ^= h >> 13;
		h *= 0xc2b2ae35;
		h ^= h >> 16;
		return h;
	}

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
