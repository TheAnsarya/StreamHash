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
	// MetroHash constants
	private const ulong K0 = 0xd6d018f5UL;
	private const ulong K1 = 0xa2aa033bUL;
	private const ulong K2 = 0x62992fc1UL;
	private const ulong K3 = 0x30bc5b29UL;

	private readonly ulong _seed;

	// State variables
	private ulong _v0, _v1, _v2, _v3;

	/// <inheritdoc/>
	public override int BlockSize => 32;

	/// <inheritdoc/>
	public override int DigestSize => 8;

	/// <summary>
	/// Creates a new MetroHash64 hasher with seed 0.
	/// </summary>
	public MetroHash64() : this(0) { }

	/// <summary>
	/// Creates a new MetroHash64 hasher with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value.</param>
	public MetroHash64(ulong seed) {
		_seed = seed;
		Initialize();
	}

	private void Initialize() {
		ulong seedPlusK = (_seed + K2) * K0;
		_v0 = seedPlusK;
		_v1 = seedPlusK;
		_v2 = seedPlusK;
		_v3 = seedPlusK;
	}

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		ulong b0 = BinaryPrimitives.ReadUInt64LittleEndian(block);
		ulong b1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);
		ulong b2 = BinaryPrimitives.ReadUInt64LittleEndian(block[16..]);
		ulong b3 = BinaryPrimitives.ReadUInt64LittleEndian(block[24..]);

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
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		ulong hash;

		if (TotalBytesProcessed >= 32) {
			// Combine state for long inputs
			_v2 ^= BitOperations.RotateRight(((_v0 + _v3) * K0) + _v1, 37) * K1;
			_v3 ^= BitOperations.RotateRight(((_v1 + _v2) * K1) + _v0, 37) * K0;
			_v0 ^= BitOperations.RotateRight(((_v0 + _v2) * K0) + _v3, 37) * K1;
			_v1 ^= BitOperations.RotateRight(((_v1 + _v3) * K1) + _v2, 37) * K0;
			hash = _v0 + _v1;
		} else {
			// Short input initialization
			hash = (_seed + K2) * K0;
		}

		// Process remaining 8-byte chunks
		int pos = 0;
		while (remaining.Length - pos >= 8) {
			ulong val = BinaryPrimitives.ReadUInt64LittleEndian(remaining[pos..]);
			hash += val * K3;
			pos += 8;
			hash ^= BitOperations.RotateRight(hash, 55) * K1;
		}

		// Process remaining 4-byte chunk
		if (remaining.Length - pos >= 4) {
			uint val = BinaryPrimitives.ReadUInt32LittleEndian(remaining[pos..]);
			hash += val * K3;
			pos += 4;
			hash ^= BitOperations.RotateRight(hash, 26) * K1;
		}

		// Process remaining 2-byte chunk
		if (remaining.Length - pos >= 2) {
			ushort val = BinaryPrimitives.ReadUInt16LittleEndian(remaining[pos..]);
			hash += val * K3;
			pos += 2;
			hash ^= BitOperations.RotateRight(hash, 48) * K1;
		}

		// Process remaining byte
		if (remaining.Length - pos >= 1) {
			hash += remaining[pos] * K3;
			hash ^= BitOperations.RotateRight(hash, 37) * K1;
		}

		// Final mixing
		hash ^= BitOperations.RotateRight(hash, 28);
		hash *= K0;
		hash ^= BitOperations.RotateRight(hash, 29);

		return hash;
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		Initialize();
	}

	/// <summary>
	/// Computes MetroHash64 of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">Optional seed value.</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong Hash(ReadOnlySpan<byte> data, ulong seed = 0) {
		using var hasher = new MetroHash64(seed);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
