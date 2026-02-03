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
	// MetroHash128 constants
	private const ulong K0 = 0xc83a91e1UL;
	private const ulong K1 = 0x8648dbdbUL;
	private const ulong K2 = 0x7bdec03bUL;
	private const ulong K3 = 0x2f5870a5UL;

	private readonly ulong _seed;

	// State variables
	private ulong _v0, _v1, _v2, _v3;

	/// <inheritdoc/>
	public override int BlockSize => 32;

	/// <inheritdoc/>
	public override int DigestSize => 16;

	/// <summary>
	/// Creates a new MetroHash128 hasher with seed 0.
	/// </summary>
	public MetroHash128() : this(0) { }

	/// <summary>
	/// Creates a new MetroHash128 hasher with the specified seed.
	/// </summary>
	/// <param name="seed">The seed value.</param>
	public MetroHash128(ulong seed) {
		_seed = seed;
		Initialize();
	}

	private void Initialize() {
		_v0 = (_seed - K0) * K3;
		_v1 = (_seed + K1) * K2;
		_v2 = (_seed + K0) * K2;
		_v3 = (_seed - K1) * K3;
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
	protected override UInt128 ComputeFinal(ReadOnlySpan<byte> remaining) {
		if (TotalBytesProcessed >= 32) {
			// Combine state for long inputs
			_v2 ^= BitOperations.RotateRight(((_v0 + _v3) * K0) + _v1, 21) * K1;
			_v3 ^= BitOperations.RotateRight(((_v1 + _v2) * K1) + _v0, 21) * K0;
			_v0 ^= BitOperations.RotateRight(((_v0 + _v2) * K0) + _v3, 21) * K1;
			_v1 ^= BitOperations.RotateRight(((_v1 + _v3) * K1) + _v2, 21) * K0;
		}

		// Process remaining 16-byte chunks
		int pos = 0;
		if (remaining.Length - pos >= 16) {
			ulong val0 = BinaryPrimitives.ReadUInt64LittleEndian(remaining[pos..]);
			ulong val1 = BinaryPrimitives.ReadUInt64LittleEndian(remaining[(pos + 8)..]);
			_v0 += val0 * K2;
			_v0 = BitOperations.RotateRight(_v0, 33) * K3;
			_v1 += val1 * K2;
			_v1 = BitOperations.RotateRight(_v1, 33) * K3;
			_v0 ^= BitOperations.RotateRight((_v0 * K2) + _v1, 45) * K1;
			_v1 ^= BitOperations.RotateRight((_v1 * K3) + _v0, 45) * K0;
			pos += 16;
		}

		// Process remaining 8-byte chunk
		if (remaining.Length - pos >= 8) {
			ulong val = BinaryPrimitives.ReadUInt64LittleEndian(remaining[pos..]);
			_v0 += val * K2;
			_v0 = BitOperations.RotateRight(_v0, 33) * K3;
			_v0 ^= BitOperations.RotateRight((_v0 * K2) + _v1, 27) * K1;
			pos += 8;
		}

		// Process remaining 4-byte chunk
		if (remaining.Length - pos >= 4) {
			uint val = BinaryPrimitives.ReadUInt32LittleEndian(remaining[pos..]);
			_v1 += val * K2;
			_v1 = BitOperations.RotateRight(_v1, 33) * K3;
			_v1 ^= BitOperations.RotateRight((_v1 * K3) + _v0, 46) * K0;
			pos += 4;
		}

		// Process remaining 2-byte chunk
		if (remaining.Length - pos >= 2) {
			ushort val = BinaryPrimitives.ReadUInt16LittleEndian(remaining[pos..]);
			_v0 += val * K2;
			_v0 = BitOperations.RotateRight(_v0, 33) * K3;
			_v0 ^= BitOperations.RotateRight((_v0 * K2) + _v1, 22) * K1;
			pos += 2;
		}

		// Process remaining byte
		if (remaining.Length - pos >= 1) {
			_v1 += remaining[pos] * K2;
			_v1 = BitOperations.RotateRight(_v1, 33) * K3;
			_v1 ^= BitOperations.RotateRight((_v1 * K3) + _v0, 58) * K0;
		}

		// Final mixing
		_v0 += BitOperations.RotateRight((_v0 * K0) + _v1, 13);
		_v1 += BitOperations.RotateRight((_v1 * K1) + _v0, 37);
		_v0 += BitOperations.RotateRight((_v0 * K2) + _v1, 13);
		_v1 += BitOperations.RotateRight((_v1 * K3) + _v0, 37);

		return new UInt128(_v1, _v0);
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		Initialize();
	}

	/// <summary>
	/// Computes MetroHash128 of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">Optional seed value.</param>
	/// <returns>The 128-bit hash value.</returns>
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
