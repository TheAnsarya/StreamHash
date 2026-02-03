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
	private readonly ulong _k0;
	private readonly ulong _k1;
	private ulong _v0;
	private ulong _v1;
	private ulong _v2;
	private ulong _v3;

	/// <inheritdoc/>
	public override int BlockSize => 8;

	/// <inheritdoc/>
	public override int DigestSize => 8;

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
	public SipHash24(ReadOnlySpan<byte> key) {
		if (key.Length != 16) {
			throw new ArgumentException("SipHash key must be exactly 16 bytes.", nameof(key));
		}

		_k0 = BinaryPrimitives.ReadUInt64LittleEndian(key);
		_k1 = BinaryPrimitives.ReadUInt64LittleEndian(key[8..]);
		Initialize();
	}

	/// <summary>
	/// Creates a new SipHash-2-4 hasher with the specified key halves.
	/// </summary>
	/// <param name="k0">First 64 bits of the key.</param>
	/// <param name="k1">Second 64 bits of the key.</param>
	public SipHash24(ulong k0, ulong k1) {
		_k0 = k0;
		_k1 = k1;
		Initialize();
	}

	private void Initialize() {
		_v0 = _k0 ^ 0x736f6d6570736575;
		_v1 = _k1 ^ 0x646f72616e646f6d;
		_v2 = _k0 ^ 0x6c7967656e657261;
		_v3 = _k1 ^ 0x7465646279746573;
	}

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		ulong m = BinaryPrimitives.ReadUInt64LittleEndian(block);

		_v3 ^= m;

		// 2 compression rounds
		SipRound();
		SipRound();

		_v0 ^= m;
	}

	/// <inheritdoc/>
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		// Construct final block with length in high byte
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

		_v3 ^= b;

		// 2 compression rounds
		SipRound();
		SipRound();

		_v0 ^= b;

		// 4 finalization rounds
		_v2 ^= 0xff;

		SipRound();
		SipRound();
		SipRound();
		SipRound();

		return _v0 ^ _v1 ^ _v2 ^ _v3;
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		Initialize();
	}

	/// <summary>
	/// One round of SipHash mixing.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void SipRound() {
		_v0 += _v1;
		_v1 = BitOperations.RotateLeft(_v1, 13);
		_v1 ^= _v0;
		_v0 = BitOperations.RotateLeft(_v0, 32);

		_v2 += _v3;
		_v3 = BitOperations.RotateLeft(_v3, 16);
		_v3 ^= _v2;

		_v0 += _v3;
		_v3 = BitOperations.RotateLeft(_v3, 21);
		_v3 ^= _v0;

		_v2 += _v1;
		_v1 = BitOperations.RotateLeft(_v1, 17);
		_v1 ^= _v2;
		_v2 = BitOperations.RotateLeft(_v2, 32);
	}

	/// <summary>
	/// Computes SipHash-2-4 of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="key">A 16-byte key.</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong Hash(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key) {
		using var hasher = new SipHash24(key);
		hasher.Update(data);
		return hasher.Finalize();
	}

	/// <summary>
	/// Computes SipHash-2-4 of the given data with key components.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="k0">First 64 bits of the key.</param>
	/// <param name="k1">Second 64 bits of the key.</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong Hash(ReadOnlySpan<byte> data, ulong k0, ulong k1) {
		using var hasher = new SipHash24(k0, k1);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
