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
	/// <summary>
	/// Magic constant: the golden ratio, an arbitrary constant.
	/// </summary>
	private const ulong SC = 0xdeadbeefdeadbeef;

	/// <summary>
	/// Number of 64-bit words in the internal state.
	/// </summary>
	private const int NumVars = 12;

	/// <summary>
	/// Block size in bytes (96 = NumVars * 8).
	/// </summary>
	private const int BlockSizeBytes = NumVars * 8;

	private readonly ulong _seed1;
	private readonly ulong _seed2;

	// Internal state (12 x 64-bit)
	private ulong _s0, _s1, _s2, _s3, _s4, _s5;
	private ulong _s6, _s7, _s8, _s9, _s10, _s11;

	/// <inheritdoc/>
	public override int BlockSize => BlockSizeBytes;

	/// <inheritdoc/>
	public override int DigestSize => 16;

	/// <summary>
	/// Creates a new SpookyHash V2 hasher with zero seeds.
	/// </summary>
	public SpookyHash128() : this(0, 0) { }

	/// <summary>
	/// Creates a new SpookyHash V2 hasher with the specified seeds.
	/// </summary>
	/// <param name="seed1">First 64-bit seed.</param>
	/// <param name="seed2">Second 64-bit seed.</param>
	public SpookyHash128(ulong seed1, ulong seed2) {
		_seed1 = seed1;
		_seed2 = seed2;
		InitializeState();
	}

	private void InitializeState() {
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

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		// Read 12 x 64-bit words
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

		Mix(ref _s0, ref _s1, ref _s2, ref _s3, ref _s4, ref _s5,
			ref _s6, ref _s7, ref _s8, ref _s9, ref _s10, ref _s11,
			d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11);
	}

	/// <inheritdoc/>
	protected override UInt128 ComputeFinal(ReadOnlySpan<byte> remaining) {
		int length = (int)TotalBytesProcessed;

		// For short messages (< 192 bytes), use short hash
		if (length < BlockSizeBytes * 2) {
			return ShortHash(remaining, length);
		}

		// Handle remaining data
		Span<byte> lastBlock = stackalloc byte[BlockSizeBytes];
		lastBlock.Clear();

		if (remaining.Length > 0) {
			remaining.CopyTo(lastBlock);
		}

		// Put length in last byte
		lastBlock[BlockSizeBytes - 1] = (byte)(remaining.Length);

		// Process last partial block
		ProcessLastBlock(lastBlock);

		// End mixing
		EndPartial(ref _s0, ref _s1, ref _s2, ref _s3, ref _s4, ref _s5,
				   ref _s6, ref _s7, ref _s8, ref _s9, ref _s10, ref _s11);
		EndPartial(ref _s0, ref _s1, ref _s2, ref _s3, ref _s4, ref _s5,
				   ref _s6, ref _s7, ref _s8, ref _s9, ref _s10, ref _s11);
		EndPartial(ref _s0, ref _s1, ref _s2, ref _s3, ref _s4, ref _s5,
				   ref _s6, ref _s7, ref _s8, ref _s9, ref _s10, ref _s11);

		return new UInt128(_s1, _s0);
	}

	private void ProcessLastBlock(ReadOnlySpan<byte> block) {
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

		_s0 += d0; _s1 += d1; _s2 += d2; _s3 += d3;
		_s4 += d4; _s5 += d5; _s6 += d6; _s7 += d7;
		_s8 += d8; _s9 += d9; _s10 += d10; _s11 += d11;
	}

	/// <summary>
	/// Short hash for messages less than 192 bytes.
	/// </summary>
	private UInt128 ShortHash(ReadOnlySpan<byte> data, int totalLength) {
		ulong h0 = _seed1;
		ulong h1 = _seed2;
		ulong h2 = SC;
		ulong h3 = SC;

		// Pad to 32 bytes
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

			h2 += d0;
			h3 += d1;
			ShortMix(ref h0, ref h1, ref h2, ref h3);
			h0 += d2;
			h1 += d3;

			offset += 32;
			remaining -= 32;
		}

		// Handle tail
		if (remaining > 0) {
			data[offset..].CopyTo(buf);
		}

		// Add length
		h3 += (ulong)totalLength << 56;

		ulong t0 = BinaryPrimitives.ReadUInt64LittleEndian(buf);
		ulong t1 = BinaryPrimitives.ReadUInt64LittleEndian(buf[8..]);
		ulong t2 = BinaryPrimitives.ReadUInt64LittleEndian(buf[16..]);
		ulong t3 = BinaryPrimitives.ReadUInt64LittleEndian(buf[24..]);

		h2 += t0;
		h3 += t1;
		ShortMix(ref h0, ref h1, ref h2, ref h3);
		h0 += t2;
		h1 += t3;

		ShortEnd(ref h0, ref h1, ref h2, ref h3);

		return new UInt128(h1, h0);
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		InitializeState();
	}

	/// <summary>
	/// The main mixing function for long messages.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Mix(
		ref ulong s0, ref ulong s1, ref ulong s2, ref ulong s3,
		ref ulong s4, ref ulong s5, ref ulong s6, ref ulong s7,
		ref ulong s8, ref ulong s9, ref ulong s10, ref ulong s11,
		ulong d0, ulong d1, ulong d2, ulong d3,
		ulong d4, ulong d5, ulong d6, ulong d7,
		ulong d8, ulong d9, ulong d10, ulong d11) {
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
	/// End mixing partial.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EndPartial(
		ref ulong s0, ref ulong s1, ref ulong s2, ref ulong s3,
		ref ulong s4, ref ulong s5, ref ulong s6, ref ulong s7,
		ref ulong s8, ref ulong s9, ref ulong s10, ref ulong s11) {
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
	/// Short message mixing.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ShortMix(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3) {
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
	/// Short message finalization.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ShortEnd(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3) {
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

	/// <summary>
	/// Computes SpookyHash V2 128-bit hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed1">First 64-bit seed (default: 0).</param>
	/// <param name="seed2">Second 64-bit seed (default: 0).</param>
	/// <returns>The 128-bit hash value.</returns>
	public static UInt128 Hash(ReadOnlySpan<byte> data, ulong seed1 = 0, ulong seed2 = 0) {
		using var hasher = new SpookyHash128(seed1, seed2);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
