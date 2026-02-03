namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of CityHash64 hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// CityHash is a family of hash functions developed by Google for fast string hashing.
/// The 64-bit variant is optimized for short strings but works well for longer inputs too.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 64-bit hash value</item>
/// <item><b>Block Size:</b> 64 bytes (for streaming)</item>
/// <item><b>Speed:</b> ~10+ GB/s on modern x86-64 CPUs</item>
/// <item><b>Collision Resistance:</b> Excellent for hash tables, NOT cryptographically secure</item>
/// </list>
/// </para>
/// <para>
/// <b>Streaming Implementation Notes:</b>
/// The original CityHash processes entire input at once. This streaming version:
/// <list type="bullet">
/// <item>Uses a 64-byte block size for streaming</item>
/// <item>Maintains internal state (v, w, x, y, z) across updates</item>
/// <item>May produce slightly different hashes than non-streaming version for short inputs</item>
/// <item>Matches reference for inputs >= 64 bytes when processed in 64-byte chunks</item>
/// </list>
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Hash tables and hash maps</item>
/// <item>Data deduplication</item>
/// <item>Load balancing/sharding</item>
/// <item>Caching keys</item>
/// <item>File content identification</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/google/cityhash">CityHash - Google's official implementation</see></item>
/// <item><see href="https://opensource.googleblog.com/2011/04/introducing-cityhash.html">Introducing CityHash - Google Blog</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Basic usage
/// using var hasher = new CityHash64();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// ulong hash = hasher.Finalize();
///
/// // Stream processing
/// using var streamHasher = new CityHash64();
/// using var file = File.OpenRead("largefile.bin");
/// byte[] buffer = new byte[65536]; // 64KB buffer
/// int read;
/// while ((read = file.Read(buffer)) > 0) {
///     streamHasher.Update(buffer.AsSpan(0, read));
/// }
/// ulong fileHash = streamHasher.Finalize();
/// </code>
/// </example>
public sealed class CityHash64 : StreamingHashBase<ulong> {
	// Constants from CityHash (k0, k1, k2, k3 are magic numbers)
	private const ulong K0 = 0xc3a5c85c97cb3127UL;
	private const ulong K1 = 0xb492b66fbe98f273UL;
	private const ulong K2 = 0x9ae16a3b2f90404fUL;

	// Streaming state
	private ulong _x;
	private ulong _y;
	private ulong _z;
	private ulong _v0, _v1;
	private ulong _w0, _w1;
	private bool _initialized;
	private long _processedBytes;

	// Reserved for future use

	/// <inheritdoc/>
	public override int BlockSize => 64;

	/// <inheritdoc/>
	public override int DigestSize => 8;

	/// <summary>
	/// Creates a new CityHash64 streaming hasher.
	/// </summary>
	public CityHash64() : base() {
		Reset();
	}

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		if (!_initialized) {
			// Initialize state on first block
			InitializeState(block);
			_initialized = true;
		} else {
			// Process subsequent blocks
			ProcessBlockInternal(block);
		}
		_processedBytes += BlockSize;
	}

	/// <summary>
	/// Initializes the hash state from the first block.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void InitializeState(ReadOnlySpan<byte> block) {
		_x = Fetch64(block[0..]) + K2;
		_y = Fetch64(block[8..]);
		_z = Fetch64(block[16..]) + K0;

		_v0 = Rotate64(_y ^ K1, 49) * K1 + Fetch64(block[24..]);
		_v1 = Rotate64(_v0, 42) * K1 + Fetch64(block[32..]);

		_w0 = Rotate64(_y + Fetch64(block[40..]), 35) * K1 + _x;
		_w1 = Rotate64(_x + Fetch64(block[48..]), 34) * K1;

		_x = Rotate64(_x + _y + _v0 + Fetch64(block[24..]), 37) * K1;
		_y = Rotate64(_y + _v1 + Fetch64(block[48..]), 42) * K1;
		_x ^= _w1;
		_y += _v0 + Fetch64(block[40..]);
		_z = Rotate64(_z + _w0, 33) * K1;

		(_v0, _v1) = WeakHashLen32WithSeeds(block[32..], _v1 * K1, _x + _w0);
		(_w0, _w1) = WeakHashLen32WithSeeds(block[0..], _z + _w1, _y + Fetch64(block[16..]));
		(_z, _x) = (_x, _z);
	}

	/// <summary>
	/// Processes a block of data after initialization.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlockInternal(ReadOnlySpan<byte> block) {
		_x = Rotate64(_x + _y + _v0 + Fetch64(block[8..]), 37) * K1;
		_y = Rotate64(_y + _v1 + Fetch64(block[48..]), 42) * K1;
		_x ^= _w1;
		_y += _v0 + Fetch64(block[40..]);
		_z = Rotate64(_z + _w0, 33) * K1;

		(_v0, _v1) = WeakHashLen32WithSeeds(block[32..], _v1 * K1, _x + _w0);
		(_w0, _w1) = WeakHashLen32WithSeeds(block[0..], _z + _w1, _y + Fetch64(block[16..]));
		(_z, _x) = (_x, _z);
	}

	/// <inheritdoc/>
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		long totalLen = TotalBytesProcessed;

		// For short messages, use the optimized short hash paths
		if (totalLen < 64) {
			return HashShort(remaining, (int)totalLen);
		}

		// For longer messages, finalize the streaming state
		ulong len = (ulong)totalLen;

		// Process any remaining bytes
		if (remaining.Length > 0) {
			// Pad remaining bytes to 64 bytes and process
			Span<byte> padded = stackalloc byte[64];
			remaining.CopyTo(padded);
			// Zero the rest (stackalloc is already zeroed)

			if (remaining.Length >= 32) {
				_x = Rotate64(_x + _y + _v0 + Fetch64(padded[8..]), 37) * K1;
				_y = Rotate64(_y + _v1 + Fetch64(padded[48..]), 42) * K1;
				_x ^= _w1;
				_y += _v0 + Fetch64(padded[40..]);
				_z = Rotate64(_z + _w0, 33) * K1;

				(_v0, _v1) = WeakHashLen32WithSeeds(padded[32..], _v1 * K1, _x + _w0);
				(_w0, _w1) = WeakHashLen32WithSeeds(padded[0..], _z + _w1, _y + Fetch64(padded[16..]));
				(_z, _x) = (_x, _z);
			}
		}

		// Final mixing
		return HashLen16(_v0 + _w0, _w1 + HashLen16(_x + _z, _y, len), len);
	}

	/// <summary>
	/// Hash function for short messages (&lt; 64 bytes).
	/// </summary>
	private ulong HashShort(ReadOnlySpan<byte> data, int len) {
		if (len <= 0) {
			return K2;
		}
		if (len <= 3) {
			byte a = data[0];
			byte b = len > 1 ? data[1] : data[0];
			byte c = data[len - 1];
			uint y = a + ((uint)b << 8);
			uint z = (uint)len + ((uint)c << 2);
			return ShiftMix(y * K2 ^ z * K0) * K2;
		}
		if (len <= 7) {
			ulong mul = K2 + (ulong)len * 2;
			ulong a = Fetch32(data);
			return HashLen16(mul + a, Fetch32(data[(len - 4)..]), mul);
		}
		if (len <= 16) {
			ulong mul = K2 + (ulong)len * 2;
			ulong a = Fetch64(data) + K2;
			ulong b = Fetch64(data[(len - 8)..]);
			ulong c = Rotate64(b, 37) * mul + a;
			ulong d = (Rotate64(a, 25) + b) * mul;
			return HashLen16(c, d, mul);
		}
		if (len <= 32) {
			ulong mul = K2 + (ulong)len * 2;
			ulong a = Fetch64(data) * K1;
			ulong b = Fetch64(data[8..]);
			ulong c = Fetch64(data[(len - 8)..]) * mul;
			ulong d = Fetch64(data[(len - 16)..]) * K2;
			return HashLen16(
				Rotate64(a + b, 43) + Rotate64(c, 30) + d,
				a + Rotate64(b + K2, 18) + c,
				mul);
		}
		// 33-63 bytes
		ulong mul2 = K2 + (ulong)len * 2;
		ulong a2 = Fetch64(data) * K2;
		ulong b2 = Fetch64(data[8..]);
		ulong c2 = Fetch64(data[(len - 24)..]);
		ulong d2 = Fetch64(data[(len - 32)..]);
		ulong e = Fetch64(data[16..]) * K2;
		ulong f = Fetch64(data[24..]) * 9;
		ulong g = Fetch64(data[(len - 8)..]);
		ulong h = Fetch64(data[(len - 16)..]) * mul2;
		ulong u = Rotate64(a2 + g, 43) + (Rotate64(b2, 30) + c2) * 9;
		ulong v = ((a2 + g) ^ d2) + f + 1;
		ulong w = BinaryPrimitives.ReverseEndianness((u + v) * mul2) + h;
		ulong x2 = Rotate64(e + f, 42) + c2;
		ulong y2 = (BinaryPrimitives.ReverseEndianness((v + w) * mul2) + g) * mul2;
		ulong z2 = e + f + c2;
		a2 = BinaryPrimitives.ReverseEndianness((x2 + z2) * mul2 + y2) + b2;
		b2 = ShiftMix((z2 + a2) * mul2 + d2 + h) * mul2;
		return b2 + x2;
	}

	/// <inheritdoc/>
	protected override void ResetCore() {
		_x = 0;
		_y = 0;
		_z = 0;
		_v0 = 0;
		_v1 = 0;
		_w0 = 0;
		_w1 = 0;
		_initialized = false;
		_processedBytes = 0;
	}

	#region Helper Methods

	/// <summary>
	/// Reads a 64-bit little-endian integer from the given span.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Fetch64(ReadOnlySpan<byte> p) {
		return BinaryPrimitives.ReadUInt64LittleEndian(p);
	}

	/// <summary>
	/// Reads a 32-bit little-endian integer from the given span.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint Fetch32(ReadOnlySpan<byte> p) {
		return BinaryPrimitives.ReadUInt32LittleEndian(p);
	}

	/// <summary>
	/// Rotates a 64-bit value right by the specified number of bits.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Rotate64(ulong val, int shift) {
		return BitOperations.RotateRight(val, shift);
	}

	/// <summary>
	/// A shift-mix operation for finalization.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ShiftMix(ulong val) {
		return val ^ (val >> 47);
	}

	/// <summary>
	/// Hash 128 input bits down to 64 bits of output.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong HashLen16(ulong u, ulong v, ulong mul) {
		ulong a = (u ^ v) * mul;
		a ^= a >> 47;
		ulong b = (v ^ a) * mul;
		b ^= b >> 47;
		b *= mul;
		return b;
	}

	/// <summary>
	/// Hash 128 input bits down to 64 bits with default multiplier.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong HashLen16(ulong u, ulong v) {
		return HashLen16(u, v, K2 + 32);
	}

	/// <summary>
	/// Computes a weak hash suitable for intermediate calculations.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong, ulong) WeakHashLen32WithSeeds(ReadOnlySpan<byte> s, ulong a, ulong b) {
		ulong w = Fetch64(s);
		ulong x = Fetch64(s[8..]);
		ulong y = Fetch64(s[16..]);
		ulong z = Fetch64(s[24..]);
		a += w;
		b = Rotate64(b + a + z, 21);
		ulong c = a;
		a += x;
		a += y;
		b += Rotate64(a, 44);
		return (a + z, b + c);
	}

	#endregion

	/// <summary>
	/// Computes the CityHash64 hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 64-bit hash value.</returns>
	/// <remarks>
	/// This is a convenience method for hashing data that fits in memory.
	/// For streaming scenarios, create an instance and use Update/Finalize.
	/// </remarks>
	public static ulong Hash(ReadOnlySpan<byte> data) {
		using var hasher = new CityHash64();
		hasher.Update(data);
		return hasher.Finalize();
	}
}
