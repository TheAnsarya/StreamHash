namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of FarmHash64 algorithm.
/// </summary>
/// <remarks>
/// <para>
/// FarmHash is a successor to CityHash, also developed by Google. It provides improved
/// performance and quality while maintaining compatibility with CityHash for certain use cases.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 64-bit hash value</item>
/// <item><b>Block Size:</b> 64 bytes</item>
/// <item><b>Speed:</b> ~10-15 GB/s on modern x86-64 CPUs</item>
/// <item><b>Collision Resistance:</b> Excellent for hash tables, NOT cryptographically secure</item>
/// </list>
/// </para>
/// <para>
/// <b>Key Differences from CityHash:</b>
/// <list type="bullet">
/// <item>Better performance on certain CPUs</item>
/// <item>Improved hash quality for specific patterns</item>
/// <item>Platform-specific optimizations available</item>
/// </list>
/// </para>
/// <para>
/// <b>Streaming Implementation Notes:</b>
/// <list type="bullet">
/// <item>Uses 64-byte block processing</item>
/// <item>Maintains internal state similar to CityHash</item>
/// <item>Optimized for large input streams</item>
/// </list>
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Hash tables with better distribution</item>
/// <item>Data partitioning/sharding</item>
/// <item>Content fingerprinting</item>
/// <item>Caching and deduplication</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/google/farmhash">FarmHash - Google's official repository</see></item>
/// <item><see href="https://opensource.googleblog.com/2014/03/introducing-farmhash.html">Introducing FarmHash - Google Blog</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Basic usage
/// using var hasher = new FarmHash64();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// ulong hash = hasher.Finalize();
///
/// // Stream processing
/// using var streamHasher = new FarmHash64();
/// using var file = File.OpenRead("largefile.bin");
/// byte[] buffer = new byte[65536];
/// int read;
/// while ((read = file.Read(buffer)) > 0) {
///     streamHasher.Update(buffer.AsSpan(0, read));
/// }
/// ulong fileHash = streamHasher.Finalize();
/// </code>
/// </example>
public sealed class FarmHash64 : StreamingHashBase<ulong> {
	// FarmHash constants
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

	/// <inheritdoc/>
	public override int BlockSize => 64;

	/// <inheritdoc/>
	public override int DigestSize => 8;

	/// <summary>
	/// Creates a new FarmHash64 streaming hasher.
	/// </summary>
	public FarmHash64() : base() {
		Reset();
	}

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		if (!_initialized) {
			InitializeState(block);
			_initialized = true;
		} else {
			ProcessBlockInternal(block);
		}
		_processedBytes += BlockSize;
	}

	/// <summary>
	/// Initializes the hash state from the first block.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void InitializeState(ReadOnlySpan<byte> block) {
		ulong s0 = Fetch64(block);
		ulong s1 = Fetch64(block[8..]);
		ulong s2 = Fetch64(block[16..]);
		ulong s3 = Fetch64(block[24..]);
		ulong s4 = Fetch64(block[32..]);
		ulong s5 = Fetch64(block[40..]);
		ulong s6 = Fetch64(block[48..]);
		ulong s7 = Fetch64(block[56..]);

		_x = s0 + K2;
		_y = s1 * K1 + 113;
		_z = ShiftMix(_y * K2 + s2) * K2;

		_v0 = s0 + s4;
		_v1 = s1 + s5 + ShiftMix(s1);

		_w0 = s6 + K0;
		_w1 = s7 + ShiftMix(s6 + s7);

		_z += ShiftMix(_v0 + _w0) * K2;
		_x = Rotate64(_z + _x, 39) * K1;
		_y = Rotate64(_y, 33);
	}

	/// <summary>
	/// Processes a block of data after initialization.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlockInternal(ReadOnlySpan<byte> block) {
		ulong s0 = Fetch64(block);
		ulong s1 = Fetch64(block[8..]);
		ulong s2 = Fetch64(block[16..]);
		ulong s3 = Fetch64(block[24..]);
		ulong s4 = Fetch64(block[32..]);
		ulong s5 = Fetch64(block[40..]);
		ulong s6 = Fetch64(block[48..]);
		ulong s7 = Fetch64(block[56..]);

		_x = Rotate64(_x + _y + _v0 + s1, 37) * K1;
		_y = Rotate64(_y + _v1 + s6, 42) * K1;
		_x ^= _w1;
		_y += _v0 + s5;
		_z = Rotate64(_z + _w0, 33) * K1;

		(_v0, _v1) = WeakHashLen32WithSeeds(s4, s5, s6, s7, _v1 * K1, _x + _w0);
		(_w0, _w1) = WeakHashLen32WithSeeds(s0, s1, s2, s3, _z + _w1, _y + s2);
		(_z, _x) = (_x, _z);
	}

	/// <inheritdoc/>
	protected override ulong ComputeFinal(ReadOnlySpan<byte> remaining) {
		long totalLen = TotalBytesProcessed;

		// For short messages, use optimized paths
		if (totalLen < 64) {
			return HashShort(remaining, (int)totalLen);
		}

		// Process any remaining bytes
		if (remaining.Length > 0) {
			Span<byte> padded = stackalloc byte[64];
			remaining.CopyTo(padded);

			ulong s0 = Fetch64(padded);
			ulong s1 = Fetch64(padded[8..]);
			ulong s2 = Fetch64(padded[16..]);
			ulong s3 = Fetch64(padded[24..]);

			_x += s0;
			_y += s1;
			_z += s2;
			_v0 += s3;
		}

		// Final mixing
		ulong len = (ulong)totalLen;
		return HashLen16(_v0 + _w0, _w1 + HashLen16(_x + _z, _y, len), len);
	}

	/// <summary>
	/// Hash function for short messages (&lt; 64 bytes).
	/// </summary>
	private static ulong HashShort(ReadOnlySpan<byte> data, int len) {
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Fetch64(ReadOnlySpan<byte> p) {
		return BinaryPrimitives.ReadUInt64LittleEndian(p);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint Fetch32(ReadOnlySpan<byte> p) {
		return BinaryPrimitives.ReadUInt32LittleEndian(p);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Rotate64(ulong val, int shift) {
		return BitOperations.RotateRight(val, shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ShiftMix(ulong val) {
		return val ^ (val >> 47);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong HashLen16(ulong u, ulong v, ulong mul) {
		ulong a = (u ^ v) * mul;
		a ^= a >> 47;
		ulong b = (v ^ a) * mul;
		b ^= b >> 47;
		b *= mul;
		return b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong, ulong) WeakHashLen32WithSeeds(
		ulong s0, ulong s1, ulong s2, ulong s3, ulong a, ulong b) {
		a += s0;
		b = Rotate64(b + a + s3, 21);
		ulong c = a;
		a += s1;
		a += s2;
		b += Rotate64(a, 44);
		return (a + s3, b + c);
	}

	#endregion

	/// <summary>
	/// Computes the FarmHash64 hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong Hash(ReadOnlySpan<byte> data) {
		using var hasher = new FarmHash64();
		hasher.Update(data);
		return hasher.Finalize();
	}
}
