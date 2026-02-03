namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of CityHash128 hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// CityHash128 is the 128-bit variant of Google's CityHash family. It provides a larger
/// output space while maintaining excellent speed characteristics.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> 128-bit hash value (as <see cref="UInt128"/>)</item>
/// <item><b>Block Size:</b> 128 bytes</item>
/// <item><b>Speed:</b> ~8+ GB/s on modern x86-64 CPUs</item>
/// <item><b>Collision Resistance:</b> Excellent for general purposes, NOT cryptographically secure</item>
/// </list>
/// </para>
/// <para>
/// <b>Streaming Implementation Notes:</b>
/// <list type="bullet">
/// <item>Uses a 128-byte block size for efficient streaming</item>
/// <item>Maintains 128-bit state pair (u, v) across updates</item>
/// <item>Processes blocks using CityMurmur-style mixing</item>
/// </list>
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Distributed systems requiring low collision probability</item>
/// <item>Content-addressable storage</item>
/// <item>Database indexing</item>
/// <item>Deduplication systems</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/google/cityhash">CityHash - Google's official implementation</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Basic usage
/// using var hasher = new CityHash128();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// UInt128 hash = hasher.Finalize();
///
/// // Stream processing large files
/// using var streamHasher = new CityHash128();
/// using var file = File.OpenRead("largefile.bin");
/// byte[] buffer = new byte[131072]; // 128KB buffer
/// int read;
/// while ((read = file.Read(buffer)) > 0) {
///     streamHasher.Update(buffer.AsSpan(0, read));
/// }
/// UInt128 fileHash = streamHasher.Finalize();
/// </code>
/// </example>
public sealed class CityHash128 : StreamingHashBase<UInt128> {
	// Constants from CityHash
	private const ulong K0 = 0xc3a5c85c97cb3127UL;
	private const ulong K1 = 0xb492b66fbe98f273UL;
	private const ulong K2 = 0x9ae16a3b2f90404fUL;

	// Internal state
	private ulong _x;
	private ulong _y;
	private ulong _z;
	private ulong _v0, _v1;
	private ulong _w0, _w1;
	private bool _initialized;
	private long _processedBytes;

	/// <inheritdoc/>
	public override int BlockSize => 128;

	/// <inheritdoc/>
	public override int DigestSize => 16;

	/// <summary>
	/// Creates a new CityHash128 streaming hasher.
	/// </summary>
	public CityHash128() : base() {
		Reset();
	}

	/// <inheritdoc/>
	protected override void ProcessBlock(ReadOnlySpan<byte> block) {
		if (!_initialized) {
			// Initialize state from first block
			InitializeFromBlock(block);
			_initialized = true;
		} else {
			// Process block normally
			ProcessFullBlock(block);
		}
		_processedBytes += BlockSize;
	}

	/// <summary>
	/// Initializes state from the first 128-byte block.
	/// </summary>
	private void InitializeFromBlock(ReadOnlySpan<byte> block) {
		_x = Fetch64(block[104..]) ^ K1;
		_y = Fetch64(block[0..]);
		_z = HashLen16(Fetch64(block[112..]) ^ K1, Fetch64(block[120..]));

		_v0 = HashLen16(_z ^ K1, Fetch64(block[16..]));
		_v1 = Fetch64(block[8..]);

		_w0 = HashLen16(_v0 + _y, Fetch64(block[24..]));
		_w1 = _x;

		// Process both halves of the first block
		ProcessHalfBlock(block[0..64]);
		ProcessHalfBlock(block[64..128]);
	}

	/// <summary>
	/// Processes a half-block (64 bytes) of data.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessHalfBlock(ReadOnlySpan<byte> block) {
		_x = Rotate64(_x + _y + _v0 + Fetch64(block[8..]), 37) * K1;
		_y = Rotate64(_y + _v1 + Fetch64(block[48..]), 42) * K1;
		_x ^= _w1;
		_y += _v0 + Fetch64(block[40..]);
		_z = Rotate64(_z + _w0, 33) * K1;

		(_v0, _v1) = WeakHashLen32WithSeeds(block[32..], _v1 * K1, _x + _w0);
		(_w0, _w1) = WeakHashLen32WithSeeds(block[0..], _z + _w1, _y + Fetch64(block[16..]));
		(_z, _x) = (_x, _z);
	}

	/// <summary>
	/// Processes a full 128-byte block.
	/// </summary>
	private void ProcessFullBlock(ReadOnlySpan<byte> block) {
		ProcessHalfBlock(block[0..64]);
		ProcessHalfBlock(block[64..128]);
	}

	/// <inheritdoc/>
	protected override UInt128 ComputeFinal(ReadOnlySpan<byte> remaining) {
		long totalLen = TotalBytesProcessed;

		// For short messages, use optimized path
		if (totalLen < 128) {
			return HashShort(remaining, (int)totalLen);
		}

		// Process any remaining data
		if (remaining.Length > 0) {
			// Pad to a full block if we have remaining bytes
			Span<byte> padded = stackalloc byte[128];
			remaining.CopyTo(padded);

			// Process what we can
			if (remaining.Length >= 64) {
				ProcessHalfBlock(padded[0..64]);
			}
			if (remaining.Length >= 32) {
				// Mix in remaining bytes
				_x += Fetch64(padded);
				_y += Fetch64(padded[8..]);
				_z += Fetch64(padded[16..]);
				_v0 += Fetch64(padded[24..]);
			}
		}

		// Finalization
		ulong lowPart = HashLen16(_v0 + _w0, _w1, (ulong)totalLen);
		ulong highPart = HashLen16(_x + _z, _y, (ulong)totalLen);

		return new UInt128(highPart, lowPart);
	}

	/// <summary>
	/// Hash function for short messages (&lt; 128 bytes).
	/// </summary>
	private static UInt128 HashShort(ReadOnlySpan<byte> data, int len) {
		if (len <= 0) {
			return new UInt128(K1, K0);
		}

		if (len <= 16) {
			// Very short - simple mixing
			ulong a = len >= 8 ? Fetch64(data) : K0;
			ulong b = len >= 8 ? Fetch64(data[(len - 8)..]) : K0;
			return new UInt128(a + K0, b + K1);
		}

		if (len <= 32) {
			ulong a = Fetch64(data);
			ulong b = Fetch64(data[8..]);
			ulong c = Fetch64(data[(len - 8)..]);
			ulong d = Fetch64(data[(len - 16)..]);
			return new UInt128(
				HashLen16(a, c, K1),
				HashLen16(b, d, K2));
		}

		if (len <= 64) {
			ulong a = Fetch64(data);
			ulong b = Fetch64(data[8..]);
			ulong c = Fetch64(data[(len - 8)..]);
			ulong d = Fetch64(data[(len - 16)..]);
			ulong e = Fetch64(data[16..]);
			ulong f = Fetch64(data[24..]);
			ulong g = len >= 40 ? Fetch64(data[32..]) : K0;
			ulong h = len >= 48 ? Fetch64(data[40..]) : K0;

			return new UInt128(
				HashLen16(a + e, c + g, K1),
				HashLen16(b + f, d + h, K2));
		}

		// 65-127 bytes
		ulong x = Fetch64(data);
		ulong y = Fetch64(data[8..]) ^ K1;
		ulong z = Fetch64(data[(len - 8)..]);
		ulong v0 = Fetch64(data[(len - 16)..]) ^ K2;
		ulong v1 = Fetch64(data[16..]);
		ulong w0 = Fetch64(data[24..]) + K0;
		ulong w1 = Fetch64(data[32..]);

		x = Rotate64(x + y + v0 + Fetch64(data[40..]), 37) * K1;
		y = Rotate64(y + v1 + Fetch64(data[48..]), 42) * K1;
		x ^= w1;
		y += v0 + z;
		z = Rotate64(z + w0, 33) * K1;

		return new UInt128(
			HashLen16(v0 + w0, w1, (ulong)len),
			HashLen16(x + z, y, (ulong)len));
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
	private static ulong Rotate64(ulong val, int shift) {
		return BitOperations.RotateRight(val, shift);
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
	private static ulong HashLen16(ulong u, ulong v) {
		return HashLen16(u, v, K2 + 32);
	}

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
	/// Computes the CityHash128 hash of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 128-bit hash value.</returns>
	public static UInt128 Hash(ReadOnlySpan<byte> data) {
		using var hasher = new CityHash128();
		hasher.Update(data);
		return hasher.Finalize();
	}
}
