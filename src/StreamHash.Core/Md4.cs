using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the MD4 message-digest algorithm.
/// </summary>
/// <remarks>
/// <para>
/// MD4 is a 128-bit cryptographic hash function designed by Ronald Rivest in 1990.
/// It is the predecessor to MD5 and uses three rounds of 16 operations each with
/// different boolean functions. MD4 processes data in 64-byte (512-bit) blocks
/// using little-endian 32-bit words.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 128 bits (16 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Structure:</b> Merkle-Damgård construction</item>
/// <item><b>Rounds:</b> 3 rounds × 16 steps = 48 operations per block</item>
/// <item><b>Word Size:</b> 32-bit words, little-endian</item>
/// <item><b>Security:</b> Cryptographically broken; use only for legacy compatibility</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://datatracker.ietf.org/doc/html/rfc1320">RFC 1320 - The MD4 Message-Digest Algorithm</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeMd4Digest : IStreamingHashBytes {
	private const int BlockSizeValue = 64;
	private const int DigestSizeValue = 16;

	// MD4 initial hash values (same as MD5)
	private const uint Iv0 = 0x67452301;
	private const uint Iv1 = 0xefcdab89;
	private const uint Iv2 = 0x98badcfe;
	private const uint Iv3 = 0x10325476;

	// Round 2 constant: sqrt(2) × 2^30
	private const uint C2 = 0x5a827999;
	// Round 3 constant: sqrt(3) × 2^30
	private const uint C3 = 0x6ed9eba1;

	private uint _h0, _h1, _h2, _h3;
	private readonly byte[] _buffer = new byte[BlockSizeValue];
	private int _bufferOffset;
	private long _totalBytes;

	/// <summary>
	/// Creates a new MD4 streaming hash instance.
	/// </summary>
	public NativeMd4Digest() {
		Reset();
	}

	/// <inheritdoc/>
	public int BlockSize => BlockSizeValue;

	/// <inheritdoc/>
	public int DigestSize => DigestSizeValue;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		_totalBytes += data.Length;
		int offset = 0;

		if (_bufferOffset > 0) {
			int toCopy = Math.Min(BlockSizeValue - _bufferOffset, data.Length);
			data.Slice(0, toCopy).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += toCopy;
			offset += toCopy;

			if (_bufferOffset == BlockSizeValue) {
				ProcessBlock(_buffer);
				_bufferOffset = 0;
			}
		}

		while (offset + BlockSizeValue <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockSizeValue));
			offset += BlockSizeValue;
		}

		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += data.Length - offset;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		long bitLength = _totalBytes * 8;

		// Padding: message must be congruent to 56 mod 64
		int paddingLength = 56 - (int)(_totalBytes % 64);
		if (paddingLength <= 0) paddingLength += 64;

		Span<byte> padding = stackalloc byte[paddingLength + 8];
		padding[0] = 0x80;
		padding.Slice(1, paddingLength - 1).Clear();

		// 64-bit length in little-endian
		BinaryPrimitives.WriteUInt64LittleEndian(padding.Slice(paddingLength), (ulong)bitLength);

		int paddingOffset = 0;
		while (paddingOffset < padding.Length) {
			int toCopy = Math.Min(BlockSizeValue - _bufferOffset, padding.Length - paddingOffset);
			padding.Slice(paddingOffset, toCopy).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += toCopy;
			paddingOffset += toCopy;

			if (_bufferOffset == BlockSizeValue) {
				ProcessBlock(_buffer);
				_bufferOffset = 0;
			}
		}

		byte[] result = new byte[DigestSizeValue];
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(0), _h0);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), _h1);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), _h2);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12), _h3);
		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		_h0 = Iv0; _h1 = Iv1; _h2 = Iv2; _h3 = Iv3;
		_bufferOffset = 0;
		_totalBytes = 0;
		Array.Clear(_buffer);
	}

	/// <inheritdoc/>
	public void Dispose() {
		Array.Clear(_buffer);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		Span<uint> x = stackalloc uint[16];
		for (int i = 0; i < 16; i++) {
			x[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(i * 4));
		}

		uint a = _h0, b = _h1, c = _h2, d = _h3;

		// Round 1: F(b, c, d) = (b & c) | (~b & d)
		a = RotateLeft(a + F(b, c, d) + x[0], 3);
		d = RotateLeft(d + F(a, b, c) + x[1], 7);
		c = RotateLeft(c + F(d, a, b) + x[2], 11);
		b = RotateLeft(b + F(c, d, a) + x[3], 19);
		a = RotateLeft(a + F(b, c, d) + x[4], 3);
		d = RotateLeft(d + F(a, b, c) + x[5], 7);
		c = RotateLeft(c + F(d, a, b) + x[6], 11);
		b = RotateLeft(b + F(c, d, a) + x[7], 19);
		a = RotateLeft(a + F(b, c, d) + x[8], 3);
		d = RotateLeft(d + F(a, b, c) + x[9], 7);
		c = RotateLeft(c + F(d, a, b) + x[10], 11);
		b = RotateLeft(b + F(c, d, a) + x[11], 19);
		a = RotateLeft(a + F(b, c, d) + x[12], 3);
		d = RotateLeft(d + F(a, b, c) + x[13], 7);
		c = RotateLeft(c + F(d, a, b) + x[14], 11);
		b = RotateLeft(b + F(c, d, a) + x[15], 19);

		// Round 2: G(b, c, d) = (b & c) | (b & d) | (c & d)
		a = RotateLeft(a + G(b, c, d) + x[0] + C2, 3);
		d = RotateLeft(d + G(a, b, c) + x[4] + C2, 5);
		c = RotateLeft(c + G(d, a, b) + x[8] + C2, 9);
		b = RotateLeft(b + G(c, d, a) + x[12] + C2, 13);
		a = RotateLeft(a + G(b, c, d) + x[1] + C2, 3);
		d = RotateLeft(d + G(a, b, c) + x[5] + C2, 5);
		c = RotateLeft(c + G(d, a, b) + x[9] + C2, 9);
		b = RotateLeft(b + G(c, d, a) + x[13] + C2, 13);
		a = RotateLeft(a + G(b, c, d) + x[2] + C2, 3);
		d = RotateLeft(d + G(a, b, c) + x[6] + C2, 5);
		c = RotateLeft(c + G(d, a, b) + x[10] + C2, 9);
		b = RotateLeft(b + G(c, d, a) + x[14] + C2, 13);
		a = RotateLeft(a + G(b, c, d) + x[3] + C2, 3);
		d = RotateLeft(d + G(a, b, c) + x[7] + C2, 5);
		c = RotateLeft(c + G(d, a, b) + x[11] + C2, 9);
		b = RotateLeft(b + G(c, d, a) + x[15] + C2, 13);

		// Round 3: H(b, c, d) = b ^ c ^ d
		a = RotateLeft(a + H(b, c, d) + x[0] + C3, 3);
		d = RotateLeft(d + H(a, b, c) + x[8] + C3, 9);
		c = RotateLeft(c + H(d, a, b) + x[4] + C3, 11);
		b = RotateLeft(b + H(c, d, a) + x[12] + C3, 15);
		a = RotateLeft(a + H(b, c, d) + x[2] + C3, 3);
		d = RotateLeft(d + H(a, b, c) + x[10] + C3, 9);
		c = RotateLeft(c + H(d, a, b) + x[6] + C3, 11);
		b = RotateLeft(b + H(c, d, a) + x[14] + C3, 15);
		a = RotateLeft(a + H(b, c, d) + x[1] + C3, 3);
		d = RotateLeft(d + H(a, b, c) + x[9] + C3, 9);
		c = RotateLeft(c + H(d, a, b) + x[5] + C3, 11);
		b = RotateLeft(b + H(c, d, a) + x[13] + C3, 15);
		a = RotateLeft(a + H(b, c, d) + x[3] + C3, 3);
		d = RotateLeft(d + H(a, b, c) + x[11] + C3, 9);
		c = RotateLeft(c + H(d, a, b) + x[7] + C3, 11);
		b = RotateLeft(b + H(c, d, a) + x[15] + C3, 15);

		_h0 += a; _h1 += b; _h2 += c; _h3 += d;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint H(uint x, uint y, uint z) => x ^ y ^ z;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RotateLeft(uint x, int n) => (x << n) | (x >> (32 - n));
}

/// <summary>
/// Factory methods for creating native MD4 streaming hash instances.
/// </summary>
internal static class Md4Factory {
	/// <summary>
	/// Creates an MD4 streaming hash instance.
	/// </summary>
	/// <returns>A new MD4 streaming hash.</returns>
	public static IStreamingHashBytes CreateMd4() => new NativeMd4Digest();

	/// <summary>
	/// Computes MD4 hash in one shot with minimal allocations.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 16-byte MD4 hash.</returns>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeMd4(ReadOnlySpan<byte> data) {
		using var hasher = new NativeMd4Digest();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}
}
