using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the SHA-0 message digest algorithm.
/// </summary>
/// <remarks>
/// <para>
/// SHA-0 (also known as SHA) was the original Secure Hash Algorithm published by NIST
/// in 1993 as FIPS PUB 180. It was withdrawn in 1995 and replaced by SHA-1 (FIPS 180-1),
/// which added a single left-rotation operation in the message schedule expansion.
/// This seemingly minor change significantly improved the algorithm's resistance to
/// differential cryptanalysis.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 160 bits (20 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Structure:</b> Merkle-Damgård construction</item>
/// <item><b>Rounds:</b> 80 compression rounds per block</item>
/// <item><b>Word Size:</b> 32-bit words, big-endian</item>
/// <item><b>Security:</b> Cryptographically broken; use only for legacy compatibility</item>
/// </list>
/// </para>
/// <para>
/// <b>Key Difference from SHA-1:</b>
/// In SHA-1, the message schedule expansion uses:
/// <c>w[i] = RotateLeft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)</c>
/// In SHA-0, the rotation is omitted:
/// <c>w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]</c>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://csrc.nist.gov/pubs/fips/180/final">FIPS PUB 180 (original SHA)</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeSha0Digest : IStreamingHashBytes {
	private const int BlockSizeValue = 64;
	private const int DigestSizeValue = 20;

	// Same initial hash values as SHA-1
	private const uint Iv0 = 0x67452301;
	private const uint Iv1 = 0xefcdab89;
	private const uint Iv2 = 0x98badcfe;
	private const uint Iv3 = 0x10325476;
	private const uint Iv4 = 0xc3d2e1f0;

	// Round constants (same as SHA-1)
	private const uint K0 = 0x5a827999; // Rounds  0-19
	private const uint K1 = 0x6ed9eba1; // Rounds 20-39
	private const uint K2 = 0x8f1bbcdc; // Rounds 40-59
	private const uint K3 = 0xca62c1d6; // Rounds 60-79

	private uint _h0, _h1, _h2, _h3, _h4;
	private readonly byte[] _buffer = new byte[BlockSizeValue];
	private int _bufferOffset;
	private long _totalBytes;

	/// <summary>
	/// Creates a new SHA-0 streaming hash instance.
	/// </summary>
	public NativeSha0Digest() {
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

		int paddingLength = 56 - (int)(_totalBytes % 64);
		if (paddingLength <= 0) paddingLength += 64;

		Span<byte> padding = stackalloc byte[paddingLength + 8];
		padding[0] = 0x80;
		padding.Slice(1, paddingLength - 1).Clear();

		// 64-bit length in big-endian
		BinaryPrimitives.WriteUInt64BigEndian(padding.Slice(paddingLength), (ulong)bitLength);

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
		BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(0), _h0);
		BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), _h1);
		BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), _h2);
		BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12), _h3);
		BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(16), _h4);
		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		_h0 = Iv0; _h1 = Iv1; _h2 = Iv2; _h3 = Iv3; _h4 = Iv4;
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
		Span<uint> w = stackalloc uint[80];

		// Load 16 message words (big-endian)
		for (int i = 0; i < 16; i++) {
			w[i] = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i * 4));
		}

		// Message schedule expansion — NO rotation (this is the key difference from SHA-1)
		for (int i = 16; i < 80; i++) {
			w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
		}

		uint a = _h0, b = _h1, c = _h2, d = _h3, e = _h4;

		// 80 rounds, same structure as SHA-1
		for (int i = 0; i < 80; i++) {
			uint f, k;
			if (i < 20) {
				f = (b & c) | (~b & d);
				k = K0;
			} else if (i < 40) {
				f = b ^ c ^ d;
				k = K1;
			} else if (i < 60) {
				f = (b & c) | (b & d) | (c & d);
				k = K2;
			} else {
				f = b ^ c ^ d;
				k = K3;
			}

			uint temp = RotateLeft(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = RotateLeft(b, 30);
			b = a;
			a = temp;
		}

		_h0 += a; _h1 += b; _h2 += c; _h3 += d; _h4 += e;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RotateLeft(uint x, int n) => (x << n) | (x >> (32 - n));
}

/// <summary>
/// Factory methods for creating native SHA-0 streaming hash instances.
/// </summary>
internal static class Sha0Factory {
	/// <summary>
	/// Creates a SHA-0 streaming hash instance.
	/// </summary>
	/// <returns>A new SHA-0 streaming hash.</returns>
	public static IStreamingHashBytes CreateSha0() => new NativeSha0Digest();

	/// <summary>
	/// Computes SHA-0 hash in one shot with minimal allocations.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 20-byte SHA-0 hash.</returns>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeSha0(ReadOnlySpan<byte> data) {
		using var hasher = new NativeSha0Digest();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}
}
