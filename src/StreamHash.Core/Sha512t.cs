using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace StreamHash.Core;

/// <summary>
/// Native implementation of SHA-512/224 and SHA-512/256 hash algorithms.
/// </summary>
/// <remarks>
/// <para>
/// SHA-512/t is a family of hash functions defined in FIPS 180-4 that truncate
/// SHA-512 output to t bits. The key difference from simple truncation is that
/// each variant uses a different initialization vector (IV) derived from
/// SHA-512("SHA-512/t").
/// </para>
/// <para>
/// This implementation uses .NET's IncrementalHash for the core SHA-512
/// computation, with custom IV generation per the FIPS 180-4 specification.
/// </para>
/// </remarks>
internal sealed class NativeSha512tDigest : IStreamingHashBytes {
	private readonly int _digestSize;
	private readonly byte[] _buffer;
	private int _bufferOffset;
	private long _totalBytes;

	// SHA-512 state (8 x 64-bit words)
	private ulong _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7;

	// Original IV values for reset
	private readonly ulong _iv0, _iv1, _iv2, _iv3, _iv4, _iv5, _iv6, _iv7;

	private const int BlockSizeValue = 128; // SHA-512 block size

	// SHA-512 round constants
	private static readonly ulong[] K = [
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	];

	/// <summary>
	/// Creates a new SHA-512/t digest with the specified output size.
	/// </summary>
	/// <param name="t">The output size in bits (must be 224 or 256).</param>
	/// <exception cref="ArgumentException">Thrown when t is not 224 or 256.</exception>
	public NativeSha512tDigest(int t) {
		if (t != 224 && t != 256) {
			throw new ArgumentException("SHA-512/t only supports t=224 or t=256", nameof(t));
		}

		_digestSize = t / 8;
		_buffer = new byte[BlockSize];

		// Generate IV using FIPS 180-4 algorithm:
		// IV = SHA-512(SHA-512-IV XOR 0xa5a5...a5a5 || "SHA-512/t")
		GenerateIV(t, out _iv0, out _iv1, out _iv2, out _iv3, out _iv4, out _iv5, out _iv6, out _iv7);

		_h0 = _iv0; _h1 = _iv1; _h2 = _iv2; _h3 = _iv3;
		_h4 = _iv4; _h5 = _iv5; _h6 = _iv6; _h7 = _iv7;
	}

	/// <inheritdoc/>
	public int BlockSize => BlockSizeValue;

	/// <inheritdoc/>
	public int DigestSize => _digestSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		_totalBytes += data.Length;
		int offset = 0;

		// Fill buffer first
		if (_bufferOffset > 0) {
			int toCopy = Math.Min(BlockSize - _bufferOffset, data.Length);
			data.Slice(0, toCopy).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += toCopy;
			offset += toCopy;

			if (_bufferOffset == BlockSize) {
				ProcessBlock(_buffer);
				_bufferOffset = 0;
			}
		}

		// Process complete blocks
		while (offset + BlockSize <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockSize));
			offset += BlockSize;
		}

		// Buffer remaining
		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += data.Length - offset;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		// Padding: append 1 bit, then zeros, then 128-bit length
		long bitLength = _totalBytes * 8;

		// Calculate padding needed (message must be congruent to 112 mod 128)
		int paddingLength = 112 - (int)(_totalBytes % 128);
		if (paddingLength <= 0) paddingLength += 128;

		Span<byte> padding = stackalloc byte[paddingLength + 16];
		padding[0] = 0x80;
		padding.Slice(1, paddingLength - 1).Clear();

		// 128-bit length (big-endian, high 64 bits first which are 0)
		padding[paddingLength] = 0;
		padding[paddingLength + 1] = 0;
		padding[paddingLength + 2] = 0;
		padding[paddingLength + 3] = 0;
		padding[paddingLength + 4] = 0;
		padding[paddingLength + 5] = 0;
		padding[paddingLength + 6] = 0;
		padding[paddingLength + 7] = 0;

		// Low 64 bits of length
		BinaryPrimitives.WriteUInt64BigEndian(padding.Slice(paddingLength + 8), (ulong)bitLength);

		// Don't count padding in _totalBytes since we're finalizing
		int savedTotalOffset = _bufferOffset;
		int paddingOffset = 0;
		while (paddingOffset < padding.Length) {
			int toCopy = Math.Min(BlockSize - _bufferOffset, padding.Length - paddingOffset);
			padding.Slice(paddingOffset, toCopy).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += toCopy;
			paddingOffset += toCopy;

			if (_bufferOffset == BlockSize) {
				ProcessBlock(_buffer);
				_bufferOffset = 0;
			}
		}

		// Output truncated hash
		byte[] result = new byte[_digestSize];
		Span<byte> fullHash = stackalloc byte[64];
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(0), _h0);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(8), _h1);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(16), _h2);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(24), _h3);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(32), _h4);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(40), _h5);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(48), _h6);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(56), _h7);

		fullHash.Slice(0, _digestSize).CopyTo(result);
		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		_h0 = _iv0; _h1 = _iv1; _h2 = _iv2; _h3 = _iv3;
		_h4 = _iv4; _h5 = _iv5; _h6 = _iv6; _h7 = _iv7;
		_bufferOffset = 0;
		_totalBytes = 0;
		Array.Clear(_buffer);
	}

	/// <inheritdoc/>
	public void Dispose() {
		Array.Clear(_buffer);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		Span<ulong> w = stackalloc ulong[80];

		// Load message words
		for (int i = 0; i < 16; i++) {
			w[i] = BinaryPrimitives.ReadUInt64BigEndian(block.Slice(i * 8));
		}

		// Expand message schedule — cache repeated reads to reduce indexing
		for (int i = 16; i < 80; i++) {
			ulong w15 = w[i - 15];
			ulong w2 = w[i - 2];
			ulong s0 = BitOperations.RotateRight(w15, 1) ^ BitOperations.RotateRight(w15, 8) ^ (w15 >> 7);
			ulong s1 = BitOperations.RotateRight(w2, 19) ^ BitOperations.RotateRight(w2, 61) ^ (w2 >> 6);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		ulong a = _h0, b = _h1, c = _h2, d = _h3;
		ulong e = _h4, f = _h5, g = _h6, h = _h7;

		// 8x unrolled compression — eliminates per-round variable shuffling (6 moves/round * 80 = 480 moves saved)
		// Each round writes to a different variable position, so after 8 rounds we're back to the original layout.
		for (int i = 0; i < 80; i += 8) {
			h += BitOperations.RotateRight(e, 14) ^ BitOperations.RotateRight(e, 18) ^ BitOperations.RotateRight(e, 41);
			h += (e & f) ^ (~e & g);
			h += K[i] + w[i];
			d += h;
			h += BitOperations.RotateRight(a, 28) ^ BitOperations.RotateRight(a, 34) ^ BitOperations.RotateRight(a, 39);
			h += (a & b) ^ (a & c) ^ (b & c);

			g += BitOperations.RotateRight(d, 14) ^ BitOperations.RotateRight(d, 18) ^ BitOperations.RotateRight(d, 41);
			g += (d & e) ^ (~d & f);
			g += K[i + 1] + w[i + 1];
			c += g;
			g += BitOperations.RotateRight(h, 28) ^ BitOperations.RotateRight(h, 34) ^ BitOperations.RotateRight(h, 39);
			g += (h & a) ^ (h & b) ^ (a & b);

			f += BitOperations.RotateRight(c, 14) ^ BitOperations.RotateRight(c, 18) ^ BitOperations.RotateRight(c, 41);
			f += (c & d) ^ (~c & e);
			f += K[i + 2] + w[i + 2];
			b += f;
			f += BitOperations.RotateRight(g, 28) ^ BitOperations.RotateRight(g, 34) ^ BitOperations.RotateRight(g, 39);
			f += (g & h) ^ (g & a) ^ (h & a);

			e += BitOperations.RotateRight(b, 14) ^ BitOperations.RotateRight(b, 18) ^ BitOperations.RotateRight(b, 41);
			e += (b & c) ^ (~b & d);
			e += K[i + 3] + w[i + 3];
			a += e;
			e += BitOperations.RotateRight(f, 28) ^ BitOperations.RotateRight(f, 34) ^ BitOperations.RotateRight(f, 39);
			e += (f & g) ^ (f & h) ^ (g & h);

			d += BitOperations.RotateRight(a, 14) ^ BitOperations.RotateRight(a, 18) ^ BitOperations.RotateRight(a, 41);
			d += (a & b) ^ (~a & c);
			d += K[i + 4] + w[i + 4];
			h += d;
			d += BitOperations.RotateRight(e, 28) ^ BitOperations.RotateRight(e, 34) ^ BitOperations.RotateRight(e, 39);
			d += (e & f) ^ (e & g) ^ (f & g);

			c += BitOperations.RotateRight(h, 14) ^ BitOperations.RotateRight(h, 18) ^ BitOperations.RotateRight(h, 41);
			c += (h & a) ^ (~h & b);
			c += K[i + 5] + w[i + 5];
			g += c;
			c += BitOperations.RotateRight(d, 28) ^ BitOperations.RotateRight(d, 34) ^ BitOperations.RotateRight(d, 39);
			c += (d & e) ^ (d & f) ^ (e & f);

			b += BitOperations.RotateRight(g, 14) ^ BitOperations.RotateRight(g, 18) ^ BitOperations.RotateRight(g, 41);
			b += (g & h) ^ (~g & a);
			b += K[i + 6] + w[i + 6];
			f += b;
			b += BitOperations.RotateRight(c, 28) ^ BitOperations.RotateRight(c, 34) ^ BitOperations.RotateRight(c, 39);
			b += (c & d) ^ (c & e) ^ (d & e);

			a += BitOperations.RotateRight(f, 14) ^ BitOperations.RotateRight(f, 18) ^ BitOperations.RotateRight(f, 41);
			a += (f & g) ^ (~f & h);
			a += K[i + 7] + w[i + 7];
			e += a;
			a += BitOperations.RotateRight(b, 28) ^ BitOperations.RotateRight(b, 34) ^ BitOperations.RotateRight(b, 39);
			a += (b & c) ^ (b & d) ^ (c & d);
		}

		_h0 += a; _h1 += b; _h2 += c; _h3 += d;
		_h4 += e; _h5 += f; _h6 += g; _h7 += h;
	}

	/// <summary>
	/// Generates the initialization vector for SHA-512/t per FIPS 180-4.
	/// </summary>
	/// <remarks>
	/// The IV is computed as: SHA-512(IV' || "SHA-512/t")
	/// where IV' is the SHA-512 IV with each word XORed with 0xa5a5a5a5a5a5a5a5.
	/// </remarks>
	private static void GenerateIV(int t, out ulong h0, out ulong h1, out ulong h2, out ulong h3,
		out ulong h4, out ulong h5, out ulong h6, out ulong h7) {

		// Pre-computed IVs for common variants
		if (t == 224) {
			// SHA-512/224 IV (pre-computed per FIPS 180-4)
			h0 = 0x8c3d37c819544da2;
			h1 = 0x73e1996689dcd4d6;
			h2 = 0x1dfab7ae32ff9c82;
			h3 = 0x679dd514582f9fcf;
			h4 = 0x0f6d2b697bd44da8;
			h5 = 0x77e36f7304c48942;
			h6 = 0x3f9d85a86a1d36c8;
			h7 = 0x1112e6ad91d692a1;
		} else if (t == 256) {
			// SHA-512/256 IV (pre-computed per FIPS 180-4)
			h0 = 0x22312194fc2bf72c;
			h1 = 0x9f555fa3c84c64c2;
			h2 = 0x2393b86b6f53b151;
			h3 = 0x963877195940eabd;
			h4 = 0x96283ee2a88effe3;
			h5 = 0xbe5e1e2553863992;
			h6 = 0x2b0199fc2c85b8aa;
			h7 = 0x0eb72ddc81c52ca2;
		} else {
			throw new ArgumentException($"Unsupported t value: {t}", nameof(t));
		}
	}
}

/// <summary>
/// Factory methods for creating SHA-512/t streaming hash instances.
/// </summary>
internal static class Sha512tFactory {
	/// <summary>SHA-512 round constants as a constant data blob for zero-overhead access.</summary>
	private static ReadOnlySpan<ulong> K =>
	[
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	];

	/// <summary>
	/// Creates a SHA-512/224 streaming hash instance.
	/// </summary>
	/// <returns>A new SHA-512/224 streaming hash.</returns>
	public static IStreamingHashBytes CreateSha512_224() => new NativeSha512tDigest(224);

	/// <summary>
	/// Creates a SHA-512/256 streaming hash instance.
	/// </summary>
	/// <returns>A new SHA-512/256 streaming hash.</returns>
	public static IStreamingHashBytes CreateSha512_256() => new NativeSha512tDigest(256);

	/// <summary>
	/// Computes SHA-512/224 hash in one shot with minimal allocations.
	/// </summary>
	public static byte[] ComputeSha512_224(ReadOnlySpan<byte> data) {
		return ComputeSha512tStatic(data, 224);
	}

	/// <summary>
	/// Computes SHA-512/256 hash in one shot with minimal allocations.
	/// </summary>
	public static byte[] ComputeSha512_256(ReadOnlySpan<byte> data) {
		return ComputeSha512tStatic(data, 256);
	}

	/// <summary>
	/// Static optimized SHA-512/t computation using stack-allocated state.
	/// </summary>
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static byte[] ComputeSha512tStatic(ReadOnlySpan<byte> data, int t) {
		const int BlockSize = 128;
		int digestSize = t / 8;

		// Initialize state with pre-computed IVs
		ulong h0, h1, h2, h3, h4, h5, h6, h7;
		if (t == 224) {
			h0 = 0x8c3d37c819544da2; h1 = 0x73e1996689dcd4d6;
			h2 = 0x1dfab7ae32ff9c82; h3 = 0x679dd514582f9fcf;
			h4 = 0x0f6d2b697bd44da8; h5 = 0x77e36f7304c48942;
			h6 = 0x3f9d85a86a1d36c8; h7 = 0x1112e6ad91d692a1;
		} else {
			h0 = 0x22312194fc2bf72c; h1 = 0x9f555fa3c84c64c2;
			h2 = 0x2393b86b6f53b151; h3 = 0x963877195940eabd;
			h4 = 0x96283ee2a88effe3; h5 = 0xbe5e1e2553863992;
			h6 = 0x2b0199fc2c85b8aa; h7 = 0x0eb72ddc81c52ca2;
		}

		long totalBytes = data.Length;
		int offset = 0;

		// Process full blocks
		Span<ulong> w = stackalloc ulong[80];
		while (offset + BlockSize <= data.Length) {
			ProcessBlockStatic(data.Slice(offset, BlockSize), ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, w);
			offset += BlockSize;
		}

		// Padding
		Span<byte> padding = stackalloc byte[BlockSize * 2];
		padding.Clear();
		int remaining = data.Length - offset;
		if (remaining > 0) {
			data.Slice(offset).CopyTo(padding);
		}
		padding[remaining] = 0x80;

		int paddingLength = (remaining < 112) ? (BlockSize - remaining) : (BlockSize * 2 - remaining);
		int totalPaddingLen = remaining + paddingLength;
		BinaryPrimitives.WriteUInt64BigEndian(padding.Slice(totalPaddingLen - 8), (ulong)(totalBytes * 8));

		// Process padding blocks
		int paddingOffset = 0;
		while (paddingOffset < totalPaddingLen) {
			ProcessBlockStatic(padding.Slice(paddingOffset, BlockSize), ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, w);
			paddingOffset += BlockSize;
		}

		// Output truncated hash
		byte[] result = new byte[digestSize];
		Span<byte> fullHash = stackalloc byte[64];
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(0), h0);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(8), h1);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(16), h2);
		BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(24), h3);
		if (digestSize > 32) {
			BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(32), h4);
			BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(40), h5);
			BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(48), h6);
			BinaryPrimitives.WriteUInt64BigEndian(fullHash.Slice(56), h7);
		}
		fullHash.Slice(0, digestSize).CopyTo(result);
		return result;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void ProcessBlockStatic(ReadOnlySpan<byte> block,
		ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3,
		ref ulong h4, ref ulong h5, ref ulong h6, ref ulong h7,
		Span<ulong> w) {

		// Load message words — direct pointer arithmetic avoids per-word Slice bounds checks
		ref byte blockRef = ref MemoryMarshal.GetReference(block);
		for (int i = 0; i < 16; i++) {
			w[i] = BinaryPrimitives.ReverseEndianness(
				Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, i * 8)));
		}

		// Expand message schedule — cache repeated reads
		for (int i = 16; i < 80; i++) {
			ulong w15 = w[i - 15];
			ulong w2 = w[i - 2];
			ulong s0 = BitOperations.RotateRight(w15, 1) ^ BitOperations.RotateRight(w15, 8) ^ (w15 >> 7);
			ulong s1 = BitOperations.RotateRight(w2, 19) ^ BitOperations.RotateRight(w2, 61) ^ (w2 >> 6);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		ulong a = h0, b = h1, c = h2, d = h3;
		ulong e = h4, f = h5, g = h6, h = h7;

		// 8x unrolled compression — eliminates per-round variable shuffling
		for (int i = 0; i < 80; i += 8) {
			h += BitOperations.RotateRight(e, 14) ^ BitOperations.RotateRight(e, 18) ^ BitOperations.RotateRight(e, 41);
			h += (e & f) ^ (~e & g);
			h += K[i] + w[i];
			d += h;
			h += BitOperations.RotateRight(a, 28) ^ BitOperations.RotateRight(a, 34) ^ BitOperations.RotateRight(a, 39);
			h += (a & b) ^ (a & c) ^ (b & c);

			g += BitOperations.RotateRight(d, 14) ^ BitOperations.RotateRight(d, 18) ^ BitOperations.RotateRight(d, 41);
			g += (d & e) ^ (~d & f);
			g += K[i + 1] + w[i + 1];
			c += g;
			g += BitOperations.RotateRight(h, 28) ^ BitOperations.RotateRight(h, 34) ^ BitOperations.RotateRight(h, 39);
			g += (h & a) ^ (h & b) ^ (a & b);

			f += BitOperations.RotateRight(c, 14) ^ BitOperations.RotateRight(c, 18) ^ BitOperations.RotateRight(c, 41);
			f += (c & d) ^ (~c & e);
			f += K[i + 2] + w[i + 2];
			b += f;
			f += BitOperations.RotateRight(g, 28) ^ BitOperations.RotateRight(g, 34) ^ BitOperations.RotateRight(g, 39);
			f += (g & h) ^ (g & a) ^ (h & a);

			e += BitOperations.RotateRight(b, 14) ^ BitOperations.RotateRight(b, 18) ^ BitOperations.RotateRight(b, 41);
			e += (b & c) ^ (~b & d);
			e += K[i + 3] + w[i + 3];
			a += e;
			e += BitOperations.RotateRight(f, 28) ^ BitOperations.RotateRight(f, 34) ^ BitOperations.RotateRight(f, 39);
			e += (f & g) ^ (f & h) ^ (g & h);

			d += BitOperations.RotateRight(a, 14) ^ BitOperations.RotateRight(a, 18) ^ BitOperations.RotateRight(a, 41);
			d += (a & b) ^ (~a & c);
			d += K[i + 4] + w[i + 4];
			h += d;
			d += BitOperations.RotateRight(e, 28) ^ BitOperations.RotateRight(e, 34) ^ BitOperations.RotateRight(e, 39);
			d += (e & f) ^ (e & g) ^ (f & g);

			c += BitOperations.RotateRight(h, 14) ^ BitOperations.RotateRight(h, 18) ^ BitOperations.RotateRight(h, 41);
			c += (h & a) ^ (~h & b);
			c += K[i + 5] + w[i + 5];
			g += c;
			c += BitOperations.RotateRight(d, 28) ^ BitOperations.RotateRight(d, 34) ^ BitOperations.RotateRight(d, 39);
			c += (d & e) ^ (d & f) ^ (e & f);

			b += BitOperations.RotateRight(g, 14) ^ BitOperations.RotateRight(g, 18) ^ BitOperations.RotateRight(g, 41);
			b += (g & h) ^ (~g & a);
			b += K[i + 6] + w[i + 6];
			f += b;
			b += BitOperations.RotateRight(c, 28) ^ BitOperations.RotateRight(c, 34) ^ BitOperations.RotateRight(c, 39);
			b += (c & d) ^ (c & e) ^ (d & e);

			a += BitOperations.RotateRight(f, 14) ^ BitOperations.RotateRight(f, 18) ^ BitOperations.RotateRight(f, 41);
			a += (f & g) ^ (~f & h);
			a += K[i + 7] + w[i + 7];
			e += a;
			a += BitOperations.RotateRight(b, 28) ^ BitOperations.RotateRight(b, 34) ^ BitOperations.RotateRight(b, 39);
			a += (b & c) ^ (b & d) ^ (c & d);
		}

		h0 += a; h1 += b; h2 += c; h3 += d;
		h4 += e; h5 += f; h6 += g; h7 += h;
	}
}
