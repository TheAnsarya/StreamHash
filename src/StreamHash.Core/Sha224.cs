using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the SHA-224 cryptographic hash function.
/// </summary>
/// <remarks>
/// <para>
/// SHA-224 is a truncated version of SHA-256- it uses the same compression function
/// and message schedule but with different initial hash values (derived from the
/// fractional parts of the square roots of the 23rd through 30th primes) and
/// produces a 28-byte (224-bit) output instead of 32 bytes.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 224 bits (28 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Structure:</b> Merkle-Damgård construction</item>
/// <item><b>Rounds:</b> 64 compression rounds per block</item>
/// <item><b>Word Size:</b> 32-bit words</item>
/// <item><b>Security:</b> 112-bit collision resistance</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://csrc.nist.gov/pubs/fips/180-4/upd1/final">FIPS 180-4</see></item>
/// <item><see href="https://datatracker.ietf.org/doc/html/rfc3874">RFC 3874 - SHA-224</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeSha224Digest : IStreamingHashBytes {
	private const int BlockSizeValue = 64;
	private const int DigestSizeValue = 28;

	// SHA-224 initial hash values (FIPS 180-4 section 5.3.2)
	// Second 32 bits of the fractional parts of the square roots of the 23rd through 30th primes
	private const uint Iv0 = 0xc1059ed8;
	private const uint Iv1 = 0x367cd507;
	private const uint Iv2 = 0x3070dd17;
	private const uint Iv3 = 0xf70e5939;
	private const uint Iv4 = 0xffc00b31;
	private const uint Iv5 = 0x68581511;
	private const uint Iv6 = 0x64f98fa7;
	private const uint Iv7 = 0xbefa4fa4;

	private uint _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7;
	private readonly byte[] _buffer = new byte[BlockSizeValue];
	private int _bufferOffset;
	private long _totalBytes;

	/// <summary>
	/// Creates a new SHA-224 streaming hash instance.
	/// </summary>
	public NativeSha224Digest() {
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

		// Fill buffer first
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

		// Process complete blocks
		while (offset + BlockSizeValue <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockSizeValue));
			offset += BlockSizeValue;
		}

		// Buffer remaining
		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += data.Length - offset;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		// Padding: append 1 bit, then zeros, then 64-bit length (big-endian)
		long bitLength = _totalBytes * 8;

		// Calculate padding needed (message must be congruent to 56 mod 64)
		int paddingLength = 56 - (int)(_totalBytes % 64);
		if (paddingLength <= 0) paddingLength += 64;

		Span<byte> padding = stackalloc byte[paddingLength + 8];
		padding[0] = 0x80;
		padding.Slice(1, paddingLength - 1).Clear();

		// 64-bit length in big-endian
		BinaryPrimitives.WriteUInt64BigEndian(padding.Slice(paddingLength), (ulong)bitLength);

		// Process padding through Update logic without counting in _totalBytes
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

		// Output first 28 bytes (224 bits) of the 32-byte state
		byte[] result = new byte[DigestSizeValue];
		Span<byte> fullHash = stackalloc byte[32];
		BinaryPrimitives.WriteUInt32BigEndian(fullHash.Slice(0), _h0);
		BinaryPrimitives.WriteUInt32BigEndian(fullHash.Slice(4), _h1);
		BinaryPrimitives.WriteUInt32BigEndian(fullHash.Slice(8), _h2);
		BinaryPrimitives.WriteUInt32BigEndian(fullHash.Slice(12), _h3);
		BinaryPrimitives.WriteUInt32BigEndian(fullHash.Slice(16), _h4);
		BinaryPrimitives.WriteUInt32BigEndian(fullHash.Slice(20), _h5);
		BinaryPrimitives.WriteUInt32BigEndian(fullHash.Slice(24), _h6);
		// _h7 is not included: SHA-224 truncates to 7 words (28 bytes)

		fullHash.Slice(0, DigestSizeValue).CopyTo(result);
		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		_h0 = Iv0; _h1 = Iv1; _h2 = Iv2; _h3 = Iv3;
		_h4 = Iv4; _h5 = Iv5; _h6 = Iv6; _h7 = Iv7;
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
		Span<uint> w = stackalloc uint[64];

		// Load 16 message words (big-endian)
		for (int i = 0; i < 16; i++) {
			w[i] = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i * 4));
		}

		// Expand message schedule
		for (int i = 16; i < 64; i++) {
			uint s0 = RotateRight(w[i - 15], 7) ^ RotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3);
			uint s1 = RotateRight(w[i - 2], 17) ^ RotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint a = _h0, b = _h1, c = _h2, d = _h3;
		uint e = _h4, f = _h5, g = _h6, h = _h7;

		// Main compression loop (same as SHA-256)
		for (int i = 0; i < 64; i++) {
			uint S1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
			uint ch = (e & f) ^ (~e & g);
			uint temp1 = h + S1 + ch + K[i] + w[i];
			uint S0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
			uint maj = (a & b) ^ (a & c) ^ (b & c);
			uint temp2 = S0 + maj;

			h = g; g = f; f = e; e = d + temp1;
			d = c; c = b; b = a; a = temp1 + temp2;
		}

		_h0 += a; _h1 += b; _h2 += c; _h3 += d;
		_h4 += e; _h5 += f; _h6 += g; _h7 += h;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RotateRight(uint x, int n) => (x >> n) | (x << (32 - n));

	// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
	private static readonly uint[] K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];
}

/// <summary>
/// Factory methods for creating native SHA-224 streaming hash instances.
/// </summary>
internal static class Sha224Factory {
	/// <summary>
	/// Creates a SHA-224 streaming hash instance.
	/// </summary>
	/// <returns>A new SHA-224 streaming hash.</returns>
	public static IStreamingHashBytes CreateSha224() => new NativeSha224Digest();

	/// <summary>
	/// Computes SHA-224 hash in one shot with minimal allocations.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 28-byte SHA-224 hash.</returns>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeSha224(ReadOnlySpan<byte> data) {
		using var hasher = new NativeSha224Digest();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}
}
