using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the GOST R 34.11-94 cryptographic hash function.
/// </summary>
/// <remarks>
/// <para>
/// GOST R 34.11-94 is a Russian cryptographic hash standard that produces a 256-bit (32-byte) hash value.
/// It uses the GOST 28147-89 block cipher internally for the compression function.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 256 bits (32 bytes)</item>
/// <item><b>Block Size:</b> 256 bits (32 bytes)</item>
/// <item><b>Structure:</b> Merkle-Damgård with GOST 28147-89 cipher</item>
/// <item><b>Rounds:</b> 32 rounds of GOST block cipher per encryption</item>
/// </list>
/// </para>
/// <para>
/// <b>Performance Optimizations:</b>
/// <list type="bullet">
/// <item>Inline S-box lookups with pre-expanded tables</item>
/// <item>Optimized key schedule computation</item>
/// <item>Minimal allocations using stackalloc where possible</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://datatracker.ietf.org/doc/html/rfc5831">RFC 5831 - GOST R 34.11-94</see></item>
/// <item><see href="https://datatracker.ietf.org/doc/html/rfc5830">RFC 5830 - GOST 28147-89</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeGost94 : IStreamingHashBytes {
	// ========== Constants ==========

	/// <summary>Block size in bytes (256 bits).</summary>
	private const int BlockSizeConst = 32;

	/// <summary>Hash output size in bytes (256 bits).</summary>
	private const int HashSize = 32;

	/// <summary>
	/// The D-A S-box used for GOST R 34.11-94 digest calculation.
	/// This is the standard S-box defined in the specification for hash computation.
	/// 8 S-boxes of 16 4-bit values each, stored as bytes.
	/// </summary>
	/// <remarks>
	/// Note: This is different from the "Default" S-box used for encryption.
	/// BouncyCastle calls this "D-A" (Digest variant A) in GOST28147Engine.
	/// </remarks>
	private static readonly byte[,] SBox = {
		// S-box 1 (D-A)
		{ 0xa, 0x4, 0x5, 0x6, 0x8, 0x1, 0x3, 0x7, 0xd, 0xc, 0xe, 0x0, 0x9, 0x2, 0xb, 0xf },
		// S-box 2 (D-A)
		{ 0x5, 0xf, 0x4, 0x0, 0x2, 0xd, 0xb, 0x9, 0x1, 0x7, 0x6, 0x3, 0xc, 0xe, 0xa, 0x8 },
		// S-box 3 (D-A)
		{ 0x7, 0xf, 0xc, 0xe, 0x9, 0x4, 0x1, 0x0, 0x3, 0xb, 0x5, 0x2, 0x6, 0xa, 0x8, 0xd },
		// S-box 4 (D-A)
		{ 0x4, 0xa, 0x7, 0xc, 0x0, 0xf, 0x2, 0x8, 0xe, 0x1, 0x6, 0x5, 0xd, 0xb, 0x9, 0x3 },
		// S-box 5 (D-A)
		{ 0x7, 0x6, 0x4, 0xb, 0x9, 0xc, 0x2, 0xa, 0x1, 0x8, 0x0, 0xe, 0xf, 0xd, 0x3, 0x5 },
		// S-box 6 (D-A)
		{ 0x7, 0x6, 0x2, 0x4, 0xd, 0x9, 0xf, 0x0, 0xa, 0x1, 0x5, 0xb, 0x8, 0xe, 0xc, 0x3 },
		// S-box 7 (D-A)
		{ 0xd, 0xe, 0x4, 0x1, 0x7, 0x0, 0x5, 0xa, 0x3, 0xc, 0x8, 0xf, 0x6, 0x2, 0x9, 0xb },
		// S-box 8 (D-A)
		{ 0x1, 0x3, 0xa, 0x9, 0x5, 0xb, 0x4, 0xf, 0x8, 0x6, 0x7, 0xe, 0xd, 0x0, 0x2, 0xc }
	};

	/// <summary>
	/// Pre-expanded S-boxes for faster lookups.
	/// Each element combines two 4-bit S-box lookups into one byte lookup.
	/// </summary>
	internal static readonly uint[] K87;
	internal static readonly uint[] K65;
	internal static readonly uint[] K43;
	internal static readonly uint[] K21;

	/// <summary>
	/// Constant C2 used in key generation (from RFC 5831).
	/// </summary>
	internal static readonly byte[] C2 = {
		0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
		0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
		0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff,
		0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff
	};

	// ========== Static Constructor ==========

	static NativeGost94() {
		// Pre-expand S-boxes for faster lookup
		// Each K array allows looking up two S-box values at once
		K87 = new uint[256];
		K65 = new uint[256];
		K43 = new uint[256];
		K21 = new uint[256];

		for (int i = 0; i < 256; i++) {
			int lo = i & 0x0f;
			int hi = (i >> 4) & 0x0f;

			K87[i] = ((uint)SBox[7, hi] << 4) | SBox[6, lo];
			K65[i] = ((uint)SBox[5, hi] << 4) | SBox[4, lo];
			K43[i] = ((uint)SBox[3, hi] << 4) | SBox[2, lo];
			K21[i] = ((uint)SBox[1, hi] << 4) | SBox[0, lo];
		}

		// Shift pre-expanded values to their final positions
		for (int i = 0; i < 256; i++) {
			K87[i] <<= 24;
			K65[i] <<= 16;
			K43[i] <<= 8;
			// K21 stays in low byte position
		}
	}

	// ========== Instance Fields ==========

	/// <summary>Current hash value H.</summary>
	private readonly byte[] _h = new byte[BlockSizeConst];

	/// <summary>Running checksum Σ.</summary>
	private readonly byte[] _sum = new byte[BlockSizeConst];

	/// <summary>Message length counter L (in bits, mod 2^256).</summary>
	private readonly byte[] _length = new byte[BlockSizeConst];

	/// <summary>Buffer for incomplete blocks.</summary>
	private readonly byte[] _buffer = new byte[BlockSizeConst];

	/// <summary>Current position in buffer.</summary>
	private int _bufferOffset;

	/// <summary>Total bytes processed.</summary>
	private long _totalBytes;

	// ========== Working Arrays (reused to reduce allocations) ==========
	private readonly byte[] _m = new byte[BlockSizeConst];
	private readonly byte[] _u = new byte[BlockSizeConst];
	private readonly byte[] _v = new byte[BlockSizeConst];
	private readonly byte[] _w = new byte[BlockSizeConst];
	private readonly byte[] _s = new byte[BlockSizeConst];
	private readonly byte[] _key = new byte[BlockSizeConst];

	// ========== Constructor ==========

	/// <summary>
	/// Creates a new instance of the GOST R 34.11-94 hash function.
	/// </summary>
	public NativeGost94() {
		Reset();
	}

	// ========== IStreamingHashBytes Implementation ==========

	/// <inheritdoc/>
	public int BlockSize => BlockSizeConst;

	/// <inheritdoc/>
	public int DigestSize => HashSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		int offset = 0;
		int length = data.Length;
		_totalBytes += length;

		// Fill buffer if there's partial data
		if (_bufferOffset > 0) {
			int toCopy = Math.Min(BlockSize - _bufferOffset, length);
			data.Slice(offset, toCopy).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += toCopy;
			offset += toCopy;
			length -= toCopy;

			if (_bufferOffset == BlockSize) {
				ProcessBlock(_buffer);
				_bufferOffset = 0;
			}
		}

		// Process complete blocks
		while (length >= BlockSize) {
			ProcessBlock(data.Slice(offset, BlockSize));
			offset += BlockSize;
			length -= BlockSize;
		}

		// Buffer remaining data
		if (length > 0) {
			data.Slice(offset, length).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += length;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		byte[] hash = new byte[HashSize];
		FinalizeHash(hash);
		Reset();
		return hash;
	}

	/// <inheritdoc/>
	public void Dispose() {
		// No unmanaged resources to dispose
	}

	/// <inheritdoc/>
	public void Reset() {
		Array.Clear(_h);
		Array.Clear(_sum);
		Array.Clear(_length);
		Array.Clear(_buffer);
		_bufferOffset = 0;
		_totalBytes = 0;
	}

	// ========== Core Algorithm ==========

	/// <summary>
	/// Processes a single 256-bit block.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Copy block to M
		block.CopyTo(_m);

		// Update checksum: Σ = (Σ + M) mod 2^256
		AddModulo256(_sum, _m);

		// Compute step hash function: H = χ(M, H)
		StepHash(_m, _h);
	}

	/// <summary>
	/// Finalizes the hash computation.
	/// </summary>
	private void FinalizeHash(Span<byte> output) {
		// Store bit count in L (little-endian)
		ulong bitCount = (ulong)_totalBytes * 8;
		BinaryPrimitives.WriteUInt64LittleEndian(_length, bitCount);

		// Pad remaining data with zeros and process
		if (_bufferOffset > 0) {
			// Clear rest of buffer
			Array.Clear(_buffer, _bufferOffset, BlockSizeConst - _bufferOffset);

			// Update checksum with padded final block
			AddModulo256(_sum, _buffer);

			// Process padded block
			StepHash(_buffer, _h);
		}

		// Process L (length)
		StepHash(_length, _h);

		// Process Σ (checksum)
		StepHash(_sum, _h);

		// Copy final hash
		_h.AsSpan().CopyTo(output);
	}

	/// <summary>
	/// Step hash function χ(M, H) - the core compression function.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void StepHash(byte[] m, byte[] h) {
		// Generate keys K1..K4
		// Initialize: U = H, V = M
		h.CopyTo(_u, 0);
		m.CopyTo(_v, 0);

		// W = U XOR V
		for (int j = 0; j < BlockSize; j++) {
			_w[j] = (byte)(_u[j] ^ _v[j]);
		}

		// K1 = P(W)
		PermutationP(_w, _key);

		// Encrypt: s0 = E(K1, h0)
		EncryptBlock(_key, h, 0, _s, 0);

		// Keys K2, K3, K4
		for (int i = 1; i < 4; i++) {
			// U = A(U) XOR C[i]
			TransformA(_u);
			if (i == 2) {
				// XOR with C2
				for (int j = 0; j < BlockSize; j++) {
					_u[j] ^= C2[j];
				}
			}

			// V = A(A(V))
			TransformA(_v);
			TransformA(_v);

			// W = U XOR V
			for (int j = 0; j < BlockSize; j++) {
				_w[j] = (byte)(_u[j] ^ _v[j]);
			}

			// K[i] = P(W)
			PermutationP(_w, _key);

			// Encrypt: s[i] = E(K[i], h[i])
			EncryptBlock(_key, h, i * 8, _s, i * 8);
		}

		// Mixing transformation: ψ^61(H XOR ψ(M XOR ψ^12(S)))
		// Apply ψ^12 to S
		for (int i = 0; i < 12; i++) {
			TransformPsi(_s);
		}

		// S = S XOR M
		for (int j = 0; j < BlockSize; j++) {
			_s[j] ^= m[j];
		}

		// Apply ψ once
		TransformPsi(_s);

		// S = S XOR H
		for (int j = 0; j < BlockSize; j++) {
			_s[j] ^= h[j];
		}

		// Apply ψ^61
		for (int i = 0; i < 61; i++) {
			TransformPsi(_s);
		}

		// Copy result to H
		_s.CopyTo(h, 0);
	}

	/// <summary>
	/// Permutation P: reorders bytes according to the GOST specification.
	/// P(Y) = y[φ(32)] || y[φ(31)] || ... || y[φ(1)]
	/// where φ(i + 1 + 4(k-1)) = 8i + k, i=0..3, k=1..8
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PermutationP(byte[] input, byte[] output) {
		// The permutation interleaves bytes from 4 groups of 8
		for (int k = 0; k < 8; k++) {
			output[k * 4] = input[k];
			output[k * 4 + 1] = input[8 + k];
			output[k * 4 + 2] = input[16 + k];
			output[k * 4 + 3] = input[24 + k];
		}
	}

	/// <summary>
	/// Transform A: A(Y) = (y1 XOR y2) || y4 || y3 || y2
	/// where Y = y1 || y2 || y3 || y4 (each yi is 64 bits / 8 bytes)
	/// Note: BouncyCastle stores as y1|y2|y3|y4 in memory order.
	/// </summary>
	private static void TransformA(byte[] y) {
		// Save y1 XOR y2 (first 8 bytes XOR next 8 bytes)
		Span<byte> xorResult = stackalloc byte[8];
		for (int i = 0; i < 8; i++) {
			xorResult[i] = (byte)(y[i] ^ y[8 + i]);
		}

		// Shift: y2->y1, y3->y2, y4->y3, (y1 XOR y2)->y4
		// In byte terms: [0-7]=[8-15], [8-15]=[16-23], [16-23]=[24-31], [24-31]=xorResult
		for (int i = 0; i < 24; i++) {
			y[i] = y[i + 8];
		}
		xorResult.CopyTo(y.AsSpan(24));
	}

	/// <summary>
	/// Transform ψ (psi): LFSR-based mixing
	/// ψ(Y) = (y1 XOR y2 XOR y3 XOR y4 XOR y13 XOR y16) || y16 || y15 || ... || y2
	/// where Y = y16 || y15 || ... || y1 (each yi is 16 bits)
	/// </summary>
	private static void TransformPsi(byte[] y) {
		// Read 16 16-bit words (little-endian shorts)
		Span<ushort> words = stackalloc ushort[16];
		for (int i = 0; i < 16; i++) {
			words[i] = BinaryPrimitives.ReadUInt16LittleEndian(y.AsSpan(i * 2));
		}

		// Compute new word: y[0] XOR y[1] XOR y[2] XOR y[3] XOR y[12] XOR y[15]
		ushort newWord = (ushort)(words[0] ^ words[1] ^ words[2] ^ words[3] ^ words[12] ^ words[15]);

		// Shift all words: w_S[i] = wS[i+1] for i=0..14, w_S[15] = newWord
		for (int i = 0; i < 15; i++) {
			words[i] = words[i + 1];
		}
		words[15] = newWord;

		// Write back to bytes
		for (int i = 0; i < 16; i++) {
			BinaryPrimitives.WriteUInt16LittleEndian(y.AsSpan(i * 2), words[i]);
		}
	}

	/// <summary>
	/// GOST 28147-89 block cipher encryption (ECB mode, single 64-bit block).
	/// </summary>
	private static void EncryptBlock(byte[] key, byte[] input, int inOff, byte[] output, int outOff) {
		// Read 64-bit input as two 32-bit words (little-endian)
		uint n1 = BinaryPrimitives.ReadUInt32LittleEndian(input.AsSpan(inOff));
		uint n2 = BinaryPrimitives.ReadUInt32LittleEndian(input.AsSpan(inOff + 4));

		// 32 rounds of encryption
		// Rounds 1-24: use keys K0-K7 three times in order
		// Rounds 25-32: use keys K7-K0 once in reverse
		for (int round = 0; round < 24; round++) {
			uint subkey = GetSubkey(key, round & 7);
			uint temp = n1;
			n1 = n2 ^ GostRound(n1, subkey);
			n2 = temp;
		}
		for (int round = 0; round < 8; round++) {
			uint subkey = GetSubkey(key, 7 - round);
			uint temp = n1;
			n1 = n2 ^ GostRound(n1, subkey);
			n2 = temp;
		}

		// Output (swap n1 and n2 for final result)
		BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(outOff), n2);
		BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(outOff + 4), n1);
	}

	/// <summary>
	/// Gets a 32-bit subkey from the 256-bit key.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GetSubkey(byte[] key, int index) {
		return BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(index * 4));
	}

	/// <summary>
	/// GOST round function: S-box substitution + rotation.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GostRound(uint n, uint key) {
		uint sum = n + key;

		// S-box substitution using pre-expanded tables
		uint result = K87[(sum >> 24) & 0xff]
					| K65[(sum >> 16) & 0xff]
					| K43[(sum >> 8) & 0xff]
					| K21[sum & 0xff];

		// Rotate left by 11 bits
		return (result << 11) | (result >> 21);
	}

	/// <summary>
	/// Adds two 256-bit numbers modulo 2^256 (little-endian).
	/// </summary>
	private static void AddModulo256(byte[] sum, byte[] input) {
		int carry = 0;
		for (int i = 0; i < BlockSizeConst; i++) {
			int s = sum[i] + input[i] + carry;
			sum[i] = (byte)s;
			carry = s >> 8;
		}
	}
}

/// <summary>
/// Factory for creating GOST-94 hash instances with optimized static computation.
/// </summary>
public static class Gost94Factory {
	/// <summary>
	/// Computes GOST R 34.11-94 hash using the streaming API.
	/// </summary>
	public static byte[] ComputeGost94(ReadOnlySpan<byte> data) {
		var hasher = new NativeGost94();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes GOST R 34.11-94 hash with minimal allocations using stackalloc for state.
	/// Only allocates the 32-byte result array.
	/// </summary>
	public static byte[] ComputeGost94Static(ReadOnlySpan<byte> data) {
		// State arrays on stack
		Span<byte> h = stackalloc byte[32];      // Current hash value
		Span<byte> sum = stackalloc byte[32];    // Running checksum
		Span<byte> length = stackalloc byte[32]; // Length counter
		Span<byte> buffer = stackalloc byte[32]; // Block buffer
		Span<byte> m = stackalloc byte[32];
		Span<byte> u = stackalloc byte[32];
		Span<byte> v = stackalloc byte[32];
		Span<byte> w = stackalloc byte[32];
		Span<byte> s = stackalloc byte[32];
		Span<byte> key = stackalloc byte[32];
		Span<byte> temp = stackalloc byte[8];

		int bufferOffset = 0;
		ulong totalBytes = 0;

		// Process data
		int offset = 0;
		int remaining = data.Length;

		// Process complete blocks
		while (remaining >= 32) {
			ReadOnlySpan<byte> block = data.Slice(offset, 32);

			// Update checksum
			AddModulo256Static(sum, block);
			totalBytes += 32;

			// Step hash
			StepHashStatic(block, h, m, u, v, w, s, key, temp);

			offset += 32;
			remaining -= 32;
		}

		// Buffer remaining data
		if (remaining > 0) {
			data.Slice(offset, remaining).CopyTo(buffer);
			bufferOffset = remaining;
		}

		// Finalize
		// Store bit count in length
		BinaryPrimitives.WriteUInt64LittleEndian(length, totalBytes * 8 + (ulong)bufferOffset * 8);

		// Process final block if any
		if (bufferOffset > 0) {
			buffer.Slice(bufferOffset).Clear();
			AddModulo256Static(sum, buffer);
			StepHashStatic(buffer, h, m, u, v, w, s, key, temp);
		}

		// Process length
		StepHashStatic(length, h, m, u, v, w, s, key, temp);

		// Process checksum
		StepHashStatic(sum, h, m, u, v, w, s, key, temp);

		// Return result (only allocation)
		byte[] result = new byte[32];
		h.CopyTo(result);
		return result;
	}

	/// <summary>
	/// Step hash function using spans.
	/// </summary>
	private static void StepHashStatic(
		ReadOnlySpan<byte> m,
		Span<byte> h,
		Span<byte> mBuf,
		Span<byte> u,
		Span<byte> v,
		Span<byte> w,
		Span<byte> s,
		Span<byte> key,
		Span<byte> temp) {
		// Copy m to buffer
		m.CopyTo(mBuf);

		// Initialize: U = H, V = M
		h.CopyTo(u);
		mBuf.CopyTo(v);

		// W = U XOR V
		for (int j = 0; j < 32; j++) {
			w[j] = (byte)(u[j] ^ v[j]);
		}

		// K1 = P(W)
		PermutationPStatic(w, key);

		// Encrypt: s0 = E(K1, h0)
		EncryptBlockStatic(key, h, s);

		// Keys K2, K3, K4
		for (int i = 1; i < 4; i++) {
			// U = A(U) XOR C[i]
			TransformAStatic(u, temp);
			if (i == 2) {
				// XOR with C2 (static readonly constant)
				for (int j = 0; j < 32; j++) {
					u[j] ^= NativeGost94.C2[j];
				}
			}

			// V = A(A(V))
			TransformAStatic(v, temp);
			TransformAStatic(v, temp);

			// W = U XOR V
			for (int j = 0; j < 32; j++) {
				w[j] = (byte)(u[j] ^ v[j]);
			}

			// K[i] = P(W)
			PermutationPStatic(w, key);

			// Encrypt: s[i] = E(K[i], h[i])
			EncryptBlockStatic(key, h.Slice(i * 8, 8), s.Slice(i * 8, 8));
		}

		// Mixing transformation
		for (int i = 0; i < 12; i++) {
			TransformPsiStatic(s);
		}

		for (int j = 0; j < 32; j++) {
			s[j] ^= mBuf[j];
		}

		TransformPsiStatic(s);

		for (int j = 0; j < 32; j++) {
			s[j] ^= h[j];
		}

		for (int i = 0; i < 61; i++) {
			TransformPsiStatic(s);
		}

		s.CopyTo(h);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PermutationPStatic(ReadOnlySpan<byte> input, Span<byte> output) {
		for (int k = 0; k < 8; k++) {
			output[k * 4] = input[k];
			output[k * 4 + 1] = input[8 + k];
			output[k * 4 + 2] = input[16 + k];
			output[k * 4 + 3] = input[24 + k];
		}
	}

	private static void TransformAStatic(Span<byte> y, Span<byte> temp) {
		for (int i = 0; i < 8; i++) {
			temp[i] = (byte)(y[i] ^ y[8 + i]);
		}
		for (int i = 0; i < 24; i++) {
			y[i] = y[i + 8];
		}
		temp.CopyTo(y.Slice(24));
	}

	private static void TransformPsiStatic(Span<byte> y) {
		// Read 16 16-bit words (little-endian shorts)
		Span<ushort> words = stackalloc ushort[16];
		for (int i = 0; i < 16; i++) {
			words[i] = BinaryPrimitives.ReadUInt16LittleEndian(y.Slice(i * 2));
		}

		// Compute new word: y[0] XOR y[1] XOR y[2] XOR y[3] XOR y[12] XOR y[15]
		ushort newWord = (ushort)(words[0] ^ words[1] ^ words[2] ^ words[3] ^ words[12] ^ words[15]);

		// Shift all words: w_S[i] = wS[i+1] for i=0..14, w_S[15] = newWord
		for (int i = 0; i < 15; i++) {
			words[i] = words[i + 1];
		}
		words[15] = newWord;

		// Write back to bytes
		for (int i = 0; i < 16; i++) {
			BinaryPrimitives.WriteUInt16LittleEndian(y.Slice(i * 2), words[i]);
		}
	}

	/// <summary>
	/// The D-A S-box used for GOST R 34.11-94 digest calculation (shared with NativeGost94).
	/// </summary>
	private static readonly byte[,] SBox = {
		{ 0xa, 0x4, 0x5, 0x6, 0x8, 0x1, 0x3, 0x7, 0xd, 0xc, 0xe, 0x0, 0x9, 0x2, 0xb, 0xf },
		{ 0x5, 0xf, 0x4, 0x0, 0x2, 0xd, 0xb, 0x9, 0x1, 0x7, 0x6, 0x3, 0xc, 0xe, 0xa, 0x8 },
		{ 0x7, 0xf, 0xc, 0xe, 0x9, 0x4, 0x1, 0x0, 0x3, 0xb, 0x5, 0x2, 0x6, 0xa, 0x8, 0xd },
		{ 0x4, 0xa, 0x7, 0xc, 0x0, 0xf, 0x2, 0x8, 0xe, 0x1, 0x6, 0x5, 0xd, 0xb, 0x9, 0x3 },
		{ 0x7, 0x6, 0x4, 0xb, 0x9, 0xc, 0x2, 0xa, 0x1, 0x8, 0x0, 0xe, 0xf, 0xd, 0x3, 0x5 },
		{ 0x7, 0x6, 0x2, 0x4, 0xd, 0x9, 0xf, 0x0, 0xa, 0x1, 0x5, 0xb, 0x8, 0xe, 0xc, 0x3 },
		{ 0xd, 0xe, 0x4, 0x1, 0x7, 0x0, 0x5, 0xa, 0x3, 0xc, 0x8, 0xf, 0x6, 0x2, 0x9, 0xb },
		{ 0x1, 0x3, 0xa, 0x9, 0x5, 0xb, 0x4, 0xf, 0x8, 0x6, 0x7, 0xe, 0xd, 0x0, 0x2, 0xc }
	};

	private static readonly uint[] K87Static;
	private static readonly uint[] K65Static;
	private static readonly uint[] K43Static;
	private static readonly uint[] K21Static;

	static Gost94Factory() {
		K87Static = new uint[256];
		K65Static = new uint[256];
		K43Static = new uint[256];
		K21Static = new uint[256];

		for (int i = 0; i < 256; i++) {
			int lo = i & 0x0f;
			int hi = (i >> 4) & 0x0f;

			K87Static[i] = ((uint)SBox[7, hi] << 4) | SBox[6, lo];
			K65Static[i] = ((uint)SBox[5, hi] << 4) | SBox[4, lo];
			K43Static[i] = ((uint)SBox[3, hi] << 4) | SBox[2, lo];
			K21Static[i] = ((uint)SBox[1, hi] << 4) | SBox[0, lo];
		}

		for (int i = 0; i < 256; i++) {
			K87Static[i] <<= 24;
			K65Static[i] <<= 16;
			K43Static[i] <<= 8;
		}
	}

	private static void EncryptBlockStatic(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output) {
		uint n1 = BinaryPrimitives.ReadUInt32LittleEndian(input);
		uint n2 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(4));

		for (int round = 0; round < 24; round++) {
			uint subkey = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice((round & 7) * 4));
			uint temp = n1;
			n1 = n2 ^ GostRoundStatic(n1, subkey);
			n2 = temp;
		}
		for (int round = 0; round < 8; round++) {
			uint subkey = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice((7 - round) * 4));
			uint temp = n1;
			n1 = n2 ^ GostRoundStatic(n1, subkey);
			n2 = temp;
		}

		BinaryPrimitives.WriteUInt32LittleEndian(output, n2);
		BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4), n1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GostRoundStatic(uint n, uint key) {
		uint sum = n + key;
		uint result = K87Static[(sum >> 24) & 0xff]
					| K65Static[(sum >> 16) & 0xff]
					| K43Static[(sum >> 8) & 0xff]
					| K21Static[sum & 0xff];
		return (result << 11) | (result >> 21);
	}

	private static void AddModulo256Static(Span<byte> sum, ReadOnlySpan<byte> input) {
		int carry = 0;
		for (int i = 0; i < 32; i++) {
			int s = sum[i] + input[i] + carry;
			sum[i] = (byte)s;
			carry = s >> 8;
		}
	}
}
