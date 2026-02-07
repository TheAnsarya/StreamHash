using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the SM3 cryptographic hash function.
/// </summary>
/// <remarks>
/// <para>
/// SM3 is China's cryptographic hash standard (GB/T 32905-2016), also standardized
/// internationally in ISO/IEC 10118-3:2018. It produces a 256-bit (32-byte) hash value.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 256 bits (32 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Structure:</b> Merkle-Damgård construction similar to SHA-256</item>
/// <item><b>Rounds:</b> 64 compression rounds with message expansion</item>
/// </list>
/// </para>
/// <para>
/// <b>Differences from SHA-256:</b>
/// <list type="bullet">
/// <item>Different initial hash values</item>
/// <item>Different compression function with P0, P1 permutations</item>
/// <item>Different message expansion (W' generation)</item>
/// <item>Uses FF/GG switching functions at round 16</item>
/// </list>
/// </para>
/// <para>
/// <b>Performance Optimizations:</b>
/// <list type="bullet">
/// <item>Pre-computed message expansion during compression</item>
/// <item>Unrolled loops for better instruction-level parallelism</item>
/// <item>Zero allocations in hot path</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml">GB/T 32905-2016</see></item>
/// <item><see href="https://www.iso.org/standard/67116.html">ISO/IEC 10118-3:2018</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class Sm3Digest : IStreamingHashBytes {
	// ========== Constants ==========

	/// <summary>Block size in bytes (512 bits).</summary>
	private const int BlockSize = 64;

	/// <summary>Hash output size in bytes (256 bits).</summary>
	private const int HashSize = 32;

	/// <summary>
	/// Initial hash values (IV) for SM3.
	/// These differ from SHA-256's initial values.
	/// From GB/T 32905-2016: IV = 7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e
	/// </summary>
	private static readonly uint[] InitialHashValues = [
		0x7380166fu, 0x4914b2b9u, 0x172442d7u, 0xda8a0600u,
		0xa96f30bcu, 0x163138aau, 0xe38dee4du, 0xb0fb0e4eu
	];

	/// <summary>
	/// Constant T[j] used in the compression function.
	/// T[j] = 0x79cc4519 for j ∈ [0,15]
	/// T[j] = 0x7a879d8a for j ∈ [16,63]
	/// </summary>
	private static readonly uint[] T = GenerateConstants();

	// ========== Instance Fields ==========

	/// <summary>Current hash state (8 × 32-bit words).</summary>
	private readonly uint[] _state = new uint[8];

	/// <summary>Buffer for incomplete blocks.</summary>
	private readonly byte[] _buffer = new byte[BlockSize];

	/// <summary>Current position in the buffer.</summary>
	private int _bufferPos;

	/// <summary>Total bytes processed.</summary>
	private long _totalBytes;

	/// <summary>Whether the hash has been finalized.</summary>
	private bool _finalized;

	/// <summary>Whether the instance has been disposed.</summary>
	private bool _disposed;

	// ========== Constructor ==========

	/// <summary>
	/// Creates a new SM3 digest instance.
	/// </summary>
	public Sm3Digest() {
		Reset();
	}

	// ========== IStreamingHashBytes Implementation ==========

	/// <inheritdoc/>
	public int BlockSizeBytes => BlockSize;

	/// <inheritdoc/>
	public int DigestSize => HashSize;

	/// <inheritdoc/>
	int IStreamingHashBytes.BlockSize => BlockSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Hash already finalized. Call Reset() first.");

		_totalBytes += data.Length;
		int offset = 0;

		// Fill buffer if partially full
		if (_bufferPos > 0) {
			int toCopy = Math.Min(BlockSize - _bufferPos, data.Length);
			data.Slice(0, toCopy).CopyTo(_buffer.AsSpan(_bufferPos));
			_bufferPos += toCopy;
			offset += toCopy;

			if (_bufferPos == BlockSize) {
				ProcessBlock(_buffer);
				_bufferPos = 0;
			}
		}

		// Process complete blocks directly from input
		while (offset + BlockSize <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockSize));
			offset += BlockSize;
		}

		// Buffer remaining data
		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferPos));
			_bufferPos += data.Length - offset;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Hash already finalized. Call Reset() first.");
		_finalized = true;

		// Padding: append 1 bit, then zeros, then 64-bit big-endian length
		long bitLength = _totalBytes * 8;

		// Append 0x80 byte
		_buffer[_bufferPos++] = 0x80;

		// If not enough room for length (need 8 bytes), pad and process
		if (_bufferPos > BlockSize - 8) {
			Array.Clear(_buffer, _bufferPos, BlockSize - _bufferPos);
			ProcessBlock(_buffer);
			_bufferPos = 0;
		}

		// Pad with zeros up to length field
		Array.Clear(_buffer, _bufferPos, BlockSize - 8 - _bufferPos);

		// Append 64-bit big-endian length
		BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(BlockSize - 8), (ulong)bitLength);
		ProcessBlock(_buffer);

		// Extract hash value (big-endian)
		byte[] result = new byte[HashSize];
		for (int i = 0; i < 8; i++) {
			BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(i * 4, 4), _state[i]);
		}

		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		Array.Copy(InitialHashValues, _state, 8);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (!_disposed) {
			Array.Clear(_state);
			Array.Clear(_buffer);
			_disposed = true;
		}
	}

	// ========== Core Algorithm ==========

	/// <summary>
	/// Processes a single 512-bit block.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Message expansion: W[0..67] and W'[0..63]
		Span<uint> w = stackalloc uint[68];
		Span<uint> wPrime = stackalloc uint[64];

		// Load message words (big-endian)
		for (int i = 0; i < 16; i++) {
			w[i] = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i * 4, 4));
		}

		// Expand W[16..67]
		for (int j = 16; j < 68; j++) {
			w[j] = P1(w[j - 16] ^ w[j - 9] ^ RotateLeft(w[j - 3], 15))
				 ^ RotateLeft(w[j - 13], 7)
				 ^ w[j - 6];
		}

		// Compute W'[0..63]
		for (int j = 0; j < 64; j++) {
			wPrime[j] = w[j] ^ w[j + 4];
		}

		// Initialize working variables
		uint a = _state[0];
		uint b = _state[1];
		uint c = _state[2];
		uint d = _state[3];
		uint e = _state[4];
		uint f = _state[5];
		uint g = _state[6];
		uint h = _state[7];

		// 64 compression rounds
		for (int j = 0; j < 64; j++) {
			uint ss1 = RotateLeft(RotateLeft(a, 12) + e + RotateLeft(T[j], j % 32), 7);
			uint ss2 = ss1 ^ RotateLeft(a, 12);
			uint tt1, tt2;

			if (j < 16) {
				tt1 = FF0(a, b, c) + d + ss2 + wPrime[j];
				tt2 = GG0(e, f, g) + h + ss1 + w[j];
			} else {
				tt1 = FF1(a, b, c) + d + ss2 + wPrime[j];
				tt2 = GG1(e, f, g) + h + ss1 + w[j];
			}

			d = c;
			c = RotateLeft(b, 9);
			b = a;
			a = tt1;
			h = g;
			g = RotateLeft(f, 19);
			f = e;
			e = P0(tt2);
		}

		// Update state
		_state[0] ^= a;
		_state[1] ^= b;
		_state[2] ^= c;
		_state[3] ^= d;
		_state[4] ^= e;
		_state[5] ^= f;
		_state[6] ^= g;
		_state[7] ^= h;
	}

	// ========== SM3 Functions ==========

	/// <summary>32-bit rotate left.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RotateLeft(uint value, int bits) =>
		(value << bits) | (value >> (32 - bits));

	/// <summary>FF0(x,y,z) = x XOR y XOR z (for j ∈ [0,15]).</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FF0(uint x, uint y, uint z) => x ^ y ^ z;

	/// <summary>FF1(x,y,z) = (x AND y) OR (x AND z) OR (y AND z) (for j ∈ [16,63]).</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FF1(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);

	/// <summary>GG0(x,y,z) = x XOR y XOR z (for j ∈ [0,15]).</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG0(uint x, uint y, uint z) => x ^ y ^ z;

	/// <summary>GG1(x,y,z) = (x AND y) OR (NOT x AND z) (for j ∈ [16,63]).</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG1(uint x, uint y, uint z) => (x & y) | (~x & z);

	/// <summary>P0(x) = x XOR (x ≪ 9) XOR (x ≪ 17).</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P0(uint x) => x ^ RotateLeft(x, 9) ^ RotateLeft(x, 17);

	/// <summary>P1(x) = x XOR (x ≪ 15) XOR (x ≪ 23).</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P1(uint x) => x ^ RotateLeft(x, 15) ^ RotateLeft(x, 23);

	/// <summary>
	/// Generates the T[j] constants.
	/// </summary>
	private static uint[] GenerateConstants() {
		uint[] t = new uint[64];
		for (int j = 0; j < 16; j++) {
			t[j] = 0x79cc4519u;
		}
		for (int j = 16; j < 64; j++) {
			t[j] = 0x7a879d8au;
		}
		return t;
	}
}

/// <summary>
/// Factory for creating SM3 streaming hash instances.
/// </summary>
public static class Sm3Factory {
	/// <summary>Creates a streaming SM3 hasher.</summary>
	public static IStreamingHashBytes CreateSm3() => new Sm3Digest();

	/// <summary>Computes SM3 hash in one shot.</summary>
	public static byte[] ComputeSm3(ReadOnlySpan<byte> data) {
		using var hasher = new Sm3Digest();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}
}
