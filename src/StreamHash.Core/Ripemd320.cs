using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the RIPEMD-320 cryptographic hash function.
/// </summary>
/// <remarks>
/// <para>
/// RIPEMD-320 is an extended version of RIPEMD-160 with a 320-bit (40-byte) hash result.
/// It runs two parallel RIPEMD-160 instances with different initial values and exchanges
/// a chaining variable between the two parallel lines after each round.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 320 bits (40 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Structure:</b> Dual-line Merkle-Damgård construction</item>
/// <item><b>Rounds:</b> 80 compression rounds (5 rounds × 16 steps × 2 lines)</item>
/// <item><b>Security:</b> Same as RIPEMD-160 (designed for longer hash, not higher security)</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://homes.esat.kuleuven.be/~bosselae/ripemd160.html">RIPEMD Homepage</see></item>
/// <item><see href="https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd320.txt">RIPEMD-320 Pseudocode</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class Ripemd320Digest : IStreamingHashBytes {
	// ========== Constants ==========

	private const int BlockSize = 64;
	private const int HashSize = 40;

	// Initial values for the left line (same as RIPEMD-160)
	private static readonly uint[] InitialValuesLeft = [
		0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u
	];

	// Initial values for the right line (different from left)
	private static readonly uint[] InitialValuesRight = [
		0x76543210u, 0xfedcba98u, 0x89abcdefu, 0x01234567u, 0x3c2d1e0fu
	];

	// Message word selection for the left line (rounds 0-4)
	private static readonly int[] RL = [
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,   // Round 0
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,   // Round 1
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,   // Round 2
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,   // Round 3
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13    // Round 4
	];

	// Message word selection for the right line (rounds 0-4)
	private static readonly int[] RR = [
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,   // Round 0
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,   // Round 1
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,   // Round 2
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,   // Round 3
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11    // Round 4
	];

	// Rotation amounts for the left line
	private static readonly int[] SL = [
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,     // Round 0
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,     // Round 1
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,     // Round 2
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,     // Round 3
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6      // Round 4
	];

	// Rotation amounts for the right line
	private static readonly int[] SR = [
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,     // Round 0
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,     // Round 1
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,     // Round 2
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,     // Round 3
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11      // Round 4
	];

	// ========== Instance Fields ==========

	private readonly uint[] _stateLeft = new uint[5];
	private readonly uint[] _stateRight = new uint[5];
	private readonly byte[] _buffer = new byte[BlockSize];
	private int _bufferPos;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;

	public Ripemd320Digest() {
		Reset();
	}

	// ========== IStreamingHashBytes Implementation ==========

	public int BlockSizeBytes => BlockSize;
	public int DigestSize => HashSize;
	int IStreamingHashBytes.BlockSize => BlockSize;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Hash already finalized. Call Reset() first.");

		_totalBytes += data.Length;
		int offset = 0;

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

		while (offset + BlockSize <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockSize));
			offset += BlockSize;
		}

		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferPos));
			_bufferPos += data.Length - offset;
		}
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Hash already finalized. Call Reset() first.");
		_finalized = true;

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

		// Append 64-bit little-endian length (RIPEMD uses little-endian!)
		BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(BlockSize - 8), (ulong)bitLength);
		ProcessBlock(_buffer);

		// Extract hash value (little-endian, interleaved left/right)
		byte[] result = new byte[HashSize];
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(0, 4), _stateLeft[0]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), _stateLeft[1]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8, 4), _stateLeft[2]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12, 4), _stateLeft[3]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16, 4), _stateLeft[4]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(20, 4), _stateRight[0]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(24, 4), _stateRight[1]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(28, 4), _stateRight[2]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(32, 4), _stateRight[3]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(36, 4), _stateRight[4]);

		return result;
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		Array.Copy(InitialValuesLeft, _stateLeft, 5);
		Array.Copy(InitialValuesRight, _stateRight, 5);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
		_finalized = false;
	}

	public void Dispose() {
		if (!_disposed) {
			Array.Clear(_stateLeft);
			Array.Clear(_stateRight);
			Array.Clear(_buffer);
			_disposed = true;
		}
	}

	// ========== Core Algorithm ==========

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Load message words (little-endian)
		Span<uint> x = stackalloc uint[16];
		for (int i = 0; i < 16; i++) {
			x[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(i * 4, 4));
		}

		// Initialize working variables
		uint al = _stateLeft[0], bl = _stateLeft[1], cl = _stateLeft[2], dl = _stateLeft[3], el = _stateLeft[4];
		uint ar = _stateRight[0], br = _stateRight[1], cr = _stateRight[2], dr = _stateRight[3], er = _stateRight[4];

		// Round 0 (steps 0-15): Left uses F0, Right uses F4
		for (int j = 0; j < 16; j++) {
			uint tl = RotateLeft(al + F0(bl, cl, dl) + x[RL[j]], SL[j]) + el;
			al = el; el = dl; dl = RotateLeft(cl, 10); cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F4(br, cr, dr) + x[RR[j]] + 0x50a28be6u, SR[j]) + er;
			ar = er; er = dr; dr = RotateLeft(cr, 10); cr = br; br = tr;
		}

		// Exchange B after round 0 (j=15)
		(bl, br) = (br, bl);

		// Round 1 (steps 16-31): Left uses F1, Right uses F3
		for (int j = 16; j < 32; j++) {
			uint tl = RotateLeft(al + F1(bl, cl, dl) + x[RL[j]] + 0x5a827999u, SL[j]) + el;
			al = el; el = dl; dl = RotateLeft(cl, 10); cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F3(br, cr, dr) + x[RR[j]] + 0x5c4dd124u, SR[j]) + er;
			ar = er; er = dr; dr = RotateLeft(cr, 10); cr = br; br = tr;
		}

		// Exchange D after round 1 (j=31)
		(dl, dr) = (dr, dl);

		// Round 2 (steps 32-47): Left uses F2, Right uses F2
		for (int j = 32; j < 48; j++) {
			uint tl = RotateLeft(al + F2(bl, cl, dl) + x[RL[j]] + 0x6ed9eba1u, SL[j]) + el;
			al = el; el = dl; dl = RotateLeft(cl, 10); cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F2(br, cr, dr) + x[RR[j]] + 0x6d703ef3u, SR[j]) + er;
			ar = er; er = dr; dr = RotateLeft(cr, 10); cr = br; br = tr;
		}

		// Exchange A after round 2 (j=47)
		(al, ar) = (ar, al);

		// Round 3 (steps 48-63): Left uses F3, Right uses F1
		for (int j = 48; j < 64; j++) {
			uint tl = RotateLeft(al + F3(bl, cl, dl) + x[RL[j]] + 0x8f1bbcdcu, SL[j]) + el;
			al = el; el = dl; dl = RotateLeft(cl, 10); cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F1(br, cr, dr) + x[RR[j]] + 0x7a6d76e9u, SR[j]) + er;
			ar = er; er = dr; dr = RotateLeft(cr, 10); cr = br; br = tr;
		}

		// Exchange C after round 3 (j=63)
		(cl, cr) = (cr, cl);

		// Round 4 (steps 64-79): Left uses F4, Right uses F0
		for (int j = 64; j < 80; j++) {
			uint tl = RotateLeft(al + F4(bl, cl, dl) + x[RL[j]] + 0xa953fd4eu, SL[j]) + el;
			al = el; el = dl; dl = RotateLeft(cl, 10); cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F0(br, cr, dr) + x[RR[j]], SR[j]) + er;
			ar = er; er = dr; dr = RotateLeft(cr, 10); cr = br; br = tr;
		}

		// Exchange E after round 4 (j=79)
		(el, er) = (er, el);

		// Update state
		_stateLeft[0] += al;
		_stateLeft[1] += bl;
		_stateLeft[2] += cl;
		_stateLeft[3] += dl;
		_stateLeft[4] += el;
		_stateRight[0] += ar;
		_stateRight[1] += br;
		_stateRight[2] += cr;
		_stateRight[3] += dr;
		_stateRight[4] += er;
	}

	// ========== RIPEMD Boolean Functions ==========

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RotateLeft(uint value, int bits) =>
		(value << bits) | (value >> (32 - bits));

	/// <summary>F0(x,y,z) = x XOR y XOR z</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint F0(uint x, uint y, uint z) => x ^ y ^ z;

	/// <summary>F1(x,y,z) = (x AND y) OR (NOT x AND z)</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint F1(uint x, uint y, uint z) => (x & y) | (~x & z);

	/// <summary>F2(x,y,z) = (x OR NOT y) XOR z</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint F2(uint x, uint y, uint z) => (x | ~y) ^ z;

	/// <summary>F3(x,y,z) = (x AND z) OR (y AND NOT z)</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint F3(uint x, uint y, uint z) => (x & z) | (y & ~z);

	/// <summary>F4(x,y,z) = x XOR (y OR NOT z)</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint F4(uint x, uint y, uint z) => x ^ (y | ~z);
}

/// <summary>
/// Factory for creating RIPEMD-320 streaming hash instances.
/// </summary>
public static class Ripemd320Factory {
	/// <summary>Creates a streaming RIPEMD-320 hasher.</summary>
	public static IStreamingHashBytes CreateRipemd320() => new Ripemd320Digest();

	/// <summary>Computes RIPEMD-320 hash in one shot with minimal allocations.</summary>
	public static byte[] ComputeRipemd320(ReadOnlySpan<byte> data) {
		return ComputeRipemd320Static(data);
	}

	/// <summary>
	/// Static optimized one-shot computation using stack-allocated state.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static byte[] ComputeRipemd320Static(ReadOnlySpan<byte> data) {
		const int BlockSize = 64;
		const int HashSize = 40;

		// Stack-allocated state (5 words each for left and right lines)
		Span<uint> stateL = stackalloc uint[5];
		Span<uint> stateR = stackalloc uint[5];
		stateL[0] = 0x67452301u; stateL[1] = 0xefcdab89u; stateL[2] = 0x98badcfeu; stateL[3] = 0x10325476u; stateL[4] = 0xc3d2e1f0u;
		stateR[0] = 0x76543210u; stateR[1] = 0xfedcba98u; stateR[2] = 0x89abcdefu; stateR[3] = 0x01234567u; stateR[4] = 0x3c2d1e0fu;

		long totalBytes = data.Length;
		int offset = 0;

		while (offset + BlockSize <= data.Length) {
			ProcessBlockStatic(data.Slice(offset, BlockSize), stateL, stateR);
			offset += BlockSize;
		}

		Span<byte> finalBlock = stackalloc byte[BlockSize];
		int remaining = data.Length - offset;
		if (remaining > 0) {
			data.Slice(offset).CopyTo(finalBlock);
		}

		int padPos = remaining;
		finalBlock[padPos++] = 0x80;

		if (padPos > BlockSize - 8) {
			finalBlock.Slice(padPos).Clear();
			ProcessBlockStatic(finalBlock, stateL, stateR);
			finalBlock.Clear();
			padPos = 0;
		}

		finalBlock.Slice(padPos, BlockSize - 8 - padPos).Clear();
		BinaryPrimitives.WriteUInt64LittleEndian(finalBlock.Slice(BlockSize - 8), (ulong)(totalBytes * 8));
		ProcessBlockStatic(finalBlock, stateL, stateR);

		byte[] result = new byte[HashSize];
		for (int i = 0; i < 5; i++) {
			BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(i * 4, 4), stateL[i]);
		}
		for (int i = 0; i < 5; i++) {
			BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(20 + i * 4, 4), stateR[i]);
		}
		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlockStatic(ReadOnlySpan<byte> block, Span<uint> stateL, Span<uint> stateR) {
		ReadOnlySpan<int> RL = [
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
			3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
			1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
			4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
		];
		ReadOnlySpan<int> RR = [
			5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
			6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
			15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
			8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
			12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
		];
		ReadOnlySpan<int> SL = [
			11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
			7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
			11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
			11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
			9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
		];
		ReadOnlySpan<int> SR = [
			8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
			9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
			9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
			15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
			8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
		];

		Span<uint> x = stackalloc uint[16];
		for (int i = 0; i < 16; i++) {
			x[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(i * 4, 4));
		}

		uint al = stateL[0], bl = stateL[1], cl = stateL[2], dl = stateL[3], el = stateL[4];
		uint ar = stateR[0], br = stateR[1], cr = stateR[2], dr = stateR[3], er = stateR[4];

		// Round 0 (F0 left, F4 right)
		for (int j = 0; j < 16; j++) {
			uint tl = RotL(al + (bl ^ cl ^ dl) + x[RL[j]], SL[j]) + el;
			al = el; el = dl; dl = RotL(cl, 10); cl = bl; bl = tl;
			uint tr = RotL(ar + (br ^ (cr | ~dr)) + x[RR[j]] + 0x50a28be6u, SR[j]) + er;
			ar = er; er = dr; dr = RotL(cr, 10); cr = br; br = tr;
		}
		(bl, br) = (br, bl);

		// Round 1 (F1 left, F3 right)
		for (int j = 16; j < 32; j++) {
			uint tl = RotL(al + ((bl & cl) | (~bl & dl)) + x[RL[j]] + 0x5a827999u, SL[j]) + el;
			al = el; el = dl; dl = RotL(cl, 10); cl = bl; bl = tl;
			uint tr = RotL(ar + ((br & dr) | (cr & ~dr)) + x[RR[j]] + 0x5c4dd124u, SR[j]) + er;
			ar = er; er = dr; dr = RotL(cr, 10); cr = br; br = tr;
		}
		(dl, dr) = (dr, dl);

		// Round 2 (F2 both)
		for (int j = 32; j < 48; j++) {
			uint tl = RotL(al + ((bl | ~cl) ^ dl) + x[RL[j]] + 0x6ed9eba1u, SL[j]) + el;
			al = el; el = dl; dl = RotL(cl, 10); cl = bl; bl = tl;
			uint tr = RotL(ar + ((br | ~cr) ^ dr) + x[RR[j]] + 0x6d703ef3u, SR[j]) + er;
			ar = er; er = dr; dr = RotL(cr, 10); cr = br; br = tr;
		}
		(al, ar) = (ar, al);

		// Round 3 (F3 left, F1 right)
		for (int j = 48; j < 64; j++) {
			uint tl = RotL(al + ((bl & dl) | (cl & ~dl)) + x[RL[j]] + 0x8f1bbcdcu, SL[j]) + el;
			al = el; el = dl; dl = RotL(cl, 10); cl = bl; bl = tl;
			uint tr = RotL(ar + ((br & cr) | (~br & dr)) + x[RR[j]] + 0x7a6d76e9u, SR[j]) + er;
			ar = er; er = dr; dr = RotL(cr, 10); cr = br; br = tr;
		}
		(cl, cr) = (cr, cl);

		// Round 4 (F4 left, F0 right)
		for (int j = 64; j < 80; j++) {
			uint tl = RotL(al + (bl ^ (cl | ~dl)) + x[RL[j]] + 0xa953fd4eu, SL[j]) + el;
			al = el; el = dl; dl = RotL(cl, 10); cl = bl; bl = tl;
			uint tr = RotL(ar + (br ^ cr ^ dr) + x[RR[j]], SR[j]) + er;
			ar = er; er = dr; dr = RotL(cr, 10); cr = br; br = tr;
		}
		(el, er) = (er, el);

		stateL[0] += al; stateL[1] += bl; stateL[2] += cl; stateL[3] += dl; stateL[4] += el;
		stateR[0] += ar; stateR[1] += br; stateR[2] += cr; stateR[3] += dr; stateR[4] += er;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RotL(uint value, int bits) => (value << bits) | (value >> (32 - bits));
}
