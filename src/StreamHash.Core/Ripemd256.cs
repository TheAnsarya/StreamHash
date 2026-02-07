using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the RIPEMD-256 cryptographic hash function.
/// </summary>
/// <remarks>
/// <para>
/// RIPEMD-256 is an extended version of RIPEMD-128 with a 256-bit (32-byte) hash result.
/// It runs two parallel RIPEMD-128 instances with different initial values and exchanges
/// a chaining variable between the two parallel lines after each round.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 256 bits (32 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Structure:</b> Dual-line Merkle-Damgård construction</item>
/// <item><b>Rounds:</b> 64 compression rounds (4 rounds × 16 steps × 2 lines)</item>
/// <item><b>Security:</b> Same as RIPEMD-128 (designed for longer hash, not higher security)</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://homes.esat.kuleuven.be/~bosselae/ripemd160.html">RIPEMD Homepage</see></item>
/// <item><see href="https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd256.txt">RIPEMD-256 Pseudocode</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class Ripemd256Digest : IStreamingHashBytes {
	// ========== Constants ==========

	private const int BlockSize = 64;
	private const int HashSize = 32;

	// Initial values for the left line (same as RIPEMD-128)
	private static readonly uint[] InitialValuesLeft = [
		0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u
	];

	// Initial values for the right line (different from left)
	private static readonly uint[] InitialValuesRight = [
		0x76543210u, 0xfedcba98u, 0x89abcdefu, 0x01234567u
	];

	// Message word selection for the left line (rounds 0-3)
	private static readonly int[] RL = [
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,  // Round 0
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,  // Round 1
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,  // Round 2
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2   // Round 3
	];

	// Message word selection for the right line (rounds 0-3)
	private static readonly int[] RR = [
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,  // Round 0
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,  // Round 1
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,  // Round 2
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14   // Round 3
	];

	// Rotation amounts for the left line
	private static readonly int[] SL = [
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,    // Round 0
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,    // Round 1
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,    // Round 2
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12     // Round 3
	];

	// Rotation amounts for the right line
	private static readonly int[] SR = [
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,    // Round 0
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,    // Round 1
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,    // Round 2
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8     // Round 3
	];

	// ========== Instance Fields ==========

	private readonly uint[] _stateLeft = new uint[4];
	private readonly uint[] _stateRight = new uint[4];
	private readonly byte[] _buffer = new byte[BlockSize];
	private int _bufferPos;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;

	public Ripemd256Digest() {
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
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16, 4), _stateRight[0]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(20, 4), _stateRight[1]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(24, 4), _stateRight[2]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(28, 4), _stateRight[3]);

		return result;
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		Array.Copy(InitialValuesLeft, _stateLeft, 4);
		Array.Copy(InitialValuesRight, _stateRight, 4);
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
		uint al = _stateLeft[0], bl = _stateLeft[1], cl = _stateLeft[2], dl = _stateLeft[3];
		uint ar = _stateRight[0], br = _stateRight[1], cr = _stateRight[2], dr = _stateRight[3];

		// Round 0 (steps 0-15)
		for (int j = 0; j < 16; j++) {
			uint tl = RotateLeft(al + F0(bl, cl, dl) + x[RL[j]], SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F3(br, cr, dr) + x[RR[j]] + 0x50a28be6u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Exchange after round 0
		(al, ar) = (ar, al);

		// Round 1 (steps 16-31)
		for (int j = 16; j < 32; j++) {
			uint tl = RotateLeft(al + F1(bl, cl, dl) + x[RL[j]] + 0x5a827999u, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F2(br, cr, dr) + x[RR[j]] + 0x5c4dd124u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Exchange after round 1
		(bl, br) = (br, bl);

		// Round 2 (steps 32-47)
		for (int j = 32; j < 48; j++) {
			uint tl = RotateLeft(al + F2(bl, cl, dl) + x[RL[j]] + 0x6ed9eba1u, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F1(br, cr, dr) + x[RR[j]] + 0x6d703ef3u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Exchange after round 2
		(cl, cr) = (cr, cl);

		// Round 3 (steps 48-63)
		for (int j = 48; j < 64; j++) {
			uint tl = RotateLeft(al + F3(bl, cl, dl) + x[RL[j]] + 0x8f1bbcdcu, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F0(br, cr, dr) + x[RR[j]], SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Exchange after round 3
		(dl, dr) = (dr, dl);

		// Update state
		_stateLeft[0] += al;
		_stateLeft[1] += bl;
		_stateLeft[2] += cl;
		_stateLeft[3] += dl;
		_stateRight[0] += ar;
		_stateRight[1] += br;
		_stateRight[2] += cr;
		_stateRight[3] += dr;
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
}

/// <summary>
/// Factory for creating RIPEMD-256 streaming hash instances.
/// </summary>
public static class Ripemd256Factory {
	/// <summary>Creates a streaming RIPEMD-256 hasher.</summary>
	public static IStreamingHashBytes CreateRipemd256() => new Ripemd256Digest();

	/// <summary>Computes RIPEMD-256 hash in one shot.</summary>
	public static byte[] ComputeRipemd256(ReadOnlySpan<byte> data) {
		using var hasher = new Ripemd256Digest();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}
}
