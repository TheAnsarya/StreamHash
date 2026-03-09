using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the RIPEMD-128 cryptographic hash function.
/// </summary>
/// <remarks>
/// <para>
/// RIPEMD-128 is a 128-bit cryptographic hash function designed as a plug-in replacement
/// for MD4/MD5. It uses two parallel lines of computation (left and right) with different
/// boolean functions and constants, then combines the results into a single 128-bit hash.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 128 bits (16 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Structure:</b> Dual-line Merkle-Damgård construction</item>
/// <item><b>Rounds:</b> 64 compression rounds (4 rounds × 16 steps × 2 lines)</item>
/// <item><b>Security:</b> Provides 128-bit hash; collision resistance below modern standards</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://homes.esat.kuleuven.be/~bosselae/ripemd160.html">RIPEMD Homepage</see></item>
/// <item><see href="https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd128.txt">RIPEMD-128 Pseudocode</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class Ripemd128Digest : IStreamingHashBytes {
	// ========== Constants ==========

	private const int BlockSize = 64;
	private const int HashSize = 16;

	// Initial hash values (same as MD4/MD5)
	private static readonly uint[] InitialValues = [
		0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u
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

	private readonly uint[] _state = new uint[4];
	private readonly byte[] _buffer = new byte[BlockSize];
	private int _bufferPos;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;

	/// <summary>Initializes a new instance of the <see cref="Ripemd128Digest"/> class.</summary>
	public Ripemd128Digest() {
		Reset();
	}

	// ========== IStreamingHashBytes Implementation ==========

	/// <inheritdoc/>
	public int BlockSizeBytes => BlockSize;
	/// <inheritdoc/>
	public int DigestSize => HashSize;
	int IStreamingHashBytes.BlockSize => BlockSize;
	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
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

	/// <inheritdoc/>
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

		// Append 64-bit little-endian length
		BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(BlockSize - 8), (ulong)bitLength);
		ProcessBlock(_buffer);

		// Extract hash value (little-endian, 4 words = 16 bytes)
		byte[] result = new byte[HashSize];
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(0, 4), _state[0]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), _state[1]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8, 4), _state[2]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12, 4), _state[3]);

		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		Array.Copy(InitialValues, _state, 4);
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

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Load message words (little-endian)
		Span<uint> x = stackalloc uint[16];
		for (int i = 0; i < 16; i++) {
			x[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(i * 4, 4));
		}

		// Initialize working variables for both parallel lines from the same state
		uint al = _state[0], bl = _state[1], cl = _state[2], dl = _state[3];
		uint ar = _state[0], br = _state[1], cr = _state[2], dr = _state[3];

		// Round 0 (steps 0-15): Left uses F0, Right uses F3
		for (int j = 0; j < 16; j++) {
			uint tl = RotateLeft(al + F0(bl, cl, dl) + x[RL[j]], SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F3(br, cr, dr) + x[RR[j]] + 0x50a28be6u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Round 1 (steps 16-31): Left uses F1, Right uses F2
		for (int j = 16; j < 32; j++) {
			uint tl = RotateLeft(al + F1(bl, cl, dl) + x[RL[j]] + 0x5a827999u, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F2(br, cr, dr) + x[RR[j]] + 0x5c4dd124u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Round 2 (steps 32-47): Left uses F2, Right uses F1
		for (int j = 32; j < 48; j++) {
			uint tl = RotateLeft(al + F2(bl, cl, dl) + x[RL[j]] + 0x6ed9eba1u, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F1(br, cr, dr) + x[RR[j]] + 0x6d703ef3u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Round 3 (steps 48-63): Left uses F3, Right uses F0
		for (int j = 48; j < 64; j++) {
			uint tl = RotateLeft(al + F3(bl, cl, dl) + x[RL[j]] + 0x8f1bbcdcu, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;

			uint tr = RotateLeft(ar + F0(br, cr, dr) + x[RR[j]], SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Combine both parallel lines with circular shift finalization
		// Reference: rmd128.txt specification
		uint t = _state[1] + cl + dr;
		_state[1] = _state[2] + dl + ar;
		_state[2] = _state[3] + al + br;
		_state[3] = _state[0] + bl + cr;
		_state[0] = t;
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
/// Factory for creating RIPEMD-128 streaming hash instances.
/// </summary>
public static class Ripemd128Factory {
	/// <summary>Creates a streaming RIPEMD-128 hasher.</summary>
	public static IStreamingHashBytes CreateRipemd128() => new Ripemd128Digest();

	/// <summary>Computes RIPEMD-128 hash in one shot with minimal allocations.</summary>
	public static byte[] ComputeRipemd128(ReadOnlySpan<byte> data) {
		return ComputeRipemd128Static(data);
	}

	/// <summary>
	/// Static optimized one-shot computation using stack-allocated state.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static byte[] ComputeRipemd128Static(ReadOnlySpan<byte> data) {
		const int BlockSize = 64;
		const int HashSize = 16;

		// Stack-allocated state
		Span<uint> state = stackalloc uint[4];
		state[0] = 0x67452301u; state[1] = 0xefcdab89u; state[2] = 0x98badcfeu; state[3] = 0x10325476u;

		long totalBytes = data.Length;
		int offset = 0;

		// Process complete blocks
		while (offset + BlockSize <= data.Length) {
			ProcessBlockStatic(data.Slice(offset, BlockSize), state);
			offset += BlockSize;
		}

		// Handle final block with padding
		Span<byte> finalBlock = stackalloc byte[BlockSize];
		int remaining = data.Length - offset;
		if (remaining > 0) {
			data.Slice(offset).CopyTo(finalBlock);
		}

		// Padding
		int padPos = remaining;
		finalBlock[padPos++] = 0x80;

		if (padPos > BlockSize - 8) {
			finalBlock.Slice(padPos).Clear();
			ProcessBlockStatic(finalBlock, state);
			finalBlock.Clear();
			padPos = 0;
		}

		finalBlock.Slice(padPos, BlockSize - 8 - padPos).Clear();
		BinaryPrimitives.WriteUInt64LittleEndian(finalBlock.Slice(BlockSize - 8), (ulong)(totalBytes * 8));
		ProcessBlockStatic(finalBlock, state);

		// Output - only allocation
		byte[] result = new byte[HashSize];
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(0, 4), state[0]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), state[1]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8, 4), state[2]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12, 4), state[3]);
		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlockStatic(ReadOnlySpan<byte> block, Span<uint> state) {
		ReadOnlySpan<int> RL = [
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
			3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
			1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
		];
		ReadOnlySpan<int> RR = [
			5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
			6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
			15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
			8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
		];
		ReadOnlySpan<int> SL = [
			11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
			7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
			11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
			11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
		];
		ReadOnlySpan<int> SR = [
			8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
			9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
			9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
			15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
		];

		Span<uint> x = stackalloc uint[16];
		for (int i = 0; i < 16; i++) {
			x[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(i * 4, 4));
		}

		uint al = state[0], bl = state[1], cl = state[2], dl = state[3];
		uint ar = state[0], br = state[1], cr = state[2], dr = state[3];

		// Round 0
		for (int j = 0; j < 16; j++) {
			uint tl = RotL(al + (bl ^ cl ^ dl) + x[RL[j]], SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;
			uint tr = RotL(ar + ((br & dr) | (cr & ~dr)) + x[RR[j]] + 0x50a28be6u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Round 1
		for (int j = 16; j < 32; j++) {
			uint tl = RotL(al + ((bl & cl) | (~bl & dl)) + x[RL[j]] + 0x5a827999u, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;
			uint tr = RotL(ar + ((br | ~cr) ^ dr) + x[RR[j]] + 0x5c4dd124u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Round 2
		for (int j = 32; j < 48; j++) {
			uint tl = RotL(al + ((bl | ~cl) ^ dl) + x[RL[j]] + 0x6ed9eba1u, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;
			uint tr = RotL(ar + ((br & cr) | (~br & dr)) + x[RR[j]] + 0x6d703ef3u, SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Round 3
		for (int j = 48; j < 64; j++) {
			uint tl = RotL(al + ((bl & dl) | (cl & ~dl)) + x[RL[j]] + 0x8f1bbcdcu, SL[j]);
			al = dl; dl = cl; cl = bl; bl = tl;
			uint tr = RotL(ar + (br ^ cr ^ dr) + x[RR[j]], SR[j]);
			ar = dr; dr = cr; cr = br; br = tr;
		}

		// Combine both parallel lines with circular shift
		uint t = state[1] + cl + dr;
		state[1] = state[2] + dl + ar;
		state[2] = state[3] + al + br;
		state[3] = state[0] + bl + cr;
		state[0] = t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RotL(uint value, int bits) => (value << bits) | (value >> (32 - bits));
}
