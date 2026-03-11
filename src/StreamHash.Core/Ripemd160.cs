using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the RIPEMD-160 cryptographic hash function.
/// </summary>
/// <remarks>
/// <para>
/// RIPEMD-160 is a 160-bit cryptographic hash function designed as a strengthened
/// replacement for MD4/MD5 and RIPEMD-128. It uses two parallel lines of computation with
/// five rounds each, then combines the results into a single 160-bit hash.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 160 bits (20 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Structure:</b> Dual-line Merkle-Damgård construction</item>
/// <item><b>Rounds:</b> 80 compression rounds (5 rounds × 16 steps × 2 lines)</item>
/// <item><b>Security:</b> Provides 160-bit hash; widely used in Bitcoin and PGP</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://homes.esat.kuleuven.be/~bosselae/ripemd160.html">RIPEMD Homepage</see></item>
/// <item><see href="https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd160.txt">RIPEMD-160 Pseudocode</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class Ripemd160Digest : IStreamingHashBytes {
	// ========== Constants ==========

	private const int BlockSize = 64;
	private const int HashSize = 20;

	// Initial hash values (same as MD4/RIPEMD-128 plus 5th word)
	private static readonly uint[] InitialValues = [
		0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u
	];

	// ========== Instance Fields ==========

	private readonly uint[] _state = new uint[5];
	private readonly byte[] _buffer = new byte[BlockSize];
	private int _bufferPos;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;

	/// <summary>Initializes a new instance of the <see cref="Ripemd160Digest"/> class.</summary>
	public Ripemd160Digest() {
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

		// Extract hash value (little-endian, 5 words = 20 bytes)
		byte[] result = new byte[HashSize];
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(0, 4), _state[0]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), _state[1]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8, 4), _state[2]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12, 4), _state[3]);
		BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16, 4), _state[4]);

		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		Array.Copy(InitialValues, _state, 5);
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

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Load message words into local variables to avoid span indexing overhead
		uint x0 = BinaryPrimitives.ReadUInt32LittleEndian(block);
		uint x1 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(4));
		uint x2 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(8));
		uint x3 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12));
		uint x4 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(16));
		uint x5 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(20));
		uint x6 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(24));
		uint x7 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(28));
		uint x8 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(32));
		uint x9 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(36));
		uint x10 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(40));
		uint x11 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(44));
		uint x12 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(48));
		uint x13 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(52));
		uint x14 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(56));
		uint x15 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(60));

		uint al = _state[0], bl = _state[1], cl = _state[2], dl = _state[3], el = _state[4];
		uint ar = _state[0], br = _state[1], cr = _state[2], dr = _state[3], er = _state[4];

		uint tl, tr;

		// ═══════════════ Round 0: Left=F0, Right=F4 ═══════════════
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x0, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x5 + 0x50a28be6u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x1, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x14 + 0x50a28be6u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x2, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x7 + 0x50a28be6u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x3, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x0 + 0x50a28be6u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x4, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x9 + 0x50a28be6u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x5, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x2 + 0x50a28be6u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x6, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x11 + 0x50a28be6u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x7, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x4 + 0x50a28be6u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x8, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x13 + 0x50a28be6u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x9, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x6 + 0x50a28be6u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x10, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x15 + 0x50a28be6u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x11, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x8 + 0x50a28be6u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x12, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x1 + 0x50a28be6u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x13, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x10 + 0x50a28be6u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x14, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x3 + 0x50a28be6u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x15, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x12 + 0x50a28be6u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// ═══════════════ Round 1: Left=F1, Right=F3 ═══════════════
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x7 + 0x5a827999u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x6 + 0x5c4dd124u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x4 + 0x5a827999u, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x11 + 0x5c4dd124u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x13 + 0x5a827999u, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x3 + 0x5c4dd124u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x1 + 0x5a827999u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x7 + 0x5c4dd124u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x10 + 0x5a827999u, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x0 + 0x5c4dd124u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x6 + 0x5a827999u, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x13 + 0x5c4dd124u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x15 + 0x5a827999u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x5 + 0x5c4dd124u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x3 + 0x5a827999u, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x10 + 0x5c4dd124u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x12 + 0x5a827999u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x14 + 0x5c4dd124u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x0 + 0x5a827999u, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x15 + 0x5c4dd124u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x9 + 0x5a827999u, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x8 + 0x5c4dd124u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x5 + 0x5a827999u, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x12 + 0x5c4dd124u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x2 + 0x5a827999u, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x4 + 0x5c4dd124u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x14 + 0x5a827999u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x9 + 0x5c4dd124u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x11 + 0x5a827999u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x1 + 0x5c4dd124u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x8 + 0x5a827999u, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x2 + 0x5c4dd124u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// ═══════════════ Round 2: Left=F2, Right=F2 ═══════════════
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x3 + 0x6ed9eba1u, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x15 + 0x6d703ef3u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x10 + 0x6ed9eba1u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x5 + 0x6d703ef3u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x14 + 0x6ed9eba1u, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x1 + 0x6d703ef3u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x4 + 0x6ed9eba1u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x3 + 0x6d703ef3u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x9 + 0x6ed9eba1u, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x7 + 0x6d703ef3u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x15 + 0x6ed9eba1u, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x14 + 0x6d703ef3u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x8 + 0x6ed9eba1u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x6 + 0x6d703ef3u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x1 + 0x6ed9eba1u, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x9 + 0x6d703ef3u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x2 + 0x6ed9eba1u, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x11 + 0x6d703ef3u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x7 + 0x6ed9eba1u, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x8 + 0x6d703ef3u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x0 + 0x6ed9eba1u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x12 + 0x6d703ef3u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x6 + 0x6ed9eba1u, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x2 + 0x6d703ef3u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x13 + 0x6ed9eba1u, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x10 + 0x6d703ef3u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x11 + 0x6ed9eba1u, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x0 + 0x6d703ef3u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x5 + 0x6ed9eba1u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x4 + 0x6d703ef3u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x12 + 0x6ed9eba1u, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x13 + 0x6d703ef3u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// ═══════════════ Round 3: Left=F3, Right=F1 ═══════════════
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x1 + 0x8f1bbcdcu, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x8 + 0x7a6d76e9u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x9 + 0x8f1bbcdcu, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x6 + 0x7a6d76e9u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x11 + 0x8f1bbcdcu, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x4 + 0x7a6d76e9u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x10 + 0x8f1bbcdcu, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x1 + 0x7a6d76e9u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x0 + 0x8f1bbcdcu, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x3 + 0x7a6d76e9u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x8 + 0x8f1bbcdcu, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x11 + 0x7a6d76e9u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x12 + 0x8f1bbcdcu, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x15 + 0x7a6d76e9u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x4 + 0x8f1bbcdcu, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x0 + 0x7a6d76e9u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x13 + 0x8f1bbcdcu, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x5 + 0x7a6d76e9u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x3 + 0x8f1bbcdcu, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x12 + 0x7a6d76e9u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x7 + 0x8f1bbcdcu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x2 + 0x7a6d76e9u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x15 + 0x8f1bbcdcu, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x13 + 0x7a6d76e9u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x14 + 0x8f1bbcdcu, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x9 + 0x7a6d76e9u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x5 + 0x8f1bbcdcu, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x7 + 0x7a6d76e9u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x6 + 0x8f1bbcdcu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x10 + 0x7a6d76e9u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x2 + 0x8f1bbcdcu, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x14 + 0x7a6d76e9u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// ═══════════════ Round 4: Left=F4, Right=F0 ═══════════════
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x4 + 0xa953fd4eu, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x12, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x0 + 0xa953fd4eu, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x15, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x5 + 0xa953fd4eu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x10, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x9 + 0xa953fd4eu, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x4, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x7 + 0xa953fd4eu, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x1, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x12 + 0xa953fd4eu, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x5, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x2 + 0xa953fd4eu, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x8, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x10 + 0xa953fd4eu, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x7, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x14 + 0xa953fd4eu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x6, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x1 + 0xa953fd4eu, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x2, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x3 + 0xa953fd4eu, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x13, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x8 + 0xa953fd4eu, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x14, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x11 + 0xa953fd4eu, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x0, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x6 + 0xa953fd4eu, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x3, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x15 + 0xa953fd4eu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x9, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x13 + 0xa953fd4eu, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x11, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// Combine both parallel lines
		uint t = _state[1] + cl + dr;
		_state[1] = _state[2] + dl + er;
		_state[2] = _state[3] + el + ar;
		_state[3] = _state[4] + al + br;
		_state[4] = _state[0] + bl + cr;
		_state[0] = t;
	}
}

/// <summary>
/// Factory for creating RIPEMD-160 streaming hash instances.
/// </summary>
public static class Ripemd160Factory {
	/// <summary>Creates a streaming RIPEMD-160 hasher.</summary>
	public static IStreamingHashBytes CreateRipemd160() => new Ripemd160Digest();

	/// <summary>Computes RIPEMD-160 hash in one shot with minimal allocations.</summary>
	public static byte[] ComputeRipemd160(ReadOnlySpan<byte> data) {
		return ComputeRipemd160Static(data);
	}

	/// <summary>
	/// Static optimized one-shot computation using stack-allocated state.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static byte[] ComputeRipemd160Static(ReadOnlySpan<byte> data) {
		const int BlockSize = 64;
		const int HashSize = 20;

		// Stack-allocated state (5 words)
		Span<uint> state = stackalloc uint[5];
		state[0] = 0x67452301u; state[1] = 0xefcdab89u; state[2] = 0x98badcfeu; state[3] = 0x10325476u; state[4] = 0xc3d2e1f0u;

		long totalBytes = data.Length;
		int offset = 0;

		while (offset + BlockSize <= data.Length) {
			ProcessBlockStatic(data.Slice(offset, BlockSize), state);
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
			ProcessBlockStatic(finalBlock, state);
			finalBlock.Clear();
			padPos = 0;
		}

		finalBlock.Slice(padPos, BlockSize - 8 - padPos).Clear();
		BinaryPrimitives.WriteUInt64LittleEndian(finalBlock.Slice(BlockSize - 8), (ulong)(totalBytes * 8));
		ProcessBlockStatic(finalBlock, state);

		byte[] result = new byte[HashSize];
		for (int i = 0; i < 5; i++) {
			BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(i * 4, 4), state[i]);
		}
		return result;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlockStatic(ReadOnlySpan<byte> block, Span<uint> state) {
		uint x0 = BinaryPrimitives.ReadUInt32LittleEndian(block);
		uint x1 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(4));
		uint x2 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(8));
		uint x3 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12));
		uint x4 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(16));
		uint x5 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(20));
		uint x6 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(24));
		uint x7 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(28));
		uint x8 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(32));
		uint x9 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(36));
		uint x10 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(40));
		uint x11 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(44));
		uint x12 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(48));
		uint x13 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(52));
		uint x14 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(56));
		uint x15 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(60));

		uint al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
		uint ar = state[0], br = state[1], cr = state[2], dr = state[3], er = state[4];
		uint tl, tr;

		// Round 0: Left=F0, Right=F4
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x0, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x5 + 0x50a28be6u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x1, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x14 + 0x50a28be6u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x2, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x7 + 0x50a28be6u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x3, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x0 + 0x50a28be6u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x4, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x9 + 0x50a28be6u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x5, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x2 + 0x50a28be6u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x6, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x11 + 0x50a28be6u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x7, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x4 + 0x50a28be6u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x8, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x13 + 0x50a28be6u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x9, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x6 + 0x50a28be6u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x10, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x15 + 0x50a28be6u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x11, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x8 + 0x50a28be6u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x12, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x1 + 0x50a28be6u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x13, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x10 + 0x50a28be6u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x14, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x3 + 0x50a28be6u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ cl ^ dl) + x15, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ (cr | ~dr)) + x12 + 0x50a28be6u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// Round 1: Left=F1, Right=F3
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x7 + 0x5a827999u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x6 + 0x5c4dd124u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x4 + 0x5a827999u, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x11 + 0x5c4dd124u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x13 + 0x5a827999u, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x3 + 0x5c4dd124u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x1 + 0x5a827999u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x7 + 0x5c4dd124u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x10 + 0x5a827999u, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x0 + 0x5c4dd124u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x6 + 0x5a827999u, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x13 + 0x5c4dd124u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x15 + 0x5a827999u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x5 + 0x5c4dd124u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x3 + 0x5a827999u, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x10 + 0x5c4dd124u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x12 + 0x5a827999u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x14 + 0x5c4dd124u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x0 + 0x5a827999u, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x15 + 0x5c4dd124u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x9 + 0x5a827999u, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x8 + 0x5c4dd124u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x5 + 0x5a827999u, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x12 + 0x5c4dd124u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x2 + 0x5a827999u, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x4 + 0x5c4dd124u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x14 + 0x5a827999u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x9 + 0x5c4dd124u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x11 + 0x5a827999u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x1 + 0x5c4dd124u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & cl) | (~bl & dl)) + x8 + 0x5a827999u, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & dr) | (cr & ~dr)) + x2 + 0x5c4dd124u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// Round 2: Left=F2, Right=F2
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x3 + 0x6ed9eba1u, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x15 + 0x6d703ef3u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x10 + 0x6ed9eba1u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x5 + 0x6d703ef3u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x14 + 0x6ed9eba1u, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x1 + 0x6d703ef3u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x4 + 0x6ed9eba1u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x3 + 0x6d703ef3u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x9 + 0x6ed9eba1u, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x7 + 0x6d703ef3u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x15 + 0x6ed9eba1u, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x14 + 0x6d703ef3u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x8 + 0x6ed9eba1u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x6 + 0x6d703ef3u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x1 + 0x6ed9eba1u, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x9 + 0x6d703ef3u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x2 + 0x6ed9eba1u, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x11 + 0x6d703ef3u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x7 + 0x6ed9eba1u, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x8 + 0x6d703ef3u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x0 + 0x6ed9eba1u, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x12 + 0x6d703ef3u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x6 + 0x6ed9eba1u, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x2 + 0x6d703ef3u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x13 + 0x6ed9eba1u, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x10 + 0x6d703ef3u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x11 + 0x6ed9eba1u, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x0 + 0x6d703ef3u, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x5 + 0x6ed9eba1u, 7) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x4 + 0x6d703ef3u, 7) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl | ~cl) ^ dl) + x12 + 0x6ed9eba1u, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br | ~cr) ^ dr) + x13 + 0x6d703ef3u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// Round 3: Left=F3, Right=F1
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x1 + 0x8f1bbcdcu, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x8 + 0x7a6d76e9u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x9 + 0x8f1bbcdcu, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x6 + 0x7a6d76e9u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x11 + 0x8f1bbcdcu, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x4 + 0x7a6d76e9u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x10 + 0x8f1bbcdcu, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x1 + 0x7a6d76e9u, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x0 + 0x8f1bbcdcu, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x3 + 0x7a6d76e9u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x8 + 0x8f1bbcdcu, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x11 + 0x7a6d76e9u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x12 + 0x8f1bbcdcu, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x15 + 0x7a6d76e9u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x4 + 0x8f1bbcdcu, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x0 + 0x7a6d76e9u, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x13 + 0x8f1bbcdcu, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x5 + 0x7a6d76e9u, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x3 + 0x8f1bbcdcu, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x12 + 0x7a6d76e9u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x7 + 0x8f1bbcdcu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x2 + 0x7a6d76e9u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x15 + 0x8f1bbcdcu, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x13 + 0x7a6d76e9u, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x14 + 0x8f1bbcdcu, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x9 + 0x7a6d76e9u, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x5 + 0x8f1bbcdcu, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x7 + 0x7a6d76e9u, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x6 + 0x8f1bbcdcu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x10 + 0x7a6d76e9u, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + ((bl & dl) | (cl & ~dl)) + x2 + 0x8f1bbcdcu, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + ((br & cr) | (~br & dr)) + x14 + 0x7a6d76e9u, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		// Round 4: Left=F4, Right=F0
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x4 + 0xa953fd4eu, 9) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x12, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x0 + 0xa953fd4eu, 15) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x15, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x5 + 0xa953fd4eu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x10, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x9 + 0xa953fd4eu, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x4, 9) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x7 + 0xa953fd4eu, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x1, 12) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x12 + 0xa953fd4eu, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x5, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x2 + 0xa953fd4eu, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x8, 14) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x10 + 0xa953fd4eu, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x7, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x14 + 0xa953fd4eu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x6, 8) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x1 + 0xa953fd4eu, 12) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x2, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x3 + 0xa953fd4eu, 13) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x13, 6) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x8 + 0xa953fd4eu, 14) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x14, 5) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x11 + 0xa953fd4eu, 11) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x0, 15) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x6 + 0xa953fd4eu, 8) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x3, 13) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x15 + 0xa953fd4eu, 5) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x9, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;
		tl = BitOperations.RotateLeft(al + (bl ^ (cl | ~dl)) + x13 + 0xa953fd4eu, 6) + el; al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = tl;
		tr = BitOperations.RotateLeft(ar + (br ^ cr ^ dr) + x11, 11) + er; ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = tr;

		uint t = state[1] + cl + dr;
		state[1] = state[2] + dl + er;
		state[2] = state[3] + el + ar;
		state[3] = state[4] + al + br;
		state[4] = state[0] + bl + cr;
		state[0] = t;
	}
}
