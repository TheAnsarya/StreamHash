namespace StreamHash.Core;

/// <summary>
/// SHA-0 streaming hash implementation.
/// SHA-0 is the original SHA algorithm (FIPS 180) without the rotation in message expansion.
/// Note: SHA-0 is cryptographically broken and should never be used for security.
/// </summary>
internal sealed class Sha0StreamingHash : IStreamingHashBytes {
	private const int DigestLength = 20;
	private const int BlockLength = 64;

	// State variables (same initial values as SHA-1)
	private uint _h0 = 0x67452301;
	private uint _h1 = 0xefcdab89;
	private uint _h2 = 0x98badcfe;
	private uint _h3 = 0x10325476;
	private uint _h4 = 0xc3d2e1f0;

	private readonly byte[] _buffer = new byte[BlockLength];
	private int _bufferOffset;
	private long _totalBytes;

	public int BlockSize => BlockLength;
	public int DigestSize => DigestLength;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		_totalBytes += data.Length;
		int offset = 0;

		// If we have data in the buffer, fill it first
		if (_bufferOffset > 0) {
			int toCopy = Math.Min(BlockLength - _bufferOffset, data.Length);
			data.Slice(0, toCopy).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += toCopy;
			offset += toCopy;

			if (_bufferOffset == BlockLength) {
				ProcessBlock(_buffer);
				_bufferOffset = 0;
			}
		}

		// Process complete blocks directly
		while (offset + BlockLength <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockLength));
			offset += BlockLength;
		}

		// Copy remaining data to buffer
		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += data.Length - offset;
		}
	}

	public byte[] FinalizeBytes() {
		// Padding
		long bitLength = _totalBytes * 8;
		int paddingLength = (BlockLength - 9 - _bufferOffset % BlockLength + BlockLength) % BlockLength + 1;

		Span<byte> padding = stackalloc byte[paddingLength + 8];
		padding[0] = 0x80;
		padding.Slice(1, paddingLength - 1).Clear();

		// Big-endian bit length
		for (int i = 0; i < 8; i++) {
			padding[paddingLength + i] = (byte)(bitLength >> (56 - i * 8));
		}

		Update(padding);

		// Output hash
		byte[] result = new byte[DigestLength];
		WriteUInt32BE(_h0, result, 0);
		WriteUInt32BE(_h1, result, 4);
		WriteUInt32BE(_h2, result, 8);
		WriteUInt32BE(_h3, result, 12);
		WriteUInt32BE(_h4, result, 16);

		return result;
	}

	public void Reset() {
		_h0 = 0x67452301;
		_h1 = 0xefcdab89;
		_h2 = 0x98badcfe;
		_h3 = 0x10325476;
		_h4 = 0xc3d2e1f0;
		_bufferOffset = 0;
		_totalBytes = 0;
		Array.Clear(_buffer);
	}

	public void Dispose() {
		// Clear sensitive data
		Array.Clear(_buffer);
	}

	private void ProcessBlock(ReadOnlySpan<byte> block) {
		Span<uint> w = stackalloc uint[80];

		// Load message into first 16 words
		for (int i = 0; i < 16; i++) {
			w[i] = ReadUInt32BE(block, i * 4);
		}

		// SHA-0 expansion: NO rotation (unlike SHA-1 which rotates by 1)
		for (int i = 16; i < 80; i++) {
			w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
			// SHA-1 would do: w[i] = RotateLeft(w[i], 1);
		}

		uint a = _h0, b = _h1, c = _h2, d = _h3, e = _h4;

		// Main loop
		for (int i = 0; i < 20; i++) {
			uint f = (b & c) | (~b & d);
			uint temp = RotateLeft(a, 5) + f + e + 0x5a827999 + w[i];
			e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
		}

		for (int i = 20; i < 40; i++) {
			uint f = b ^ c ^ d;
			uint temp = RotateLeft(a, 5) + f + e + 0x6ed9eba1 + w[i];
			e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
		}

		for (int i = 40; i < 60; i++) {
			uint f = (b & c) | (b & d) | (c & d);
			uint temp = RotateLeft(a, 5) + f + e + 0x8f1bbcdc + w[i];
			e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
		}

		for (int i = 60; i < 80; i++) {
			uint f = b ^ c ^ d;
			uint temp = RotateLeft(a, 5) + f + e + 0xca62c1d6 + w[i];
			e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
		}

		_h0 += a; _h1 += b; _h2 += c; _h3 += d; _h4 += e;
	}

	private static uint RotateLeft(uint x, int n) => (x << n) | (x >> (32 - n));
	private static uint ReadUInt32BE(ReadOnlySpan<byte> data, int offset) =>
		((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) | ((uint)data[offset + 2] << 8) | data[offset + 3];
	private static void WriteUInt32BE(uint value, byte[] data, int offset) {
		data[offset] = (byte)(value >> 24);
		data[offset + 1] = (byte)(value >> 16);
		data[offset + 2] = (byte)(value >> 8);
		data[offset + 3] = (byte)value;
	}
}
