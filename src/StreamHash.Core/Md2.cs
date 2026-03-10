using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the MD2 message-digest algorithm.
/// </summary>
/// <remarks>
/// <para>
/// MD2 is a 128-bit cryptographic hash function designed by Ronald Rivest in 1989.
/// Unlike MD4 and MD5 which use Merkle-Damgård construction, MD2 uses a unique
/// substitution-permutation design based on a random permutation of bytes (the Pi
/// substitution table, derived from the digits of pi).
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 128 bits (16 bytes)</item>
/// <item><b>Block Size:</b> 128 bits (16 bytes)</item>
/// <item><b>Structure:</b> Substitution-permutation network (NOT Merkle-Damgård)</item>
/// <item><b>Rounds:</b> 18 rounds per block</item>
/// <item><b>Security:</b> Cryptographically broken; use only for legacy compatibility</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://datatracker.ietf.org/doc/html/rfc1319">RFC 1319 - The MD2 Message-Digest Algorithm</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeMd2Digest : IStreamingHashBytes {
	private const int BlockSizeValue = 16;
	private const int DigestSizeValue = 16;

	// Pi substitution table (S-box), derived from digits of pi
	// This is the random permutation of {0, 1, ..., 255} specified in RFC 1319
	private static readonly byte[] S = [
		41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
		98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
		30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
		190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
		169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
		128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
		255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
		79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
		69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
		27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
		85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
		44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
		106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
		120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
		242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
		49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20
	];

	// MD2 state: 48-byte auxiliary buffer X, 16-byte checksum C, 16-byte message digest state
	private readonly byte[] _x = new byte[48];
	private readonly byte[] _checksum = new byte[16];
	private readonly byte[] _buffer = new byte[BlockSizeValue];
	private int _bufferOffset;
	private long _totalBytes;

	/// <summary>
	/// Creates a new MD2 streaming hash instance.
	/// </summary>
	public NativeMd2Digest() {
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
				UpdateChecksum(_buffer);
				_bufferOffset = 0;
			}
		}

		while (offset + BlockSizeValue <= data.Length) {
			var block = data.Slice(offset, BlockSizeValue);
			ProcessBlock(block);
			UpdateChecksum(block);
			offset += BlockSizeValue;
		}

		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += data.Length - offset;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		// MD2 padding: pad with byte value equal to number of padding bytes needed
		int padLen = BlockSizeValue - _bufferOffset;
		Span<byte> padding = stackalloc byte[padLen];
		padding.Fill((byte)padLen);

		// Process the padding as data
		padding.CopyTo(_buffer.AsSpan(_bufferOffset));
		ProcessBlock(_buffer);
		UpdateChecksum(_buffer);

		// Process the checksum as a final block
		ProcessBlock(_checksum);

		// The hash is the first 16 bytes of _x (the message digest state)
		byte[] result = new byte[DigestSizeValue];
		Array.Copy(_x, 0, result, 0, DigestSizeValue);
		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		Array.Clear(_x);
		Array.Clear(_checksum);
		Array.Clear(_buffer);
		_bufferOffset = 0;
		_totalBytes = 0;
	}

	/// <inheritdoc/>
	public void Dispose() {
		Array.Clear(_x);
		Array.Clear(_checksum);
		Array.Clear(_buffer);
	}

	/// <summary>
	/// Processes one 16-byte block through the MD2 compression function.
	/// </summary>
	/// <remarks>
	/// Per RFC 1319 Step 3: 18 rounds of substitution using the Pi table.
	/// X[0..15] holds the running message digest state,
	/// X[16..31] is the current message block,
	/// X[32..47] is the XOR of the above.
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Copy block into X[16..31] and compute X[32..47] = X[0..15] ^ block
		for (int i = 0; i < 16; i++) {
			_x[16 + i] = block[i];
			_x[32 + i] = (byte)(_x[i] ^ block[i]);
		}

		// 18 rounds of substitution
		int t = 0;
		for (int round = 0; round < 18; round++) {
			for (int k = 0; k < 48; k++) {
				t = _x[k] ^ S[t];
				_x[k] = (byte)t;
			}
			t = (t + round) & 0xff;
		}
	}

	/// <summary>
	/// Updates the MD2 checksum with one 16-byte block.
	/// </summary>
	/// <remarks>
	/// Per RFC 1319 Step 2: The running checksum C is updated using the Pi table.
	/// </remarks>
	private void UpdateChecksum(ReadOnlySpan<byte> block) {
		int l = _checksum[15];
		for (int i = 0; i < 16; i++) {
			l = _checksum[i] ^ S[block[i] ^ l];
			_checksum[i] = (byte)l;
		}
	}
}

/// <summary>
/// Factory methods for creating native MD2 streaming hash instances.
/// </summary>
internal static class Md2Factory {
	/// <summary>
	/// Creates an MD2 streaming hash instance.
	/// </summary>
	/// <returns>A new MD2 streaming hash.</returns>
	public static IStreamingHashBytes CreateMd2() => new NativeMd2Digest();

	/// <summary>
	/// Computes MD2 hash in one shot with minimal allocations.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 16-byte MD2 hash.</returns>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeMd2(ReadOnlySpan<byte> data) {
		using var hasher = new NativeMd2Digest();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}
}
