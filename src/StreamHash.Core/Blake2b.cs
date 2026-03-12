using System.Buffers.Binary;
using System.Runtime.CompilerServices;
namespace StreamHash.Core;
/// <summary>
/// High-performance streaming implementation of the BLAKE2b cryptographic hash function (RFC 7693).
/// </summary>
/// <remarks>
/// <para>
/// BLAKE2b is a cryptographic hash function optimized for 64-bit platforms. It produces digests
/// from 1 to 64 bytes and processes data in 128-byte blocks. The algorithm uses 12 rounds of
/// a compression function based on a modified ChaCha quarter-round.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 1-64 bytes (configurable)</item>
/// <item><b>Block Size:</b> 128 bytes</item>
/// <item><b>Rounds:</b> 12</item>
/// <item><b>Word Size:</b> 64-bit, little-endian</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://www.rfc-editor.org/rfc/rfc7693">RFC 7693 - The BLAKE2 Cryptographic Hash and MAC</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeBlake2bDigest : IStreamingHashBytes {
private const int BlockSizeValue = 128;
private const int Rounds = 12;
private readonly int _digestSize;
private readonly ulong[] _h = new ulong[8];
private readonly byte[] _buffer = new byte[BlockSizeValue];
private int _bufferOffset;
private ulong _t0, _t1; // counter
/// <summary>
/// BLAKE2b initialization vector (first 8 primes, fractional parts of square roots).
/// </summary>
private static readonly ulong[] IV = [
0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
0x510e527fade682d1, 0x9b05688c2b3e6c1f,
0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];
/// <summary>
/// BLAKE2 message schedule permutation sigma (flat array, 12 rows x 16 columns).
/// Retained for the reference G function; the hot-path Compress is fully unrolled.
/// </summary>
private static ReadOnlySpan<byte> Sigma => [
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
];
/// <summary>
/// Creates a new BLAKE2b streaming hash instance.
/// </summary>
/// <param name="digestSize">Output size in bytes (1-64). Default is 64.</param>
public NativeBlake2bDigest(int digestSize = 64) {
ArgumentOutOfRangeException.ThrowIfLessThan(digestSize, 1);
ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSize, 64);
_digestSize = digestSize;
Reset();
}
/// <inheritdoc/>
public int BlockSize => BlockSizeValue;
/// <inheritdoc/>
public int DigestSize => _digestSize;
/// <inheritdoc/>
public long TotalBytesProcessed => (long)_t0;
/// <inheritdoc/>
public void Update(ReadOnlySpan<byte> data) {
int offset = 0;
int remaining = data.Length;
// If we have buffered data and new data fills the block
if (_bufferOffset > 0) {
int space = BlockSizeValue - _bufferOffset;
if (remaining > space) {
data.Slice(offset, space).CopyTo(_buffer.AsSpan(_bufferOffset));
_bufferOffset = BlockSizeValue;
offset += space;
remaining -= space;
IncrementCounter(BlockSizeValue);
Compress(_buffer, false);
_bufferOffset = 0;
} else {
data.Slice(offset, remaining).CopyTo(_buffer.AsSpan(_bufferOffset));
_bufferOffset += remaining;
return;
}
}
// Process full blocks, but keep at least one byte for finalization
while (remaining > BlockSizeValue) {
IncrementCounter(BlockSizeValue);
Compress(data.Slice(offset, BlockSizeValue), false);
offset += BlockSizeValue;
remaining -= BlockSizeValue;
}
// Buffer remaining bytes
if (remaining > 0) {
data.Slice(offset, remaining).CopyTo(_buffer.AsSpan());
_bufferOffset = remaining;
}
}
/// <inheritdoc/>
public byte[] FinalizeBytes() {
// Pad with zeros
Array.Clear(_buffer, _bufferOffset, BlockSizeValue - _bufferOffset);
IncrementCounter(_bufferOffset);
Compress(_buffer, true);
// Produce output
byte[] result = new byte[_digestSize];
Span<byte> output = result.AsSpan();
Span<byte> temp = stackalloc byte[8];
for (int i = 0; i < 8 && i * 8 < _digestSize; i++) {
int bytesToWrite = Math.Min(8, _digestSize - i * 8);
BinaryPrimitives.WriteUInt64LittleEndian(temp, _h[i]);
temp[..bytesToWrite].CopyTo(output[(i * 8)..]);
}
return result;
}
/// <inheritdoc/>
public void Reset() {
Array.Copy(IV, _h, 8);
// XOR parameter block into h[0]: digest length, fanout=1, depth=1
_h[0] ^= 0x01010000UL | (uint)_digestSize;
_bufferOffset = 0;
_t0 = 0;
_t1 = 0;
Array.Clear(_buffer);
}
/// <inheritdoc/>
public void Dispose() {
// No unmanaged resources
}
/// <summary>
/// Increments the 128-bit counter by the given number of bytes.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveInlining)]
private void IncrementCounter(int inc) {
_t0 += (ulong)inc;
if (_t0 < (ulong)inc) {
_t1++;
}
}
/// <summary>
/// BLAKE2b compression function. Processes one 128-byte block.
/// Fully unrolled with local message word variables to eliminate all Span bounds checks.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveOptimization)]
[SkipLocalsInit]
private void Compress(ReadOnlySpan<byte> block, bool isFinal) {
// Parse message block into 16 64-bit local variables (eliminates all Span indexing)
ulong m0 = BinaryPrimitives.ReadUInt64LittleEndian(block);
ulong m1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);
ulong m2 = BinaryPrimitives.ReadUInt64LittleEndian(block[16..]);
ulong m3 = BinaryPrimitives.ReadUInt64LittleEndian(block[24..]);
ulong m4 = BinaryPrimitives.ReadUInt64LittleEndian(block[32..]);
ulong m5 = BinaryPrimitives.ReadUInt64LittleEndian(block[40..]);
ulong m6 = BinaryPrimitives.ReadUInt64LittleEndian(block[48..]);
ulong m7 = BinaryPrimitives.ReadUInt64LittleEndian(block[56..]);
ulong m8 = BinaryPrimitives.ReadUInt64LittleEndian(block[64..]);
ulong m9 = BinaryPrimitives.ReadUInt64LittleEndian(block[72..]);
ulong m10 = BinaryPrimitives.ReadUInt64LittleEndian(block[80..]);
ulong m11 = BinaryPrimitives.ReadUInt64LittleEndian(block[88..]);
ulong m12 = BinaryPrimitives.ReadUInt64LittleEndian(block[96..]);
ulong m13 = BinaryPrimitives.ReadUInt64LittleEndian(block[104..]);
ulong m14 = BinaryPrimitives.ReadUInt64LittleEndian(block[112..]);
ulong m15 = BinaryPrimitives.ReadUInt64LittleEndian(block[120..]);
// Initialize working vector as local variables (no array/Span bounds checks)
ulong v0 = _h[0], v1 = _h[1], v2 = _h[2], v3 = _h[3];
ulong v4 = _h[4], v5 = _h[5], v6 = _h[6], v7 = _h[7];
ulong v8 = IV[0], v9 = IV[1], v10 = IV[2], v11 = IV[3];
ulong v12 = IV[4] ^ _t0;
ulong v13 = IV[5] ^ _t1;
ulong v14 = isFinal ? IV[6] ^ 0xffffffffffffffff : IV[6];
ulong v15 = IV[7];
// 12 rounds of mixing, fully unrolled with hardcoded sigma permutations
		// Round 0
		v0 += v4 + m0; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m1; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m2; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m3; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m4; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m5; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m6; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m7; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m8; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m9; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m10; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m11; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m12; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m13; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m14; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m15; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 1
		v0 += v4 + m14; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m10; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m4; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m8; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m9; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m15; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m13; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m6; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m1; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m12; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m0; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m2; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m11; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m7; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m5; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m3; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 2
		v0 += v4 + m11; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m8; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m12; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m0; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m5; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m2; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m15; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m13; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m10; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m14; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m3; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m6; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m7; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m1; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m9; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m4; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 3
		v0 += v4 + m7; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m9; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m3; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m1; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m13; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m12; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m11; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m14; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m2; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m6; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m5; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m10; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m4; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m0; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m15; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m8; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 4
		v0 += v4 + m9; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m0; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m5; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m7; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m2; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m4; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m10; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m15; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m14; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m1; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m11; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m12; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m6; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m8; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m3; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m13; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 5
		v0 += v4 + m2; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m12; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m6; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m10; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m0; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m11; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m8; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m3; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m4; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m13; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m7; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m5; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m15; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m14; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m1; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m9; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 6
		v0 += v4 + m12; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m5; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m1; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m15; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m14; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m13; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m4; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m10; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m0; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m7; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m6; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m3; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m9; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m2; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m8; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m11; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 7
		v0 += v4 + m13; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m11; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m7; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m14; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m12; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m1; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m3; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m9; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m5; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m0; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m15; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m4; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m8; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m6; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m2; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m10; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 8
		v0 += v4 + m6; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m15; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m14; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m9; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m11; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m3; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m0; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m8; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m12; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m2; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m13; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m7; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m1; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m4; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m10; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m5; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 9
		v0 += v4 + m10; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m2; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m8; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m4; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m7; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m6; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m1; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m5; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m15; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m11; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m9; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m14; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m3; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m12; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m13; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m0; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 10
		v0 += v4 + m0; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m1; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m2; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m3; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m4; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m5; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m6; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m7; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m8; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m9; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m10; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m11; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m12; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m13; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m14; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m15; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


		// Round 11
		v0 += v4 + m14; v12 = ulong.RotateRight(v12 ^ v0, 32);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 24);
		v0 += v4 + m10; v12 = ulong.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = ulong.RotateRight(v4 ^ v8, 63);

		v1 += v5 + m4; v13 = ulong.RotateRight(v13 ^ v1, 32);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 24);
		v1 += v5 + m8; v13 = ulong.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = ulong.RotateRight(v5 ^ v9, 63);

		v2 += v6 + m9; v14 = ulong.RotateRight(v14 ^ v2, 32);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 24);
		v2 += v6 + m15; v14 = ulong.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = ulong.RotateRight(v6 ^ v10, 63);

		v3 += v7 + m13; v15 = ulong.RotateRight(v15 ^ v3, 32);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 24);
		v3 += v7 + m6; v15 = ulong.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = ulong.RotateRight(v7 ^ v11, 63);

		v0 += v5 + m1; v15 = ulong.RotateRight(v15 ^ v0, 32);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 24);
		v0 += v5 + m12; v15 = ulong.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = ulong.RotateRight(v5 ^ v10, 63);

		v1 += v6 + m0; v12 = ulong.RotateRight(v12 ^ v1, 32);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 24);
		v1 += v6 + m2; v12 = ulong.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = ulong.RotateRight(v6 ^ v11, 63);

		v2 += v7 + m11; v13 = ulong.RotateRight(v13 ^ v2, 32);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 24);
		v2 += v7 + m7; v13 = ulong.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = ulong.RotateRight(v7 ^ v8, 63);

		v3 += v4 + m5; v14 = ulong.RotateRight(v14 ^ v3, 32);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 24);
		v3 += v4 + m3; v14 = ulong.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = ulong.RotateRight(v4 ^ v9, 63);


// Finalize: XOR upper and lower halves back into state
_h[0] ^= v0 ^ v8;
_h[1] ^= v1 ^ v9;
_h[2] ^= v2 ^ v10;
_h[3] ^= v3 ^ v11;
_h[4] ^= v4 ^ v12;
_h[5] ^= v5 ^ v13;
_h[6] ^= v6 ^ v14;
_h[7] ^= v7 ^ v15;
}
/// <summary>
/// BLAKE2b G mixing function (retained for reference; hot path uses fully unrolled version).
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveInlining)]
private static void G(Span<ulong> v, Span<ulong> m, int round, int a, int b, int c, int d, int i) {
int s0 = Sigma[round * 16 + 2 * i];
int s1 = Sigma[round * 16 + 2 * i + 1];
v[a] += v[b] + m[s0];
v[d] = ulong.RotateRight(v[d] ^ v[a], 32);
v[c] += v[d];
v[b] = ulong.RotateRight(v[b] ^ v[c], 24);
v[a] += v[b] + m[s1];
v[d] = ulong.RotateRight(v[d] ^ v[a], 16);
v[c] += v[d];
v[b] = ulong.RotateRight(v[b] ^ v[c], 63);
}
}
/// <summary>
/// High-performance streaming implementation of the BLAKE2s cryptographic hash function (RFC 7693).
/// </summary>
/// <remarks>
/// <para>
/// BLAKE2s is a cryptographic hash function optimized for 8-to-32-bit platforms. It produces digests
/// from 1 to 32 bytes and processes data in 64-byte blocks. The algorithm uses 10 rounds of
/// a compression function based on a modified ChaCha quarter-round.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 1-32 bytes (configurable)</item>
/// <item><b>Block Size:</b> 64 bytes</item>
/// <item><b>Rounds:</b> 10</item>
/// <item><b>Word Size:</b> 32-bit, little-endian</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://www.rfc-editor.org/rfc/rfc7693">RFC 7693 - The BLAKE2 Cryptographic Hash and MAC</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeBlake2sDigest : IStreamingHashBytes {
private const int BlockSizeValue = 64;
private const int Rounds = 10;
private readonly int _digestSize;
private readonly uint[] _h = new uint[8];
private readonly byte[] _buffer = new byte[BlockSizeValue];
private int _bufferOffset;
private uint _t0, _t1; // counter
/// <summary>
/// BLAKE2s initialization vector (first 8 primes, fractional parts of square roots).
/// </summary>
private static readonly uint[] IV = [
0x6a09e667, 0xbb67ae85,
0x3c6ef372, 0xa54ff53a,
0x510e527f, 0x9b05688c,
0x1f83d9ab, 0x5be0cd19
];
/// <summary>
/// BLAKE2 message schedule permutation sigma (flat array, 10 rows x 16 columns).
/// Retained for the reference G function; the hot-path Compress is fully unrolled.
/// </summary>
private static ReadOnlySpan<byte> Sigma => [
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
];
/// <summary>
/// Creates a new BLAKE2s streaming hash instance.
/// </summary>
/// <param name="digestSize">Output size in bytes (1-32). Default is 32.</param>
public NativeBlake2sDigest(int digestSize = 32) {
ArgumentOutOfRangeException.ThrowIfLessThan(digestSize, 1);
ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSize, 32);
_digestSize = digestSize;
Reset();
}
/// <inheritdoc/>
public int BlockSize => BlockSizeValue;
/// <inheritdoc/>
public int DigestSize => _digestSize;
/// <inheritdoc/>
public long TotalBytesProcessed => (long)_t0;
/// <inheritdoc/>
public void Update(ReadOnlySpan<byte> data) {
int offset = 0;
int remaining = data.Length;
if (_bufferOffset > 0) {
int space = BlockSizeValue - _bufferOffset;
if (remaining > space) {
data.Slice(offset, space).CopyTo(_buffer.AsSpan(_bufferOffset));
_bufferOffset = BlockSizeValue;
offset += space;
remaining -= space;
IncrementCounter(BlockSizeValue);
Compress(_buffer, false);
_bufferOffset = 0;
} else {
data.Slice(offset, remaining).CopyTo(_buffer.AsSpan(_bufferOffset));
_bufferOffset += remaining;
return;
}
}
while (remaining > BlockSizeValue) {
IncrementCounter(BlockSizeValue);
Compress(data.Slice(offset, BlockSizeValue), false);
offset += BlockSizeValue;
remaining -= BlockSizeValue;
}
if (remaining > 0) {
data.Slice(offset, remaining).CopyTo(_buffer.AsSpan());
_bufferOffset = remaining;
}
}
/// <inheritdoc/>
public byte[] FinalizeBytes() {
Array.Clear(_buffer, _bufferOffset, BlockSizeValue - _bufferOffset);
IncrementCounter(_bufferOffset);
Compress(_buffer, true);
byte[] result = new byte[_digestSize];
Span<byte> output = result.AsSpan();
Span<byte> temp = stackalloc byte[4];
for (int i = 0; i < 8 && i * 4 < _digestSize; i++) {
int bytesToWrite = Math.Min(4, _digestSize - i * 4);
BinaryPrimitives.WriteUInt32LittleEndian(temp, _h[i]);
temp[..bytesToWrite].CopyTo(output[(i * 4)..]);
}
return result;
}
/// <inheritdoc/>
public void Reset() {
Array.Copy(IV, _h, 8);
_h[0] ^= 0x01010000U | (uint)_digestSize;
_bufferOffset = 0;
_t0 = 0;
_t1 = 0;
Array.Clear(_buffer);
}
/// <inheritdoc/>
public void Dispose() { }
/// <summary>
/// Increments the 64-bit counter by the given number of bytes.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveInlining)]
private void IncrementCounter(int inc) {
_t0 += (uint)inc;
if (_t0 < (uint)inc) {
_t1++;
}
}
/// <summary>
/// BLAKE2s compression function. Processes one 64-byte block.
/// Fully unrolled with local message word variables to eliminate all Span bounds checks.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveOptimization)]
[SkipLocalsInit]
private void Compress(ReadOnlySpan<byte> block, bool isFinal) {
// Parse message block into 16 32-bit local variables (eliminates all Span indexing)
uint m0 = BinaryPrimitives.ReadUInt32LittleEndian(block);
uint m1 = BinaryPrimitives.ReadUInt32LittleEndian(block[4..]);
uint m2 = BinaryPrimitives.ReadUInt32LittleEndian(block[8..]);
uint m3 = BinaryPrimitives.ReadUInt32LittleEndian(block[12..]);
uint m4 = BinaryPrimitives.ReadUInt32LittleEndian(block[16..]);
uint m5 = BinaryPrimitives.ReadUInt32LittleEndian(block[20..]);
uint m6 = BinaryPrimitives.ReadUInt32LittleEndian(block[24..]);
uint m7 = BinaryPrimitives.ReadUInt32LittleEndian(block[28..]);
uint m8 = BinaryPrimitives.ReadUInt32LittleEndian(block[32..]);
uint m9 = BinaryPrimitives.ReadUInt32LittleEndian(block[36..]);
uint m10 = BinaryPrimitives.ReadUInt32LittleEndian(block[40..]);
uint m11 = BinaryPrimitives.ReadUInt32LittleEndian(block[44..]);
uint m12 = BinaryPrimitives.ReadUInt32LittleEndian(block[48..]);
uint m13 = BinaryPrimitives.ReadUInt32LittleEndian(block[52..]);
uint m14 = BinaryPrimitives.ReadUInt32LittleEndian(block[56..]);
uint m15 = BinaryPrimitives.ReadUInt32LittleEndian(block[60..]);
// Initialize working vector as local variables (no Span bounds checks)
uint v0 = _h[0], v1 = _h[1], v2 = _h[2], v3 = _h[3];
uint v4 = _h[4], v5 = _h[5], v6 = _h[6], v7 = _h[7];
uint v8 = IV[0], v9 = IV[1], v10 = IV[2], v11 = IV[3];
uint v12 = IV[4] ^ _t0;
uint v13 = IV[5] ^ _t1;
uint v14 = isFinal ? IV[6] ^ 0xffffffff : IV[6];
uint v15 = IV[7];
// 10 rounds of mixing, fully unrolled with hardcoded sigma permutations
		// Round 0
		v0 += v4 + m0; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m1; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m2; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m3; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m4; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m5; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m6; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m7; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m8; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m9; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m10; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m11; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m12; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m13; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m14; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m15; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 1
		v0 += v4 + m14; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m10; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m4; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m8; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m9; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m15; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m13; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m6; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m1; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m12; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m0; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m2; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m11; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m7; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m5; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m3; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 2
		v0 += v4 + m11; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m8; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m12; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m0; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m5; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m2; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m15; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m13; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m10; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m14; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m3; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m6; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m7; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m1; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m9; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m4; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 3
		v0 += v4 + m7; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m9; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m3; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m1; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m13; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m12; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m11; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m14; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m2; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m6; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m5; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m10; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m4; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m0; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m15; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m8; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 4
		v0 += v4 + m9; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m0; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m5; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m7; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m2; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m4; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m10; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m15; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m14; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m1; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m11; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m12; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m6; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m8; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m3; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m13; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 5
		v0 += v4 + m2; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m12; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m6; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m10; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m0; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m11; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m8; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m3; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m4; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m13; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m7; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m5; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m15; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m14; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m1; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m9; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 6
		v0 += v4 + m12; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m5; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m1; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m15; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m14; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m13; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m4; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m10; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m0; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m7; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m6; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m3; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m9; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m2; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m8; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m11; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 7
		v0 += v4 + m13; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m11; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m7; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m14; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m12; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m1; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m3; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m9; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m5; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m0; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m15; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m4; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m8; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m6; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m2; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m10; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 8
		v0 += v4 + m6; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m15; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m14; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m9; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m11; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m3; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m0; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m8; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m12; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m2; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m13; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m7; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m1; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m4; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m10; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m5; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


		// Round 9
		v0 += v4 + m10; v12 = uint.RotateRight(v12 ^ v0, 16);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 12);
		v0 += v4 + m2; v12 = uint.RotateRight(v12 ^ v0, 8);
		v8 += v12; v4 = uint.RotateRight(v4 ^ v8, 7);

		v1 += v5 + m8; v13 = uint.RotateRight(v13 ^ v1, 16);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 12);
		v1 += v5 + m4; v13 = uint.RotateRight(v13 ^ v1, 8);
		v9 += v13; v5 = uint.RotateRight(v5 ^ v9, 7);

		v2 += v6 + m7; v14 = uint.RotateRight(v14 ^ v2, 16);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 12);
		v2 += v6 + m6; v14 = uint.RotateRight(v14 ^ v2, 8);
		v10 += v14; v6 = uint.RotateRight(v6 ^ v10, 7);

		v3 += v7 + m1; v15 = uint.RotateRight(v15 ^ v3, 16);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 12);
		v3 += v7 + m5; v15 = uint.RotateRight(v15 ^ v3, 8);
		v11 += v15; v7 = uint.RotateRight(v7 ^ v11, 7);

		v0 += v5 + m15; v15 = uint.RotateRight(v15 ^ v0, 16);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 12);
		v0 += v5 + m11; v15 = uint.RotateRight(v15 ^ v0, 8);
		v10 += v15; v5 = uint.RotateRight(v5 ^ v10, 7);

		v1 += v6 + m9; v12 = uint.RotateRight(v12 ^ v1, 16);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 12);
		v1 += v6 + m14; v12 = uint.RotateRight(v12 ^ v1, 8);
		v11 += v12; v6 = uint.RotateRight(v6 ^ v11, 7);

		v2 += v7 + m3; v13 = uint.RotateRight(v13 ^ v2, 16);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 12);
		v2 += v7 + m12; v13 = uint.RotateRight(v13 ^ v2, 8);
		v8 += v13; v7 = uint.RotateRight(v7 ^ v8, 7);

		v3 += v4 + m13; v14 = uint.RotateRight(v14 ^ v3, 16);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 12);
		v3 += v4 + m0; v14 = uint.RotateRight(v14 ^ v3, 8);
		v9 += v14; v4 = uint.RotateRight(v4 ^ v9, 7);


// Finalize: XOR upper and lower halves back into state
_h[0] ^= v0 ^ v8;
_h[1] ^= v1 ^ v9;
_h[2] ^= v2 ^ v10;
_h[3] ^= v3 ^ v11;
_h[4] ^= v4 ^ v12;
_h[5] ^= v5 ^ v13;
_h[6] ^= v6 ^ v14;
_h[7] ^= v7 ^ v15;
}
/// <summary>
/// BLAKE2s G mixing function (retained for reference; hot path uses fully unrolled version).
/// Rotation constants: 16, 12, 8, 7.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveInlining)]
private static void G(Span<uint> v, Span<uint> m, int round, int a, int b, int c, int d, int i) {
int s0 = Sigma[round * 16 + 2 * i];
int s1 = Sigma[round * 16 + 2 * i + 1];
v[a] += v[b] + m[s0];
v[d] = uint.RotateRight(v[d] ^ v[a], 16);
v[c] += v[d];
v[b] = uint.RotateRight(v[b] ^ v[c], 12);
v[a] += v[b] + m[s1];
v[d] = uint.RotateRight(v[d] ^ v[a], 8);
v[c] += v[d];
v[b] = uint.RotateRight(v[b] ^ v[c], 7);
}
}
/// <summary>
/// Factory methods for creating native BLAKE2b and BLAKE2s streaming hash instances.
/// </summary>
internal static class NativeBlake2Factory {
/// <summary>
/// Creates a BLAKE2b-512 streaming hash instance.
/// </summary>
public static IStreamingHashBytes CreateBlake2b() => new NativeBlake2bDigest(64);
/// <summary>
/// Creates a BLAKE2b-256 streaming hash instance (used as BLAKE-256).
/// </summary>
public static IStreamingHashBytes CreateBlake256() => new NativeBlake2bDigest(32);
/// <summary>
/// Creates a BLAKE2b-512 streaming hash instance (used as BLAKE-512).
/// </summary>
public static IStreamingHashBytes CreateBlake512() => new NativeBlake2bDigest(64);
/// <summary>
/// Creates a BLAKE2s-256 streaming hash instance.
/// </summary>
public static IStreamingHashBytes CreateBlake2s() => new NativeBlake2sDigest(32);

	/// <summary>
	/// Computes BLAKE2b-512 hash in one shot.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeBlake2b(ReadOnlySpan<byte> data) {
		using var hasher = new NativeBlake2bDigest(64);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes BLAKE2b-256 hash in one shot (BLAKE-256).
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeBlake256(ReadOnlySpan<byte> data) {
		using var hasher = new NativeBlake2bDigest(32);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes BLAKE2b-512 hash in one shot (BLAKE-512).
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeBlake512(ReadOnlySpan<byte> data) {
		using var hasher = new NativeBlake2bDigest(64);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes BLAKE2s-256 hash in one shot.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeBlake2s(ReadOnlySpan<byte> data) {
		using var hasher = new NativeBlake2sDigest(32);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}
}
