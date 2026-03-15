using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
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
/// Byte shuffle mask for 64-bit RotateRight(24): each 8-byte lane shifts bytes right by 3.
/// Static to avoid per-call reconstruction and reduce register pressure in CompressAvx2.
/// </summary>
private static readonly Vector256<byte> Rot24Mask = Vector256.Create(
(byte)3, 4, 5, 6, 7, 0, 1, 2,
11, 12, 13, 14, 15, 8, 9, 10,
3, 4, 5, 6, 7, 0, 1, 2,
11, 12, 13, 14, 15, 8, 9, 10);
/// <summary>
/// Byte shuffle mask for 64-bit RotateRight(16): each 8-byte lane shifts bytes right by 2.
/// Static to avoid per-call reconstruction and reduce register pressure in CompressAvx2.
/// </summary>
private static readonly Vector256<byte> Rot16Mask = Vector256.Create(
(byte)2, 3, 4, 5, 6, 7, 0, 1,
10, 11, 12, 13, 14, 15, 8, 9,
2, 3, 4, 5, 6, 7, 0, 1,
10, 11, 12, 13, 14, 15, 8, 9);
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
/// BLAKE2b compression function dispatcher. Selects AVX2 or scalar path at runtime.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveInlining)]
private void Compress(ReadOnlySpan<byte> block, bool isFinal) {
if (Avx2.IsSupported) {
CompressAvx2(block, isFinal);
} else {
CompressScalar(block, isFinal);
}
}

/// <summary>
/// BLAKE2b scalar compression function. Processes one 128-byte block.
/// Fully unrolled with local message word variables to eliminate all Span bounds checks.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveOptimization)]
[SkipLocalsInit]
private void CompressScalar(ReadOnlySpan<byte> block, bool isFinal) {
// Parse message block into 16 64-bit local variables using direct unaligned reads
// to avoid Span slice overhead. On little-endian x86 this compiles to plain MOV instructions.
ref byte blockRef = ref MemoryMarshal.GetReference(block);
ulong m0 = Unsafe.ReadUnaligned<ulong>(ref blockRef);
ulong m1 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 8));
ulong m2 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 16));
ulong m3 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 24));
ulong m4 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 32));
ulong m5 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 40));
ulong m6 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 48));
ulong m7 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 56));
ulong m8 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 64));
ulong m9 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 72));
ulong m10 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 80));
ulong m11 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 88));
ulong m12 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 96));
ulong m13 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 104));
ulong m14 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 112));
ulong m15 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref blockRef, 120));
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
/// BLAKE2b compression function using AVX2 SIMD intrinsics.
/// Row-based vectorization processes all 4 column/diagonal G functions in parallel.
/// </summary>
/// <remarks>
/// <para>
/// Uses Vector256&lt;ulong&gt; (4 x 64-bit lanes) to vectorize the working matrix rows.
/// Rotation implementations:
/// <list type="bullet">
/// <item>RotateRight(32): Avx2.Shuffle on uint32 halves (0xB1)</item>
/// <item>RotateRight(24): Avx2.Shuffle with byte permutation mask</item>
/// <item>RotateRight(16): Avx2.Shuffle with byte permutation mask</item>
/// <item>RotateRight(63): ShiftRightLogical(63) | ShiftLeftLogical(1)</item>
/// </list>
/// </para>
/// </remarks>
[MethodImpl(MethodImplOptions.AggressiveOptimization)]
[SkipLocalsInit]
private void CompressAvx2(ReadOnlySpan<byte> block, bool isFinal) {
	// Load message block as 4 vectors — all-SIMD, eliminates 16 scalar→SIMD cross-domain moves
	// msg0=[w0,w1,w2,w3], msg1=[w4,w5,w6,w7], msg2=[w8,w9,w10,w11], msg3=[w12,w13,w14,w15]
	ref byte blockRef = ref MemoryMarshal.GetReference(block);
	var msg0 = Unsafe.As<byte, Vector256<ulong>>(ref blockRef);
	var msg1 = Unsafe.As<byte, Vector256<ulong>>(ref Unsafe.Add(ref blockRef, 32));
	var msg2 = Unsafe.As<byte, Vector256<ulong>>(ref Unsafe.Add(ref blockRef, 64));
	var msg3 = Unsafe.As<byte, Vector256<ulong>>(ref Unsafe.Add(ref blockRef, 96));

	// Load rotation masks from static fields
	var rot24Mask = Rot24Mask;
	var rot16Mask = Rot16Mask;

	// Initialize working vector rows from hash state and IV using direct vector loads
	ref ulong hRef = ref MemoryMarshal.GetArrayDataReference(_h);
	var row0 = Unsafe.As<ulong, Vector256<ulong>>(ref hRef);
	var row1 = Unsafe.As<ulong, Vector256<ulong>>(ref Unsafe.Add(ref hRef, 4));
	ref ulong ivRef = ref MemoryMarshal.GetArrayDataReference(IV);
	var row2 = Unsafe.As<ulong, Vector256<ulong>>(ref ivRef);
	var row3 = Avx2.Xor(
		Unsafe.As<ulong, Vector256<ulong>>(ref Unsafe.Add(ref ivRef, 4)),
		Vector256.Create(_t0, _t1, isFinal ? 0xffffffffffffffff : 0UL, 0UL));

	Vector256<ulong> b0, b1, t0;

		// ===== Round 0 (sigma: 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15) =====
		// Column: b0=[w0,w2,w4,w6], b1=[w1,w3,w5,w7]
		b0 = Avx2.Permute4x64(Avx2.UnpackLow(msg0, msg1), 0xd8);
		b1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg0, msg1), 0xd8);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w8,w10,w12,w14], b1=[w9,w11,w13,w15]
		b0 = Avx2.Permute4x64(Avx2.UnpackLow(msg2, msg3), 0xd8);
		b1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg2, msg3), 0xd8);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 1 (sigma: 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3) =====
		// Column: b0=[w14,w4,w9,w13], b1=[w10,w8,w15,w6]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64(), 0x02), Avx2.UnpackHigh(msg2, msg3), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(msg2, 0x02), Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x30).AsUInt64(), 0x0b), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w1,w0,w11,w5], b1=[w12,w2,w7,w3]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg0, 0x01), Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg1.AsInt32(), 0x0c).AsUInt64(), 0x07), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x30).AsUInt64(), 0x08), Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg0), 0x0e), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 2 (sigma: 11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4) =====
		// Column: b0=[w11,w12,w5,w15], b1=[w8,w0,w2,w13]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg3.AsInt32(), 0x03).AsUInt64(), 0x03), Avx2.Permute4x64(Avx2.Blend(msg1.AsInt32(), msg3.AsInt32(), 0xc0).AsUInt64(), 0x0d), 0x20);
		b1 = Avx2.Permute2x128(Avx2.UnpackLow(msg2, msg0), Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg3.AsInt32(), 0x0c).AsUInt64(), 0x06), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w10,w3,w7,w9], b1=[w14,w6,w1,w4]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg0.AsInt32(), 0xc0).AsUInt64(), 0x0e), Avx2.Permute4x64(Avx2.Blend(msg1.AsInt32(), msg2.AsInt32(), 0x0c).AsUInt64(), 0x07), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.UnpackLow(msg3, msg1), 0x0e), Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64(), 0x01), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 3 (sigma: 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8) =====
		// Column: b0=[w7,w3,w13,w11], b1=[w9,w1,w12,w14]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg0), 0x0e), Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0xc0).AsUInt64(), 0x0d), 0x20);
		b1 = Avx2.Permute2x128(Avx2.UnpackHigh(msg2, msg0), Avx2.Permute4x64(msg3, 0x08), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w2,w5,w4,w15], b1=[w6,w10,w0,w8]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0x0c).AsUInt64(), 0x06), Avx2.Permute4x64(Avx2.Blend(msg1.AsInt32(), msg3.AsInt32(), 0xc0).AsUInt64(), 0x0c), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.UnpackLow(msg1, msg2), 0x0e), Avx2.UnpackLow(msg0, msg2), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 4 (sigma: 9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13) =====
		// Column: b0=[w9,w5,w2,w10], b1=[w0,w7,w4,w15]
		b0 = Avx2.Permute2x128(Avx2.UnpackHigh(msg2, msg1), Avx2.Permute4x64(Avx2.UnpackLow(msg0, msg2), 0x0e), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0xc0).AsUInt64(), 0x0c), Avx2.Permute4x64(Avx2.Blend(msg1.AsInt32(), msg3.AsInt32(), 0xc0).AsUInt64(), 0x0c), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w14,w11,w6,w3], b1=[w1,w12,w8,w13]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0xc0).AsUInt64(), 0x0e), Avx2.Permute4x64(Avx2.Blend(msg1.AsInt32(), msg0.AsInt32(), 0xc0).AsUInt64(), 0x0e), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg3.AsInt32(), 0x03).AsUInt64(), 0x01), Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg3.AsInt32(), 0x0c).AsUInt64(), 0x04), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 5 (sigma: 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9) =====
		// Column: b0=[w2,w6,w0,w8], b1=[w12,w10,w11,w3]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.UnpackLow(msg0, msg1), 0x0e), Avx2.UnpackLow(msg0, msg2), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x30).AsUInt64(), 0x08), Avx2.Permute4x64(Avx2.UnpackHigh(msg2, msg0), 0x0e), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w4,w7,w15,w1], b1=[w13,w5,w14,w9]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg1, 0x0c), Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x0c).AsUInt64(), 0x07), 0x20);
		b1 = Avx2.Permute2x128(Avx2.UnpackHigh(msg3, msg1), Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x0c).AsUInt64(), 0x06), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 6 (sigma: 12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11) =====
		// Column: b0=[w12,w1,w14,w4], b1=[w5,w15,w13,w10]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x0c).AsUInt64(), 0x04), Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64(), 0x02), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg1.AsInt32(), msg3.AsInt32(), 0xc0).AsUInt64(), 0x0d), Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x30).AsUInt64(), 0x09), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w0,w6,w9,w8], b1=[w7,w3,w2,w11]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0x30).AsUInt64(), 0x08), Avx2.Permute4x64(msg2, 0x01), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg0), 0x0e), Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg2.AsInt32(), 0xc0).AsUInt64(), 0x0e), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 7 (sigma: 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10) =====
		// Column: b0=[w13,w7,w12,w3], b1=[w11,w14,w1,w9]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0xc0).AsUInt64(), 0x0d), Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0xc0).AsUInt64(), 0x0c), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg3.AsInt32(), 0x30).AsUInt64(), 0x0b), Avx2.UnpackHigh(msg0, msg2), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w5,w15,w8,w2], b1=[w0,w4,w6,w10]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg1.AsInt32(), msg3.AsInt32(), 0xc0).AsUInt64(), 0x0d), Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg0.AsInt32(), 0x30).AsUInt64(), 0x08), 0x20);
		b1 = Avx2.Permute2x128(Avx2.UnpackLow(msg0, msg1), Avx2.Permute4x64(Avx2.UnpackLow(msg1, msg2), 0x0e), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 8 (sigma: 6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5) =====
		// Column: b0=[w6,w14,w11,w0], b1=[w15,w9,w3,w8]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.UnpackLow(msg1, msg3), 0x0e), Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg0.AsInt32(), 0x03).AsUInt64(), 0x03), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x0c).AsUInt64(), 0x07), Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg2.AsInt32(), 0x03).AsUInt64(), 0x03), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w12,w13,w1,w10], b1=[w2,w7,w4,w5]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg3, 0x04), Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg2.AsInt32(), 0x30).AsUInt64(), 0x09), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0xc0).AsUInt64(), 0x0e), Avx2.Permute4x64(msg1, 0x04), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 9 (sigma: 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0) =====
		// Column: b0=[w10,w8,w7,w1], b1=[w2,w4,w6,w5]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg2, 0x02), Avx2.Permute4x64(Avx2.Blend(msg1.AsInt32(), msg0.AsInt32(), 0x0c).AsUInt64(), 0x07), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64(), 0x02), Avx2.Permute4x64(msg1, 0x06), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w15,w9,w3,w13], b1=[w11,w14,w12,w0]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x0c).AsUInt64(), 0x07), Avx2.Permute4x64(Avx2.Blend(msg0.AsInt32(), msg3.AsInt32(), 0x0c).AsUInt64(), 0x07), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg3.AsInt32(), 0x30).AsUInt64(), 0x0b), Avx2.UnpackLow(msg3, msg0), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 10 (same as Round 0) =====
		// Column: b0=[w0,w2,w4,w6], b1=[w1,w3,w5,w7]
		b0 = Avx2.Permute4x64(Avx2.UnpackLow(msg0, msg1), 0xd8);
		b1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg0, msg1), 0xd8);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w8,w10,w12,w14], b1=[w9,w11,w13,w15]
		b0 = Avx2.Permute4x64(Avx2.UnpackLow(msg2, msg3), 0xd8);
		b1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg2, msg3), 0xd8);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 11 (same as Round 1) =====
		// Column: b0=[w14,w4,w9,w13], b1=[w10,w8,w15,w6]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64(), 0x02), Avx2.UnpackHigh(msg2, msg3), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(msg2, 0x02), Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x30).AsUInt64(), 0x0b), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w1,w0,w11,w5], b1=[w12,w2,w7,w3]
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg0, 0x01), Avx2.Permute4x64(Avx2.Blend(msg2.AsInt32(), msg1.AsInt32(), 0x0c).AsUInt64(), 0x07), 0x20);
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x30).AsUInt64(), 0x08), Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg0), 0x0e), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

	// Finalize: XOR upper and lower halves back into state using vector operations
	var f0 = Avx2.Xor(row0, row2);
	var f1 = Avx2.Xor(row1, row3);
	ref ulong hEnd = ref MemoryMarshal.GetArrayDataReference(_h);
	Unsafe.As<ulong, Vector256<ulong>>(ref hEnd) = Avx2.Xor(
		Unsafe.As<ulong, Vector256<ulong>>(ref hEnd), f0);
	Unsafe.As<ulong, Vector256<ulong>>(ref Unsafe.Add(ref hEnd, 4)) = Avx2.Xor(
		Unsafe.As<ulong, Vector256<ulong>>(ref Unsafe.Add(ref hEnd, 4)), f1);
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
/// BLAKE2s compression function dispatcher. Selects SSSE3 or scalar path at runtime.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveInlining)]
private void Compress(ReadOnlySpan<byte> block, bool isFinal) {
if (Ssse3.IsSupported) {
CompressSsse3(block, isFinal);
} else {
CompressScalar(block, isFinal);
}
}

/// <summary>
/// BLAKE2s scalar compression function. Processes one 64-byte block.
/// Fully unrolled with local message word variables to eliminate all Span bounds checks.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveOptimization)]
[SkipLocalsInit]
private void CompressScalar(ReadOnlySpan<byte> block, bool isFinal) {
// Parse message block into 16 32-bit local variables using direct unaligned reads
ref byte blockRef = ref MemoryMarshal.GetReference(block);
uint m0 = Unsafe.ReadUnaligned<uint>(ref blockRef);
uint m1 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 4));
uint m2 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 8));
uint m3 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 12));
uint m4 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 16));
uint m5 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 20));
uint m6 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 24));
uint m7 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 28));
uint m8 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 32));
uint m9 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 36));
uint m10 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 40));
uint m11 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 44));
uint m12 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 48));
uint m13 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 52));
uint m14 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 56));
uint m15 = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, 60));
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
/// BLAKE2s compression function using SSSE3 SIMD intrinsics.
/// Row-based vectorization processes all 4 column/diagonal G functions in parallel.
/// </summary>
/// <remarks>
/// <para>
/// Uses Vector128&lt;uint&gt; (4 x 32-bit lanes) to vectorize the working matrix rows.
/// Rotation implementations:
/// <list type="bullet">
/// <item>RotateRight(16): Ssse3.Shuffle with byte permutation mask</item>
/// <item>RotateRight(12): ShiftRightLogical(12) | ShiftLeftLogical(20)</item>
/// <item>RotateRight(8): Ssse3.Shuffle with byte permutation mask</item>
/// <item>RotateRight(7): ShiftRightLogical(7) | ShiftLeftLogical(25)</item>
/// </list>
/// </para>
/// </remarks>
[MethodImpl(MethodImplOptions.AggressiveOptimization)]
[SkipLocalsInit]
private void CompressSsse3(ReadOnlySpan<byte> block, bool isFinal) {
		// Load message block as 4 vector registers (replaces 16 scalar reads)
		ref byte blockRef = ref MemoryMarshal.GetReference(block);
		var msg0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref blockRef);
		var msg1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 16));
		var msg2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 32));
		var msg3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 48));
// Byte shuffle masks for 32-bit rotations via PSHUFB
// RotateRight(16): each 4-byte lane swaps upper and lower halves
var rot16Mask = Vector128.Create(
(byte)2, 3, 0, 1,
6, 7, 4, 5,
10, 11, 8, 9,
14, 15, 12, 13);
// RotateRight(8): each 4-byte lane shifts bytes right by 1
var rot8Mask = Vector128.Create(
(byte)1, 2, 3, 0,
5, 6, 7, 4,
9, 10, 11, 8,
13, 14, 15, 12);
// Initialize working vector rows from hash state and IV using direct vector loads
ref uint hRef = ref MemoryMarshal.GetArrayDataReference(_h);
var row0 = Unsafe.As<uint, Vector128<uint>>(ref hRef);
var row1 = Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref hRef, 4));
ref uint ivRef = ref MemoryMarshal.GetArrayDataReference(IV);
var row2 = Unsafe.As<uint, Vector128<uint>>(ref ivRef);
var row3 = Sse2.Xor(
Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref ivRef, 4)),
Vector128.Create(_t0, _t1, isFinal ? 0xffffffff : 0U, 0U));
Vector128<uint> b0, b1, t0, tt, tu;
		// Round 0 - Column phase
		b0 = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0x88).AsUInt32();
		b1 = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0xdd).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 0 - Diagonal phase
		b0 = Sse.Shuffle(msg2.AsSingle(), msg3.AsSingle(), 0x88).AsUInt32();
		b1 = Sse.Shuffle(msg2.AsSingle(), msg3.AsSingle(), 0xdd).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 1 - Column phase
		tt = Sse.Shuffle(msg3.AsSingle(), msg1.AsSingle(), 0x0a).AsUInt32();
		tu = Sse.Shuffle(msg2.AsSingle(), msg3.AsSingle(), 0x55).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg3.AsSingle(), msg1.AsSingle(), 0x23).AsUInt32();
		b1 = Sse.Shuffle(msg2.AsSingle(), tt.AsSingle(), 0x82).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 1 - Diagonal phase
		tt = Sse.Shuffle(msg2.AsSingle(), msg1.AsSingle(), 0x13).AsUInt32();
		b0 = Sse.Shuffle(msg0.AsSingle(), tt.AsSingle(), 0x81).AsUInt32();
		tt = Sse.Shuffle(msg3.AsSingle(), msg0.AsSingle(), 0xa0).AsUInt32();
		tu = Sse.Shuffle(msg1.AsSingle(), msg0.AsSingle(), 0xff).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 2 - Column phase
		tt = Sse.Shuffle(msg2.AsSingle(), msg3.AsSingle(), 0x0f).AsUInt32();
		tu = Sse.Shuffle(msg1.AsSingle(), msg3.AsSingle(), 0xf5).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg2.AsSingle(), msg0.AsSingle(), 0x00).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg3.AsSingle(), 0x5a).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 2 - Diagonal phase
		tt = Sse.Shuffle(msg2.AsSingle(), msg0.AsSingle(), 0xfa).AsUInt32();
		tu = Sse.Shuffle(msg1.AsSingle(), msg2.AsSingle(), 0x5f).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg3.AsSingle(), msg1.AsSingle(), 0xaa).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0x05).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 3 - Column phase
		tt = Sse.Shuffle(msg1.AsSingle(), msg0.AsSingle(), 0xff).AsUInt32();
		tu = Sse.Shuffle(msg3.AsSingle(), msg2.AsSingle(), 0xf5).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg2.AsSingle(), msg0.AsSingle(), 0x11).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), msg3.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 3 - Diagonal phase
		tt = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0x5a).AsUInt32();
		tu = Sse.Shuffle(msg1.AsSingle(), msg3.AsSingle(), 0xf0).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg1.AsSingle(), msg2.AsSingle(), 0xaa).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg2.AsSingle(), 0x00).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 4 - Column phase
		tt = Sse.Shuffle(msg2.AsSingle(), msg1.AsSingle(), 0x55).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg2.AsSingle(), 0xaa).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0xf0).AsUInt32();
		tu = Sse.Shuffle(msg1.AsSingle(), msg3.AsSingle(), 0xf0).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 4 - Diagonal phase
		tt = Sse.Shuffle(msg3.AsSingle(), msg2.AsSingle(), 0xfa).AsUInt32();
		tu = Sse.Shuffle(msg1.AsSingle(), msg0.AsSingle(), 0xfa).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg0.AsSingle(), msg3.AsSingle(), 0x05).AsUInt32();
		tu = Sse.Shuffle(msg2.AsSingle(), msg3.AsSingle(), 0x50).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 5 - Column phase
		tt = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0xaa).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg2.AsSingle(), 0x00).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg3.AsSingle(), msg2.AsSingle(), 0xa0).AsUInt32();
		tu = Sse.Shuffle(msg2.AsSingle(), msg0.AsSingle(), 0xff).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 5 - Diagonal phase
		tt = Sse.Shuffle(msg3.AsSingle(), msg0.AsSingle(), 0x13).AsUInt32();
		b0 = Sse.Shuffle(msg1.AsSingle(), tt.AsSingle(), 0x8c).AsUInt32();
		tt = Sse.Shuffle(msg3.AsSingle(), msg1.AsSingle(), 0x55).AsUInt32();
		tu = Sse.Shuffle(msg3.AsSingle(), msg2.AsSingle(), 0x5a).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 6 - Column phase
		tt = Sse.Shuffle(msg3.AsSingle(), msg0.AsSingle(), 0x50).AsUInt32();
		tu = Sse.Shuffle(msg3.AsSingle(), msg1.AsSingle(), 0x0a).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg1.AsSingle(), msg3.AsSingle(), 0xf5).AsUInt32();
		tu = Sse.Shuffle(msg3.AsSingle(), msg2.AsSingle(), 0xa5).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 6 - Diagonal phase
		tt = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0x20).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), msg2.AsSingle(), 0x18).AsUInt32();
		tt = Sse.Shuffle(msg1.AsSingle(), msg0.AsSingle(), 0xff).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg2.AsSingle(), 0xfa).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 7 - Column phase
		tt = Sse.Shuffle(msg3.AsSingle(), msg1.AsSingle(), 0xf5).AsUInt32();
		tu = Sse.Shuffle(msg3.AsSingle(), msg0.AsSingle(), 0xf0).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg2.AsSingle(), msg3.AsSingle(), 0xaf).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg2.AsSingle(), 0x55).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 7 - Diagonal phase
		tt = Sse.Shuffle(msg1.AsSingle(), msg3.AsSingle(), 0xf5).AsUInt32();
		tu = Sse.Shuffle(msg2.AsSingle(), msg0.AsSingle(), 0xa0).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0x00).AsUInt32();
		tu = Sse.Shuffle(msg1.AsSingle(), msg2.AsSingle(), 0xaa).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 8 - Column phase
		tt = Sse.Shuffle(msg1.AsSingle(), msg3.AsSingle(), 0xaa).AsUInt32();
		tu = Sse.Shuffle(msg2.AsSingle(), msg0.AsSingle(), 0x0f).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg3.AsSingle(), msg2.AsSingle(), 0x5f).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg2.AsSingle(), 0x0f).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 8 - Diagonal phase
		tt = Sse.Shuffle(msg0.AsSingle(), msg2.AsSingle(), 0x21).AsUInt32();
		b0 = Sse.Shuffle(msg3.AsSingle(), tt.AsSingle(), 0x84).AsUInt32();
		tt = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0x32).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), msg1.AsSingle(), 0x48).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();

		// Round 9 - Column phase
		tt = Sse.Shuffle(msg1.AsSingle(), msg0.AsSingle(), 0x13).AsUInt32();
		b0 = Sse.Shuffle(msg2.AsSingle(), tt.AsSingle(), 0x82).AsUInt32();
		tt = Sse.Shuffle(msg0.AsSingle(), msg1.AsSingle(), 0x02).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), msg1.AsSingle(), 0x68).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Diagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();
		// Round 9 - Diagonal phase
		tt = Sse.Shuffle(msg3.AsSingle(), msg2.AsSingle(), 0x5f).AsUInt32();
		tu = Sse.Shuffle(msg0.AsSingle(), msg3.AsSingle(), 0x0f).AsUInt32();
		b0 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		tt = Sse.Shuffle(msg2.AsSingle(), msg3.AsSingle(), 0xaf).AsUInt32();
		tu = Sse.Shuffle(msg3.AsSingle(), msg0.AsSingle(), 0x05).AsUInt32();
		b1 = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();
		row0 = Sse2.Add(Sse2.Add(row0, row1), b0);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
		row0 = Sse2.Add(Sse2.Add(row0, row1), b1);
		row3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
		row2 = Sse2.Add(row2, row3);
		t0 = Sse2.Xor(row1, row2);
		row1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
		// Undiagonalize
		row1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
		row2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
		row3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();
// Finalize: XOR upper and lower halves back into state using vector operations
var f0 = Sse2.Xor(row0, row2);
var f1 = Sse2.Xor(row1, row3);
ref uint hEnd = ref MemoryMarshal.GetArrayDataReference(_h);
Unsafe.As<uint, Vector128<uint>>(ref hEnd) = Sse2.Xor(
Unsafe.As<uint, Vector128<uint>>(ref hEnd), f0);
Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref hEnd, 4)) = Sse2.Xor(
Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref hEnd, 4)), f1);
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
