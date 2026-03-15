using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the BLAKE3 cryptographic hash function.
/// </summary>
/// <remarks>
/// <para>
/// BLAKE3 is a cryptographic hash function that uses a Merkle tree structure for parallelism.
/// Data is split into 1024-byte chunks, each compressed independently. Chunks are then merged
/// using a binary tree of parent nodes. The compression function is based on BLAKE2s with 7 rounds.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 32 bytes (default, extendable)</item>
/// <item><b>Chunk Size:</b> 1024 bytes (16 blocks of 64 bytes)</item>
/// <item><b>Rounds:</b> 7 per compression</item>
/// <item><b>Word Size:</b> 32-bit, little-endian</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf">BLAKE3 Specification</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeBlake3Digest : IStreamingHashBytes {
	private const int BlockLen = 64;
	private const int ChunkLen = 1024;
	private const int OutLen = 32;
	private const int Rounds = 7;

	// Domain separation flags
	private const uint ChunkStart = 1u << 0;
	private const uint ChunkEnd = 1u << 1;
	private const uint Parent = 1u << 2;
	private const uint Root = 1u << 3;

	/// <summary>
	/// BLAKE3 IV (same as BLAKE2s IV, derived from SHA-256 fractional parts).
	/// </summary>
	private static readonly uint[] IV = [
		0x6a09e667, 0xbb67ae85,
		0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c,
		0x1f83d9ab, 0x5be0cd19
	];

	/// <summary>
	/// BLAKE3 fixed message word permutation, applied between each round.
	/// </summary>
	private static readonly byte[] MsgPermutation = [
		2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
	];

	// Buffer entire chunk (up to 1024 bytes)
	private readonly byte[] _chunkBuf = new byte[ChunkLen];
	private int _chunkLen;
	private ulong _chunkCounter;

	// Flat tree stack for parent nodes (max depth 54 for 2^54 chunks)
	// Stored as contiguous uint words to eliminate jagged array overhead
	private readonly uint[] _cvStack = new uint[54 * 8];
	private int _cvStackLen;

	private long _totalBytes;

	/// <summary>
	/// Creates a new BLAKE3 streaming hash instance.
	/// </summary>
	public NativeBlake3Digest() => Reset();

	/// <inheritdoc/>
	public int BlockSize => BlockLen;

	/// <inheritdoc/>
	public int DigestSize => OutLen;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		_totalBytes += data.Length;
		int offset = 0;

		// Stack-allocate compression buffers once, reuse across all chunk completions
		Span<uint> chunkCv = stackalloc uint[8];
		Span<uint> compressOutput = stackalloc uint[16];

		while (offset < data.Length) {
			// If the chunk buffer is full (1024 bytes), finalize this chunk and start a new one
			if (_chunkLen == ChunkLen) {
				CompressChunk(_chunkBuf.AsSpan(0, ChunkLen), IV, _chunkCounter, compressOutput, chunkCv);
				AddChunkCv(chunkCv, _chunkCounter, compressOutput);
				_chunkCounter++;
				_chunkLen = 0;
			}

			int canTake = Math.Min(ChunkLen - _chunkLen, data.Length - offset);
			data.Slice(offset, canTake).CopyTo(_chunkBuf.AsSpan(_chunkLen));
			_chunkLen += canTake;
			offset += canTake;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		ReadOnlySpan<byte> chunkData = _chunkBuf.AsSpan(0, _chunkLen);
		Span<uint> output = stackalloc uint[16];

		if (_cvStackLen == 0) {
			// Single chunk — compress as root
			CompressChunkRoot(chunkData, IV, _chunkCounter, output);
			return WordsToBytes(output);
		}

		// Multiple chunks — finalize current chunk normally, then merge parent stack
		Span<uint> cv = stackalloc uint[8];
		CompressChunk(chunkData, IV, _chunkCounter, output, cv);

		// Pack two CVs as 16 message words — avoids uint→byte→uint round trip
		Span<uint> parentWords = stackalloc uint[16];

		while (_cvStackLen > 0) {
			_cvStackLen--;
			_cvStack.AsSpan(_cvStackLen * 8, 8).CopyTo(parentWords);
			cv.CopyTo(parentWords[8..]);

			if (_cvStackLen == 0) {
				// Root parent — return full 16-word output
				CompressWords(IV, parentWords, 0, BlockLen, Parent | Root, output);
				return WordsToBytes(output);
			}

			CompressWords(IV, parentWords, 0, BlockLen, Parent, output);
			output[..8].CopyTo(cv);
		}

		// Should not reach here
		return WordsToBytes(output);
	}

	/// <inheritdoc/>
	public void Reset() {
		Array.Clear(_chunkBuf);
		_chunkLen = 0;
		_chunkCounter = 0;
		_cvStackLen = 0;
		_totalBytes = 0;
	}

	/// <inheritdoc/>
	public void Dispose() { }

	/// <summary>
	/// Compresses an entire chunk, writing the 8-word chaining value to <paramref name="cvOut"/>.
	/// </summary>
	private static void CompressChunk(ReadOnlySpan<byte> chunk, ReadOnlySpan<uint> key, ulong chunkCounter,
		Span<uint> output, Span<uint> cvOut) {
		Span<uint> cv = stackalloc uint[8];
		key[..8].CopyTo(cv);

		int nBlocks = (chunk.Length + BlockLen - 1) / BlockLen;
		if (nBlocks == 0) nBlocks = 1;

		// Stack buffer only needed for partial last block padding
		Span<byte> padBlock = stackalloc byte[BlockLen];

		for (int i = 0; i < nBlocks; i++) {
			int blockStart = i * BlockLen;
			int remaining = chunk.Length - blockStart;
			int blockBytes = Math.Min(BlockLen, remaining);

			uint flags = 0u;
			if (i == 0) flags |= ChunkStart;
			if (i == nBlocks - 1) flags |= ChunkEnd;

			if (blockBytes == BlockLen) {
				// Full block — compress directly from source, no copy needed
				Compress(cv, chunk.Slice(blockStart, BlockLen), chunkCounter, (uint)blockBytes, flags, output);
			} else {
				// Partial last block — pad with zeros
				padBlock.Clear();
				if (blockBytes > 0) chunk.Slice(blockStart, blockBytes).CopyTo(padBlock);
				Compress(cv, padBlock, chunkCounter, (uint)blockBytes, flags, output);
			}

			output[..8].CopyTo(cv);
		}

		cv.CopyTo(cvOut);
	}

	/// <summary>
	/// Compresses an entire chunk as the root, writing full 16-word output to <paramref name="output"/>.
	/// </summary>
	private static void CompressChunkRoot(ReadOnlySpan<byte> chunk, ReadOnlySpan<uint> key, ulong chunkCounter,
		Span<uint> output) {
		Span<uint> cv = stackalloc uint[8];
		key[..8].CopyTo(cv);

		int nBlocks = (chunk.Length + BlockLen - 1) / BlockLen;
		if (nBlocks == 0) nBlocks = 1;

		// Stack buffer only needed for partial last block padding
		Span<byte> padBlock = stackalloc byte[BlockLen];

		for (int i = 0; i < nBlocks; i++) {
			int blockStart = i * BlockLen;
			int remaining = chunk.Length - blockStart;
			int blockBytes = Math.Min(BlockLen, remaining);

			uint flags = 0u;
			if (i == 0) flags |= ChunkStart;
			if (i == nBlocks - 1) flags |= ChunkEnd;

			if (blockBytes == BlockLen) {
				if (i < nBlocks - 1) {
					Compress(cv, chunk.Slice(blockStart, BlockLen), chunkCounter, (uint)blockBytes, flags, output);
					output[..8].CopyTo(cv);
				} else {
					Compress(cv, chunk.Slice(blockStart, BlockLen), chunkCounter, (uint)blockBytes, flags | Root, output);
					return;
				}
			} else {
				padBlock.Clear();
				if (blockBytes > 0) chunk.Slice(blockStart, blockBytes).CopyTo(padBlock);
				if (i < nBlocks - 1) {
					Compress(cv, padBlock, chunkCounter, (uint)blockBytes, flags, output);
					output[..8].CopyTo(cv);
				} else {
					Compress(cv, padBlock, chunkCounter, (uint)blockBytes, flags | Root, output);
					return;
				}
			}
		}

		// Fallback for empty input
		padBlock.Clear();
		Compress(cv, padBlock, chunkCounter, 0, ChunkStart | ChunkEnd | Root, output);
	}

	/// <summary>
	/// Converts the first 8 words of output to a 32-byte result (little-endian).
	/// </summary>
	private static byte[] WordsToBytes(ReadOnlySpan<uint> output) {
		byte[] result = new byte[OutLen];
		for (int i = 0; i < 8; i++) {
			BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(i * 4), output[i]);
		}
		return result;
	}

	/// <summary>
	/// Adds a chunk chaining value to the tree, merging completed subtrees.
	/// Uses direct word packing to avoid uint→byte→uint round trips in parent compression.
	/// </summary>
	private void AddChunkCv(ReadOnlySpan<uint> newCv, ulong totalChunks, Span<uint> output) {
		// Pack two CVs as 16 message words for parent compression
		Span<uint> parentWords = stackalloc uint[16];
		Span<uint> working = stackalloc uint[8];
		newCv.CopyTo(working);

		while ((totalChunks & 1) != 0) {
			_cvStackLen--;
			_cvStack.AsSpan(_cvStackLen * 8, 8).CopyTo(parentWords);
			working.CopyTo(parentWords[8..]);

			CompressWords(IV, parentWords, 0, BlockLen, Parent, output);
			output[..8].CopyTo(working);
			totalChunks >>= 1;
		}

		working.CopyTo(_cvStack.AsSpan(_cvStackLen * 8, 8));
		_cvStackLen++;
	}

	/// <summary>
	/// BLAKE3 compression function. Parses block bytes into message words, then compresses.
	/// </summary>
	/// <remarks>
	/// Uses <see cref="Unsafe"/> for fast little-endian message word
	/// loading on x86/x64. Delegates to <see cref="CompressWords"/> for the actual compression.
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Compress(ReadOnlySpan<uint> cv, ReadOnlySpan<byte> block, ulong counter,
		uint blockLen, uint flags, Span<uint> output) {
		// Parse block into 16 message words using unaligned reads (LE on x86)
		Span<uint> m = stackalloc uint[16];
		ref byte blockRef = ref MemoryMarshal.GetReference(block);
		for (int i = 0; i < 16; i++) {
			m[i] = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, i * 4));
		}
		CompressWords(cv, m, counter, blockLen, flags, output);
	}

	/// <summary>
	/// BLAKE3 compression core operating on pre-parsed message words.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Accepts message words directly to avoid byte→uint→byte round trips during parent
	/// compression, where chaining values are already available as uint words.
	/// </para>
	/// <para>
	/// Uses local variables for all state and message words to maximize register allocation.
	/// Message permutation uses cycle decomposition (two 8-cycles) instead of temp array + copy.
	/// </para>
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void CompressWords(ReadOnlySpan<uint> cv, ReadOnlySpan<uint> m, ulong counter,
		uint blockLen, uint flags, Span<uint> output) {
		// Initialize state from CV using direct ref access to skip bounds checks
		ref uint cvRef = ref MemoryMarshal.GetReference(cv);
		uint s0 = cvRef, s1 = Unsafe.Add(ref cvRef, 1);
		uint s2 = Unsafe.Add(ref cvRef, 2), s3 = Unsafe.Add(ref cvRef, 3);
		uint s4 = Unsafe.Add(ref cvRef, 4), s5 = Unsafe.Add(ref cvRef, 5);
		uint s6 = Unsafe.Add(ref cvRef, 6), s7 = Unsafe.Add(ref cvRef, 7);

		ref uint ivRef = ref MemoryMarshal.GetArrayDataReference(IV);
		uint s8 = ivRef, s9 = Unsafe.Add(ref ivRef, 1);
		uint s10 = Unsafe.Add(ref ivRef, 2), s11 = Unsafe.Add(ref ivRef, 3);
		uint s12 = (uint)(counter & 0xffffffff);
		uint s13 = (uint)(counter >> 32);
		uint s14 = blockLen;
		uint s15 = flags;

		// Load message words into locals for in-place permutation
		ref uint mRef = ref MemoryMarshal.GetReference(m);
		uint m0 = mRef, m1 = Unsafe.Add(ref mRef, 1);
		uint m2 = Unsafe.Add(ref mRef, 2), m3 = Unsafe.Add(ref mRef, 3);
		uint m4 = Unsafe.Add(ref mRef, 4), m5 = Unsafe.Add(ref mRef, 5);
		uint m6 = Unsafe.Add(ref mRef, 6), m7 = Unsafe.Add(ref mRef, 7);
		uint m8 = Unsafe.Add(ref mRef, 8), m9 = Unsafe.Add(ref mRef, 9);
		uint m10 = Unsafe.Add(ref mRef, 10), m11 = Unsafe.Add(ref mRef, 11);
		uint m12 = Unsafe.Add(ref mRef, 12), m13 = Unsafe.Add(ref mRef, 13);
		uint m14 = Unsafe.Add(ref mRef, 14), m15 = Unsafe.Add(ref mRef, 15);

		for (int round = 0; round < Rounds; round++) {
			// Column step: (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)
			s0 += s4 + m0; s12 = uint.RotateRight(s12 ^ s0, 16); s8 += s12; s4 = uint.RotateRight(s4 ^ s8, 12);
			s0 += s4 + m1; s12 = uint.RotateRight(s12 ^ s0, 8); s8 += s12; s4 = uint.RotateRight(s4 ^ s8, 7);

			s1 += s5 + m2; s13 = uint.RotateRight(s13 ^ s1, 16); s9 += s13; s5 = uint.RotateRight(s5 ^ s9, 12);
			s1 += s5 + m3; s13 = uint.RotateRight(s13 ^ s1, 8); s9 += s13; s5 = uint.RotateRight(s5 ^ s9, 7);

			s2 += s6 + m4; s14 = uint.RotateRight(s14 ^ s2, 16); s10 += s14; s6 = uint.RotateRight(s6 ^ s10, 12);
			s2 += s6 + m5; s14 = uint.RotateRight(s14 ^ s2, 8); s10 += s14; s6 = uint.RotateRight(s6 ^ s10, 7);

			s3 += s7 + m6; s15 = uint.RotateRight(s15 ^ s3, 16); s11 += s15; s7 = uint.RotateRight(s7 ^ s11, 12);
			s3 += s7 + m7; s15 = uint.RotateRight(s15 ^ s3, 8); s11 += s15; s7 = uint.RotateRight(s7 ^ s11, 7);

			// Diagonal step: (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14)
			s0 += s5 + m8; s15 = uint.RotateRight(s15 ^ s0, 16); s10 += s15; s5 = uint.RotateRight(s5 ^ s10, 12);
			s0 += s5 + m9; s15 = uint.RotateRight(s15 ^ s0, 8); s10 += s15; s5 = uint.RotateRight(s5 ^ s10, 7);

			s1 += s6 + m10; s12 = uint.RotateRight(s12 ^ s1, 16); s11 += s12; s6 = uint.RotateRight(s6 ^ s11, 12);
			s1 += s6 + m11; s12 = uint.RotateRight(s12 ^ s1, 8); s11 += s12; s6 = uint.RotateRight(s6 ^ s11, 7);

			s2 += s7 + m12; s13 = uint.RotateRight(s13 ^ s2, 16); s8 += s13; s7 = uint.RotateRight(s7 ^ s8, 12);
			s2 += s7 + m13; s13 = uint.RotateRight(s13 ^ s2, 8); s8 += s13; s7 = uint.RotateRight(s7 ^ s8, 7);

			s3 += s4 + m14; s14 = uint.RotateRight(s14 ^ s3, 16); s9 += s14; s4 = uint.RotateRight(s4 ^ s9, 12);
			s3 += s4 + m15; s14 = uint.RotateRight(s14 ^ s3, 8); s9 += s14; s4 = uint.RotateRight(s4 ^ s9, 7);

			// In-place message permutation using cycle decomposition (except last round)
			// Permutation [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8] decomposes into two 8-cycles
			if (round < Rounds - 1) {
				uint tmp;
				// Cycle 1: 0→2→3→10→12→9→11→5→0
				tmp = m0; m0 = m2; m2 = m3; m3 = m10; m10 = m12; m12 = m9; m9 = m11; m11 = m5; m5 = tmp;
				// Cycle 2: 1→6→4→7→13→14→15→8→1
				tmp = m1; m1 = m6; m6 = m4; m4 = m7; m7 = m13; m13 = m14; m14 = m15; m15 = m8; m8 = tmp;
			}
		}

		// Write output using direct ref access — first 8 = state XOR high state, last 8 = high state XOR CV
		ref uint outRef = ref MemoryMarshal.GetReference(output);
		outRef = s0 ^ s8; Unsafe.Add(ref outRef, 1) = s1 ^ s9;
		Unsafe.Add(ref outRef, 2) = s2 ^ s10; Unsafe.Add(ref outRef, 3) = s3 ^ s11;
		Unsafe.Add(ref outRef, 4) = s4 ^ s12; Unsafe.Add(ref outRef, 5) = s5 ^ s13;
		Unsafe.Add(ref outRef, 6) = s6 ^ s14; Unsafe.Add(ref outRef, 7) = s7 ^ s15;
		Unsafe.Add(ref outRef, 8) = s8 ^ cvRef; Unsafe.Add(ref outRef, 9) = s9 ^ Unsafe.Add(ref cvRef, 1);
		Unsafe.Add(ref outRef, 10) = s10 ^ Unsafe.Add(ref cvRef, 2); Unsafe.Add(ref outRef, 11) = s11 ^ Unsafe.Add(ref cvRef, 3);
		Unsafe.Add(ref outRef, 12) = s12 ^ Unsafe.Add(ref cvRef, 4); Unsafe.Add(ref outRef, 13) = s13 ^ Unsafe.Add(ref cvRef, 5);
		Unsafe.Add(ref outRef, 14) = s14 ^ Unsafe.Add(ref cvRef, 6); Unsafe.Add(ref outRef, 15) = s15 ^ Unsafe.Add(ref cvRef, 7);
	}
}

/// <summary>
/// Factory methods for creating native BLAKE3 streaming hash instances.
/// </summary>
internal static class NativeBlake3Factory {
	/// <summary>
	/// Creates a BLAKE3 streaming hash instance.
	/// </summary>
	public static IStreamingHashBytes CreateBlake3() => new NativeBlake3Digest();

	/// <summary>
	/// Computes BLAKE3 hash in one shot.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static byte[] ComputeHash(ReadOnlySpan<byte> data) {
		using var hasher = new NativeBlake3Digest();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}
}
