using System.Buffers.Binary;
using System.Runtime.CompilerServices;

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

	// Tree stack for parent nodes (max depth 54 for 2^54 chunks)
	private readonly uint[][] _cvStack = new uint[54][];
	private int _cvStackLen;

	private long _totalBytes;

	/// <summary>
	/// Creates a new BLAKE3 streaming hash instance.
	/// </summary>
	public NativeBlake3Digest() {
		for (int i = 0; i < _cvStack.Length; i++) {
			_cvStack[i] = new uint[8];
		}
		Reset();
	}

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

		while (offset < data.Length) {
			// If the chunk buffer is full (1024 bytes), finalize this chunk and start a new one
			if (_chunkLen == ChunkLen) {
				uint[] chunkCv = CompressChunk(_chunkBuf.AsSpan(0, ChunkLen), IV, _chunkCounter);
				AddChunkCv(chunkCv, _chunkCounter);
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

		if (_cvStackLen == 0) {
			// Single chunk — compress as root
			uint[] rootOutput = CompressChunkRoot(chunkData, IV, _chunkCounter);
			return WordsToBytes(rootOutput);
		}

		// Multiple chunks — finalize current chunk normally, then merge parent stack
		uint[] cv = CompressChunk(chunkData, IV, _chunkCounter);

		// Merge with parent stack
		while (_cvStackLen > 0) {
			_cvStackLen--;
			uint[] left = _cvStack[_cvStackLen];

			byte[] parentBlock = new byte[BlockLen];
			CvToBytes(left, parentBlock, 0);
			CvToBytes(cv, parentBlock, 32);

			if (_cvStackLen == 0) {
				// Root parent — return full 16-word output
				uint[] rootOutput = Compress(IV, parentBlock, 0, BlockLen, Parent | Root);
				return WordsToBytes(rootOutput);
			}

			cv = First8(Compress(IV, parentBlock, 0, BlockLen, Parent));
		}

		// Should not reach here
		return WordsToBytes([cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
			0, 0, 0, 0, 0, 0, 0, 0]);
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
	/// Compresses an entire chunk and returns its 8-word chaining value.
	/// </summary>
	private static uint[] CompressChunk(ReadOnlySpan<byte> chunk, ReadOnlySpan<uint> key, ulong chunkCounter) {
		uint[] cv = new uint[8];
		key[..8].CopyTo(cv);

		int nBlocks = (chunk.Length + BlockLen - 1) / BlockLen;
		if (nBlocks == 0) nBlocks = 1;

		for (int i = 0; i < nBlocks; i++) {
			int blockStart = i * BlockLen;
			int remaining = chunk.Length - blockStart;
			int blockBytes = Math.Min(BlockLen, remaining);

			byte[] block = new byte[BlockLen];
			if (blockBytes > 0) {
				chunk.Slice(blockStart, blockBytes).CopyTo(block);
			}

			uint flags = 0u;
			if (i == 0) flags |= ChunkStart;
			if (i == nBlocks - 1) flags |= ChunkEnd;

			cv = First8(Compress(cv, block, chunkCounter, (uint)blockBytes, flags));
		}

		return cv;
	}

	/// <summary>
	/// Compresses an entire chunk as the root, returning full 16-word output from the last block.
	/// </summary>
	private static uint[] CompressChunkRoot(ReadOnlySpan<byte> chunk, ReadOnlySpan<uint> key, ulong chunkCounter) {
		uint[] cv = new uint[8];
		key[..8].CopyTo(cv);

		int nBlocks = (chunk.Length + BlockLen - 1) / BlockLen;
		if (nBlocks == 0) nBlocks = 1;

		for (int i = 0; i < nBlocks; i++) {
			int blockStart = i * BlockLen;
			int remaining = chunk.Length - blockStart;
			int blockBytes = Math.Min(BlockLen, remaining);

			byte[] block = new byte[BlockLen];
			if (blockBytes > 0) {
				chunk.Slice(blockStart, blockBytes).CopyTo(block);
			}

			uint flags = 0u;
			if (i == 0) flags |= ChunkStart;
			if (i == nBlocks - 1) flags |= ChunkEnd;

			if (i < nBlocks - 1) {
				cv = First8(Compress(cv, block, chunkCounter, (uint)blockBytes, flags));
			} else {
				// Last block — return full 16-word root output
				return Compress(cv, block, chunkCounter, (uint)blockBytes, flags | Root);
			}
		}

		// Fallback for empty input
		return Compress(cv, new byte[BlockLen], chunkCounter, 0, ChunkStart | ChunkEnd | Root);
	}

	/// <summary>
	/// Returns the first 8 words of a 16-word array.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint[] First8(uint[] output) =>
		[output[0], output[1], output[2], output[3], output[4], output[5], output[6], output[7]];

	/// <summary>
	/// Converts the first 8 words of output to a 32-byte result.
	/// </summary>
	private static byte[] WordsToBytes(uint[] output) {
		byte[] result = new byte[OutLen];
		for (int i = 0; i < 8; i++) {
			BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(i * 4), output[i]);
		}
		return result;
	}

	/// <summary>
	/// Adds a chunk chaining value to the tree, merging completed subtrees.
	/// </summary>
	private void AddChunkCv(uint[] newCv, ulong totalChunks) {
		while ((totalChunks & 1) != 0) {
			_cvStackLen--;
			uint[] left = _cvStack[_cvStackLen];

			byte[] parentBlock = new byte[BlockLen];
			CvToBytes(left, parentBlock, 0);
			CvToBytes(newCv, parentBlock, 32);

			newCv = First8(Compress(IV, parentBlock, 0, BlockLen, Parent));
			totalChunks >>= 1;
		}

		Array.Copy(newCv, _cvStack[_cvStackLen], 8);
		_cvStackLen++;
	}

	/// <summary>
	/// Writes 8 uint32 words as little-endian bytes into a block at the given offset.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CvToBytes(uint[] cv, byte[] block, int offset) {
		for (int i = 0; i < 8; i++) {
			BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(offset + i * 4), cv[i]);
		}
	}

	/// <summary>
	/// BLAKE3 compression function. Returns 16 words.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static uint[] Compress(ReadOnlySpan<uint> cv, ReadOnlySpan<byte> block, ulong counter, uint blockLen, uint flags) {
		// Parse block into 16 message words
		Span<uint> m = stackalloc uint[16];
		for (int i = 0; i < 16; i++) {
			m[i] = BinaryPrimitives.ReadUInt32LittleEndian(block[(i * 4)..]);
		}

		// Initialize state
		uint s0 = cv[0], s1 = cv[1], s2 = cv[2], s3 = cv[3];
		uint s4 = cv[4], s5 = cv[5], s6 = cv[6], s7 = cv[7];
		uint s8 = IV[0], s9 = IV[1], s10 = IV[2], s11 = IV[3];
		uint s12 = (uint)(counter & 0xffffffff);
		uint s13 = (uint)(counter >> 32);
		uint s14 = blockLen;
		uint s15 = flags;

		Span<uint> permuted = stackalloc uint[16];

		for (int round = 0; round < Rounds; round++) {
			// Column step: (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)
			s0 += s4 + m[0]; s12 = uint.RotateRight(s12 ^ s0, 16); s8 += s12; s4 = uint.RotateRight(s4 ^ s8, 12);
			s0 += s4 + m[1]; s12 = uint.RotateRight(s12 ^ s0, 8); s8 += s12; s4 = uint.RotateRight(s4 ^ s8, 7);

			s1 += s5 + m[2]; s13 = uint.RotateRight(s13 ^ s1, 16); s9 += s13; s5 = uint.RotateRight(s5 ^ s9, 12);
			s1 += s5 + m[3]; s13 = uint.RotateRight(s13 ^ s1, 8); s9 += s13; s5 = uint.RotateRight(s5 ^ s9, 7);

			s2 += s6 + m[4]; s14 = uint.RotateRight(s14 ^ s2, 16); s10 += s14; s6 = uint.RotateRight(s6 ^ s10, 12);
			s2 += s6 + m[5]; s14 = uint.RotateRight(s14 ^ s2, 8); s10 += s14; s6 = uint.RotateRight(s6 ^ s10, 7);

			s3 += s7 + m[6]; s15 = uint.RotateRight(s15 ^ s3, 16); s11 += s15; s7 = uint.RotateRight(s7 ^ s11, 12);
			s3 += s7 + m[7]; s15 = uint.RotateRight(s15 ^ s3, 8); s11 += s15; s7 = uint.RotateRight(s7 ^ s11, 7);

			// Diagonal step: (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14)
			s0 += s5 + m[8]; s15 = uint.RotateRight(s15 ^ s0, 16); s10 += s15; s5 = uint.RotateRight(s5 ^ s10, 12);
			s0 += s5 + m[9]; s15 = uint.RotateRight(s15 ^ s0, 8); s10 += s15; s5 = uint.RotateRight(s5 ^ s10, 7);

			s1 += s6 + m[10]; s12 = uint.RotateRight(s12 ^ s1, 16); s11 += s12; s6 = uint.RotateRight(s6 ^ s11, 12);
			s1 += s6 + m[11]; s12 = uint.RotateRight(s12 ^ s1, 8); s11 += s12; s6 = uint.RotateRight(s6 ^ s11, 7);

			s2 += s7 + m[12]; s13 = uint.RotateRight(s13 ^ s2, 16); s8 += s13; s7 = uint.RotateRight(s7 ^ s8, 12);
			s2 += s7 + m[13]; s13 = uint.RotateRight(s13 ^ s2, 8); s8 += s13; s7 = uint.RotateRight(s7 ^ s8, 7);

			s3 += s4 + m[14]; s14 = uint.RotateRight(s14 ^ s3, 16); s9 += s14; s4 = uint.RotateRight(s4 ^ s9, 12);
			s3 += s4 + m[15]; s14 = uint.RotateRight(s14 ^ s3, 8); s9 += s14; s4 = uint.RotateRight(s4 ^ s9, 7);

			// Permute message words for next round (except last)
			if (round < Rounds - 1) {
				for (int i = 0; i < 16; i++) {
					permuted[i] = m[MsgPermutation[i]];
				}
				permuted.CopyTo(m);
			}
		}

		return [
			s0 ^ s8, s1 ^ s9, s2 ^ s10, s3 ^ s11,
			s4 ^ s12, s5 ^ s13, s6 ^ s14, s7 ^ s15,
			s8 ^ cv[0], s9 ^ cv[1], s10 ^ cv[2], s11 ^ cv[3],
			s12 ^ cv[4], s13 ^ cv[5], s14 ^ cv[6], s15 ^ cv[7]
		];
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
