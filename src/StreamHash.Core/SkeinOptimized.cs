using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Optimized native implementation of Skein hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// Skein is a cryptographic hash function designed by Bruce Schneier, Niels Ferguson,
/// Stefan Lucks, Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas, and Jesse Walker.
/// It was a finalist in the NIST SHA-3 competition.
/// </para>
/// <para>
/// This implementation uses zero-allocation techniques:
/// - Pre-allocated working arrays in constructor
/// - Stackalloc for small temporary buffers
/// - No array allocations in hot paths
/// </para>
/// <para>
/// Reference: "The Skein Hash Function Family" - https://www.skein-hash.info/
/// Reference: dchest/skein Go implementation for test vectors
/// </para>
/// </remarks>
internal abstract class SkeinOptimized : IStreamingHashBytes {
	/// <summary>State size in bits.</summary>
	protected readonly int _stateBits;

	/// <summary>Output size in bits.</summary>
	protected readonly int _outputBits;

	/// <summary>Block size in bytes (state size / 8).</summary>
	protected readonly int _blockBytes;

	/// <summary>Number of 64-bit words in state.</summary>
	protected readonly int _numWords;

	/// <summary>Current state.</summary>
	protected readonly ulong[] _state;

	/// <summary>Working buffer for block processing.</summary>
	protected readonly byte[] _buffer;

	/// <summary>Current position in buffer.</summary>
	protected int _bufferPos;

	/// <summary>Total bytes processed.</summary>
	protected long _totalBytes;

	/// <summary>Tweak values T0, T1.</summary>
	protected ulong _t0, _t1;

	/// <summary>Pre-allocated working arrays for Threefish (reused across calls).</summary>
	protected readonly ulong[] _work;

	/// <summary>Pre-allocated saved state for output transform.</summary>
	protected readonly ulong[] _savedState;

	/// <summary>Pre-allocated counter block for output transform.</summary>
	protected readonly byte[] _counterBlock;

	/// <summary>Pre-allocated config block.</summary>
	protected readonly byte[] _configBlock;

	/// <summary>
	/// Creates a new Skein instance with pre-allocated buffers.
	/// </summary>
	/// <param name="stateBits">State size in bits (256, 512, or 1024).</param>
	/// <param name="outputBits">Output size in bits.</param>
	protected SkeinOptimized(int stateBits, int outputBits) {
		_stateBits = stateBits;
		_outputBits = outputBits;
		_blockBytes = stateBits / 8;
		_numWords = stateBits / 64;

		// Pre-allocate all arrays once
		_state = new ulong[_numWords];
		_buffer = new byte[_blockBytes];
		_work = new ulong[_numWords];
		_savedState = new ulong[_numWords];
		_counterBlock = new byte[_blockBytes];
		_configBlock = new byte[_blockBytes];

		// Note: Reset() is NOT called here - derived classes must call it after their own initialization
	}

	/// <inheritdoc/>
	public int BlockSize => _blockBytes;

	/// <inheritdoc/>
	public int DigestSize => _outputBits / 8;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public void Update(ReadOnlySpan<byte> data) {
		_totalBytes += data.Length;
		int offset = 0;

		// Process partial buffer first
		if (_bufferPos > 0) {
			int needed = _blockBytes - _bufferPos;
			if (data.Length < needed) {
				data.CopyTo(_buffer.AsSpan(_bufferPos));
				_bufferPos += data.Length;
				return;
			}
			data[..needed].CopyTo(_buffer.AsSpan(_bufferPos));

			// Update tweak with byte count
			_t0 += (ulong)_blockBytes;
			ProcessBlock(_buffer, false);
			offset = needed;
			_bufferPos = 0;
		}

		// Process full blocks
		while (offset + _blockBytes <= data.Length) {
			_t0 += (ulong)_blockBytes;
			ProcessBlockSpan(data.Slice(offset, _blockBytes), false);
			offset += _blockBytes;
		}

		// Save remaining bytes
		if (offset < data.Length) {
			data[offset..].CopyTo(_buffer.AsSpan());
			_bufferPos = data.Length - offset;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		// Set final flag
		_t1 |= TweakFinal;

		// Update tweak with final byte count
		_t0 += (ulong)_bufferPos;

		// Pad remaining bytes with zeros
		Array.Clear(_buffer, _bufferPos, _blockBytes - _bufferPos);

		// Process final block
		ProcessBlock(_buffer, true);

		// Output transformation
		byte[] result = new byte[DigestSize];
		OutputTransform(result);

		return result;
	}

	/// <inheritdoc/>
	public abstract void Reset();

	/// <inheritdoc/>
	public void Dispose() {
		Array.Clear(_state);
		Array.Clear(_buffer);
		Array.Clear(_work);
		Array.Clear(_savedState);
		Array.Clear(_counterBlock);
	}

	/// <summary>
	/// Processes a single block with Threefish encryption.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	protected void ProcessBlock(byte[] block, bool isFinal) {
		// Convert block to words using efficient span casting
		var blockSpan = MemoryMarshal.Cast<byte, ulong>(block.AsSpan());
		for (int i = 0; i < _numWords; i++) {
			_work[i] = blockSpan[i];
		}

		// Encrypt with Threefish
		ThreefishEncrypt();

		// XOR plaintext into ciphertext
		for (int i = 0; i < _numWords; i++) {
			_state[i] = _work[i] ^ blockSpan[i];
		}

		// Clear first bit if not final
		if (!isFinal) {
			_t1 &= ~TweakFirst;
		}
	}

	/// <summary>
	/// Processes a block directly from a span.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	protected void ProcessBlockSpan(ReadOnlySpan<byte> block, bool isFinal) {
		// Convert block to words
		var blockSpan = MemoryMarshal.Cast<byte, ulong>(block);
		for (int i = 0; i < _numWords; i++) {
			_work[i] = blockSpan[i];
		}

		// Encrypt with Threefish
		ThreefishEncrypt();

		// XOR plaintext into ciphertext
		for (int i = 0; i < _numWords; i++) {
			_state[i] = _work[i] ^ blockSpan[i];
		}

		// Clear first bit if not final
		if (!isFinal) {
			_t1 &= ~TweakFirst;
		}
	}

	/// <summary>
	/// Performs the output transformation to produce the hash.
	/// Zero-allocation version using pre-allocated arrays.
	/// </summary>
	protected void OutputTransform(byte[] output) {
		int bytesOutput = 0;
		int blockCounter = 0;

		// Save the current state (chain value after message processing)
		Array.Copy(_state, _savedState, _numWords);

		// Clear counter block once
		Array.Clear(_counterBlock);

		while (bytesOutput < DigestSize) {
			// Restore state for each output block
			Array.Copy(_savedState, _state, _numWords);

			// Set up output tweak
			_t0 = 8;
			_t1 = TweakFirst | TweakFinal | TweakTypeOut;

			// Write counter to pre-allocated block
			BitConverter.TryWriteBytes(_counterBlock.AsSpan(0, 8), (ulong)blockCounter);

			// Parse counter block as words
			var counterSpan = MemoryMarshal.Cast<byte, ulong>(_counterBlock.AsSpan());
			for (int i = 0; i < _numWords; i++) {
				_work[i] = counterSpan[i];
			}

			// Run Threefish
			ThreefishEncrypt();

			// XOR output with counter block (only first word is non-zero)
			_work[0] ^= (ulong)blockCounter;

			// Copy output words
			int bytesToCopy = Math.Min(_blockBytes, DigestSize - bytesOutput);
			var outputSpan = output.AsSpan(bytesOutput);

			// Write words efficiently
			int fullWords = bytesToCopy / 8;
			for (int i = 0; i < fullWords; i++) {
				BitConverter.TryWriteBytes(outputSpan.Slice(i * 8, 8), _work[i]);
			}

			// Handle partial last word
			int remaining = bytesToCopy % 8;
			if (remaining > 0) {
				ulong lastWord = _work[fullWords];
				for (int j = 0; j < remaining; j++) {
					outputSpan[fullWords * 8 + j] = (byte)(lastWord >> (j * 8));
				}
			}

			bytesOutput += bytesToCopy;
			blockCounter++;
		}
	}

	/// <summary>
	/// Threefish block cipher encryption - zero allocation, uses pre-allocated _work array.
	/// Uses _state as key, _work as input/output, _t0/_t1 as tweak.
	/// </summary>
	protected abstract void ThreefishEncrypt();

	// Tweak flags
	protected const ulong TweakFirst = 1UL << 62;
	protected const ulong TweakFinal = 1UL << 63;
	protected const ulong TweakTypeMsg = 48UL << 56;
	protected const ulong TweakTypeOut = 63UL << 56;
	protected const ulong TweakTypeCfg = 4UL << 56;

	// Threefish constant
	protected const ulong C240 = 0x1bd11bdaa9fc1a22UL;

	/// <summary>Rotate left helper.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected static ulong RotL(ulong v, int n) => BitOperations.RotateLeft(v, n);
}

/// <summary>
/// Optimized Skein-256 with zero-allocation Threefish-256.
/// </summary>
internal sealed class Skein256Optimized : SkeinOptimized {
	public Skein256Optimized(int outputBits = 256) : base(256, outputBits) {
		Reset();
	}

	public override void Reset() {
		Array.Clear(_state);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;

		InitializeConfiguration();
	}

	private void InitializeConfiguration() {
		// Use pre-allocated config block
		Array.Clear(_configBlock);
		_configBlock[0] = (byte)'S';
		_configBlock[1] = (byte)'H';
		_configBlock[2] = (byte)'A';
		_configBlock[3] = (byte)'3';
		_configBlock[4] = 1;
		BitConverter.TryWriteBytes(_configBlock.AsSpan(8, 8), (ulong)_outputBits);

		_t0 = 32;
		_t1 = TweakFirst | TweakFinal | TweakTypeCfg;
		ProcessBlock(_configBlock, true);

		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;
	}

	/// <summary>
	/// Threefish-256: 72 rounds, 4 words. Fully unrolled key schedule.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected override void ThreefishEncrypt() {
		ulong k0 = _state[0], k1 = _state[1], k2 = _state[2], k3 = _state[3];
		ulong k4 = k0 ^ k1 ^ k2 ^ k3 ^ C240;
		ulong t0 = _t0, t1 = _t1, t2 = t0 ^ t1;

		ulong v0 = _work[0] + k0;
		ulong v1 = _work[1] + k1 + t0;
		ulong v2 = _work[2] + k2 + t1;
		ulong v3 = _work[3] + k3;

		// Unroll 18 iterations (72 rounds / 4 rounds per iteration)
		// Rotation constants from Skein spec v1.3, Section 8.3
		// d=0
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k1; v1 += k2 + t1; v2 += k3 + t2; v3 += k4 + 1;

		// d=1
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k2; v1 += k3 + t2; v2 += k4 + t0; v3 += k0 + 2;

		// d=2
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k3; v1 += k4 + t0; v2 += k0 + t1; v3 += k1 + 3;

		// d=3
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k4; v1 += k0 + t1; v2 += k1 + t2; v3 += k2 + 4;

		// d=4
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k0; v1 += k1 + t2; v2 += k2 + t0; v3 += k3 + 5;

		// d=5
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k1; v1 += k2 + t0; v2 += k3 + t1; v3 += k4 + 6;

		// d=6
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k2; v1 += k3 + t1; v2 += k4 + t2; v3 += k0 + 7;

		// d=7
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k3; v1 += k4 + t2; v2 += k0 + t0; v3 += k1 + 8;

		// d=8
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k4; v1 += k0 + t0; v2 += k1 + t1; v3 += k2 + 9;

		// d=9
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k0; v1 += k1 + t1; v2 += k2 + t2; v3 += k3 + 10;

		// d=10
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k1; v1 += k2 + t2; v2 += k3 + t0; v3 += k4 + 11;

		// d=11
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k2; v1 += k3 + t0; v2 += k4 + t1; v3 += k0 + 12;

		// d=12
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k3; v1 += k4 + t1; v2 += k0 + t2; v3 += k1 + 13;

		// d=13
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k4; v1 += k0 + t2; v2 += k1 + t0; v3 += k2 + 14;

		// d=14
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k0; v1 += k1 + t0; v2 += k2 + t1; v3 += k3 + 15;

		// d=15
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k1; v1 += k2 + t1; v2 += k3 + t2; v3 += k4 + 16;

		// d=16
		v0 += v1; v1 = RotL(v1, 14) ^ v0; v2 += v3; v3 = RotL(v3, 16) ^ v2;
		v0 += v3; v3 = RotL(v3, 52) ^ v0; v2 += v1; v1 = RotL(v1, 57) ^ v2;
		v0 += v1; v1 = RotL(v1, 23) ^ v0; v2 += v3; v3 = RotL(v3, 40) ^ v2;
		v0 += v3; v3 = RotL(v3, 5) ^ v0; v2 += v1; v1 = RotL(v1, 37) ^ v2;
		v0 += k2; v1 += k3 + t2; v2 += k4 + t0; v3 += k0 + 17;

		// d=17 (final)
		v0 += v1; v1 = RotL(v1, 25) ^ v0; v2 += v3; v3 = RotL(v3, 33) ^ v2;
		v0 += v3; v3 = RotL(v3, 46) ^ v0; v2 += v1; v1 = RotL(v1, 12) ^ v2;
		v0 += v1; v1 = RotL(v1, 58) ^ v0; v2 += v3; v3 = RotL(v3, 22) ^ v2;
		v0 += v3; v3 = RotL(v3, 32) ^ v0; v2 += v1; v1 = RotL(v1, 32) ^ v2;
		v0 += k3; v1 += k4 + t0; v2 += k0 + t1; v3 += k1 + 18;

		_work[0] = v0;
		_work[1] = v1;
		_work[2] = v2;
		_work[3] = v3;
	}
}

/// <summary>
/// Optimized Skein-512 with zero-allocation Threefish-512.
/// </summary>
internal sealed class Skein512Optimized : SkeinOptimized {
	public Skein512Optimized(int outputBits = 512) : base(512, outputBits) {
		Reset();
	}

	public override void Reset() {
		Array.Clear(_state);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;

		InitializeConfiguration();
	}

	private void InitializeConfiguration() {
		Array.Clear(_configBlock);
		_configBlock[0] = (byte)'S';
		_configBlock[1] = (byte)'H';
		_configBlock[2] = (byte)'A';
		_configBlock[3] = (byte)'3';
		_configBlock[4] = 1;
		BitConverter.TryWriteBytes(_configBlock.AsSpan(8, 8), (ulong)_outputBits);

		_t0 = 32;
		_t1 = TweakFirst | TweakFinal | TweakTypeCfg;
		ProcessBlock(_configBlock, true);

		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;
	}

	/// <summary>
	/// Threefish-512: 72 rounds, 8 words. Fully unrolled.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected override void ThreefishEncrypt() {
		ulong k0 = _state[0], k1 = _state[1], k2 = _state[2], k3 = _state[3];
		ulong k4 = _state[4], k5 = _state[5], k6 = _state[6], k7 = _state[7];
		ulong k8 = k0 ^ k1 ^ k2 ^ k3 ^ k4 ^ k5 ^ k6 ^ k7 ^ C240;
		ulong t0 = _t0, t1 = _t1, t2 = t0 ^ t1;

		ulong b0 = _work[0] + k0;
		ulong b1 = _work[1] + k1;
		ulong b2 = _work[2] + k2;
		ulong b3 = _work[3] + k3;
		ulong b4 = _work[4] + k4;
		ulong b5 = _work[5] + k5 + t0;
		ulong b6 = _work[6] + k6 + t1;
		ulong b7 = _work[7] + k7;

		// Unroll all 18 iterations (72 rounds)
		// Rotation constants from Skein spec v1.3

		// d=0
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k1; b1 += k2; b2 += k3; b3 += k4; b4 += k5; b5 += k6 + t1; b6 += k7 + t2; b7 += k8 + 1;

		// d=1
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k2; b1 += k3; b2 += k4; b3 += k5; b4 += k6; b5 += k7 + t2; b6 += k8 + t0; b7 += k0 + 2;

		// d=2
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k3; b1 += k4; b2 += k5; b3 += k6; b4 += k7; b5 += k8 + t0; b6 += k0 + t1; b7 += k1 + 3;

		// d=3
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k4; b1 += k5; b2 += k6; b3 += k7; b4 += k8; b5 += k0 + t1; b6 += k1 + t2; b7 += k2 + 4;

		// d=4
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k5; b1 += k6; b2 += k7; b3 += k8; b4 += k0; b5 += k1 + t2; b6 += k2 + t0; b7 += k3 + 5;

		// d=5
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k6; b1 += k7; b2 += k8; b3 += k0; b4 += k1; b5 += k2 + t0; b6 += k3 + t1; b7 += k4 + 6;

		// d=6
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k7; b1 += k8; b2 += k0; b3 += k1; b4 += k2; b5 += k3 + t1; b6 += k4 + t2; b7 += k5 + 7;

		// d=7
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k8; b1 += k0; b2 += k1; b3 += k2; b4 += k3; b5 += k4 + t2; b6 += k5 + t0; b7 += k6 + 8;

		// d=8
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k0; b1 += k1; b2 += k2; b3 += k3; b4 += k4; b5 += k5 + t0; b6 += k6 + t1; b7 += k7 + 9;

		// d=9
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k1; b1 += k2; b2 += k3; b3 += k4; b4 += k5; b5 += k6 + t1; b6 += k7 + t2; b7 += k8 + 10;

		// d=10
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k2; b1 += k3; b2 += k4; b3 += k5; b4 += k6; b5 += k7 + t2; b6 += k8 + t0; b7 += k0 + 11;

		// d=11
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k3; b1 += k4; b2 += k5; b3 += k6; b4 += k7; b5 += k8 + t0; b6 += k0 + t1; b7 += k1 + 12;

		// d=12
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k4; b1 += k5; b2 += k6; b3 += k7; b4 += k8; b5 += k0 + t1; b6 += k1 + t2; b7 += k2 + 13;

		// d=13
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k5; b1 += k6; b2 += k7; b3 += k8; b4 += k0; b5 += k1 + t2; b6 += k2 + t0; b7 += k3 + 14;

		// d=14
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k6; b1 += k7; b2 += k8; b3 += k0; b4 += k1; b5 += k2 + t0; b6 += k3 + t1; b7 += k4 + 15;

		// d=15
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k7; b1 += k8; b2 += k0; b3 += k1; b4 += k2; b5 += k3 + t1; b6 += k4 + t2; b7 += k5 + 16;

		// d=16
		b0 += b1; b1 = RotL(b1, 46) ^ b0; b2 += b3; b3 = RotL(b3, 36) ^ b2;
		b4 += b5; b5 = RotL(b5, 19) ^ b4; b6 += b7; b7 = RotL(b7, 37) ^ b6;
		b2 += b1; b1 = RotL(b1, 33) ^ b2; b4 += b7; b7 = RotL(b7, 27) ^ b4;
		b6 += b5; b5 = RotL(b5, 14) ^ b6; b0 += b3; b3 = RotL(b3, 42) ^ b0;
		b4 += b1; b1 = RotL(b1, 17) ^ b4; b6 += b3; b3 = RotL(b3, 49) ^ b6;
		b0 += b5; b5 = RotL(b5, 36) ^ b0; b2 += b7; b7 = RotL(b7, 39) ^ b2;
		b6 += b1; b1 = RotL(b1, 44) ^ b6; b0 += b7; b7 = RotL(b7, 9) ^ b0;
		b2 += b5; b5 = RotL(b5, 54) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4;
		b0 += k8; b1 += k0; b2 += k1; b3 += k2; b4 += k3; b5 += k4 + t2; b6 += k5 + t0; b7 += k6 + 17;

		// d=17 (final)
		b0 += b1; b1 = RotL(b1, 39) ^ b0; b2 += b3; b3 = RotL(b3, 30) ^ b2;
		b4 += b5; b5 = RotL(b5, 34) ^ b4; b6 += b7; b7 = RotL(b7, 24) ^ b6;
		b2 += b1; b1 = RotL(b1, 13) ^ b2; b4 += b7; b7 = RotL(b7, 50) ^ b4;
		b6 += b5; b5 = RotL(b5, 10) ^ b6; b0 += b3; b3 = RotL(b3, 17) ^ b0;
		b4 += b1; b1 = RotL(b1, 25) ^ b4; b6 += b3; b3 = RotL(b3, 29) ^ b6;
		b0 += b5; b5 = RotL(b5, 39) ^ b0; b2 += b7; b7 = RotL(b7, 43) ^ b2;
		b6 += b1; b1 = RotL(b1, 8) ^ b6; b0 += b7; b7 = RotL(b7, 35) ^ b0;
		b2 += b5; b5 = RotL(b5, 56) ^ b2; b4 += b3; b3 = RotL(b3, 22) ^ b4;
		b0 += k0; b1 += k1; b2 += k2; b3 += k3; b4 += k4; b5 += k5 + t0; b6 += k6 + t1; b7 += k7 + 18;

		_work[0] = b0;
		_work[1] = b1;
		_work[2] = b2;
		_work[3] = b3;
		_work[4] = b4;
		_work[5] = b5;
		_work[6] = b6;
		_work[7] = b7;
	}
}

/// <summary>
/// Optimized Skein-1024 with zero-allocation Threefish-1024.
/// </summary>
internal sealed class Skein1024Optimized : SkeinOptimized {
	/// <summary>Pre-allocated extended key schedule (17 keys + 16 repeated = 33 total).</summary>
	private readonly ulong[] _kw = new ulong[33];

	/// <summary>Pre-allocated extended tweak (3 values + 2 repeated = 5 total).</summary>
	private readonly ulong[] _ts = new ulong[5];

	public Skein1024Optimized(int outputBits = 1024) : base(1024, outputBits) {
		Reset();
	}

	public override void Reset() {
		Array.Clear(_state);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;

		InitializeConfiguration();
	}

	private void InitializeConfiguration() {
		Array.Clear(_configBlock);
		_configBlock[0] = (byte)'S';
		_configBlock[1] = (byte)'H';
		_configBlock[2] = (byte)'A';
		_configBlock[3] = (byte)'3';
		_configBlock[4] = 1;
		BitConverter.TryWriteBytes(_configBlock.AsSpan(8, 8), (ulong)_outputBits);

		_t0 = 32;
		_t1 = TweakFirst | TweakFinal | TweakTypeCfg;
		ProcessBlock(_configBlock, true);

		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;
	}

	/// <summary>
	/// Threefish-1024: 80 rounds, 16 words.
	/// Uses local variables instead of arrays to eliminate bounds checking.
	/// Extended key schedule (33 entries) eliminates modulo in key injection.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	protected override void ThreefishEncrypt() {
		// Build extended key schedule: 17 keys + 16 repeated = 33 total for modulo-free lookup
		ulong[] kw = _kw;
		ulong knw = C240;
		for (int i = 0; i < 16; i++) {
			kw[i] = _state[i];
			knw ^= _state[i];
		}
		kw[16] = knw;
		for (int i = 0; i < 16; i++) {
			kw[17 + i] = kw[i];
		}

		// Extended tweak: 5 entries for modulo-free lookup
		ulong t0 = _t0, t1 = _t1, t2 = t0 ^ t1;
		ulong[] ts = _ts;
		ts[0] = t0; ts[1] = t1; ts[2] = t2; ts[3] = t0; ts[4] = t1;

		// Load plaintext into 16 local variables (CRITICAL: eliminates array bounds checking)
		ulong b0 = _work[0], b1 = _work[1], b2 = _work[2], b3 = _work[3];
		ulong b4 = _work[4], b5 = _work[5], b6 = _work[6], b7 = _work[7];
		ulong b8 = _work[8], b9 = _work[9], b10 = _work[10], b11 = _work[11];
		ulong b12 = _work[12], b13 = _work[13], b14 = _work[14], b15 = _work[15];

		// First subkey injection (subkey 0)
		b0 += kw[0]; b1 += kw[1]; b2 += kw[2]; b3 += kw[3];
		b4 += kw[4]; b5 += kw[5]; b6 += kw[6]; b7 += kw[7];
		b8 += kw[8]; b9 += kw[9]; b10 += kw[10]; b11 += kw[11];
		b12 += kw[12]; b13 += kw[13] + t0; b14 += kw[14] + t1; b15 += kw[15];

		// 20 iterations of 4 rounds each (80 rounds total) — fully unrolled with literal rotation constants
		// Eliminates ReadOnlySpan<byte> RotConsts memory loads + variable-count rotates per mix operation
		// Each RotL call now has a compile-time constant rotation amount → JIT emits immediate-operand ROL

		// ===== Iteration d=0 =====
		b0 += b1; b1 = RotL(b1, 24) ^ b0; b2 += b3; b3 = RotL(b3, 13) ^ b2; b4 += b5; b5 = RotL(b5, 8) ^ b4; b6 += b7; b7 = RotL(b7, 47) ^ b6; b8 += b9; b9 = RotL(b9, 8) ^ b8; b10 += b11; b11 = RotL(b11, 17) ^ b10; b12 += b13; b13 = RotL(b13, 22) ^ b12; b14 += b15; b15 = RotL(b15, 37) ^ b14;
		b0 += b9; b9 = RotL(b9, 38) ^ b0; b2 += b13; b13 = RotL(b13, 19) ^ b2; b6 += b11; b11 = RotL(b11, 10) ^ b6; b4 += b15; b15 = RotL(b15, 55) ^ b4; b10 += b7; b7 = RotL(b7, 49) ^ b10; b12 += b3; b3 = RotL(b3, 18) ^ b12; b14 += b5; b5 = RotL(b5, 23) ^ b14; b8 += b1; b1 = RotL(b1, 52) ^ b8;
		b0 += b7; b7 = RotL(b7, 33) ^ b0; b2 += b5; b5 = RotL(b5, 4) ^ b2; b4 += b3; b3 = RotL(b3, 51) ^ b4; b6 += b1; b1 = RotL(b1, 13) ^ b6; b12 += b15; b15 = RotL(b15, 34) ^ b12; b14 += b13; b13 = RotL(b13, 41) ^ b14; b8 += b11; b11 = RotL(b11, 59) ^ b8; b10 += b9; b9 = RotL(b9, 17) ^ b10;
		b0 += b15; b15 = RotL(b15, 5) ^ b0; b2 += b11; b11 = RotL(b11, 20) ^ b2; b6 += b13; b13 = RotL(b13, 48) ^ b6; b4 += b9; b9 = RotL(b9, 41) ^ b4; b14 += b1; b1 = RotL(b1, 47) ^ b14; b8 += b5; b5 = RotL(b5, 28) ^ b8; b10 += b3; b3 = RotL(b3, 16) ^ b10; b12 += b7; b7 = RotL(b7, 25) ^ b12;
		b0 += kw[1]; b1 += kw[2]; b2 += kw[3]; b3 += kw[4];
		b4 += kw[5]; b5 += kw[6]; b6 += kw[7]; b7 += kw[8];
		b8 += kw[9]; b9 += kw[10]; b10 += kw[11]; b11 += kw[12];
		b12 += kw[13];
		b13 += kw[14] + ts[1];
		b14 += kw[15] + ts[2];
		b15 += kw[16] + (ulong)1;

		// ===== Iteration d=1 =====
		b0 += b1; b1 = RotL(b1, 38) ^ b0; b2 += b3; b3 = RotL(b3, 19) ^ b2; b4 += b5; b5 = RotL(b5, 10) ^ b4; b6 += b7; b7 = RotL(b7, 55) ^ b6; b8 += b9; b9 = RotL(b9, 49) ^ b8; b10 += b11; b11 = RotL(b11, 18) ^ b10; b12 += b13; b13 = RotL(b13, 23) ^ b12; b14 += b15; b15 = RotL(b15, 52) ^ b14;
		b0 += b9; b9 = RotL(b9, 33) ^ b0; b2 += b13; b13 = RotL(b13, 4) ^ b2; b6 += b11; b11 = RotL(b11, 51) ^ b6; b4 += b15; b15 = RotL(b15, 13) ^ b4; b10 += b7; b7 = RotL(b7, 34) ^ b10; b12 += b3; b3 = RotL(b3, 41) ^ b12; b14 += b5; b5 = RotL(b5, 59) ^ b14; b8 += b1; b1 = RotL(b1, 17) ^ b8;
		b0 += b7; b7 = RotL(b7, 5) ^ b0; b2 += b5; b5 = RotL(b5, 20) ^ b2; b4 += b3; b3 = RotL(b3, 48) ^ b4; b6 += b1; b1 = RotL(b1, 41) ^ b6; b12 += b15; b15 = RotL(b15, 47) ^ b12; b14 += b13; b13 = RotL(b13, 28) ^ b14; b8 += b11; b11 = RotL(b11, 16) ^ b8; b10 += b9; b9 = RotL(b9, 25) ^ b10;
		b0 += b15; b15 = RotL(b15, 41) ^ b0; b2 += b11; b11 = RotL(b11, 9) ^ b2; b6 += b13; b13 = RotL(b13, 37) ^ b6; b4 += b9; b9 = RotL(b9, 31) ^ b4; b14 += b1; b1 = RotL(b1, 12) ^ b14; b8 += b5; b5 = RotL(b5, 47) ^ b8; b10 += b3; b3 = RotL(b3, 44) ^ b10; b12 += b7; b7 = RotL(b7, 30) ^ b12;
		b0 += kw[2]; b1 += kw[3]; b2 += kw[4]; b3 += kw[5];
		b4 += kw[6]; b5 += kw[7]; b6 += kw[8]; b7 += kw[9];
		b8 += kw[10]; b9 += kw[11]; b10 += kw[12]; b11 += kw[13];
		b12 += kw[14];
		b13 += kw[15] + ts[2];
		b14 += kw[16] + ts[3];
		b15 += kw[17] + (ulong)2;

		// ===== Iteration d=2 =====
		b0 += b1; b1 = RotL(b1, 33) ^ b0; b2 += b3; b3 = RotL(b3, 4) ^ b2; b4 += b5; b5 = RotL(b5, 51) ^ b4; b6 += b7; b7 = RotL(b7, 13) ^ b6; b8 += b9; b9 = RotL(b9, 34) ^ b8; b10 += b11; b11 = RotL(b11, 41) ^ b10; b12 += b13; b13 = RotL(b13, 59) ^ b12; b14 += b15; b15 = RotL(b15, 17) ^ b14;
		b0 += b9; b9 = RotL(b9, 5) ^ b0; b2 += b13; b13 = RotL(b13, 20) ^ b2; b6 += b11; b11 = RotL(b11, 48) ^ b6; b4 += b15; b15 = RotL(b15, 41) ^ b4; b10 += b7; b7 = RotL(b7, 47) ^ b10; b12 += b3; b3 = RotL(b3, 28) ^ b12; b14 += b5; b5 = RotL(b5, 16) ^ b14; b8 += b1; b1 = RotL(b1, 25) ^ b8;
		b0 += b7; b7 = RotL(b7, 41) ^ b0; b2 += b5; b5 = RotL(b5, 9) ^ b2; b4 += b3; b3 = RotL(b3, 37) ^ b4; b6 += b1; b1 = RotL(b1, 31) ^ b6; b12 += b15; b15 = RotL(b15, 12) ^ b12; b14 += b13; b13 = RotL(b13, 47) ^ b14; b8 += b11; b11 = RotL(b11, 44) ^ b8; b10 += b9; b9 = RotL(b9, 30) ^ b10;
		b0 += b15; b15 = RotL(b15, 16) ^ b0; b2 += b11; b11 = RotL(b11, 34) ^ b2; b6 += b13; b13 = RotL(b13, 56) ^ b6; b4 += b9; b9 = RotL(b9, 51) ^ b4; b14 += b1; b1 = RotL(b1, 4) ^ b14; b8 += b5; b5 = RotL(b5, 53) ^ b8; b10 += b3; b3 = RotL(b3, 42) ^ b10; b12 += b7; b7 = RotL(b7, 41) ^ b12;
		b0 += kw[3]; b1 += kw[4]; b2 += kw[5]; b3 += kw[6];
		b4 += kw[7]; b5 += kw[8]; b6 += kw[9]; b7 += kw[10];
		b8 += kw[11]; b9 += kw[12]; b10 += kw[13]; b11 += kw[14];
		b12 += kw[15];
		b13 += kw[16] + ts[0];
		b14 += kw[17] + ts[1];
		b15 += kw[18] + (ulong)3;

		// ===== Iteration d=3 =====
		b0 += b1; b1 = RotL(b1, 5) ^ b0; b2 += b3; b3 = RotL(b3, 20) ^ b2; b4 += b5; b5 = RotL(b5, 48) ^ b4; b6 += b7; b7 = RotL(b7, 41) ^ b6; b8 += b9; b9 = RotL(b9, 47) ^ b8; b10 += b11; b11 = RotL(b11, 28) ^ b10; b12 += b13; b13 = RotL(b13, 16) ^ b12; b14 += b15; b15 = RotL(b15, 25) ^ b14;
		b0 += b9; b9 = RotL(b9, 41) ^ b0; b2 += b13; b13 = RotL(b13, 9) ^ b2; b6 += b11; b11 = RotL(b11, 37) ^ b6; b4 += b15; b15 = RotL(b15, 31) ^ b4; b10 += b7; b7 = RotL(b7, 12) ^ b10; b12 += b3; b3 = RotL(b3, 47) ^ b12; b14 += b5; b5 = RotL(b5, 44) ^ b14; b8 += b1; b1 = RotL(b1, 30) ^ b8;
		b0 += b7; b7 = RotL(b7, 16) ^ b0; b2 += b5; b5 = RotL(b5, 34) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4; b6 += b1; b1 = RotL(b1, 51) ^ b6; b12 += b15; b15 = RotL(b15, 4) ^ b12; b14 += b13; b13 = RotL(b13, 53) ^ b14; b8 += b11; b11 = RotL(b11, 42) ^ b8; b10 += b9; b9 = RotL(b9, 41) ^ b10;
		b0 += b15; b15 = RotL(b15, 31) ^ b0; b2 += b11; b11 = RotL(b11, 44) ^ b2; b6 += b13; b13 = RotL(b13, 47) ^ b6; b4 += b9; b9 = RotL(b9, 46) ^ b4; b14 += b1; b1 = RotL(b1, 19) ^ b14; b8 += b5; b5 = RotL(b5, 42) ^ b8; b10 += b3; b3 = RotL(b3, 44) ^ b10; b12 += b7; b7 = RotL(b7, 25) ^ b12;
		b0 += kw[4]; b1 += kw[5]; b2 += kw[6]; b3 += kw[7];
		b4 += kw[8]; b5 += kw[9]; b6 += kw[10]; b7 += kw[11];
		b8 += kw[12]; b9 += kw[13]; b10 += kw[14]; b11 += kw[15];
		b12 += kw[16];
		b13 += kw[17] + ts[1];
		b14 += kw[18] + ts[2];
		b15 += kw[19] + (ulong)4;

		// ===== Iteration d=4 =====
		b0 += b1; b1 = RotL(b1, 41) ^ b0; b2 += b3; b3 = RotL(b3, 9) ^ b2; b4 += b5; b5 = RotL(b5, 37) ^ b4; b6 += b7; b7 = RotL(b7, 31) ^ b6; b8 += b9; b9 = RotL(b9, 12) ^ b8; b10 += b11; b11 = RotL(b11, 47) ^ b10; b12 += b13; b13 = RotL(b13, 44) ^ b12; b14 += b15; b15 = RotL(b15, 30) ^ b14;
		b0 += b9; b9 = RotL(b9, 16) ^ b0; b2 += b13; b13 = RotL(b13, 34) ^ b2; b6 += b11; b11 = RotL(b11, 56) ^ b6; b4 += b15; b15 = RotL(b15, 51) ^ b4; b10 += b7; b7 = RotL(b7, 4) ^ b10; b12 += b3; b3 = RotL(b3, 53) ^ b12; b14 += b5; b5 = RotL(b5, 42) ^ b14; b8 += b1; b1 = RotL(b1, 41) ^ b8;
		b0 += b7; b7 = RotL(b7, 31) ^ b0; b2 += b5; b5 = RotL(b5, 44) ^ b2; b4 += b3; b3 = RotL(b3, 47) ^ b4; b6 += b1; b1 = RotL(b1, 46) ^ b6; b12 += b15; b15 = RotL(b15, 19) ^ b12; b14 += b13; b13 = RotL(b13, 42) ^ b14; b8 += b11; b11 = RotL(b11, 44) ^ b8; b10 += b9; b9 = RotL(b9, 25) ^ b10;
		b0 += b15; b15 = RotL(b15, 9) ^ b0; b2 += b11; b11 = RotL(b11, 48) ^ b2; b6 += b13; b13 = RotL(b13, 35) ^ b6; b4 += b9; b9 = RotL(b9, 52) ^ b4; b14 += b1; b1 = RotL(b1, 23) ^ b14; b8 += b5; b5 = RotL(b5, 31) ^ b8; b10 += b3; b3 = RotL(b3, 37) ^ b10; b12 += b7; b7 = RotL(b7, 20) ^ b12;
		b0 += kw[5]; b1 += kw[6]; b2 += kw[7]; b3 += kw[8];
		b4 += kw[9]; b5 += kw[10]; b6 += kw[11]; b7 += kw[12];
		b8 += kw[13]; b9 += kw[14]; b10 += kw[15]; b11 += kw[16];
		b12 += kw[17];
		b13 += kw[18] + ts[2];
		b14 += kw[19] + ts[3];
		b15 += kw[20] + (ulong)5;

		// ===== Iteration d=5 =====
		b0 += b1; b1 = RotL(b1, 16) ^ b0; b2 += b3; b3 = RotL(b3, 34) ^ b2; b4 += b5; b5 = RotL(b5, 56) ^ b4; b6 += b7; b7 = RotL(b7, 51) ^ b6; b8 += b9; b9 = RotL(b9, 4) ^ b8; b10 += b11; b11 = RotL(b11, 53) ^ b10; b12 += b13; b13 = RotL(b13, 42) ^ b12; b14 += b15; b15 = RotL(b15, 41) ^ b14;
		b0 += b9; b9 = RotL(b9, 31) ^ b0; b2 += b13; b13 = RotL(b13, 44) ^ b2; b6 += b11; b11 = RotL(b11, 47) ^ b6; b4 += b15; b15 = RotL(b15, 46) ^ b4; b10 += b7; b7 = RotL(b7, 19) ^ b10; b12 += b3; b3 = RotL(b3, 42) ^ b12; b14 += b5; b5 = RotL(b5, 44) ^ b14; b8 += b1; b1 = RotL(b1, 25) ^ b8;
		b0 += b7; b7 = RotL(b7, 9) ^ b0; b2 += b5; b5 = RotL(b5, 48) ^ b2; b4 += b3; b3 = RotL(b3, 35) ^ b4; b6 += b1; b1 = RotL(b1, 52) ^ b6; b12 += b15; b15 = RotL(b15, 23) ^ b12; b14 += b13; b13 = RotL(b13, 31) ^ b14; b8 += b11; b11 = RotL(b11, 37) ^ b8; b10 += b9; b9 = RotL(b9, 20) ^ b10;
		b0 += b15; b15 = RotL(b15, 24) ^ b0; b2 += b11; b11 = RotL(b11, 13) ^ b2; b6 += b13; b13 = RotL(b13, 8) ^ b6; b4 += b9; b9 = RotL(b9, 47) ^ b4; b14 += b1; b1 = RotL(b1, 8) ^ b14; b8 += b5; b5 = RotL(b5, 17) ^ b8; b10 += b3; b3 = RotL(b3, 22) ^ b10; b12 += b7; b7 = RotL(b7, 37) ^ b12;
		b0 += kw[6]; b1 += kw[7]; b2 += kw[8]; b3 += kw[9];
		b4 += kw[10]; b5 += kw[11]; b6 += kw[12]; b7 += kw[13];
		b8 += kw[14]; b9 += kw[15]; b10 += kw[16]; b11 += kw[17];
		b12 += kw[18];
		b13 += kw[19] + ts[0];
		b14 += kw[20] + ts[1];
		b15 += kw[21] + (ulong)6;

		// ===== Iteration d=6 =====
		b0 += b1; b1 = RotL(b1, 31) ^ b0; b2 += b3; b3 = RotL(b3, 44) ^ b2; b4 += b5; b5 = RotL(b5, 47) ^ b4; b6 += b7; b7 = RotL(b7, 46) ^ b6; b8 += b9; b9 = RotL(b9, 19) ^ b8; b10 += b11; b11 = RotL(b11, 42) ^ b10; b12 += b13; b13 = RotL(b13, 44) ^ b12; b14 += b15; b15 = RotL(b15, 25) ^ b14;
		b0 += b9; b9 = RotL(b9, 9) ^ b0; b2 += b13; b13 = RotL(b13, 48) ^ b2; b6 += b11; b11 = RotL(b11, 35) ^ b6; b4 += b15; b15 = RotL(b15, 52) ^ b4; b10 += b7; b7 = RotL(b7, 23) ^ b10; b12 += b3; b3 = RotL(b3, 31) ^ b12; b14 += b5; b5 = RotL(b5, 37) ^ b14; b8 += b1; b1 = RotL(b1, 20) ^ b8;
		b0 += b7; b7 = RotL(b7, 24) ^ b0; b2 += b5; b5 = RotL(b5, 13) ^ b2; b4 += b3; b3 = RotL(b3, 8) ^ b4; b6 += b1; b1 = RotL(b1, 47) ^ b6; b12 += b15; b15 = RotL(b15, 8) ^ b12; b14 += b13; b13 = RotL(b13, 17) ^ b14; b8 += b11; b11 = RotL(b11, 22) ^ b8; b10 += b9; b9 = RotL(b9, 37) ^ b10;
		b0 += b15; b15 = RotL(b15, 38) ^ b0; b2 += b11; b11 = RotL(b11, 19) ^ b2; b6 += b13; b13 = RotL(b13, 10) ^ b6; b4 += b9; b9 = RotL(b9, 55) ^ b4; b14 += b1; b1 = RotL(b1, 49) ^ b14; b8 += b5; b5 = RotL(b5, 18) ^ b8; b10 += b3; b3 = RotL(b3, 23) ^ b10; b12 += b7; b7 = RotL(b7, 52) ^ b12;
		b0 += kw[7]; b1 += kw[8]; b2 += kw[9]; b3 += kw[10];
		b4 += kw[11]; b5 += kw[12]; b6 += kw[13]; b7 += kw[14];
		b8 += kw[15]; b9 += kw[16]; b10 += kw[17]; b11 += kw[18];
		b12 += kw[19];
		b13 += kw[20] + ts[1];
		b14 += kw[21] + ts[2];
		b15 += kw[22] + (ulong)7;

		// ===== Iteration d=7 =====
		b0 += b1; b1 = RotL(b1, 9) ^ b0; b2 += b3; b3 = RotL(b3, 48) ^ b2; b4 += b5; b5 = RotL(b5, 35) ^ b4; b6 += b7; b7 = RotL(b7, 52) ^ b6; b8 += b9; b9 = RotL(b9, 23) ^ b8; b10 += b11; b11 = RotL(b11, 31) ^ b10; b12 += b13; b13 = RotL(b13, 37) ^ b12; b14 += b15; b15 = RotL(b15, 20) ^ b14;
		b0 += b9; b9 = RotL(b9, 24) ^ b0; b2 += b13; b13 = RotL(b13, 13) ^ b2; b6 += b11; b11 = RotL(b11, 8) ^ b6; b4 += b15; b15 = RotL(b15, 47) ^ b4; b10 += b7; b7 = RotL(b7, 8) ^ b10; b12 += b3; b3 = RotL(b3, 17) ^ b12; b14 += b5; b5 = RotL(b5, 22) ^ b14; b8 += b1; b1 = RotL(b1, 37) ^ b8;
		b0 += b7; b7 = RotL(b7, 38) ^ b0; b2 += b5; b5 = RotL(b5, 19) ^ b2; b4 += b3; b3 = RotL(b3, 10) ^ b4; b6 += b1; b1 = RotL(b1, 55) ^ b6; b12 += b15; b15 = RotL(b15, 49) ^ b12; b14 += b13; b13 = RotL(b13, 18) ^ b14; b8 += b11; b11 = RotL(b11, 23) ^ b8; b10 += b9; b9 = RotL(b9, 52) ^ b10;
		b0 += b15; b15 = RotL(b15, 33) ^ b0; b2 += b11; b11 = RotL(b11, 4) ^ b2; b6 += b13; b13 = RotL(b13, 51) ^ b6; b4 += b9; b9 = RotL(b9, 13) ^ b4; b14 += b1; b1 = RotL(b1, 34) ^ b14; b8 += b5; b5 = RotL(b5, 41) ^ b8; b10 += b3; b3 = RotL(b3, 59) ^ b10; b12 += b7; b7 = RotL(b7, 17) ^ b12;
		b0 += kw[8]; b1 += kw[9]; b2 += kw[10]; b3 += kw[11];
		b4 += kw[12]; b5 += kw[13]; b6 += kw[14]; b7 += kw[15];
		b8 += kw[16]; b9 += kw[17]; b10 += kw[18]; b11 += kw[19];
		b12 += kw[20];
		b13 += kw[21] + ts[2];
		b14 += kw[22] + ts[3];
		b15 += kw[23] + (ulong)8;

		// ===== Iteration d=8 =====
		b0 += b1; b1 = RotL(b1, 24) ^ b0; b2 += b3; b3 = RotL(b3, 13) ^ b2; b4 += b5; b5 = RotL(b5, 8) ^ b4; b6 += b7; b7 = RotL(b7, 47) ^ b6; b8 += b9; b9 = RotL(b9, 8) ^ b8; b10 += b11; b11 = RotL(b11, 17) ^ b10; b12 += b13; b13 = RotL(b13, 22) ^ b12; b14 += b15; b15 = RotL(b15, 37) ^ b14;
		b0 += b9; b9 = RotL(b9, 38) ^ b0; b2 += b13; b13 = RotL(b13, 19) ^ b2; b6 += b11; b11 = RotL(b11, 10) ^ b6; b4 += b15; b15 = RotL(b15, 55) ^ b4; b10 += b7; b7 = RotL(b7, 49) ^ b10; b12 += b3; b3 = RotL(b3, 18) ^ b12; b14 += b5; b5 = RotL(b5, 23) ^ b14; b8 += b1; b1 = RotL(b1, 52) ^ b8;
		b0 += b7; b7 = RotL(b7, 33) ^ b0; b2 += b5; b5 = RotL(b5, 4) ^ b2; b4 += b3; b3 = RotL(b3, 51) ^ b4; b6 += b1; b1 = RotL(b1, 13) ^ b6; b12 += b15; b15 = RotL(b15, 34) ^ b12; b14 += b13; b13 = RotL(b13, 41) ^ b14; b8 += b11; b11 = RotL(b11, 59) ^ b8; b10 += b9; b9 = RotL(b9, 17) ^ b10;
		b0 += b15; b15 = RotL(b15, 5) ^ b0; b2 += b11; b11 = RotL(b11, 20) ^ b2; b6 += b13; b13 = RotL(b13, 48) ^ b6; b4 += b9; b9 = RotL(b9, 41) ^ b4; b14 += b1; b1 = RotL(b1, 47) ^ b14; b8 += b5; b5 = RotL(b5, 28) ^ b8; b10 += b3; b3 = RotL(b3, 16) ^ b10; b12 += b7; b7 = RotL(b7, 25) ^ b12;
		b0 += kw[9]; b1 += kw[10]; b2 += kw[11]; b3 += kw[12];
		b4 += kw[13]; b5 += kw[14]; b6 += kw[15]; b7 += kw[16];
		b8 += kw[17]; b9 += kw[18]; b10 += kw[19]; b11 += kw[20];
		b12 += kw[21];
		b13 += kw[22] + ts[0];
		b14 += kw[23] + ts[1];
		b15 += kw[24] + (ulong)9;

		// ===== Iteration d=9 =====
		b0 += b1; b1 = RotL(b1, 38) ^ b0; b2 += b3; b3 = RotL(b3, 19) ^ b2; b4 += b5; b5 = RotL(b5, 10) ^ b4; b6 += b7; b7 = RotL(b7, 55) ^ b6; b8 += b9; b9 = RotL(b9, 49) ^ b8; b10 += b11; b11 = RotL(b11, 18) ^ b10; b12 += b13; b13 = RotL(b13, 23) ^ b12; b14 += b15; b15 = RotL(b15, 52) ^ b14;
		b0 += b9; b9 = RotL(b9, 33) ^ b0; b2 += b13; b13 = RotL(b13, 4) ^ b2; b6 += b11; b11 = RotL(b11, 51) ^ b6; b4 += b15; b15 = RotL(b15, 13) ^ b4; b10 += b7; b7 = RotL(b7, 34) ^ b10; b12 += b3; b3 = RotL(b3, 41) ^ b12; b14 += b5; b5 = RotL(b5, 59) ^ b14; b8 += b1; b1 = RotL(b1, 17) ^ b8;
		b0 += b7; b7 = RotL(b7, 5) ^ b0; b2 += b5; b5 = RotL(b5, 20) ^ b2; b4 += b3; b3 = RotL(b3, 48) ^ b4; b6 += b1; b1 = RotL(b1, 41) ^ b6; b12 += b15; b15 = RotL(b15, 47) ^ b12; b14 += b13; b13 = RotL(b13, 28) ^ b14; b8 += b11; b11 = RotL(b11, 16) ^ b8; b10 += b9; b9 = RotL(b9, 25) ^ b10;
		b0 += b15; b15 = RotL(b15, 41) ^ b0; b2 += b11; b11 = RotL(b11, 9) ^ b2; b6 += b13; b13 = RotL(b13, 37) ^ b6; b4 += b9; b9 = RotL(b9, 31) ^ b4; b14 += b1; b1 = RotL(b1, 12) ^ b14; b8 += b5; b5 = RotL(b5, 47) ^ b8; b10 += b3; b3 = RotL(b3, 44) ^ b10; b12 += b7; b7 = RotL(b7, 30) ^ b12;
		b0 += kw[10]; b1 += kw[11]; b2 += kw[12]; b3 += kw[13];
		b4 += kw[14]; b5 += kw[15]; b6 += kw[16]; b7 += kw[17];
		b8 += kw[18]; b9 += kw[19]; b10 += kw[20]; b11 += kw[21];
		b12 += kw[22];
		b13 += kw[23] + ts[1];
		b14 += kw[24] + ts[2];
		b15 += kw[25] + (ulong)10;

		// ===== Iteration d=10 =====
		b0 += b1; b1 = RotL(b1, 33) ^ b0; b2 += b3; b3 = RotL(b3, 4) ^ b2; b4 += b5; b5 = RotL(b5, 51) ^ b4; b6 += b7; b7 = RotL(b7, 13) ^ b6; b8 += b9; b9 = RotL(b9, 34) ^ b8; b10 += b11; b11 = RotL(b11, 41) ^ b10; b12 += b13; b13 = RotL(b13, 59) ^ b12; b14 += b15; b15 = RotL(b15, 17) ^ b14;
		b0 += b9; b9 = RotL(b9, 5) ^ b0; b2 += b13; b13 = RotL(b13, 20) ^ b2; b6 += b11; b11 = RotL(b11, 48) ^ b6; b4 += b15; b15 = RotL(b15, 41) ^ b4; b10 += b7; b7 = RotL(b7, 47) ^ b10; b12 += b3; b3 = RotL(b3, 28) ^ b12; b14 += b5; b5 = RotL(b5, 16) ^ b14; b8 += b1; b1 = RotL(b1, 25) ^ b8;
		b0 += b7; b7 = RotL(b7, 41) ^ b0; b2 += b5; b5 = RotL(b5, 9) ^ b2; b4 += b3; b3 = RotL(b3, 37) ^ b4; b6 += b1; b1 = RotL(b1, 31) ^ b6; b12 += b15; b15 = RotL(b15, 12) ^ b12; b14 += b13; b13 = RotL(b13, 47) ^ b14; b8 += b11; b11 = RotL(b11, 44) ^ b8; b10 += b9; b9 = RotL(b9, 30) ^ b10;
		b0 += b15; b15 = RotL(b15, 16) ^ b0; b2 += b11; b11 = RotL(b11, 34) ^ b2; b6 += b13; b13 = RotL(b13, 56) ^ b6; b4 += b9; b9 = RotL(b9, 51) ^ b4; b14 += b1; b1 = RotL(b1, 4) ^ b14; b8 += b5; b5 = RotL(b5, 53) ^ b8; b10 += b3; b3 = RotL(b3, 42) ^ b10; b12 += b7; b7 = RotL(b7, 41) ^ b12;
		b0 += kw[11]; b1 += kw[12]; b2 += kw[13]; b3 += kw[14];
		b4 += kw[15]; b5 += kw[16]; b6 += kw[17]; b7 += kw[18];
		b8 += kw[19]; b9 += kw[20]; b10 += kw[21]; b11 += kw[22];
		b12 += kw[23];
		b13 += kw[24] + ts[2];
		b14 += kw[25] + ts[3];
		b15 += kw[26] + (ulong)11;

		// ===== Iteration d=11 =====
		b0 += b1; b1 = RotL(b1, 5) ^ b0; b2 += b3; b3 = RotL(b3, 20) ^ b2; b4 += b5; b5 = RotL(b5, 48) ^ b4; b6 += b7; b7 = RotL(b7, 41) ^ b6; b8 += b9; b9 = RotL(b9, 47) ^ b8; b10 += b11; b11 = RotL(b11, 28) ^ b10; b12 += b13; b13 = RotL(b13, 16) ^ b12; b14 += b15; b15 = RotL(b15, 25) ^ b14;
		b0 += b9; b9 = RotL(b9, 41) ^ b0; b2 += b13; b13 = RotL(b13, 9) ^ b2; b6 += b11; b11 = RotL(b11, 37) ^ b6; b4 += b15; b15 = RotL(b15, 31) ^ b4; b10 += b7; b7 = RotL(b7, 12) ^ b10; b12 += b3; b3 = RotL(b3, 47) ^ b12; b14 += b5; b5 = RotL(b5, 44) ^ b14; b8 += b1; b1 = RotL(b1, 30) ^ b8;
		b0 += b7; b7 = RotL(b7, 16) ^ b0; b2 += b5; b5 = RotL(b5, 34) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4; b6 += b1; b1 = RotL(b1, 51) ^ b6; b12 += b15; b15 = RotL(b15, 4) ^ b12; b14 += b13; b13 = RotL(b13, 53) ^ b14; b8 += b11; b11 = RotL(b11, 42) ^ b8; b10 += b9; b9 = RotL(b9, 41) ^ b10;
		b0 += b15; b15 = RotL(b15, 31) ^ b0; b2 += b11; b11 = RotL(b11, 44) ^ b2; b6 += b13; b13 = RotL(b13, 47) ^ b6; b4 += b9; b9 = RotL(b9, 46) ^ b4; b14 += b1; b1 = RotL(b1, 19) ^ b14; b8 += b5; b5 = RotL(b5, 42) ^ b8; b10 += b3; b3 = RotL(b3, 44) ^ b10; b12 += b7; b7 = RotL(b7, 25) ^ b12;
		b0 += kw[12]; b1 += kw[13]; b2 += kw[14]; b3 += kw[15];
		b4 += kw[16]; b5 += kw[17]; b6 += kw[18]; b7 += kw[19];
		b8 += kw[20]; b9 += kw[21]; b10 += kw[22]; b11 += kw[23];
		b12 += kw[24];
		b13 += kw[25] + ts[0];
		b14 += kw[26] + ts[1];
		b15 += kw[27] + (ulong)12;

		// ===== Iteration d=12 =====
		b0 += b1; b1 = RotL(b1, 41) ^ b0; b2 += b3; b3 = RotL(b3, 9) ^ b2; b4 += b5; b5 = RotL(b5, 37) ^ b4; b6 += b7; b7 = RotL(b7, 31) ^ b6; b8 += b9; b9 = RotL(b9, 12) ^ b8; b10 += b11; b11 = RotL(b11, 47) ^ b10; b12 += b13; b13 = RotL(b13, 44) ^ b12; b14 += b15; b15 = RotL(b15, 30) ^ b14;
		b0 += b9; b9 = RotL(b9, 16) ^ b0; b2 += b13; b13 = RotL(b13, 34) ^ b2; b6 += b11; b11 = RotL(b11, 56) ^ b6; b4 += b15; b15 = RotL(b15, 51) ^ b4; b10 += b7; b7 = RotL(b7, 4) ^ b10; b12 += b3; b3 = RotL(b3, 53) ^ b12; b14 += b5; b5 = RotL(b5, 42) ^ b14; b8 += b1; b1 = RotL(b1, 41) ^ b8;
		b0 += b7; b7 = RotL(b7, 31) ^ b0; b2 += b5; b5 = RotL(b5, 44) ^ b2; b4 += b3; b3 = RotL(b3, 47) ^ b4; b6 += b1; b1 = RotL(b1, 46) ^ b6; b12 += b15; b15 = RotL(b15, 19) ^ b12; b14 += b13; b13 = RotL(b13, 42) ^ b14; b8 += b11; b11 = RotL(b11, 44) ^ b8; b10 += b9; b9 = RotL(b9, 25) ^ b10;
		b0 += b15; b15 = RotL(b15, 9) ^ b0; b2 += b11; b11 = RotL(b11, 48) ^ b2; b6 += b13; b13 = RotL(b13, 35) ^ b6; b4 += b9; b9 = RotL(b9, 52) ^ b4; b14 += b1; b1 = RotL(b1, 23) ^ b14; b8 += b5; b5 = RotL(b5, 31) ^ b8; b10 += b3; b3 = RotL(b3, 37) ^ b10; b12 += b7; b7 = RotL(b7, 20) ^ b12;
		b0 += kw[13]; b1 += kw[14]; b2 += kw[15]; b3 += kw[16];
		b4 += kw[17]; b5 += kw[18]; b6 += kw[19]; b7 += kw[20];
		b8 += kw[21]; b9 += kw[22]; b10 += kw[23]; b11 += kw[24];
		b12 += kw[25];
		b13 += kw[26] + ts[1];
		b14 += kw[27] + ts[2];
		b15 += kw[28] + (ulong)13;

		// ===== Iteration d=13 =====
		b0 += b1; b1 = RotL(b1, 16) ^ b0; b2 += b3; b3 = RotL(b3, 34) ^ b2; b4 += b5; b5 = RotL(b5, 56) ^ b4; b6 += b7; b7 = RotL(b7, 51) ^ b6; b8 += b9; b9 = RotL(b9, 4) ^ b8; b10 += b11; b11 = RotL(b11, 53) ^ b10; b12 += b13; b13 = RotL(b13, 42) ^ b12; b14 += b15; b15 = RotL(b15, 41) ^ b14;
		b0 += b9; b9 = RotL(b9, 31) ^ b0; b2 += b13; b13 = RotL(b13, 44) ^ b2; b6 += b11; b11 = RotL(b11, 47) ^ b6; b4 += b15; b15 = RotL(b15, 46) ^ b4; b10 += b7; b7 = RotL(b7, 19) ^ b10; b12 += b3; b3 = RotL(b3, 42) ^ b12; b14 += b5; b5 = RotL(b5, 44) ^ b14; b8 += b1; b1 = RotL(b1, 25) ^ b8;
		b0 += b7; b7 = RotL(b7, 9) ^ b0; b2 += b5; b5 = RotL(b5, 48) ^ b2; b4 += b3; b3 = RotL(b3, 35) ^ b4; b6 += b1; b1 = RotL(b1, 52) ^ b6; b12 += b15; b15 = RotL(b15, 23) ^ b12; b14 += b13; b13 = RotL(b13, 31) ^ b14; b8 += b11; b11 = RotL(b11, 37) ^ b8; b10 += b9; b9 = RotL(b9, 20) ^ b10;
		b0 += b15; b15 = RotL(b15, 24) ^ b0; b2 += b11; b11 = RotL(b11, 13) ^ b2; b6 += b13; b13 = RotL(b13, 8) ^ b6; b4 += b9; b9 = RotL(b9, 47) ^ b4; b14 += b1; b1 = RotL(b1, 8) ^ b14; b8 += b5; b5 = RotL(b5, 17) ^ b8; b10 += b3; b3 = RotL(b3, 22) ^ b10; b12 += b7; b7 = RotL(b7, 37) ^ b12;
		b0 += kw[14]; b1 += kw[15]; b2 += kw[16]; b3 += kw[17];
		b4 += kw[18]; b5 += kw[19]; b6 += kw[20]; b7 += kw[21];
		b8 += kw[22]; b9 += kw[23]; b10 += kw[24]; b11 += kw[25];
		b12 += kw[26];
		b13 += kw[27] + ts[2];
		b14 += kw[28] + ts[3];
		b15 += kw[29] + (ulong)14;

		// ===== Iteration d=14 =====
		b0 += b1; b1 = RotL(b1, 31) ^ b0; b2 += b3; b3 = RotL(b3, 44) ^ b2; b4 += b5; b5 = RotL(b5, 47) ^ b4; b6 += b7; b7 = RotL(b7, 46) ^ b6; b8 += b9; b9 = RotL(b9, 19) ^ b8; b10 += b11; b11 = RotL(b11, 42) ^ b10; b12 += b13; b13 = RotL(b13, 44) ^ b12; b14 += b15; b15 = RotL(b15, 25) ^ b14;
		b0 += b9; b9 = RotL(b9, 9) ^ b0; b2 += b13; b13 = RotL(b13, 48) ^ b2; b6 += b11; b11 = RotL(b11, 35) ^ b6; b4 += b15; b15 = RotL(b15, 52) ^ b4; b10 += b7; b7 = RotL(b7, 23) ^ b10; b12 += b3; b3 = RotL(b3, 31) ^ b12; b14 += b5; b5 = RotL(b5, 37) ^ b14; b8 += b1; b1 = RotL(b1, 20) ^ b8;
		b0 += b7; b7 = RotL(b7, 24) ^ b0; b2 += b5; b5 = RotL(b5, 13) ^ b2; b4 += b3; b3 = RotL(b3, 8) ^ b4; b6 += b1; b1 = RotL(b1, 47) ^ b6; b12 += b15; b15 = RotL(b15, 8) ^ b12; b14 += b13; b13 = RotL(b13, 17) ^ b14; b8 += b11; b11 = RotL(b11, 22) ^ b8; b10 += b9; b9 = RotL(b9, 37) ^ b10;
		b0 += b15; b15 = RotL(b15, 38) ^ b0; b2 += b11; b11 = RotL(b11, 19) ^ b2; b6 += b13; b13 = RotL(b13, 10) ^ b6; b4 += b9; b9 = RotL(b9, 55) ^ b4; b14 += b1; b1 = RotL(b1, 49) ^ b14; b8 += b5; b5 = RotL(b5, 18) ^ b8; b10 += b3; b3 = RotL(b3, 23) ^ b10; b12 += b7; b7 = RotL(b7, 52) ^ b12;
		b0 += kw[15]; b1 += kw[16]; b2 += kw[17]; b3 += kw[18];
		b4 += kw[19]; b5 += kw[20]; b6 += kw[21]; b7 += kw[22];
		b8 += kw[23]; b9 += kw[24]; b10 += kw[25]; b11 += kw[26];
		b12 += kw[27];
		b13 += kw[28] + ts[0];
		b14 += kw[29] + ts[1];
		b15 += kw[30] + (ulong)15;

		// ===== Iteration d=15 =====
		b0 += b1; b1 = RotL(b1, 9) ^ b0; b2 += b3; b3 = RotL(b3, 48) ^ b2; b4 += b5; b5 = RotL(b5, 35) ^ b4; b6 += b7; b7 = RotL(b7, 52) ^ b6; b8 += b9; b9 = RotL(b9, 23) ^ b8; b10 += b11; b11 = RotL(b11, 31) ^ b10; b12 += b13; b13 = RotL(b13, 37) ^ b12; b14 += b15; b15 = RotL(b15, 20) ^ b14;
		b0 += b9; b9 = RotL(b9, 24) ^ b0; b2 += b13; b13 = RotL(b13, 13) ^ b2; b6 += b11; b11 = RotL(b11, 8) ^ b6; b4 += b15; b15 = RotL(b15, 47) ^ b4; b10 += b7; b7 = RotL(b7, 8) ^ b10; b12 += b3; b3 = RotL(b3, 17) ^ b12; b14 += b5; b5 = RotL(b5, 22) ^ b14; b8 += b1; b1 = RotL(b1, 37) ^ b8;
		b0 += b7; b7 = RotL(b7, 38) ^ b0; b2 += b5; b5 = RotL(b5, 19) ^ b2; b4 += b3; b3 = RotL(b3, 10) ^ b4; b6 += b1; b1 = RotL(b1, 55) ^ b6; b12 += b15; b15 = RotL(b15, 49) ^ b12; b14 += b13; b13 = RotL(b13, 18) ^ b14; b8 += b11; b11 = RotL(b11, 23) ^ b8; b10 += b9; b9 = RotL(b9, 52) ^ b10;
		b0 += b15; b15 = RotL(b15, 33) ^ b0; b2 += b11; b11 = RotL(b11, 4) ^ b2; b6 += b13; b13 = RotL(b13, 51) ^ b6; b4 += b9; b9 = RotL(b9, 13) ^ b4; b14 += b1; b1 = RotL(b1, 34) ^ b14; b8 += b5; b5 = RotL(b5, 41) ^ b8; b10 += b3; b3 = RotL(b3, 59) ^ b10; b12 += b7; b7 = RotL(b7, 17) ^ b12;
		b0 += kw[16]; b1 += kw[17]; b2 += kw[18]; b3 += kw[19];
		b4 += kw[20]; b5 += kw[21]; b6 += kw[22]; b7 += kw[23];
		b8 += kw[24]; b9 += kw[25]; b10 += kw[26]; b11 += kw[27];
		b12 += kw[28];
		b13 += kw[29] + ts[1];
		b14 += kw[30] + ts[2];
		b15 += kw[31] + (ulong)16;

		// ===== Iteration d=16 =====
		b0 += b1; b1 = RotL(b1, 24) ^ b0; b2 += b3; b3 = RotL(b3, 13) ^ b2; b4 += b5; b5 = RotL(b5, 8) ^ b4; b6 += b7; b7 = RotL(b7, 47) ^ b6; b8 += b9; b9 = RotL(b9, 8) ^ b8; b10 += b11; b11 = RotL(b11, 17) ^ b10; b12 += b13; b13 = RotL(b13, 22) ^ b12; b14 += b15; b15 = RotL(b15, 37) ^ b14;
		b0 += b9; b9 = RotL(b9, 38) ^ b0; b2 += b13; b13 = RotL(b13, 19) ^ b2; b6 += b11; b11 = RotL(b11, 10) ^ b6; b4 += b15; b15 = RotL(b15, 55) ^ b4; b10 += b7; b7 = RotL(b7, 49) ^ b10; b12 += b3; b3 = RotL(b3, 18) ^ b12; b14 += b5; b5 = RotL(b5, 23) ^ b14; b8 += b1; b1 = RotL(b1, 52) ^ b8;
		b0 += b7; b7 = RotL(b7, 33) ^ b0; b2 += b5; b5 = RotL(b5, 4) ^ b2; b4 += b3; b3 = RotL(b3, 51) ^ b4; b6 += b1; b1 = RotL(b1, 13) ^ b6; b12 += b15; b15 = RotL(b15, 34) ^ b12; b14 += b13; b13 = RotL(b13, 41) ^ b14; b8 += b11; b11 = RotL(b11, 59) ^ b8; b10 += b9; b9 = RotL(b9, 17) ^ b10;
		b0 += b15; b15 = RotL(b15, 5) ^ b0; b2 += b11; b11 = RotL(b11, 20) ^ b2; b6 += b13; b13 = RotL(b13, 48) ^ b6; b4 += b9; b9 = RotL(b9, 41) ^ b4; b14 += b1; b1 = RotL(b1, 47) ^ b14; b8 += b5; b5 = RotL(b5, 28) ^ b8; b10 += b3; b3 = RotL(b3, 16) ^ b10; b12 += b7; b7 = RotL(b7, 25) ^ b12;
		b0 += kw[0]; b1 += kw[1]; b2 += kw[2]; b3 += kw[3];
		b4 += kw[4]; b5 += kw[5]; b6 += kw[6]; b7 += kw[7];
		b8 += kw[8]; b9 += kw[9]; b10 += kw[10]; b11 += kw[11];
		b12 += kw[12];
		b13 += kw[13] + ts[2];
		b14 += kw[14] + ts[3];
		b15 += kw[15] + (ulong)17;

		// ===== Iteration d=17 =====
		b0 += b1; b1 = RotL(b1, 38) ^ b0; b2 += b3; b3 = RotL(b3, 19) ^ b2; b4 += b5; b5 = RotL(b5, 10) ^ b4; b6 += b7; b7 = RotL(b7, 55) ^ b6; b8 += b9; b9 = RotL(b9, 49) ^ b8; b10 += b11; b11 = RotL(b11, 18) ^ b10; b12 += b13; b13 = RotL(b13, 23) ^ b12; b14 += b15; b15 = RotL(b15, 52) ^ b14;
		b0 += b9; b9 = RotL(b9, 33) ^ b0; b2 += b13; b13 = RotL(b13, 4) ^ b2; b6 += b11; b11 = RotL(b11, 51) ^ b6; b4 += b15; b15 = RotL(b15, 13) ^ b4; b10 += b7; b7 = RotL(b7, 34) ^ b10; b12 += b3; b3 = RotL(b3, 41) ^ b12; b14 += b5; b5 = RotL(b5, 59) ^ b14; b8 += b1; b1 = RotL(b1, 17) ^ b8;
		b0 += b7; b7 = RotL(b7, 5) ^ b0; b2 += b5; b5 = RotL(b5, 20) ^ b2; b4 += b3; b3 = RotL(b3, 48) ^ b4; b6 += b1; b1 = RotL(b1, 41) ^ b6; b12 += b15; b15 = RotL(b15, 47) ^ b12; b14 += b13; b13 = RotL(b13, 28) ^ b14; b8 += b11; b11 = RotL(b11, 16) ^ b8; b10 += b9; b9 = RotL(b9, 25) ^ b10;
		b0 += b15; b15 = RotL(b15, 41) ^ b0; b2 += b11; b11 = RotL(b11, 9) ^ b2; b6 += b13; b13 = RotL(b13, 37) ^ b6; b4 += b9; b9 = RotL(b9, 31) ^ b4; b14 += b1; b1 = RotL(b1, 12) ^ b14; b8 += b5; b5 = RotL(b5, 47) ^ b8; b10 += b3; b3 = RotL(b3, 44) ^ b10; b12 += b7; b7 = RotL(b7, 30) ^ b12;
		b0 += kw[1]; b1 += kw[2]; b2 += kw[3]; b3 += kw[4];
		b4 += kw[5]; b5 += kw[6]; b6 += kw[7]; b7 += kw[8];
		b8 += kw[9]; b9 += kw[10]; b10 += kw[11]; b11 += kw[12];
		b12 += kw[13];
		b13 += kw[14] + ts[0];
		b14 += kw[15] + ts[1];
		b15 += kw[16] + (ulong)18;

		// ===== Iteration d=18 =====
		b0 += b1; b1 = RotL(b1, 33) ^ b0; b2 += b3; b3 = RotL(b3, 4) ^ b2; b4 += b5; b5 = RotL(b5, 51) ^ b4; b6 += b7; b7 = RotL(b7, 13) ^ b6; b8 += b9; b9 = RotL(b9, 34) ^ b8; b10 += b11; b11 = RotL(b11, 41) ^ b10; b12 += b13; b13 = RotL(b13, 59) ^ b12; b14 += b15; b15 = RotL(b15, 17) ^ b14;
		b0 += b9; b9 = RotL(b9, 5) ^ b0; b2 += b13; b13 = RotL(b13, 20) ^ b2; b6 += b11; b11 = RotL(b11, 48) ^ b6; b4 += b15; b15 = RotL(b15, 41) ^ b4; b10 += b7; b7 = RotL(b7, 47) ^ b10; b12 += b3; b3 = RotL(b3, 28) ^ b12; b14 += b5; b5 = RotL(b5, 16) ^ b14; b8 += b1; b1 = RotL(b1, 25) ^ b8;
		b0 += b7; b7 = RotL(b7, 41) ^ b0; b2 += b5; b5 = RotL(b5, 9) ^ b2; b4 += b3; b3 = RotL(b3, 37) ^ b4; b6 += b1; b1 = RotL(b1, 31) ^ b6; b12 += b15; b15 = RotL(b15, 12) ^ b12; b14 += b13; b13 = RotL(b13, 47) ^ b14; b8 += b11; b11 = RotL(b11, 44) ^ b8; b10 += b9; b9 = RotL(b9, 30) ^ b10;
		b0 += b15; b15 = RotL(b15, 16) ^ b0; b2 += b11; b11 = RotL(b11, 34) ^ b2; b6 += b13; b13 = RotL(b13, 56) ^ b6; b4 += b9; b9 = RotL(b9, 51) ^ b4; b14 += b1; b1 = RotL(b1, 4) ^ b14; b8 += b5; b5 = RotL(b5, 53) ^ b8; b10 += b3; b3 = RotL(b3, 42) ^ b10; b12 += b7; b7 = RotL(b7, 41) ^ b12;
		b0 += kw[2]; b1 += kw[3]; b2 += kw[4]; b3 += kw[5];
		b4 += kw[6]; b5 += kw[7]; b6 += kw[8]; b7 += kw[9];
		b8 += kw[10]; b9 += kw[11]; b10 += kw[12]; b11 += kw[13];
		b12 += kw[14];
		b13 += kw[15] + ts[1];
		b14 += kw[16] + ts[2];
		b15 += kw[17] + (ulong)19;

		// ===== Iteration d=19 =====
		b0 += b1; b1 = RotL(b1, 5) ^ b0; b2 += b3; b3 = RotL(b3, 20) ^ b2; b4 += b5; b5 = RotL(b5, 48) ^ b4; b6 += b7; b7 = RotL(b7, 41) ^ b6; b8 += b9; b9 = RotL(b9, 47) ^ b8; b10 += b11; b11 = RotL(b11, 28) ^ b10; b12 += b13; b13 = RotL(b13, 16) ^ b12; b14 += b15; b15 = RotL(b15, 25) ^ b14;
		b0 += b9; b9 = RotL(b9, 41) ^ b0; b2 += b13; b13 = RotL(b13, 9) ^ b2; b6 += b11; b11 = RotL(b11, 37) ^ b6; b4 += b15; b15 = RotL(b15, 31) ^ b4; b10 += b7; b7 = RotL(b7, 12) ^ b10; b12 += b3; b3 = RotL(b3, 47) ^ b12; b14 += b5; b5 = RotL(b5, 44) ^ b14; b8 += b1; b1 = RotL(b1, 30) ^ b8;
		b0 += b7; b7 = RotL(b7, 16) ^ b0; b2 += b5; b5 = RotL(b5, 34) ^ b2; b4 += b3; b3 = RotL(b3, 56) ^ b4; b6 += b1; b1 = RotL(b1, 51) ^ b6; b12 += b15; b15 = RotL(b15, 4) ^ b12; b14 += b13; b13 = RotL(b13, 53) ^ b14; b8 += b11; b11 = RotL(b11, 42) ^ b8; b10 += b9; b9 = RotL(b9, 41) ^ b10;
		b0 += b15; b15 = RotL(b15, 31) ^ b0; b2 += b11; b11 = RotL(b11, 44) ^ b2; b6 += b13; b13 = RotL(b13, 47) ^ b6; b4 += b9; b9 = RotL(b9, 46) ^ b4; b14 += b1; b1 = RotL(b1, 19) ^ b14; b8 += b5; b5 = RotL(b5, 42) ^ b8; b10 += b3; b3 = RotL(b3, 44) ^ b10; b12 += b7; b7 = RotL(b7, 25) ^ b12;
		b0 += kw[3]; b1 += kw[4]; b2 += kw[5]; b3 += kw[6];
		b4 += kw[7]; b5 += kw[8]; b6 += kw[9]; b7 += kw[10];
		b8 += kw[11]; b9 += kw[12]; b10 += kw[13]; b11 += kw[14];
		b12 += kw[15];
		b13 += kw[16] + ts[2];
		b14 += kw[17] + ts[3];
		b15 += kw[18] + (ulong)20;

		// Store results back
		_work[0] = b0; _work[1] = b1; _work[2] = b2; _work[3] = b3;
		_work[4] = b4; _work[5] = b5; _work[6] = b6; _work[7] = b7;
		_work[8] = b8; _work[9] = b9; _work[10] = b10; _work[11] = b11;
		_work[12] = b12; _work[13] = b13; _work[14] = b14; _work[15] = b15;
	}
}

/// <summary>
/// Factory for creating optimized Skein hash instances.
/// </summary>
public static class SkeinOptimizedFactory {
	/// <summary>
	/// Computes Skein-256 hash of the given data.
	/// </summary>
	public static byte[] ComputeSkein256(ReadOnlySpan<byte> data) {
		using var hasher = new Skein256Optimized(256);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes Skein-512 hash of the given data.
	/// </summary>
	public static byte[] ComputeSkein512(ReadOnlySpan<byte> data) {
		using var hasher = new Skein512Optimized(512);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes Skein-1024 hash of the given data.
	/// </summary>
	public static byte[] ComputeSkein1024(ReadOnlySpan<byte> data) {
		using var hasher = new Skein1024Optimized(1024);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Creates a streaming Skein-256 instance.
	/// </summary>
	public static IStreamingHashBytes CreateSkein256() => new Skein256Optimized(256);

	/// <summary>
	/// Creates a streaming Skein-512 instance.
	/// </summary>
	public static IStreamingHashBytes CreateSkein512() => new Skein512Optimized(512);

	/// <summary>
	/// Creates a streaming Skein-1024 instance.
	/// </summary>
	public static IStreamingHashBytes CreateSkein1024() => new Skein1024Optimized(1024);
}

