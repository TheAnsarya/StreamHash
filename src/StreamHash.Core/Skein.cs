using System.Buffers;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// Native implementation of Skein hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// Skein is a cryptographic hash function designed by Bruce Schneier, Niels Ferguson,
/// Stefan Lucks, Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas, and Jesse Walker.
/// It was a finalist in the NIST SHA-3 competition.
/// </para>
/// <para>
/// Skein is built on the Threefish tweakable block cipher and supports multiple
/// state sizes (256, 512, 1024 bits) with configurable output sizes.
/// </para>
/// <para>
/// Reference: "The Skein Hash Function Family" - https://www.skein-hash.info/
/// </para>
/// </remarks>
internal abstract class Skein : IStreamingHashBytes {
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

	/// <summary>Working arrays for Threefish.</summary>
	protected readonly ulong[] _key;
	protected readonly ulong[] _tweak;
	protected readonly ulong[] _work;

	/// <summary>
	/// Creates a new Skein instance.
	/// </summary>
	/// <param name="stateBits">State size in bits (256, 512, or 1024).</param>
	/// <param name="outputBits">Output size in bits.</param>
	protected Skein(int stateBits, int outputBits) {
		_stateBits = stateBits;
		_outputBits = outputBits;
		_blockBytes = stateBits / 8;
		_numWords = stateBits / 64;

		_state = new ulong[_numWords];
		_buffer = new byte[_blockBytes];
		_key = new ulong[_numWords + 1];
		_tweak = new ulong[3];
		_work = new ulong[_numWords];

		Reset();
	}

	/// <inheritdoc/>
	public int BlockSize => _blockBytes;

	/// <inheritdoc/>
	public int DigestSize => _outputBits / 8;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
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

		// Output transformation (if needed)
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
		Array.Clear(_key);
		Array.Clear(_tweak);
		Array.Clear(_work);
	}

	/// <summary>
	/// Processes a single block with Threefish encryption.
	/// </summary>
	protected void ProcessBlock(byte[] block, bool isFinal) {
		// Convert block to words
		for (int i = 0; i < _numWords; i++) {
			_work[i] = BitConverter.ToUInt64(block, i * 8);
		}

		// Encrypt with Threefish
		ThreefishEncrypt(_state, _work, _key, _t0, _t1);

		// XOR plaintext into ciphertext
		for (int i = 0; i < _numWords; i++) {
			_state[i] = _work[i] ^ BitConverter.ToUInt64(block, i * 8);
		}

		// Clear first bit if not final
		if (!isFinal) {
			_t1 &= ~TweakFirst;
		}
	}

	/// <summary>
	/// Processes a block directly from a span.
	/// </summary>
	protected void ProcessBlockSpan(ReadOnlySpan<byte> block, bool isFinal) {
		// Convert block to words
		for (int i = 0; i < _numWords; i++) {
			_work[i] = BitConverter.ToUInt64(block.Slice(i * 8, 8));
		}

		// Encrypt with Threefish
		ThreefishEncrypt(_state, _work, _key, _t0, _t1);

		// XOR plaintext into ciphertext
		for (int i = 0; i < _numWords; i++) {
			_state[i] = _work[i] ^ BitConverter.ToUInt64(block.Slice(i * 8, 8));
		}

		// Clear first bit if not final
		if (!isFinal) {
			_t1 &= ~TweakFirst;
		}
	}

	/// <summary>
	/// Performs the output transformation to produce the hash.
	/// For each output block needed, we run UBI on an 8-byte counter value.
	/// The tweak position is always 8 (bytes in counter block), with type=OUTPUT.
	/// </summary>
	protected void OutputTransform(byte[] output) {
		int bytesOutput = 0;
		int blockCounter = 0;

		// Save the current state (chain value after message processing)
		ulong[] savedState = new ulong[_numWords];
		Array.Copy(_state, savedState, _numWords);

		while (bytesOutput < DigestSize) {
			// Restore state for each output block (UBI preserves pre-output state)
			Array.Copy(savedState, _state, _numWords);

			// Set up output tweak: position=8 (counter is 8 bytes), type=OUTPUT, First+Final
			_t0 = 8;  // Always 8 bytes of input (the counter)
			_t1 = TweakFirst | TweakFinal | TweakTypeOut;

			// Create counter block: 8-byte counter followed by zeros
			byte[] counterBlock = new byte[_blockBytes];
			BitConverter.TryWriteBytes(counterBlock.AsSpan(0, 8), (ulong)blockCounter);

			// Parse counter block as words
			for (int i = 0; i < _numWords; i++) {
				_work[i] = BitConverter.ToUInt64(counterBlock, i * 8);
			}

			// Run Threefish with state as key, counter block as input
			ThreefishEncrypt(_state, _work, _key, _t0, _t1);

			// XOR Threefish output with counter block (UBI feedforward)
			for (int i = 0; i < _numWords; i++) {
				_work[i] ^= BitConverter.ToUInt64(counterBlock, i * 8);
			}

			// Copy output words
			int bytesToCopy = Math.Min(_blockBytes, DigestSize - bytesOutput);
			for (int i = 0; i < bytesToCopy / 8; i++) {
				if (bytesOutput + i * 8 + 8 <= DigestSize) {
					BitConverter.TryWriteBytes(output.AsSpan(bytesOutput + i * 8, 8), _work[i]);
				}
			}

			// Handle partial last word
			int remaining = bytesToCopy % 8;
			if (remaining > 0) {
				int wordIdx = bytesToCopy / 8;
				if (wordIdx < _numWords) {
					for (int j = 0; j < remaining; j++) {
						output[bytesOutput + wordIdx * 8 + j] = (byte)(_work[wordIdx] >> (j * 8));
					}
				}
			}

			bytesOutput += bytesToCopy;
			blockCounter++;
		}
	}

	/// <summary>
	/// Threefish block cipher encryption (key schedule and rounds).
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected abstract void ThreefishEncrypt(ulong[] key, ulong[] input, ulong[] keySchedule, ulong t0, ulong t1);

	// Tweak flags
	protected const ulong TweakFirst = 1UL << 62;
	protected const ulong TweakFinal = 1UL << 63;
	protected const ulong TweakTypeMsg = 48UL << 56;  // Message type
	protected const ulong TweakTypeOut = 63UL << 56;  // Output type
	protected const ulong TweakTypeCfg = 4UL << 56;   // Configuration type

	// Threefish constant
	protected const ulong C240 = 0x1bd11bdaa9fc1a22UL;
}

/// <summary>
/// Skein-256 (256-bit state size, configurable output).
/// </summary>
internal sealed class Skein256Hash : Skein {
	// Threefish-256 rotation constants (8 rounds × 2 values)
	// Reference: Skein specification v1.3, Section 8.3
	private static readonly int[,] RotationConstants256 = {
		{ 14, 16 }, // Round 0
		{ 52, 57 }, // Round 1
		{ 23, 40 }, // Round 2
		{  5, 37 }, // Round 3
		{ 25, 33 }, // Round 4
		{ 46, 12 }, // Round 5
		{ 58, 22 }, // Round 6
		{ 32, 32 }  // Round 7
	};

	public Skein256Hash(int outputBits = 256) : base(256, outputBits) { }

	public override void Reset() {
		Array.Clear(_state);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;

		// Initialize state with configuration block
		InitializeConfiguration();
	}

	private void InitializeConfiguration() {
		// Configuration block (simplified - uses standard parameters)
		byte[] config = new byte[_blockBytes];
		// Schema identifier "SHA3"
		config[0] = (byte)'S';
		config[1] = (byte)'H';
		config[2] = (byte)'A';
		config[3] = (byte)'3';
		// Version = 1
		config[4] = 1;
		config[5] = 0;
		// Reserved
		config[6] = 0;
		config[7] = 0;
		// Output length in bits (little-endian)
		BitConverter.TryWriteBytes(config.AsSpan(8, 8), (ulong)_outputBits);

		// Process config with type = Cfg
		_t0 = 32; // Config block is 32 bytes
		_t1 = TweakFirst | TweakFinal | TweakTypeCfg;
		ProcessBlock(config, true);

		// Reset tweak for message
		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected override void ThreefishEncrypt(ulong[] key, ulong[] input, ulong[] keySchedule, ulong t0, ulong t1) {
		// Threefish-256: 72 rounds, 4 words
		// Reference: Skein specification v1.3
		ulong k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
		ulong k4 = k0 ^ k1 ^ k2 ^ k3 ^ C240;
		ulong t2 = t0 ^ t1;

		ulong v0 = input[0] + k0;
		ulong v1 = input[1] + k1 + t0;
		ulong v2 = input[2] + k2 + t1;
		ulong v3 = input[3] + k3;

		ulong[] ks = [k0, k1, k2, k3, k4];
		ulong[] ts = [t0, t1, t2];

		// 72 rounds = 18 iterations of 4 rounds each
		for (int d = 0; d < 18; d++) {
			int r0 = (4 * d + 0) % 8;
			int r1 = (4 * d + 1) % 8;
			int r2 = (4 * d + 2) % 8;
			int r3 = (4 * d + 3) % 8;

			// Round 4*d+0: Mix(0,1), Mix(2,3)
			v0 += v1; v1 = RotateLeft(v1, RotationConstants256[r0, 0]) ^ v0;
			v2 += v3; v3 = RotateLeft(v3, RotationConstants256[r0, 1]) ^ v2;

			// Round 4*d+1: Mix(0,3), Mix(2,1) - after permutation
			v0 += v3; v3 = RotateLeft(v3, RotationConstants256[r1, 0]) ^ v0;
			v2 += v1; v1 = RotateLeft(v1, RotationConstants256[r1, 1]) ^ v2;

			// Round 4*d+2: Mix(0,1), Mix(2,3) - after permutation back
			v0 += v1; v1 = RotateLeft(v1, RotationConstants256[r2, 0]) ^ v0;
			v2 += v3; v3 = RotateLeft(v3, RotationConstants256[r2, 1]) ^ v2;

			// Round 4*d+3: Mix(0,3), Mix(2,1) - after permutation
			v0 += v3; v3 = RotateLeft(v3, RotationConstants256[r3, 0]) ^ v0;
			v2 += v1; v1 = RotateLeft(v1, RotationConstants256[r3, 1]) ^ v2;

			// Key injection every 4 rounds
			v0 += ks[(d + 1) % 5];
			v1 += ks[(d + 2) % 5] + ts[(d + 1) % 3];
			v2 += ks[(d + 3) % 5] + ts[(d + 2) % 3];
			v3 += ks[(d + 4) % 5] + (ulong)(d + 1);
		}

		input[0] = v0;
		input[1] = v1;
		input[2] = v2;
		input[3] = v3;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong RotateLeft(ulong value, int count) => (value << count) | (value >> (64 - count));
}

/// <summary>
/// Skein-512 (512-bit state size, configurable output).
/// </summary>
internal sealed class Skein512Hash : Skein {
	// Threefish-512 rotation constants (8 rounds × 4 values)
	// Reference: Skein specification v1.3, Section 8.3
	private static readonly int[,] RotationConstants512 = {
		{ 46, 36, 19, 37 }, // Round 0
		{ 33, 27, 14, 42 }, // Round 1
		{ 17, 49, 36, 39 }, // Round 2
		{ 44,  9, 54, 56 }, // Round 3
		{ 39, 30, 34, 24 }, // Round 4
		{ 13, 50, 10, 17 }, // Round 5
		{ 25, 29, 39, 43 }, // Round 6
		{  8, 35, 56, 22 }  // Round 7
	};

	public Skein512Hash(int outputBits = 512) : base(512, outputBits) { }

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
		byte[] config = new byte[_blockBytes];
		config[0] = (byte)'S';
		config[1] = (byte)'H';
		config[2] = (byte)'A';
		config[3] = (byte)'3';
		config[4] = 1;
		config[5] = 0;
		config[6] = 0;
		config[7] = 0;
		BitConverter.TryWriteBytes(config.AsSpan(8, 8), (ulong)_outputBits);

		_t0 = 32;
		_t1 = TweakFirst | TweakFinal | TweakTypeCfg;
		ProcessBlock(config, true);

		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected override void ThreefishEncrypt(ulong[] key, ulong[] input, ulong[] keySchedule, ulong t0, ulong t1) {
		// Threefish-512: 72 rounds, 8 words
		// Reference: Skein specification v1.3 and BouncyCastle implementation
		ulong k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
		ulong k4 = key[4], k5 = key[5], k6 = key[6], k7 = key[7];
		ulong k8 = k0 ^ k1 ^ k2 ^ k3 ^ k4 ^ k5 ^ k6 ^ k7 ^ C240;
		ulong t2 = t0 ^ t1;

		// Initial key addition
		ulong b0 = input[0] + k0;
		ulong b1 = input[1] + k1;
		ulong b2 = input[2] + k2;
		ulong b3 = input[3] + k3;
		ulong b4 = input[4] + k4;
		ulong b5 = input[5] + k5 + t0;
		ulong b6 = input[6] + k6 + t1;
		ulong b7 = input[7] + k7;

		ulong[] ks = [k0, k1, k2, k3, k4, k5, k6, k7, k8];
		ulong[] ts = [t0, t1, t2];

		// 72 rounds = 18 iterations of 4 rounds each
		// Key injection happens every 4 rounds
		// Permutation pattern cycles every 4 rounds
		// Rotation constants cycle every 8 rounds
		for (int d = 0; d < 18; d++) {
			int r0 = (4 * d + 0) % 8;
			int r1 = (4 * d + 1) % 8;
			int r2 = (4 * d + 2) % 8;
			int r3 = (4 * d + 3) % 8;

			// Round 4*d+0: Mix(0,1), Mix(2,3), Mix(4,5), Mix(6,7)
			b0 += b1; b1 = RotateLeft(b1, RotationConstants512[r0, 0]) ^ b0;
			b2 += b3; b3 = RotateLeft(b3, RotationConstants512[r0, 1]) ^ b2;
			b4 += b5; b5 = RotateLeft(b5, RotationConstants512[r0, 2]) ^ b4;
			b6 += b7; b7 = RotateLeft(b7, RotationConstants512[r0, 3]) ^ b6;

			// Round 4*d+1: Mix(2,1), Mix(4,7), Mix(6,5), Mix(0,3)
			// Permutation: 0→2, 1→1, 2→4, 3→7, 4→6, 5→5, 6→0, 7→3
			b2 += b1; b1 = RotateLeft(b1, RotationConstants512[r1, 0]) ^ b2;
			b4 += b7; b7 = RotateLeft(b7, RotationConstants512[r1, 1]) ^ b4;
			b6 += b5; b5 = RotateLeft(b5, RotationConstants512[r1, 2]) ^ b6;
			b0 += b3; b3 = RotateLeft(b3, RotationConstants512[r1, 3]) ^ b0;

			// Round 4*d+2: Mix(4,1), Mix(6,3), Mix(0,5), Mix(2,7)
			b4 += b1; b1 = RotateLeft(b1, RotationConstants512[r2, 0]) ^ b4;
			b6 += b3; b3 = RotateLeft(b3, RotationConstants512[r2, 1]) ^ b6;
			b0 += b5; b5 = RotateLeft(b5, RotationConstants512[r2, 2]) ^ b0;
			b2 += b7; b7 = RotateLeft(b7, RotationConstants512[r2, 3]) ^ b2;

			// Round 4*d+3: Mix(6,1), Mix(0,7), Mix(2,5), Mix(4,3)
			b6 += b1; b1 = RotateLeft(b1, RotationConstants512[r3, 0]) ^ b6;
			b0 += b7; b7 = RotateLeft(b7, RotationConstants512[r3, 1]) ^ b0;
			b2 += b5; b5 = RotateLeft(b5, RotationConstants512[r3, 2]) ^ b2;
			b4 += b3; b3 = RotateLeft(b3, RotationConstants512[r3, 3]) ^ b4;

			// Key injection every 4 rounds
			b0 += ks[(d + 1) % 9];
			b1 += ks[(d + 2) % 9];
			b2 += ks[(d + 3) % 9];
			b3 += ks[(d + 4) % 9];
			b4 += ks[(d + 5) % 9];
			b5 += ks[(d + 6) % 9] + ts[(d + 1) % 3];
			b6 += ks[(d + 7) % 9] + ts[(d + 2) % 3];
			b7 += ks[(d + 8) % 9] + (ulong)(d + 1);
		}

		input[0] = b0;
		input[1] = b1;
		input[2] = b2;
		input[3] = b3;
		input[4] = b4;
		input[5] = b5;
		input[6] = b6;
		input[7] = b7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong RotateLeft(ulong value, int count) => (value << count) | (value >> (64 - count));
}

/// <summary>
/// Skein-1024 (1024-bit state size, configurable output).
/// </summary>
internal sealed class Skein1024Hash : Skein {
	public Skein1024Hash(int outputBits = 1024) : base(1024, outputBits) { }

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
		byte[] config = new byte[_blockBytes];
		config[0] = (byte)'S';
		config[1] = (byte)'H';
		config[2] = (byte)'A';
		config[3] = (byte)'3';
		config[4] = 1;
		config[5] = 0;
		config[6] = 0;
		config[7] = 0;
		BitConverter.TryWriteBytes(config.AsSpan(8, 8), (ulong)_outputBits);

		_t0 = 32;
		_t1 = TweakFirst | TweakFinal | TweakTypeCfg;
		ProcessBlock(config, true);

		_t0 = 0;
		_t1 = TweakFirst | TweakTypeMsg;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected override void ThreefishEncrypt(ulong[] key, ulong[] input, ulong[] keySchedule, ulong t0, ulong t1) {
		// Threefish-1024: 80 rounds, 16 words
		// Simplified implementation - full version would have 16 state words
		ulong parity = C240;
		for (int i = 0; i < 16; i++) {
			parity ^= key[i];
		}

		ulong t2 = t0 ^ t1;
		ulong[] v = new ulong[16];
		ulong[] ks = new ulong[17];

		for (int i = 0; i < 16; i++) {
			ks[i] = key[i];
			v[i] = input[i] + key[i];
		}
		ks[16] = parity;

		v[13] += t0;
		v[14] += t1;

		ulong[] ts = [t0, t1, t2];

		// Rotation constants for Threefish-1024
		int[,] rot = new int[8, 8] {
			{ 24, 13, 8, 47, 8, 17, 22, 37 },
			{ 38, 19, 10, 55, 49, 18, 23, 52 },
			{ 33, 4, 51, 13, 34, 41, 59, 17 },
			{ 5, 20, 48, 41, 47, 28, 16, 25 },
			{ 41, 9, 37, 31, 12, 47, 44, 30 },
			{ 16, 34, 56, 51, 4, 53, 42, 41 },
			{ 31, 44, 47, 46, 19, 42, 44, 25 },
			{ 9, 48, 35, 52, 23, 31, 37, 20 }
		};

		// 80 rounds (20 iterations of 4 rounds each)
		for (int d = 0; d < 20; d++) {
			int dm = d % 8;

			// 4 rounds of mixing
			for (int r = 0; r < 4; r++) {
				int[] pairs = r switch {
					0 => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
					1 => [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1],
					2 => [0, 7, 2, 5, 4, 3, 6, 1, 12, 15, 14, 13, 8, 11, 10, 9],
					_ => [0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7]
				};

				for (int i = 0; i < 8; i++) {
					int a = pairs[i * 2];
					int b = pairs[i * 2 + 1];
					v[a] += v[b];
					v[b] = RotateLeft(v[b], rot[(dm + r) % 8, i]) ^ v[a];
				}
			}

			// Key injection
			for (int i = 0; i < 16; i++) {
				v[i] += ks[(d + 1 + i) % 17];
			}
			v[13] += ts[(d + 1) % 3];
			v[14] += ts[(d + 2) % 3];
			v[15] += (ulong)(d + 1);
		}

		for (int i = 0; i < 16; i++) {
			input[i] = v[i];
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong RotateLeft(ulong value, int count) => (value << count) | (value >> (64 - count));
}

/// <summary>
/// Factory for creating Skein hash instances.
/// </summary>
public static class SkeinFactory {
	/// <summary>
	/// Computes Skein-256 hash of the given data.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 256-bit hash.</returns>
	public static byte[] ComputeSkein256(ReadOnlySpan<byte> data) {
		using var hasher = new Skein256Hash(256);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes Skein-512 hash of the given data.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 512-bit hash.</returns>
	public static byte[] ComputeSkein512(ReadOnlySpan<byte> data) {
		using var hasher = new Skein512Hash(512);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes Skein-1024 hash of the given data.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 1024-bit hash.</returns>
	public static byte[] ComputeSkein1024(ReadOnlySpan<byte> data) {
		using var hasher = new Skein1024Hash(1024);
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Creates a streaming Skein-256 instance.
	/// </summary>
	public static IStreamingHashBytes CreateSkein256() => new Skein256Hash(256);

	/// <summary>
	/// Creates a streaming Skein-512 instance.
	/// </summary>
	public static IStreamingHashBytes CreateSkein512() => new Skein512Hash(512);

	/// <summary>
	/// Creates a streaming Skein-1024 instance.
	/// </summary>
	public static IStreamingHashBytes CreateSkein1024() => new Skein1024Hash(1024);
}
