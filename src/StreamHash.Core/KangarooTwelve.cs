namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of KangarooTwelve (K12), a fast extendable-output function.
/// </summary>
/// <remarks>
/// <para>
/// KangarooTwelve is a fast hash function based on Keccak-p[1600, 12] with reduced rounds.
/// It uses only 12 rounds (vs 24 in SHA-3) while maintaining excellent security margins.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output:</b> Variable length (XOF - extendable-output function)</item>
/// <item><b>Block Size:</b> 8192 bytes (chaining value block)</item>
/// <item><b>State Size:</b> 1600 bits (200 bytes)</item>
/// <item><b>Security:</b> 128-bit security level</item>
/// <item><b>Speed:</b> ~10+ GB/s on modern CPUs with SIMD</item>
/// </list>
/// </para>
/// <para>
/// <b>Structure:</b>
/// <list type="bullet">
/// <item>Uses Keccak-p[1600, 12] as the underlying permutation</item>
/// <item>Supports tree hashing for parallel processing (not used in streaming mode)</item>
/// <item>Customization string support for domain separation</item>
/// <item>XOF mode allows arbitrary output length</item>
/// </list>
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>High-speed hashing for large files</item>
/// <item>Key derivation functions</item>
/// <item>Generating random-looking output of any length</item>
/// <item>Post-quantum secure applications</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://keccak.team/kangarootwelve.html">KangarooTwelve Official Page</see></item>
/// <item><see href="https://eprint.iacr.org/2016/770.pdf">KangarooTwelve Paper</see></item>
/// <item><see href="https://github.com/XKCP/XKCP">XKCP Reference Implementation</see></item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Simple hash with default 32-byte output
/// using var hasher = new KangarooTwelve();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// byte[] hash = hasher.Finalize();
///
/// // With customization string
/// using var hasher2 = new KangarooTwelve(customization: Encoding.UTF8.GetBytes("MyApp"));
/// hasher2.Update(data);
/// byte[] hash2 = hasher2.Finalize();
///
/// // Custom output length (64 bytes)
/// using var hasher3 = new KangarooTwelve(outputLength: 64);
/// hasher3.Update(data);
/// byte[] hash3 = hasher3.Finalize();
/// </code>
/// </example>
/// <remarks>
/// <para>
/// This class does not implement <see cref="IStreamingHash{TResult}"/> because KangarooTwelve
/// is an XOF (extendable-output function) with variable-length output, which cannot be
/// represented as a fixed-size struct type.
/// </para>
/// </remarks>
public sealed class KangarooTwelve : IDisposable {
	/// <summary>
	/// Rate for Keccak-p[1600, 12] in K12 (1600 - 256 = 1344 bits = 168 bytes).
	/// </summary>
	private const int Rate = 168;

	/// <summary>
	/// Block size for the inner Keccak absorb.
	/// </summary>
	private const int KeccakBlockSize = Rate;

	/// <summary>
	/// Chunk size for tree hashing (8192 bytes).
	/// </summary>
	private const int ChunkSize = 8192;

	/// <summary>
	/// Number of Keccak-p rounds (12 for K12).
	/// </summary>
	private const int Rounds = 12;

	/// <summary>
	/// Keccak round constants for iota step.
	/// </summary>
	private static readonly ulong[] RoundConstants = [
		0x000000008000808bUL,
		0x800000000000008bUL,
		0x8000000000008089UL,
		0x8000000000008003UL,
		0x8000000000008002UL,
		0x8000000000000080UL,
		0x000000000000800aUL,
		0x800000008000000aUL,
		0x8000000080008081UL,
		0x8000000000008080UL,
		0x0000000080000001UL,
		0x8000000080008008UL,
	];

	/// <summary>
	/// Rotation offsets for the rho step.
	/// </summary>
	private static readonly int[] RhoOffsets = [
		0, 1, 62, 28, 27,
		36, 44, 6, 55, 20,
		3, 10, 43, 25, 39,
		41, 45, 15, 21, 8,
		18, 2, 61, 56, 14
	];

	/// <summary>
	/// The Keccak state (25 64-bit words = 1600 bits).
	/// </summary>
	private readonly ulong[] _state = new ulong[25];

	/// <summary>
	/// Buffer for absorbing data.
	/// </summary>
	private readonly byte[] _buffer;

	/// <summary>
	/// Current position in the buffer.
	/// </summary>
	private int _bufferPosition;

	/// <summary>
	/// Total bytes processed so far.
	/// </summary>
	private long _totalBytes;

	/// <summary>
	/// Whether Finalize has been called.
	/// </summary>
	private bool _finalized;

	/// <summary>
	/// Whether the instance has been disposed.
	/// </summary>
	private bool _disposed;

	/// <summary>
	/// The customization string (optional).
	/// </summary>
	private readonly byte[] _customization;

	/// <summary>
	/// The desired output length in bytes.
	/// </summary>
	private readonly int _outputLength;

	/// <summary>
	/// Number of complete chunks processed.
	/// </summary>
	private int _chunkCount;

	/// <summary>
	/// Buffer for current chunk data.
	/// </summary>
	private readonly byte[] _chunkBuffer;

	/// <summary>
	/// Position within current chunk.
	/// </summary>
	private int _chunkPosition;

	/// <summary>
	/// Whether we're still in the first chunk.
	/// </summary>
	private bool _inFirstChunk = true;

	/// <summary>
	/// Chaining values for tree hashing.
	/// </summary>
	private readonly List<byte[]> _chainingValues = [];

	/// <inheritdoc/>
	public int BlockSize => ChunkSize;

	/// <inheritdoc/>
	public int DigestSize => _outputLength;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// Creates a new KangarooTwelve hasher with default settings.
	/// </summary>
	/// <param name="outputLength">Desired output length in bytes. Default is 32.</param>
	/// <param name="customization">Optional customization string for domain separation.</param>
	public KangarooTwelve(int outputLength = 32, byte[]? customization = null) {
		if (outputLength <= 0) {
			throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length must be positive.");
		}

		_outputLength = outputLength;
		_customization = customization ?? [];
		_buffer = new byte[Rate];
		_chunkBuffer = new byte[ChunkSize];
		_bufferPosition = 0;
		_chunkPosition = 0;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Cannot update after Finalize() has been called. Call Reset() first.");
		}

		if (data.IsEmpty) {
			return;
		}

		_totalBytes += data.Length;
		int offset = 0;

		while (offset < data.Length) {
			int remaining = data.Length - offset;
			int chunkRemaining = ChunkSize - _chunkPosition;
			int toCopy = Math.Min(remaining, chunkRemaining);

			data.Slice(offset, toCopy).CopyTo(_chunkBuffer.AsSpan(_chunkPosition));
			_chunkPosition += toCopy;
			offset += toCopy;

			// If chunk is complete, process it
			if (_chunkPosition == ChunkSize) {
				ProcessChunk();
			}
		}
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		if (data == null) throw new ArgumentNullException(nameof(data));
		if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
		if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
		if (offset + length > data.Length) throw new ArgumentException("Invalid offset/length combination.");

		Update(data.AsSpan(offset, length));
	}

	/// <summary>
	/// Processes a complete chunk.
	/// </summary>
	private void ProcessChunk() {
		if (_inFirstChunk) {
			// First chunk: absorb directly into main state
			AbsorbIntoState(_chunkBuffer.AsSpan(0, ChunkSize));
			_inFirstChunk = false;
		} else {
			// Subsequent chunks: compute chaining value
			byte[] cv = ComputeChainingValue(_chunkBuffer.AsSpan(0, ChunkSize));
			_chainingValues.Add(cv);
			_chunkCount++;
		}

		_chunkPosition = 0;
	}

	/// <summary>
	/// Computes a 32-byte chaining value for a chunk.
	/// </summary>
	private byte[] ComputeChainingValue(ReadOnlySpan<byte> chunk) {
		ulong[] chunkState = new ulong[25];

		// Absorb the chunk
		int pos = 0;
		while (pos < chunk.Length) {
			int blockLen = Math.Min(Rate, chunk.Length - pos);
			AbsorbBlock(chunkState, chunk.Slice(pos, blockLen), (byte)(pos + blockLen == chunk.Length ? 0x0b : 0x00));
			pos += blockLen;
		}

		// Pad and finalize for chaining value (32 bytes)
		PadAndPermute(chunkState, 0x0b);

		// Extract 32 bytes
		byte[] cv = new byte[32];
		for (int i = 0; i < 4; i++) {
			BinaryPrimitives.WriteUInt64LittleEndian(cv.AsSpan(i * 8), chunkState[i]);
		}

		return cv;
	}

	/// <summary>
	/// Absorbs data into the main state.
	/// </summary>
	private void AbsorbIntoState(ReadOnlySpan<byte> data) {
		int pos = 0;
		while (pos < data.Length) {
			int remaining = data.Length - pos;
			int bufferRemaining = Rate - _bufferPosition;
			int toCopy = Math.Min(remaining, bufferRemaining);

			data.Slice(pos, toCopy).CopyTo(_buffer.AsSpan(_bufferPosition));
			_bufferPosition += toCopy;
			pos += toCopy;

			if (_bufferPosition == Rate) {
				// XOR buffer into state and permute
				XorIntoState(_buffer);
				KeccakPermutation();
				_bufferPosition = 0;
			}
		}
	}

	/// <summary>
	/// XORs a rate-sized block into the state.
	/// </summary>
	private void XorIntoState(ReadOnlySpan<byte> block) {
		for (int i = 0; i < Rate / 8; i++) {
			_state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * 8, 8));
		}
	}

	/// <summary>
	/// Absorbs a block into a given state with domain separation.
	/// </summary>
	private static void AbsorbBlock(ulong[] state, ReadOnlySpan<byte> block, byte domainSep) {
		Span<byte> padded = stackalloc byte[Rate];
		block.CopyTo(padded);

		for (int i = 0; i < Rate / 8; i++) {
			state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(padded.Slice(i * 8, 8));
		}

		KeccakPermutation(state);
	}

	/// <summary>
	/// Pads and performs final permutation.
	/// </summary>
	private static void PadAndPermute(ulong[] state, byte domainSep) {
		// Apply domain separation and padding
		state[0] ^= domainSep;
		state[Rate / 8 - 1] ^= 0x80UL << 56;
		KeccakPermutation(state);
	}

	/// <inheritdoc/>
	public byte[] Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException("Finalize() has already been called. Call Reset() first.");
		}

		_finalized = true;

		// Process remaining chunk data
		if (_inFirstChunk) {
			// All data fit in first chunk
			AbsorbIntoState(_chunkBuffer.AsSpan(0, _chunkPosition));
		} else {
			// Process final partial chunk if any
			if (_chunkPosition > 0) {
				byte[] cv = ComputeChainingValue(_chunkBuffer.AsSpan(0, _chunkPosition));
				_chainingValues.Add(cv);
				_chunkCount++;
			}

			// Absorb chaining values
			foreach (byte[] cv in _chainingValues) {
				AbsorbIntoState(cv);
			}
		}

		// Absorb customization string with length encoding
		AbsorbCustomization();

		// Apply padding
		// K12 uses suffix 0x07 for non-tree mode, 0x06 for tree mode
		byte suffix = _chainingValues.Count == 0 ? (byte)0x07 : (byte)0x06;

		// Pad the buffer
		_buffer[_bufferPosition] = suffix;
		_buffer[Rate - 1] |= 0x80;

		// XOR padded buffer into state
		XorIntoState(_buffer.AsSpan(0, Rate));
		KeccakPermutation();

		// Squeeze output
		return Squeeze(_outputLength);
	}

	/// <summary>
	/// Absorbs the customization string.
	/// </summary>
	private void AbsorbCustomization() {
		if (_customization.Length == 0) {
			// Absorb just the length encoding (0)
			AbsorbIntoState([0x00]);
		} else {
			// Absorb customization string followed by length encoding
			AbsorbIntoState(_customization);
			AbsorbLengthEncoding(_customization.Length);
		}
	}

	/// <summary>
	/// Absorbs the right-encoded length.
	/// </summary>
	private void AbsorbLengthEncoding(int length) {
		// Right encode the length
		Span<byte> encoded = stackalloc byte[9];
		int pos = 8;

		if (length == 0) {
			encoded[pos--] = 1;
			encoded[pos] = 0;
		} else {
			int n = 0;
			int temp = length;
			while (temp > 0) {
				encoded[pos--] = (byte)(temp & 0xff);
				temp >>= 8;
				n++;
			}
			encoded[8] = (byte)n;
		}

		AbsorbIntoState(encoded.Slice(pos + 1, 9 - pos - 1));
	}

	/// <summary>
	/// Squeezes output bytes from the state.
	/// </summary>
	private byte[] Squeeze(int length) {
		byte[] output = new byte[length];
		int outputPos = 0;

		while (outputPos < length) {
			int blockLen = Math.Min(Rate, length - outputPos);

			// Extract bytes from state
			for (int i = 0; i < blockLen; i++) {
				int wordIndex = i / 8;
				int byteIndex = i % 8;
				output[outputPos + i] = (byte)(_state[wordIndex] >> (byteIndex * 8));
			}

			outputPos += blockLen;

			if (outputPos < length) {
				KeccakPermutation();
			}
		}

		return output;
	}

	/// <summary>
	/// Performs the Keccak-p[1600, 12] permutation on the instance state.
	/// </summary>
	private void KeccakPermutation() {
		KeccakPermutation(_state);
	}

	/// <summary>
	/// Performs the Keccak-p[1600, 12] permutation.
	/// </summary>
	/// <param name="state">The 25-word state to permute.</param>
	private static void KeccakPermutation(ulong[] state) {
		Span<ulong> c = stackalloc ulong[5];
		Span<ulong> d = stackalloc ulong[5];
		Span<ulong> b = stackalloc ulong[25];

		// Only 12 rounds for K12
		for (int round = 24 - Rounds; round < 24; round++) {
			// θ (theta) step
			for (int x = 0; x < 5; x++) {
				c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
			}

			for (int x = 0; x < 5; x++) {
				d[x] = c[(x + 4) % 5] ^ BitOperations.RotateLeft(c[(x + 1) % 5], 1);
			}

			for (int i = 0; i < 25; i++) {
				state[i] ^= d[i % 5];
			}

			// ρ (rho) and π (pi) steps combined
			for (int i = 0; i < 25; i++) {
				int x = i % 5;
				int y = i / 5;
				int newX = y;
				int newY = (2 * x + 3 * y) % 5;
				b[newX + 5 * newY] = BitOperations.RotateLeft(state[i], RhoOffsets[i]);
			}

			// χ (chi) step
			for (int y = 0; y < 5; y++) {
				for (int x = 0; x < 5; x++) {
					state[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
				}
			}

			// ι (iota) step
			state[0] ^= RoundConstants[round - (24 - Rounds)];
		}
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		Array.Clear(_state);
		Array.Clear(_buffer);
		Array.Clear(_chunkBuffer);
		_bufferPosition = 0;
		_chunkPosition = 0;
		_totalBytes = 0;
		_chunkCount = 0;
		_inFirstChunk = true;
		_chainingValues.Clear();
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (!_disposed) {
			Array.Clear(_state);
			Array.Clear(_buffer);
			Array.Clear(_chunkBuffer);
			_chainingValues.Clear();
			_disposed = true;
		}
	}

	/// <summary>
	/// Computes KangarooTwelve of the given data in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="outputLength">Desired output length in bytes.</param>
	/// <param name="customization">Optional customization string.</param>
	/// <returns>The hash value.</returns>
	public static byte[] Hash(ReadOnlySpan<byte> data, int outputLength = 32, byte[]? customization = null) {
		using var hasher = new KangarooTwelve(outputLength, customization);
		hasher.Update(data);
		return hasher.Finalize();
	}
}
