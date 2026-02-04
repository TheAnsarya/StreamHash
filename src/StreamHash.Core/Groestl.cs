namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of the Grøstl hash function (SHA-3 finalist).
/// </summary>
/// <remarks>
/// <para>
/// Grøstl is a cryptographic hash function designed by Praveen Gauravaram et al.
/// It was one of the five finalists in the NIST SHA-3 competition.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Structure:</b> Wide-pipe Merkle-Damgård with output transformation</item>
/// <item><b>Compression Function:</b> Uses two AES-like permutations P and Q</item>
/// <item><b>Block Size:</b> 64 bytes (512 bits) for Grøstl-256, 128 bytes (1024 bits) for Grøstl-512</item>
/// <item><b>State Size:</b> 512 bits for ≤256-bit output, 1024 bits for >256-bit output</item>
/// <item><b>S-box:</b> AES S-box</item>
/// <item><b>Security:</b> 128-bit for Grøstl-256, 256-bit for Grøstl-512</item>
/// </list>
/// </para>
/// <para>
/// <b>Design Principles:</b>
/// <list type="bullet">
/// <item>Uses two distinct permutations P and Q applied to message and chaining value</item>
/// <item>AES-like structure with SubBytes, ShiftBytes, MixBytes, AddRoundConstant</item>
/// <item>10 rounds for 512-bit state, 14 rounds for 1024-bit state</item>
/// <item>Output transformation: P(h) XOR h to prevent length extension attacks</item>
/// </list>
/// </para>
/// <para>
/// <b>Performance Optimizations:</b>
/// <list type="bullet">
/// <item>T-tables for MixBytes - pre-computed GF(2^8) multiplication tables</item>
/// <item>Pre-allocated buffers - zero allocations in hot path</item>
/// <item>Loop unrolling in critical sections</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://www.groestl.info/">Grøstl Official Website</see></item>
/// <item><see href="https://www.groestl.info/Groestl.pdf">Grøstl Specification</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class GroestlDigest : IStreamingHashBytes {
	// ========== Constants ==========

	/// <summary>Number of columns in the state matrix for 512-bit variant.</summary>
	private const int Cols512 = 8;

	/// <summary>Number of columns in the state matrix for 1024-bit variant.</summary>
	private const int Cols1024 = 16;

	/// <summary>Number of rounds for 512-bit state (Grøstl-224/256).</summary>
	private const int Rounds512 = 10;

	/// <summary>Number of rounds for 1024-bit state (Grøstl-384/512).</summary>
	private const int Rounds1024 = 14;

	/// <summary>Number of rows in the state matrix (always 8 for all variants).</summary>
	private const int Rows = 8;

	/// <summary>
	/// AES S-box used in SubBytes transformation.
	/// This is the same S-box used in AES (Rijndael).
	/// </summary>
	private static readonly byte[] SBox = [
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	];

	// ========== T-Tables for MixBytes Optimization ==========
	// Pre-computed multiplication tables for GF(2^8) with polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
	// The MDS matrix uses coefficients [02, 02, 03, 04, 05, 03, 05, 07]
	// These tables eliminate the need for runtime multiplication

	/// <summary>Multiplication by 0x02 in GF(2^8).</summary>
	private static readonly byte[] Mul02 = GenerateMulTable(0x02);

	/// <summary>Multiplication by 0x03 in GF(2^8).</summary>
	private static readonly byte[] Mul03 = GenerateMulTable(0x03);

	/// <summary>Multiplication by 0x04 in GF(2^8).</summary>
	private static readonly byte[] Mul04 = GenerateMulTable(0x04);

	/// <summary>Multiplication by 0x05 in GF(2^8).</summary>
	private static readonly byte[] Mul05 = GenerateMulTable(0x05);

	/// <summary>Multiplication by 0x07 in GF(2^8).</summary>
	private static readonly byte[] Mul07 = GenerateMulTable(0x07);

	/// <summary>
	/// Generate multiplication table for a constant in GF(2^8).
	/// </summary>
	/// <param name="constant">The constant to multiply by.</param>
	/// <returns>Table where Table[x] = constant * x in GF(2^8).</returns>
	private static byte[] GenerateMulTable(byte constant) {
		byte[] table = new byte[256];
		for (int i = 0; i < 256; i++) {
			table[i] = MultiplyGF((byte)i, constant);
		}
		return table;
	}

	/// <summary>
	/// Multiplication in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
	/// Used only during static initialization to generate T-tables.
	/// </summary>
	private static byte MultiplyGF(byte a, byte b) {
		byte result = 0;
		byte hi_bit;

		for (int i = 0; i < 8; i++) {
			if ((b & 1) != 0) {
				result ^= a;
			}

			hi_bit = (byte)(a & 0x80);
			a <<= 1;

			if (hi_bit != 0) {
				a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
			}

			b >>= 1;
		}

		return result;
	}

	/// <summary>
	/// Shift values for ShiftBytes in P permutation (512-bit state).
	/// Row i is shifted by Shift512P[i] positions to the left.
	/// </summary>
	private static readonly int[] Shift512P = [0, 1, 2, 3, 4, 5, 6, 7];

	/// <summary>
	/// Shift values for ShiftBytes in Q permutation (512-bit state).
	/// Row i is shifted by Shift512Q[i] positions to the left.
	/// </summary>
	private static readonly int[] Shift512Q = [1, 3, 5, 7, 0, 2, 4, 6];

	/// <summary>
	/// Shift values for ShiftBytes in P permutation (1024-bit state).
	/// </summary>
	private static readonly int[] Shift1024P = [0, 1, 2, 3, 4, 5, 6, 11];

	/// <summary>
	/// Shift values for ShiftBytes in Q permutation (1024-bit state).
	/// </summary>
	private static readonly int[] Shift1024Q = [1, 3, 5, 11, 0, 2, 4, 6];

	// ========== Instance Fields ==========

	/// <summary>Output hash size in bytes.</summary>
	private readonly int _hashSize;

	/// <summary>Block size in bytes (64 for 256-bit, 128 for 512-bit).</summary>
	private readonly int _blockSize;

	/// <summary>Number of columns in state matrix.</summary>
	private readonly int _cols;

	/// <summary>Number of rounds.</summary>
	private readonly int _rounds;

	/// <summary>Chaining value (state) - stored as column-major 8×cols matrix.</summary>
	private readonly byte[] _state;

	/// <summary>Message buffer for incomplete blocks.</summary>
	private readonly byte[] _buffer;

	/// <summary>Pre-allocated temporary buffer for message block (m).</summary>
	private readonly byte[] _tempM;

	/// <summary>Pre-allocated temporary buffer for h XOR m.</summary>
	private readonly byte[] _tempHM;

	/// <summary>Pre-allocated temporary row buffer for ShiftBytes.</summary>
	private readonly byte[] _tempRow;

	/// <summary>Pre-allocated temporary column buffer for MixBytes.</summary>
	private readonly byte[] _tempCol;

	/// <summary>Current position in buffer.</summary>
	private int _bufferPos;

	/// <summary>Total number of blocks processed.</summary>
	private ulong _blockCount;

	/// <summary>Total bytes processed.</summary>
	private long _totalBytes;

	/// <summary>Whether the hash has been finalized.</summary>
	private bool _finalized;

	/// <summary>Whether the instance has been disposed.</summary>
	private bool _disposed;

	// ========== Constructors ==========

	/// <summary>
	/// Creates a new Grøstl digest with the specified output size.
	/// </summary>
	/// <param name="hashBits">Output hash size in bits (224, 256, 384, or 512).</param>
	/// <exception cref="ArgumentException">Invalid hash size.</exception>
	public GroestlDigest(int hashBits) {
		if (hashBits != 224 && hashBits != 256 && hashBits != 384 && hashBits != 512) {
			throw new ArgumentException("Hash size must be 224, 256, 384, or 512 bits", nameof(hashBits));
		}

		_hashSize = hashBits / 8;

		// Use 512-bit state for ≤256-bit output, 1024-bit for larger
		if (hashBits <= 256) {
			_cols = Cols512;
			_rounds = Rounds512;
			_blockSize = 64; // 512 bits
		} else {
			_cols = Cols1024;
			_rounds = Rounds1024;
			_blockSize = 128; // 1024 bits
		}

		_state = new byte[Rows * _cols];
		_buffer = new byte[_blockSize];
		_tempM = new byte[Rows * _cols];
		_tempHM = new byte[Rows * _cols];
		_tempRow = new byte[_cols > Cols512 ? Cols1024 : Cols512];
		_tempCol = new byte[Rows];

		Reset();
	}

	// ========== IStreamingHashBytes Implementation ==========

	/// <inheritdoc/>
	public int BlockSize => _blockSize;

	/// <inheritdoc/>
	public int DigestSize => _hashSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Hash already finalized");

		_totalBytes += data.Length;
		int offset = 0;

		// Fill buffer if partially full
		if (_bufferPos > 0) {
			int toCopy = Math.Min(_blockSize - _bufferPos, data.Length);
			data.Slice(0, toCopy).CopyTo(_buffer.AsSpan(_bufferPos));
			_bufferPos += toCopy;
			offset += toCopy;

			if (_bufferPos == _blockSize) {
				ProcessBlock(_buffer);
				_blockCount++;
				_bufferPos = 0;
			}
		}

		// Process complete blocks directly
		while (offset + _blockSize <= data.Length) {
			ProcessBlock(data.Slice(offset, _blockSize));
			_blockCount++;
			offset += _blockSize;
		}

		// Buffer remaining data
		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferPos));
			_bufferPos += data.Length - offset;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Hash already finalized");
		_finalized = true;

		// Padding: append 1 bit, then zeros, then 64-bit block count (big-endian)
		// Total padded length must be multiple of block size
		ulong totalBlocks = _blockCount + 1; // Include final block

		// Calculate how many more bytes we need
		int paddingStart = _bufferPos;
		_buffer[paddingStart] = 0x80; // Append bit '1'

		// Fill rest with zeros
		Array.Clear(_buffer, paddingStart + 1, _blockSize - paddingStart - 1);

		// If not enough room for the 8-byte length, process this block and start a new one
		if (paddingStart >= _blockSize - 8) {
			ProcessBlock(_buffer);
			totalBlocks++;
			Array.Clear(_buffer, 0, _blockSize);
		}

		// Append block count as big-endian 64-bit integer
		for (int i = 0; i < 8; i++) {
			_buffer[_blockSize - 8 + i] = (byte)(totalBlocks >> (56 - i * 8));
		}

		ProcessBlock(_buffer);

		// Output transformation: h' = P(h) XOR h
		// This prevents length extension attacks
		byte[] h = (byte[])_state.Clone();
		byte[] ph = new byte[_state.Length];
		Array.Copy(_state, ph, _state.Length);
		PermutationP(ph);

		for (int i = 0; i < _state.Length; i++) {
			h[i] ^= ph[i];
		}

		// Extract hash from rightmost columns
		byte[] result = new byte[_hashSize];
		int startCol = _cols - (_hashSize / Rows);
		for (int col = 0; col < _hashSize / Rows; col++) {
			for (int row = 0; row < Rows; row++) {
				result[col * Rows + row] = h[row * _cols + startCol + col];
			}
		}

		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		// Initial value: IV has the hash length in the last byte position
		Array.Clear(_state, 0, _state.Length);

		// Set IV: rightmost byte contains hash size in bits (big-endian)
		// For Grøstl-256: state[cols-1] = 0x00, state[rows*cols-1] = 0x01, state[rows*cols-2] = 0x00
		// Actually, IV_n = n (the hash length) in the last column
		int hashBits = _hashSize * 8;
		_state[Rows * _cols - 2] = (byte)(hashBits >> 8);
		_state[Rows * _cols - 1] = (byte)hashBits;

		Array.Clear(_buffer, 0, _blockSize);
		_bufferPos = 0;
		_blockCount = 0;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (!_disposed) {
			Array.Clear(_state);
			Array.Clear(_buffer);
			Array.Clear(_tempM);
			Array.Clear(_tempHM);
			Array.Clear(_tempRow);
			Array.Clear(_tempCol);
			_disposed = true;
		}
	}

	// ========== Core Algorithm ==========

	/// <summary>
	/// Processes a single message block using the Grøstl compression function.
	/// f(h, m) = P(h XOR m) XOR Q(m) XOR h
	/// </summary>
	/// <param name="block">The message block to process.</param>
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Convert block to column-major matrix using pre-allocated buffer
		for (int col = 0; col < _cols; col++) {
			for (int row = 0; row < Rows; row++) {
				_tempM[row * _cols + col] = block[col * Rows + row];
			}
		}

		// Compute h XOR m for P input using pre-allocated buffer
		for (int i = 0; i < _state.Length; i++) {
			_tempHM[i] = (byte)(_state[i] ^ _tempM[i]);
		}

		// Apply P permutation to (h XOR m)
		PermutationP(_tempHM);

		// Apply Q permutation to m
		PermutationQ(_tempM);

		// New state: P(h XOR m) XOR Q(m) XOR h
		for (int i = 0; i < _state.Length; i++) {
			_state[i] = (byte)(_tempHM[i] ^ _tempM[i] ^ _state[i]);
		}
	}

	/// <summary>
	/// Applies the P permutation (used for chaining value path).
	/// </summary>
	private void PermutationP(byte[] state) {
		int[] shift = _cols == Cols512 ? Shift512P : Shift1024P;

		for (int round = 0; round < _rounds; round++) {
			// AddRoundConstant for P: XOR round constant into first row
			AddRoundConstantP(state, round);

			// SubBytes: Apply S-box to every byte
			SubBytes(state);

			// ShiftBytes: Cyclically shift rows
			ShiftBytes(state, shift);

			// MixBytes: Mix columns using MDS matrix
			MixBytes(state);
		}
	}

	/// <summary>
	/// Applies the Q permutation (used for message path).
	/// </summary>
	private void PermutationQ(byte[] state) {
		int[] shift = _cols == Cols512 ? Shift512Q : Shift1024Q;

		for (int round = 0; round < _rounds; round++) {
			// AddRoundConstant for Q: different constants than P
			AddRoundConstantQ(state, round);

			// SubBytes: Apply S-box to every byte
			SubBytes(state);

			// ShiftBytes: Cyclically shift rows (different shift values)
			ShiftBytes(state, shift);

			// MixBytes: Mix columns using MDS matrix
			MixBytes(state);
		}
	}

	/// <summary>
	/// Adds round constants for P permutation.
	/// For P: first row XORed with (i * 0x10) XOR round
	/// </summary>
	private void AddRoundConstantP(byte[] state, int round) {
		for (int col = 0; col < _cols; col++) {
			// P uses: state[0,col] ^= (col << 4) ^ round
			state[col] ^= (byte)((col << 4) ^ round);
		}
	}

	/// <summary>
	/// Adds round constants for Q permutation.
	/// For Q: XOR 0xff into all positions, then XOR column/round values
	/// </summary>
	private void AddRoundConstantQ(byte[] state, int round) {
		// Q permutation: XOR 0xff into entire state first
		for (int i = 0; i < state.Length; i++) {
			state[i] ^= 0xff;
		}

		// Then XOR specific values into last row
		for (int col = 0; col < _cols; col++) {
			int idx = (Rows - 1) * _cols + col;
			state[idx] ^= (byte)((col << 4) ^ round);
		}
	}

	/// <summary>
	/// SubBytes transformation: Apply AES S-box to every byte.
	/// </summary>
	private void SubBytes(byte[] state) {
		for (int i = 0; i < state.Length; i++) {
			state[i] = SBox[state[i]];
		}
	}

	/// <summary>
	/// ShiftBytes transformation: Cyclically shift each row by different amounts.
	/// </summary>
	private void ShiftBytes(byte[] state, int[] shift) {
		for (int row = 0; row < Rows; row++) {
			int s = shift[row];
			if (s == 0) continue;

			// Copy row with shift using pre-allocated buffer
			for (int col = 0; col < _cols; col++) {
				_tempRow[col] = state[row * _cols + (col + s) % _cols];
			}

			// Write back
			for (int col = 0; col < _cols; col++) {
				state[row * _cols + col] = _tempRow[col];
			}
		}
	}

	/// <summary>
	/// MixBytes transformation: Mix columns using MDS matrix multiplication in GF(2^8).
	/// Uses T-tables for efficient computation - each multiplication is a table lookup.
	/// The MDS matrix is circulant: [02, 02, 03, 04, 05, 03, 05, 07].
	/// </summary>
	private void MixBytes(byte[] state) {
		for (int col = 0; col < _cols; col++) {
			// Extract column using pre-allocated buffer
			for (int row = 0; row < Rows; row++) {
				_tempCol[row] = state[row * _cols + col];
			}

			// Apply MDS matrix multiplication using T-tables
			// MDS matrix: [02, 02, 03, 04, 05, 03, 05, 07] (circulant)
			// result[row] = sum of Mul[coeff][col[(row+i) mod 8]] for each coefficient
			byte c0 = _tempCol[0], c1 = _tempCol[1], c2 = _tempCol[2], c3 = _tempCol[3];
			byte c4 = _tempCol[4], c5 = _tempCol[5], c6 = _tempCol[6], c7 = _tempCol[7];

			// Row 0: [02, 02, 03, 04, 05, 03, 05, 07] × [c0, c1, c2, c3, c4, c5, c6, c7]
			state[0 * _cols + col] = (byte)(Mul02[c0] ^ Mul02[c1] ^ Mul03[c2] ^ Mul04[c3] ^
										   Mul05[c4] ^ Mul03[c5] ^ Mul05[c6] ^ Mul07[c7]);

			// Row 1: rotate coefficients left by 1
			state[1 * _cols + col] = (byte)(Mul02[c1] ^ Mul02[c2] ^ Mul03[c3] ^ Mul04[c4] ^
										   Mul05[c5] ^ Mul03[c6] ^ Mul05[c7] ^ Mul07[c0]);

			// Row 2: rotate coefficients left by 2
			state[2 * _cols + col] = (byte)(Mul02[c2] ^ Mul02[c3] ^ Mul03[c4] ^ Mul04[c5] ^
										   Mul05[c6] ^ Mul03[c7] ^ Mul05[c0] ^ Mul07[c1]);

			// Row 3: rotate coefficients left by 3
			state[3 * _cols + col] = (byte)(Mul02[c3] ^ Mul02[c4] ^ Mul03[c5] ^ Mul04[c6] ^
										   Mul05[c7] ^ Mul03[c0] ^ Mul05[c1] ^ Mul07[c2]);

			// Row 4: rotate coefficients left by 4
			state[4 * _cols + col] = (byte)(Mul02[c4] ^ Mul02[c5] ^ Mul03[c6] ^ Mul04[c7] ^
										   Mul05[c0] ^ Mul03[c1] ^ Mul05[c2] ^ Mul07[c3]);

			// Row 5: rotate coefficients left by 5
			state[5 * _cols + col] = (byte)(Mul02[c5] ^ Mul02[c6] ^ Mul03[c7] ^ Mul04[c0] ^
										   Mul05[c1] ^ Mul03[c2] ^ Mul05[c3] ^ Mul07[c4]);

			// Row 6: rotate coefficients left by 6
			state[6 * _cols + col] = (byte)(Mul02[c6] ^ Mul02[c7] ^ Mul03[c0] ^ Mul04[c1] ^
										   Mul05[c2] ^ Mul03[c3] ^ Mul05[c4] ^ Mul07[c5]);

			// Row 7: rotate coefficients left by 7
			state[7 * _cols + col] = (byte)(Mul02[c7] ^ Mul02[c0] ^ Mul03[c1] ^ Mul04[c2] ^
										   Mul05[c3] ^ Mul03[c4] ^ Mul05[c5] ^ Mul07[c6]);
		}
	}
}

/// <summary>
/// Grøstl-256 streaming hash implementation.
/// </summary>
public sealed class Groestl256 : IStreamingHashBytes {
	private readonly GroestlDigest _inner = new(256);

	/// <inheritdoc/>
	public int BlockSize => _inner.BlockSize;

	/// <inheritdoc/>
	public int DigestSize => _inner.DigestSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _inner.TotalBytesProcessed;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) => _inner.Update(data);

	/// <inheritdoc/>
	public byte[] FinalizeBytes() => _inner.FinalizeBytes();

	/// <inheritdoc/>
	public void Reset() => _inner.Reset();

	/// <inheritdoc/>
	public void Dispose() => _inner.Dispose();
}

/// <summary>
/// Grøstl-512 streaming hash implementation.
/// </summary>
public sealed class Groestl512 : IStreamingHashBytes {
	private readonly GroestlDigest _inner = new(512);

	/// <inheritdoc/>
	public int BlockSize => _inner.BlockSize;

	/// <inheritdoc/>
	public int DigestSize => _inner.DigestSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _inner.TotalBytesProcessed;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) => _inner.Update(data);

	/// <inheritdoc/>
	public byte[] FinalizeBytes() => _inner.FinalizeBytes();

	/// <inheritdoc/>
	public void Reset() => _inner.Reset();

	/// <inheritdoc/>
	public void Dispose() => _inner.Dispose();
}
