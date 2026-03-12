namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the Whirlpool hash function.
/// </summary>
/// <remarks>
/// <para>
/// Whirlpool is a cryptographic hash function designed by Vincent Rijmen and Paulo S. L. M. Barreto.
/// It produces a 512-bit (64-byte) hash value and was adopted by ISO/IEC 10118-3:2004.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Output Size:</b> 512 bits (64 bytes)</item>
/// <item><b>Block Size:</b> 512 bits (64 bytes)</item>
/// <item><b>State Size:</b> 512 bits (8×8 byte matrix)</item>
/// <item><b>Rounds:</b> 10</item>
/// <item><b>Structure:</b> Miyaguchi-Preneel scheme with AES-like cipher W</item>
/// </list>
/// </para>
/// <para>
/// <b>Design Features:</b>
/// <list type="bullet">
/// <item>Uses a dedicated 8×8 S-box (not the AES S-box)</item>
/// <item>MDS matrix for diffusion (circulant matrix)</item>
/// <item>Cyclical shift rows (different from AES shift pattern)</item>
/// <item>Miyaguchi-Preneel construction: h = E(h, m) XOR h XOR m</item>
/// </list>
/// </para>
/// <para>
/// <b>Performance Optimizations:</b>
/// <list type="bullet">
/// <item>Pre-computed T-tables combining SubBytes, ShiftColumns, and MixRows</item>
/// <item>8 T-tables of 256 64-bit entries each for column-wise processing</item>
/// <item>Zero heap allocations in hot path</item>
/// <item>Efficient 64-bit operations for state manipulation</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html">Whirlpool Official Page</see></item>
/// <item><see href="https://www.iso.org/standard/39876.html">ISO/IEC 10118-3:2004</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class WhirlpoolDigest : IStreamingHashBytes {
	// ========== Constants ==========

	/// <summary>Hash output size in bytes (512 bits).</summary>
	private const int DigestSizeBytes = 64;

	/// <summary>Block size in bytes (512 bits).</summary>
	private const int BlockSizeBytes = 64;

	/// <summary>Number of rounds in the cipher.</summary>
	private const int Rounds = 10;

	/// <summary>State dimension (8×8 matrix).</summary>
	private const int StateDim = 8;

	// ========== Whirlpool S-box ==========
	/// <summary>
	/// The Whirlpool S-box. Unlike AES, Whirlpool uses its own dedicated S-box
	/// designed for optimal cryptographic properties in the 8×8 matrix structure.
	/// </summary>
	private static readonly byte[] SBox = [
		0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
		0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
		0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
		0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
		0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
		0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
		0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
		0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
		0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
		0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
		0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
		0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
		0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
		0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
		0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
		0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
	];

	// ========== T-Tables ==========
	// Pre-computed tables combining SubBytes, ShiftColumns, and MixRows.
	// Each table C[i] gives the contribution to the 8-byte column from S-box(x) at row i.
	// This is the standard Whirlpool optimization used in reference implementations.

	private static readonly ulong[] C0 = new ulong[256];
	private static readonly ulong[] C1 = new ulong[256];
	private static readonly ulong[] C2 = new ulong[256];
	private static readonly ulong[] C3 = new ulong[256];
	private static readonly ulong[] C4 = new ulong[256];
	private static readonly ulong[] C5 = new ulong[256];
	private static readonly ulong[] C6 = new ulong[256];
	private static readonly ulong[] C7 = new ulong[256];

	/// <summary>Round constants for the key schedule.</summary>
	private static readonly ulong[] RoundConstants = new ulong[Rounds + 1];

	// ========== Static Initialization ==========

	/// <summary>Reduction polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1.</summary>
	private const int ReductionPolynomial = 0x11d;

	/// <summary>
	/// Static constructor to initialize T-tables and round constants.
	/// </summary>
	static WhirlpoolDigest() {
		InitializeTables();
		InitializeRoundConstants();
	}

	/// <summary>
	/// GF(2^8) multiplication by x (polynomial shift with reduction).
	/// Uses the Whirlpool reduction polynomial 0x11d.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int MulX(int input) {
		return (input << 1) ^ (-(input >> 7) & ReductionPolynomial);
	}

	/// <summary>
	/// Pack 8 bytes into a 64-bit value (big-endian order).
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong PackIntoUInt64(int b7, int b6, int b5, int b4, int b3, int b2, int b1, int b0) {
		return ((ulong)b7 << 56) ^
			   ((ulong)b6 << 48) ^
			   ((ulong)b5 << 40) ^
			   ((ulong)b4 << 32) ^
			   ((ulong)b3 << 24) ^
			   ((ulong)b2 << 16) ^
			   ((ulong)b1 << 8) ^
			   (ulong)b0;
	}

	/// <summary>
	/// Initialize the T-tables using the same method as BouncyCastle's implementation.
	/// Each table C[i] combines SubBytes with the MDS matrix multiplication.
	/// The MDS coefficients are [1, 1, 4, 1, 8, 5, 2, 9] in GF(2^8).
	/// </summary>
	private static void InitializeTables() {
		for (int i = 0; i < 256; i++) {
			int v1 = SBox[i];
			int v2 = MulX(v1);
			int v4 = MulX(v2);
			int v5 = v4 ^ v1;
			int v8 = MulX(v4);
			int v9 = v8 ^ v1;

			// MDS matrix row: [1, 1, 4, 1, 8, 5, 2, 9]
			// Each C[i] table is a rotated version of C0
			C0[i] = PackIntoUInt64(v1, v1, v4, v1, v8, v5, v2, v9);
			C1[i] = PackIntoUInt64(v9, v1, v1, v4, v1, v8, v5, v2);
			C2[i] = PackIntoUInt64(v2, v9, v1, v1, v4, v1, v8, v5);
			C3[i] = PackIntoUInt64(v5, v2, v9, v1, v1, v4, v1, v8);
			C4[i] = PackIntoUInt64(v8, v5, v2, v9, v1, v1, v4, v1);
			C5[i] = PackIntoUInt64(v1, v8, v5, v2, v9, v1, v1, v4);
			C6[i] = PackIntoUInt64(v4, v1, v8, v5, v2, v9, v1, v1);
			C7[i] = PackIntoUInt64(v1, v4, v1, v8, v5, v2, v9, v1);
		}
	}

	/// <summary>
	/// Initialize round constants from T-tables.
	/// rc[r] is derived by extracting specific bytes from C0..C7 tables.
	/// </summary>
	private static void InitializeRoundConstants() {
		RoundConstants[0] = 0UL;
		for (int r = 1; r <= Rounds; r++) {
			int i = 8 * (r - 1);
			RoundConstants[r] =
				(C0[i] & 0xff00000000000000UL) ^
				(C1[i + 1] & 0x00ff000000000000UL) ^
				(C2[i + 2] & 0x0000ff0000000000UL) ^
				(C3[i + 3] & 0x000000ff00000000UL) ^
				(C4[i + 4] & 0x00000000ff000000UL) ^
				(C5[i + 5] & 0x0000000000ff0000UL) ^
				(C6[i + 6] & 0x000000000000ff00UL) ^
				(C7[i + 7] & 0x00000000000000ffUL);
		}
	}

	// ========== Instance State ==========

	/// <summary>Hash state (8 64-bit words representing 8×8 byte matrix).</summary>
	private readonly ulong[] _state = new ulong[StateDim];

	/// <summary>Block buffer for incomplete blocks.</summary>
	private readonly byte[] _buffer = new byte[BlockSizeBytes];

	/// <summary>Temporary state for round function.</summary>
	private readonly ulong[] _k = new ulong[StateDim]; // Key schedule state
	private readonly ulong[] _l = new ulong[StateDim]; // Temporary for key expansion
	private readonly ulong[] _block = new ulong[StateDim]; // Message block as 64-bit words
	private readonly ulong[] _tempState = new ulong[StateDim]; // Temporary state

	/// <summary>Current position in the buffer.</summary>
	private int _bufferPos;

	/// <summary>Total number of bits processed (for padding).</summary>
	private ulong _bitCount;

	/// <summary>Whether the hash has been finalized.</summary>
	private bool _finalized;

	// ========== IStreamingHashBytes Implementation ==========

	/// <inheritdoc/>
	public int DigestSize => DigestSizeBytes;

	/// <inheritdoc/>
	public int HashSize => DigestSizeBytes;

	/// <inheritdoc/>
	public int BlockSize => BlockSizeBytes;

	/// <inheritdoc/>
	public long TotalBytesProcessed => (long)(_bitCount / 8);

	/// <summary>
	/// Creates a new Whirlpool digest instance.
	/// </summary>
	public WhirlpoolDigest() {
		Reset();
	}

	/// <inheritdoc/>
	public void Reset() {
		Array.Clear(_state);
		Array.Clear(_buffer);
		Array.Clear(_k);
		Array.Clear(_l);
		Array.Clear(_block);
		Array.Clear(_tempState);
		_bufferPos = 0;
		_bitCount = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		if (_finalized) {
			throw new InvalidOperationException("Cannot update after finalization. Call Reset() first.");
		}

		int offset = 0;
		int length = data.Length;
		_bitCount += (ulong)length * 8;

		// If we have buffered data, try to complete a block
		if (_bufferPos > 0) {
			int toCopy = Math.Min(BlockSizeBytes - _bufferPos, length);
			data.Slice(offset, toCopy).CopyTo(_buffer.AsSpan(_bufferPos));
			_bufferPos += toCopy;
			offset += toCopy;
			length -= toCopy;

			if (_bufferPos == BlockSizeBytes) {
				ProcessBlock(_buffer);
				_bufferPos = 0;
			}
		}

		// Process full blocks directly
		while (length >= BlockSizeBytes) {
			ProcessBlock(data.Slice(offset, BlockSizeBytes));
			offset += BlockSizeBytes;
			length -= BlockSizeBytes;
		}

		// Buffer remaining bytes
		if (length > 0) {
			data.Slice(offset, length).CopyTo(_buffer.AsSpan(_bufferPos));
			_bufferPos += length;
		}
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		Update(data.AsSpan(offset, length));
	}

	/// <inheritdoc/>
	public byte[] Finalize() {
		if (_finalized) {
			throw new InvalidOperationException("Already finalized. Call Reset() first.");
		}
		_finalized = true;

		// Padding: append 1 bit, then zeros, then 256-bit length
		// We need at least 33 bytes for padding (1 byte for 0x80 + 32 bytes for length)
		_buffer[_bufferPos++] = 0x80;

		if (_bufferPos > BlockSizeBytes - 32) {
			// Not enough room for length, fill and process
			Array.Clear(_buffer, _bufferPos, BlockSizeBytes - _bufferPos);
			ProcessBlock(_buffer);
			_bufferPos = 0;
		}

		// Fill with zeros up to length field
		Array.Clear(_buffer, _bufferPos, BlockSizeBytes - 32 - _bufferPos);

		// Append 256-bit length (we only use 64 bits, but spec requires 256)
		// Upper 192 bits are zero, lower 64 bits contain bit count (big-endian)
		for (int i = BlockSizeBytes - 32; i < BlockSizeBytes - 8; i++) {
			_buffer[i] = 0;
		}

		// Write bit count as big-endian 64-bit value in last 8 bytes
		ulong bits = _bitCount;
		_buffer[BlockSizeBytes - 8] = (byte)(bits >> 56);
		_buffer[BlockSizeBytes - 7] = (byte)(bits >> 48);
		_buffer[BlockSizeBytes - 6] = (byte)(bits >> 40);
		_buffer[BlockSizeBytes - 5] = (byte)(bits >> 32);
		_buffer[BlockSizeBytes - 4] = (byte)(bits >> 24);
		_buffer[BlockSizeBytes - 3] = (byte)(bits >> 16);
		_buffer[BlockSizeBytes - 2] = (byte)(bits >> 8);
		_buffer[BlockSizeBytes - 1] = (byte)bits;

		ProcessBlock(_buffer);

		// Extract hash from state (big-endian)
		byte[] result = new byte[DigestSizeBytes];
		for (int i = 0; i < StateDim; i++) {
			ulong w = _state[i];
			result[i * 8 + 0] = (byte)(w >> 56);
			result[i * 8 + 1] = (byte)(w >> 48);
			result[i * 8 + 2] = (byte)(w >> 40);
			result[i * 8 + 3] = (byte)(w >> 32);
			result[i * 8 + 4] = (byte)(w >> 24);
			result[i * 8 + 5] = (byte)(w >> 16);
			result[i * 8 + 6] = (byte)(w >> 8);
			result[i * 8 + 7] = (byte)w;
		}

		return result;
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() => Finalize();

	/// <inheritdoc/>
	public void Dispose() {
		// Clear sensitive data
		Array.Clear(_state);
		Array.Clear(_buffer);
		Array.Clear(_k);
		Array.Clear(_l);
		Array.Clear(_block);
		Array.Clear(_tempState);
	}

	// ========== Block Processing ==========

	/// <summary>
	/// Process a single 512-bit block using the Miyaguchi-Preneel construction:
	/// H(i+1) = E(K=H(i), M) XOR H(i) XOR M
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Convert block to 8 64-bit words (big-endian)
		for (int i = 0; i < StateDim; i++) {
			int offset = i * 8;
			_block[i] = ((ulong)block[offset] << 56) |
						((ulong)block[offset + 1] << 48) |
						((ulong)block[offset + 2] << 40) |
						((ulong)block[offset + 3] << 32) |
						((ulong)block[offset + 4] << 24) |
						((ulong)block[offset + 5] << 16) |
						((ulong)block[offset + 6] << 8) |
						block[offset + 7];
		}

		// Initialize cipher state: K[0] = H (current hash state)
		// State[0] = K[0] XOR M
		for (int i = 0; i < StateDim; i++) {
			_k[i] = _state[i];
			_tempState[i] = _block[i] ^ _k[i];
		}

		// 10 rounds of the W cipher
		for (int r = 1; r <= Rounds; r++) {
			// Key expansion round
			KeyExpansionRound(r);

			// State transformation round
			StateRound();
		}

		// Miyaguchi-Preneel: H(i+1) = E(K, M) XOR H(i) XOR M
		for (int i = 0; i < StateDim; i++) {
			_state[i] ^= _tempState[i] ^ _block[i];
		}
	}

	/// <summary>
	/// Perform key expansion round: apply SubBytes, ShiftColumns, MixRows, AddRoundConstant.
	/// Uses T-tables for efficiency.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void KeyExpansionRound(int round) {
		// Apply T-table transformation to key state
		// For output column i, byte j comes from input column (i-j) & 7

		_l[0] = C0[(byte)(_k[0] >> 56)] ^ C1[(byte)(_k[7] >> 48)] ^ C2[(byte)(_k[6] >> 40)] ^ C3[(byte)(_k[5] >> 32)] ^
				C4[(byte)(_k[4] >> 24)] ^ C5[(byte)(_k[3] >> 16)] ^ C6[(byte)(_k[2] >> 8)] ^ C7[(byte)_k[1]];

		_l[1] = C0[(byte)(_k[1] >> 56)] ^ C1[(byte)(_k[0] >> 48)] ^ C2[(byte)(_k[7] >> 40)] ^ C3[(byte)(_k[6] >> 32)] ^
				C4[(byte)(_k[5] >> 24)] ^ C5[(byte)(_k[4] >> 16)] ^ C6[(byte)(_k[3] >> 8)] ^ C7[(byte)_k[2]];

		_l[2] = C0[(byte)(_k[2] >> 56)] ^ C1[(byte)(_k[1] >> 48)] ^ C2[(byte)(_k[0] >> 40)] ^ C3[(byte)(_k[7] >> 32)] ^
				C4[(byte)(_k[6] >> 24)] ^ C5[(byte)(_k[5] >> 16)] ^ C6[(byte)(_k[4] >> 8)] ^ C7[(byte)_k[3]];

		_l[3] = C0[(byte)(_k[3] >> 56)] ^ C1[(byte)(_k[2] >> 48)] ^ C2[(byte)(_k[1] >> 40)] ^ C3[(byte)(_k[0] >> 32)] ^
				C4[(byte)(_k[7] >> 24)] ^ C5[(byte)(_k[6] >> 16)] ^ C6[(byte)(_k[5] >> 8)] ^ C7[(byte)_k[4]];

		_l[4] = C0[(byte)(_k[4] >> 56)] ^ C1[(byte)(_k[3] >> 48)] ^ C2[(byte)(_k[2] >> 40)] ^ C3[(byte)(_k[1] >> 32)] ^
				C4[(byte)(_k[0] >> 24)] ^ C5[(byte)(_k[7] >> 16)] ^ C6[(byte)(_k[6] >> 8)] ^ C7[(byte)_k[5]];

		_l[5] = C0[(byte)(_k[5] >> 56)] ^ C1[(byte)(_k[4] >> 48)] ^ C2[(byte)(_k[3] >> 40)] ^ C3[(byte)(_k[2] >> 32)] ^
				C4[(byte)(_k[1] >> 24)] ^ C5[(byte)(_k[0] >> 16)] ^ C6[(byte)(_k[7] >> 8)] ^ C7[(byte)_k[6]];

		_l[6] = C0[(byte)(_k[6] >> 56)] ^ C1[(byte)(_k[5] >> 48)] ^ C2[(byte)(_k[4] >> 40)] ^ C3[(byte)(_k[3] >> 32)] ^
				C4[(byte)(_k[2] >> 24)] ^ C5[(byte)(_k[1] >> 16)] ^ C6[(byte)(_k[0] >> 8)] ^ C7[(byte)_k[7]];

		_l[7] = C0[(byte)(_k[7] >> 56)] ^ C1[(byte)(_k[6] >> 48)] ^ C2[(byte)(_k[5] >> 40)] ^ C3[(byte)(_k[4] >> 32)] ^
				C4[(byte)(_k[3] >> 24)] ^ C5[(byte)(_k[2] >> 16)] ^ C6[(byte)(_k[1] >> 8)] ^ C7[(byte)_k[0]];

		// Copy to _k and add round constant to first word only
		Array.Copy(_l, _k, StateDim);
		_k[0] ^= RoundConstants[round];
	}

	/// <summary>
	/// Perform state transformation round: apply SubBytes, ShiftColumns, MixRows, AddRoundKey.
	/// Uses T-tables for efficiency.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void StateRound() {
		ulong s0 = _tempState[0], s1 = _tempState[1], s2 = _tempState[2], s3 = _tempState[3];
		ulong s4 = _tempState[4], s5 = _tempState[5], s6 = _tempState[6], s7 = _tempState[7];

		// For output column i, byte j comes from input column (i-j) & 7
		// Add round key after T-table transformation

		_l[0] = C0[(byte)(s0 >> 56)] ^ C1[(byte)(s7 >> 48)] ^ C2[(byte)(s6 >> 40)] ^ C3[(byte)(s5 >> 32)] ^
				C4[(byte)(s4 >> 24)] ^ C5[(byte)(s3 >> 16)] ^ C6[(byte)(s2 >> 8)] ^ C7[(byte)s1];

		_l[1] = C0[(byte)(s1 >> 56)] ^ C1[(byte)(s0 >> 48)] ^ C2[(byte)(s7 >> 40)] ^ C3[(byte)(s6 >> 32)] ^
				C4[(byte)(s5 >> 24)] ^ C5[(byte)(s4 >> 16)] ^ C6[(byte)(s3 >> 8)] ^ C7[(byte)s2];

		_l[2] = C0[(byte)(s2 >> 56)] ^ C1[(byte)(s1 >> 48)] ^ C2[(byte)(s0 >> 40)] ^ C3[(byte)(s7 >> 32)] ^
				C4[(byte)(s6 >> 24)] ^ C5[(byte)(s5 >> 16)] ^ C6[(byte)(s4 >> 8)] ^ C7[(byte)s3];

		_l[3] = C0[(byte)(s3 >> 56)] ^ C1[(byte)(s2 >> 48)] ^ C2[(byte)(s1 >> 40)] ^ C3[(byte)(s0 >> 32)] ^
				C4[(byte)(s7 >> 24)] ^ C5[(byte)(s6 >> 16)] ^ C6[(byte)(s5 >> 8)] ^ C7[(byte)s4];

		_l[4] = C0[(byte)(s4 >> 56)] ^ C1[(byte)(s3 >> 48)] ^ C2[(byte)(s2 >> 40)] ^ C3[(byte)(s1 >> 32)] ^
				C4[(byte)(s0 >> 24)] ^ C5[(byte)(s7 >> 16)] ^ C6[(byte)(s6 >> 8)] ^ C7[(byte)s5];

		_l[5] = C0[(byte)(s5 >> 56)] ^ C1[(byte)(s4 >> 48)] ^ C2[(byte)(s3 >> 40)] ^ C3[(byte)(s2 >> 32)] ^
				C4[(byte)(s1 >> 24)] ^ C5[(byte)(s0 >> 16)] ^ C6[(byte)(s7 >> 8)] ^ C7[(byte)s6];

		_l[6] = C0[(byte)(s6 >> 56)] ^ C1[(byte)(s5 >> 48)] ^ C2[(byte)(s4 >> 40)] ^ C3[(byte)(s3 >> 32)] ^
				C4[(byte)(s2 >> 24)] ^ C5[(byte)(s1 >> 16)] ^ C6[(byte)(s0 >> 8)] ^ C7[(byte)s7];

		_l[7] = C0[(byte)(s7 >> 56)] ^ C1[(byte)(s6 >> 48)] ^ C2[(byte)(s5 >> 40)] ^ C3[(byte)(s4 >> 32)] ^
				C4[(byte)(s3 >> 24)] ^ C5[(byte)(s2 >> 16)] ^ C6[(byte)(s1 >> 8)] ^ C7[(byte)s0];

		// Copy to _tempState and XOR with round key
		_tempState[0] = _l[0] ^ _k[0];
		_tempState[1] = _l[1] ^ _k[1];
		_tempState[2] = _l[2] ^ _k[2];
		_tempState[3] = _l[3] ^ _k[3];
		_tempState[4] = _l[4] ^ _k[4];
		_tempState[5] = _l[5] ^ _k[5];
		_tempState[6] = _l[6] ^ _k[6];
		_tempState[7] = _l[7] ^ _k[7];
	}
}
