using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace StreamHash.Core;

/// <summary>
/// Native implementation of Streebog (GOST R 34.11-2012) hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// Streebog is the Russian federal standard for cryptographic hash functions,
/// defined in GOST R 34.11-2012. It supports two digest sizes: 256 and 512 bits.
/// </para>
/// <para>
/// The algorithm processes data in 512-bit (64-byte) blocks using a compression
/// function based on the Merkle-Damgård construction with an added checksum.
/// </para>
/// <para>
/// Reference: GOST R 34.11-2012 "Information technology. Cryptographic protection
/// of information. Hash function"
/// </para>
/// </remarks>
internal abstract class Streebog : IStreamingHashBytes {
	/// <summary>Block size in bytes (512 bits).</summary>
	protected const int BlockSizeBytes = 64;

	/// <summary>Current hash state (h).</summary>
	protected readonly ulong[] _h = new ulong[8];

	/// <summary>Checksum state (Σ).</summary>
	protected readonly ulong[] _sigma = new ulong[8];

	/// <summary>Message length counter (N).</summary>
	protected readonly ulong[] _n = new ulong[8];

	/// <summary>Partial block buffer.</summary>
	protected readonly byte[] _buffer = new byte[BlockSizeBytes];

	/// <summary>Current position in buffer.</summary>
	protected int _bufferPos;

	/// <summary>Total bytes processed.</summary>
	protected long _totalBytes;

	/// <summary>Digest size in bytes.</summary>
	protected readonly int _digestSize;

	/// <summary>Working arrays to avoid allocations.</summary>
	protected readonly ulong[] _tempM = new ulong[8];
	protected readonly ulong[] _tempK = new ulong[8];
	protected readonly ulong[] _tempT = new ulong[8];

	/// <summary>
	/// Creates a new Streebog instance.
	/// </summary>
	/// <param name="digestSize">Digest size in bytes (32 or 64).</param>
	protected Streebog(int digestSize) {
		_digestSize = digestSize;
		Reset();
	}

	/// <inheritdoc/>
	public int BlockSize => BlockSizeBytes;

	/// <inheritdoc/>
	public int DigestSize => _digestSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		_totalBytes += data.Length;
		int offset = 0;

		// Process partial buffer first
		if (_bufferPos > 0) {
			int needed = BlockSizeBytes - _bufferPos;
			if (data.Length < needed) {
				data.CopyTo(_buffer.AsSpan(_bufferPos));
				_bufferPos += data.Length;
				return;
			}
			data[..needed].CopyTo(_buffer.AsSpan(_bufferPos));
			ProcessBlock(_buffer);
			offset = needed;
			_bufferPos = 0;
		}

		// Process full blocks
		while (offset + BlockSizeBytes <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockSizeBytes));
			offset += BlockSizeBytes;
		}

		// Save remaining bytes
		if (offset < data.Length) {
			data[offset..].CopyTo(_buffer.AsSpan());
			_bufferPos = data.Length - offset;
		}
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		// Pad the message
		byte[] padded = new byte[BlockSizeBytes];
		_buffer.AsSpan(0, _bufferPos).CopyTo(padded);
		padded[_bufferPos] = 0x01;
		// Rest is already zeros

		// g(h, m) for padded block
		GCompress(_h, padded, _tempM, _tempK, _tempT);

		// Update N with final bit count
		ulong bitCount = (ulong)_totalBytes * 8;
		AddUlong(_n, bitCount);

		// Update Σ with final block
		AddBlock(_sigma, padded);

		// h = g(h, N)
		BytesToUlongs(_n, padded, 0);
		GCompress(_h, padded, _tempM, _tempK, _tempT);

		// h = g(h, Σ)
		BytesToUlongs(_sigma, padded, 0);
		GCompress(_h, padded, _tempM, _tempK, _tempT);

		// Output hash
		byte[] result = new byte[_digestSize];
		if (_digestSize == 32) {
			// 256-bit: take high 32 bytes
			for (int i = 0; i < 4; i++) {
				ulong val = _h[i + 4];
				for (int j = 0; j < 8; j++) {
					result[i * 8 + j] = (byte)(val >> (j * 8));
				}
			}
		} else {
			// 512-bit: take all 64 bytes
			for (int i = 0; i < 8; i++) {
				ulong val = _h[i];
				for (int j = 0; j < 8; j++) {
					result[i * 8 + j] = (byte)(val >> (j * 8));
				}
			}
		}

		return result;
	}

	/// <inheritdoc/>
	public abstract void Reset();

	/// <inheritdoc/>
	public void Dispose() {
		// Clear sensitive data
		Array.Clear(_h);
		Array.Clear(_sigma);
		Array.Clear(_n);
		Array.Clear(_buffer);
		Array.Clear(_tempM);
		Array.Clear(_tempK);
		Array.Clear(_tempT);
	}

	/// <summary>
	/// Processes a single 512-bit block.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		// Update N (add 512 bits)
		AddUlong(_n, 512);

		// Update Σ
		AddBlock(_sigma, block);

		// g compression
		GCompress(_h, block, _tempM, _tempK, _tempT);
	}

	/// <summary>
	/// The g compression function: h = h ⊕ LPS(h ⊕ m) ⊕ m
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GCompress(ulong[] h, ReadOnlySpan<byte> m, ulong[] mArr, ulong[] k, ulong[] t) {
		// Convert m to ulongs
		for (int i = 0; i < 8; i++) {
			mArr[i] = BitConverter.ToUInt64(m.Slice(i * 8, 8));
		}

		// K = h ⊕ N (but N is embedded in the call pattern)
		for (int i = 0; i < 8; i++) {
			k[i] = h[i];
		}

		// Initial XOR: K = LPS(K ⊕ m) for first round uses h directly
		for (int i = 0; i < 8; i++) {
			t[i] = k[i] ^ mArr[i];
		}
		LPS(t, k);

		// 12 rounds of compression
		for (int round = 0; round < 12; round++) {
			// K = K ⊕ C[round]
			for (int i = 0; i < 8; i++) {
				k[i] ^= RoundConstants[round, i];
			}
			LPS(k, t);
			Array.Copy(t, k, 8);
		}

		// h = k ⊕ h ⊕ m
		for (int i = 0; i < 8; i++) {
			h[i] ^= k[i] ^ mArr[i];
		}
	}

	/// <summary>
	/// LPS transformation: L(P(S(x)))
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LPS(ulong[] input, ulong[] output) {
		// Combined S-box and P-permutation via precomputed tables
		for (int i = 0; i < 8; i++) {
			output[i] = 0;
		}

		for (int i = 0; i < 8; i++) {
			ulong val = input[i];
			for (int j = 0; j < 8; j++) {
				int idx = (int)(val >> (j * 8)) & 0xff;
				output[j] ^= SBoxTransform[i * 256 + idx];
			}
		}
	}

	/// <summary>
	/// Adds a 64-bit value to the N counter (little-endian).
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddUlong(ulong[] n, ulong val) {
		ulong carry = val;
		for (int i = 0; i < 8 && carry != 0; i++) {
			ulong sum = n[i] + carry;
			carry = sum < n[i] ? 1UL : 0UL;
			n[i] = sum;
		}
	}

	/// <summary>
	/// Adds a block to the checksum Σ.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddBlock(ulong[] sigma, ReadOnlySpan<byte> block) {
		ulong carry = 0;
		for (int i = 0; i < 8; i++) {
			ulong val = BitConverter.ToUInt64(block.Slice(i * 8, 8));
			ulong sum = sigma[i] + val + carry;
			carry = (sum < sigma[i] || (carry != 0 && sum == sigma[i])) ? 1UL : 0UL;
			sigma[i] = sum;
		}
	}

	/// <summary>
	/// Converts ulong array to bytes (little-endian).
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void BytesToUlongs(ulong[] src, byte[] dest, int destOffset) {
		for (int i = 0; i < 8; i++) {
			ulong val = src[i];
			for (int j = 0; j < 8; j++) {
				dest[destOffset + i * 8 + j] = (byte)(val >> (j * 8));
			}
		}
	}

	#region Lookup Tables

	/// <summary>
	/// The Streebog S-box (Pi substitution).
	/// </summary>
	private static readonly byte[] SBox = [
		0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
		0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
		0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
		0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
		0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab, 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
		0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
		0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
		0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e, 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
		0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
		0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
		0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44, 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
		0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
		0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
		0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe, 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
		0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
		0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6
	];

	/// <summary>
	/// Linear transformation matrix A (for L transformation).
	/// Each row defines how to combine bytes for the output.
	/// </summary>
	private static readonly ulong[] LinearMatrix = [
		0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
		0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
		0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
		0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
		0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207f57b69,
		0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
		0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
		0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
		0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
		0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
		0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
		0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
		0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
		0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
		0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
		0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083
	];

	/// <summary>
	/// Combined S-box and linear transformation lookup table.
	/// This table combines the S-box substitution, permutation, and linear
	/// transformation into a single lookup for performance.
	/// </summary>
	private static readonly ulong[] SBoxTransform = GenerateSBoxTransform();

	/// <summary>
	/// Round constants C[i] for i = 0..11.
	/// </summary>
	private static readonly ulong[,] RoundConstants = GenerateRoundConstants();

	/// <summary>
	/// Generates the combined S-box and linear transformation table.
	/// </summary>
	private static ulong[] GenerateSBoxTransform() {
		ulong[] table = new ulong[8 * 256];

		for (int i = 0; i < 8; i++) {
			for (int j = 0; j < 256; j++) {
				// Apply S-box
				byte sboxOut = SBox[j];

				// Apply linear transformation for this position
				ulong result = 0;
				for (int bit = 0; bit < 8; bit++) {
					if ((sboxOut & (1 << bit)) != 0) {
						result ^= LinearMatrix[i * 8 + bit];
					}
				}

				table[i * 256 + j] = result;
			}
		}

		return table;
	}

	/// <summary>
	/// Generates the round constants C[0..11].
	/// </summary>
	private static ulong[,] GenerateRoundConstants() {
		ulong[,] constants = new ulong[12, 8];

		for (int round = 0; round < 12; round++) {
			byte[] temp = new byte[64];
			for (int i = 0; i < 64; i++) {
				temp[i] = (byte)(i * 8 + round);
			}

			// Apply LPS to get round constant
			ulong[] input = new ulong[8];
			ulong[] output = new ulong[8];

			for (int i = 0; i < 8; i++) {
				input[i] = BitConverter.ToUInt64(temp, i * 8);
			}

			LPS(input, output);

			for (int i = 0; i < 8; i++) {
				constants[round, i] = output[i];
			}
		}

		return constants;
	}

	#endregion
}

/// <summary>
/// Streebog-256 (GOST R 34.11-2012 with 256-bit output).
/// </summary>
internal sealed class Streebog256 : Streebog {
	/// <summary>
	/// Creates a new Streebog-256 instance.
	/// </summary>
	public Streebog256() : base(32) { }

	/// <inheritdoc/>
	public override void Reset() {
		// Initialize h with 0x01 for 256-bit output
		for (int i = 0; i < 8; i++) {
			_h[i] = 0x0101010101010101UL;
		}
		Array.Clear(_sigma);
		Array.Clear(_n);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
	}
}

/// <summary>
/// Streebog-512 (GOST R 34.11-2012 with 512-bit output).
/// </summary>
internal sealed class Streebog512 : Streebog {
	/// <summary>
	/// Creates a new Streebog-512 instance.
	/// </summary>
	public Streebog512() : base(64) { }

	/// <inheritdoc/>
	public override void Reset() {
		// Initialize h with 0x00 for 512-bit output
		Array.Clear(_h);
		Array.Clear(_sigma);
		Array.Clear(_n);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
	}
}

/// <summary>
/// Factory for creating Streebog hash instances.
/// </summary>
public static class StreebogFactory {
	/// <summary>
	/// Computes Streebog-256 hash of the given data.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 256-bit hash.</returns>
	public static byte[] ComputeStreebog256(ReadOnlySpan<byte> data) {
		using var hasher = new Streebog256();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Computes Streebog-512 hash of the given data.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 512-bit hash.</returns>
	public static byte[] ComputeStreebog512(ReadOnlySpan<byte> data) {
		using var hasher = new Streebog512();
		hasher.Update(data);
		return hasher.FinalizeBytes();
	}

	/// <summary>
	/// Creates a streaming Streebog-256 instance.
	/// </summary>
	public static IStreamingHashBytes CreateStreebog256() => new Streebog256();

	/// <summary>
	/// Creates a streaming Streebog-512 instance.
	/// </summary>
	public static IStreamingHashBytes CreateStreebog512() => new Streebog512();
}
