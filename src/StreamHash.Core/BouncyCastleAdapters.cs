using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace StreamHash.Core;

/// <summary>
/// Adapter wrapping BouncyCastle IDigest implementations as StreamHash <see cref="IStreamingHashBytes"/>.
/// </summary>
internal sealed class BouncyCastleAdapter : IStreamingHashBytes {
	private readonly IDigest _digest;
	private readonly int _digestSize;
	private readonly int _blockSize;
	private long _totalBytes;

	public BouncyCastleAdapter(IDigest digest) {
		_digest = digest ?? throw new ArgumentNullException(nameof(digest));
		_digestSize = digest.GetDigestSize();
		_blockSize = digest.GetByteLength();
	}

	public int BlockSize => _blockSize;
	public int DigestSize => _digestSize;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		// BouncyCastle supports Span in newer versions
		_digest.BlockUpdate(data);
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		byte[] result = new byte[_digestSize];
		_digest.DoFinal(result, 0);
		return result;
	}

	public void Reset() {
		_digest.Reset();
		_totalBytes = 0;
	}

	public void Dispose() {
		// BouncyCastle digests don't need disposal
	}
}

/// <summary>
/// Static factory for creating BouncyCastle digest wrappers.
/// </summary>
internal static class BouncyCastleFactory {
	// MD Family
	public static IStreamingHashBytes CreateMd2() => new BouncyCastleAdapter(new MD2Digest());
	public static IStreamingHashBytes CreateMd4() => new BouncyCastleAdapter(new MD4Digest());

	// SHA Family
	public static IStreamingHashBytes CreateSha224() => new BouncyCastleAdapter(new Sha224Digest());
	public static IStreamingHashBytes CreateSha512_224() => new BouncyCastleAdapter(new Sha512tDigest(224));
	public static IStreamingHashBytes CreateSha512_256() => new BouncyCastleAdapter(new Sha512tDigest(256));

	// SHA-3 Family - DEPRECATED: Use Sha3Factory instead for native SIMD performance
	/// <summary>Creates SHA3-224 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use Sha3Factory.CreateSha3_224() instead for native SIMD performance via dotSHA3")]
	public static IStreamingHashBytes CreateSha3_224() => new BouncyCastleAdapter(new Sha3Digest(224));

	/// <summary>Creates SHA3-256 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use Sha3Factory.CreateSha3_256() instead for native SIMD performance via dotSHA3")]
	public static IStreamingHashBytes CreateSha3_256() => new BouncyCastleAdapter(new Sha3Digest(256));

	/// <summary>Creates SHA3-384 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use Sha3Factory.CreateSha3_384() instead for native SIMD performance via dotSHA3")]
	public static IStreamingHashBytes CreateSha3_384() => new BouncyCastleAdapter(new Sha3Digest(384));

	/// <summary>Creates SHA3-512 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use Sha3Factory.CreateSha3_512() instead for native SIMD performance via dotSHA3")]
	public static IStreamingHashBytes CreateSha3_512() => new BouncyCastleAdapter(new Sha3Digest(512));

	// Keccak - DEPRECATED: Use AcryptohashnetFactory instead
	/// <summary>Creates Keccak-256 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use AcryptohashnetFactory.CreateKeccak256() instead for lower memory overhead")]
	public static IStreamingHashBytes CreateKeccak256() => new BouncyCastleAdapter(new KeccakDigest(256));

	/// <summary>Creates Keccak-512 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use AcryptohashnetFactory.CreateKeccak512() instead for lower memory overhead")]
	public static IStreamingHashBytes CreateKeccak512() => new BouncyCastleAdapter(new KeccakDigest(512));

	// BLAKE Family - DEPRECATED: Use Blake2Factory instead for 5-10x better performance
	/// <summary>Creates BLAKE2b-256 (BLAKE-256) using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use Blake2Factory.CreateBlake256() instead for 5-10x better performance via Blake2Fast")]
	public static IStreamingHashBytes CreateBlake256() => new BouncyCastleAdapter(new Blake2bDigest(256));

	/// <summary>Creates BLAKE2b-512 (BLAKE-512) using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use Blake2Factory.CreateBlake512() instead for 5-10x better performance via Blake2Fast")]
	public static IStreamingHashBytes CreateBlake512() => new BouncyCastleAdapter(new Blake2bDigest(512));

	/// <summary>Creates BLAKE2b-512 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use Blake2Factory.CreateBlake2b() instead for 5-10x better performance via Blake2Fast")]
	public static IStreamingHashBytes CreateBlake2b() => new BouncyCastleAdapter(new Blake2bDigest(512));

	/// <summary>Creates BLAKE2s-256 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use Blake2Factory.CreateBlake2s() instead for 5-10x better performance via Blake2Fast")]
	public static IStreamingHashBytes CreateBlake2s() => new BouncyCastleAdapter(new Blake2sDigest(256));

	/// <summary>
	/// Creates a BLAKE3 streaming hasher using BouncyCastle.
	/// </summary>
	/// <remarks>
	/// <para>
	/// <b>DEPRECATED:</b> Use <see cref="Blake3Factory.CreateBlake3"/> instead for
	/// significantly better performance (10-20x faster with native SIMD via Blake3.NET).
	/// </para>
	/// </remarks>
	[Obsolete("Use Blake3Factory.CreateBlake3() instead for 10-20x better performance via Blake3.NET")]
	public static IStreamingHashBytes CreateBlake3() => new BouncyCastleAdapter(new Blake3Digest(256));

	// RIPEMD Family - DEPRECATED for 128/160: Use AcryptohashnetFactory instead
	/// <summary>Creates RIPEMD-128 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use AcryptohashnetFactory.CreateRipemd128() instead for lower memory overhead")]
	public static IStreamingHashBytes CreateRipemd128() => new BouncyCastleAdapter(new RipeMD128Digest());

	/// <summary>Creates RIPEMD-160 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use AcryptohashnetFactory.CreateRipemd160() instead for lower memory overhead")]
	public static IStreamingHashBytes CreateRipemd160() => new BouncyCastleAdapter(new RipeMD160Digest());

	// RIPEMD-256 and RIPEMD-320 stay on BouncyCastle (not in acryptohashnet)
	public static IStreamingHashBytes CreateRipemd256() => new BouncyCastleAdapter(new RipeMD256Digest());
	public static IStreamingHashBytes CreateRipemd320() => new BouncyCastleAdapter(new RipeMD320Digest());

	// Other Crypto - Tiger DEPRECATED: Use AcryptohashnetFactory instead
	public static IStreamingHashBytes CreateWhirlpool() => new BouncyCastleAdapter(new Org.BouncyCastle.Crypto.Digests.WhirlpoolDigest());

	/// <summary>Creates Tiger-192 using BouncyCastle. DEPRECATED.</summary>
	[Obsolete("Use AcryptohashnetFactory.CreateTiger192() instead for lower memory overhead")]
	public static IStreamingHashBytes CreateTiger192() => new BouncyCastleAdapter(new TigerDigest());

	public static IStreamingHashBytes CreateGost94() => new BouncyCastleAdapter(new Gost3411Digest());
	public static IStreamingHashBytes CreateStreebog256() => new BouncyCastleAdapter(new Gost3411_2012_256Digest());
	public static IStreamingHashBytes CreateStreebog512() => new BouncyCastleAdapter(new Gost3411_2012_512Digest());
	public static IStreamingHashBytes CreateSkein256() => new BouncyCastleAdapter(new SkeinDigest(256, 256));
	public static IStreamingHashBytes CreateSkein512() => new BouncyCastleAdapter(new SkeinDigest(512, 512));
	public static IStreamingHashBytes CreateSkein1024() => new BouncyCastleAdapter(new SkeinDigest(1024, 1024));
	public static IStreamingHashBytes CreateSm3() => new BouncyCastleAdapter(new SM3Digest());

	// SHA-0 uses custom implementation (not in BouncyCastle)
	public static IStreamingHashBytes CreateSha0() => new Sha0StreamingHash();

	// Groestl - custom implementations (not available in BouncyCastle)
	public static IStreamingHashBytes CreateGroestl256() => new Groestl256();
	public static IStreamingHashBytes CreateGroestl512() => new Groestl512();

	// JH - custom implementations (not available in BouncyCastle)
	public static IStreamingHashBytes CreateJh256() => new JH256();
	public static IStreamingHashBytes CreateJh512() => new JH512();

	/// <summary>
	/// Computes hash using a BouncyCastle digest in one shot.
	/// </summary>
	public static byte[] ComputeHash(IDigest digest, ReadOnlySpan<byte> data) {
		digest.BlockUpdate(data);
		byte[] result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return result;
	}
}

/// <summary>
/// SHA-0 streaming hash implementation.
/// SHA-0 is the original SHA algorithm (FIPS 180) without the rotation in message expansion.
/// Note: SHA-0 is cryptographically broken and should never be used for security.
/// </summary>
internal sealed class Sha0StreamingHash : IStreamingHashBytes {
	private const int DigestLength = 20;
	private const int BlockLength = 64;

	// State variables (same initial values as SHA-1)
	private uint _h0 = 0x67452301;
	private uint _h1 = 0xefcdab89;
	private uint _h2 = 0x98badcfe;
	private uint _h3 = 0x10325476;
	private uint _h4 = 0xc3d2e1f0;

	private readonly byte[] _buffer = new byte[BlockLength];
	private int _bufferOffset;
	private long _totalBytes;

	public int BlockSize => BlockLength;
	public int DigestSize => DigestLength;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		_totalBytes += data.Length;
		int offset = 0;

		// If we have data in the buffer, fill it first
		if (_bufferOffset > 0) {
			int toCopy = Math.Min(BlockLength - _bufferOffset, data.Length);
			data.Slice(0, toCopy).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += toCopy;
			offset += toCopy;

			if (_bufferOffset == BlockLength) {
				ProcessBlock(_buffer);
				_bufferOffset = 0;
			}
		}

		// Process complete blocks directly
		while (offset + BlockLength <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockLength));
			offset += BlockLength;
		}

		// Copy remaining data to buffer
		if (offset < data.Length) {
			data.Slice(offset).CopyTo(_buffer.AsSpan(_bufferOffset));
			_bufferOffset += data.Length - offset;
		}
	}

	public byte[] FinalizeBytes() {
		// Padding
		long bitLength = _totalBytes * 8;
		int paddingLength = (BlockLength - 9 - _bufferOffset % BlockLength + BlockLength) % BlockLength + 1;

		Span<byte> padding = stackalloc byte[paddingLength + 8];
		padding[0] = 0x80;
		padding.Slice(1, paddingLength - 1).Clear();

		// Big-endian bit length
		for (int i = 0; i < 8; i++) {
			padding[paddingLength + i] = (byte)(bitLength >> (56 - i * 8));
		}

		Update(padding);

		// Output hash
		byte[] result = new byte[DigestLength];
		WriteUInt32BE(_h0, result, 0);
		WriteUInt32BE(_h1, result, 4);
		WriteUInt32BE(_h2, result, 8);
		WriteUInt32BE(_h3, result, 12);
		WriteUInt32BE(_h4, result, 16);

		return result;
	}

	public void Reset() {
		_h0 = 0x67452301;
		_h1 = 0xefcdab89;
		_h2 = 0x98badcfe;
		_h3 = 0x10325476;
		_h4 = 0xc3d2e1f0;
		_bufferOffset = 0;
		_totalBytes = 0;
		Array.Clear(_buffer);
	}

	public void Dispose() {
		// Clear sensitive data
		Array.Clear(_buffer);
	}

	private void ProcessBlock(ReadOnlySpan<byte> block) {
		Span<uint> w = stackalloc uint[80];

		// Load message into first 16 words
		for (int i = 0; i < 16; i++) {
			w[i] = ReadUInt32BE(block, i * 4);
		}

		// SHA-0 expansion: NO rotation (unlike SHA-1 which rotates by 1)
		for (int i = 16; i < 80; i++) {
			w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
			// SHA-1 would do: w[i] = RotateLeft(w[i], 1);
		}

		uint a = _h0, b = _h1, c = _h2, d = _h3, e = _h4;

		// Main loop
		for (int i = 0; i < 20; i++) {
			uint f = (b & c) | (~b & d);
			uint temp = RotateLeft(a, 5) + f + e + 0x5a827999 + w[i];
			e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
		}

		for (int i = 20; i < 40; i++) {
			uint f = b ^ c ^ d;
			uint temp = RotateLeft(a, 5) + f + e + 0x6ed9eba1 + w[i];
			e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
		}

		for (int i = 40; i < 60; i++) {
			uint f = (b & c) | (b & d) | (c & d);
			uint temp = RotateLeft(a, 5) + f + e + 0x8f1bbcdc + w[i];
			e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
		}

		for (int i = 60; i < 80; i++) {
			uint f = b ^ c ^ d;
			uint temp = RotateLeft(a, 5) + f + e + 0xca62c1d6 + w[i];
			e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
		}

		_h0 += a; _h1 += b; _h2 += c; _h3 += d; _h4 += e;
	}

	private static uint RotateLeft(uint x, int n) => (x << n) | (x >> (32 - n));
	private static uint ReadUInt32BE(ReadOnlySpan<byte> data, int offset) =>
		((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) | ((uint)data[offset + 2] << 8) | data[offset + 3];
	private static void WriteUInt32BE(uint value, byte[] data, int offset) {
		data[offset] = (byte)(value >> 24);
		data[offset + 1] = (byte)(value >> 16);
		data[offset + 2] = (byte)(value >> 8);
		data[offset + 3] = (byte)value;
	}
}
