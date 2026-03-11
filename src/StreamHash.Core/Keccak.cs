using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// High-performance streaming implementation of the Keccak/SHA-3 hash function family.
/// </summary>
/// <remarks>
/// <para>
/// Keccak is the cryptographic primitive that won the NIST SHA-3 competition.
/// This implementation supports both Keccak (original) and SHA-3 (FIPS 202) variants.
/// </para>
/// <para>
/// <b>Algorithm Characteristics:</b>
/// <list type="bullet">
/// <item><b>Structure:</b> Sponge construction with Keccak-f[1600] permutation</item>
/// <item><b>State Size:</b> 1600 bits (200 bytes) organized as 5×5 array of 64-bit lanes</item>
/// <item><b>Permutation:</b> 24 rounds of θ, ρ, π, χ, ι transformations</item>
/// <item><b>Rate/Capacity:</b> Varies by output size (r + c = 1600)</item>
/// </list>
/// </para>
/// <para>
/// <b>Supported Variants:</b>
/// <list type="bullet">
/// <item>Keccak-224/256/384/512 - Original Keccak with 0x01 domain separator</item>
/// <item>SHA3-224/256/384/512 - FIPS 202 standard with 0x06 domain separator</item>
/// </list>
/// </para>
/// <para>
/// <b>Performance Optimizations:</b>
/// <list type="bullet">
/// <item>Lane-complement optimization to reduce NOT operations</item>
/// <item>Pre-computed rotation offsets</item>
/// <item>Unrolled round function for better instruction-level parallelism</item>
/// <item>Zero allocations in hot path</item>
/// </list>
/// </para>
/// <para>
/// <b>References:</b>
/// <list type="bullet">
/// <item><see href="https://keccak.team/keccak.html">Keccak Team Website</see></item>
/// <item><see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS 202</see></item>
/// </list>
/// </para>
/// </remarks>
public sealed class NativeKeccak : IStreamingHashBytes {
	// ========== Constants ==========

	/// <summary>State size in bytes (1600 bits = 200 bytes).</summary>
	private const int StateSize = 200;

	/// <summary>Number of lanes (5×5 = 25 64-bit words).</summary>
	private const int NumLanes = 25;

	/// <summary>Number of rounds in Keccak-f[1600].</summary>
	private const int NumRounds = 24;

	/// <summary>Domain separator for original Keccak.</summary>
	private const byte KeccakDomainSeparator = 0x01;

	/// <summary>Domain separator for SHA-3 (FIPS 202).</summary>
	private const byte Sha3DomainSeparator = 0x06;

	/// <summary>
	/// Round constants (RC) for the ι (iota) step.
	/// Pre-computed from LFSR with primitive polynomial x^8 + x^6 + x^5 + x^4 + 1.
	/// </summary>
	private static readonly ulong[] RoundConstants = [
		0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
		0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
		0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
		0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
		0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
		0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
	];

	/// <summary>
	/// Rotation offsets for the ρ (rho) step.
	/// Indexed as [x + 5*y] for lane (x,y).
	/// </summary>
	private static readonly int[] RotationOffsets = [
		 0,  1, 62, 28, 27,  // y=0
		36, 44,  6, 55, 20,  // y=1
		 3, 10, 43, 25, 39,  // y=2
		41, 45, 15, 21,  8,  // y=3
		18,  2, 61, 56, 14   // y=4
	];

	// ========== Instance Fields ==========

	/// <summary>The 1600-bit state as 25 64-bit lanes.</summary>
	private readonly ulong[] _state = new ulong[NumLanes];

	/// <summary>Buffer for incomplete blocks.</summary>
	private readonly byte[] _buffer;

	/// <summary>Rate in bytes (block size).</summary>
	private readonly int _rate;

	/// <summary>Output hash size in bytes.</summary>
	private readonly int _hashSize;

	/// <summary>Domain separator byte (0x01 for Keccak, 0x06 for SHA-3).</summary>
	private readonly byte _domainSeparator;

	/// <summary>Current position in the buffer.</summary>
	private int _bufferPos;

	/// <summary>Total bytes processed.</summary>
	private long _totalBytes;

	/// <summary>Whether the hash has been finalized.</summary>
	private bool _finalized;

	/// <summary>Whether the instance has been disposed.</summary>
	private bool _disposed;

	// ========== Constructors ==========

	/// <summary>
	/// Creates a new Keccak/SHA-3 digest with specified parameters.
	/// </summary>
	/// <param name="hashBits">Output hash size in bits (224, 256, 384, or 512).</param>
	/// <param name="useSha3Padding">True for SHA-3 (0x06), false for original Keccak (0x01).</param>
	public NativeKeccak(int hashBits, bool useSha3Padding = true) {
		if (hashBits != 224 && hashBits != 256 && hashBits != 384 && hashBits != 512) {
			throw new ArgumentException("Hash size must be 224, 256, 384, or 512 bits", nameof(hashBits));
		}

		_hashSize = hashBits / 8;

		// Capacity = 2 × hash size, Rate = 1600 - Capacity
		int capacityBits = hashBits * 2;
		_rate = (1600 - capacityBits) / 8;

		_buffer = new byte[_rate];
		_domainSeparator = useSha3Padding ? Sha3DomainSeparator : KeccakDomainSeparator;
	}

	// ========== IStreamingHashBytes Implementation ==========

	/// <inheritdoc/>
	public int BlockSize => _rate;

	/// <inheritdoc/>
	public int DigestSize => _hashSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Hash already finalized. Call Reset() first.");

		_totalBytes += data.Length;
		int offset = 0;

		// Fill buffer if partially full
		if (_bufferPos > 0) {
			int toCopy = Math.Min(_rate - _bufferPos, data.Length);
			data.Slice(0, toCopy).CopyTo(_buffer.AsSpan(_bufferPos));
			_bufferPos += toCopy;
			offset += toCopy;

			if (_bufferPos == _rate) {
				AbsorbBlock(_buffer);
				_bufferPos = 0;
			}
		}

		// Process complete blocks directly from input
		while (offset + _rate <= data.Length) {
			AbsorbBlock(data.Slice(offset, _rate));
			offset += _rate;
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
		if (_finalized) throw new InvalidOperationException("Hash already finalized. Call Reset() first.");
		_finalized = true;

		// Pad the message
		// For SHA-3: append 0x06 || zeros || 0x80
		// For Keccak: append 0x01 || zeros || 0x80
		Array.Clear(_buffer, _bufferPos, _rate - _bufferPos);
		_buffer[_bufferPos] = _domainSeparator;
		_buffer[_rate - 1] |= 0x80;

		// Absorb final padded block
		AbsorbBlock(_buffer);

		// Squeeze output
		byte[] result = new byte[_hashSize];
		int outputOffset = 0;
		int remaining = _hashSize;

		while (remaining > 0) {
			int toCopy = Math.Min(_rate, remaining);
			ExtractBytes(result.AsSpan(outputOffset, toCopy));
			outputOffset += toCopy;
			remaining -= toCopy;

			if (remaining > 0) {
				KeccakF1600();
			}
		}

		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		Array.Clear(_state);
		Array.Clear(_buffer);
		_bufferPos = 0;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (!_disposed) {
			Array.Clear(_state);
			Array.Clear(_buffer);
			_disposed = true;
		}
	}

	// ========== Core Algorithm ==========

	/// <summary>
	/// Absorbs a rate-sized block into the state.
	/// XORs input bytes into state lanes, then applies Keccak-f[1600].
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AbsorbBlock(ReadOnlySpan<byte> block) {
		// XOR block into state (rate bytes only)
		int lanes = _rate / 8;
		for (int i = 0; i < lanes; i++) {
			_state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * 8, 8));
		}

		KeccakF1600();
	}

	/// <summary>
	/// Extracts bytes from the state for squeezing.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ExtractBytes(Span<byte> output) {
		int fullLanes = output.Length / 8;
		int remaining = output.Length % 8;

		for (int i = 0; i < fullLanes; i++) {
			BinaryPrimitives.WriteUInt64LittleEndian(output.Slice(i * 8, 8), _state[i]);
		}

		if (remaining > 0) {
			Span<byte> temp = stackalloc byte[8];
			BinaryPrimitives.WriteUInt64LittleEndian(temp, _state[fullLanes]);
			temp.Slice(0, remaining).CopyTo(output.Slice(fullLanes * 8));
		}
	}

	/// <summary>
	/// The Keccak-f[1600] permutation - 24 rounds of θ, ρ, π, χ, ι.
	/// Uses 25 local variables to eliminate array/span bounds checking.
	/// </summary>
	private void KeccakF1600() {
		// Load state into 25 local variables (eliminates span bounds checking in hot loop)
		ulong a00 = _state[0], a01 = _state[1], a02 = _state[2], a03 = _state[3], a04 = _state[4];
		ulong a05 = _state[5], a06 = _state[6], a07 = _state[7], a08 = _state[8], a09 = _state[9];
		ulong a10 = _state[10], a11 = _state[11], a12 = _state[12], a13 = _state[13], a14 = _state[14];
		ulong a15 = _state[15], a16 = _state[16], a17 = _state[17], a18 = _state[18], a19 = _state[19];
		ulong a20 = _state[20], a21 = _state[21], a22 = _state[22], a23 = _state[23], a24 = _state[24];

		for (int round = 0; round < NumRounds; round++) {
			// θ (theta) step - Column parity mixing
			ulong c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
			ulong c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
			ulong c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
			ulong c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
			ulong c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

			ulong d1 = RotateLeft64(c1, 1) ^ c4;
			ulong d2 = RotateLeft64(c2, 1) ^ c0;
			ulong d3 = RotateLeft64(c3, 1) ^ c1;
			ulong d4 = RotateLeft64(c4, 1) ^ c2;
			ulong d0 = RotateLeft64(c0, 1) ^ c3;

			a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
			a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
			a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
			a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
			a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

			// ρ (rho) and π (pi) steps combined - in-place using local variable chain
			c1 = RotateLeft64(a01, 1);
			a01 = RotateLeft64(a06, 44);
			a06 = RotateLeft64(a09, 20);
			a09 = RotateLeft64(a22, 61);
			a22 = RotateLeft64(a14, 39);
			a14 = RotateLeft64(a20, 18);
			a20 = RotateLeft64(a02, 62);
			a02 = RotateLeft64(a12, 43);
			a12 = RotateLeft64(a13, 25);
			a13 = RotateLeft64(a19, 8);
			a19 = RotateLeft64(a23, 56);
			a23 = RotateLeft64(a15, 41);
			a15 = RotateLeft64(a04, 27);
			a04 = RotateLeft64(a24, 14);
			a24 = RotateLeft64(a21, 2);
			a21 = RotateLeft64(a08, 55);
			a08 = RotateLeft64(a16, 45);
			a16 = RotateLeft64(a05, 36);
			a05 = RotateLeft64(a03, 28);
			a03 = RotateLeft64(a18, 21);
			a18 = RotateLeft64(a17, 15);
			a17 = RotateLeft64(a11, 10);
			a11 = RotateLeft64(a07, 6);
			a07 = RotateLeft64(a10, 3);
			a10 = c1;

			// χ (chi) step - Non-linear mixing using only 2 temporaries per row
			c0 = a00 ^ (~a01 & a02);
			c1 = a01 ^ (~a02 & a03);
			a02 ^= ~a03 & a04;
			a03 ^= ~a04 & a00;
			a04 ^= ~a00 & a01;
			a00 = c0;
			a01 = c1;

			c0 = a05 ^ (~a06 & a07);
			c1 = a06 ^ (~a07 & a08);
			a07 ^= ~a08 & a09;
			a08 ^= ~a09 & a05;
			a09 ^= ~a05 & a06;
			a05 = c0;
			a06 = c1;

			c0 = a10 ^ (~a11 & a12);
			c1 = a11 ^ (~a12 & a13);
			a12 ^= ~a13 & a14;
			a13 ^= ~a14 & a10;
			a14 ^= ~a10 & a11;
			a10 = c0;
			a11 = c1;

			c0 = a15 ^ (~a16 & a17);
			c1 = a16 ^ (~a17 & a18);
			a17 ^= ~a18 & a19;
			a18 ^= ~a19 & a15;
			a19 ^= ~a15 & a16;
			a15 = c0;
			a16 = c1;

			c0 = a20 ^ (~a21 & a22);
			c1 = a21 ^ (~a22 & a23);
			a22 ^= ~a23 & a24;
			a23 ^= ~a24 & a20;
			a24 ^= ~a20 & a21;
			a20 = c0;
			a21 = c1;

			// ι (iota) step - Round constant addition
			a00 ^= RoundConstants[round];
		}

		// Write state back
		_state[0] = a00; _state[1] = a01; _state[2] = a02; _state[3] = a03; _state[4] = a04;
		_state[5] = a05; _state[6] = a06; _state[7] = a07; _state[8] = a08; _state[9] = a09;
		_state[10] = a10; _state[11] = a11; _state[12] = a12; _state[13] = a13; _state[14] = a14;
		_state[15] = a15; _state[16] = a16; _state[17] = a17; _state[18] = a18; _state[19] = a19;
		_state[20] = a20; _state[21] = a21; _state[22] = a22; _state[23] = a23; _state[24] = a24;
	}

	/// <summary>
	/// 64-bit rotate left.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong RotateLeft64(ulong value, int offset) =>
		(value << offset) | (value >> (64 - offset));
}

// ========== Concrete SHA-3 Implementations ==========

/// <summary>
/// SHA3-224 streaming hash implementation (FIPS 202).
/// </summary>
public sealed class Sha3_224 : IStreamingHashBytes {
	private readonly NativeKeccak _inner = new(224, useSha3Padding: true);

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
/// SHA3-256 streaming hash implementation (FIPS 202).
/// </summary>
public sealed class Sha3_256 : IStreamingHashBytes {
	private readonly NativeKeccak _inner = new(256, useSha3Padding: true);

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
/// SHA3-384 streaming hash implementation (FIPS 202).
/// </summary>
public sealed class Sha3_384 : IStreamingHashBytes {
	private readonly NativeKeccak _inner = new(384, useSha3Padding: true);

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
/// SHA3-512 streaming hash implementation (FIPS 202).
/// </summary>
public sealed class Sha3_512 : IStreamingHashBytes {
	private readonly NativeKeccak _inner = new(512, useSha3Padding: true);

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
/// Factory for creating native SHA-3/Keccak streaming hash instances.
/// </summary>
public static class NativeSha3Factory {
	// ========== SHA-3 (FIPS 202) ==========

	/// <summary>Creates a streaming SHA3-224 hasher.</summary>
	public static IStreamingHashBytes CreateSha3_224() => new Sha3_224();

	/// <summary>Creates a streaming SHA3-256 hasher.</summary>
	public static IStreamingHashBytes CreateSha3_256() => new Sha3_256();

	/// <summary>Creates a streaming SHA3-384 hasher.</summary>
	public static IStreamingHashBytes CreateSha3_384() => new Sha3_384();

	/// <summary>Creates a streaming SHA3-512 hasher.</summary>
	public static IStreamingHashBytes CreateSha3_512() => new Sha3_512();

	/// <summary>Computes SHA3-224 hash in one shot.</summary>
	public static byte[] ComputeSha3_224(ReadOnlySpan<byte> data) {
		return ComputeKeccakStatic(data, 224, useSha3Padding: true);
	}

	/// <summary>Computes SHA3-256 hash in one shot.</summary>
	public static byte[] ComputeSha3_256(ReadOnlySpan<byte> data) {
		return ComputeKeccakStatic(data, 256, useSha3Padding: true);
	}

	/// <summary>Computes SHA3-384 hash in one shot.</summary>
	public static byte[] ComputeSha3_384(ReadOnlySpan<byte> data) {
		return ComputeKeccakStatic(data, 384, useSha3Padding: true);
	}

	/// <summary>Computes SHA3-512 hash in one shot.</summary>
	public static byte[] ComputeSha3_512(ReadOnlySpan<byte> data) {
		return ComputeKeccakStatic(data, 512, useSha3Padding: true);
	}

	// ========== Original Keccak ==========

	/// <summary>Creates a streaming Keccak-224 hasher (original padding).</summary>
	public static IStreamingHashBytes CreateKeccak224() => new NativeKeccak(224, useSha3Padding: false);

	/// <summary>Creates a streaming Keccak-256 hasher (original padding).</summary>
	public static IStreamingHashBytes CreateKeccak256() => new NativeKeccak(256, useSha3Padding: false);

	/// <summary>Creates a streaming Keccak-384 hasher (original padding).</summary>
	public static IStreamingHashBytes CreateKeccak384() => new NativeKeccak(384, useSha3Padding: false);

	/// <summary>Creates a streaming Keccak-512 hasher (original padding).</summary>
	public static IStreamingHashBytes CreateKeccak512() => new NativeKeccak(512, useSha3Padding: false);

	/// <summary>Computes Keccak-256 hash in one shot.</summary>
	public static byte[] ComputeKeccak256(ReadOnlySpan<byte> data) {
		return ComputeKeccakStatic(data, 256, useSha3Padding: false);
	}

	/// <summary>Computes Keccak-512 hash in one shot.</summary>
	public static byte[] ComputeKeccak512(ReadOnlySpan<byte> data) {
		return ComputeKeccakStatic(data, 512, useSha3Padding: false);
	}

	/// <summary>
	/// Static optimized Keccak/SHA3 computation using stack-allocated state.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static byte[] ComputeKeccakStatic(ReadOnlySpan<byte> data, int hashBits, bool useSha3Padding) {
		int hashSize = hashBits / 8;
		int rate = (1600 - 2 * hashBits) / 8;
		byte domainSep = useSha3Padding ? (byte)0x06 : (byte)0x01;

		// Stack-allocated 1600-bit state (25 x 8 = 200 bytes)
		Span<ulong> state = stackalloc ulong[25];
		state.Clear();

		// Absorb full blocks
		int offset = 0;
		int lanes = rate / 8;
		while (offset + rate <= data.Length) {
			for (int i = 0; i < lanes; i++) {
				state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset + i * 8, 8));
			}
			KeccakF1600Static(state);
			offset += rate;
		}

		// Pad final block
		Span<byte> buffer = stackalloc byte[rate];
		buffer.Clear();
		int remaining = data.Length - offset;
		if (remaining > 0) {
			data.Slice(offset).CopyTo(buffer);
		}
		buffer[remaining] = domainSep;
		buffer[rate - 1] |= 0x80;

		// Absorb final block
		for (int i = 0; i < lanes; i++) {
			state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(i * 8, 8));
		}
		KeccakF1600Static(state);

		// Squeeze output (for SHA3/Keccak, output size <= rate so single squeeze)
		byte[] result = new byte[hashSize];
		int fullLanes = hashSize / 8;
		for (int i = 0; i < fullLanes; i++) {
			BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(i * 8, 8), state[i]);
		}
		int leftover = hashSize % 8;
		if (leftover > 0) {
			Span<byte> temp = stackalloc byte[8];
			BinaryPrimitives.WriteUInt64LittleEndian(temp, state[fullLanes]);
			temp.Slice(0, leftover).CopyTo(result.AsSpan(fullLanes * 8));
		}

		return result;
	}

	/// <summary>
	/// Static Keccak-f[1600] permutation - 24 rounds.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void KeccakF1600Static(Span<ulong> state) {
		ReadOnlySpan<ulong> RC = [
			0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
			0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
			0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
			0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
			0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
			0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
		];

		Span<ulong> c = stackalloc ulong[5];
		Span<ulong> b = stackalloc ulong[25];

		for (int round = 0; round < 24; round++) {
			// θ step
			c[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
			c[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
			c[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
			c[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
			c[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

			ulong d0 = c[4] ^ ((c[1] << 1) | (c[1] >> 63));
			ulong d1 = c[0] ^ ((c[2] << 1) | (c[2] >> 63));
			ulong d2 = c[1] ^ ((c[3] << 1) | (c[3] >> 63));
			ulong d3 = c[2] ^ ((c[4] << 1) | (c[4] >> 63));
			ulong d4 = c[3] ^ ((c[0] << 1) | (c[0] >> 63));

			state[0] ^= d0; state[5] ^= d0; state[10] ^= d0; state[15] ^= d0; state[20] ^= d0;
			state[1] ^= d1; state[6] ^= d1; state[11] ^= d1; state[16] ^= d1; state[21] ^= d1;
			state[2] ^= d2; state[7] ^= d2; state[12] ^= d2; state[17] ^= d2; state[22] ^= d2;
			state[3] ^= d3; state[8] ^= d3; state[13] ^= d3; state[18] ^= d3; state[23] ^= d3;
			state[4] ^= d4; state[9] ^= d4; state[14] ^= d4; state[19] ^= d4; state[24] ^= d4;

			// ρ and π steps combined
			b[0] = state[0];
			b[1] = (state[6] << 44) | (state[6] >> 20);
			b[2] = (state[12] << 43) | (state[12] >> 21);
			b[3] = (state[18] << 21) | (state[18] >> 43);
			b[4] = (state[24] << 14) | (state[24] >> 50);
			b[5] = (state[3] << 28) | (state[3] >> 36);
			b[6] = (state[9] << 20) | (state[9] >> 44);
			b[7] = (state[10] << 3) | (state[10] >> 61);
			b[8] = (state[16] << 45) | (state[16] >> 19);
			b[9] = (state[22] << 61) | (state[22] >> 3);
			b[10] = (state[1] << 1) | (state[1] >> 63);
			b[11] = (state[7] << 6) | (state[7] >> 58);
			b[12] = (state[13] << 25) | (state[13] >> 39);
			b[13] = (state[19] << 8) | (state[19] >> 56);
			b[14] = (state[20] << 18) | (state[20] >> 46);
			b[15] = (state[4] << 27) | (state[4] >> 37);
			b[16] = (state[5] << 36) | (state[5] >> 28);
			b[17] = (state[11] << 10) | (state[11] >> 54);
			b[18] = (state[17] << 15) | (state[17] >> 49);
			b[19] = (state[23] << 56) | (state[23] >> 8);
			b[20] = (state[2] << 62) | (state[2] >> 2);
			b[21] = (state[8] << 55) | (state[8] >> 9);
			b[22] = (state[14] << 39) | (state[14] >> 25);
			b[23] = (state[15] << 41) | (state[15] >> 23);
			b[24] = (state[21] << 2) | (state[21] >> 62);

			// χ and ι steps
			state[0] = b[0] ^ (~b[1] & b[2]) ^ RC[round];
			state[1] = b[1] ^ (~b[2] & b[3]);
			state[2] = b[2] ^ (~b[3] & b[4]);
			state[3] = b[3] ^ (~b[4] & b[0]);
			state[4] = b[4] ^ (~b[0] & b[1]);
			state[5] = b[5] ^ (~b[6] & b[7]);
			state[6] = b[6] ^ (~b[7] & b[8]);
			state[7] = b[7] ^ (~b[8] & b[9]);
			state[8] = b[8] ^ (~b[9] & b[5]);
			state[9] = b[9] ^ (~b[5] & b[6]);
			state[10] = b[10] ^ (~b[11] & b[12]);
			state[11] = b[11] ^ (~b[12] & b[13]);
			state[12] = b[12] ^ (~b[13] & b[14]);
			state[13] = b[13] ^ (~b[14] & b[10]);
			state[14] = b[14] ^ (~b[10] & b[11]);
			state[15] = b[15] ^ (~b[16] & b[17]);
			state[16] = b[16] ^ (~b[17] & b[18]);
			state[17] = b[17] ^ (~b[18] & b[19]);
			state[18] = b[18] ^ (~b[19] & b[15]);
			state[19] = b[19] ^ (~b[15] & b[16]);
			state[20] = b[20] ^ (~b[21] & b[22]);
			state[21] = b[21] ^ (~b[22] & b[23]);
			state[22] = b[22] ^ (~b[23] & b[24]);
			state[23] = b[23] ^ (~b[24] & b[20]);
			state[24] = b[24] ^ (~b[20] & b[21]);
		}
	}
}
