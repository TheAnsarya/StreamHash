using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
[SkipLocalsInit]
public sealed class NativeKeccak : IStreamingHashBytes {
	// ========== Constants ==========

	/// <summary>State size in bytes (1600 bits = 200 bytes).</summary>
	private const int StateSize = 200;

	/// <summary>Number of lanes (5×5 = 25 64-bit words).</summary>
	private const int NumLanes = 25;

	/// <summary>Domain separator for original Keccak.</summary>
	private const byte KeccakDomainSeparator = 0x01;

	/// <summary>Domain separator for SHA-3 (FIPS 202).</summary>
	private const byte Sha3DomainSeparator = 0x06;



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
		if (offset + _rate <= data.Length) {
			AbsorbMultipleBlocks(data, ref offset);
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
	/// Absorbs multiple rate-sized blocks by keeping state on the stack,
	/// eliminating per-block heap-array load/store overhead.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private void AbsorbMultipleBlocks(ReadOnlySpan<byte> data, ref int offset) {
		int rate = _rate;
		int lanes = rate >> 3;

		while (offset + rate <= data.Length) {
			ReadOnlySpan<ulong> inputLanes = MemoryMarshal.Cast<byte, ulong>(data.Slice(offset, rate));
			ref ulong stateRef = ref MemoryMarshal.GetArrayDataReference(_state);
			for (int i = 0; i < lanes; i++) {
				Unsafe.Add(ref stateRef, i) ^= inputLanes[i];
			}
			KeccakF1600();
			offset += rate;
		}
	}

	/// <summary>
	/// Absorbs a rate-sized block into the state.
	/// XORs input bytes into state lanes, then applies Keccak-f[1600].
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AbsorbBlock(ReadOnlySpan<byte> block) {
		// XOR block into state (rate bytes only)
		// Use MemoryMarshal.Cast for zero-copy ulong access on little-endian
		int lanes = _rate >> 3;
		ReadOnlySpan<ulong> inputLanes = MemoryMarshal.Cast<byte, ulong>(block);
		ref ulong stateRef = ref MemoryMarshal.GetArrayDataReference(_state);
		for (int i = 0; i < lanes; i++) {
			Unsafe.Add(ref stateRef, i) ^= inputLanes[i];
		}

		KeccakF1600();
	}

	/// <summary>
	/// Extracts bytes from the state for squeezing.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ExtractBytes(Span<byte> output) {
		// Use MemoryMarshal.AsBytes for zero-copy extraction on little-endian
		ReadOnlySpan<byte> stateBytes = MemoryMarshal.AsBytes(_state.AsSpan());
		stateBytes.Slice(0, output.Length).CopyTo(output);
	}

/// <summary>
/// Keccak-f[1600] round constants (24 rounds).
/// </summary>
private static readonly ulong[] RoundConstants =
[
	0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
	0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
	0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
	0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
	0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
	0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
];

/// <summary>
/// The Keccak-f[1600] permutation - 24 rounds of θ, ρ, π, χ, ι.
/// Uses 25 local variables with looped rounds for instruction cache efficiency.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveOptimization)]
private void KeccakF1600() {
// Load state into 25 local variables using ref to eliminate bounds checking
ref ulong sr = ref MemoryMarshal.GetArrayDataReference(_state);
ulong a00 = sr, a01 = Unsafe.Add(ref sr, 1), a02 = Unsafe.Add(ref sr, 2), a03 = Unsafe.Add(ref sr, 3), a04 = Unsafe.Add(ref sr, 4);
ulong a05 = Unsafe.Add(ref sr, 5), a06 = Unsafe.Add(ref sr, 6), a07 = Unsafe.Add(ref sr, 7), a08 = Unsafe.Add(ref sr, 8), a09 = Unsafe.Add(ref sr, 9);
ulong a10 = Unsafe.Add(ref sr, 10), a11 = Unsafe.Add(ref sr, 11), a12 = Unsafe.Add(ref sr, 12), a13 = Unsafe.Add(ref sr, 13), a14 = Unsafe.Add(ref sr, 14);
ulong a15 = Unsafe.Add(ref sr, 15), a16 = Unsafe.Add(ref sr, 16), a17 = Unsafe.Add(ref sr, 17), a18 = Unsafe.Add(ref sr, 18), a19 = Unsafe.Add(ref sr, 19);
ulong a20 = Unsafe.Add(ref sr, 20), a21 = Unsafe.Add(ref sr, 21), a22 = Unsafe.Add(ref sr, 22), a23 = Unsafe.Add(ref sr, 23), a24 = Unsafe.Add(ref sr, 24);

ulong c0, c1, c2, c3, c4, d0, d1, d2, d3, d4;
ulong[] rc = RoundConstants;

for (int round = 0; round < 24; round++) {
// θ (Theta) - Column parity + diffusion
c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;
d1 = BitOperations.RotateLeft(c1, 1) ^ c4;
d2 = BitOperations.RotateLeft(c2, 1) ^ c0;
d3 = BitOperations.RotateLeft(c3, 1) ^ c1;
d4 = BitOperations.RotateLeft(c4, 1) ^ c2;
d0 = BitOperations.RotateLeft(c0, 1) ^ c3;
a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

// ρ (Rho) + π (Pi) - Rotation and lane permutation (single 24-element cycle)
c1 = BitOperations.RotateLeft(a01, 1);
a01 = BitOperations.RotateLeft(a06, 44);
a06 = BitOperations.RotateLeft(a09, 20);
a09 = BitOperations.RotateLeft(a22, 61);
a22 = BitOperations.RotateLeft(a14, 39);
a14 = BitOperations.RotateLeft(a20, 18);
a20 = BitOperations.RotateLeft(a02, 62);
a02 = BitOperations.RotateLeft(a12, 43);
a12 = BitOperations.RotateLeft(a13, 25);
a13 = BitOperations.RotateLeft(a19, 8);
a19 = BitOperations.RotateLeft(a23, 56);
a23 = BitOperations.RotateLeft(a15, 41);
a15 = BitOperations.RotateLeft(a04, 27);
a04 = BitOperations.RotateLeft(a24, 14);
a24 = BitOperations.RotateLeft(a21, 2);
a21 = BitOperations.RotateLeft(a08, 55);
a08 = BitOperations.RotateLeft(a16, 45);
a16 = BitOperations.RotateLeft(a05, 36);
a05 = BitOperations.RotateLeft(a03, 28);
a03 = BitOperations.RotateLeft(a18, 21);
a18 = BitOperations.RotateLeft(a17, 15);
a17 = BitOperations.RotateLeft(a11, 10);
a11 = BitOperations.RotateLeft(a07, 6);
a07 = BitOperations.RotateLeft(a10, 3);
a10 = c1;

// χ (Chi) - Non-linear row mixing
c0 = a00 ^ (~a01 & a02); c1 = a01 ^ (~a02 & a03);
a02 ^= ~a03 & a04; a03 ^= ~a04 & a00; a04 ^= ~a00 & a01; a00 = c0; a01 = c1;
c0 = a05 ^ (~a06 & a07); c1 = a06 ^ (~a07 & a08);
a07 ^= ~a08 & a09; a08 ^= ~a09 & a05; a09 ^= ~a05 & a06; a05 = c0; a06 = c1;
c0 = a10 ^ (~a11 & a12); c1 = a11 ^ (~a12 & a13);
a12 ^= ~a13 & a14; a13 ^= ~a14 & a10; a14 ^= ~a10 & a11; a10 = c0; a11 = c1;
c0 = a15 ^ (~a16 & a17); c1 = a16 ^ (~a17 & a18);
a17 ^= ~a18 & a19; a18 ^= ~a19 & a15; a19 ^= ~a15 & a16; a15 = c0; a16 = c1;
c0 = a20 ^ (~a21 & a22); c1 = a21 ^ (~a22 & a23);
a22 ^= ~a23 & a24; a23 ^= ~a24 & a20; a24 ^= ~a20 & a21; a20 = c0; a21 = c1;

// ι (Iota) - Round constant XOR
a00 ^= rc[round];
}

	// Write state back using ref to eliminate bounds checks
	ref ulong s = ref MemoryMarshal.GetArrayDataReference(_state);
	s = a00; Unsafe.Add(ref s, 1) = a01; Unsafe.Add(ref s, 2) = a02; Unsafe.Add(ref s, 3) = a03; Unsafe.Add(ref s, 4) = a04;
	Unsafe.Add(ref s, 5) = a05; Unsafe.Add(ref s, 6) = a06; Unsafe.Add(ref s, 7) = a07; Unsafe.Add(ref s, 8) = a08; Unsafe.Add(ref s, 9) = a09;
	Unsafe.Add(ref s, 10) = a10; Unsafe.Add(ref s, 11) = a11; Unsafe.Add(ref s, 12) = a12; Unsafe.Add(ref s, 13) = a13; Unsafe.Add(ref s, 14) = a14;
	Unsafe.Add(ref s, 15) = a15; Unsafe.Add(ref s, 16) = a16; Unsafe.Add(ref s, 17) = a17; Unsafe.Add(ref s, 18) = a18; Unsafe.Add(ref s, 19) = a19;
	Unsafe.Add(ref s, 20) = a20; Unsafe.Add(ref s, 21) = a21; Unsafe.Add(ref s, 22) = a22; Unsafe.Add(ref s, 23) = a23; Unsafe.Add(ref s, 24) = a24;
}


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
		int lanes = rate >> 3;
		while (offset + rate <= data.Length) {
			ReadOnlySpan<ulong> inputLanes = MemoryMarshal.Cast<byte, ulong>(data.Slice(offset, rate));
			for (int i = 0; i < lanes; i++) {
				state[i] ^= inputLanes[i];
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
		ReadOnlySpan<ulong> finalLanes = MemoryMarshal.Cast<byte, ulong>(buffer);
		for (int i = 0; i < lanes; i++) {
			state[i] ^= finalLanes[i];
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
/// Keccak-f[1600] round constants for the static permutation.
/// </summary>
private static ReadOnlySpan<ulong> StaticRoundConstants =>
[
0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
];

/// <summary>
/// Static Keccak-f[1600] permutation - 24 rounds using 25 local variables.
/// Looped for instruction cache efficiency.
/// </summary>
[MethodImpl(MethodImplOptions.AggressiveOptimization)]
[SkipLocalsInit]
private static void KeccakF1600Static(Span<ulong> state) {
// Load state into 25 local variables (eliminates span bounds checking)
ulong a00 = state[0], a01 = state[1], a02 = state[2], a03 = state[3], a04 = state[4];
ulong a05 = state[5], a06 = state[6], a07 = state[7], a08 = state[8], a09 = state[9];
ulong a10 = state[10], a11 = state[11], a12 = state[12], a13 = state[13], a14 = state[14];
ulong a15 = state[15], a16 = state[16], a17 = state[17], a18 = state[18], a19 = state[19];
ulong a20 = state[20], a21 = state[21], a22 = state[22], a23 = state[23], a24 = state[24];

ulong c0, c1, c2, c3, c4, d0, d1, d2, d3, d4;
ReadOnlySpan<ulong> rc = StaticRoundConstants;

for (int round = 0; round < 24; round++) {
// θ (Theta)
c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;
d1 = BitOperations.RotateLeft(c1, 1) ^ c4;
d2 = BitOperations.RotateLeft(c2, 1) ^ c0;
d3 = BitOperations.RotateLeft(c3, 1) ^ c1;
d4 = BitOperations.RotateLeft(c4, 1) ^ c2;
d0 = BitOperations.RotateLeft(c0, 1) ^ c3;
a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

// ρ (Rho) + π (Pi)
c1 = BitOperations.RotateLeft(a01, 1);
a01 = BitOperations.RotateLeft(a06, 44);
a06 = BitOperations.RotateLeft(a09, 20);
a09 = BitOperations.RotateLeft(a22, 61);
a22 = BitOperations.RotateLeft(a14, 39);
a14 = BitOperations.RotateLeft(a20, 18);
a20 = BitOperations.RotateLeft(a02, 62);
a02 = BitOperations.RotateLeft(a12, 43);
a12 = BitOperations.RotateLeft(a13, 25);
a13 = BitOperations.RotateLeft(a19, 8);
a19 = BitOperations.RotateLeft(a23, 56);
a23 = BitOperations.RotateLeft(a15, 41);
a15 = BitOperations.RotateLeft(a04, 27);
a04 = BitOperations.RotateLeft(a24, 14);
a24 = BitOperations.RotateLeft(a21, 2);
a21 = BitOperations.RotateLeft(a08, 55);
a08 = BitOperations.RotateLeft(a16, 45);
a16 = BitOperations.RotateLeft(a05, 36);
a05 = BitOperations.RotateLeft(a03, 28);
a03 = BitOperations.RotateLeft(a18, 21);
a18 = BitOperations.RotateLeft(a17, 15);
a17 = BitOperations.RotateLeft(a11, 10);
a11 = BitOperations.RotateLeft(a07, 6);
a07 = BitOperations.RotateLeft(a10, 3);
a10 = c1;

// χ (Chi)
c0 = a00 ^ (~a01 & a02); c1 = a01 ^ (~a02 & a03);
a02 ^= ~a03 & a04; a03 ^= ~a04 & a00; a04 ^= ~a00 & a01; a00 = c0; a01 = c1;
c0 = a05 ^ (~a06 & a07); c1 = a06 ^ (~a07 & a08);
a07 ^= ~a08 & a09; a08 ^= ~a09 & a05; a09 ^= ~a05 & a06; a05 = c0; a06 = c1;
c0 = a10 ^ (~a11 & a12); c1 = a11 ^ (~a12 & a13);
a12 ^= ~a13 & a14; a13 ^= ~a14 & a10; a14 ^= ~a10 & a11; a10 = c0; a11 = c1;
c0 = a15 ^ (~a16 & a17); c1 = a16 ^ (~a17 & a18);
a17 ^= ~a18 & a19; a18 ^= ~a19 & a15; a19 ^= ~a15 & a16; a15 = c0; a16 = c1;
c0 = a20 ^ (~a21 & a22); c1 = a21 ^ (~a22 & a23);
a22 ^= ~a23 & a24; a23 ^= ~a24 & a20; a24 ^= ~a20 & a21; a20 = c0; a21 = c1;

// ι (Iota)
a00 ^= rc[round];
}

// Write state back
state[0] = a00; state[1] = a01; state[2] = a02; state[3] = a03; state[4] = a04;
state[5] = a05; state[6] = a06; state[7] = a07; state[8] = a08; state[9] = a09;
state[10] = a10; state[11] = a11; state[12] = a12; state[13] = a13; state[14] = a14;
state[15] = a15; state[16] = a16; state[17] = a17; state[18] = a18; state[19] = a19;
state[20] = a20; state[21] = a21; state[22] = a22; state[23] = a23; state[24] = a24;
}
}
