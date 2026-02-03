using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of wyhash - one of the fastest hash functions available.
/// </summary>
/// <remarks>
/// <para>
/// wyhash is a non-cryptographic hash function created by Wang Yi (王一). It's designed
/// for maximum speed while maintaining excellent quality (passes SMHasher, BigCrush, PractRand).
/// </para>
/// <para>
/// <b>Algorithm Details:</b>
/// <list type="bullet">
/// <item>Uses 128-bit multiply for mixing (MUM - MUltiply and Mix)</item>
/// <item>Processes data in 48-byte blocks using 3 parallel accumulators</item>
/// <item>Excellent avalanche properties and collision resistance</item>
/// <item>Public domain (The Unlicense)</item>
/// </list>
/// </para>
/// <para>
/// <b>Performance:</b> 15-25 GB/s on modern hardware - one of the fastest hash functions available.
/// </para>
/// <para>
/// <b>Streaming Implementation Notes:</b>
/// wyhash processes data in 48-byte blocks for large inputs. This streaming implementation
/// buffers data until a complete 48-byte block is available, then processes it.
/// For inputs less than 48 bytes, special handling is used in finalization.
/// </para>
/// <para>
/// <b>Example:</b>
/// <code>
/// using var hasher = new Wyhash64();
/// hasher.Update(chunk1);
/// hasher.Update(chunk2);
/// ulong hash = hasher.Finalize();
/// </code>
/// </para>
/// </remarks>
/// <seealso href="https://github.com/wangyi-fudan/wyhash">wyhash GitHub repository</seealso>
public sealed class Wyhash64 : IStreamingHash<ulong> {
	// Default secret parameters from wyhash reference implementation
	private static readonly ulong[] DefaultSecret = [
		0x2d358dccaa6c78a5ul,
		0x8bb84b93962eacc9ul,
		0x4b33a62ed433d4a3ul,
		0x4d5a2da51de1aa47ul
	];

	/// <summary>
	/// The block size for wyhash (48 bytes for main loop).
	/// </summary>
	public const int BlockSizeValue = 48;

	/// <summary>
	/// The digest size for wyhash (8 bytes / 64 bits).
	/// </summary>
	public const int DigestSizeValue = 8;

	private readonly ulong[] _secret;
	private readonly ulong _initialSeed;

	// Streaming state - accumulate all data for proper finalization
	// wyhash's finalization reads from the END of data, making true streaming complex
	// We use a chunked approach: process 48-byte blocks but keep tail for finalization
	private ulong _seed;
	private ulong _see1;
	private ulong _see2;
	private readonly byte[] _buffer;
	private int _bufferPosition;
	private long _totalBytes;
	private bool _processedLargeBlock;
	private bool _finalized;
	private bool _disposed;

	// Keep track of last 16 bytes seen (for finalization of large inputs)
	private readonly byte[] _last16;
	private int _last16Len;

	/// <inheritdoc/>
	public int BlockSize => BlockSizeValue;

	/// <inheritdoc/>
	public int DigestSize => DigestSizeValue;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// Initializes a new instance with default seed (0) and default secret.
	/// </summary>
	public Wyhash64() : this(0) { }

	/// <summary>
	/// Initializes a new instance with the specified seed and default secret.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	public Wyhash64(ulong seed) : this(seed, DefaultSecret) { }

	/// <summary>
	/// Initializes a new instance with the specified seed and custom secret.
	/// </summary>
	/// <param name="seed">The seed value for the hash computation.</param>
	/// <param name="secret">Custom secret parameters (must be 4 elements).</param>
	public Wyhash64(ulong seed, ulong[] secret) {
		ArgumentNullException.ThrowIfNull(secret);
		if (secret.Length != 4) {
			throw new ArgumentException("Secret must contain exactly 4 elements.", nameof(secret));
		}

		_secret = secret;
		_initialSeed = seed;
		_buffer = new byte[BlockSizeValue];
		_last16 = new byte[16];
		Reset();
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

		// If we have buffered data, try to complete a 48-byte block
		if (_bufferPosition > 0) {
			int needed = BlockSizeValue - _bufferPosition;
			if (data.Length >= needed) {
				// Complete the block
				data[..needed].CopyTo(_buffer.AsSpan(_bufferPosition));
				ProcessBlock(_buffer);
				_bufferPosition = 0;
				offset = needed;
			} else {
				// Not enough data, just buffer it
				data.CopyTo(_buffer.AsSpan(_bufferPosition));
				_bufferPosition += data.Length;
				// Update last16 tracking
				UpdateLast16(data);
				return;
			}
		}

		// Process complete 48-byte blocks directly from input
		while (offset + BlockSizeValue <= data.Length) {
			ProcessBlock(data.Slice(offset, BlockSizeValue));
			offset += BlockSizeValue;
		}

		// Buffer remaining bytes
		int remaining = data.Length - offset;
		if (remaining > 0) {
			data.Slice(offset, remaining).CopyTo(_buffer.AsSpan());
			_bufferPosition = remaining;
		}

		// Always update last16 with the end of the incoming data
		UpdateLast16(data);
	}

	/// <summary>
	/// Updates the last 16 bytes tracking.
	/// </summary>
	private void UpdateLast16(ReadOnlySpan<byte> data) {
		if (data.Length >= 16) {
			// Take last 16 bytes from this chunk
			data[^16..].CopyTo(_last16);
			_last16Len = 16;
		} else {
			// Shift existing and append new
			int shift = data.Length;
			if (_last16Len + shift <= 16) {
				// Just append
				data.CopyTo(_last16.AsSpan(_last16Len));
				_last16Len += shift;
			} else {
				// Shift left and append
				int keep = 16 - shift;
				_last16.AsSpan(_last16Len - keep, keep).CopyTo(_last16);
				data.CopyTo(_last16.AsSpan(keep));
				_last16Len = 16;
			}
		}
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		ArgumentNullException.ThrowIfNull(data);
		Update(data.AsSpan(offset, length));
	}

	/// <summary>
	/// Processes a single 48-byte block.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlock(ReadOnlySpan<byte> block) {
		_processedLargeBlock = true;

		// Read 6 64-bit values (48 bytes)
		ulong v0 = BinaryPrimitives.ReadUInt64LittleEndian(block);
		ulong v1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);
		ulong v2 = BinaryPrimitives.ReadUInt64LittleEndian(block[16..]);
		ulong v3 = BinaryPrimitives.ReadUInt64LittleEndian(block[24..]);
		ulong v4 = BinaryPrimitives.ReadUInt64LittleEndian(block[32..]);
		ulong v5 = BinaryPrimitives.ReadUInt64LittleEndian(block[40..]);

		// Process with 3 accumulators
		_seed = WyMix(v0 ^ _secret[1], v1 ^ _seed);
		_see1 = WyMix(v2 ^ _secret[2], v3 ^ _see1);
		_see2 = WyMix(v4 ^ _secret[3], v5 ^ _see2);
	}

	/// <inheritdoc/>
	public ulong Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Finalize() has already been called. Call Reset() before computing a new hash.");
		}

		_finalized = true;

		int len = (int)_totalBytes;

		// Handle small inputs (<=16 bytes) - no blocks processed
		if (len <= 16) {
			return FinalizeSmall();
		}

		// For larger inputs, merge accumulators if we processed blocks
		ulong seed = _processedLargeBlock ? (_seed ^ _see1 ^ _see2) : _seed;

		// Process any remaining 16-byte chunks from buffer
		int remaining = _bufferPosition;
		int pos = 0;
		while (remaining > 16) {
			seed = WyMix(
				BinaryPrimitives.ReadUInt64LittleEndian(_buffer.AsSpan(pos)) ^ _secret[1],
				BinaryPrimitives.ReadUInt64LittleEndian(_buffer.AsSpan(pos + 8)) ^ seed);
			pos += 16;
			remaining -= 16;
		}

		// Final 16 bytes - read from _last16 which tracks the end of all input
		// wyhash reads the last 16 bytes as two overlapping 8-byte reads
		ulong a = BinaryPrimitives.ReadUInt64LittleEndian(_last16.AsSpan(0));
		ulong b = BinaryPrimitives.ReadUInt64LittleEndian(_last16.AsSpan(8));

		// Final mixing
		a ^= _secret[1];
		b ^= seed;
		WyMum(ref a, ref b);
		return WyMix(a ^ _secret[0] ^ (ulong)len, b ^ _secret[1]);
	}

	/// <summary>
	/// Finalizes for small inputs (0-16 bytes).
	/// </summary>
	private ulong FinalizeSmall() {
		int len = (int)_totalBytes;
		ulong a, b;

		if (len >= 4) {
			int half = len >> 3 << 2;
			a = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(0)) << 32) |
				BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(half));
			b = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(len - 4)) << 32) |
				BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(len - 4 - half));
		} else if (len > 0) {
			a = ((ulong)_buffer[0] << 16) |
				((ulong)_buffer[len >> 1] << 8) |
				_buffer[len - 1];
			b = 0;
		} else {
			a = 0;
			b = 0;
		}

		// Final mixing
		a ^= _secret[1];
		b ^= _seed;
		WyMum(ref a, ref b);
		return WyMix(a ^ _secret[0] ^ (ulong)len, b ^ _secret[1]);
	}

	/// <summary>
	/// Finalizes and returns the hash as a byte array.
	/// </summary>
	/// <returns>The 8-byte hash value.</returns>
	public byte[] FinalizeToBytes() {
		var hash = Finalize();
		var result = new byte[8];
		BinaryPrimitives.WriteUInt64LittleEndian(result, hash);
		return result;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		// Initialize seed with secret mixing (as per wyhash spec)
		_seed = _initialSeed ^ WyMix(_initialSeed ^ _secret[0], _secret[1]);
		_see1 = _seed;
		_see2 = _seed;
		_bufferPosition = 0;
		_totalBytes = 0;
		_processedLargeBlock = false;
		_finalized = false;
		_last16Len = 0;
		Array.Clear(_last16);
		Array.Clear(_buffer);
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (!_disposed) {
			_disposed = true;
		}
	}

	/// <summary>
	/// MUM (MUltiply and Mix) - core mixing function.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WyMum(ref ulong a, ref ulong b) {
		UInt128 r = (UInt128)a * b;
		a = (ulong)r;
		b = (ulong)(r >> 64);
	}

	/// <summary>
	/// Mix function combining MUM and XOR.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong WyMix(ulong a, ulong b) {
		WyMum(ref a, ref b);
		return a ^ b;
	}

	/// <summary>
	/// Computes wyhash of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong Hash(ReadOnlySpan<byte> data, ulong seed = 0) {
		return HashWithSecret(data, seed, DefaultSecret);
	}

	/// <summary>
	/// Computes wyhash of the input data with custom secret.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value.</param>
	/// <param name="secret">Custom secret parameters (must be 4 elements).</param>
	/// <returns>The 64-bit hash value.</returns>
	public static ulong HashWithSecret(ReadOnlySpan<byte> data, ulong seed, ulong[] secret) {
		int len = data.Length;
		seed ^= WyMix(seed ^ secret[0], secret[1]);

		ulong a, b;
		if (len <= 16) {
			if (len >= 4) {
				int half = len >> 3 << 2;
				a = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(data) << 32) |
					BinaryPrimitives.ReadUInt32LittleEndian(data[half..]);
				b = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(data[(len - 4)..]) << 32) |
					BinaryPrimitives.ReadUInt32LittleEndian(data[(len - 4 - half)..]);
			} else if (len > 0) {
				a = ((ulong)data[0] << 16) | ((ulong)data[len >> 1] << 8) | data[len - 1];
				b = 0;
			} else {
				a = 0;
				b = 0;
			}
		} else {
			int i = len;
			int p = 0;

			if (i >= 48) {
				ulong see1 = seed, see2 = seed;
				do {
					seed = WyMix(BinaryPrimitives.ReadUInt64LittleEndian(data[p..]) ^ secret[1],
						BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 8)..]) ^ seed);
					see1 = WyMix(BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 16)..]) ^ secret[2],
						BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 24)..]) ^ see1);
					see2 = WyMix(BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 32)..]) ^ secret[3],
						BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 40)..]) ^ see2);
					p += 48;
					i -= 48;
				} while (i >= 48);
				seed ^= see1 ^ see2;
			}

			while (i > 16) {
				seed = WyMix(BinaryPrimitives.ReadUInt64LittleEndian(data[p..]) ^ secret[1],
					BinaryPrimitives.ReadUInt64LittleEndian(data[(p + 8)..]) ^ seed);
				i -= 16;
				p += 16;
			}

			a = BinaryPrimitives.ReadUInt64LittleEndian(data[(len - 16)..]);
			b = BinaryPrimitives.ReadUInt64LittleEndian(data[(len - 8)..]);
		}

		a ^= secret[1];
		b ^= seed;
		WyMum(ref a, ref b);
		return WyMix(a ^ secret[0] ^ (ulong)len, b ^ secret[1]);
	}

	/// <summary>
	/// Computes wyhash of the input data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="seed">The seed value (default: 0).</param>
	/// <returns>The hash as a byte array.</returns>
	public static byte[] HashToBytes(ReadOnlySpan<byte> data, ulong seed = 0) {
		var result = new byte[8];
		BinaryPrimitives.WriteUInt64LittleEndian(result, Hash(data, seed));
		return result;
	}
}
