using System.IO.Hashing;

namespace StreamHash.Core;

/// <summary>
/// Adapter that wraps <see cref="IStreamingHash{TResult}"/> to provide <see cref="IStreamingHashBytes"/> interface.
/// </summary>
/// <typeparam name="TResult">The native result type of the wrapped hasher.</typeparam>
internal sealed class StreamingHashBytesAdapter<TResult> : IStreamingHashBytes where TResult : struct {
	private readonly IStreamingHash<TResult> _inner;
	private bool _disposed;

	public StreamingHashBytesAdapter(IStreamingHash<TResult> inner) {
		ArgumentNullException.ThrowIfNull(inner);
		_inner = inner;
	}

	public int BlockSize => _inner.BlockSize;
	public int DigestSize => _inner.DigestSize;
	public long TotalBytesProcessed => _inner.TotalBytesProcessed;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Update(data);
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		TResult result = _inner.Finalize();

		// Convert based on type
		return result switch {
			ushort u16 => BitConverter.GetBytes(u16),
			uint u32 => BitConverter.GetBytes(u32),
			ulong u64 => BitConverter.GetBytes(u64),
			UInt128 u128 => ConvertUInt128(u128),
			byte[] bytes => bytes,
			_ => throw new InvalidOperationException($"Unsupported result type: {typeof(TResult)}")
		};
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Reset();
	}

	public void Dispose() {
		if (!_disposed) {
			_inner.Dispose();
			_disposed = true;
		}
	}

	private static byte[] ConvertUInt128(UInt128 value) {
		byte[] result = new byte[16];
		ulong lo = (ulong)value;
		ulong hi = (ulong)(value >> 64);
		BitConverter.TryWriteBytes(result.AsSpan(0, 8), lo);
		BitConverter.TryWriteBytes(result.AsSpan(8, 8), hi);
		return result;
	}
}

/// <summary>
/// Adapter for System.IO.Hashing NonCryptographicHashAlgorithm with 32-bit output.
/// </summary>
internal sealed class NonCryptoHashAdapter32 : IStreamingHashBytes {
	private readonly NonCryptographicHashAlgorithm _inner;
	private bool _disposed;
	private long _totalBytes;

	public NonCryptoHashAdapter32(NonCryptographicHashAlgorithm inner) {
		ArgumentNullException.ThrowIfNull(inner);
		_inner = inner;
	}

	public int BlockSize => 4; // Typical for 32-bit hashes
	public int DigestSize => 4;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Append(data);
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _inner.GetCurrentHash();
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Reset();
		_totalBytes = 0;
	}

	public void Dispose() {
		_disposed = true;
		// NonCryptographicHashAlgorithm doesn't implement IDisposable
	}
}

/// <summary>
/// Adapter for System.IO.Hashing NonCryptographicHashAlgorithm with 64-bit output.
/// </summary>
internal sealed class NonCryptoHashAdapter64 : IStreamingHashBytes {
	private readonly NonCryptographicHashAlgorithm _inner;
	private bool _disposed;
	private long _totalBytes;

	public NonCryptoHashAdapter64(NonCryptographicHashAlgorithm inner) {
		ArgumentNullException.ThrowIfNull(inner);
		_inner = inner;
	}

	public int BlockSize => 8; // Typical for 64-bit hashes
	public int DigestSize => 8;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Append(data);
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _inner.GetCurrentHash();
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Reset();
		_totalBytes = 0;
	}

	public void Dispose() {
		_disposed = true;
	}
}

/// <summary>
/// Adapter for System.IO.Hashing NonCryptographicHashAlgorithm with 128-bit output.
/// </summary>
internal sealed class NonCryptoHashAdapter128 : IStreamingHashBytes {
	private readonly NonCryptographicHashAlgorithm _inner;
	private bool _disposed;
	private long _totalBytes;

	public NonCryptoHashAdapter128(NonCryptographicHashAlgorithm inner) {
		ArgumentNullException.ThrowIfNull(inner);
		_inner = inner;
	}

	public int BlockSize => 16;
	public int DigestSize => 16;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Append(data);
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _inner.GetCurrentHash();
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Reset();
		_totalBytes = 0;
	}

	public void Dispose() {
		_disposed = true;
	}
}

/// <summary>
/// Adapter for System.Security.Cryptography incremental hashing.
/// Wraps <see cref="System.Security.Cryptography.IncrementalHash"/> for streaming.
/// </summary>
internal sealed class IncrementalHashAdapter : IStreamingHashBytes {
	private readonly System.Security.Cryptography.HashAlgorithmName _algorithmName;
	private System.Security.Cryptography.IncrementalHash _inner;
	private readonly int _digestSize;
	private bool _disposed;
	private long _totalBytes;

	/// <summary>
	/// Creates an adapter for the specified hash algorithm.
	/// </summary>
	/// <param name="algorithmName">The hash algorithm name (MD5, SHA1, SHA256, SHA384, SHA512).</param>
	public IncrementalHashAdapter(System.Security.Cryptography.HashAlgorithmName algorithmName) {
		_algorithmName = algorithmName;
		_inner = System.Security.Cryptography.IncrementalHash.CreateHash(algorithmName);
		_digestSize = algorithmName.Name switch {
			"MD5" => 16,
			"SHA1" => 20,
			"SHA256" => 32,
			"SHA384" => 48,
			"SHA512" => 64,
			_ => throw new ArgumentException($"Unknown algorithm: {algorithmName}")
		};
	}

	public int BlockSize => 64; // Most crypto hashes use 64-byte blocks (512 bits)
	public int DigestSize => _digestSize;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.AppendData(data);
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _inner.GetCurrentHash();
	}

	public void Reset() {
		// IncrementalHash doesn't support reset - dispose and recreate
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Dispose();
		_inner = System.Security.Cryptography.IncrementalHash.CreateHash(_algorithmName);
		_totalBytes = 0;
	}

	public void Dispose() {
		if (!_disposed) {
			_inner.Dispose();
			_disposed = true;
		}
	}
}

/// <summary>
/// Streaming adapter for CRC-32C (Castagnoli polynomial).
/// </summary>
internal sealed class Crc32CStreamingAdapter : IStreamingHashBytes {
	private uint _crc = 0xFFFFFFFF;
	private long _totalBytes;
	private bool _disposed;

	public int BlockSize => 4;
	public int DigestSize => 4;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		foreach (byte b in data) {
			_crc ^= b;
			for (int i = 0; i < 8; i++) {
				_crc = (_crc >> 1) ^ ((_crc & 1) * 0x82F63B78u);
			}
		}
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		uint result = _crc ^ 0xFFFFFFFF;
		return BitConverter.GetBytes(result);
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_crc = 0xFFFFFFFF;
		_totalBytes = 0;
	}

	public void Dispose() {
		_disposed = true;
	}
}

/// <summary>
/// Streaming adapter for Adler-32 checksum.
/// </summary>
internal sealed class Adler32StreamingAdapter : IStreamingHashBytes {
	private uint _a = 1;
	private uint _b = 0;
	private long _totalBytes;
	private bool _disposed;
	private const uint MOD = 65521;

	public int BlockSize => 4;
	public int DigestSize => 4;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		foreach (byte bt in data) {
			_a = (_a + bt) % MOD;
			_b = (_b + _a) % MOD;
		}
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		uint result = (_b << 16) | _a;
		return BitConverter.GetBytes(result);
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_a = 1;
		_b = 0;
		_totalBytes = 0;
	}

	public void Dispose() {
		_disposed = true;
	}
}

/// <summary>
/// Streaming adapter for Fletcher-16 checksum.
/// </summary>
internal sealed class Fletcher16StreamingAdapter : IStreamingHashBytes {
	// Max bytes before modulo is required to prevent overflow:
	// sum1 max = 254 + 255*n, sum2 max = 254 + 254*n + 255*n*(n+1)/2
	// With uint: safe for n=5802 before sum2 could overflow
	private const int ChunkSize = 5802;

	private uint _sum1;
	private uint _sum2;
	private long _totalBytes;
	private bool _disposed;

	public int BlockSize => 2;
	public int DigestSize => 2;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		int offset = 0;
		while (offset < data.Length) {
			int chunkLength = Math.Min(ChunkSize, data.Length - offset);
			int i = 0;
			for (; i <= chunkLength - 4; i += 4) {
				_sum1 += data[offset + i];
				_sum2 += _sum1;
				_sum1 += data[offset + i + 1];
				_sum2 += _sum1;
				_sum1 += data[offset + i + 2];
				_sum2 += _sum1;
				_sum1 += data[offset + i + 3];
				_sum2 += _sum1;
			}
			for (; i < chunkLength; i++) {
				_sum1 += data[offset + i];
				_sum2 += _sum1;
			}
			_sum1 %= 255;
			_sum2 %= 255;
			offset += chunkLength;
		}
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		ushort result = (ushort)((_sum2 << 8) | _sum1);
		return BitConverter.GetBytes(result);
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_sum1 = 0;
		_sum2 = 0;
		_totalBytes = 0;
	}

	public void Dispose() {
		_disposed = true;
	}
}

/// <summary>
/// Streaming adapter for Fletcher-32 checksum.
/// </summary>
internal sealed class Fletcher32StreamingAdapter : IStreamingHashBytes {
	// Max bytes before modulo: with ulong sums and mod 65535,
	// safe chunk size is 5802 (same conservative bound)
	private const int ChunkSize = 5802;

	private ulong _sum1;
	private ulong _sum2;
	private long _totalBytes;
	private bool _disposed;

	public int BlockSize => 4;
	public int DigestSize => 4;
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		int offset = 0;
		while (offset < data.Length) {
			int chunkLength = Math.Min(ChunkSize, data.Length - offset);
			int i = 0;
			for (; i <= chunkLength - 4; i += 4) {
				_sum1 += data[offset + i];
				_sum2 += _sum1;
				_sum1 += data[offset + i + 1];
				_sum2 += _sum1;
				_sum1 += data[offset + i + 2];
				_sum2 += _sum1;
				_sum1 += data[offset + i + 3];
				_sum2 += _sum1;
			}
			for (; i < chunkLength; i++) {
				_sum1 += data[offset + i];
				_sum2 += _sum1;
			}
			_sum1 %= 65535;
			_sum2 %= 65535;
			offset += chunkLength;
		}
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		uint result = (uint)((_sum2 << 16) | _sum1);
		return BitConverter.GetBytes(result);
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_sum1 = 0;
		_sum2 = 0;
		_totalBytes = 0;
	}

	public void Dispose() {
		_disposed = true;
	}
}
