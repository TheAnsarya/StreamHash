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
		_inner = inner ?? throw new ArgumentNullException(nameof(inner));
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
		_inner = inner ?? throw new ArgumentNullException(nameof(inner));
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
		_inner = inner ?? throw new ArgumentNullException(nameof(inner));
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
		_inner = inner ?? throw new ArgumentNullException(nameof(inner));
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
/// Adapter that wraps <see cref="KangarooTwelve"/> to provide <see cref="IStreamingHashBytes"/> interface.
/// </summary>
internal sealed class KangarooTwelveAdapter : IStreamingHashBytes {
	private KangarooTwelve? _inner;
	private bool _disposed;
	private long _totalBytes;

	public KangarooTwelveAdapter() {
		_inner = new KangarooTwelve();
	}

	public int BlockSize => 8192; // K12 chunk size
	public int DigestSize => 32;  // Default K12 output
	public long TotalBytesProcessed => _totalBytes;

	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner!.Update(data);
		_totalBytes += data.Length;
	}

	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _inner!.Finalize();
	}

	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner?.Dispose();
		_inner = new KangarooTwelve();
		_totalBytes = 0;
	}

	public void Dispose() {
		if (!_disposed) {
			_inner?.Dispose();
			_inner = null;
			_disposed = true;
		}
	}
}
