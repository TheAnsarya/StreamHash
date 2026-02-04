namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of DJB2 hash algorithm by Dan Bernstein.
/// </summary>
/// <remarks>
/// <para>
/// DJB2 is a simple and fast non-cryptographic hash function created by Dan Bernstein.
/// It's one of the most widely used simple hash functions, particularly for string hashing.
/// </para>
/// <para>
/// <b>Algorithm:</b>
/// <code>
/// hash = 5381
/// for each byte:
///     hash = ((hash &lt;&lt; 5) + hash) + byte  // hash * 33 + byte
/// </code>
/// </para>
/// <para>
/// <b>Why 5381?</b>
/// Dan Bernstein never fully explained, but it's:
/// <list type="bullet">
/// <item>An odd number</item>
/// <item>A prime number</item>
/// <item>A deficient number (sum of proper divisors &lt; number)</item>
/// <item>Produces good distribution empirically</item>
/// </list>
/// </para>
/// <para>
/// <b>Why 33?</b>
/// The multiplier 33 = 2^5 + 1 allows the compiler to optimize to shift+add.
/// It also provides good bit mixing properties.
/// </para>
/// <para>
/// <b>Variants:</b>
/// <list type="bullet">
/// <item><b>DJB2:</b> Uses addition: hash * 33 + byte</item>
/// <item><b>DJB2a (SDBM variant):</b> Uses XOR: hash * 33 ^ byte</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// using var hasher = new Djb2Streaming();
/// hasher.Update(Encoding.UTF8.GetBytes("Hello, World!"));
/// uint hash = hasher.Finalize();
///
/// // One-shot
/// uint quick = Djb2Streaming.Hash(data);
/// </code>
/// </example>
public sealed class Djb2Streaming : IStreamingHash<uint> {
	// ═══════════════════════════════════════════════════════════════════════════
	// Constants
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Initial hash value: 5381.
	/// This magic number was chosen by Dan Bernstein for its empirically good properties.
	/// </summary>
	public const uint InitialValue = 5381;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	private uint _hash;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;
	private readonly bool _useXor;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public int BlockSize => 1;

	/// <inheritdoc/>
	public int DigestSize => 4;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new DJB2 hasher using addition (standard variant).
	/// </summary>
	public Djb2Streaming() : this(useXor: false) { }

	/// <summary>
	/// Creates a new DJB2 hasher.
	/// </summary>
	/// <param name="useXor">If true, uses XOR instead of addition (DJB2a variant).</param>
	public Djb2Streaming(bool useXor) {
		_useXor = useXor;
		_hash = InitialValue;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Update Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) {
			throw new InvalidOperationException("Cannot update after Finalize(). Call Reset() first.");
		}

		if (_useXor) {
			// DJB2a variant: XOR
			foreach (byte b in data) {
				_hash = ((_hash << 5) + _hash) ^ b;
			}
		} else {
			// Standard DJB2: addition
			foreach (byte b in data) {
				_hash = ((_hash << 5) + _hash) + b;
			}
		}

		_totalBytes += data.Length;
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		ArgumentNullException.ThrowIfNull(data);
		Update(data.AsSpan(offset, length));
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Finalization
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public uint Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) {
			throw new InvalidOperationException("Finalize() already called. Call Reset() first.");
		}
		_finalized = true;
		return _hash;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_hash = InitialValue;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		_disposed = true;
	}

	/// <summary>
	/// Computes DJB2 hash in one call.
	/// </summary>
	/// <param name="data">Data to hash.</param>
	/// <param name="useXor">Use XOR variant (DJB2a) instead of addition.</param>
	/// <returns>32-bit hash value.</returns>
	public static uint Hash(ReadOnlySpan<byte> data, bool useXor = false) {
		uint hash = InitialValue;
		if (useXor) {
			foreach (byte b in data) {
				hash = ((hash << 5) + hash) ^ b;
			}
		} else {
			foreach (byte b in data) {
				hash = ((hash << 5) + hash) + b;
			}
		}
		return hash;
	}
}

/// <summary>
/// Streaming implementation of SDBM hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// SDBM hash is a simple hash function created for the SDBM (a public-domain
/// reimplementation of ndbm) database library.
/// </para>
/// <para>
/// <b>Algorithm:</b>
/// <code>
/// hash = 0
/// for each byte:
///     hash = byte + (hash &lt;&lt; 6) + (hash &lt;&lt; 16) - hash
/// </code>
/// The magic formula is equivalent to: hash * 65599 + byte
/// </para>
/// <para>
/// <b>Why 65599?</b>
/// This is 2^16 + 2^6 - 1, chosen for good distribution and fast computation
/// using shifts instead of multiplication.
/// </para>
/// </remarks>
public sealed class SdbmStreaming : IStreamingHash<uint> {
	private uint _hash;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;

	/// <inheritdoc/>
	public int BlockSize => 1;

	/// <inheritdoc/>
	public int DigestSize => 4;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// Creates a new SDBM hasher.
	/// </summary>
	public SdbmStreaming() {
		_hash = 0;
	}

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) {
			throw new InvalidOperationException("Cannot update after Finalize(). Call Reset() first.");
		}

		// SDBM: hash * 65599 + byte = byte + (hash << 6) + (hash << 16) - hash
		foreach (byte b in data) {
			_hash = b + (_hash << 6) + (_hash << 16) - _hash;
		}

		_totalBytes += data.Length;
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		ArgumentNullException.ThrowIfNull(data);
		Update(data.AsSpan(offset, length));
	}

	/// <inheritdoc/>
	public uint Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) {
			throw new InvalidOperationException("Finalize() already called. Call Reset() first.");
		}
		_finalized = true;
		return _hash;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_hash = 0;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		_disposed = true;
	}

	/// <summary>
	/// Computes SDBM hash in one call.
	/// </summary>
	public static uint Hash(ReadOnlySpan<byte> data) {
		uint hash = 0;
		foreach (byte b in data) {
			hash = b + (hash << 6) + (hash << 16) - hash;
		}
		return hash;
	}
}

/// <summary>
/// Streaming implementation of Lose Lose hash (simple sum hash).
/// </summary>
/// <remarks>
/// <para>
/// Lose Lose is the simplest possible hash function - just sum the bytes.
/// It has terrible collision resistance but is useful as a baseline.
/// </para>
/// <para>
/// <b>Algorithm:</b>
/// <code>
/// hash = 0
/// for each byte:
///     hash = hash + byte
/// </code>
/// </para>
/// <para>
/// <b>⚠️ Warning:</b> This hash has extremely poor distribution.
/// Only use for educational purposes or when simplicity is paramount.
/// </para>
/// </remarks>
public sealed class LoseLoseStreaming : IStreamingHash<uint> {
	private uint _hash;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;

	/// <inheritdoc/>
	public int BlockSize => 1;

	/// <inheritdoc/>
	public int DigestSize => 4;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>Creates a new Lose Lose hasher.</summary>
	public LoseLoseStreaming() => _hash = 0;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Finalize() already called.");

		foreach (byte b in data) {
			_hash += b;
		}
		_totalBytes += data.Length;
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		ArgumentNullException.ThrowIfNull(data);
		Update(data.AsSpan(offset, length));
	}

	/// <inheritdoc/>
	public uint Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) throw new InvalidOperationException("Finalize() already called.");
		_finalized = true;
		return _hash;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_hash = 0;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() => _disposed = true;

	/// <summary>Computes Lose Lose hash in one call.</summary>
	public static uint Hash(ReadOnlySpan<byte> data) {
		uint hash = 0;
		foreach (byte b in data) hash += b;
		return hash;
	}
}
