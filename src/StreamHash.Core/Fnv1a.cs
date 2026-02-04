using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of FNV-1a (Fowler-Noll-Vo) hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// FNV-1a is a non-cryptographic hash function created by Glenn Fowler, Landon Curt Noll,
/// and Kiem-Phong Vo. It's widely used due to its simplicity and good distribution.
/// </para>
/// <para>
/// <b>Algorithm (FNV-1a):</b>
/// <code>
/// hash = FNV_offset_basis
/// for each byte:
///     hash = hash XOR byte
///     hash = hash * FNV_prime
/// </code>
/// </para>
/// <para>
/// <b>FNV-1a vs FNV-1:</b>
/// FNV-1a XORs before multiplying (better avalanche), FNV-1 multiplies before XORing.
/// FNV-1a is generally preferred and used in this implementation.
/// </para>
/// <para>
/// <b>Variants Supported:</b>
/// <list type="bullet">
/// <item><b>FNV-1a-32:</b> 32-bit hash with prime 0x01000193 and offset 0x811c9dc5</item>
/// <item><b>FNV-1a-64:</b> 64-bit hash with prime 0x00000100000001B3 and offset 0xcbf29ce484222325</item>
/// </list>
/// </para>
/// <para>
/// <b>Use Cases:</b>
/// <list type="bullet">
/// <item>Hash tables and hash maps</item>
/// <item>Data fingerprinting</item>
/// <item>Checksums for small data</item>
/// <item>String hashing</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // 32-bit FNV-1a
/// using var fnv32 = new Fnv1a32Streaming();
/// fnv32.Update(data);
/// uint hash32 = fnv32.Finalize();
///
/// // 64-bit FNV-1a
/// using var fnv64 = new Fnv1a64Streaming();
/// fnv64.Update(data);
/// ulong hash64 = fnv64.Finalize();
///
/// // One-shot
/// uint quick = Fnv1a32Streaming.Hash(data);
/// </code>
/// </example>
/// <seealso href="http://www.isthe.com/chongo/tech/comp/fnv/">FNV Hash Home Page</seealso>
public sealed class Fnv1a32Streaming : IStreamingHash<uint> {
	// ═══════════════════════════════════════════════════════════════════════════
	// Constants
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// FNV-1a 32-bit prime number: 16777619 (0x01000193).
	/// This is 2^24 + 2^8 + 0x93, chosen for good multiplication properties.
	/// </summary>
	public const uint FnvPrime32 = 0x01000193;

	/// <summary>
	/// FNV-1a 32-bit offset basis: 2166136261 (0x811c9dc5).
	/// This is the initial hash value, derived from FNV-0 hash of a specific string.
	/// </summary>
	public const uint FnvOffsetBasis32 = 0x811c9dc5;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>Current hash value.</summary>
	private uint _hash;

	/// <summary>Total bytes processed.</summary>
	private long _totalBytes;

	/// <summary>Whether Finalize has been called.</summary>
	private bool _finalized;

	/// <summary>Whether disposed.</summary>
	private bool _disposed;

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
	// Constructor
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new FNV-1a 32-bit hasher.
	/// </summary>
	public Fnv1a32Streaming() {
		_hash = FnvOffsetBasis32;
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

		// FNV-1a: XOR then multiply
		foreach (byte b in data) {
			_hash ^= b;
			_hash *= FnvPrime32;
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
		_hash = FnvOffsetBasis32;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		_disposed = true;
	}

	/// <summary>
	/// Computes FNV-1a 32-bit hash in one call.
	/// </summary>
	public static uint Hash(ReadOnlySpan<byte> data) {
		uint hash = FnvOffsetBasis32;
		foreach (byte b in data) {
			hash ^= b;
			hash *= FnvPrime32;
		}
		return hash;
	}
}

/// <summary>
/// Streaming implementation of FNV-1a 64-bit hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// FNV-1a-64 is the 64-bit variant of the Fowler-Noll-Vo hash function.
/// It provides better collision resistance than the 32-bit variant.
/// </para>
/// <para>
/// <b>Algorithm:</b>
/// Uses 64-bit prime 0x00000100000001B3 and offset basis 0xcbf29ce484222325.
/// </para>
/// </remarks>
public sealed class Fnv1a64Streaming : IStreamingHash<ulong> {
	// ═══════════════════════════════════════════════════════════════════════════
	// Constants
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// FNV-1a 64-bit prime: 1099511628211 (0x00000100000001B3).
	/// </summary>
	public const ulong FnvPrime64 = 0x00000100000001b3;

	/// <summary>
	/// FNV-1a 64-bit offset basis: 14695981039346656037 (0xcbf29ce484222325).
	/// </summary>
	public const ulong FnvOffsetBasis64 = 0xcbf29ce484222325;

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	private ulong _hash;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public int BlockSize => 1;

	/// <inheritdoc/>
	public int DigestSize => 8;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructor
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new FNV-1a 64-bit hasher.
	/// </summary>
	public Fnv1a64Streaming() {
		_hash = FnvOffsetBasis64;
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

		foreach (byte b in data) {
			_hash ^= b;
			_hash *= FnvPrime64;
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
	public ulong Finalize() {
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
		_hash = FnvOffsetBasis64;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		_disposed = true;
	}

	/// <summary>
	/// Computes FNV-1a 64-bit hash in one call.
	/// </summary>
	public static ulong Hash(ReadOnlySpan<byte> data) {
		ulong hash = FnvOffsetBasis64;
		foreach (byte b in data) {
			hash ^= b;
			hash *= FnvPrime64;
		}
		return hash;
	}
}
