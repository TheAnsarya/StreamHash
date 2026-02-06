using CryptoHashAlgorithm = System.Security.Cryptography.HashAlgorithm;

namespace StreamHash.Core;

/// <summary>
/// Streaming adapter for acryptohashnet hash algorithms.
/// Wraps <see cref="CryptoHashAlgorithm"/> types from acryptohashnet library.
/// </summary>
/// <remarks>
/// acryptohashnet provides pure managed C# implementations of hash algorithms
/// that inherit from <see cref="System.Security.Cryptography.HashAlgorithm"/>,
/// supporting streaming via TransformBlock/TransformFinalBlock.
/// </remarks>
internal sealed class AcryptohashnetAdapter : IStreamingHashBytes {
	private readonly CryptoHashAlgorithm _algorithm;
	private readonly int _digestSize;
	private bool _disposed;
	private long _totalBytes;
	private bool _finalized;

	/// <summary>
	/// Creates an adapter wrapping the specified acryptohashnet hash algorithm.
	/// </summary>
	/// <param name="algorithm">The hash algorithm instance from acryptohashnet.</param>
	/// <param name="digestSize">The digest size in bytes.</param>
	public AcryptohashnetAdapter(CryptoHashAlgorithm algorithm, int digestSize) {
		_algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
		_digestSize = digestSize;
	}

	/// <inheritdoc/>
	public int BlockSize => 64; // Most hash algorithms use 64-byte (512-bit) blocks

	/// <inheritdoc/>
	public int DigestSize => _digestSize;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) {
			throw new InvalidOperationException("Cannot update after finalization. Call Reset() first.");
		}

		// acryptohashnet HashAlgorithm.TransformBlock requires byte[]
		// Use ArrayPool for efficiency with larger data
		if (data.Length <= 256) {
			// Small data: use stackalloc to avoid allocation
			Span<byte> buffer = stackalloc byte[data.Length];
			data.CopyTo(buffer);
			_algorithm.TransformBlock(buffer.ToArray(), 0, data.Length, null, 0);
		} else {
			// Larger data: copy to array (acryptohashnet needs byte[])
			byte[] buffer = data.ToArray();
			_algorithm.TransformBlock(buffer, 0, buffer.Length, null, 0);
		}

		_totalBytes += data.Length;
	}

	/// <inheritdoc/>
	public byte[] FinalizeBytes() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (!_finalized) {
			// Complete the hash computation
			_algorithm.TransformFinalBlock([], 0, 0);
			_finalized = true;
		}

		return _algorithm.Hash ?? throw new InvalidOperationException("Hash computation failed.");
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_algorithm.Initialize();
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (!_disposed) {
			_algorithm.Dispose();
			_disposed = true;
		}
	}
}

/// <summary>
/// Factory for creating acryptohashnet streaming hash adapters.
/// Provides optimized pure managed C# implementations for RIPEMD, Keccak, and other algorithms.
/// </summary>
/// <remarks>
/// <para>
/// acryptohashnet v3.1.0 provides the following algorithms:
/// </para>
/// <list type="bullet">
/// <item><description>RIPEMD-128, RIPEMD-160</description></item>
/// <item><description>Keccak-224, Keccak-256, Keccak-384, Keccak-512</description></item>
/// <item><description>MD2, MD4, MD5</description></item>
/// <item><description>SHA-0, SHA-1</description></item>
/// <item><description>Tiger, Tiger2</description></item>
/// <item><description>Haval (various bit sizes)</description></item>
/// <item><description>Snefru, Snefru256</description></item>
/// </list>
/// <para>
/// Optimized with low memory footprint compared to BouncyCastle for these algorithms.
/// </para>
/// </remarks>
public static class AcryptohashnetFactory {
	// =========================================================================
	// RIPEMD Family - Pure managed C# implementation
	// =========================================================================

	/// <summary>
	/// Creates a streaming RIPEMD-128 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for RIPEMD-128.</returns>
	public static IStreamingHashBytes CreateRipemd128() =>
		new AcryptohashnetAdapter(new acryptohashnet.RIPEMD128(), 16);

	/// <summary>
	/// Creates a streaming RIPEMD-160 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for RIPEMD-160.</returns>
	public static IStreamingHashBytes CreateRipemd160() =>
		new AcryptohashnetAdapter(new acryptohashnet.RIPEMD160(), 20);

	/// <summary>
	/// Computes RIPEMD-128 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 16-byte RIPEMD-128 hash.</returns>
	public static byte[] ComputeRipemd128(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.RIPEMD128();
		return hasher.ComputeHash(data.ToArray());
	}

	/// <summary>
	/// Computes RIPEMD-160 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 20-byte RIPEMD-160 hash.</returns>
	public static byte[] ComputeRipemd160(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.RIPEMD160();
		return hasher.ComputeHash(data.ToArray());
	}

	// =========================================================================
	// Keccak Family - Pure managed C# implementation
	// =========================================================================

	/// <summary>
	/// Creates a streaming Keccak-256 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for Keccak-256.</returns>
	public static IStreamingHashBytes CreateKeccak256() =>
		new AcryptohashnetAdapter(new acryptohashnet.Keccak256(), 32);

	/// <summary>
	/// Creates a streaming Keccak-512 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for Keccak-512.</returns>
	public static IStreamingHashBytes CreateKeccak512() =>
		new AcryptohashnetAdapter(new acryptohashnet.Keccak512(), 64);

	/// <summary>
	/// Computes Keccak-256 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 32-byte Keccak-256 hash.</returns>
	public static byte[] ComputeKeccak256(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.Keccak256();
		return hasher.ComputeHash(data.ToArray());
	}

	/// <summary>
	/// Computes Keccak-512 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 64-byte Keccak-512 hash.</returns>
	public static byte[] ComputeKeccak512(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.Keccak512();
		return hasher.ComputeHash(data.ToArray());
	}

	// =========================================================================
	// MD Family - Pure managed C# (MD2 is only in acryptohashnet, not .NET)
	// =========================================================================

	/// <summary>
	/// Creates a streaming MD2 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for MD2.</returns>
	/// <remarks>
	/// MD2 is obsolete and insecure. Use only for legacy compatibility.
	/// </remarks>
	public static IStreamingHashBytes CreateMd2() =>
		new AcryptohashnetAdapter(new acryptohashnet.MD2(), 16);

	/// <summary>
	/// Creates a streaming MD4 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for MD4.</returns>
	/// <remarks>
	/// MD4 is obsolete and insecure. Use only for legacy compatibility.
	/// </remarks>
	public static IStreamingHashBytes CreateMd4() =>
		new AcryptohashnetAdapter(new acryptohashnet.MD4(), 16);

	/// <summary>
	/// Computes MD2 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 16-byte MD2 hash.</returns>
	public static byte[] ComputeMd2(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.MD2();
		return hasher.ComputeHash(data.ToArray());
	}

	/// <summary>
	/// Computes MD4 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 16-byte MD4 hash.</returns>
	public static byte[] ComputeMd4(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.MD4();
		return hasher.ComputeHash(data.ToArray());
	}

	// =========================================================================
	// SHA Family - Pure managed C# (SHA-0 and SHA-224 not in .NET BCL)
	// =========================================================================

	/// <summary>
	/// Creates a streaming SHA-0 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for SHA-0.</returns>
	/// <remarks>
	/// SHA-0 is the original version of SHA before NIST patched a weakness.
	/// It is insecure and should only be used for legacy compatibility.
	/// </remarks>
	public static IStreamingHashBytes CreateSha0() =>
		new AcryptohashnetAdapter(new acryptohashnet.SHA0(), 20);

	/// <summary>
	/// Creates a streaming SHA-224 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for SHA-224.</returns>
	public static IStreamingHashBytes CreateSha224() =>
		new AcryptohashnetAdapter(new acryptohashnet.SHA224(), 28);

	/// <summary>
	/// Computes SHA-0 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 20-byte SHA-0 hash.</returns>
	public static byte[] ComputeSha0(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.SHA0();
		return hasher.ComputeHash(data.ToArray());
	}

	/// <summary>
	/// Computes SHA-224 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 28-byte SHA-224 hash.</returns>
	public static byte[] ComputeSha224(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.SHA224();
		return hasher.ComputeHash(data.ToArray());
	}

	// =========================================================================
	// Tiger Family - Pure managed C# implementation
	// =========================================================================

	/// <summary>
	/// Creates a streaming Tiger-192 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for Tiger-192.</returns>
	public static IStreamingHashBytes CreateTiger192() =>
		new AcryptohashnetAdapter(new acryptohashnet.Tiger(), 24);

	/// <summary>
	/// Creates a streaming Tiger2-192 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for Tiger2-192.</returns>
	public static IStreamingHashBytes CreateTiger2_192() =>
		new AcryptohashnetAdapter(new acryptohashnet.Tiger2(), 24);

	/// <summary>
	/// Computes Tiger-192 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 24-byte Tiger-192 hash.</returns>
	public static byte[] ComputeTiger192(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.Tiger();
		return hasher.ComputeHash(data.ToArray());
	}

	/// <summary>
	/// Computes Tiger2-192 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 24-byte Tiger2-192 hash.</returns>
	public static byte[] ComputeTiger2_192(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.Tiger2();
		return hasher.ComputeHash(data.ToArray());
	}

	// =========================================================================
	// Snefru Family - Pure managed C# implementation
	// =========================================================================

	/// <summary>
	/// Creates a streaming Snefru-128 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for Snefru-128.</returns>
	public static IStreamingHashBytes CreateSnefru128() =>
		new AcryptohashnetAdapter(new acryptohashnet.Snefru(), 16);

	/// <summary>
	/// Creates a streaming Snefru-256 hasher.
	/// </summary>
	/// <returns>A streaming hash adapter for Snefru-256.</returns>
	public static IStreamingHashBytes CreateSnefru256() =>
		new AcryptohashnetAdapter(new acryptohashnet.Snefru256(), 32);

	/// <summary>
	/// Computes Snefru-128 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 16-byte Snefru-128 hash.</returns>
	public static byte[] ComputeSnefru128(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.Snefru();
		return hasher.ComputeHash(data.ToArray());
	}

	/// <summary>
	/// Computes Snefru-256 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 32-byte Snefru-256 hash.</returns>
	public static byte[] ComputeSnefru256(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.Snefru256();
		return hasher.ComputeHash(data.ToArray());
	}

	// =========================================================================
	// Haval Family - Pure managed C# implementation
	// =========================================================================

	/// <summary>
	/// Creates a streaming Haval-128 hasher (5 passes).
	/// </summary>
	/// <returns>A streaming hash adapter for Haval-128.</returns>
	public static IStreamingHashBytes CreateHaval128() =>
		new AcryptohashnetAdapter(new acryptohashnet.Haval128(), 16);

	/// <summary>
	/// Creates a streaming Haval-160 hasher (5 passes).
	/// </summary>
	/// <returns>A streaming hash adapter for Haval-160.</returns>
	public static IStreamingHashBytes CreateHaval160() =>
		new AcryptohashnetAdapter(new acryptohashnet.Haval160(), 20);

	/// <summary>
	/// Creates a streaming Haval-192 hasher (5 passes).
	/// </summary>
	/// <returns>A streaming hash adapter for Haval-192.</returns>
	public static IStreamingHashBytes CreateHaval192() =>
		new AcryptohashnetAdapter(new acryptohashnet.Haval192(), 24);

	/// <summary>
	/// Creates a streaming Haval-224 hasher (5 passes).
	/// </summary>
	/// <returns>A streaming hash adapter for Haval-224.</returns>
	public static IStreamingHashBytes CreateHaval224() =>
		new AcryptohashnetAdapter(new acryptohashnet.Haval224(), 28);

	/// <summary>
	/// Creates a streaming Haval-256 hasher (5 passes).
	/// </summary>
	/// <returns>A streaming hash adapter for Haval-256.</returns>
	public static IStreamingHashBytes CreateHaval256() =>
		new AcryptohashnetAdapter(new acryptohashnet.Haval256(), 32);

	/// <summary>
	/// Computes Haval-256 hash in one shot.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <returns>The 32-byte Haval-256 hash.</returns>
	public static byte[] ComputeHaval256(ReadOnlySpan<byte> data) {
		using var hasher = new acryptohashnet.Haval256();
		return hasher.ComputeHash(data.ToArray());
	}
}
