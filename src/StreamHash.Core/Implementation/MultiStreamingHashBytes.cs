using System.Buffers;
using StreamHash.Core.Abstractions;

namespace StreamHash.Core.Implementation;

/// <summary>
/// High-performance batch streaming hash implementation using parallel processing.
/// </summary>
/// <remarks>
/// <para>
/// Uses parallel processing for 70 hash algorithms with a single pre-allocated buffer.
/// The buffer is rented once at construction and reused for all Update() calls.
/// </para>
/// </remarks>
internal sealed class MultiStreamingHashBytes : IMultiStreamingHashBytes {
	private readonly Dictionary<string, IStreamingHashBytes> _hashers;
	private readonly string[] _algorithmNames;
	private readonly IStreamingHashBytes[] _hasherArray;
	private byte[] _buffer;
	private int _bufferSize;
	private bool _disposed;
	private bool _finalized;

	private const int InitialBufferSize = 16 * 1024 * 1024; // 16MB buffer for optimal throughput
	private const int ParallelThreshold = 8;

	/// <summary>
	/// Initializes a new instance of the <see cref="MultiStreamingHashBytes"/> class.
	/// </summary>
	/// <param name="algorithmNames">The names of algorithms to include in this batch.</param>
	public MultiStreamingHashBytes(IEnumerable<string> algorithmNames) {
		_hashers = new Dictionary<string, IStreamingHashBytes>(StringComparer.OrdinalIgnoreCase);
		foreach (var name in algorithmNames) {
			var algo = ParseAlgorithmName(name);
			var hasher = HashFacade.CreateStreaming(algo);
			_hashers[name] = hasher;
		}
		_algorithmNames = _hashers.Keys.ToArray();
		_hasherArray = _hashers.Values.ToArray();

		// Pre-allocate buffer for parallel processing
		if (_hasherArray.Length >= ParallelThreshold) {
			_buffer = ArrayPool<byte>.Shared.Rent(InitialBufferSize);
			_bufferSize = _buffer.Length;
		} else {
			_buffer = [];
			_bufferSize = 0;
		}
	}

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) {
			throw new InvalidOperationException("Cannot update after FinalizeAll(). Call Reset() first.");
		}

		if (data.Length == 0) {
			return;
		}

		// Parallel for many hashers
		if (_hasherArray.Length >= ParallelThreshold) {
			// Grow buffer if needed (rare - only if chunk > 1MB)
			if (data.Length > _bufferSize) {
				ArrayPool<byte>.Shared.Return(_buffer);
				_buffer = ArrayPool<byte>.Shared.Rent(data.Length);
				_bufferSize = _buffer.Length;
			}

			// Single copy to shared buffer
			data.CopyTo(_buffer);
			int len = data.Length;
			var hashers = _hasherArray;
			var buffer = _buffer;

			// Parallel update - direct foreach for optimal distribution
			Parallel.ForEach(hashers, hasher => hasher.Update(buffer.AsSpan(0, len)));
		} else {
			// Sequential for few hashers
			foreach (var hasher in _hasherArray) {
				hasher.Update(data);
			}
		}
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		Update(data.AsSpan(offset, length));
	}

	/// <inheritdoc/>
	public Dictionary<string, string> FinalizeAll() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		var results = new Dictionary<string, string>(_hashers.Count, StringComparer.OrdinalIgnoreCase);

		// Finalize each hasher and collect hex string results
		foreach (var (name, hasher) in _hashers) {
			var hashBytes = hasher.FinalizeBytes();
			results[name] = Convert.ToHexStringLower(hashBytes);
		}

		_finalized = true;
		return results;
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		foreach (var hasher in _hasherArray) {
			hasher.Reset();
		}
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (_disposed) {
			return;
		}

		// Return rented buffer to pool
		if (_buffer.Length > 0) {
			ArrayPool<byte>.Shared.Return(_buffer);
			_buffer = [];
			_bufferSize = 0;
		}

		foreach (var hasher in _hasherArray) {
			hasher.Dispose();
		}
		_hashers.Clear();
		_disposed = true;
	}

	/// <inheritdoc/>
	public int AlgorithmCount => _hashers.Count;

	/// <inheritdoc/>
	public IReadOnlyList<string> AlgorithmNames => _algorithmNames;

	/// <summary>
	/// Parses an algorithm name string to the corresponding HashAlgorithm enum value.
	/// </summary>
	private static HashAlgorithm ParseAlgorithmName(string name) {
		return name.ToUpperInvariant().Replace("-", "").Replace("/", "") switch {
			"CRC32" => HashAlgorithm.Crc32,
			"CRC32C" => HashAlgorithm.Crc32C,
			"CRC64" => HashAlgorithm.Crc64,
			"CRC16CCITT" => HashAlgorithm.Crc16Ccitt,
			"CRC16MODBUS" => HashAlgorithm.Crc16Modbus,
			"CRC16USB" => HashAlgorithm.Crc16Usb,
			"ADLER32" => HashAlgorithm.Adler32,
			"FLETCHER16" => HashAlgorithm.Fletcher16,
			"FLETCHER32" => HashAlgorithm.Fletcher32,
			"XXHASH32" => HashAlgorithm.XxHash32,
			"XXHASH64" => HashAlgorithm.XxHash64,
			"XXHASH3" => HashAlgorithm.XxHash3,
			"XXHASH128" => HashAlgorithm.XxHash128,
			"MURMURHASH332" => HashAlgorithm.MurmurHash3_32,
			"MURMURHASH3128" => HashAlgorithm.MurmurHash3_128,
			"CITYHASH64" => HashAlgorithm.CityHash64,
			"CITYHASH128" => HashAlgorithm.CityHash128,
			"FARMHASH64" => HashAlgorithm.FarmHash64,
			"SPOOKYHASH128" => HashAlgorithm.SpookyHash128,
			"SIPHASH24" => HashAlgorithm.SipHash24,
			"HIGHWAYHASH64" => HashAlgorithm.HighwayHash64,
			"METROHASH64" => HashAlgorithm.MetroHash64,
			"METROHASH128" => HashAlgorithm.MetroHash128,
			"WYHASH64" => HashAlgorithm.Wyhash64,
			"FNV1A32" => HashAlgorithm.Fnv1a32,
			"FNV1A64" => HashAlgorithm.Fnv1a64,
			"DJB2" => HashAlgorithm.Djb2,
			"DJB2A" => HashAlgorithm.Djb2a,
			"SDBM" => HashAlgorithm.Sdbm,
			"LOSELOSE" => HashAlgorithm.LoseLose,
			"MD2" => HashAlgorithm.Md2,
			"MD4" => HashAlgorithm.Md4,
			"MD5" => HashAlgorithm.Md5,
			"SHA0" => HashAlgorithm.Sha0,
			"SHA1" => HashAlgorithm.Sha1,
			"SHA224" => HashAlgorithm.Sha224,
			"SHA256" => HashAlgorithm.Sha256,
			"SHA384" => HashAlgorithm.Sha384,
			"SHA512" => HashAlgorithm.Sha512,
			"SHA512224" => HashAlgorithm.Sha512_224,
			"SHA512256" => HashAlgorithm.Sha512_256,
			"SHA3224" => HashAlgorithm.Sha3_224,
			"SHA3256" => HashAlgorithm.Sha3_256,
			"SHA3384" => HashAlgorithm.Sha3_384,
			"SHA3512" => HashAlgorithm.Sha3_512,
			"KECCAK256" => HashAlgorithm.Keccak256,
			"KECCAK512" => HashAlgorithm.Keccak512,
			"BLAKE256" => HashAlgorithm.Blake256,
			"BLAKE512" => HashAlgorithm.Blake512,
			"BLAKE2B" => HashAlgorithm.Blake2b,
			"BLAKE2S" => HashAlgorithm.Blake2s,
			"BLAKE3" => HashAlgorithm.Blake3,
			"RIPEMD128" => HashAlgorithm.Ripemd128,
			"RIPEMD160" => HashAlgorithm.Ripemd160,
			"RIPEMD256" => HashAlgorithm.Ripemd256,
			"RIPEMD320" => HashAlgorithm.Ripemd320,
			"WHIRLPOOL" => HashAlgorithm.Whirlpool,
			"TIGER192" => HashAlgorithm.Tiger192,
			"GOST94" => HashAlgorithm.Gost94,
			"STREEBOG256" => HashAlgorithm.Streebog256,
			"STREEBOG512" => HashAlgorithm.Streebog512,
			"SKEIN256" => HashAlgorithm.Skein256,
			"SKEIN512" => HashAlgorithm.Skein512,
			"SKEIN1024" => HashAlgorithm.Skein1024,
			"GROESTL256" or "GRØSTL256" => HashAlgorithm.Groestl256,
			"GROESTL512" or "GRØSTL512" => HashAlgorithm.Groestl512,
			"JH256" => HashAlgorithm.Jh256,
			"JH512" => HashAlgorithm.Jh512,
			"KANGAROOTWELVE" => HashAlgorithm.KangarooTwelve,
			"SM3" => HashAlgorithm.Sm3,
			_ => throw new NotSupportedException($"Unknown algorithm name: {name}")
		};
	}
}
