namespace StreamHash.Core;

/// <summary>
/// Flags for selecting which algorithm categories to include in batch operations.
/// </summary>
[Flags]
public enum HashAlgorithmSet {
	/// <summary>
	/// No algorithms selected.
	/// </summary>
	None = 0,

	/// <summary>
	/// Checksum algorithms: CRC32, CRC32C, CRC64, Adler-32, Fletcher-16, Fletcher-32, etc.
	/// </summary>
	Checksums = 1 << 0,

	/// <summary>
	/// Fast non-cryptographic hash algorithms: xxHash, MurmurHash, CityHash, SpookyHash, etc.
	/// </summary>
	FastNonCrypto = 1 << 1,

	/// <summary>
	/// Cryptographic hash algorithms: SHA-256, SHA-512, BLAKE2, BLAKE3, etc.
	/// </summary>
	Cryptographic = 1 << 2,

	/// <summary>
	/// Experimental or specialized algorithms: KangarooTwelve, etc.
	/// </summary>
	Experimental = 1 << 3,

	/// <summary>
	/// All available algorithms (default).
	/// </summary>
	All = Checksums | FastNonCrypto | Cryptographic | Experimental
}
