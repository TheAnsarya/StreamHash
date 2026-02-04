namespace StreamHash.Core;

/// <summary>
/// Streaming hash interface that returns byte[] from finalization.
/// </summary>
/// <remarks>
/// <para>
/// This interface provides a consistent API for streaming hashing where the result
/// is always returned as a byte array, regardless of the underlying result type.
/// </para>
/// <para>
/// Use this interface when you need to work with hash algorithms polymorphically
/// and always want byte[] results.
/// </para>
/// </remarks>
public interface IStreamingHashBytes : IDisposable {
	/// <summary>
	/// Gets the block size in bytes.
	/// </summary>
	int BlockSize { get; }

	/// <summary>
	/// Gets the digest size in bytes.
	/// </summary>
	int DigestSize { get; }

	/// <summary>
	/// Gets the total bytes processed.
	/// </summary>
	long TotalBytesProcessed { get; }

	/// <summary>
	/// Appends data to the hash computation.
	/// </summary>
	/// <param name="data">The data to add.</param>
	void Update(ReadOnlySpan<byte> data);

	/// <summary>
	/// Completes the hash computation and returns the result as bytes.
	/// </summary>
	/// <returns>The hash value as a byte array.</returns>
	byte[] FinalizeBytes();

	/// <summary>
	/// Completes the hash computation and returns the result as a hex string.
	/// </summary>
	/// <returns>The hash value as a lowercase hexadecimal string.</returns>
	string FinalizeHex() => Convert.ToHexStringLower(FinalizeBytes());

	/// <summary>
	/// Resets the hasher to its initial state.
	/// </summary>
	void Reset();
}
