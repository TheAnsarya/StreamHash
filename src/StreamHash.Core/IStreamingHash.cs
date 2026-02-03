namespace StreamHash.Core;

/// <summary>
/// Interface for streaming hash algorithms that can process data incrementally.
/// </summary>
/// <typeparam name="TResult">The type of the hash result (uint, ulong, byte[], UInt128, etc.)</typeparam>
/// <remarks>
/// <para>
/// Streaming hash algorithms allow data to be processed in chunks rather than all at once,
/// enabling constant memory usage regardless of input size.
/// </para>
/// <para>
/// <b>Usage Pattern:</b>
/// <code>
/// using var hasher = new MurmurHash3_32();
/// hasher.Update(chunk1);
/// hasher.Update(chunk2);
/// hasher.Update(chunk3);
/// uint hash = hasher.Finalize();
/// </code>
/// </para>
/// <para>
/// <b>Thread Safety:</b> Implementations are NOT thread-safe. Each thread should use its own instance.
/// </para>
/// </remarks>
/// <seealso cref="StreamingHashBase{TResult}"/>
public interface IStreamingHash<TResult> : IDisposable where TResult : struct {
	/// <summary>
	/// Gets the block size in bytes that the algorithm processes internally.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Data is buffered until a complete block is available for processing.
	/// For optimal performance, provide data in multiples of this block size.
	/// </para>
	/// <para>
	/// Common block sizes:
	/// <list type="bullet">
	/// <item>MurmurHash3-32: 4 bytes</item>
	/// <item>MurmurHash3-128: 16 bytes</item>
	/// <item>CityHash64: 32 bytes</item>
	/// <item>CityHash128: 16 bytes</item>
	/// <item>SpookyHash: 96 bytes</item>
	/// <item>SipHash: 8 bytes</item>
	/// <item>FarmHash: 64 bytes</item>
	/// <item>HighwayHash: 32 bytes</item>
	/// </list>
	/// </para>
	/// </remarks>
	int BlockSize { get; }

	/// <summary>
	/// Gets the size of the hash output in bytes.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Common digest sizes:
	/// <list type="bullet">
	/// <item>32-bit hashes: 4 bytes</item>
	/// <item>64-bit hashes: 8 bytes</item>
	/// <item>128-bit hashes: 16 bytes</item>
	/// </list>
	/// </para>
	/// </remarks>
	int DigestSize { get; }

	/// <summary>
	/// Gets the total number of bytes that have been processed so far.
	/// </summary>
	/// <remarks>
	/// This includes both fully processed blocks and any pending data in the internal buffer.
	/// </remarks>
	long TotalBytesProcessed { get; }

	/// <summary>
	/// Appends data to the hash computation.
	/// </summary>
	/// <param name="data">The data to add to the hash computation.</param>
	/// <remarks>
	/// <para>
	/// Data is accumulated in an internal buffer until a complete block is available.
	/// When enough data is accumulated, full blocks are processed immediately.
	/// </para>
	/// <para>
	/// <b>Performance Tips:</b>
	/// <list type="bullet">
	/// <item>Provide data in multiples of <see cref="BlockSize"/> for best performance</item>
	/// <item>Use <see cref="ReadOnlySpan{T}"/> to avoid copying data</item>
	/// <item>For file hashing, use a buffer size that is a multiple of the block size</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <exception cref="ObjectDisposedException">The hasher has been disposed.</exception>
	void Update(ReadOnlySpan<byte> data);

	/// <summary>
	/// Completes the hash computation and returns the result.
	/// </summary>
	/// <returns>The computed hash value.</returns>
	/// <remarks>
	/// <para>
	/// After calling <see cref="Finalize"/>, the hasher is in an invalid state.
	/// Call <see cref="Reset"/> before processing more data, or dispose and create a new instance.
	/// </para>
	/// <para>
	/// This method processes any remaining buffered data with appropriate padding.
	/// </para>
	/// </remarks>
	/// <exception cref="ObjectDisposedException">The hasher has been disposed.</exception>
	/// <exception cref="InvalidOperationException">Finalize has already been called without a subsequent Reset.</exception>
	TResult Finalize();

	/// <summary>
	/// Resets the hasher to its initial state, ready to compute a new hash.
	/// </summary>
	/// <remarks>
	/// <para>
	/// After calling <see cref="Reset"/>, the hasher is in the same state as a newly created instance
	/// with the same seed/key parameters.
	/// </para>
	/// <para>
	/// This method clears all internal state including:
	/// <list type="bullet">
	/// <item>Accumulated hash state</item>
	/// <item>Internal buffer contents</item>
	/// <item>Total bytes processed counter</item>
	/// </list>
	/// </para>
	/// </remarks>
	/// <exception cref="ObjectDisposedException">The hasher has been disposed.</exception>
	void Reset();
}
