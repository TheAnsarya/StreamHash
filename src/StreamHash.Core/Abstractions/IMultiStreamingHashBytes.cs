namespace StreamHash.Core.Abstractions;

/// <summary>
/// Represents a streaming hash context for multiple algorithms.
/// Efficiently updates all selected algorithms with a single memory pass.
/// </summary>
/// <remarks>
/// This interface provides batch processing capabilities for computing multiple
/// hash algorithms simultaneously. It uses parallel processing and optimized
/// memory access patterns to significantly improve performance compared to
/// computing each hash sequentially.
/// </remarks>
public interface IMultiStreamingHashBytes : IDisposable {
	/// <summary>
	/// Updates all hash states with the provided data.
	/// </summary>
	/// <param name="data">The data to process.</param>
	/// <remarks>
	/// This method updates ALL algorithms in parallel, using a single
	/// memory pass to maximize cache efficiency and CPU utilization.
	/// On multi-core systems, this can provide 8-16x speedup compared
	/// to sequential processing.
	/// </remarks>
	void Update(ReadOnlySpan<byte> data);

	/// <summary>
	/// Updates all hash states with the provided data.
	/// </summary>
	/// <param name="data">The data buffer to process.</param>
	/// <param name="offset">The offset in the buffer to start reading from.</param>
	/// <param name="length">The number of bytes to process.</param>
	void Update(byte[] data, int offset, int length);

	/// <summary>
	/// Finalizes all hash computations and returns the results.
	/// </summary>
	/// <returns>
	/// Dictionary mapping algorithm name to hex-encoded hash value (lowercase).
	/// </returns>
	/// <remarks>
	/// After calling this method, the hash states are finalized and cannot
	/// be updated further. Call <see cref="Reset"/> to reuse the context.
	/// </remarks>
	Dictionary<string, string> FinalizeAll();

	/// <summary>
	/// Resets all hash states to initial values.
	/// </summary>
	/// <remarks>
	/// This allows reusing the same context to hash multiple different
	/// data sets without allocating new hasher instances.
	/// </remarks>
	void Reset();

	/// <summary>
	/// Gets the number of algorithms in this batch context.
	/// </summary>
	int AlgorithmCount { get; }

	/// <summary>
	/// Gets the names of all algorithms in this batch context.
	/// </summary>
	IReadOnlyList<string> AlgorithmNames { get; }
}
