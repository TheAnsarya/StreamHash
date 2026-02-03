namespace StreamHash.Core;

/// <summary>
/// Base class for streaming hash implementations providing common functionality.
/// </summary>
/// <typeparam name="TResult">The type of the hash result.</typeparam>
/// <remarks>
/// <para>
/// This abstract base class handles common streaming hash operations:
/// <list type="bullet">
/// <item>Internal buffer management with <see cref="ArrayPool{T}"/> for efficiency</item>
/// <item>State tracking (total bytes, finalized flag)</item>
/// <item>Disposal pattern implementation</item>
/// <item>Block-based processing orchestration</item>
/// </list>
/// </para>
/// <para>
/// <b>Implementing a New Hash Algorithm:</b>
/// <code>
/// public class MyHash : StreamingHashBase&lt;uint&gt;
/// {
///     public override int BlockSize => 4;
///     public override int DigestSize => 4;
///
///     private uint _state;
///
///     protected override void ProcessBlock(ReadOnlySpan&lt;byte&gt; block) {
///         // Process one complete block
///         _state ^= BinaryPrimitives.ReadUInt32LittleEndian(block);
///     }
///
///     protected override uint ComputeFinal(ReadOnlySpan&lt;byte&gt; remaining) {
///         // Handle remaining bytes and return final hash
///         return _state ^ (uint)TotalBytesProcessed;
///     }
///
///     protected override void ResetCore() {
///         _state = 0;
///     }
/// }
/// </code>
/// </para>
/// </remarks>
public abstract class StreamingHashBase<TResult> : IStreamingHash<TResult> where TResult : struct {
	private byte[]? _buffer;
	private int _bufferPosition;
	private long _totalBytes;
	private bool _finalized;
	private bool _disposed;

	/// <inheritdoc/>
	public abstract int BlockSize { get; }

	/// <inheritdoc/>
	public abstract int DigestSize { get; }

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// Gets whether the hasher has been finalized and needs to be reset before further use.
	/// </summary>
	protected bool IsFinalized => _finalized;

	/// <summary>
	/// Gets the internal buffer as a span.
	/// </summary>
	protected Span<byte> Buffer => _buffer.AsSpan(0, _bufferPosition);

	/// <summary>
	/// Initializes a new instance of the streaming hash.
	/// </summary>
	protected StreamingHashBase() {
		_buffer = ArrayPool<byte>.Shared.Rent(BlockSize * 2);
		_bufferPosition = 0;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Cannot update after Finalize() has been called. Call Reset() first.");
		}

		if (data.IsEmpty) {
			return;
		}

		_totalBytes += data.Length;

		// If we have buffered data, try to complete a block
		if (_bufferPosition > 0) {
			int needed = BlockSize - _bufferPosition;
			if (data.Length >= needed) {
				// Complete the block
				data[..needed].CopyTo(_buffer.AsSpan(_bufferPosition));
				ProcessBlock(_buffer.AsSpan(0, BlockSize));
				_bufferPosition = 0;
				data = data[needed..];
			} else {
				// Still not enough, just buffer
				data.CopyTo(_buffer.AsSpan(_bufferPosition));
				_bufferPosition += data.Length;
				return;
			}
		}

		// Process complete blocks directly from input
		while (data.Length >= BlockSize) {
			ProcessBlock(data[..BlockSize]);
			data = data[BlockSize..];
		}

		// Buffer remaining bytes
		if (data.Length > 0) {
			data.CopyTo(_buffer.AsSpan(_bufferPosition));
			_bufferPosition += data.Length;
		}
	}

	/// <inheritdoc/>
	public TResult Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_finalized) {
			throw new InvalidOperationException(
				"Finalize() has already been called. Call Reset() to compute a new hash.");
		}

		_finalized = true;
		return ComputeFinal(_buffer.AsSpan(0, _bufferPosition));
	}

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);

		_bufferPosition = 0;
		_totalBytes = 0;
		_finalized = false;
		ResetCore();
	}

	/// <summary>
	/// Processes a complete block of data.
	/// </summary>
	/// <param name="block">A span containing exactly <see cref="BlockSize"/> bytes.</param>
	/// <remarks>
	/// <para>
	/// This method is called for each complete block of input data.
	/// Implementations should update their internal hash state based on the block contents.
	/// </para>
	/// <para>
	/// The span is guaranteed to be exactly <see cref="BlockSize"/> bytes long.
	/// </para>
	/// </remarks>
	protected abstract void ProcessBlock(ReadOnlySpan<byte> block);

	/// <summary>
	/// Computes the final hash value from any remaining data.
	/// </summary>
	/// <param name="remaining">Any data that didn't form a complete block (0 to BlockSize-1 bytes).</param>
	/// <returns>The final hash value.</returns>
	/// <remarks>
	/// <para>
	/// This method is called by <see cref="Finalize"/> to complete the hash computation.
	/// It receives any buffered data that didn't form a complete block.
	/// </para>
	/// <para>
	/// Implementations should:
	/// <list type="bullet">
	/// <item>Process the remaining bytes with appropriate padding</item>
	/// <item>Apply any final mixing/finalization steps</item>
	/// <item>Return the final hash value</item>
	/// </list>
	/// </para>
	/// </remarks>
	protected abstract TResult ComputeFinal(ReadOnlySpan<byte> remaining);

	/// <summary>
	/// Resets the algorithm-specific internal state.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Called by <see cref="Reset"/> after the base class state is cleared.
	/// Implementations should reset all algorithm-specific state variables to their initial values.
	/// </para>
	/// </remarks>
	protected abstract void ResetCore();

	/// <summary>
	/// Releases resources used by the hasher.
	/// </summary>
	/// <param name="disposing">True if called from Dispose(), false if from finalizer.</param>
	protected virtual void Dispose(bool disposing) {
		if (!_disposed) {
			if (disposing) {
				if (_buffer is not null) {
					ArrayPool<byte>.Shared.Return(_buffer);
					_buffer = null;
				}
			}
			_disposed = true;
		}
	}

	/// <inheritdoc/>
	public void Dispose() {
		Dispose(disposing: true);
		GC.SuppressFinalize(this);
	}
}
