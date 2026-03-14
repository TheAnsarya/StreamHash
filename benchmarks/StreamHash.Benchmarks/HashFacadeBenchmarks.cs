using BenchmarkDotNet.Attributes;
using System.IO.Hashing;
using System.Security.Cryptography;
using StreamHash.Core;

namespace StreamHash.Benchmarks;

/// <summary>
/// Benchmarks comparing HashFacade with direct algorithm calls.
/// Validates that the facade has minimal overhead.
/// </summary>
[MemoryDiagnoser]
public sealed class HashFacadeBenchmarks {
	private byte[] _data = null!;

	[Params(1024, 65536, 1048576)]
	public int DataSize { get; set; }

	[GlobalSetup]
	public void Setup() {
		_data = new byte[DataSize];
		new Random(42).NextBytes(_data);
	}

	#region One-Shot via Facade vs Direct

	[Benchmark(Baseline = true)]
	public byte[] Facade_XxHash64() {
		return HashFacade.ComputeHash(Core.HashAlgorithm.XxHash64, _data);
	}

	[Benchmark]
	public byte[] Direct_XxHash64() {
		var hash = new XxHash64();
		hash.Append(_data);
		return hash.GetCurrentHash();
	}

	[Benchmark]
	public byte[] Facade_Sha256() {
		return HashFacade.ComputeHash(Core.HashAlgorithm.Sha256, _data);
	}

	[Benchmark]
	public byte[] Direct_Sha256() {
		return SHA256.HashData(_data);
	}

	[Benchmark]
	public byte[] Facade_MurmurHash3_128() {
		return HashFacade.ComputeHash(Core.HashAlgorithm.MurmurHash3_128, _data);
	}

	[Benchmark]
	public byte[] Direct_MurmurHash3_128() {
		using var hasher = new MurmurHash3_128();
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] Facade_CityHash64() {
		return HashFacade.ComputeHash(Core.HashAlgorithm.CityHash64, _data);
	}

	[Benchmark]
	public byte[] Direct_CityHash64() {
		using var hasher = new CityHash64();
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] Facade_Wyhash64() {
		return HashFacade.ComputeHash(Core.HashAlgorithm.Wyhash64, _data);
	}

	[Benchmark]
	public byte[] Direct_Wyhash64() {
		using var hasher = new Wyhash64();
		hasher.Update(_data);
		ulong result = hasher.Finalize();
		return BitConverter.GetBytes(result);
	}

	#endregion

	#region Checksum Benchmarks

	[Benchmark]
	public byte[] Facade_Crc32() {
		return HashFacade.ComputeHash(Core.HashAlgorithm.Crc32, _data);
	}

	[Benchmark]
	public byte[] Direct_Crc32() {
		var hash = new Crc32();
		hash.Append(_data);
		return hash.GetCurrentHash();
	}

	[Benchmark]
	public byte[] Facade_Adler32() {
		return HashFacade.ComputeAdler32(_data);
	}

	[Benchmark]
	public byte[] Facade_Fletcher16() {
		return HashFacade.ComputeFletcher16(_data);
	}

	[Benchmark]
	public byte[] Facade_Fletcher32() {
		return HashFacade.ComputeFletcher32(_data);
	}

	#endregion

	#region Streaming Comparison

	[Benchmark]
	public byte[] Streaming_MurmurHash3_32() {
		using var hasher = HashFacade.CreateStreaming(Core.HashAlgorithm.MurmurHash3_32);
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] Streaming_CityHash128() {
		using var hasher = HashFacade.CreateStreaming(Core.HashAlgorithm.CityHash128);
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] Streaming_XxHash128() {
		using var hasher = HashFacade.CreateStreaming(Core.HashAlgorithm.XxHash128);
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	[Benchmark]
	public byte[] Streaming_KangarooTwelve() {
		using var hasher = HashFacade.CreateStreaming(Core.HashAlgorithm.KangarooTwelve);
		hasher.Update(_data);
		return hasher.FinalizeBytes();
	}

	#endregion
}
