using StreamHash.Core;
using Xunit;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for native Keccak/SHA-3 streaming implementation.
/// Test vectors from NIST CAVP and Keccak team reference implementation.
/// </summary>
public class KeccakTests {
	// ========== SHA3-256 Test Vectors (FIPS 202) ==========

	/// <summary>SHA3-256 empty string test vector.</summary>
	[Fact]
	public void Sha3_256_Empty() {
		// SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
		var expected = Convert.FromHexString("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
		using var sha3 = NativeSha3Factory.CreateSha3_256();
		var hash = sha3.FinalizeBytes();
		Assert.Equal(expected, hash);
	}

	/// <summary>SHA3-256 "abc" test vector.</summary>
	[Fact]
	public void Sha3_256_Abc() {
		// SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
		var expected = Convert.FromHexString("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
		var input = "abc"u8.ToArray();
		var hash = NativeSha3Factory.ComputeSha3_256(input);
		Assert.Equal(expected, hash);
	}

	/// <summary>SHA3-256 one block message test vector.</summary>
	[Fact]
	public void Sha3_256_OneBlock() {
		// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
		// SHA3-256 = 41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376
		var expected = Convert.FromHexString("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
		var input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"u8.ToArray();
		var hash = NativeSha3Factory.ComputeSha3_256(input);
		Assert.Equal(expected, hash);
	}

	/// <summary>SHA3-256 two block message test vector.</summary>
	[Fact]
	public void Sha3_256_TwoBlocks() {
		// "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
		// SHA3-256 = 916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18
		var expected = Convert.FromHexString("916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");
		var input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"u8.ToArray();
		var hash = NativeSha3Factory.ComputeSha3_256(input);
		Assert.Equal(expected, hash);
	}

	// ========== SHA3-224 Test Vectors ==========

	/// <summary>SHA3-224 empty string test vector.</summary>
	[Fact]
	public void Sha3_224_Empty() {
		var expected = Convert.FromHexString("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
		using var sha3 = NativeSha3Factory.CreateSha3_224();
		var hash = sha3.FinalizeBytes();
		Assert.Equal(expected, hash);
	}

	/// <summary>SHA3-224 "abc" test vector.</summary>
	[Fact]
	public void Sha3_224_Abc() {
		var expected = Convert.FromHexString("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
		var input = "abc"u8.ToArray();
		using var sha3 = NativeSha3Factory.CreateSha3_224();
		sha3.Update(input);
		var hash = sha3.FinalizeBytes();
		Assert.Equal(expected, hash);
	}

	// ========== SHA3-384 Test Vectors ==========

	/// <summary>SHA3-384 empty string test vector.</summary>
	[Fact]
	public void Sha3_384_Empty() {
		var expected = Convert.FromHexString("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
		using var sha3 = NativeSha3Factory.CreateSha3_384();
		var hash = sha3.FinalizeBytes();
		Assert.Equal(expected, hash);
	}

	/// <summary>SHA3-384 "abc" test vector.</summary>
	[Fact]
	public void Sha3_384_Abc() {
		var expected = Convert.FromHexString("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
		var input = "abc"u8.ToArray();
		var hash = NativeSha3Factory.ComputeSha3_384(input);
		Assert.Equal(expected, hash);
	}

	// ========== SHA3-512 Test Vectors ==========

	/// <summary>SHA3-512 empty string test vector.</summary>
	[Fact]
	public void Sha3_512_Empty() {
		var expected = Convert.FromHexString("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
		using var sha3 = NativeSha3Factory.CreateSha3_512();
		var hash = sha3.FinalizeBytes();
		Assert.Equal(expected, hash);
	}

	/// <summary>SHA3-512 "abc" test vector.</summary>
	[Fact]
	public void Sha3_512_Abc() {
		var expected = Convert.FromHexString("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
		var input = "abc"u8.ToArray();
		var hash = NativeSha3Factory.ComputeSha3_512(input);
		Assert.Equal(expected, hash);
	}

	// ========== Keccak-256 Test Vectors (Original Padding) ==========

	/// <summary>Keccak-256 empty string test vector.</summary>
	[Fact]
	public void Keccak256_Empty() {
		// Keccak-256("") with 0x01 padding
		var expected = Convert.FromHexString("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
		using var keccak = NativeSha3Factory.CreateKeccak256();
		var hash = keccak.FinalizeBytes();
		Assert.Equal(expected, hash);
	}

	/// <summary>Keccak-256 "abc" test vector.</summary>
	[Fact]
	public void Keccak256_Abc() {
		// This is what Ethereum uses
		var expected = Convert.FromHexString("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
		var input = "abc"u8.ToArray();
		var hash = NativeSha3Factory.ComputeKeccak256(input);
		Assert.Equal(expected, hash);
	}

	// ========== Keccak-512 Test Vectors ==========

	/// <summary>Keccak-512 empty string test vector.</summary>
	[Fact]
	public void Keccak512_Empty() {
		var expected = Convert.FromHexString("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");
		using var keccak = NativeSha3Factory.CreateKeccak512();
		var hash = keccak.FinalizeBytes();
		Assert.Equal(expected, hash);
	}

	/// <summary>Keccak-512 "abc" test vector.</summary>
	[Fact]
	public void Keccak512_Abc() {
		var expected = Convert.FromHexString("18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96");
		var input = "abc"u8.ToArray();
		var hash = NativeSha3Factory.ComputeKeccak512(input);
		Assert.Equal(expected, hash);
	}

	// ========== Streaming Tests ==========

	/// <summary>Test incremental update produces same result as one-shot.</summary>
	[Fact]
	public void Sha3_256_Streaming_MatchesOneShot() {
		var input = new byte[10000];
		Random.Shared.NextBytes(input);

		// One-shot
		var expected = NativeSha3Factory.ComputeSha3_256(input);

		// Streaming in various chunk sizes
		foreach (var chunkSize in new[] { 1, 7, 17, 64, 136, 137, 1000 }) {
			using var sha3 = NativeSha3Factory.CreateSha3_256();
			for (int i = 0; i < input.Length; i += chunkSize) {
				int len = Math.Min(chunkSize, input.Length - i);
				sha3.Update(input.AsSpan(i, len));
			}
			var hash = sha3.FinalizeBytes();
			Assert.Equal(expected, hash);
		}
	}

	/// <summary>Test Reset() allows reuse.</summary>
	[Fact]
	public void Sha3_256_Reset_AllowsReuse() {
		using var sha3 = NativeSha3Factory.CreateSha3_256();

		// First computation
		sha3.Update("abc"u8);
		var hash1 = sha3.FinalizeBytes();

		// Reset and compute again
		sha3.Reset();
		sha3.Update("abc"u8);
		var hash2 = sha3.FinalizeBytes();

		Assert.Equal(hash1, hash2);
	}

	/// <summary>Test different inputs produce different outputs.</summary>
	[Fact]
	public void Sha3_256_DifferentInputs_DifferentOutputs() {
		var hash1 = NativeSha3Factory.ComputeSha3_256("abc"u8);
		var hash2 = NativeSha3Factory.ComputeSha3_256("abd"u8);
		Assert.NotEqual(hash1, hash2);
	}

	/// <summary>Test BlockSize and DigestSize properties.</summary>
	[Fact]
	public void Properties_ReturnCorrectValues() {
		using var sha3_224 = NativeSha3Factory.CreateSha3_224();
		Assert.Equal(28, sha3_224.DigestSize);
		Assert.Equal(144, sha3_224.BlockSize); // (1600 - 2*224) / 8

		using var sha3_256 = NativeSha3Factory.CreateSha3_256();
		Assert.Equal(32, sha3_256.DigestSize);
		Assert.Equal(136, sha3_256.BlockSize); // (1600 - 2*256) / 8

		using var sha3_384 = NativeSha3Factory.CreateSha3_384();
		Assert.Equal(48, sha3_384.DigestSize);
		Assert.Equal(104, sha3_384.BlockSize); // (1600 - 2*384) / 8

		using var sha3_512 = NativeSha3Factory.CreateSha3_512();
		Assert.Equal(64, sha3_512.DigestSize);
		Assert.Equal(72, sha3_512.BlockSize); // (1600 - 2*512) / 8
	}

	/// <summary>Test TotalBytesProcessed is tracked correctly.</summary>
	[Fact]
	public void TotalBytesProcessed_IsTracked() {
		using var sha3 = NativeSha3Factory.CreateSha3_256();
		Assert.Equal(0, sha3.TotalBytesProcessed);

		sha3.Update(new byte[100]);
		Assert.Equal(100, sha3.TotalBytesProcessed);

		sha3.Update(new byte[200]);
		Assert.Equal(300, sha3.TotalBytesProcessed);

		sha3.Reset();
		Assert.Equal(0, sha3.TotalBytesProcessed);
	}

	// ========== Edge Cases ==========

	/// <summary>Test exact block size boundary.</summary>
	[Fact]
	public void Sha3_256_ExactBlockSize() {
		var input = new byte[136]; // Exactly one block for SHA3-256
		for (int i = 0; i < input.Length; i++) input[i] = (byte)(i & 0xff);

		using var sha3 = NativeSha3Factory.CreateSha3_256();
		sha3.Update(input);
		var hash = sha3.FinalizeBytes();

		Assert.Equal(32, hash.Length);
	}

	/// <summary>Test multiple exact blocks.</summary>
	[Fact]
	public void Sha3_256_MultipleExactBlocks() {
		var input = new byte[136 * 10]; // Exactly 10 blocks
		Random.Shared.NextBytes(input);

		var expected = NativeSha3Factory.ComputeSha3_256(input);

		// Also test streaming
		using var sha3 = NativeSha3Factory.CreateSha3_256();
		for (int i = 0; i < 10; i++) {
			sha3.Update(input.AsSpan(i * 136, 136));
		}
		var hash = sha3.FinalizeBytes();

		Assert.Equal(expected, hash);
	}

	/// <summary>Test large input (1 MB).</summary>
	[Fact]
	public void Sha3_256_LargeInput() {
		var input = new byte[1024 * 1024];
		Array.Fill(input, (byte)'a');

		// SHA3-256 of 1MB of 'a' characters
		using var sha3 = NativeSha3Factory.CreateSha3_256();
		sha3.Update(input);
		var hash = sha3.FinalizeBytes();

		Assert.Equal(32, hash.Length);
		// Verify it's deterministic
		Assert.Equal(hash, NativeSha3Factory.ComputeSha3_256(input));
	}

	// ========== Error Handling ==========

	/// <summary>Test invalid hash size throws.</summary>
	[Fact]
	public void InvalidHashSize_Throws() {
		Assert.Throws<ArgumentException>(() => new NativeKeccak(128));
		Assert.Throws<ArgumentException>(() => new NativeKeccak(192));
		Assert.Throws<ArgumentException>(() => new NativeKeccak(320));
		Assert.Throws<ArgumentException>(() => new NativeKeccak(1024));
	}

	/// <summary>Test finalize twice throws.</summary>
	[Fact]
	public void FinalizeTwice_Throws() {
		using var sha3 = NativeSha3Factory.CreateSha3_256();
		sha3.FinalizeBytes();
		Assert.Throws<InvalidOperationException>(() => sha3.FinalizeBytes());
	}

	/// <summary>Test update after finalize throws.</summary>
	[Fact]
	public void UpdateAfterFinalize_Throws() {
		using var sha3 = NativeSha3Factory.CreateSha3_256();
		sha3.FinalizeBytes();
		Assert.Throws<InvalidOperationException>(() => sha3.Update(new byte[1]));
	}

	/// <summary>Test disposed throws.</summary>
	[Fact]
	public void DisposedOperations_Throw() {
		var sha3 = NativeSha3Factory.CreateSha3_256();
		sha3.Dispose();

		Assert.Throws<ObjectDisposedException>(() => sha3.Update(new byte[1]));
		Assert.Throws<ObjectDisposedException>(() => sha3.FinalizeBytes());
		Assert.Throws<ObjectDisposedException>(() => sha3.Reset());
	}
}
