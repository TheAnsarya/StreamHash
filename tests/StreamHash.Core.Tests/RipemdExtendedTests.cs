using StreamHash.Core;
using Xunit;

namespace StreamHash.Core.Tests;

/// <summary>
/// Tests for native RIPEMD-256 and RIPEMD-320 streaming implementations.
/// Test vectors from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
/// </summary>
public class RipemdExtendedTests {
	// ========== RIPEMD-256 Test Vectors ==========

	[Fact]
	public void Ripemd256_Empty() {
		var expected = Convert.FromHexString("02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d");
		var hash = Ripemd256Factory.ComputeRipemd256([]);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd256_SingleChar_a() {
		var expected = Convert.FromHexString("f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925");
		var hash = Ripemd256Factory.ComputeRipemd256("a"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd256_Abc() {
		var expected = Convert.FromHexString("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65");
		var hash = Ripemd256Factory.ComputeRipemd256("abc"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd256_MessageDigest() {
		var expected = Convert.FromHexString("87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e");
		var hash = Ripemd256Factory.ComputeRipemd256("message digest"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd256_Alphabet() {
		var expected = Convert.FromHexString("649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133");
		var hash = Ripemd256Factory.ComputeRipemd256("abcdefghijklmnopqrstuvwxyz"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd256_AlphabetLong() {
		// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
		var expected = Convert.FromHexString("3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f");
		var hash = Ripemd256Factory.ComputeRipemd256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd256_AlphaNumeric() {
		// "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		var expected = Convert.FromHexString("5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8");
		var hash = Ripemd256Factory.ComputeRipemd256("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd256_EightDigits() {
		// 8 times "1234567890"
		var expected = Convert.FromHexString("06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd");
		var input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"u8.ToArray();
		var hash = Ripemd256Factory.ComputeRipemd256(input);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd256_Streaming_MatchesOneShot() {
		var input = new byte[10000];
		Random.Shared.NextBytes(input);

		var expected = Ripemd256Factory.ComputeRipemd256(input);

		foreach (var chunkSize in new[] { 1, 7, 17, 63, 64, 65, 128, 1000 }) {
			using var hasher = Ripemd256Factory.CreateRipemd256();
			for (int i = 0; i < input.Length; i += chunkSize) {
				int len = Math.Min(chunkSize, input.Length - i);
				hasher.Update(input.AsSpan(i, len));
			}
			var hash = hasher.FinalizeBytes();
			Assert.Equal(expected, hash);
		}
	}

	[Fact]
	public void Ripemd256_Properties() {
		using var hasher = Ripemd256Factory.CreateRipemd256();
		Assert.Equal(32, hasher.DigestSize);
		Assert.Equal(64, hasher.BlockSize);
	}

	// ========== RIPEMD-320 Test Vectors ==========

	[Fact]
	public void Ripemd320_Empty() {
		var expected = Convert.FromHexString("22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8");
		var hash = Ripemd320Factory.ComputeRipemd320([]);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd320_SingleChar_a() {
		var expected = Convert.FromHexString("ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d");
		var hash = Ripemd320Factory.ComputeRipemd320("a"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd320_Abc() {
		var expected = Convert.FromHexString("de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d");
		var hash = Ripemd320Factory.ComputeRipemd320("abc"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd320_MessageDigest() {
		var expected = Convert.FromHexString("3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197");
		var hash = Ripemd320Factory.ComputeRipemd320("message digest"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd320_Alphabet() {
		var expected = Convert.FromHexString("cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009");
		var hash = Ripemd320Factory.ComputeRipemd320("abcdefghijklmnopqrstuvwxyz"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd320_AlphabetLong() {
		// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
		var expected = Convert.FromHexString("d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac");
		var hash = Ripemd320Factory.ComputeRipemd320("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd320_AlphaNumeric() {
		// "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		var expected = Convert.FromHexString("ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4");
		var hash = Ripemd320Factory.ComputeRipemd320("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"u8);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd320_EightDigits() {
		// 8 times "1234567890"
		var expected = Convert.FromHexString("557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42");
		var input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"u8.ToArray();
		var hash = Ripemd320Factory.ComputeRipemd320(input);
		Assert.Equal(expected, hash);
	}

	[Fact]
	public void Ripemd320_Streaming_MatchesOneShot() {
		var input = new byte[10000];
		Random.Shared.NextBytes(input);

		var expected = Ripemd320Factory.ComputeRipemd320(input);

		foreach (var chunkSize in new[] { 1, 7, 17, 63, 64, 65, 128, 1000 }) {
			using var hasher = Ripemd320Factory.CreateRipemd320();
			for (int i = 0; i < input.Length; i += chunkSize) {
				int len = Math.Min(chunkSize, input.Length - i);
				hasher.Update(input.AsSpan(i, len));
			}
			var hash = hasher.FinalizeBytes();
			Assert.Equal(expected, hash);
		}
	}

	[Fact]
	public void Ripemd320_Properties() {
		using var hasher = Ripemd320Factory.CreateRipemd320();
		Assert.Equal(40, hasher.DigestSize);
		Assert.Equal(64, hasher.BlockSize);
	}

	// ========== Cross-Validation Tests ==========

	[Fact]
	public void Ripemd256_MatchesHashFacade() {
		foreach (var size in new[] { 0, 1, 32, 55, 56, 57, 63, 64, 65, 128, 1000 }) {
			var input = new byte[size];
			Random.Shared.NextBytes(input);

			var factoryHash = Ripemd256Factory.ComputeRipemd256(input);
			var facadeHash = HashFacade.ComputeHash(HashAlgorithm.Ripemd256, input);

			Assert.Equal(facadeHash, factoryHash);
		}
	}

	[Fact]
	public void Ripemd320_MatchesHashFacade() {
		foreach (var size in new[] { 0, 1, 32, 55, 56, 57, 63, 64, 65, 128, 1000 }) {
			var input = new byte[size];
			Random.Shared.NextBytes(input);

			var factoryHash = Ripemd320Factory.ComputeRipemd320(input);
			var facadeHash = HashFacade.ComputeHash(HashAlgorithm.Ripemd320, input);

			Assert.Equal(facadeHash, factoryHash);
		}
	}
}
